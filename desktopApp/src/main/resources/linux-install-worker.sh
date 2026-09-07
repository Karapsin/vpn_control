# Captured fixed code, never a privileged -File/source of a user-writable script.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL
unset ENV BASH_ENV CDPATH
umask 077

require_uint() {
    case "$1" in ''|*[!0-9]*) return 1 ;; esac
    [ "${#1}" -le 18 ] && [ "$1" -gt 0 ]
}

read_request() {
    IFS= read -r version
    IFS= read -r request_job
    IFS= read -r request_pid
    IFS= read -r request_start
    IFS= read -r request_uid
    IFS= read -r package_type
    IFS= read -r package_sha256
    IFS= read -r package_size
    IFS= read -r package_file
    IFS= read -r launcher
    IFS= read -r state_directory
    IFS= read -r frontend_pid
    IFS= read -r frontend_start
    extra=
    if IFS= read -r extra || [ -n "$extra" ]; then return 1; fi
}

require_root_object() {
    [ ! -L "$1" ] && [ "$(stat -c %u -- "$1")" = 0 ]
    object_mode=$(stat -c %a -- "$1")
    [ "$((0$object_mode & 022))" -eq 0 ]
}

process_start() {
    # Remove pid/comm through the last closing parenthesis; comm may contain spaces/parentheses.
    process_stat=$(cat "/proc/$1/stat") || return 1
    process_fields=${process_stat##*) }
    printf '%s\n' "$process_fields" | awk '{print $20}'
}

same_process() {
    [ -d "/proc/$1" ] && [ "$(process_start "$1")" = "$2" ]
}

publish_receipt() {
    receipt_phase=$1
    receipt_code=${2:-OK}
    sequence=$((sequence + 1))
    receipt_temporary="$job_path/status-$job_id-$sequence.tmp"
    (set -C; printf '{"version":1,"jobId":"%s","sequence":%s,"phase":"%s","code":"%s"}' \
        "$job_id" "$sequence" "$receipt_phase" "$receipt_code" > "$receipt_temporary")
    chmod 0644 "$receipt_temporary"
    sync -f "$receipt_temporary"
    mv -f -- "$receipt_temporary" "$job_path/status.json"
    sync -f "$job_path"
}

is_cancelled() {
    # The creator retains this inode; the user can write the byte, never redirect a root write.
    cancel_value=$(od -An -tu1 -N1 < "/proc/$$/fd/8" | tr -d ' \n')
    case "$cancel_value" in 0) return 1 ;; 1) return 0 ;; *) return 0 ;; esac
}

clear_pending() {
    printf '\000' | dd of="/proc/$$/fd/9" bs=1 seek=8 conv=notrunc status=none
    sync -f "$machine_root/gate-linux"
}

receive_bytes() {
    receive_count=$1
    receive_target=$2
    # Only this pre-install reader is bounded/killed, never a package manager or application process.
    (set -C; exec timeout --kill-after=1 180 head -c "$receive_count" <&6 > "$receive_target") &
    reader_pid=$!
    while kill -0 "$reader_pid" 2>/dev/null; do
        if is_cancelled || ! same_process "$owner_pid" "$owner_start"; then
            kill -TERM "$reader_pid" 2>/dev/null || :
            wait "$reader_pid" 2>/dev/null || :
            reader_pid=
            publish_receipt CANCELLED CANCELLED
            terminal=1
            exit 0
        fi
        sleep 0.05
    done
    wait "$reader_pid"
    reader_pid=
    [ "$(stat -c %s "$receive_target")" = "$receive_count" ]
}

receive_request() {
    receive_bytes 7 "$job_path/frame"
    [ "$(tail -c 1 "$job_path/frame" | od -An -tu1 | tr -d ' \n')" = 10 ]
    request_length=$(head -c 6 "$job_path/frame")
    case "$request_length" in *[!0-9]*) return 1 ;; esac
    request_length=$(printf '%s' "$request_length" | sed 's/^0*//')
    require_uint "$request_length"
    [ "$request_length" -le 16384 ]
    receive_bytes "$request_length" "$job_path/request"
    read_request < "$job_path/request"
}

cleanup() {
    exit_status=$?
    trap - EXIT
    if [ -n "$reader_pid" ]; then
        kill -TERM "$reader_pid" 2>/dev/null || :
        wait "$reader_pid" 2>/dev/null || :
    fi
    if [ "$job_created" = 1 ] && [ "$terminal" = 0 ] && [ "$installing" = 0 ]; then
        publish_receipt FAILED RUNTIME_FAILED || :
        terminal=1
    fi
    # An interrupted package manager has unknown outcome. Preserve pending and INSTALLING for recovery.
    if [ "$pending" = 1 ] && [ "$terminal" = 1 ]; then clear_pending || :; fi
    if [ "$terminal" = 1 ]; then arch_cleanup_preparation; rm -f -- "$job_path/package" "$job_path/package.deb"; fi
    exit "$exit_status"
}

job_id=${1:-}
owner_pid=${2:-}
[ "$#" = 2 ]
case "$job_id" in ????????-????-????-????-????????????) ;; *) exit 1 ;; esac
case "$job_id" in *[!a-f0-9-]*) exit 1 ;; esac
require_uint "$owner_pid"
[ "$(id -u)" = 0 ]
[ -d "/proc/$owner_pid" ]
owner_uid=$(stat -c %u "/proc/$owner_pid")
require_uint "$owner_uid"
owner_start=$(process_start "$owner_pid")
require_uint "$owner_start"
owner_image=$(readlink "/proc/$owner_pid/exe")
case "$owner_image" in /*/vpn-control) ;; *) exit 1 ;; esac
image_remaining=${owner_image#/}
image_prefix=
while [ -n "$image_remaining" ]; do
    image_component=${image_remaining%%/*}
    case "$image_component" in ''|.|..) exit 1 ;; esac
    image_prefix="$image_prefix/$image_component"
    require_root_object "$image_prefix"
    if [ "$image_remaining" = "$image_component" ]; then break; fi
    [ -d "$image_prefix" ]
    image_remaining=${image_remaining#*/}
done
[ -f "$owner_image" ] && [ -x "$owner_image" ]
[ -p "/proc/$$/fd/0" ]
exec 6<&0
command -v timeout >/dev/null
machine_root=/var/lib/vpn-control-install-jobs
for ancestor in / /var /var/lib; do [ -d "$ancestor" ]; require_root_object "$ancestor"; done
if [ ! -e "$machine_root" ]; then mkdir -m 0755 "$machine_root"; fi
[ -d "$machine_root" ]; require_root_object "$machine_root"
if [ ! -e "$machine_root/reservation-linux" ]; then (set -C; : > "$machine_root/reservation-linux"); fi
require_root_object "$machine_root/reservation-linux"
[ -f "$machine_root/reservation-linux" ] && [ "$(stat -c %h "$machine_root/reservation-linux")" = 1 ]
exec 7<> "$machine_root/reservation-linux"
flock -n -x 7
if [ ! -e "$machine_root/gate-linux" ]; then
    (set -C; dd if=/dev/zero bs=17 count=1 status=none > "$machine_root/gate-linux")
    chmod 0444 "$machine_root/gate-linux"
fi
require_root_object "$machine_root/gate-linux"
[ -f "$machine_root/gate-linux" ] && [ "$(stat -c %h "$machine_root/gate-linux")" = 1 ]
[ "$(stat -c %s "$machine_root/gate-linux")" = 17 ]
[ "$(od -An -tu1 "$machine_root/gate-linux" | tr -d ' \n')" = 00000000000000000 ]
exec 9<> "$machine_root/gate-linux"
job_path="$machine_root/$job_id"
mkdir -m 0755 "$job_path"
sequence=-1
job_created=1
pending=0
terminal=0
installing=0
reader_pid=
trap cleanup EXIT
(set -C; printf '\000' > "$job_path/cancel")
chmod 0600 "$job_path/cancel"
chown "$owner_uid" "$job_path/cancel"
exec 8< "$job_path/cancel"
publish_receipt PREPARING
receive_request
[ "$version" = 1 ] && [ "$request_job" = "$job_id" ] && [ "$request_pid" = "$owner_pid" ]
[ "$request_start" = "$owner_start" ] && [ "$request_uid" = "$owner_uid" ]
[ "$launcher" = "$owner_image" ]
require_uint "$package_size"
[ "${#package_sha256}" = 64 ]
case "$package_sha256" in *[!a-f0-9]*) exit 1 ;; esac
case "$package_type" in deb) command -v apt-get >/dev/null; command -v dpkg-deb >/dev/null ;; rpm) command -v rpm >/dev/null ;; arch-bundle) command -v tar >/dev/null ;; *) exit 1 ;; esac
if [ "$frontend_pid" != 0 ] || [ "$frontend_start" != 0 ]; then
    require_uint "$frontend_pid"; require_uint "$frontend_start"
    same_process "$frontend_pid" "$frontend_start"
    [ "$(stat -c %u "/proc/$frontend_pid")" = "$owner_uid" ]
    [ "$(readlink "/proc/$frontend_pid/exe")" = "$owner_image" ]
fi
verified_package="$job_path/package"
# APT recognizes a captured local archive by its .deb suffix. The file remains
# inside the protected job and is verified before dependency resolution/install.
if [ "$package_type" = deb ]; then verified_package="$job_path/package.deb"; fi
receive_bytes "$package_size" "$verified_package"
[ "$(stat -c %s "$verified_package")" = "$package_size" ]
[ "$(sha256sum "$verified_package" | cut -d' ' -f1)" = "$package_sha256" ]
case "$package_type" in
    deb) [ "$(dpkg-deb -f "$verified_package" Package)" = vpn-control ] ;;
    rpm) [ "$(rpm -qp --qf '%{NAME}' "$verified_package")" = vpn-control ] ;;
    arch-bundle) arch_prepare ;;
esac
sync -f "$verified_package"
same_process "$owner_pid" "$owner_start"
printf '\001' | dd of="/proc/$$/fd/9" bs=1 seek=8 conv=notrunc status=none
sync -f "$machine_root/gate-linux"
pending=1
publish_receipt AUTHORIZED
deadline=$(( $(date +%s) + 180 ))
receive_bytes 37 "$job_path/commit"
[ "$(cat "$job_path/commit")" = "$job_id" ]
publish_receipt WAITING_FOR_EXIT
while :; do
    if is_cancelled; then publish_receipt CANCELLED CANCELLED; terminal=1; exit 0; fi
    [ "$(date +%s)" -lt "$deadline" ]
    if ! same_process "$owner_pid" "$owner_start" &&
        { [ "$frontend_pid" = 0 ] || ! same_process "$frontend_pid" "$frontend_start"; }; then
        if flock -n -x 9; then break; fi
    fi
    sleep 0.1
done
# No process is killed. Reject legacy copies still executing any image from this installation.
installation_directory=${owner_image%/*}
for process in /proc/[0-9]*; do
    process_image=$(readlink "$process/exe" 2>/dev/null) || continue
    case "$process_image" in "$installation_directory/"*) exit 1 ;; esac
done
installing=1
publish_receipt INSTALLING
arch_install_unknown=0
set +e
case "$package_type" in
    # Resolve this archive's required dependencies without a global repair,
    # recommendation install, package removal, or unauthenticated fallback.
    deb) DEBIAN_FRONTEND=noninteractive apt-get --assume-yes --no-remove --no-install-recommends --reinstall install -- "$verified_package" 6<&- 7>&- 8<&- 9>&- ;;
    rpm) rpm -Uvh --replacepkgs -- "$verified_package" 6<&- 7>&- 8<&- 9>&- ;;
    arch-bundle) arch_install_prepared ;;
esac
installer_result=$?
set -e
if [ "$arch_install_unknown" = 1 ]; then exit 1; fi
if [ "$installer_result" = 0 ]; then publish_receipt SUCCEEDED; else publish_receipt FAILED RUNTIME_FAILED; fi
terminal=1
exit 0

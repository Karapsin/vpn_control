# Original-user watcher. Authorization and installation remain in the separately captured privileged worker.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
unset ENV BASH_ENV CDPATH _JPACKAGE_LAUNCHER
umask 077

relaunch_after_install() {
    # The captured authenticated frontend records whether this install should
    # return to a window. CLI-only owners resume their persistent service.
    if [ "$frontend_pid" = 0 ]; then
        exec "$launcher" --state-dir "$state_directory" serve
    else
        exec "$launcher" --state-dir "$state_directory"
    fi
}

job_id=${1:-}
owner_pid=${2:-}
[ "$#" = 2 ]
case "$job_id" in ????????-????-????-????-????????????) ;; *) exit 1 ;; esac
case "$job_id" in *[!a-f0-9-]*) exit 1 ;; esac
case "$owner_pid" in ''|*[!0-9]*) exit 1 ;; esac
owner_uid=$(id -u)
[ "$owner_uid" != 0 ]
[ "$(stat -c %u "/proc/$owner_pid")" = "$owner_uid" ]
owner_stat=$(cat "/proc/$owner_pid/stat")
owner_start=$(printf '%s\n' "${owner_stat##*) }" | awk '{print $20}')
owner_image=$(readlink "/proc/$owner_pid/exe")
[ -p "/proc/$$/fd/0" ]
exec 3<&0
IFS= read -r version <&3
IFS= read -r request_job <&3
IFS= read -r request_pid <&3
IFS= read -r request_start <&3
IFS= read -r request_uid <&3
IFS= read -r package_type <&3
IFS= read -r package_sha256 <&3
IFS= read -r package_size <&3
IFS= read -r package_file <&3
IFS= read -r launcher <&3
IFS= read -r state_directory <&3
IFS= read -r frontend_pid <&3
IFS= read -r frontend_start <&3
extra=
if IFS= read -r extra <&3 || [ -n "$extra" ]; then exit 1; fi
exec 3<&-
[ "$version" = 1 ] && [ "$request_job" = "$job_id" ] && [ "$request_pid" = "$owner_pid" ]
[ "$request_uid" = "$owner_uid" ] && [ "$request_start" = "$owner_start" ] && [ "$launcher" = "$owner_image" ]
case "$launcher" in /*/vpn-control) ;; *) exit 1 ;; esac
case "$state_directory" in /*) ;; *) exit 1 ;; esac
self_stat=$(cat "/proc/$$/stat")
self_start=$(printf '%s\n' "${self_stat##*) }" | awk '{print $20}')
printf '%s\n%s\n%s\n' "$job_id" "$$" "$self_start"

machine_root=/var/lib/vpn-control-install-jobs
job_path="$machine_root/$job_id"
deadline=$(( $(date +%s) + 2100 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    if [ ! -e "$job_path/status.json" ]; then sleep 0.1; continue; fi
    for path in / /var /var/lib "$machine_root" "$job_path"; do
        [ ! -L "$path" ] && [ -d "$path" ] && [ "$(stat -c %u "$path")" = 0 ]
        mode=$(stat -c %a "$path")
        [ "$((0$mode & 022))" -eq 0 ]
    done
    exec 3< "$job_path/status.json"
    [ -f "/proc/$$/fd/3" ] && [ "$(stat -Lc %u "/proc/$$/fd/3")" = 0 ]
    [ "$(stat -Lc %s "/proc/$$/fd/3")" -le 4096 ]
    mode=$(stat -Lc %a "/proc/$$/fd/3")
    [ "$((0$mode & 022))" -eq 0 ]
    receipt=$(head -c 4096 <&3)
    exec 3<&-
    if printf '%s' "$receipt" | grep -Eq '^\{"version":1,"jobId":"'"$job_id"'","sequence":[0-9]+,"phase":"(FAILED|CANCELLED)","code":"[A-Z_]+"\}$'; then exit 1; fi
    if printf '%s' "$receipt" | grep -Eq '^\{"version":1,"jobId":"'"$job_id"'","sequence":[0-9]+,"phase":"SUCCEEDED","code":"OK"\}$'; then
        # The final receipt is published before the coordinator clears pending and releases admission.
        if [ "$(od -An -tu1 "$machine_root/gate-linux" | tr -d ' \n')" = 00000000000000000 ]; then
            relaunch_after_install >/dev/null 2>&1
        fi
    fi
    sleep 0.1
done
exit 2

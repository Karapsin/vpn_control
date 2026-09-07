# Fixed captured Arch bundle handling. No bundle-provided script is executed with privilege.
# Functions are prepended to linux-install-worker.sh in the same captured -c argument.

arch_validate_listing() {
    awk '
    function fail() { bad=1; exit 1 }
    function parent(path) { sub(/\/[^\/]+$/, "", path); return path }
    function canonical(path, parts,n,i) {
        if (path !~ /^[A-Za-z0-9_.+\/-]+$/) return 0
        n=split(path,parts,"/")
        if (parts[1] != "vpn-control-arch-update") return 0
        for(i=1;i<=n;i++) if(parts[i]=="" || parts[i]=="." || parts[i]=="..") return 0
        return 1
    }
    function parents_are_directories(path,p) {
        while(path!=root) { p=parent(path); if(p==path || kind[p]!="d") return 0; path=p }
        return 1
    }
    BEGIN { root="vpn-control-arch-update" }
    {
        if (NF<6 || length($1)!=10 || $2 !~ /^[0-9]+\/[0-9]+$/ || $3 !~ /^[0-9]+$/) fail()
        type=substr($1,1,1); name=$6
        if(type=="d") sub(/\/$/,"",name)
        if(!canonical(name) || (name in kind)) fail()
        if(type=="l") {
            if(NF!=8 || $7!="->" || $8 !~ /^[A-Za-z0-9_.+\/-]+$/ || substr($8,1,1)=="/") fail()
            link[name]=$8
        } else if ((type!="d" && type!="-") || NF!=6) fail()
        kind[name]=type
    }
    END {
        if(bad) exit 1
        if(kind[root]!="d" || kind[root "/app"]!="d" || kind[root "/app/bin"]!="d" ||
           kind[root "/app/bin/vpn-control"]!="-" || kind[root "/sing-box"]!="-" ||
           kind[root "/install.sh"]!="-" || kind[root "/VERSION"]!="-") exit 1
        for(name in kind) {
            if(!parents_are_directories(name)) exit 1
            if(kind[name]=="l") {
                # Only app-internal direct regular-file aliases are needed by jlink legal files.
                # No hardlinks, directory symlinks, chains, or copies pointing outside app survive.
                if(index(name,root "/app/")!=1) exit 1
                target=parent(name); n=split(link[name],parts,"/")
                for(i=1;i<=n;i++) {
                    if(parts[i]=="" || parts[i]==".") exit 1
                    if(parts[i]=="..") { if(target==root) exit 1; target=parent(target) }
                    else target=target "/" parts[i]
                }
                if(index(target,root "/app/")!=1 || kind[target]!="-" || !parents_are_directories(target)) exit 1
            }
        }
    }'
}

arch_unpack_archive() {
    arch_archive=$1
    arch_unpack=$2
    # The listing grammar below is GNU tar, not an inferred BSD/libarchive output format.
    tar --version | head -n 1 | grep -F "GNU tar" >/dev/null
    [ ! -e "$arch_unpack" ] && [ ! -L "$arch_unpack" ]
    (umask 077; mkdir -- "$arch_unpack")
    arch_unpack_id=$(arch_object_id "$arch_unpack")
    tar --list --verbose --gzip --file="$arch_archive" --numeric-owner --full-time --quoting-style=escape > "$arch_unpack/.members"
    arch_validate_listing < "$arch_unpack/.members"
    # Extraction into a private root-owned empty namespace follows the already checked member map.
    tar --extract --gzip --file="$arch_archive" --directory="$arch_unpack" --keep-old-files \
        --no-same-owner --no-same-permissions --delay-directory-restore
    arch_bundle="$arch_unpack/vpn-control-arch-update"
    for arch_required in app/bin/vpn-control sing-box install.sh VERSION; do
        [ -f "$arch_bundle/$arch_required" ] && [ ! -L "$arch_bundle/$arch_required" ]
    done
    [ -x "$arch_bundle/app/bin/vpn-control" ] && [ -x "$arch_bundle/sing-box" ]
    awk '
        NR==1 { n=split($0,v,"[.]"); valid=(n==3)
            for(i=1;i<=n;i++) if(v[i]!~/^[0-9]+$/ || v[i]+0>19 || (length(v[i])>1 && substr(v[i],1,1)=="0")) valid=0
            if(v[1]+0<1) valid=0 }
        END { exit !(NR==1 && valid) }
    ' "$arch_bundle/VERSION"
}

arch_object_id() { stat -c '%d:%i' -- "$1"; }

arch_remove_owned_tree() {
    [ -d "$1" ] && [ ! -L "$1" ] && [ "$(arch_object_id "$1")" = "$2" ] || return 1
    rm -rf -- "$1"
}

arch_prepare() {
    [ "$owner_image" = /opt/vpn-control/bin/vpn-control ]
    for arch_command in tar gzip awk cp chown chmod install setcap getcap find mv; do command -v "$arch_command" >/dev/null; done
    for arch_path in /opt /opt/vpn-control /opt/vpn-control/bin; do
        [ -d "$arch_path" ]; require_root_object "$arch_path"
    done
    arch_target=/opt/vpn-control
    arch_stage="/opt/.vpn-control-arch-stage-$job_id"
    arch_backup="/opt/.vpn-control-arch-backup-$job_id"
    [ ! -e "$arch_stage" ] && [ ! -L "$arch_stage" ]
    [ ! -e "$arch_backup" ] && [ ! -L "$arch_backup" ]
    arch_original_id=$(arch_object_id "$arch_target")
    arch_unpack_archive "$verified_package" "$job_path/arch"
    mkdir -m 0700 -- "$arch_stage"
    arch_stage_id=$(arch_object_id "$arch_stage")
    cp -a --no-preserve=ownership -- "$arch_bundle/app/." "$arch_stage/"
    if [ -e "$arch_stage/bin/sing-box" ] || [ -L "$arch_stage/bin/sing-box" ]; then
        [ -f "$arch_stage/bin/sing-box" ] && [ ! -L "$arch_stage/bin/sing-box" ]
    fi
    install -m 0755 -- "$arch_bundle/sing-box" "$arch_stage/bin/sing-box"
    chown -hR root:root -- "$arch_stage"
    # Extraction respects restrictive umask. Normalize only the new app tree to its packaged role.
    find "$arch_stage" -type d -exec chmod 0755 '{}' +
    find "$arch_stage" -type f -perm -0100 -exec chmod 0755 '{}' +
    find "$arch_stage" -type f ! -perm -0100 -exec chmod 0644 '{}' +
    setcap cap_net_admin,cap_net_raw+ep "$arch_stage/bin/sing-box"
    arch_caps=$(getcap "$arch_stage/bin/sing-box")
    case "$arch_caps" in *cap_net_admin*cap_net_raw*) ;; *) return 1 ;; esac
    arch_icon=/usr/share/icons/hicolor/256x256/apps/vpn-control.png
    if [ -f "$arch_stage/lib/vpn-control.png" ]; then
        for arch_path in /usr /usr/share /usr/share/icons /usr/share/icons/hicolor /usr/share/icons/hicolor/256x256 /usr/share/icons/hicolor/256x256/apps; do
            if [ ! -e "$arch_path" ]; then mkdir -m 0755 -- "$arch_path"; fi
            [ -d "$arch_path" ]; require_root_object "$arch_path"
        done
        if [ -e "$arch_icon" ] || [ -L "$arch_icon" ]; then
            require_root_object "$arch_icon"
            [ -f "$arch_icon" ] && [ "$(stat -c %h -- "$arch_icon")" = 1 ]
        fi
    fi
    sync -f "$arch_stage"
}

arch_rollback() {
    if [ -e "$arch_target" ] || [ -L "$arch_target" ]; then
        arch_remove_owned_tree "$arch_target" "$arch_stage_id" || return 1
    fi
    [ -d "$arch_backup" ] && [ ! -L "$arch_backup" ] && [ "$(arch_object_id "$arch_backup")" = "$arch_original_id" ] || return 1
    mv -T -n -- "$arch_backup" "$arch_target" || return 1
    [ ! -e "$arch_backup" ] && [ "$(arch_object_id "$arch_target")" = "$arch_original_id" ]
}

arch_install_prepared() {
    # No fixed .update-backup cleanup: only this job-created stage and inode-matched backup.
    [ "$(arch_object_id "$arch_target")" = "$arch_original_id" ] || return 1
    [ "$(arch_object_id "$arch_stage")" = "$arch_stage_id" ] || return 1
    [ ! -e "$arch_backup" ] && [ ! -L "$arch_backup" ] || return 1
    mv -T -n -- "$arch_target" "$arch_backup" || return 1
    if [ -e "$arch_target" ] || [ ! -d "$arch_backup" ]; then return 1; fi
    if mv -T -n -- "$arch_stage" "$arch_target" && [ ! -e "$arch_stage" ] &&
        [ "$(arch_object_id "$arch_target")" = "$arch_stage_id" ]; then
        if [ ! -f "$arch_target/lib/vpn-control.png" ] ||
            install -m 0644 -- "$arch_target/lib/vpn-control.png" "$arch_icon"; then
            if sync -f "$arch_target"; then
                # Never roll back from a backup that cleanup may already have partially removed.
                arch_remove_owned_tree "$arch_backup" "$arch_original_id"
                return $?
            fi
        fi
    fi
    if ! arch_rollback; then arch_install_unknown=1; fi
    return 1
}

arch_cleanup_preparation() {
    if [ -n "${arch_stage_id:-}" ] && [ -d "${arch_stage:-}" ]; then
        arch_remove_owned_tree "$arch_stage" "$arch_stage_id" || :
    fi
    if [ -n "${arch_unpack_id:-}" ] && [ -d "${arch_unpack:-}" ]; then
        arch_remove_owned_tree "$arch_unpack" "$arch_unpack_id" || :
    fi
}

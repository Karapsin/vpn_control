#!/bin/sh
set -eu
[ "$#" -eq 0 ] || exit 64
[ "$(/usr/bin/id -u)" -eq 0 ] || exit 77
[ "$(/usr/bin/uname -m)" = arm64 ] || exit 78
SHARE='/Volumes/My Shared Files/bootstrap'
BUNDLE='/Volumes/My Shared Files/bootstrap/continuation-63517582'
PREFIX='/usr/local/libexec/vpn-tool-recovery-cont-63517582'
[ "$(/usr/bin/stat -f '%d:%i:%u:%g:%Lp' /usr/local/libexec/vpn-tool-recovery)" = '16777235:44063:0:0:755' ] || exit 74
[ "$(/bin/cat /usr/local/libexec/vpn-tool-recovery/bootstrap-started)" = '2cccd2e5-0774-4d9a-9b35-e2f5e52e7710' ] || exit 74
[ ! -e /usr/local/libexec/vpn-tool-recovery/bootstrap-complete ] || exit 73
[ ! -e "$PREFIX" ] && [ ! -L "$PREFIX" ] || exit 73
[ ! -e /Library/LaunchDaemons/com.vpn-control.tool-recovery.agent.plist ] && [ ! -L /Library/LaunchDaemons/com.vpn-control.tool-recovery.agent.plist ] || exit 73
[ ! -e /etc/sudoers.d/vpn-tool-recovery-readonly ] && [ ! -L /etc/sudoers.d/vpn-tool-recovery-readonly ] || exit 73
[ "$(/usr/bin/shasum -a 256 "$BUNDLE/guest-probe.py" | /usr/bin/awk '{print $1}')" = b144862272b3bbb5464bcdb3ed57403d76d4f5418c4388c859195f9afb3c38ab ] || exit 74
[ "$(/usr/bin/shasum -a 256 "$BUNDLE/guest-probe-main.py" | /usr/bin/awk '{print $1}')" = 24609b579b77af73292f91ac8756e9efedfeeebbd04e896f7787df6ec252407a ] || exit 74
[ "$(/usr/bin/shasum -a 256 "$BUNDLE/readonly-probe" | /usr/bin/awk '{print $1}')" = 988b4b8835b21da9866914e09c86e77fa1446d81c536ebc68cf5a97789d502ab ] || exit 74
[ "$(/usr/bin/shasum -a 256 "$BUNDLE/com.vpn-control.tool-recovery.agent.plist" | /usr/bin/awk '{print $1}')" = 7dd0b139e5b7f0c567c6a8810e015132699ecb3620c39769768181d28eff0c80 ] || exit 74
[ "$(/usr/bin/shasum -a 256 "$BUNDLE/python-manifest.json" | /usr/bin/awk '{print $1}')" = 7833e44e8363a9768eb697e7c0beef36373421a14fef0b74e02c4ca998ee9b90 ] || exit 74
[ "$(/usr/bin/shasum -a 256 "$BUNDLE/python-files.sha256" | /usr/bin/awk '{print $1}')" = ceee9f727d2471a0d7e97c21c0be425dde0419b47edbc0d93b61dd227addf7f0 ] || exit 74
[ "$(/usr/bin/shasum -a 256 "$BUNDLE/verify-links.sh" | /usr/bin/awk '{print $1}')" = cf3c8a67ddfac9b1acacbcccbf8c259b4892de2b0c094176484bb8a0db11552a ] || exit 74
[ "$(/usr/bin/shasum -a 256 "$BUNDLE/verify-installed.py" | /usr/bin/awk '{print $1}')" = 4212f8277ce31598540e9d2bb7baa1660993f568d3d72a6f9bf889247edb8222 ] || exit 74
[ "$(/usr/bin/id -u toolrecovery)" = 502 ] || exit 77
[ "$(/usr/bin/shasum -a 256 "$SHARE/python/python/bin/python3.12" | /usr/bin/awk '{print $1}')" = 3274dde21f9767655564d093e63c9a5faacefbf1d41bc1e6bf8b6f6e5a441903 ] || exit 74
[ "$(/usr/bin/shasum -a 256 "$SHARE/tart-guest-agent/tart-guest-agent" | /usr/bin/awk '{print $1}')" = 8bbbffe09d207164cbabc06a2b2f5085e041290e75247d28db0a0e1fa852646e ] || exit 74
/usr/bin/install -d -o root -g wheel -m 755 "$PREFIX"
/usr/bin/install -o root -g wheel -m 600 /dev/null "$PREFIX/bootstrap-started"
printf '%s\n' '63517582-8cf8-40f5-aea0-c6a1637b9b83' > "$PREFIX/bootstrap-started"
/bin/cp -RPX "$SHARE/python/python" "$PREFIX/python"
/usr/sbin/chown -Rh root:wheel "$PREFIX"
/bin/chmod -R go-w "$PREFIX"
(cd "$PREFIX/python" && /usr/bin/shasum -a 256 -c "$BUNDLE/python-files.sha256" >/dev/null)
/bin/sh "$BUNDLE/verify-links.sh" "$PREFIX/python"
"$PREFIX/python/bin/python3.12" -I -B "$BUNDLE/verify-installed.py" "$PREFIX/python" "$BUNDLE/python-manifest.json"
/usr/bin/install -o root -g wheel -m 755 "$SHARE/tart-guest-agent/tart-guest-agent" "$PREFIX/tart-guest-agent"
/usr/bin/install -o root -g wheel -m 644 "$BUNDLE/guest-probe.py" "$PREFIX/guest-probe.py"
/usr/bin/install -o root -g wheel -m 644 "$BUNDLE/guest-probe-main.py" "$PREFIX/guest-probe-main.py"
/usr/bin/install -o root -g wheel -m 755 "$BUNDLE/readonly-probe" "$PREFIX/readonly-probe"
/usr/bin/install -d -o root -g wheel -m 755 /etc/sudoers.d
printf '%s\n' 'toolrecovery ALL=(root) NOPASSWD: /usr/local/libexec/vpn-tool-recovery-cont-63517582/readonly-probe ""' > /etc/sudoers.d/vpn-tool-recovery-readonly
/usr/sbin/chown root:wheel /etc/sudoers.d/vpn-tool-recovery-readonly
/bin/chmod 440 /etc/sudoers.d/vpn-tool-recovery-readonly
/usr/sbin/visudo -cf /etc/sudoers.d/vpn-tool-recovery-readonly >/dev/null
/usr/bin/install -o root -g wheel -m 644 "$BUNDLE/com.vpn-control.tool-recovery.agent.plist" /Library/LaunchDaemons/com.vpn-control.tool-recovery.agent.plist
/bin/launchctl bootstrap system /Library/LaunchDaemons/com.vpn-control.tool-recovery.agent.plist
printf '%s\n' 'installed' > "$PREFIX/bootstrap-complete"
/bin/chmod 600 "$PREFIX/bootstrap-complete"
printf '%s\n' 'qualified_continuation_complete'

#!/bin/sh
set -eu
[ "$#" -eq 0 ] || exit 64
[ "$(/usr/bin/id -u)" -eq 0 ] || exit 77
[ "$(/usr/bin/uname -m)" = arm64 ] || exit 78
SHARE='/Volumes/My Shared Files/bootstrap'
PREFIX='/usr/local/libexec/vpn-tool-recovery'
# This exact initial install is create-only; lost acknowledgement is observed.
[ ! -e "$PREFIX" ] && [ ! -L "$PREFIX" ] || exit 73
/usr/bin/install -d -o root -g wheel -m 755 "$PREFIX"
/usr/bin/install -o root -g wheel -m 600 /dev/null "$PREFIX/bootstrap-started"
printf '%s\n' '2cccd2e5-0774-4d9a-9b35-e2f5e52e7710' > "$PREFIX/bootstrap-started"
[ "$(/usr/bin/shasum -a 256 "$SHARE/python/python/bin/python3.12" | /usr/bin/awk '{print $1}')" = 3274dde21f9767655564d093e63c9a5faacefbf1d41bc1e6bf8b6f6e5a441903 ] || exit 74
[ "$(/usr/bin/shasum -a 256 "$SHARE/tart-guest-agent/tart-guest-agent" | /usr/bin/awk '{print $1}')" = 8bbbffe09d207164cbabc06a2b2f5085e041290e75247d28db0a0e1fa852646e ] || exit 74
# These are previously authenticated public binaries, code and libraries only.
/bin/cp -RP "$SHARE/python/python" "$PREFIX/python"
/usr/bin/install -o root -g wheel -m 755 "$SHARE/tart-guest-agent/tart-guest-agent" "$PREFIX/tart-guest-agent"
/usr/bin/install -o root -g wheel -m 644 "$SHARE/guest-probe.py" "$PREFIX/guest-probe.py"
/usr/bin/install -o root -g wheel -m 644 "$SHARE/guest-probe-main.py" "$PREFIX/guest-probe-main.py"
/usr/bin/install -o root -g wheel -m 755 "$SHARE/readonly-probe" "$PREFIX/readonly-probe"
/usr/sbin/chown -R root:wheel "$PREFIX"
/bin/chmod -R go-w "$PREFIX"
# Ordinary account must already exist from the recognized Setup Assistant.
/usr/bin/id toolrecovery >/dev/null
[ "$(/usr/bin/id -u toolrecovery)" -ge 501 ] || exit 77
/usr/bin/install -d -o root -g wheel -m 755 /etc/sudoers.d
printf '%s\n' 'toolrecovery ALL=(root) NOPASSWD: /usr/local/libexec/vpn-tool-recovery/readonly-probe ""' > /etc/sudoers.d/vpn-tool-recovery-readonly
/usr/sbin/chown root:wheel /etc/sudoers.d/vpn-tool-recovery-readonly
/bin/chmod 440 /etc/sudoers.d/vpn-tool-recovery-readonly
/usr/sbin/visudo -cf /etc/sudoers.d/vpn-tool-recovery-readonly >/dev/null
/usr/bin/install -o root -g wheel -m 644 "$SHARE/com.vpn-control.tool-recovery.agent.plist" /Library/LaunchDaemons/com.vpn-control.tool-recovery.agent.plist
/bin/launchctl bootstrap system /Library/LaunchDaemons/com.vpn-control.tool-recovery.agent.plist
printf '%s\n' 'installed' > "$PREFIX/bootstrap-complete"
/bin/chmod 600 "$PREFIX/bootstrap-complete"

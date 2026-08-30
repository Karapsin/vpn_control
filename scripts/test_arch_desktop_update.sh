#!/usr/bin/env bash
set -euo pipefail

if (($# != 1)); then
  echo "Usage: test_arch_desktop_update.sh <arch-update-bundle>" >&2
  exit 2
fi

archive=$(realpath "$1")
test_root=$(mktemp -d)
cleanup() { rm -rf "$test_root"; }
trap cleanup EXIT
tar -xzf "$archive" -C "$test_root"
bundle="$test_root/vpn-control-arch-update"
install_root="$test_root/opt/vpn-control"
icon_path="$test_root/icons/vpn-control.png"

mkdir -p "$install_root"
printf '%s\n' old > "$install_root/old-version"
VPN_CONTROL_INSTALL_DIR="$install_root" \
VPN_CONTROL_ICON_PATH="$icon_path" \
VPN_CONTROL_SKIP_CAPABILITY=true \
VPN_CONTROL_SKIP_OWNERSHIP=true \
  "$bundle/install.sh" "$bundle"

[[ -x "$install_root/bin/vpn-control" ]] || { echo "Updated launcher is missing" >&2; exit 1; }
[[ -x "$install_root/bin/sing-box" ]] || { echo "Updated sing-box is missing" >&2; exit 1; }
[[ ! -e "$install_root/old-version" ]] || { echo "Old install was not replaced" >&2; exit 1; }
[[ ! -e "$install_root.update-backup" ]] || { echo "Update backup was not cleaned" >&2; exit 1; }
echo "[vpn-control] Arch update bundle smoke passed"

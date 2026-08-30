#!/usr/bin/env bash
set -euo pipefail

if (($# != 1)); then
  echo "Usage: install_arch_desktop_update.sh <extracted-bundle-root>" >&2
  exit 2
fi

bundle_root=$1
install_dir="${VPN_CONTROL_INSTALL_DIR:-/opt/vpn-control}"
icon_path="${VPN_CONTROL_ICON_PATH:-/usr/share/icons/hicolor/256x256/apps/vpn-control.png}"
skip_capability="${VPN_CONTROL_SKIP_CAPABILITY:-false}"
skip_ownership="${VPN_CONTROL_SKIP_OWNERSHIP:-false}"
source_app="$bundle_root/app"
source_runtime="$bundle_root/sing-box"
backup_dir="${install_dir}.update-backup"

case "$install_dir" in
  ""|"/"|"/opt"|"/usr"|"/usr/local")
    echo "Refusing unsafe VPN Control install directory: $install_dir" >&2
    exit 1
    ;;
esac

if [[ ! -x "$source_app/bin/vpn-control" || ! -x "$source_runtime" ]]; then
  echo "The Arch update bundle is incomplete." >&2
  exit 1
fi

restore_previous_install() {
  local exit_code=$?
  if ((exit_code != 0)) && [[ -d "$backup_dir" ]]; then
    rm -rf "$install_dir"
    mv "$backup_dir" "$install_dir"
  fi
  exit "$exit_code"
}
trap restore_previous_install EXIT

rm -rf "$backup_dir"
if [[ -d "$install_dir" ]]; then
  mv "$install_dir" "$backup_dir"
fi
mkdir -p "$(dirname "$install_dir")"
cp -a --no-preserve=ownership "$source_app" "$install_dir"
install -Dm755 "$source_runtime" "$install_dir/bin/sing-box"
if [[ "$skip_ownership" != true ]]; then
  chown -R root:root "$install_dir"
fi

if [[ "$skip_capability" != true ]]; then
  setcap cap_net_admin,cap_net_raw+ep "$install_dir/bin/sing-box"
  installed_caps=$(getcap "$install_dir/bin/sing-box" || true)
  if [[ "$installed_caps" != *cap_net_admin* || "$installed_caps" != *cap_net_raw* ]]; then
    echo "Updated sing-box is missing required Linux capabilities." >&2
    exit 1
  fi
fi

if [[ -f "$install_dir/lib/vpn-control.png" ]]; then
  install -Dm644 "$install_dir/lib/vpn-control.png" "$icon_path"
fi

rm -rf "$backup_dir"
trap - EXIT
echo "VPN Control Arch update installed successfully."

#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install_dir="${VPN_CONTROL_INSTALL_DIR:-/opt/vpn-control}"
launcher_path="${VPN_CONTROL_LAUNCHER_PATH:-/usr/local/bin/vpn-control}"
desktop_file_path="${VPN_CONTROL_DESKTOP_FILE_PATH:-/usr/share/applications/vpn-control.desktop}"
icon_path="${VPN_CONTROL_ICON_PATH:-/usr/share/icons/hicolor/256x256/apps/vpn-control.png}"
app_image_dir="$repo_root/desktopApp/build/compose/binaries/main/app/vpn-control"
runtime_sing_box="$repo_root/desktopApp/src/main/resources/bin/linux-amd64/sing-box"
user_config_home="${XDG_CONFIG_HOME:-$HOME/.config}"
user_autostart_file="$user_config_home/autostart/vpn-control.desktop"
user_systemd_service="$user_config_home/systemd/user/vpn-control.service"
user_systemd_wants="$user_config_home/systemd/user/default.target.wants/vpn-control.service"

skip_deps=false
skip_build=false
allow_running_update=false

for arg in "$@"; do
  case "$arg" in
    --skip-deps)
      skip_deps=true
      ;;
    --skip-build)
      skip_build=true
      ;;
    --allow-running-update)
      allow_running_update=true
      ;;
    -h|--help)
      cat <<'HELP'
Usage: ./scripts/arch_install.sh [--skip-deps] [--skip-build] [--allow-running-update]

Builds and installs the VPN Control desktop app locally on Arch Linux.

Options:
  --skip-deps             Do not install pacman dependencies.
  --skip-build            Reuse an existing desktopApp/build/compose app image.
  --allow-running-update  Replace the installed app even if VPN Control is running.

Environment overrides:
  VPN_CONTROL_INSTALL_DIR         default: /opt/vpn-control
  VPN_CONTROL_LAUNCHER_PATH       default: /usr/local/bin/vpn-control
  VPN_CONTROL_DESKTOP_FILE_PATH   default: /usr/share/applications/vpn-control.desktop
  VPN_CONTROL_ICON_PATH           default: /usr/share/icons/hicolor/256x256/apps/vpn-control.png
HELP
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "[vpn-control] this installer is only for Linux/Arch-style systems" >&2
  exit 1
fi

case "$install_dir" in
  ""|"/"|"/opt"|"/usr"|"/usr/local")
    echo "[vpn-control] refusing unsafe install directory: $install_dir" >&2
    exit 1
    ;;
esac

if [[ "$allow_running_update" != true ]]; then
  running_app_pids="$(pgrep -u "$(id -u)" -f "$install_dir/bin/vpn-control" || true)"
  running_runtime_pids="$(pgrep -u "$(id -u)" -f "$install_dir/bin/sing-box" || true)"
  if [[ -n "$running_app_pids" || -n "$running_runtime_pids" ]]; then
    echo "[vpn-control] refusing to replace $install_dir while VPN Control is running" >&2
    echo "[vpn-control] running app PIDs: ${running_app_pids:-none}" >&2
    echo "[vpn-control] running runtime PIDs: ${running_runtime_pids:-none}" >&2
    echo "[vpn-control] close the app first, or pass --allow-running-update if you accept runtime mismatch risk" >&2
    exit 1
  fi
fi

if [[ "$skip_deps" != true ]]; then
  if command -v pacman >/dev/null 2>&1; then
    echo "[vpn-control] installing Arch dependencies"
    sudo pacman -S --needed libcap desktop-file-utils hicolor-icon-theme
  else
    echo "[vpn-control] pacman not found; install libcap, desktop-file-utils, and hicolor-icon-theme manually"
  fi
fi

cd "$repo_root"

if [[ "$skip_build" != true ]]; then
  echo "[vpn-control] preparing bundled sing-box"
  ./scripts/prepare_sing_box_desktop_runtime.sh

  echo "[vpn-control] building desktop app image"
  ./gradlew :desktopApp:createDistributable
fi

if [[ ! -x "$app_image_dir/bin/vpn-control" ]]; then
  echo "[vpn-control] app image is missing: $app_image_dir" >&2
  echo "[vpn-control] run without --skip-build first" >&2
  exit 1
fi

if [[ ! -x "$runtime_sing_box" ]]; then
  echo "[vpn-control] sing-box runtime is missing: $runtime_sing_box" >&2
  echo "[vpn-control] run without --skip-build first" >&2
  exit 1
fi

echo "[vpn-control] installing app to $install_dir"
sudo mkdir -p "$(dirname "$install_dir")"
sudo rm -rf "$install_dir"
sudo cp -a --no-preserve=ownership "$app_image_dir" "$install_dir"

echo "[vpn-control] installing privileged sing-box runtime"
sudo install -Dm755 "$runtime_sing_box" "$install_dir/bin/sing-box"

echo "[vpn-control] ensuring Linux TUN module is loaded"
sudo modprobe tun

echo "[vpn-control] installing launcher at $launcher_path"
sudo mkdir -p "$(dirname "$launcher_path")"
sudo tee "$launcher_path" >/dev/null <<EOF
#!/usr/bin/env bash
export VPN_CONTROL_SING_BOX="$install_dir/bin/sing-box"
exec "$install_dir/bin/vpn-control" "\$@"
EOF
sudo chmod +x "$launcher_path"

echo "[vpn-control] installing desktop launcher"
sudo install -Dm644 "$install_dir/lib/vpn-control.png" "$icon_path"
sudo mkdir -p "$(dirname "$desktop_file_path")"
sudo tee "$desktop_file_path" >/dev/null <<EOF
[Desktop Entry]
Type=Application
Name=VPN Control
Exec="$launcher_path"
Icon=vpn-control
Terminal=false
Categories=Network;
EOF
sudo chown -R root:root "$install_dir"
sudo chown root:root "$launcher_path" "$desktop_file_path" "$icon_path"
sudo setcap cap_net_admin,cap_net_raw+ep "$install_dir/bin/sing-box"

if command -v update-desktop-database >/dev/null 2>&1; then
  sudo update-desktop-database "$(dirname "$desktop_file_path")" || true
fi

if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  sudo gtk-update-icon-cache -f /usr/share/icons/hicolor || true
fi

if [[ -f "$user_autostart_file" ]] && ! grep -qi '^Hidden=true' "$user_autostart_file"; then
  echo "[vpn-control] updating existing user autostart entry"
  mkdir -p "$(dirname "$user_autostart_file")"
  cat >"$user_autostart_file" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=VPN Control
Comment=Start VPN Control at login
Exec="$launcher_path" --autostart
Terminal=false
Categories=Network;
X-GNOME-Autostart-enabled=true
EOF

  mkdir -p "$(dirname "$user_systemd_service")" "$(dirname "$user_systemd_wants")"
  cat >"$user_systemd_service" <<EOF
[Unit]
Description=VPN Control Desktop

[Service]
Type=simple
ExecStart=$launcher_path --autostart
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF
  ln -sf ../vpn-control.service "$user_systemd_wants"
  systemctl --user daemon-reload >/dev/null 2>&1 || true
fi

echo "[vpn-control] installed successfully"
echo "[vpn-control] launch with: vpn-control"

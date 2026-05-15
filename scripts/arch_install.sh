#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install_dir="${VPN_CONTROL_INSTALL_DIR:-/opt/vpn-control}"
launcher_path="${VPN_CONTROL_LAUNCHER_PATH:-/usr/local/bin/vpn-control}"
desktop_file_path="${VPN_CONTROL_DESKTOP_FILE_PATH:-/usr/share/applications/vpn-control.desktop}"
icon_path="${VPN_CONTROL_ICON_PATH:-/usr/share/icons/hicolor/256x256/apps/vpn-control.png}"
app_image_dir="$repo_root/desktopApp/build/compose/binaries/main/app/vpn-control"
runtime_sing_box="$repo_root/desktopApp/src/main/resources/bin/linux-amd64/sing-box"
installed_sing_box="$install_dir/bin/sing-box"
user_config_home="${XDG_CONFIG_HOME:-$HOME/.config}"
user_autostart_file="$user_config_home/autostart/vpn-control.desktop"
user_systemd_service="$user_config_home/systemd/user/vpn-control.service"
user_systemd_wants="$user_config_home/systemd/user/default.target.wants/vpn-control.service"

skip_deps=false
skip_build=false
start_after_install=true

current_user_pids_matching() {
  local command_path=$1
  local pid
  local args

  while read -r pid args; do
    [[ -n "${pid:-}" ]] || continue
    if [[ "${args:-}" == *"$command_path"* ]]; then
      printf '%s\n' "$pid"
    fi
  done < <(ps -u "$(id -u)" -o pid= -o args=)
}

running_app_pids() {
  current_user_pids_matching "$install_dir/bin/vpn-control"
}

running_runtime_pids() {
  current_user_pids_matching "$installed_sing_box"
}

remaining_pids() {
  local pid
  for pid in "$@"; do
    if kill -0 "$pid" >/dev/null 2>&1; then
      printf '%s\n' "$pid"
    fi
  done
}

wait_for_pids_to_exit() {
  local timeout_seconds=$1
  shift
  local pids=("$@")
  local deadline=$((SECONDS + timeout_seconds))
  local still_running=()

  while (( SECONDS < deadline )); do
    mapfile -t still_running < <(remaining_pids "${pids[@]}")
    if [[ ${#still_running[@]} -eq 0 ]]; then
      return 0
    fi
    sleep 1
  done

  mapfile -t still_running < <(remaining_pids "${pids[@]}")
  [[ ${#still_running[@]} -eq 0 ]]
}

terminate_pids() {
  local label=$1
  shift
  local pids=("$@")
  local still_running=()

  if [[ ${#pids[@]} -eq 0 ]]; then
    return
  fi

  echo "[vpn-control] stopping $label PIDs: ${pids[*]}"
  kill "${pids[@]}" 2>/dev/null || true
  if wait_for_pids_to_exit 15 "${pids[@]}"; then
    return
  fi

  mapfile -t still_running < <(remaining_pids "${pids[@]}")
  if [[ ${#still_running[@]} -gt 0 ]]; then
    echo "[vpn-control] force stopping $label PIDs: ${still_running[*]}"
    kill -KILL "${still_running[@]}" 2>/dev/null || true
    wait_for_pids_to_exit 5 "${still_running[@]}" || {
      echo "[vpn-control] failed to stop $label PIDs: ${still_running[*]}" >&2
      exit 1
    }
  fi
}

stop_running_instance() {
  local app_pids=()
  local runtime_pids=()

  mapfile -t app_pids < <(running_app_pids)
  mapfile -t runtime_pids < <(running_runtime_pids)

  if [[ ${#app_pids[@]} -eq 0 && ${#runtime_pids[@]} -eq 0 ]]; then
    echo "[vpn-control] no running installed instance found"
    return
  fi

  terminate_pids "VPN Control app" "${app_pids[@]}"

  # Refresh after the app exits; a clean shutdown usually stops sing-box itself.
  mapfile -t runtime_pids < <(running_runtime_pids)
  terminate_pids "bundled sing-box runtime" "${runtime_pids[@]}"
}

start_installed_app() {
  if [[ "$start_after_install" != true ]]; then
    echo "[vpn-control] skipping app start"
    return
  fi

  if [[ -z "${DISPLAY:-}" && -z "${WAYLAND_DISPLAY:-}" ]]; then
    echo "[vpn-control] no graphical session detected; installed app was not started" >&2
    echo "[vpn-control] launch later with: vpn-control" >&2
    return
  fi

  echo "[vpn-control] starting installed app"
  nohup "$launcher_path" >/dev/null 2>&1 &
  local started_pid=$!
  disown "$started_pid" 2>/dev/null || true
  sleep 1
  if kill -0 "$started_pid" >/dev/null 2>&1; then
    echo "[vpn-control] started VPN Control PID: $started_pid"
  else
    echo "[vpn-control] start command exited quickly; check desktop logs if the app did not open" >&2
  fi
}

cleanup_legacy_user_systemd_autostart() {
  local removed=false
  local legacy_service=false

  if [[ -f "$user_systemd_service" ]] && grep -q 'VPN Control Desktop' "$user_systemd_service"; then
    legacy_service=true
    systemctl --user disable vpn-control.service >/dev/null 2>&1 || true
    rm -f "$user_systemd_service"
    removed=true
  fi

  if [[ -L "$user_systemd_wants" ]]; then
    if [[ "$(readlink "$user_systemd_wants")" == "../vpn-control.service" || "$legacy_service" == true ]]; then
      rm -f "$user_systemd_wants"
      removed=true
    fi
  elif [[ -e "$user_systemd_wants" && "$legacy_service" == true ]]; then
    rm -f "$user_systemd_wants"
    removed=true
  fi

  if [[ "$removed" == true ]]; then
    systemctl --user daemon-reload >/dev/null 2>&1 || true
    echo "[vpn-control] removed legacy user systemd autostart; XDG autostart is used for GUI startup"
  fi
}

ensure_linux_tun_available() {
  if [[ -e /dev/net/tun ]]; then
    echo "[vpn-control] Linux TUN device is available at /dev/net/tun"
    return
  fi

  local current_kernel
  local modules_dir
  current_kernel="$(uname -r)"
  modules_dir="/lib/modules/$current_kernel"
  if [[ ! -d "$modules_dir" ]]; then
    {
      echo "[vpn-control] Linux TUN device is missing at /dev/net/tun"
      echo "[vpn-control] kernel modules for the running kernel are missing: $modules_dir"
      echo "[vpn-control] installed module directories:"
      find /lib/modules -maxdepth 1 -mindepth 1 -type d -printf ' - %f\n' | sort || true
      echo "[vpn-control] reboot into an installed kernel or install the matching Arch kernel/modules package, then rerun this installer"
    } >&2
    exit 1
  fi

  local modprobe_output
  if ! modprobe_output="$(sudo modprobe tun 2>&1)"; then
    if [[ -e /dev/net/tun ]]; then
      echo "[vpn-control] Linux TUN device is available at /dev/net/tun"
      return
    fi
    {
      echo "[vpn-control] failed to load Linux TUN module for kernel $current_kernel"
      echo "[vpn-control] modprobe output: ${modprobe_output:-<empty>}"
      echo "[vpn-control] install matching kernel modules or enable TUN support, then rerun this installer"
    } >&2
    exit 1
  fi

  if [[ ! -e /dev/net/tun ]]; then
    {
      echo "[vpn-control] modprobe tun succeeded but /dev/net/tun is still missing"
      echo "[vpn-control] check kernel TUN support and device permissions, then rerun this installer"
    } >&2
    exit 1
  fi
  echo "[vpn-control] Linux TUN device is available at /dev/net/tun"
}

for arg in "$@"; do
  case "$arg" in
    --skip-deps)
      skip_deps=true
      ;;
    --skip-build)
      skip_build=true
      ;;
    --allow-running-update)
      echo "[vpn-control] --allow-running-update is deprecated; running instances are restarted automatically" >&2
      ;;
    --no-start)
      start_after_install=false
      ;;
    -h|--help)
      cat <<'HELP'
Usage: ./scripts/arch_install.sh [--skip-deps] [--skip-build] [--no-start]

Builds and installs the VPN Control desktop app locally on Arch Linux.
If an installed instance is running, the installer stops it before replacing files,
then starts the newly installed app unless --no-start is passed.

Options:
  --skip-deps             Do not install pacman dependencies.
  --skip-build            Reuse an existing desktopApp/build/compose app image.
  --no-start              Do not launch VPN Control after install.

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

echo "[vpn-control] stopping any running installed instance before replacement"
stop_running_instance

echo "[vpn-control] installing app to $install_dir"
sudo mkdir -p "$(dirname "$install_dir")"
sudo rm -rf "$install_dir"
sudo cp -a --no-preserve=ownership "$app_image_dir" "$install_dir"

echo "[vpn-control] installing privileged sing-box runtime"
sudo install -Dm755 "$runtime_sing_box" "$installed_sing_box"

echo "[vpn-control] ensuring Linux TUN support is available"
ensure_linux_tun_available

echo "[vpn-control] installing launcher at $launcher_path"
sudo mkdir -p "$(dirname "$launcher_path")"
sudo tee "$launcher_path" >/dev/null <<EOF
#!/usr/bin/env bash
set -euo pipefail

export VPN_CONTROL_SING_BOX="$install_dir/bin/sing-box"

state_dir="\${VPN_CONTROL_STATE_DIR:-\$HOME/.vpn-control-desktop}"
lock_file="\$state_dir/launcher.lock"
port_file="\$state_dir/activation.port"

request_existing_instance() {
  local port

  [[ -r "\$port_file" ]] || return 1
  port="\$(tr -dc '0-9' <"\$port_file")"
  [[ -n "\$port" ]] || return 1

  if command -v python3 >/dev/null 2>&1; then
    python3 - "\$port" <<'PY'
import socket
import sys

port = int(sys.argv[1])
with socket.create_connection(("127.0.0.1", port), timeout=0.5) as sock:
    sock.sendall(b"show\n")
PY
  else
    exec 8<>"/dev/tcp/127.0.0.1/\$port" || return 1
    printf 'show\n' >&8
    exec 8<&-
    exec 8>&-
  fi
}

if command -v flock >/dev/null 2>&1; then
  mkdir -p "\$state_dir"
  exec 9>"\$lock_file"
  if ! flock -n 9; then
    request_existing_instance >/dev/null 2>&1 || true
    exit 0
  fi
fi

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

echo "[vpn-control] granting Linux VPN capabilities to $installed_sing_box"
sudo setcap cap_net_admin,cap_net_raw+ep "$installed_sing_box"
installed_caps="$(getcap "$installed_sing_box" || true)"
if [[ "$installed_caps" != *"cap_net_admin"* || "$installed_caps" != *"cap_net_raw"* ]]; then
  {
    echo "[vpn-control] installed sing-box is missing required capabilities after setcap"
    echo "[vpn-control] expected cap_net_admin and cap_net_raw on: $installed_sing_box"
    echo "[vpn-control] getcap output: ${installed_caps:-<empty>}"
    echo "[vpn-control] retry manually: sudo setcap cap_net_admin,cap_net_raw+ep '$installed_sing_box'"
  } >&2
  exit 1
fi
echo "[vpn-control] verified Linux VPN capabilities: $installed_caps"

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
fi
cleanup_legacy_user_systemd_autostart

echo "[vpn-control] installed successfully"
start_installed_app

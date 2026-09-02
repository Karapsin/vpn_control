#!/usr/bin/env bash
set -euo pipefail

relay_port=10808
install_dir="${XDG_DATA_HOME:-$HOME/.local/share}/vpn-control-home-relay"
sing_box_bin="${VPN_CONTROL_SING_BOX:-}"
sing_box_version=1.13.4

usage() {
  echo "Usage: $0 [--port PORT] [--install-dir PATH] [--sing-box PATH]"
}

while (($# > 0)); do
  case "$1" in
    --port)
      relay_port="${2:?missing port}"
      shift 2
      ;;
    --install-dir)
      install_dir="${2:?missing install directory}"
      shift 2
      ;;
    --sing-box)
      sing_box_bin="${2:?missing sing-box path}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! "$relay_port" =~ ^[0-9]+$ ]] || ((relay_port < 1 || relay_port > 65535)); then
  echo "Invalid relay port: $relay_port" >&2
  exit 2
fi

if [[ -z "$sing_box_bin" ]]; then
  if [[ "$(uname -s)" != "Linux" ]]; then
    echo "Automatic sing-box installation is supported on Linux only. Pass --sing-box /path/to/sing-box." >&2
    exit 1
  fi
  sing_box_bin="$(command -v sing-box || true)"
fi

mkdir -p "$install_dir"
chmod 700 "$install_dir"

if [[ -z "$sing_box_bin" ]]; then
  case "$(uname -m)" in
    x86_64|amd64)
      archive_arch=amd64
      expected_sha256=634a679fc572d9d0c01b2f5f43b9d6af3f529e9f7011bdfc5931804fc0fa968a
      ;;
    aarch64|arm64)
      archive_arch=arm64
      expected_sha256=f40f1f281c5c08e04acc5ca82b3228b9d5f8c3c8de8c58ad8fef8e8981a5e17a
      ;;
    *)
      echo "No bundled download is available for architecture $(uname -m). Pass --sing-box /path/to/sing-box." >&2
      exit 1
      ;;
  esac
  download_dir="$(mktemp -d "${TMPDIR:-/tmp}/vpn-control-home-relay.XXXXXX")"
  trap 'rm -rf -- "$download_dir"' EXIT
  archive_name="sing-box-$sing_box_version-linux-$archive_arch.tar.gz"
  archive_path="$download_dir/$archive_name"
  download_url="https://github.com/SagerNet/sing-box/releases/download/v$sing_box_version/$archive_name"
  echo "Downloading sing-box $sing_box_version for linux-$archive_arch"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 -o "$archive_path" "$download_url"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$archive_path" "$download_url"
  else
    echo "curl or wget is required to download sing-box." >&2
    exit 1
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    actual_sha256="$(sha256sum "$archive_path" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual_sha256="$(shasum -a 256 "$archive_path" | awk '{print $1}')"
  else
    echo "sha256sum or shasum is required to verify the sing-box download." >&2
    exit 1
  fi
  if [[ "$actual_sha256" != "$expected_sha256" ]]; then
    echo "sing-box archive checksum mismatch." >&2
    exit 1
  fi
  tar -xzf "$archive_path" -C "$download_dir"
  sing_box_bin="$(find "$download_dir" -type f -name sing-box -print -quit)"
fi
if [[ -z "$sing_box_bin" || ! -x "$sing_box_bin" ]]; then
  echo "sing-box was not found. Pass --sing-box /path/to/sing-box." >&2
  exit 1
fi

mkdir -p "$install_dir/bin"
chmod 700 "$install_dir/bin"
installed_sing_box="$install_dir/bin/sing-box"
if [[ -e "$installed_sing_box" && "$sing_box_bin" -ef "$installed_sing_box" ]]; then
  chmod 700 "$installed_sing_box"
else
  install -m 700 "$sing_box_bin" "$installed_sing_box"
fi

config_path="$install_dir/config.json"
launcher_path="$install_dir/run.sh"

sed "s/__RELAY_PORT__/$relay_port/g" >"$config_path" <<'JSON'
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "socks",
      "tag": "home-relay-in",
      "listen": "127.0.0.1",
      "listen_port": __RELAY_PORT__
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "final": "direct"
  }
}
JSON

sed >"$launcher_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec "$script_dir/bin/sing-box" run -c "$script_dir/config.json"
SH

chmod 600 "$config_path"
chmod 700 "$launcher_path"
"$installed_sing_box" check -c "$config_path"

echo "SSH relay installed in: $install_dir"
echo "It listens only on the SSH host loopback address: 127.0.0.1:$relay_port"
echo "Start it with: $launcher_path"
echo "Keep it running with your preferred supervisor (tmux, screen, runit, s6, OpenRC, or systemd)."

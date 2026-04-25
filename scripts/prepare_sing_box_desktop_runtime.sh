#!/usr/bin/env bash
set -euo pipefail

version="${SING_BOX_VERSION:-1.13.4}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cache_dir="$repo_root/.runtime/sing-box"
target_dir="$repo_root/desktopApp/src/main/resources/bin/linux-amd64"
archive="$cache_dir/sing-box-$version-linux-amd64.tar.gz"
extract_dir="$cache_dir/linux-amd64"
url="https://github.com/SagerNet/sing-box/releases/download/v$version/sing-box-$version-linux-amd64.tar.gz"

mkdir -p "$cache_dir" "$target_dir"

if [[ ! -f "$archive" ]]; then
  echo "[vpn-control] downloading sing-box $version for linux-amd64"
  curl -fsSL "$url" -o "$archive"
fi

rm -rf "$extract_dir"
mkdir -p "$extract_dir"
tar -xzf "$archive" -C "$extract_dir"

binary="$(find "$extract_dir" -type f -name sing-box | head -n 1)"
if [[ -z "$binary" ]]; then
  echo "sing-box binary was not found in $archive" >&2
  exit 1
fi

install -m 0755 "$binary" "$target_dir/sing-box"
echo "[vpn-control] bundled linux sing-box at $target_dir/sing-box"

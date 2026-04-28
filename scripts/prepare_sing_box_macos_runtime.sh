#!/usr/bin/env bash
set -euo pipefail

version="${SING_BOX_VERSION:-1.13.4}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cache_dir="$repo_root/.runtime/sing-box"
archs=(amd64 arm64)

mkdir -p "$cache_dir"

for arch in "${archs[@]}"; do
  target_dir="$repo_root/desktopApp/src/main/resources/bin/darwin-$arch"
  archive="$cache_dir/sing-box-$version-darwin-$arch.tar.gz"
  extract_dir="$cache_dir/darwin-$arch"
  url="https://github.com/SagerNet/sing-box/releases/download/v$version/sing-box-$version-darwin-$arch.tar.gz"

  mkdir -p "$target_dir"

  if [[ ! -f "$archive" ]]; then
    echo "[vpn-control] downloading sing-box $version for darwin-$arch"
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
  echo "[vpn-control] bundled macOS sing-box at $target_dir/sing-box"
done

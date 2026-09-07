#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != Darwin ]]; then
  echo "The macOS installer worker must be built on macOS." >&2
  exit 1
fi
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case "$(uname -m)" in
  arm64) worker_arch=arm64 ;;
  x86_64) worker_arch=amd64 ;;
  *) echo "Unsupported macOS worker architecture." >&2; exit 1 ;;
esac
worker_output="$repo_root/desktopApp/src/main/resources/bin/darwin-$worker_arch"
mkdir -p "$worker_output"
xcrun clang -std=c11 -O2 -Wall -Wextra -Werror -Wno-deprecated-declarations \
  -framework CoreFoundation "$repo_root/scripts/native/macos_install_worker.c" \
  -o "$worker_output/vpn-control-install-worker"
chmod 755 "$worker_output/vpn-control-install-worker"

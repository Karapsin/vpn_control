#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
platform_name="${1:-}"

case "$platform_name" in
  android|linux|windows-vm|macos) ;;
  *) echo "Usage: $0 <android|linux|windows-vm|macos>" >&2; exit 2 ;;
esac

command -v git >/dev/null
git lfs version >/dev/null
command -v python3 >/dev/null
if [[ "$platform_name" == android ]]; then
  command -v adb >/dev/null
fi
if [[ "$platform_name" == linux && -z "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
  echo "A persistent Linux GUI session is required." >&2
  exit 1
fi
if [[ "$platform_name" == windows-vm ]]; then
  command -v virsh >/dev/null
  virsh dominfo vpn-control-win11 >/dev/null
  echo "Configure VPN_CONTROL_VISUAL_WINDOWS_VM=1 for the Linux host runner."
fi
if [[ "$platform_name" == macos ]]; then
  echo "Grant Screen Recording and Accessibility to the runner service account before enrollment."
fi

echo "Runner prerequisites found for $platform_name."
echo "Configure VPN_CONTROL_VISUAL_FLEET=1 and VPN_CONTROL_VISUAL_CAPTURE_COMMAND for the service account."
echo "Register labels: self-hosted,vpn-control-visual,$platform_name"
preflight_platform="$platform_name"
if [[ "$platform_name" == windows-vm ]]; then
  preflight_platform="windows"
fi
echo "Then run: python3 $repo_root/scripts/visual_fleet.py preflight --platform $preflight_platform --allow-missing-baselines"

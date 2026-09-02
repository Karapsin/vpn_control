#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
platform_name="${1:-}"
output_dir="${2:-}"
scene_csv="${3:-}"
case "$platform_name" in
  linux|macos) ;;
  *) echo "Usage: $0 <linux|macos> <output-dir>" >&2; exit 2 ;;
esac
[[ -n "$output_dir" ]] || { echo "Output directory is required." >&2; exit 2; }

cd "$repo_root"
mkdir -p "$output_dir"
VPN_CONTROL_VISUAL_PLATFORM="$platform_name" \
VPN_CONTROL_VISUAL_MANIFEST="$repo_root/visual-tests/scenes.json" \
VPN_CONTROL_VISUAL_OUTPUT="$(cd "$output_dir" && pwd)" \
VPN_CONTROL_VISUAL_SCENES="$scene_csv" \
  ./gradlew :desktopApp:visualCapture

validation=(python3 scripts/visual_platform.py capture-local --platform "$platform_name" --driver /usr/bin/true --output "$output_dir")
if [[ -n "$scene_csv" ]]; then
  IFS=',' read -r -a scenes <<< "$scene_csv"
  for scene in "${scenes[@]}"; do
    validation+=(--scene "$scene")
  done
fi
"${validation[@]}" >/dev/null

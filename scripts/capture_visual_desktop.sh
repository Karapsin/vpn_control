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
manifest="$repo_root/visual-tests/scenes.json"
output_abs="$(cd "$output_dir" && pwd)"
app_scenes="$(python3 scripts/select_visual_scenes.py \
  --manifest "$manifest" --platform "$platform_name" --kind app --requested "$scene_csv")"
native_scenes="$(python3 scripts/select_visual_scenes.py \
  --manifest "$manifest" --platform "$platform_name" --kind native --requested "$scene_csv")"

if [[ -n "$app_scenes" ]]; then
  VPN_CONTROL_VISUAL_PLATFORM="$platform_name" \
  VPN_CONTROL_VISUAL_MANIFEST="$manifest" \
  VPN_CONTROL_VISUAL_OUTPUT="$output_abs" \
  VPN_CONTROL_VISUAL_SCENES="$app_scenes" \
    ./gradlew :desktopApp:visualCapture
fi

background_pids=()
cleanup() {
  local pid
  for pid in "${background_pids[@]:-}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

visual_package=""
if [[ -n "$native_scenes" ]]; then
  if [[ "${VPN_CONTROL_VISUAL_PROVIDER:-local}" != "hosted" && "${VPN_CONTROL_VISUAL_ISOLATED:-}" != "1" ]]; then
    echo "Native desktop capture requires VPN_CONTROL_VISUAL_ISOLATED=1 or an ephemeral hosted runner." >&2
    exit 1
  fi
  if [[ "$platform_name" == "linux" ]]; then
    command -v openbox >/dev/null || { echo "openbox is required for native Linux capture." >&2; exit 1; }
    openbox >"$output_abs/openbox.log" 2>&1 &
    background_pids+=("$!")
    if [[ "$native_scenes" == *linux-tray-* ]] && command -v stalonetray >/dev/null; then
      stalonetray --geometry 1x1+0+0 --icon-size 1 --slot-size 1 --transparent --parent-bg \
        --window-layer bottom --skip-taskbar >"$output_abs/stalonetray.log" 2>&1 &
      background_pids+=("$!")
    fi
    if command -v /usr/lib/policykit-1-gnome/polkit-gnome-authentication-agent-1 >/dev/null; then
      /usr/lib/policykit-1-gnome/polkit-gnome-authentication-agent-1 \
        >"$output_abs/polkit-agent.log" 2>&1 &
      background_pids+=("$!")
    fi
    if [[ ",$native_scenes," == *,linux-update-installer,* ]]; then
      ./scripts/package_linux_desktop.sh --skip-tests --skip-package-regression-tests
      visual_package="$(find desktopApp/build/compose/binaries/main -type f -name '*.deb' | sort | head -n 1)"
    fi
  elif [[ ",$native_scenes," == *,macos-dmg,* || ",$native_scenes," == *,macos-gatekeeper,* || ",$native_scenes," == *,macos-install-confirmation,* ]]; then
    ./scripts/package_macos_desktop.sh --skip-tests --skip-package-regression-tests
    visual_package="$(find dist/macos -maxdepth 1 -type f -name '*.dmg' | sort | head -n 1)"
  fi
  if [[ -n "$visual_package" ]]; then
    visual_package="$(cd "$(dirname "$visual_package")" && pwd)/$(basename "$visual_package")"
  fi
  VPN_CONTROL_VISUAL_PLATFORM="$platform_name" \
  VPN_CONTROL_VISUAL_MANIFEST="$manifest" \
  VPN_CONTROL_VISUAL_OUTPUT="$output_abs" \
  VPN_CONTROL_VISUAL_NATIVE_SCENES="$native_scenes" \
  VPN_CONTROL_VISUAL_PACKAGE="$visual_package" \
    ./gradlew :desktopApp:nativeVisualCapture
fi

validation=(python3 scripts/visual_platform.py capture-local --platform "$platform_name" --driver /usr/bin/true --output "$output_dir")
if [[ -n "$scene_csv" ]]; then
  IFS=',' read -r -a scenes <<< "$scene_csv"
  for scene in "${scenes[@]}"; do
    validation+=(--scene "$scene")
  done
fi
"${validation[@]}" >/dev/null

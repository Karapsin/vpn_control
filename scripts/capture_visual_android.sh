#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${1:-$repo_root/build/visual-actual/android}"
scene_csv="${2:-}"
device_dir="/data/local/tmp/vpn-control-visual"
sdk_root="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
if [[ -z "$sdk_root" && -f "$repo_root/local.properties" ]]; then
  sdk_root="$(sed -n 's/^sdk\.dir=//p' "$repo_root/local.properties" | head -n 1)"
fi
adb_bin="$(command -v adb || true)"
if [[ -z "$adb_bin" && -n "$sdk_root" && -x "$sdk_root/platform-tools/adb" ]]; then
  adb_bin="$sdk_root/platform-tools/adb"
fi
[[ -n "$adb_bin" ]] || { echo "Android adb was not found." >&2; exit 1; }

cd "$repo_root"
mkdir -p "$output_dir"
restore_system_ui() {
  "$adb_bin" shell am broadcast -a com.android.systemui.demo -e command exit >/dev/null 2>&1 || true
}
trap restore_system_ui EXIT
while IFS= read -r scene; do
  rm -f "$output_dir/$scene.png" "$output_dir/$scene.geometry.json"
done < <(python3 - "$repo_root/visual-tests/scenes.json" "$scene_csv" <<'PY'
import json
import sys

selected = {value for value in sys.argv[2].split(",") if value}
for scene in json.load(open(sys.argv[1], encoding="utf-8"))["scenes"]:
    if "android" in scene["platforms"] and (not selected or scene["id"] in selected):
        print(scene["id"])
PY
)
if [[ "${VPN_CONTROL_VISUAL_PROVIDER:-local}" != "hosted" ]]; then
  avd_name="$($adb_bin emu avd name 2>/dev/null | sed '/^OK$/d' | head -n 1 | tr -d '\r')"
  [[ "$avd_name" == "vpn-control-visual-api35" ]] || {
    echo "Local Android visual capture refuses non-isolated device: ${avd_name:-unknown}." >&2
    exit 1
  }
fi
"$adb_bin" shell settings put global sysui_demo_allowed 1
"$adb_bin" shell am broadcast -a com.android.systemui.demo -e command exit >/dev/null 2>&1 || true
"$adb_bin" shell rm -rf "$device_dir"
"$adb_bin" uninstall com.kardinal.vpncontrol >/dev/null 2>&1 || true
"$adb_bin" uninstall com.kardinal.vpncontrol.test >/dev/null 2>&1 || true
app_scenes="$(python3 scripts/select_visual_scenes.py \
  --manifest visual-tests/scenes.json --platform android --kind app --requested "$scene_csv")"
native_scenes="$(python3 scripts/select_visual_scenes.py \
  --manifest visual-tests/scenes.json --platform android --kind native --requested "$scene_csv")"

run_gradle_capture() {
  local selected_scenes="$1"
  ./gradlew :app:connectedDebugAndroidTest \
    -Pandroid.testInstrumentationRunnerArguments.class=com.kardinal.vpncontrol.ui.VisualCaptureInstrumentedTest \
    -Pandroid.testInstrumentationRunnerArguments.visualManifest="$repo_root/visual-tests/scenes.json" \
    -Pandroid.testInstrumentationRunnerArguments.visualScenes="$selected_scenes"
}

pull_device_capture() {
  "$adb_bin" pull "$device_dir/." "$output_dir/"
}

if [[ -n "$app_scenes" ]]; then
  run_gradle_capture "$app_scenes"
  pull_device_capture
fi

if [[ -n "$native_scenes" ]]; then
  IFS=',' read -r -a native_scene_ids <<< "$native_scenes"
  for native_scene in "${native_scene_ids[@]}"; do
    # The instrumentation fixture owns the complete demo-mode state. Leave any prior
    # invocation first so SystemUI cannot accumulate duplicate Wi-Fi/status icons.
    "$adb_bin" shell am broadcast -a com.android.systemui.demo -e command exit >/dev/null 2>&1 || true
    if [[ "$native_scene" == "android-system-bars" ]]; then
      run_gradle_capture "$native_scene"
      pull_device_capture
      continue
    fi
    case "$native_scene" in
      android-vpn-consent) focus_pattern='com.android.vpndialogs' ;;
      android-open-document|android-create-document) focus_pattern='documentsui' ;;
      android-camera-qr) focus_pattern='QrCaptureActivity' ;;
      android-share-chooser) focus_pattern='ChooserActivity' ;;
      android-package-installer) focus_pattern='PackageInstallerActivity' ;;
      android-vpn-notification) focus_pattern='NotificationShade' ;;
      *) echo "Unknown Android native scene: $native_scene" >&2; exit 1 ;;
    esac
    framebuffer_capture="$output_dir/.$native_scene-framebuffer.png"
    rm -f "$framebuffer_capture"
    run_gradle_capture "$native_scene" &
    gradle_pid=$!
    native_window_ready=false
    for _ in $(seq 1 600); do
      capture_ready="$($adb_bin shell "test -f '$device_dir/$native_scene.ready' && echo ready || true" 2>/dev/null | tr -d '\r')"
      current_focus="$($adb_bin shell dumpsys window 2>/dev/null | grep 'mCurrentFocus' || true)"
      if [[ "$capture_ready" == "ready" ]] && grep -q "$focus_pattern" <<< "$current_focus"; then
        "$adb_bin" exec-out screencap -p > "$framebuffer_capture"
        if [[ -s "$framebuffer_capture" ]]; then
          "$adb_bin" shell touch "$device_dir/$native_scene.captured"
          native_window_ready=true
          break
        fi
      fi
      if ! kill -0 "$gradle_pid" >/dev/null 2>&1; then
        break
      fi
      sleep 0.1
    done
    set +e
    wait "$gradle_pid"
    gradle_exit=$?
    set -e
    (( gradle_exit == 0 )) || exit "$gradle_exit"
    [[ "$native_window_ready" == true ]] || {
      echo "$native_scene did not display its expected native surface." >&2
      exit 1
    }
    [[ -s "$framebuffer_capture" ]] || {
      echo "The emulator framebuffer did not capture $native_scene." >&2
      exit 1
    }
    pull_device_capture
    mv "$framebuffer_capture" "$output_dir/$native_scene.png"
  done
fi

python3 - "$repo_root/visual-tests/scenes.json" "$output_dir" "$scene_csv" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
output = pathlib.Path(sys.argv[2])
selected = {value for value in sys.argv[3].split(",") if value}
missing = []
for scene in manifest["scenes"]:
    if "android" not in scene["platforms"]:
        continue
    scene_id = scene["id"]
    if selected and scene_id not in selected:
        continue
    if not (output / f"{scene_id}.png").is_file():
        missing.append(f"{scene_id}.png")
    if scene.get("geometry_required", True) and not (output / f"{scene_id}.geometry.json").is_file():
        missing.append(f"{scene_id}.geometry.json")
if missing:
    raise SystemExit("Android visual capture is incomplete: " + ", ".join(missing))
PY

target_sha="${VPN_CONTROL_VISUAL_TARGET_SHA:-$(git rev-parse HEAD)}"
provider="${VPN_CONTROL_VISUAL_PROVIDER:-local}"
stamp=(python3 scripts/visual_platform.py stamp --platform android --target-sha "$target_sha" --provider "$provider" --output "$output_dir")
if [[ -n "$scene_csv" ]]; then
  IFS=',' read -r -a scenes <<< "$scene_csv"
else
  scenes=()
  while IFS= read -r scene; do
    scenes+=("$scene")
  done < <(python3 - "$repo_root/visual-tests/scenes.json" <<'PY'
import json
import sys
for scene in json.load(open(sys.argv[1], encoding="utf-8"))["scenes"]:
    if "android" in scene["platforms"]:
        print(scene["id"])
PY
  )
fi
for scene in "${scenes[@]}"; do
  stamp+=(--scene "$scene")
done
"${stamp[@]}" >/dev/null

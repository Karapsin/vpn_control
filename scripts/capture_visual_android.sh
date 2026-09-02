#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${1:-$repo_root/build/visual-actual/android}"
scene_csv="${2:-}"
device_dir="/sdcard/Android/data/com.kardinal.vpncontrol/files/visual-capture"

cd "$repo_root"
mkdir -p "$output_dir"
adb shell rm -rf "$device_dir"
./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=com.kardinal.vpncontrol.ui.VisualCaptureInstrumentedTest \
  -Pandroid.testInstrumentationRunnerArguments.visualManifest="$repo_root/visual-tests/scenes.json" \
  -Pandroid.testInstrumentationRunnerArguments.visualScenes="$scene_csv"
adb pull "$device_dir/." "$output_dir/"

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

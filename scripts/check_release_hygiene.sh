#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

bad_paths=()
while IFS= read -r -d '' path; do
  case "$path" in
    build/*|\
    app/build/*|\
    shared/*/build/*|\
    desktopApp/build/*|\
    desktopApp/src/main/resources/bin/*|\
    dist/*|\
    .runtime/*)
      bad_paths+=("$path")
      ;;
  esac
done < <(git ls-files -z)

if (( ${#bad_paths[@]} > 0 )); then
  {
    echo "Generated release/runtime artifacts are tracked by Git."
    echo "Remove these files from the index before packaging:"
    printf ' - %s\n' "${bad_paths[@]}"
  } >&2
  exit 1
fi

bash scripts/check_docs_hygiene.sh
bash scripts/test_arch_install_hygiene.sh
python3 scripts/test_assemble_update_release.py
python3 scripts/test_version_metadata.py
python3 scripts/test_vpn_integration_fixture.py
python3 scripts/test_user_facing_terminology.py
python3 scripts/check_ui_theme.py
python3 scripts/test_visual_regression.py
python3 scripts/test_visual_fleet.py
python3 -m py_compile scripts/visual_fleet.py scripts/visual_regression.py
python3 scripts/check_release_metadata.py
python3 scripts/release_notes.py --version "$(python3 scripts/version_metadata.py --field version)" >/dev/null
bash -n scripts/install_arch_desktop_update.sh
bash -n scripts/package_arch_desktop_update.sh
bash -n scripts/test_arch_desktop_update.sh
bash -n scripts/setup_visual_runner.sh

echo "[vpn-control] release hygiene passed"

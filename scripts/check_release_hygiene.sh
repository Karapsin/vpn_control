#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

bad_paths=()
while IFS= read -r -d '' path; do
  case "$path" in
    build/*|\
    app/build/*|\
    app/.cxx/*|\
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
python3 scripts/test_arch_update_permissions.py
python3 scripts/test_assemble_update_release.py
python3 scripts/test_version_metadata.py
python3 scripts/test_vpn_integration_fixture.py
python3 scripts/test_packaged_cli_harness.py
python3 scripts/test_linux_package_postinst.py
python3 scripts/test_package_linux_deb.py
python3 scripts/test_package_linux_rpm.py
python3 scripts/test_linux_public_install_harness.py
python3 scripts/test_prepare_linux_install_vm.py
python3 scripts/test_prepare_android_native_tools.py
python3 scripts/test_android_update_fixture.py
python3 scripts/test_android_install_visual_inventory.py
python3 scripts/test_desktop_update_fixture.py
python3 scripts/test_fixture_environment.py
python3 scripts/test_jpackage_launcher_harness.py
python3 scripts/test_arch_public_update.py
python3 scripts/test_macos_install_gate.py
python3 scripts/test_macos_install_enospc.py
python3 scripts/test_windows_native_helpers.py
python3 scripts/test_windows_launcher_utf8.py
python3 scripts/test_user_facing_terminology.py
python3 scripts/check_ui_theme.py
python3 scripts/test_visual_regression.py
python3 scripts/test_visual_platform.py
python3 scripts/test_visual_review.py
python3 -m py_compile scripts/visual_platform.py scripts/visual_regression.py scripts/visual_review.py
python3 scripts/check_release_metadata.py
python3 scripts/release_notes.py --version "$(python3 scripts/version_metadata.py --field version)" >/dev/null
bash -n scripts/install_arch_desktop_update.sh
bash -n scripts/package_arch_desktop_update.sh
bash -n scripts/test_arch_desktop_update.sh
bash -n scripts/bootstrap_windows_visual_vm.sh
bash -n scripts/start_windows_visual_vm.sh
bash -n scripts/mark_windows_visual_vm_ready.sh

echo "[vpn-control] release hygiene passed"

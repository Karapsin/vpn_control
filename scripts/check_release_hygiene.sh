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

failed_checks=()
run_check() {
  local status
  if "$@"; then
    return 0
  else
    status=$?
  fi
  # Cancellation must stop the run; ordinary failures are collected so the
  # remaining independent checks can report their own results in this batch.
  case "$status" in 130|143) exit "$status" ;; esac
  failed_checks+=("$* (exit $status)")
  printf '[vpn-control] check failed (%s): %s\n' "$status" "$*" >&2
  return 0
}

run_check python3 scripts/test_source_whitespace.py
run_check python3 scripts/check_source_whitespace.py
run_check python3 scripts/check_workflow_syntax.py
run_check python3 scripts/test_check_workflow_syntax.py
run_check python3 scripts/test_release_hygiene_runner.py
run_check bash scripts/check_docs_hygiene.sh
run_check bash scripts/test_arch_install_hygiene.sh
run_check python3 scripts/test_arch_update_permissions.py
run_check python3 scripts/test_assemble_update_release.py
run_check python3 scripts/test_version_metadata.py
run_check python3 scripts/test_vpn_integration_fixture.py
run_check python3 scripts/test_https_subscription_relay_fixture.py
run_check python3 scripts/test_desktop_scheduled_refresh_fixture.py
run_check python3 scripts/test_packaged_cli_harness.py
run_check python3 scripts/test_linux_package_postinst.py
run_check python3 scripts/test_package_linux_deb.py
run_check python3 scripts/test_package_linux_rpm.py
run_check python3 scripts/test_linux_public_install_harness.py
run_check python3 scripts/test_linux_fixture_owner_readiness.py
run_check python3 scripts/test_linux_fixture_runtime_config.py
run_check python3 scripts/test_linux_public_install_fixture.py
run_check python3 scripts/test_windows_fixture_stage_acl.py
run_check python3 scripts/test_guest_build_connect_proxy.py
run_check python3 scripts/test_guest_fixture_input.py
run_check python3 scripts/test_linux_gui_fixture_guard.py
run_check python3 scripts/test_linux_vpn_fixture_guard.py
run_check python3 scripts/test_prepare_linux_install_vm.py
run_check python3 scripts/test_prepare_android_native_tools.py
run_check python3 scripts/test_android_avd_sdk_preflight.py
run_check python3 scripts/test_android_update_fixture.py
run_check python3 scripts/test_android_native_fixture_build_type.py
run_check python3 -m unittest scripts.test_android_benchmark_fixture
run_check python3 -m unittest scripts.test_android_public_control_fixture
run_check python3 scripts/test_android_fixture_preflight.py
run_check python3 scripts/test_android_fixture_transport.py
run_check python3 scripts/test_android_fixture_trust.py
run_check python3 scripts/test_android_no_update_tls_preflight.py
run_check python3 scripts/test_android_installer_lifecycle.py
run_check python3 scripts/test_android_subscription_refresh_lifecycle.py
run_check python3 scripts/test_native_python_tests.py
run_check python3 scripts/test_macos_fixture_owner_launch.py
run_check python3 scripts/test_macos_fixture_processes.py
run_check python3 scripts/test_macos_vm_resource_monitor.py
run_check python3 scripts/test_python_platform_contracts.py
run_check python3 scripts/check_python_platform_contracts.py
run_check python3 scripts/test_native_fixture_preflight_script.py
run_check python3 scripts/test_linux_scheduled_refresh_scenario.py
run_check python3 scripts/test_native_fixture_run.py
run_check python3 scripts/test_native_fixture_qga.py
run_check python3 scripts/test_windows_credential_validity_qga.py
run_check python3 scripts/test_capture_visual_windows_qemu.py
run_check python3 scripts/test_native_fixture_qemu_assets.py
run_check python3 scripts/test_macos_packaging_jdk_preflight.py
run_check python3 scripts/test_macos_install_worker_target.py
run_check python3 scripts/test_android_routing_evidence.py
run_check python3 scripts/test_android_install_visual_inventory.py
run_check python3 scripts/test_desktop_update_fixture.py
run_check python3 scripts/test_fixture_environment.py
run_check python3 scripts/test_jpackage_launcher_harness.py
run_check python3 scripts/test_arch_public_update.py
run_check python3 scripts/test_rpm_public_update.py
run_check python3 scripts/test_linux_fixture_auth.py
run_check python3 scripts/test_macos_install_gate.py
run_check python3 scripts/test_macos_install_enospc.py
run_check python3 scripts/test_macos_package_cleanup.py
run_check python3 scripts/test_macos_aqua_authorization_correlation.py
run_check python3 scripts/test_windows_update_fixture_workflow.py
run_check python3 scripts/test_macos_update_fixture_workflow.py
run_check python3 scripts/test_record_macos_fixture_signing.py
run_check python3 scripts/test_setup_macos_signing.py
run_check python3 scripts/test_windows_native_helpers.py
run_check python3 scripts/test_windows_native_fixture.py
run_check python3 scripts/test_windows_prompt_observation.py
run_check python3 scripts/test_native_fixture_manifest.py
run_check python3 scripts/test_native_fixture_archive.py
run_check python3 scripts/test_native_fixture_payload.py
run_check python3 scripts/test_macos_rollback_fixture.py
run_check python3 scripts/test_windows_broker_fixture_observer.py
run_check python3 scripts/test_native_jvm_tests.py
run_check python3 scripts/test_native_fixture_signal.py
run_check python3 scripts/test_android_ssh_fixture.py
run_check python3 scripts/test_android_instrumented_launcher.py
run_check python3 scripts/test_macos_fixture_frontend.py
run_check python3 scripts/test_windows_launcher_utf8.py
run_check python3 scripts/test_user_facing_terminology.py
run_check python3 scripts/check_ui_theme.py
run_check python3 scripts/test_visual_regression.py
run_check python3 scripts/test_visual_platform.py
run_check python3 scripts/test_android_visual_geometry.py
run_check python3 scripts/test_visual_review.py
run_check python3 -m py_compile scripts/visual_platform.py scripts/visual_regression.py scripts/visual_review.py
run_check python3 scripts/check_release_metadata.py
run_check python3 scripts/release_notes.py --version "$(python3 scripts/version_metadata.py --field version)" >/dev/null
run_check bash -n scripts/install_arch_desktop_update.sh
run_check bash -n scripts/package_arch_desktop_update.sh
run_check bash -n scripts/test_arch_desktop_update.sh
run_check bash -n scripts/bootstrap_windows_visual_vm.sh
run_check bash -n scripts/start_windows_visual_vm.sh
run_check bash -n scripts/mark_windows_visual_vm_ready.sh

if (( ${#failed_checks[@]} > 0 )); then
  printf '[vpn-control] failed check: %s\n' "${failed_checks[@]}" >&2
  exit 1
fi

echo "[vpn-control] release hygiene passed"

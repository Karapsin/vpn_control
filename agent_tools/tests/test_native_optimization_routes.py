import unittest
from unittest.mock import patch

from agent_tools import mcp_server


class NativeOptimizationRoutesTest(unittest.TestCase):
    def test_preflight_routes_current_readiness_without_promoting_failure(self):
        from agent_tools import native_fixture_preflight
        request = {"scenarioId": "linux-public-update-preflight"}
        with patch.object(native_fixture_preflight, "check", return_value={"ready": False}) as check:
            result = mcp_server._vm_workflow_impl("fixture-preflight", request)
        self.assertFalse(result["ok"])
        check.assert_called_once_with(mcp_server.REPO_ROOT, request, mcp_server._native_fixed_dispatch)

    def test_artifact_mismatch_and_rebuild_are_not_success(self):
        from agent_tools import native_artifact_reuse
        with patch.object(native_artifact_reuse, "artifact_set_verify", return_value={"verification": "mismatch"}):
            self.assertFalse(mcp_server._vm_workflow_impl("artifact-set-verify", {"artifactSetId": "id"})["ok"])
        with patch.object(native_artifact_reuse, "artifact_reuse_check", return_value={"decision": "rebuild-required"}):
            self.assertFalse(mcp_server._vm_workflow_impl("artifact-reuse-check", {"artifactSetId": "id"})["ok"])

    def test_rpm_proc_observation_keeps_unreadable_processes_unknown(self):
        from agent_tools import native_rpm_public_install_ssh
        request = {"host": "fedora2328", "environment": "fedora2328"}
        with patch.object(native_rpm_public_install_ssh, "observe_proc", return_value={"ok": True, "procState": "unknown", "uninspectable": [{"pid": 123}]}) as observe:
            result = mcp_server._vm_workflow_impl("rpm-proc-observe", request)
        self.assertFalse(result["ok"])
        self.assertEqual("unknown", result["procState"])
        self.assertEqual("unknown", result["state"])
        observe.assert_called_once_with(mcp_server.REPO_ROOT, request)
        with patch.object(native_rpm_public_install_ssh, "observe_proc", return_value={"procState": "clear", "uninspectable": []}):
            self.assertTrue(mcp_server._vm_workflow_impl("rpm-proc-observe", request)["ok"])

    def test_privileged_rpm_proc_observer_only_promotes_clear_state(self):
        from agent_tools import native_rpm_public_install_ssh
        request = {"host": "fedora2328", "environment": "fedora2328"}
        with patch.object(native_rpm_public_install_ssh, "observe_proc_privileged", return_value={"ok": True, "procState": "unknown"}) as observe:
            result = mcp_server._vm_workflow_impl("rpm-proc-observe-privileged", request)
            self.assertFalse(result["ok"])
            self.assertEqual("unknown", result["state"])
            observe.assert_called_once_with(mcp_server.REPO_ROOT, request)
        with patch.object(native_rpm_public_install_ssh, "observe_proc_privileged", return_value={"procState": "clear"}):
            self.assertTrue(mcp_server._vm_workflow_impl("rpm-proc-observe-privileged", request)["ok"])

    def test_linux_fixture_route_distinguishes_dispatch_uncertainty_from_verified_artifact(self):
        from agent_tools import linux_update_fixture_workflow
        request = {"sourceSha": "a" * 40, "baseVersion": "2.1.19", "correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
        with patch.object(linux_update_fixture_workflow, "dispatch", return_value={"state": "unknown", "replayAllowed": False}) as dispatch:
            result = mcp_server._vm_workflow_impl("linux-rpm-fixture-dispatch", request)
            self.assertFalse(result["ok"])
            self.assertFalse(result["replayAllowed"])
            dispatch.assert_called_once_with(mcp_server.REPO_ROOT, request)
        with patch.object(linux_update_fixture_workflow, "status", return_value={"state": "complete", "artifactId": 81}) as status:
            result = mcp_server._vm_workflow_impl("linux-rpm-fixture-status", {"correlationId": request["correlationId"]})
            self.assertTrue(result["ok"])
            self.assertEqual("fixture-build", result["evidenceClass"])
            status.assert_called_once_with(mcp_server.REPO_ROOT, {"correlationId": request["correlationId"]})
        with patch.object(linux_update_fixture_workflow, "status", side_effect=ValueError("Invalid inputs")):
            self.assertFalse(mcp_server._vm_workflow_impl("linux-rpm-fixture-status", {"correlationId": request["correlationId"], "shell": "id"})["ok"])

    def test_linux_base_prepare_route_preserves_no_replay_and_terminal_failure(self):
        from agent_tools import linux_rpm_base_prepare
        preflight = {"host": "fedora2328", "environment": "fedora2328",
                     "expectedCurrentNevra": "vpn-control-2.1.17-1.x86_64"}
        with patch.object(linux_rpm_base_prepare, "preflight", return_value={"state": "ready"}) as observe:
            result = mcp_server._vm_workflow_impl("linux-rpm-base-prepare-preflight", preflight)
            self.assertTrue(result["ok"])
            self.assertFalse(result["productAction"])
            observe.assert_called_once_with(mcp_server.REPO_ROOT, preflight)
        request = {"host": "fedora2328", "environment": "fedora2328", "baseArtifactId": "sha256-" + "a" * 64,
                   "sourceSha": "b" * 40, "sourceFingerprint": "c" * 64,
                   "expectedCurrentNevra": "vpn-control-2.1.17-1.x86_64",
                   "expectedBaseNevra": "vpn-control-2.1.19-1.x86_64",
                   "correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
        with patch.object(linux_rpm_base_prepare, "start", return_value={"state": "unknown", "replayAllowed": False}) as start:
            result = mcp_server._vm_workflow_impl("linux-rpm-base-prepare-start", request)
            self.assertFalse(result["ok"])
            self.assertFalse(result["replayAllowed"])
            start.assert_called_once_with(mcp_server.REPO_ROOT, request)
        with patch.object(linux_rpm_base_prepare, "status", return_value={"state": "terminal", "result": "failed"}) as status:
            result = mcp_server._vm_workflow_impl("linux-rpm-base-prepare-status", {"correlationId": request["correlationId"]})
            self.assertFalse(result["ok"])
            self.assertFalse(result["productAction"])
            status.assert_called_once_with(mcp_server.REPO_ROOT, {"correlationId": request["correlationId"]})
        with patch.object(linux_rpm_base_prepare, "status", side_effect=ValueError("Invalid fields")) as status:
            self.assertFalse(mcp_server._vm_workflow_impl("linux-rpm-base-prepare-status", {"correlationId": request["correlationId"], "command": "rpm"})["ok"])
            status.assert_called_once_with(mcp_server.REPO_ROOT, {"correlationId": request["correlationId"], "command": "rpm"})

    def test_linux_owner_observation_is_read_only_and_requires_observed_state(self):
        from agent_tools import linux_rpm_base_prepare
        request = {"host": "fedora2328", "environment": "fedora2328", "pid": 18367, "startTicks": 2078693}
        with patch.object(linux_rpm_base_prepare, "observe_owner", return_value={"state": "unknown"}) as observe:
            result = mcp_server._vm_workflow_impl("linux-rpm-owner-observe", request)
            self.assertFalse(result["ok"])
            self.assertFalse(result["productAction"])
            observe.assert_called_once_with(mcp_server.REPO_ROOT, request)
        with patch.object(linux_rpm_base_prepare, "observe_owner", return_value={"state": "observed", "runtimeRunning": False}):
            self.assertTrue(mcp_server._vm_workflow_impl("linux-rpm-owner-observe", request)["ok"])

    def test_android_admission_readback_requires_exact_inputs_and_actual_admission(self):
        from agent_tools import android_admission_readback
        request = {"host": "archlinux", "device": "api35", "correlationId": "ad399bdd-25cb-4f71-857e-34ad18ae0399"}
        with patch.object(android_admission_readback, "readback", return_value={"ok": True, "outcome": "unknown"}) as readback:
            unknown = mcp_server._vm_workflow_impl("android-admission-readback", request)
            self.assertFalse(unknown["ok"])
            self.assertEqual("unknown", unknown["state"])
            readback.assert_called_once_with(mcp_server.REPO_ROOT, "archlinux", "api35", request["correlationId"],
                expected_base_sha256=None, timeout_seconds=45)
        with patch.object(android_admission_readback, "readback") as readback:
            self.assertFalse(mcp_server._vm_workflow_impl("android-admission-readback", {**request, "shell": "id"})["ok"])
            readback.assert_not_called()
        with patch.object(android_admission_readback, "readback", return_value={"outcome": "admitted"}):
            self.assertTrue(mcp_server._vm_workflow_impl("android-admission-readback", request)["ok"])

    def test_android_admission_status_observes_exact_correlation_without_replay(self):
        from agent_tools import android_admission_readback
        request = {"host": "archlinux", "device": "api35", "correlationId": "a4a2f73c-6c99-4028-a846-a4c63f21f6d6"}
        with patch.object(android_admission_readback, "readback_status", return_value={"ok": False, "outcome": "unknown"}) as observe:
            result = mcp_server._vm_workflow_impl("android-admission-status", request)
            self.assertFalse(result["ok"])
            self.assertEqual("unknown", result["state"])
            observe.assert_called_once_with(mcp_server.REPO_ROOT, request["host"], request["device"], request["correlationId"], timeout_seconds=45)
        with patch.object(android_admission_readback, "readback_status") as observe:
            self.assertFalse(mcp_server._vm_workflow_impl("android-admission-status", {**request, "newRequest": True})["ok"])
            observe.assert_not_called()

    def test_android_admission_preflight_preserves_completed_stages_on_timeout(self):
        from agent_tools import android_admission_readback
        request = {"host": "archlinux", "device": "api35", "correlationId": "a4a2f73c-6c99-4028-a846-a4c63f21f6d6"}
        stage = {"stage": "uid", "ok": True}
        with patch.object(android_admission_readback, "preflight", return_value={"ok": True, "outcome": "unknown", "completedStages": [stage]}) as preflight:
            result = mcp_server._vm_workflow_impl("android-admission-preflight", request)
            self.assertFalse(result["ok"])
            self.assertEqual("unknown", result["state"])
            self.assertEqual([stage], result["completedStages"])
            preflight.assert_called_once_with(mcp_server.REPO_ROOT, "archlinux", "api35", request["correlationId"], timeout_seconds=60)
        with patch.object(android_admission_readback, "preflight") as preflight:
            self.assertFalse(mcp_server._vm_workflow_impl("android-admission-preflight", {**request, "command": "shell"})["ok"])
            preflight.assert_not_called()

    def test_android_async_readback_routes_exact_nonreplaying_correlation(self):
        from agent_tools import android_admission_readback
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        request = {"host": "archlinux", "device": "api35", "correlationId": correlation,
                   "expectedBaseSha256": "a" * 64}
        with patch.object(android_admission_readback, "async_start", return_value={"ok": False, "state": "unknown", "replayAllowed": False}) as start:
            result = mcp_server._vm_workflow_impl("android-readback-start", request)
            self.assertFalse(result["ok"])
            self.assertFalse(result["replayAllowed"])
            start.assert_called_once_with(mcp_server.REPO_ROOT, "archlinux", "api35", correlation, "a" * 64)
        with patch.object(android_admission_readback, "async_start") as start:
            self.assertFalse(mcp_server._vm_workflow_impl("android-readback-start", {**request, "shell": "id"})["ok"])
            start.assert_not_called()
        with patch.object(android_admission_readback, "async_status", return_value={"ok": False, "state": "running", "replayAllowed": False}) as status:
            result = mcp_server._vm_workflow_impl("android-readback-status", {"correlationId": correlation})
            self.assertTrue(result["ok"])
            self.assertEqual("running", result["state"])
            self.assertFalse(result["admissionReady"])
            status.assert_called_once_with(mcp_server.REPO_ROOT, correlation)
        with patch.object(android_admission_readback, "async_collect", return_value={"ok": True, "state": "complete", "replayAllowed": False}) as collect:
            result = mcp_server._vm_workflow_impl("android-readback-collect", {"correlationId": correlation})
            self.assertTrue(result["ok"])
            self.assertTrue(result["admissionReady"])
            self.assertFalse(result["productAction"])
            collect.assert_called_once_with(mcp_server.REPO_ROOT, correlation)

    def test_android_package_install_route_never_promotes_unknown_or_collect_to_mutation_admission(self):
        from agent_tools import android_package_install
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        request = {"host": "archlinux", "device": "api35", "correlationId": correlation,
                   "artifactId": "sha256-" + "b" * 64, "stageIdentity": {"correlationId": "stage"},
                   "backupCorrelationId": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                   "expectedBackupSha256": "d" * 64, "expectedOldBaseSha256": "e" * 64,
                   "expectedOwner": "owner", "expectedRevision": 2}
        with patch.object(android_package_install, "start", return_value={"ok": False, "state": "unknown", "replayAllowed": False}) as start:
            result = mcp_server._vm_workflow_impl("android-package-install-start", request)
            self.assertFalse(result["ok"])
            self.assertFalse(result["replayAllowed"])
            start.assert_called_once()
        with patch.object(android_package_install, "start") as start:
            self.assertFalse(mcp_server._vm_workflow_impl("android-package-install-start", {**request, "shell": "id"})["ok"])
            start.assert_not_called()
        with patch.object(android_package_install, "collect", return_value={"ok": True, "state": "complete", "admissionReady": False}) as collect:
            result = mcp_server._vm_workflow_impl("android-package-install-collect", {"correlationId": correlation})
            self.assertTrue(result["ok"])
            self.assertFalse(result["admissionReady"])
            self.assertFalse(result["productAction"])
            collect.assert_called_once_with(mcp_server.REPO_ROOT, correlation)

    def test_android_public_inspect_routes_only_bounded_readonly_request(self):
        from agent_tools import android_public_inspect
        request = {"host": "archlinux", "device": "api29", "correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                   "expectedBaseSha256": "b" * 64, "expectedOwner": "owner", "expectedRevision": 0}
        with patch.object(android_public_inspect, "inspect", return_value={"ok": True, "outcome": "admitted", "nativeMutationAllowed": False}) as inspect:
            result = mcp_server._vm_workflow_impl("android-public-inspect", request)
            self.assertTrue(result["ok"])
            self.assertFalse(result["productAction"])
            self.assertFalse(result["nativeMutationAllowed"])
            inspect.assert_called_once_with(mcp_server.REPO_ROOT, "archlinux", "api29", request["correlationId"],
                "b" * 64, "owner", 0, timeout_seconds=60)
        with patch.object(android_public_inspect, "inspect", return_value={"ok": False, "outcome": "unknown", "nativeMutationAllowed": False}):
            self.assertFalse(mcp_server._vm_workflow_impl("android-public-inspect", request)["ok"])
        with patch.object(android_public_inspect, "inspect") as inspect:
            self.assertFalse(mcp_server._vm_workflow_impl("android-public-inspect", {**request, "command": "on"})["ok"])
            inspect.assert_not_called()

    def test_windows_msi_preinstall_status_only_accepts_exact_readonly_job(self):
        from agent_tools import windows_msi_public_scenario
        request = {"host": "archlinux", "jobId": "9107428f-9c80-4284-9f4e-926350105a59"}
        with patch.object(windows_msi_public_scenario, "preinstall_status", return_value={"state": "unknown"}) as observe:
            self.assertFalse(mcp_server._vm_workflow_impl("windows-msi-preinstall-status", request)["ok"])
            observe.assert_called_once_with(mcp_server.REPO_ROOT, request["host"], request["jobId"], timeout_seconds=15)
        with patch.object(windows_msi_public_scenario, "preinstall_status") as observe:
            self.assertFalse(mcp_server._vm_workflow_impl("windows-msi-preinstall-status", {**request, "command": "guest-exec"})["ok"])
            observe.assert_not_called()
        with patch.object(windows_msi_public_scenario, "preinstall_status", return_value={"state": "observed"}):
            self.assertTrue(mcp_server._vm_workflow_impl("windows-msi-preinstall-status", request)["ok"])

    def test_windows_powershell_preflight_is_fixed_and_cannot_promote_failure(self):
        from agent_tools import windows_msi_public_scenario
        with patch.object(windows_msi_public_scenario, "powershell_preflight", return_value={"state": "failed"}) as preflight:
            self.assertFalse(mcp_server._vm_workflow_impl("windows-msi-powershell-preflight", {"host": "archlinux"})["ok"])
            preflight.assert_called_once_with(mcp_server.REPO_ROOT, {"host": "archlinux"})
        with patch.object(windows_msi_public_scenario, "powershell_preflight") as preflight:
            self.assertFalse(mcp_server._vm_workflow_impl("windows-msi-powershell-preflight", {"host": "archlinux", "command": "install"})["ok"])
            preflight.assert_not_called()
        with patch.object(windows_msi_public_scenario, "powershell_preflight", return_value={"state": "passed", "checks": ["gzip", "utf8"]}):
            result = mcp_server._vm_workflow_impl("windows-msi-powershell-preflight", {"host": "archlinux"})
            self.assertTrue(result["ok"])
            self.assertFalse(result["productAction"])

    def test_windows_msi_public_route_keeps_uncertain_submission_and_terminal_observation_distinct(self):
        from agent_tools import windows_msi_public_scenario
        start_request = {"host": "archlinux", "correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                         "sourceSha": "a" * 40, "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
                         "baseMsiArtifactId": "sha256-" + "c" * 64, "targetMsiArtifactId": "sha256-" + "d" * 64}
        with patch.object(windows_msi_public_scenario, "start", return_value={"state": "unknown", "replayAllowed": False}) as submit:
            result = mcp_server._vm_workflow_impl("windows-msi-public-start", start_request)
            self.assertFalse(result["ok"])
            self.assertFalse(result["replayAllowed"])
            submit.assert_called_once_with(mcp_server.REPO_ROOT, start_request)
        with patch.object(windows_msi_public_scenario, "status", return_value={"state": "observed", "phase": "protected-terminal", "installedVerified": False}):
            result = mcp_server._vm_workflow_impl("windows-msi-public-status", {"host": "archlinux", "correlationId": start_request["correlationId"]})
            self.assertTrue(result["ok"])
            self.assertFalse(result["productAction"])
            self.assertFalse(result["installedVerified"])
        with patch.object(windows_msi_public_scenario, "collect", return_value={"state": "observed", "collected": True, "installedVerified": False}):
            self.assertFalse(mcp_server._vm_workflow_impl("windows-msi-public-collect", {"host": "archlinux", "correlationId": start_request["correlationId"]})["installedVerified"])

    def test_windows_base_route_requires_inert_preflight_and_never_replays_unknown(self):
        from agent_tools import windows_msi_base_prepare
        request = {"host": "archlinux", "correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                   "sourceSha": "a" * 40, "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
                   "baseMsiArtifactId": "sha256-" + "c" * 64,
                   "targetMsiArtifactId": "sha256-" + "d" * 64, "expectedCurrentVersion": "2.1.17"}
        with patch.object(windows_msi_base_prepare, "powershell_preflight", return_value={"state": "passed"}) as preflight:
            result = mcp_server._vm_workflow_impl("windows-msi-base-preflight", {"host": "archlinux"})
            self.assertTrue(result["ok"])
            self.assertFalse(result["productAction"])
            preflight.assert_called_once_with(mcp_server.REPO_ROOT, {"host": "archlinux"})
        with patch.object(windows_msi_base_prepare, "start", return_value={"state": "unknown", "replayAllowed": False}) as start:
            result = mcp_server._vm_workflow_impl("windows-msi-base-start", request)
            self.assertFalse(result["ok"])
            self.assertFalse(result["replayAllowed"])
            start.assert_called_once_with(mcp_server.REPO_ROOT, request)
        with patch.object(windows_msi_base_prepare, "status", return_value={"state": "terminal", "result": "FAILED"}) as status:
            result = mcp_server._vm_workflow_impl("windows-msi-base-status", {"correlationId": request["correlationId"]})
            self.assertFalse(result["ok"])
            self.assertFalse(result["productAction"])
            status.assert_called_once_with(mcp_server.REPO_ROOT, {"correlationId": request["correlationId"]})

    def test_batch_observation_does_not_accept_replacement_plan(self):
        from agent_tools import native_scenario_batch
        with patch.object(native_scenario_batch.NativeScenarioBatch, "status") as status:
            result = mcp_server._vm_workflow_impl("batch-status", {"batchId": "owned", "recipe": "replacement"})
        self.assertFalse(result["ok"])
        status.assert_not_called()

    def test_batch_failure_and_unknown_are_not_successful_completion(self):
        from agent_tools import native_scenario_batch
        for state in ("failed", "blocked", "unknown"):
            with self.subTest(state=state), patch.object(native_scenario_batch.NativeScenarioBatch, "status", return_value={"state": state}):
                self.assertFalse(mcp_server._vm_workflow_impl("batch-status", {"batchId": "owned"})["ok"])

    def test_fixed_dispatch_rejects_arbitrary_and_recursive_execution(self):
        for surface, action in (("shell", "exec"), ("vm", "baseline-restore"),
                                ("vm", "batch-start"), ("ssh", "apk-publish")):
            with self.subTest(surface=surface, action=action), self.assertRaises(ValueError):
                mcp_server._native_fixed_dispatch(surface, action, {})

    def test_fixed_dispatch_forwards_only_existing_adapter(self):
        with patch.object(mcp_server, "_ssh_workflow_impl", return_value={"available": True}) as probe:
            result = mcp_server._native_fixed_dispatch("ssh", "probe", {"host": "owned", "timeout_seconds": 15})
        self.assertTrue(result["available"])
        probe.assert_called_once_with(action="probe", host="owned", timeout_seconds=15)

    def test_matrix_status_is_read_only_and_does_not_assert_gate_success(self):
        from agent_tools import native_acceptance_matrix
        with patch.object(mcp_server.subprocess, "check_output", return_value="a" * 40), patch.object(native_acceptance_matrix, "matrix_status", return_value={"gate": "open"}) as status:
            result = mcp_server._vm_workflow_impl("matrix-status", {"sourceSha": "a" * 40})
        self.assertTrue(result["ok"])
        self.assertEqual("open", result["gate"])
        status.assert_called_once_with(mcp_server.REPO_ROOT, "a" * 40)

    def test_matrix_retract_routes_exact_reviewed_correction(self):
        from agent_tools import native_acceptance_matrix
        correction = {"receiptId": "native-acceptance-" + "a" * 32,
                      "reason": "Scenario was not observed", "reviewer": "maintainer"}
        with patch.object(native_acceptance_matrix, "matrix_retract", return_value={"receiptId": correction["receiptId"]}) as retract:
            result = mcp_server._vm_workflow_impl("matrix-retract", correction)
            self.assertTrue(result["ok"])
            retract.assert_called_once_with(mcp_server.REPO_ROOT, correction)
        with patch.object(native_acceptance_matrix, "matrix_retract", side_effect=native_acceptance_matrix.NativeAcceptanceMatrixError("bad correction")):
            result = mcp_server._vm_workflow_impl("matrix-retract", {**correction, "extra": "unsafe"})
            self.assertFalse(result["ok"])

    def test_matrix_cannot_present_old_sha_as_current_acceptance(self):
        from agent_tools import native_acceptance_matrix
        with patch.object(mcp_server.subprocess, "check_output", return_value="b" * 40), patch.object(native_acceptance_matrix, "matrix_status") as status:
            result = mcp_server._vm_workflow_impl("matrix-status", {"sourceSha": "a" * 40})
        self.assertFalse(result["ok"])
        status.assert_not_called()

    def test_reuse_success_is_explicitly_bytes_only_until_native_admission(self):
        from agent_tools import native_artifact_reuse
        with patch.object(native_artifact_reuse, "artifact_reuse_check", return_value={"decision": "verified-equivalent-product-inputs", "nativeAdmissionReady": False}):
            result = mcp_server._vm_workflow_impl("artifact-reuse-check", {"artifactSetId": "id"})
        self.assertTrue(result["ok"])
        self.assertEqual("artifact-byte-reuse", result["evidenceScope"])
        self.assertFalse(result["nativeAdmissionReady"])

    def test_baselines_use_configured_backend_only(self):
        from agent_tools import native_vm_baseline_config
        request = {"provider": "tart", "sourceId": "owned"}
        with patch.object(native_vm_baseline_config, "handle", return_value={"state": "ready"}) as handle:
            mcp_server._vm_workflow_impl("baseline-preflight", request)
        handle.assert_called_once_with(mcp_server.REPO_ROOT, "baseline-preflight", request)


if __name__ == "__main__":
    unittest.main()

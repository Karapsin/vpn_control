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

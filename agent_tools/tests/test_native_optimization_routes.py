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

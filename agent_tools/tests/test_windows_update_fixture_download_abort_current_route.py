"""MCP boundary for the isolated current failed-download recovery adapter."""
import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_update_fixture_download_abort_current as current


CORR = current._CORRELATION
REQUEST = {"correlationId": CORR}
FLAGS = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
PREFIX = "windows-update-fixture-download-abort-current"


class CurrentDownloadAbortRouteTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start()
        self.addCleanup(guard.stop)

    def test_cleanup_status_and_action_use_only_the_current_correlation(self):
        status = {"state": "diagnosed", "correlationId": CORR, "phase": "ready",
                  "cleanupAllowed": True, **FLAGS}
        with patch.object(current, "task_cleanup_status", return_value=status) as call:
            result = mcp_server._vm_workflow_impl(PREFIX + "-task-cleanup-status", REQUEST)
        call.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
        self.assertTrue(result["ok"])
        cleaned = {"state": "cleaned", "correlationId": CORR, **FLAGS}
        with patch.object(current, "task_cleanup", return_value=cleaned) as call:
            result = mcp_server._vm_workflow_impl(PREFIX + "-task-cleanup", REQUEST)
        call.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
        self.assertTrue(result["ok"])
        self.assertEqual("causal-cleanup", result["evidenceClass"])

    def test_abort_status_and_action_have_finite_projections(self):
        status = {"state": "diagnosed", "correlationId": CORR, "phase": "ready-pending",
                  "abortAllowed": True, **FLAGS}
        with patch.object(current, "status", return_value=status) as call:
            result = mcp_server._vm_workflow_impl(PREFIX + "-status", REQUEST)
        call.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
        self.assertTrue(result["ok"])
        retired = {"state": "retired", "correlationId": CORR,
                   "cleanupReceiptSha256": "a" * 64, **FLAGS}
        with patch.object(current, "abort", return_value=retired) as call:
            result = mcp_server._vm_workflow_impl(PREFIX, REQUEST)
        call.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
        self.assertTrue(result["ok"])
        self.assertEqual("native-campaign", result["evidenceClass"])

    def test_rejects_private_results_invalid_phase_flags_and_any_other_correlation(self):
        cleanup_status = {"state": "diagnosed", "correlationId": CORR, "phase": "ready",
                          "cleanupAllowed": True, **FLAGS}
        abort_status = {"state": "diagnosed", "correlationId": CORR, "phase": "ready",
                        "abortAllowed": True, **FLAGS}
        for action, method, observed in ((PREFIX + "-task-cleanup-status", "task_cleanup_status", cleanup_status),
                                         (PREFIX + "-status", "status", abort_status)):
            for poisoned in ({**observed, "phase": "private-phase"},
                             {**observed, "private": "secret"},
                             {**observed, list({"cleanupAllowed", "abortAllowed"} & set(observed))[0]: False}):
                with self.subTest(action=action, poisoned=poisoned), patch.object(current, method, return_value=poisoned):
                    rejected = mcp_server._vm_workflow_impl(action, REQUEST)
                self.assertFalse(rejected["ok"])
                self.assertNotIn("private", str(rejected))
        with patch.object(current, "abort", side_effect=AssertionError("unsafe dispatch")):
            for request in ({}, {"correlationId": "af3360e5-a53b-4cd2-b91a-4c6abfd6b118"},
                            {**REQUEST, "retry": False}, {"correlationId": 4}):
                with self.subTest(request=request):
                    result = mcp_server._vm_workflow_impl(PREFIX, request)
                self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()

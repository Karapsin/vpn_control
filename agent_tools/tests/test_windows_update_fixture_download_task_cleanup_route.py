"""MCP boundary for the fixed failed-download scheduled-task cleanup."""
import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_update_fixture_download_abort as download_abort


CORR = download_abort._CORRELATION
REQUEST = {"correlationId": CORR}
FLAGS = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}


class DownloadTaskCleanupRouteTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start()
        self.addCleanup(guard.stop)

    def test_status_is_exact_read_only_and_projects_finite_admission(self):
        observed = {"state": "diagnosed", "correlationId": CORR, "phase": "ready",
                    "cleanupAllowed": True, **FLAGS}
        with patch.object(download_abort, "task_cleanup_status", return_value=observed) as status:
            result = mcp_server._vm_workflow_impl("windows-update-fixture-download-task-cleanup-status", REQUEST)
        status.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
        self.assertTrue(result["ok"])
        self.assertEqual("causal-diagnostic", result["evidenceClass"])
        phases = ("binding", "guest-not-safe", "endpoint", "task-absent-unbound", "cleaned",
                  "diagnostic-task-failed", "diagnostic-task-principal-mismatch",
                  "diagnostic-download-complete", "diagnostic-qga-wrapper-timeout", "unknown")
        for phase in phases:
            with self.subTest(phase=phase), patch.object(download_abort, "task_cleanup_status", return_value={
                    **observed, "phase": phase, "cleanupAllowed": False}):
                projected = mcp_server._vm_workflow_impl(
                    "windows-update-fixture-download-task-cleanup-status", REQUEST)
            self.assertTrue(projected["ok"])
        for poisoned in ({**observed, "phase": "diagnostic-private"},
                         {**observed, "cleanupAllowed": False}, {**observed, "private": "secret"}):
            with self.subTest(poisoned=poisoned), patch.object(
                    download_abort, "task_cleanup_status", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl(
                    "windows-update-fixture-download-task-cleanup-status", REQUEST)
            self.assertFalse(rejected["ok"])
            self.assertNotIn("private", str(rejected))

    def test_cleanup_accepts_only_cleaned_or_unknown(self):
        cleaned = {"state": "cleaned", "correlationId": CORR, **FLAGS}
        with patch.object(download_abort, "task_cleanup", return_value=cleaned) as cleanup:
            result = mcp_server._vm_workflow_impl("windows-update-fixture-download-task-cleanup", REQUEST)
        cleanup.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
        self.assertTrue(result["ok"])
        self.assertEqual("causal-cleanup", result["evidenceClass"])
        unknown = {"state": "unknown", "correlationId": CORR, **FLAGS}
        with patch.object(download_abort, "task_cleanup", return_value=unknown):
            result = mcp_server._vm_workflow_impl("windows-update-fixture-download-task-cleanup", REQUEST)
        self.assertFalse(result["ok"])
        for poisoned in ({**cleaned, "nativeActionAllowed": True}, {**cleaned, "private": "secret"}):
            with self.subTest(poisoned=poisoned), patch.object(download_abort, "task_cleanup", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl("windows-update-fixture-download-task-cleanup", REQUEST)
            self.assertFalse(rejected["ok"])
            self.assertNotIn("private", str(rejected))

    def test_rejects_changed_request_before_dispatch(self):
        with patch.object(download_abort, "task_cleanup", side_effect=AssertionError("unsafe dispatch")):
            for request in ({}, {"correlationId": "00000000-0000-4000-8000-000000000000"},
                            {**REQUEST, "retry": False}, {"correlationId": 1}):
                with self.subTest(request=request):
                    result = mcp_server._vm_workflow_impl("windows-update-fixture-download-task-cleanup", request)
                self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()

"""MCP boundary tests for the one-use CP117 download-abort action."""
import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_update_fixture_download_abort as download_abort


CORR = download_abort._CORRELATION
REQUEST = {"correlationId": CORR}
FLAGS = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}


class DownloadAbortRouteTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start()
        self.addCleanup(guard.stop)

    def test_status_is_exact_read_only_and_projects_bounded_phases(self):
        observed = {"state": "diagnosed", "correlationId": CORR, "phase": "ready",
                    "abortAllowed": True, **FLAGS}
        with patch.object(download_abort, "status", return_value=observed) as status:
            result = mcp_server._vm_workflow_impl("windows-update-fixture-download-abort-status", REQUEST)
        status.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
        self.assertTrue(result["ok"])
        self.assertFalse(result["nativeActionAllowed"])
        self.assertEqual("causal-diagnostic", result["evidenceClass"])

        phases = ("binding", "shared-phase", "listener-absent", "listener-listening", "listener-served",
                  "listener-stopped", "listener-unknown", "guest-task-present",
                  "guest-empty", "guest-bootstrap-present", "guest-runtime-or-installer-present",
                  "guest-unknown", "campaign", "retired-binding-invalid", "retired-marker",
                  "pending-finish", "pending-finish-marker", "ready-pending", "ready-cleaned",
                  "retired", "unknown")
        for phase in phases:
            with self.subTest(phase=phase), patch.object(download_abort, "status", return_value={
                    **observed, "phase": phase, "abortAllowed": phase in {"ready-pending", "ready-cleaned"}}):
                projected = mcp_server._vm_workflow_impl(
                    "windows-update-fixture-download-abort-status", REQUEST)
            self.assertTrue(projected["ok"])

        for poisoned in ({**observed, "phase": "private-path"},
                         {**observed, "abortAllowed": False},
                         {**observed, "private": "secret"}):
            with self.subTest(poisoned=poisoned), patch.object(download_abort, "status", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl("windows-update-fixture-download-abort-status", REQUEST)
            self.assertFalse(rejected["ok"])
            self.assertNotIn("private", str(rejected))

    def test_abort_accepts_only_terminal_receipt_or_unknown(self):
        retired = {"state": "retired", "correlationId": CORR,
                   "cleanupReceiptSha256": "a" * 64, **FLAGS}
        with patch.object(download_abort, "abort", return_value=retired) as abort:
            result = mcp_server._vm_workflow_impl("windows-update-fixture-download-abort", REQUEST)
        abort.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
        self.assertTrue(result["ok"])
        self.assertEqual("native-campaign", result["evidenceClass"])

        unknown = {"state": "unknown", "correlationId": CORR, **FLAGS}
        with patch.object(download_abort, "abort", return_value=unknown):
            result = mcp_server._vm_workflow_impl("windows-update-fixture-download-abort", REQUEST)
        self.assertFalse(result["ok"])
        for poisoned in ({**retired, "cleanupReceiptSha256": "private"},
                         {**retired, "nativeActionAllowed": True}, {**retired, "private": "secret"}):
            with self.subTest(poisoned=poisoned), patch.object(download_abort, "abort", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl("windows-update-fixture-download-abort", REQUEST)
            self.assertFalse(rejected["ok"])
            self.assertNotIn("private", str(rejected))

    def test_rejects_any_altered_request_before_dispatch(self):
        with patch.object(download_abort, "abort", side_effect=AssertionError("unsafe dispatch")):
            for request in ({}, {"correlationId": "00000000-0000-4000-8000-000000000000"},
                            {**REQUEST, "retry": False}, {"correlationId": 1}):
                with self.subTest(request=request):
                    result = mcp_server._vm_workflow_impl("windows-update-fixture-download-abort", request)
                self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()

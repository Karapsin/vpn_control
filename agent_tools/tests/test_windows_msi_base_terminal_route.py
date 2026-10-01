"""MCP projection of fixed CP117 durable terminal reconciliation."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_tools import mcp_server, windows_msi_base_prepare as base


CORRELATION = "11111111-1111-4111-8111-111111111111"


class WindowsMsiBaseTerminalRouteTest(unittest.TestCase):
    def setUp(self):
        source_guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        source_guard.start(); self.addCleanup(source_guard.stop)

    def test_exact_terminal_receipt_is_read_only(self):
        receipt = {"state": "terminal", "correlationId": CORRELATION, "result": "PASSED",
                   "stage": "READBACK", "exitCode": 0, "sourceSha": "a" * 40,
                   "baseArtifactId": "sha256-" + "b" * 64, "replayAllowed": False}
        with patch.object(base, "terminal_reconcile", return_value=receipt) as reconcile:
            result = mcp_server._vm_workflow_impl("windows-msi-base-terminal-reconcile",
                                                  {"correlationId": CORRELATION})
        reconcile.assert_called_once_with(mcp_server.REPO_ROOT, {"correlationId": CORRELATION})
        self.assertTrue(result["ok"])
        self.assertFalse(result["productAction"])
        self.assertEqual(result["evidenceClass"], "causal-reconciliation")

    def test_poisoned_terminal_fields_fail_closed(self):
        receipt = {"state": "terminal", "correlationId": CORRELATION, "result": "PASSED",
                   "stage": "READBACK", "exitCode": 0, "sourceSha": "a" * 40,
                   "baseArtifactId": "sha256-" + "b" * 64, "replayAllowed": False}
        for poisoned in ({**receipt, "path": "/private/result"},
                         {**receipt, "result": "FAILED"},
                         {**receipt, "correlationId": "22222222-2222-4222-8222-222222222222"},
                         {**receipt, "sourceSha": "bad"}):
            with self.subTest(poisoned=poisoned), patch.object(base, "terminal_reconcile", return_value=poisoned):
                result = mcp_server._vm_workflow_impl("windows-msi-base-terminal-reconcile",
                                                      {"correlationId": CORRELATION})
            self.assertFalse(result["ok"])
            self.assertEqual(result["state"], "unknown")
            self.assertNotIn("private", str(result))

    def test_cli_accepts_terminal_reconcile(self):
        request = {"correlationId": CORRELATION}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "request.json"
            path.write_text(json.dumps(request))
            with patch.object(mcp_server, "vm_workflow", return_value={"tool": "vm_workflow", "ok": True}) as route, \
                    contextlib.redirect_stdout(io.StringIO()):
                code = mcp_server.main(["vm-workflow", "windows-msi-base-terminal-reconcile",
                                        "--inputs-file", str(path)])
        self.assertEqual(code, 0)
        route.assert_called_once_with("windows-msi-base-terminal-reconcile", request)

    def test_finish_observed_uses_only_exact_correlation_and_projects_lease_state(self):
        request = {"correlationId": CORRELATION}
        with patch.object(base, "finish_observed", return_value={
                "state": "active", "leaseId": CORRELATION, "replayAllowed": False}) as finish:
            result = mcp_server._vm_workflow_impl("windows-msi-base-finish-observed", request)
        finish.assert_called_once_with(mcp_server.REPO_ROOT, CORRELATION)
        self.assertTrue(result["ok"])
        self.assertFalse(result["productAction"])
        with patch.object(base, "finish_observed", side_effect=AssertionError("unsafe dispatch")):
            for invalid in ({**request, "outcome": "succeeded"}, {"correlationId": "bad"}):
                self.assertFalse(mcp_server._vm_workflow_impl("windows-msi-base-finish-observed", invalid)["ok"])
        with patch.object(base, "finish_observed", return_value={
                "state": "active", "leaseId": CORRELATION, "path": "/private", "replayAllowed": False}):
            rejected = mcp_server._vm_workflow_impl("windows-msi-base-finish-observed", request)
        self.assertFalse(rejected["ok"])
        self.assertNotIn("private", str(rejected))


if __name__ == "__main__":
    unittest.main()

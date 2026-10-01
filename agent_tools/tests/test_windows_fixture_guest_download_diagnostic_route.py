"""MCP boundary for the fixed read-only Windows guest-download diagnostic."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_update_fixture_http_stage as transfer


CORR = "e848bed2-5bea-47bc-a85a-6cf17b1fcc6a"
REQUEST = {"phase": "guest-download-diagnostic", "correlationId": CORR}
FLAGS = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}


class GuestDownloadDiagnosticRouteTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start()
        self.addCleanup(guard.stop)

    def _result(self, phase="task-failed"):
        return {"state": "diagnosed", "correlationId": CORR, "preEffect": True,
                "phase": phase, "listener": "stopped", "listenerServed": "false",
                "task": "failed", "taskResult": "unknown", "download": "absent", **FLAGS}

    def test_exact_read_only_request_and_bounded_result(self):
        observed = self._result()
        with patch.object(transfer, "workflow", return_value=observed) as workflow:
            result = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer", REQUEST)
        workflow.assert_called_once_with(mcp_server.REPO_ROOT, "guest-download-diagnostic",
                                         {"correlationId": CORR})
        self.assertTrue(result["ok"])
        self.assertEqual("causal-diagnostic", result["evidenceClass"])
        self.assertFalse(result["nativeActionAllowed"])

    def test_projects_each_finite_phase_and_rejects_private_or_inconsistent_output(self):
        phases = ("not-submitted", "diagnostic-script-oversize", "qga-wrapper-timeout",
                  "qga-wrapper-failed", "syntax-invalid", "task-action-mismatch",
                  "task-metadata-error", "task-absent", "task-running", "task-failed",
                  "task-principal-mismatch", "task-action-count-mismatch",
                  "task-state-unsupported", "task-task-info-failed", "task-action-hash-unknown",
                  "download-absent", "download-hash-mismatch", "guest-file-read-error",
                  "download-complete", "unknown")
        for phase in phases:
            with self.subTest(phase=phase), patch.object(transfer, "workflow", return_value=self._result(phase)):
                result = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer", REQUEST)
            self.assertTrue(result["ok"])
        extended = {**self._result("task-metadata-error"), "task": "metadata-error",
                    "download": "read-error"}
        with patch.object(transfer, "workflow", return_value=extended):
            result = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer", REQUEST)
        self.assertTrue(result["ok"])
        concrete_result = {**self._result("task-failed"), "taskResult": 17}
        with patch.object(transfer, "workflow", return_value=concrete_result):
            result = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer", REQUEST)
        self.assertTrue(result["ok"])
        for phase, task in (("task-principal-mismatch", "principal-mismatch"),
                            ("task-action-count-mismatch", "action-count-mismatch"),
                            ("task-state-unsupported", "state-unsupported"),
                            ("task-task-info-failed", "task-info-failed"),
                            ("task-action-hash-unknown", "action-hash-unknown")):
            observed = {**self._result(phase), "task": task}
            with self.subTest(phase=phase), patch.object(transfer, "workflow", return_value=observed):
                result = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer", REQUEST)
            self.assertTrue(result["ok"])
        for poisoned in ({**self._result(), "phase": "private-path"},
                         {**self._result(), "listenerServed": True},
                         {**self._result(), "listener": "served", "listenerServed": "false"},
                         {**self._result(), "taskResult": -1},
                         {**self._result(), "taskResult": 4, "task": "running"},
                         {**self._result(), "taskResult": True},
                         {**self._result(), "download": "private"},
                         {**self._result(), "secret": "private"}):
            with self.subTest(poisoned=poisoned), patch.object(transfer, "workflow", return_value=poisoned):
                result = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer", REQUEST)
            self.assertFalse(result["ok"])
            self.assertNotIn("private", str(result))

    def test_rejects_nonfixed_or_extended_request_before_dispatch(self):
        with patch.object(transfer, "workflow", side_effect=AssertionError("unsafe dispatch")):
            for request in ({"phase": "guest-download-diagnostic", "correlationId": "00000000-0000-4000-8000-000000000000"},
                            {**REQUEST, "path": "private"}, {"phase": "guest-download-diagnostic"}):
                with self.subTest(request=request):
                    result = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer", request)
                self.assertFalse(result["ok"])

    def test_cli_fallback_accepts_the_existing_http_transfer_action(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "request.json"
            path.write_text(json.dumps(REQUEST))
            with patch.object(mcp_server, "vm_workflow", return_value={"tool": "vm_workflow", "ok": True}) as route, \
                    contextlib.redirect_stdout(io.StringIO()):
                code = mcp_server.main(["vm-workflow", "windows-update-fixture-http-transfer",
                                        "--inputs-file", str(path)])
        self.assertEqual(0, code)
        route.assert_called_once_with("windows-update-fixture-http-transfer", REQUEST)


if __name__ == "__main__":
    unittest.main()

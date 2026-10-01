"""MCP admission for the fixed, non-admitting CP117 installer-service observer."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_tools import mcp_server, windows_msiexec_service_diagnostic as observer


class WindowsMsiexecServiceRouteTest(unittest.TestCase):
    def setUp(self):
        source_guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        source_guard.start(); self.addCleanup(source_guard.stop)

    def test_exact_status_routes_and_remains_non_admitting(self):
        request = {"action": "status", "host": "archlinux"}
        observed = {"state": "observed", "correlationId": observer._CORRELATION,
                    "sourceSha": "a" * 40, "process": "exact", "service": "bound-running",
                    "commandShape": "service-switch", "otherInstallers": "none",
                    "transaction": "none-observed", "classification": "service-idle-candidate",
                    "replayAllowed": False, "nativeActionAllowed": False,
                    "productAction": False, "readinessAdmitted": False}
        with patch.object(observer, "workflow", return_value=observed) as workflow:
            result = mcp_server._vm_workflow_impl("windows-msiexec-service-diagnostic", request)
        workflow.assert_called_once_with(mcp_server.REPO_ROOT, "status", {"host": "archlinux"})
        self.assertTrue(result["ok"])
        self.assertFalse(result["readinessAdmitted"])
        self.assertFalse(result["nativeActionAllowed"])
        self.assertEqual(result["evidenceClass"], "causal-diagnostic")

    def test_bad_input_and_raw_output_fail_closed(self):
        request = {"action": "status", "host": "archlinux"}
        with patch.object(observer, "workflow", side_effect=AssertionError("unsafe dispatch")):
            for invalid in ({**request, "pid": 1932}, {**request, "host": "other"},
                            {**request, "action": "stop"}):
                with self.subTest(invalid=invalid):
                    self.assertFalse(mcp_server._vm_workflow_impl(
                        "windows-msiexec-service-diagnostic", invalid)["ok"])
        observed = {"state": "observed", "correlationId": observer._CORRELATION,
                    "sourceSha": "a" * 40, "process": "exact", "service": "bound-running",
                    "commandShape": "service-switch", "otherInstallers": "none",
                    "transaction": "none-observed", "classification": "service-idle-candidate",
                    "replayAllowed": False, "nativeActionAllowed": False,
                    "productAction": False, "readinessAdmitted": False}
        for poisoned in ({**observed, "rawCommand": "private"},
                         {**observed, "readinessAdmitted": True},
                         {**observed, "classification": "private"},
                         {**observed, "sourceSha": "bad"}):
            with self.subTest(poisoned=poisoned), patch.object(observer, "workflow", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl("windows-msiexec-service-diagnostic", request)
            self.assertFalse(rejected["ok"])
            self.assertEqual(rejected["state"], "unknown")
            self.assertNotIn("private", str(rejected))

    def test_cli_accepts_fixed_diagnostic_action(self):
        request = {"action": "preflight", "host": "archlinux"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "request.json"
            path.write_text(json.dumps(request))
            output = io.StringIO()
            with patch.object(mcp_server, "vm_workflow", return_value={"tool": "vm_workflow", "ok": True}) as route, \
                    contextlib.redirect_stdout(output):
                code = mcp_server.main(["vm-workflow", "windows-msiexec-service-diagnostic",
                                        "--inputs-file", str(path)])
        self.assertEqual(code, 0)
        route.assert_called_once_with("windows-msiexec-service-diagnostic", request)


if __name__ == "__main__":
    unittest.main()

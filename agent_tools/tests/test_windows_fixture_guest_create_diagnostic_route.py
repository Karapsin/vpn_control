"""MCP result boundary for a failed CP117 guest-create attempt."""
import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_update_fixture_http_stage as transfer


CORR = "727a4097-e57c-46f6-ba42-5492cd4af4da"
BASE = {"state": "diagnosed", "correlationId": CORR, "preEffect": True,
        "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}


class GuestCreateDiagnosticRouteTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start(); self.addCleanup(guard.stop)

    def test_exact_read_only_result_and_finite_classification(self):
        request = {"phase": "guest-create-diagnostic", "correlationId": CORR}
        observed = {**BASE, "phase": "guest-create-not-confirmed-parent-absent",
                    "interpreter": "absent"}
        with patch.object(transfer, "workflow", return_value=observed) as workflow:
            result = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer", request)
        workflow.assert_called_once_with(mcp_server.REPO_ROOT, "guest-create-diagnostic", {"correlationId": CORR})
        self.assertTrue(result["ok"])
        self.assertFalse(result["nativeActionAllowed"])
        for poisoned in ({**observed, "phase": "private-path"},
                         {**observed, "interpreter": "powershell.exe:1234"},
                         {**observed, "secret": "private"}):
            with patch.object(transfer, "workflow", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer", request)
            self.assertFalse(rejected["ok"])
            self.assertNotIn("private", str(rejected))
        with patch.object(transfer, "workflow", side_effect=AssertionError("unsafe dispatch")):
            rejected = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                                                    {**request, "path": "private"})
        self.assertFalse(rejected["ok"])


if __name__ == "__main__":
    unittest.main()

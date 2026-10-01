"""Bounded read-only MCP projection for an uncertain CP117 host stage."""
import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_update_fixture_http_stage as transfer


CORR = "727a4097-e57c-46f6-ba42-5492cd4af4da"
BASE = {"state": "diagnosed", "correlationId": CORR, "preEffect": True,
        "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}


class HostStageProbeRouteTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start(); self.addCleanup(guard.stop)

    def test_only_complete_exact_probe_admits_listener(self):
        request = {"phase": "host-stage-probe", "correlationId": CORR}
        for phase in ("host-stage-complete", "host-stage-partial", "host-stage-absent",
                      "not-host-staged", "local-binding-invalid", "unknown"):
            with self.subTest(phase=phase), patch.object(transfer, "workflow", return_value={
                    **BASE, "phase": phase,
                    "listenerStartAllowed": phase == "host-stage-complete"}) as call:
                result = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer", request)
            call.assert_called_once_with(mcp_server.REPO_ROOT, "host-stage-probe", {"correlationId": CORR})
            self.assertTrue(result["ok"])
            self.assertEqual("causal-diagnostic", result["evidenceClass"])
            self.assertEqual(phase == "host-stage-complete", result["listenerStartAllowed"])
        for poisoned in ({**BASE, "phase": "host-stage-partial", "listenerStartAllowed": True},
                         {**BASE, "phase": "host-stage-complete", "listenerStartAllowed": False},
                         {**BASE, "phase": "host-stage-complete", "listenerStartAllowed": True,
                          "path": "private"}):
            with patch.object(transfer, "workflow", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer", request)
            self.assertFalse(rejected["ok"])
            self.assertNotIn("private", str(rejected))
        with patch.object(transfer, "workflow", side_effect=AssertionError("unsafe call")):
            rejected = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                                                    {**request, "path": "private"})
        self.assertFalse(rejected["ok"])


if __name__ == "__main__":
    unittest.main()

"""MCP projection for nonmutating Windows fixture phase status."""

import unittest
from unittest.mock import patch

from agent_tools import mcp_server, windows_fixture_phase_status as phases


CORR = "11111111-1111-4111-8111-111111111111"


class WindowsFixturePhaseStatusRouteTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start(); self.addCleanup(guard.stop)

    def test_exact_phase_and_no_replay(self):
        observed = {"state": "observed", "correlationId": CORR,
                    "phase": "transfer-unobserved", "nextFact": "observe-transfer-receipt",
                    "source": "bound", "vm": "bound", "campaign": "role-active",
                    "observation": {"listener": "absent", "guest": "created", "collect": "absent"},
                    "replayAllowed": False, "nativeActionAllowed": False,
                    "productAction": False}
        with patch.object(phases, "status", return_value=observed) as status:
            result = mcp_server._vm_workflow_impl("windows-update-fixture-phase-status",
                                                  {"correlationId": CORR})
        status.assert_called_once_with(mcp_server.REPO_ROOT, {"correlationId": CORR})
        self.assertTrue(result["ok"])
        self.assertFalse(result["nativeActionAllowed"])
        for poisoned in ({**observed, "nextFact": "prepare-not-accepted"},
                         {**observed, "replayAllowed": True},
                         {**observed, "private": "secret"}):
            with patch.object(phases, "status", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl("windows-update-fixture-phase-status",
                                                        {"correlationId": CORR})
            self.assertFalse(rejected["ok"])
            self.assertNotIn("secret", str(rejected))

    def test_aborted_pre_effect_is_finite_and_has_no_observation(self):
        corr = phases.http_stage._E66_CORRELATION
        observed = {"state": "observed", "correlationId": corr,
                    "phase": "pre-effect-aborted", "nextFact": "retire-aborted-stage",
                    "source": "bound", "vm": "bound", "campaign": "role-active",
                    "replayAllowed": False, "nativeActionAllowed": False,
                    "productAction": False}
        with patch.object(phases, "status", return_value=observed):
            result = mcp_server._vm_workflow_impl("windows-update-fixture-phase-status",
                                                  {"correlationId": corr})
        self.assertTrue(result["ok"])
        for poisoned in ({**observed, "observation": {"listener": "absent", "guest": "absent", "collect": "absent"}},
                         {**observed, "nextFact": "observe-transfer-receipt"}):
            with patch.object(phases, "status", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl("windows-update-fixture-phase-status",
                                                        {"correlationId": corr})
            self.assertFalse(rejected["ok"])


if __name__ == "__main__":
    unittest.main()

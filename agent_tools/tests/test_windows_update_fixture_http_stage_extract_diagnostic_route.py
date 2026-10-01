"""MCP boundary for the fixed read-only Windows extraction diagnostic."""
import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_update_fixture_http_stage as transfer


CORR = "e848bed2-5bea-47bc-a85a-6cf17b1fcc6a"
REQUEST = {"correlationId": CORR}
FLAGS = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
ACTION = "windows-update-fixture-http-stage-extract-diagnostic"


class StageExtractDiagnosticRouteTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start()
        self.addCleanup(guard.stop)

    def test_exact_request_projects_only_bounded_read_only_observation(self):
        observed = {"state": "diagnosed", "correlationId": CORR, "binding": "exact",
                    "phase": "guest-stage-partial", **FLAGS}
        with patch.object(transfer, "workflow", return_value=observed) as workflow:
            result = mcp_server._vm_workflow_impl(ACTION, REQUEST)
        workflow.assert_called_once_with(mcp_server.REPO_ROOT, "stage-extract-diagnostic", REQUEST)
        self.assertTrue(result["ok"])
        self.assertEqual("causal-diagnostic", result["evidenceClass"])
        self.assertFalse(result["nativeActionAllowed"])

    def test_all_finite_phases_are_accepted_and_private_or_invalid_data_is_rejected(self):
        phases = ("local-binding-invalid", "not-placed", "remote-stage-absent", "remote-stage-partial",
                  "remote-binding-mismatch", "remote-dispatch-malformed", "guest-stage-absent",
                  "guest-stage-partial", "guest-stage-full", "receipt-pending", "receipt-absent",
                  "receipt-present-unverified", "qga-protocol", "remote-layout-invalid",
                  "guest-stage-probe-failed", "dispatch-status-unknown", "result-read-failed",
                  "receipt-invalid")
        base = {"state": "diagnosed", "correlationId": CORR, "binding": "unverified", **FLAGS}
        for phase in phases:
            with self.subTest(phase=phase), patch.object(transfer, "workflow", return_value={**base, "phase": phase}):
                result = mcp_server._vm_workflow_impl(ACTION, REQUEST)
            self.assertTrue(result["ok"])
        for poisoned in ({**base, "phase": "private-phase"}, {**base, "phase": "not-placed", "binding": "private"},
                         {**base, "phase": "not-placed", "private": "secret"},
                         {**base, "phase": "not-placed", "replayAllowed": True}):
            with self.subTest(poisoned=poisoned), patch.object(transfer, "workflow", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl(ACTION, REQUEST)
            self.assertFalse(rejected["ok"])
            self.assertNotIn("private", str(rejected))

    def test_rejects_other_correlation_or_extra_input_before_dispatch(self):
        with patch.object(transfer, "workflow", side_effect=AssertionError("unsafe dispatch")):
            for request in ({}, {"correlationId": "07708dc7-6884-40a5-9a78-c75dbb391dbd"},
                            {**REQUEST, "retry": False}, {"correlationId": 1}):
                with self.subTest(request=request):
                    result = mcp_server._vm_workflow_impl(ACTION, request)
                self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()

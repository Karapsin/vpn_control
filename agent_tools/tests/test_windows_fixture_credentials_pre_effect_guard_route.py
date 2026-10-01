"""MCP boundary for the exact read-only credentials role-guard probe."""
import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_fixture_credentials as credentials


CORR = "6161b4ae-3634-4312-ac85-1bacd0001dfa"
REQUEST = {"correlationId": CORR}
FLAGS = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
ACTION = "windows-fixture-credentials-pre-effect-guard-probe"


class CredentialsPreEffectGuardRouteTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start()
        self.addCleanup(guard.stop)

    def test_exact_probe_projects_only_redacted_finite_result(self):
        observed = {"state": "observed", "correlationId": CORR, "binding": "exact",
                    "localPayload": "metadata-admitted", "remoteRoleGuard": "matched", **FLAGS}
        with patch.object(credentials, "pre_effect_guard_probe", return_value=observed) as probe:
            result = mcp_server._vm_workflow_impl(ACTION, REQUEST)
        probe.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
        self.assertTrue(result["ok"])
        self.assertEqual("causal-diagnostic", result["evidenceClass"])
        for poisoned in ({**observed, "remoteRoleGuard": "private"}, {**observed, "binding": "mismatch"},
                         {**observed, "private": "secret"}, {**observed, "replayAllowed": True}):
            with self.subTest(poisoned=poisoned), patch.object(credentials, "pre_effect_guard_probe", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl(ACTION, REQUEST)
            self.assertFalse(rejected["ok"])
            self.assertNotIn("private", str(rejected))

    def test_rejected_guard_and_unknown_are_bounded(self):
        rejected = {"state": "observed", "correlationId": CORR, "binding": "exact",
                    "localPayload": "metadata-admitted", "remoteRoleGuard": "rejected", **FLAGS}
        with patch.object(credentials, "pre_effect_guard_probe", return_value=rejected):
            result = mcp_server._vm_workflow_impl(ACTION, REQUEST)
        self.assertTrue(result["ok"])
        unknown = {"state": "unknown", "correlationId": CORR, **FLAGS}
        with patch.object(credentials, "pre_effect_guard_probe", return_value=unknown):
            result = mcp_server._vm_workflow_impl(ACTION, REQUEST)
        self.assertFalse(result["ok"])

    def test_invalid_request_does_not_dispatch(self):
        with patch.object(credentials, "pre_effect_guard_probe", side_effect=AssertionError("unsafe dispatch")):
            for request in ({}, {"correlationId": "00000000-0000-4000-8000-000000000000"},
                            {**REQUEST, "retry": False}, {"correlationId": 1}):
                with self.subTest(request=request):
                    result = mcp_server._vm_workflow_impl(ACTION, request)
                self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()

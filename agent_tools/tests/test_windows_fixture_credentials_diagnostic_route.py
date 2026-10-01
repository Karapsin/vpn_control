"""MCP boundary for the exact redacted CP117 credentials diagnostic."""
import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_fixture_credentials as credentials


CORR = "791b5235-9ca7-409c-96bc-c341047c7fb4"
REQUEST = {"correlationId": CORR}
FLAGS = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
ACTION = "windows-fixture-credentials-diagnostic"


class CredentialsDiagnosticRouteTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start()
        self.addCleanup(guard.stop)

    def test_exact_read_only_diagnostic_has_bounded_projection(self):
        observed = {"state": "diagnosed", "correlationId": CORR, "binding": "exact",
                    "phase": "terminal-failed", "nextReadOnly": "credentials-abort-status", **FLAGS}
        with patch.object(credentials, "diagnostic", return_value=observed) as diagnostic:
            result = mcp_server._vm_workflow_impl(ACTION, REQUEST)
        diagnostic.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
        self.assertTrue(result["ok"])
        self.assertEqual("causal-diagnostic", result["evidenceClass"])
        self.assertFalse(result["nativeActionAllowed"])

    def test_finite_phases_and_read_only_actions_are_enforced(self):
        base = {"state": "diagnosed", "correlationId": CORR, "binding": "exact", **FLAGS}
        for phase, next_action in (("pre-effect", "credentials-status"), ("task-running", "credential-diagnostic"),
                                   ("ready-uncommitted", "credentials-status"),
                                   ("terminal-failed", "credentials-abort-status"),
                                   ("partial", "credential-diagnostic"),
                                   ("host-group-absent", "credentials-status"),
                                   ("host-journal-absent", "credentials-status"),
                                   ("host-binding-mismatch", "credential-diagnostic"),
                                   ("host-layout-unsafe", "credential-diagnostic"),
                                   ("guest-observer-failed", "credential-diagnostic")):
            with self.subTest(phase=phase), patch.object(credentials, "diagnostic", return_value={
                    **base, "phase": phase, "nextReadOnly": next_action}):
                result = mcp_server._vm_workflow_impl(ACTION, REQUEST)
            self.assertTrue(result["ok"])
        for poisoned in ({**base, "phase": "private", "nextReadOnly": "credentials-status"},
                         {**base, "phase": "partial", "nextReadOnly": "start"},
                         {**base, "phase": "partial", "nextReadOnly": "credential-diagnostic", "secret": "value"},
                         {**base, "phase": "partial", "nextReadOnly": "credential-diagnostic", "binding": "mismatch"}):
            with self.subTest(poisoned=poisoned), patch.object(credentials, "diagnostic", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl(ACTION, REQUEST)
            self.assertFalse(rejected["ok"])
            self.assertNotIn("secret", str(rejected))

    def test_unknown_is_preserved_but_invalid_input_never_dispatches(self):
        unknown = {"state": "unknown", "correlationId": CORR, **FLAGS}
        with patch.object(credentials, "diagnostic", return_value=unknown):
            result = mcp_server._vm_workflow_impl(ACTION, REQUEST)
        self.assertFalse(result["ok"])
        with patch.object(credentials, "diagnostic", side_effect=AssertionError("unsafe dispatch")):
            for request in ({}, {"correlationId": "6161b4ae-3634-4312-ac85-1bacd0001dfa"},
                            {"correlationId": "00000000-0000-4000-8000-000000000000"},
                            {**REQUEST, "retry": False}, {"correlationId": 1}):
                with self.subTest(request=request):
                    result = mcp_server._vm_workflow_impl(ACTION, request)
                self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()

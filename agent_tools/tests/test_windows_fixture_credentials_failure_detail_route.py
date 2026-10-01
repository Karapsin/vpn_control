"""MCP boundary for the exact redacted CP117 credential failure detail."""
import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_fixture_credentials as credentials


CORR = "791b5235-9ca7-409c-96bc-c341047c7fb4"
REQUEST = {"correlationId": CORR}
FLAGS = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
ACTION = "windows-fixture-credentials-failure-detail"


class CredentialsFailureDetailRouteTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start()
        self.addCleanup(guard.stop)

    def test_exact_terminal_failure_detail_has_bounded_projection(self):
        observed = {"state": "detailed", "correlationId": CORR, "binding": "exact",
                    "taskLastResult": 7, "safeStage": "before-provenance",
                    "directory": "present", "directoryAcl": "verified", "files": "all-exact",
                    "provenance": "absent", "provenanceAcl": "absent",
                    "nextReadOnly": "credentials-abort-status", **FLAGS}
        with patch.object(credentials, "failure_detail", return_value=observed) as failure_detail:
            result = mcp_server._vm_workflow_impl(ACTION, REQUEST)
        failure_detail.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
        self.assertTrue(result["ok"])
        self.assertEqual("causal-diagnostic", result["evidenceClass"])
        self.assertFalse(result["nativeActionAllowed"])

    def test_stale_or_extra_input_never_dispatches(self):
        with patch.object(credentials, "failure_detail", side_effect=AssertionError("unsafe dispatch")):
            for request in ({}, {"correlationId": "6161b4ae-3634-4312-ac85-1bacd0001dfa"},
                            {"correlationId": "00000000-0000-4000-8000-000000000000"},
                            {**REQUEST, "retry": False}, {"correlationId": 1}):
                with self.subTest(request=request):
                    self.assertFalse(mcp_server._vm_workflow_impl(ACTION, request)["ok"])

    def test_secret_or_nonfinite_response_fails_closed_and_redacts(self):
        base = {"state": "detailed", "correlationId": CORR, "binding": "exact",
                "taskLastResult": 7, "safeStage": "before-provenance",
                "directory": "present", "directoryAcl": "verified", "files": "all-exact",
                "provenance": "absent", "provenanceAcl": "absent",
                "nextReadOnly": "credentials-abort-status", **FLAGS}
        for poisoned in ({**base, "secret": "private-key"},
                         {**base, "safeStage": "private"},
                         {**base, "taskLastResult": True},
                         {**base, "binding": "mismatch"}):
            with self.subTest(poisoned=poisoned), patch.object(credentials, "failure_detail", return_value=poisoned):
                result = mcp_server._vm_workflow_impl(ACTION, REQUEST)
            self.assertFalse(result["ok"])
            self.assertNotIn("private-key", str(result))


if __name__ == "__main__":
    unittest.main()

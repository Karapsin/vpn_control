"""MCP boundary for the redacted CP117 Python inventory diagnostic."""
import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_update_fixture_server as server


REQUEST = {
    "host": "archlinux", "leaseId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "stageCorrelationId": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    "serverCorrelationId": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    "sourceSha": "d" * 40, "fixtureReceiptArtifactId": "sha256-" + "e" * 64,
    "baseMsiArtifactId": "sha256-" + "f" * 64,
    "targetMsiArtifactId": "sha256-" + "1" * 64,
}
ACTION = "windows-fixture-python-inventory-diagnostic"


class PythonInventoryDiagnosticRouteTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start()
        self.addCleanup(guard.stop)

    def _observed(self):
        return {
            "state": "observed", "leaseId": REQUEST["leaseId"],
            "stageCorrelationId": REQUEST["stageCorrelationId"],
            "serverCorrelationId": REQUEST["serverCorrelationId"],
            "candidateCount": 2,
            "candidates": [
                {"location": "owner-local", "pythonExeSha256": "7" * 64,
                 "pythonVersion": "3.13.15", "signer": "python-software-foundation"},
                {"location": "program-files", "pythonExeSha256": "8" * 64,
                 "pythonVersion": "3.14.0", "signer": "python-software-foundation"},
            ],
            "serverReady": False,
        }

    def test_real_domain_projection_preserves_ambiguous_finite_inventory(self):
        candidates = [
            {"path": r"C:\Users\vpncp117\AppData\Local\Programs\Python\Python313\python.exe",
             "sha256": "7" * 64, "version": "3.13.15", "signer": "CN=Python Software Foundation"},
            {"path": r"C:\Program Files\Python314\python.exe",
             "sha256": "8" * 64, "version": "3.14.0", "signer": "CN=Python Software Foundation"},
        ]
        with patch.object(server, "_python_candidates", return_value=candidates):
            result = mcp_server._vm_workflow_impl(ACTION, REQUEST)
        self.assertTrue(result["ok"])
        self.assertEqual(self._observed(), {key: result[key] for key in self._observed()})
        self.assertNotIn("path", str(result).lower())
        self.assertFalse(result["nativeActionAllowed"])

    def test_wrong_or_extra_input_never_dispatches(self):
        with patch.object(server, "python_inventory_diagnostic", side_effect=AssertionError("unsafe dispatch")):
            for request in ({}, {**REQUEST, "command": "id"},
                            {**REQUEST, "serverCorrelationId": REQUEST["stageCorrelationId"]},
                            {**REQUEST, "sourceSha": "bad"}):
                with self.subTest(request=request):
                    self.assertFalse(mcp_server._vm_workflow_impl(ACTION, request)["ok"])

    def test_extra_or_poisoned_domain_response_fails_closed_and_redacts(self):
        for poisoned in ({**self._observed(), "path": r"C:\\secret"},
                         {**self._observed(), "candidateCount": 1},
                         {**self._observed(), "candidates": [{"location": "owner-local", "pythonExeSha256": "7" * 64,
                                                               "pythonVersion": "3.13.15", "signer": "secret"}]},
                         {**self._observed(), "candidates": [
                             {"location": "owner-local", "pythonExeSha256": "7" * 64,
                              "pythonVersion": "3.13." + "1" * 61,
                              "signer": "python-software-foundation"},
                             self._observed()["candidates"][1]]},
                         {**self._observed(), "serverReady": True}):
            with self.subTest(poisoned=poisoned), patch.object(server, "python_inventory_diagnostic", return_value=poisoned):
                result = mcp_server._vm_workflow_impl(ACTION, REQUEST)
            self.assertFalse(result["ok"])
            self.assertNotIn("secret", str(result).lower())


if __name__ == "__main__":
    unittest.main()

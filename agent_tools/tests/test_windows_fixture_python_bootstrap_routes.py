"""Strict MCP entry points for CP117's pinned Python bootstrap."""
import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_fixture_python_acquire_transfer as acquire
from agent_tools import windows_fixture_python_guest_install as install
from agent_tools import windows_update_fixture_server as server
from agent_tools import windows_fixture_package_mode_repair as mode_repair


REQUEST = {"host": "archlinux", "leaseId": "11111111-1111-4111-8111-111111111111",
           "stageCorrelationId": "22222222-2222-4222-8222-222222222222",
           "serverCorrelationId": "33333333-3333-4333-8333-333333333333",
           "correlationId": "44444444-4444-4444-8444-444444444444",
           "sourceSha": "a" * 40, "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
           "baseMsiArtifactId": "sha256-" + "c" * 64,
           "targetMsiArtifactId": "sha256-" + "d" * 64}
ID = {"correlationId": REQUEST["correlationId"]}


class PythonBootstrapRoutesTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start(); self.addCleanup(guard.stop)

    def test_start_requires_exact_source_bound_fields_before_dispatch(self):
        for action, module in (("windows-fixture-python-acquire-start", acquire),
                               ("windows-fixture-python-install-start", install)):
            with self.subTest(action=action), patch.object(module, "start", side_effect=AssertionError("dispatched")):
                self.assertFalse(mcp_server._vm_workflow_impl(action, {**REQUEST, "url": "https://other.invalid"})["ok"])

    def test_acquire_status_projects_verified_guest_download(self):
        observed = {"state": "downloaded", **ID, "task": "ready", "leaf": "verified",
                    "installer": "verified", "result": "succeeded", "replayAllowed": False}
        with patch.object(acquire, "status", return_value=observed):
            result = mcp_server._vm_workflow_impl("windows-fixture-python-acquire-status", ID)
        self.assertTrue(result["ok"])
        self.assertFalse(result["nativeActionAllowed"])
        with patch.object(acquire, "status", return_value={**observed, "path": "secret"}):
            result = mcp_server._vm_workflow_impl("windows-fixture-python-acquire-status", ID)
        self.assertFalse(result["ok"])
        self.assertNotIn("secret", str(result))

    def test_install_status_preserves_exact_succeeded_proof(self):
        observed = {"state": "succeeded", **ID, "intent": "verified", "private": "verified",
                    "task": "ready", "installer": "verified", "result": "succeeded",
                    "registry": "verified", "python": "verified", "replayAllowed": False}
        with patch.object(install, "status", return_value=observed):
            result = mcp_server._vm_workflow_impl("windows-fixture-python-install-status", ID)
        self.assertTrue(result["ok"])
        self.assertEqual("succeeded", result["state"])

    def test_unknown_is_never_replayed_or_admitted(self):
        with patch.object(acquire, "start", return_value={"state": "unknown", **ID,
                                                          "replayAllowed": False, "nativeActionAllowed": False,
                                                          "productAction": False}):
            result = mcp_server._vm_workflow_impl("windows-fixture-python-acquire-start", REQUEST)
        self.assertFalse(result["ok"])
        self.assertFalse(result["replayAllowed"])
        self.assertFalse(result["nativeActionAllowed"])

    def test_failure_detail_projects_finite_native_cause(self):
        observed = {"state": "observed", **ID, "resultCode": 1,
                    "partial": "digest-verified", "signer": "invalid", "parseErrors": 0,
                    "phase": "signer",
                    "replayAllowed": False}
        with patch.object(acquire, "failure_detail", return_value=observed):
            result = mcp_server._vm_workflow_impl("windows-fixture-python-acquire-failure-detail", ID)
        self.assertTrue(result["ok"])
        self.assertEqual("invalid", result["signer"])
        with patch.object(acquire, "failure_detail", return_value={**observed, "path": "secret"}):
            result = mcp_server._vm_workflow_impl("windows-fixture-python-acquire-failure-detail", ID)
        self.assertFalse(result["ok"])
        self.assertNotIn("secret", str(result))

    def test_install_diagnostic_projects_first_gate_without_paths(self):
        observed = {"state": "observed", **ID, "phase": "vpncontrol",
                    "reason": "foreign-owner", "replayAllowed": False}
        with patch.object(install, "diagnose", return_value=observed):
            result = mcp_server._vm_workflow_impl("windows-fixture-python-install-diagnostic", ID)
        self.assertTrue(result["ok"])
        self.assertEqual("vpncontrol", result["phase"])
        with patch.object(install, "diagnose", return_value={**observed, "path": "secret"}):
            result = mcp_server._vm_workflow_impl("windows-fixture-python-install-diagnostic", ID)
        self.assertFalse(result["ok"])
        self.assertNotIn("secret", str(result))

    def test_server_diagnostic_reduces_unknown_live_state_to_task_fact(self):
        value = {"serverCorrelationId": REQUEST["serverCorrelationId"]}
        observed = {"state": "observed", **value, "task": "ready",
                    "lastResult": 1, "ready": "absent", "stateContent": "empty",
                    "stageAcl": "expected", "stateAcl": "expected", "replayAllowed": False}
        with patch.object(server, "diagnose_status", return_value=observed):
            result = mcp_server._vm_workflow_impl("windows-fixture-server-diagnostic", value)
        self.assertTrue(result["ok"])
        self.assertEqual(1, result["lastResult"])
        with patch.object(server, "diagnose_status", return_value={**observed, "secret": "path"}):
            result = mcp_server._vm_workflow_impl("windows-fixture-server-diagnostic", value)
        self.assertFalse(result["ok"])
        self.assertNotIn("path", str(result))

    def test_server_static_diagnostic_keeps_only_finite_read_results(self):
        value = {"serverCorrelationId": REQUEST["serverCorrelationId"]}
        observed = {"state": "observed", **value, "import": "ok",
                    "certificate": "failed", "resources": "skipped", "resourceGate": "skipped",
                    "replayAllowed": False}
        with patch.object(server, "diagnose_static", return_value=observed):
            result = mcp_server._vm_workflow_impl("windows-fixture-server-static-diagnostic", value)
        self.assertTrue(result["ok"])
        self.assertEqual("failed", result["certificate"])
        with patch.object(server, "diagnose_static", return_value={**observed, "secret": "path"}):
            result = mcp_server._vm_workflow_impl("windows-fixture-server-static-diagnostic", value)
        self.assertFalse(result["ok"])
        self.assertNotIn("path", str(result))
        with patch.object(server, "diagnose_static", return_value={"state": "diagnosed", **value,
                                                                  "phase": "guest-exit", "replayAllowed": False}):
            result = mcp_server._vm_workflow_impl("windows-fixture-server-static-diagnostic", value)
        self.assertTrue(result["ok"])
        self.assertEqual("guest-exit", result["phase"])

    def test_package_mode_repair_route_requires_exact_correlations_and_receipt(self):
        value = {"serverCorrelationId": REQUEST["serverCorrelationId"],
                 "repairCorrelationId": REQUEST["correlationId"]}
        with patch.object(mode_repair, "start", side_effect=AssertionError("dispatched")):
            self.assertFalse(mcp_server._vm_workflow_impl(
                "windows-fixture-package-mode-repair-start", {**value, "path": "C:\\other.msi"})["ok"])
        observed = {"state": "repaired", "repairCorrelationId": value["repairCorrelationId"],
                    "replayAllowed": False, "nativeActionAllowed": False}
        with patch.object(mode_repair, "start", return_value=observed):
            result = mcp_server._vm_workflow_impl("windows-fixture-package-mode-repair-start", value)
        self.assertTrue(result["ok"])
        with patch.object(mode_repair, "status", return_value={**observed, "secret": "path"}):
            result = mcp_server._vm_workflow_impl("windows-fixture-package-mode-repair-status",
                                                  {"repairCorrelationId": value["repairCorrelationId"]})
        self.assertFalse(result["ok"])
        self.assertNotIn("path", str(result))
        with patch.object(mode_repair, "diagnose", return_value={"state": "diagnosed",
                                                                  "repairCorrelationId": value["repairCorrelationId"],
                                                                  "phase": "guest-exit", "replayAllowed": False}):
            result = mcp_server._vm_workflow_impl("windows-fixture-package-mode-repair-diagnostic",
                                                  {"repairCorrelationId": value["repairCorrelationId"]})
        self.assertTrue(result["ok"])
        self.assertEqual("guest-exit", result["phase"])

    def test_server_abort_diagnostic_projects_only_finite_guest_result(self):
        value = {"cleanupCorrelationId": REQUEST["correlationId"]}
        observed = {"state": "observed", **value, "task": "terminal", "result": "nonzero",
                    "stdout": "absent", "stderr": "absent", "replayAllowed": False}
        with patch.object(server, "diagnose_abort", return_value=observed):
            result = mcp_server._vm_workflow_impl("windows-fixture-server-abort-diagnostic", value)
        self.assertTrue(result["ok"])
        self.assertEqual("nonzero", result["result"])
        with patch.object(server, "diagnose_abort", return_value={**observed, "errorText": "private"}):
            result = mcp_server._vm_workflow_impl("windows-fixture-server-abort-diagnostic", value)
        self.assertFalse(result["ok"])
        self.assertNotIn("private", str(result))


if __name__ == "__main__":
    unittest.main()

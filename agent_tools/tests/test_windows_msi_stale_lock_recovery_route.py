"""Fail-closed MCP boundary for the fixed CP117 stale-lock recovery."""

import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_msi_stale_lock_recovery as recovery


class WindowsMsiStaleLockRecoveryRouteTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start()
        self.addCleanup(guard.stop)

    def test_exact_host_and_bounded_result(self):
        recovered = {"state": "recovered", "replayAllowed": False,
                     "nativeActionAllowed": False}
        with patch.object(recovery, "recover", return_value=recovered) as call:
            result = mcp_server._vm_workflow_impl("windows-msi-stale-lock-recover",
                                                  {"host": "archlinux"})
        call.assert_called_once_with(mcp_server.REPO_ROOT, {"host": "archlinux"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["evidenceClass"], "native-recovery")
        self.assertFalse(result["nativeActionAllowed"])

        with patch.object(recovery, "recover", side_effect=AssertionError("unsafe dispatch")):
            invalid = mcp_server._vm_workflow_impl("windows-msi-stale-lock-recover",
                                                   {"host": "archlinux", "command": "delete"})
        self.assertFalse(invalid["ok"])

        for poisoned in ({**recovered, "nativeActionAllowed": True},
                         {**recovered, "privatePath": "secret"}):
            with patch.object(recovery, "recover", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl("windows-msi-stale-lock-recover",
                                                        {"host": "archlinux"})
            self.assertFalse(rejected["ok"])
            self.assertNotIn("secret", str(rejected))

    def test_read_only_diagnosis_is_bounded(self):
        diagnostic = {"state": "diagnosed", "category": "exclusive-handle-acl-blocked",
                      "replayAllowed": False, "nativeActionAllowed": False}
        with patch.object(recovery, "diagnose", return_value=diagnostic) as call:
            result = mcp_server._vm_workflow_impl("windows-msi-stale-lock-diagnose",
                                                  {"host": "archlinux"})
        call.assert_called_once_with(mcp_server.REPO_ROOT, {"host": "archlinux"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["category"], "exclusive-handle-acl-blocked")
        for poison in ({**diagnostic, "category": "private"},
                       {**diagnostic, "nativeActionAllowed": True}):
            with patch.object(recovery, "diagnose", return_value=poison):
                rejected = mcp_server._vm_workflow_impl("windows-msi-stale-lock-diagnose",
                                                        {"host": "archlinux"})
            self.assertFalse(rejected["ok"])
            self.assertNotIn("private", str(rejected))
        with patch.object(recovery, "reconciliation_status", return_value={
                "state": "separate-one-shot-required", "replayAllowed": False,
                "nativeActionAllowed": False}):
            status = mcp_server._vm_workflow_impl(
                "windows-msi-stale-lock-reconciliation-status", {"host": "archlinux"})
        self.assertTrue(status["ok"])
        self.assertFalse(status["nativeActionAllowed"])
        for code in (0, 50, 65535):
            with patch.object(recovery, "diagnose", return_value={
                    **diagnostic, "category": "lock-open-other", "win32Code": code}):
                observed = mcp_server._vm_workflow_impl("windows-msi-stale-lock-diagnose",
                                                        {"host": "archlinux"})
            self.assertTrue(observed["ok"])
            self.assertEqual(observed["win32Code"], code)
        with patch.object(recovery, "diagnose", return_value={
                **diagnostic, "category": "lock-open-other", "win32Code": True}):
            rejected = mcp_server._vm_workflow_impl("windows-msi-stale-lock-diagnose",
                                                    {"host": "archlinux"})
        self.assertFalse(rejected["ok"])


if __name__ == "__main__":
    unittest.main()

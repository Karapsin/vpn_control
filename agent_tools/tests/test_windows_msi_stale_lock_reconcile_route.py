"""Fixed MCP boundary for one-shot CP117 stale-lock reconciliation."""

import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_msi_stale_lock_reconcile as reconcile


class WindowsMsiStaleLockReconcileRouteTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start()
        self.addCleanup(guard.stop)

    def test_exact_input_and_phase_projection(self):
        cases = (("windows-msi-stale-lock-reconcile", "reconcile", "recovered"),
                 ("windows-msi-stale-lock-reconcile-status", "status", "terminal-proven"),
                 ("windows-msi-stale-lock-reconcile-close", "close", "recovered"))
        for action, method, state in cases:
            observed = {"state": state, "replayAllowed": False,
                        "nativeActionAllowed": False}
            with self.subTest(action=action), patch.object(reconcile, method,
                return_value=observed) as call:
                result = mcp_server._vm_workflow_impl(action, {"host": "archlinux"})
            call.assert_called_once_with(mcp_server.REPO_ROOT, {"host": "archlinux"})
            self.assertTrue(result["ok"])
            self.assertFalse(result["nativeActionAllowed"])
        with patch.object(reconcile, "reconcile", side_effect=AssertionError("unsafe dispatch")):
            rejected = mcp_server._vm_workflow_impl("windows-msi-stale-lock-reconcile",
                                                    {"host": "archlinux", "force": True})
        self.assertFalse(rejected["ok"])
        for poison in ({"state": "recovered", "replayAllowed": True,
                        "nativeActionAllowed": False},
                       {"state": "terminal-proven", "replayAllowed": False,
                        "nativeActionAllowed": False},
                       {"state": "recovered", "replayAllowed": False,
                        "nativeActionAllowed": False, "path": "secret"}):
            with patch.object(reconcile, "reconcile", return_value=poison):
                result = mcp_server._vm_workflow_impl("windows-msi-stale-lock-reconcile",
                                                      {"host": "archlinux"})
            self.assertFalse(result["ok"])
            self.assertNotIn("secret", str(result))


if __name__ == "__main__":
    unittest.main()

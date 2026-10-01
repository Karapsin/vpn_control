"""MCP projection for the fixed current CP117 owner quit."""

import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_msi_owner_relaunch_quit as quit_adapter


class RelaunchQuitRouteTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start()
        self.addCleanup(guard.stop)

    def test_exact_host_and_finite_results(self):
        outcomes = {"start": {"state": "submitted", "replayAllowed": False,
                              "nativeActionAllowed": False},
                    "status": {"state": "exited", "runtimeRunning": False,
                               "ownerExited": True, "replayAllowed": False,
                               "nativeActionAllowed": False},
                    "collect": {"state": "pending", "replayAllowed": False,
                                "nativeActionAllowed": False},
                    "diagnose": {"state": "diagnosed", "phase": "tasks", "task": "absent",
                                 "replayAllowed": False, "nativeActionAllowed": False}}
        for phase, value in outcomes.items():
            with self.subTest(phase=phase), patch.object(quit_adapter, "workflow",
                                                       return_value=value) as call:
                result = mcp_server._vm_workflow_impl(
                    "windows-msi-owner-relaunch-quit-" + phase, {"host": "archlinux"})
            call.assert_called_once_with(mcp_server.REPO_ROOT, phase, {"host": "archlinux"})
            self.assertEqual(result["state"], value["state"])
            self.assertEqual(result["ok"], phase != "collect")
        with patch.object(quit_adapter, "workflow", side_effect=AssertionError("unsafe")):
            invalid = mcp_server._vm_workflow_impl(
                "windows-msi-owner-relaunch-quit-start",
                {"host": "archlinux", "pid": 123})
        self.assertFalse(invalid["ok"])

    def test_diagnose_rejects_status_shape_and_private_fields(self):
        for value in ({"state": "exited", "runtimeRunning": False, "ownerExited": True,
                       "replayAllowed": False, "nativeActionAllowed": False},
                      {"state": "diagnosed", "phase": "tasks", "task": "secret",
                       "replayAllowed": False, "nativeActionAllowed": False},
                      {"state": "diagnosed", "phase": "tasks", "task": "absent",
                       "raw": "secret", "replayAllowed": False,
                       "nativeActionAllowed": False}):
            with patch.object(quit_adapter, "workflow", return_value=value):
                result = mcp_server._vm_workflow_impl(
                    "windows-msi-owner-relaunch-quit-diagnose", {"host": "archlinux"})
            self.assertFalse(result["ok"])
            self.assertNotIn("secret", str(result))

    def test_status_cannot_promote_start_submission(self):
        with patch.object(quit_adapter, "workflow", return_value={
            "state": "submitted", "replayAllowed": False,
            "nativeActionAllowed": False,
        }):
            result = mcp_server._vm_workflow_impl(
                "windows-msi-owner-relaunch-quit-status", {"host": "archlinux"})
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "unknown")


if __name__ == "__main__":
    unittest.main()

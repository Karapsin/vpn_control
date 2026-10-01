"""Finite MCP projection for the second fixed CP117 owner quit."""

import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_msi_owner_relaunch_quit_v2 as quit_v2


class RelaunchQuitV2RouteTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start()
        self.addCleanup(guard.stop)

    def test_fixed_host_and_phase_shapes(self):
        values = {
            "start": {"state": "submitted", "replayAllowed": False,
                      "nativeActionAllowed": False},
            "status": {"state": "exited", "runtimeRunning": False,
                       "ownerExited": True, "replayAllowed": False,
                       "nativeActionAllowed": False},
            "collect": {"state": "pending", "replayAllowed": False,
                        "nativeActionAllowed": False},
            "diagnose": {"state": "diagnosed", "phase": "tasks", "task": "absent",
                         "replayAllowed": False, "nativeActionAllowed": False},
            "bootstrap-diagnostic": {"state": "diagnosed", "gate": "v1-task-present",
                                     "replayAllowed": False, "nativeActionAllowed": False},
        }
        for phase, value in values.items():
            with self.subTest(phase=phase), patch.object(quit_v2, "workflow",
                                                       return_value=value) as call:
                result = mcp_server._vm_workflow_impl(
                    "windows-msi-owner-relaunch-quit-v2-" + phase,
                    {"host": "archlinux"})
            call.assert_called_once_with(mcp_server.REPO_ROOT, phase,
                                         {"host": "archlinux"})
            self.assertEqual(result["state"], value["state"])
            self.assertEqual(result["ok"], phase != "collect")
        with patch.object(quit_v2, "workflow", side_effect=AssertionError("unsafe")):
            bad = mcp_server._vm_workflow_impl(
                "windows-msi-owner-relaunch-quit-v2-start",
                {"host": "archlinux", "pid": 17})
        self.assertFalse(bad["ok"])

    def test_status_and_diagnose_reject_cross_phase_or_private_results(self):
        cases = (
            ("status", {"state": "submitted", "replayAllowed": False,
                        "nativeActionAllowed": False}),
            ("diagnose", {"state": "exited", "runtimeRunning": False,
                          "ownerExited": True, "replayAllowed": False,
                          "nativeActionAllowed": False}),
            ("diagnose", {"state": "diagnosed", "phase": "tasks", "task": "secret",
                          "replayAllowed": False, "nativeActionAllowed": False}),
            ("diagnose", {"state": "diagnosed", "phase": "tasks", "task": "absent",
                          "private": "secret", "replayAllowed": False,
                          "nativeActionAllowed": False}),
            ("bootstrap-diagnostic", {"state": "diagnosed", "gate": "secret",
                                      "replayAllowed": False,
                                      "nativeActionAllowed": False}),
            ("bootstrap-diagnostic", {"state": "diagnosed", "phase": "tasks",
                                      "task": "absent", "replayAllowed": False,
                                      "nativeActionAllowed": False}),
        )
        for phase, value in cases:
            with self.subTest(phase=phase, value=value), patch.object(
                    quit_v2, "workflow", return_value=value):
                result = mcp_server._vm_workflow_impl(
                    "windows-msi-owner-relaunch-quit-v2-" + phase,
                    {"host": "archlinux"})
            self.assertFalse(result["ok"])
            self.assertEqual(result["state"], "unknown")
            self.assertNotIn("secret", str(result))


if __name__ == "__main__":
    unittest.main()

"""Finite MCP projection for the third fixed CP117 owner quit."""

import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_msi_owner_relaunch_quit_v3 as quit_v3


class RelaunchQuitV3RouteTest(unittest.TestCase):
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
            "bootstrap-diagnostic": {"state": "diagnosed", "gate": "prior-quit-task-present",
                                     "replayAllowed": False, "nativeActionAllowed": False},
        }
        for phase, value in values.items():
            with self.subTest(phase=phase), patch.object(quit_v3, "workflow",
                                                       return_value=value) as call:
                result = mcp_server._vm_workflow_impl(
                    "windows-msi-owner-relaunch-quit-v3-" + phase,
                    {"host": "archlinux"})
            call.assert_called_once_with(mcp_server.REPO_ROOT, phase,
                                         {"host": "archlinux"})
            self.assertEqual(result["state"], value["state"])
            self.assertEqual(result["ok"], phase != "collect")
        with patch.object(quit_v3, "workflow", side_effect=AssertionError("unsafe")):
            bad = mcp_server._vm_workflow_impl(
                "windows-msi-owner-relaunch-quit-v3-start",
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
                    quit_v3, "workflow", return_value=value):
                result = mcp_server._vm_workflow_impl(
                    "windows-msi-owner-relaunch-quit-v3-" + phase,
                    {"host": "archlinux"})
            self.assertFalse(result["ok"])
            self.assertEqual(result["state"], "unknown")
            self.assertNotIn("secret", str(result))

    def test_task_result_is_bounded_outcome_only(self):
        for state in ("pending", "exited", "failed"):
            with patch.object(quit_v3, "workflow", return_value={
                "state": state, "replayAllowed": False, "nativeActionAllowed": False,
            }) as call:
                result = mcp_server._vm_workflow_impl(
                    "windows-msi-owner-relaunch-quit-v3-task-result", {"host": "archlinux"})
            call.assert_called_once_with(mcp_server.REPO_ROOT, "task-result",
                                         {"host": "archlinux"})
            self.assertEqual(result["state"], state)
            self.assertFalse(result["ok"])
            self.assertEqual(result["evidenceClass"], "causal-diagnostic")
        with patch.object(quit_v3, "workflow", return_value={
            "state": "failed", "raw": "secret", "replayAllowed": False,
            "nativeActionAllowed": False,
        }):
            rejected = mcp_server._vm_workflow_impl(
                "windows-msi-owner-relaunch-quit-v3-task-result", {"host": "archlinux"})
        self.assertEqual(rejected["state"], "unknown")
        self.assertNotIn("secret", str(rejected))


if __name__ == "__main__":
    unittest.main()

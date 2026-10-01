"""Bounded MCP route for the third CP117 public status observation."""

import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_msi_owner_public_status_third as third


class ThirdPublicStatusRouteTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start()
        self.addCleanup(guard.stop)

    def test_exact_host_and_finite_projection(self):
        for phase in ("start", "status", "collect"):
            with self.subTest(phase=phase):
                with patch.object(third, "workflow", return_value={
                    "state": "proved", "runtimeRunning": False,
                    "replayAllowed": False, "nativeActionAllowed": False,
                }) as call:
                    result = mcp_server._vm_workflow_impl(
                        "windows-msi-owner-public-status-third-" + phase,
                        {"host": "archlinux"})
                call.assert_called_once_with(mcp_server.REPO_ROOT, phase,
                                             {"host": "archlinux"})
                self.assertTrue(result["ok"])
                self.assertEqual(result["evidenceClass"], "native-public-status")
        with patch.object(third, "workflow", side_effect=AssertionError("dispatched")):
            invalid = mcp_server._vm_workflow_impl(
                "windows-msi-owner-public-status-third-start",
                {"host": "archlinux", "task": "foreign"})
        self.assertFalse(invalid["ok"])

    def test_unknown_and_private_values_are_not_promoted(self):
        for value in (
            {"state": "unknown", "replayAllowed": False, "nativeActionAllowed": False},
            {"state": "pending", "replayAllowed": False, "nativeActionAllowed": False},
            {"state": "proved", "runtimeRunning": True,
             "replayAllowed": False, "nativeActionAllowed": False},
            {"state": "proved", "runtimeRunning": False, "secret": "token",
             "replayAllowed": False, "nativeActionAllowed": False},
        ):
            with patch.object(third, "workflow", return_value=value):
                result = mcp_server._vm_workflow_impl(
                    "windows-msi-owner-public-status-third-status", {"host": "archlinux"})
            self.assertFalse(result["ok"])
            self.assertNotIn("token", str(result))

    def test_observer_has_finite_no_replay_projection(self):
        observed = {"state": "diagnosed", "stage": "task-observer", "phase": "task",
                    "task": "absent", "replayAllowed": False,
                    "nativeActionAllowed": False}
        with patch.object(third, "workflow", return_value=observed) as call:
            result = mcp_server._vm_workflow_impl(
                "windows-msi-owner-public-status-third-observe", {"host": "archlinux"})
        call.assert_called_once_with(mcp_server.REPO_ROOT, "third-diagnostic",
                                     {"host": "archlinux"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["task"], "absent")
        for value in ({"state": "blocked", "stage": "generation", "replayAllowed": False,
                       "nativeActionAllowed": False},
                      {"state": "unknown", "stage": "task-observer", "replayAllowed": False,
                       "nativeActionAllowed": False},
                      {"state": "proved", "runtimeRunning": False,
                       "replayAllowed": False, "nativeActionAllowed": False},
                      {**observed, "task": "private-token"},
                      {**observed, "raw": "private-token"}):
            with patch.object(third, "workflow", return_value=value):
                result = mcp_server._vm_workflow_impl(
                    "windows-msi-owner-public-status-third-observe", {"host": "archlinux"})
            self.assertFalse(result["ok"])
            self.assertNotIn("private-token", str(result))


if __name__ == "__main__":
    unittest.main()

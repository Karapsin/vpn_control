"""Bounded MCP projection for CP117 original-user public status."""

import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_msi_owner_public_status as public


class WindowsMsiOwnerPublicStatusRouteTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start()
        self.addCleanup(guard.stop)

    def test_exact_host_and_bounded_phases(self):
        for phase in ("start", "status", "collect"):
            with self.subTest(phase=phase), patch.object(public, "workflow", return_value={
                "state": "proved", "runtimeRunning": False,
                "replayAllowed": False, "nativeActionAllowed": False}) as call:
                result = mcp_server._vm_workflow_impl(
                    "windows-msi-owner-public-status-" + phase, {"host": "archlinux"})
            call.assert_called_once_with(mcp_server.REPO_ROOT, phase,
                                         {"host": "archlinux"})
            self.assertTrue(result["ok"])
            self.assertEqual(result["evidenceClass"], "native-public-status")
            self.assertFalse(result["productAction"])
        with patch.object(public, "workflow", side_effect=AssertionError("unsafe")):
            rejected = mcp_server._vm_workflow_impl(
                "windows-msi-owner-public-status-start",
                {"host": "archlinux", "endpoint": "secret"})
        self.assertFalse(rejected["ok"])

    def test_unknown_pending_and_poisoned_results(self):
        for state in ("unknown", "pending"):
            with patch.object(public, "workflow", return_value={
                "state": state, "replayAllowed": False,
                "nativeActionAllowed": False}):
                result = mcp_server._vm_workflow_impl(
                    "windows-msi-owner-public-status-status", {"host": "archlinux"})
            self.assertFalse(result["ok"])
            self.assertEqual(result["state"], state)
        for poisoned in (
            {"state": "proved", "runtimeRunning": True,
             "replayAllowed": False, "nativeActionAllowed": False},
            {"state": "proved", "runtimeRunning": False, "token": "secret",
             "replayAllowed": False, "nativeActionAllowed": False},
            {"state": "pending", "replayAllowed": True,
             "nativeActionAllowed": False},
        ):
            with patch.object(public, "workflow", return_value=poisoned):
                result = mcp_server._vm_workflow_impl(
                    "windows-msi-owner-public-status-collect", {"host": "archlinux"})
            self.assertEqual(result["state"], "unknown")
            self.assertNotIn("secret", str(result))

    def test_diagnostic_is_bounded_and_read_only(self):
        observed = {"state": "diagnosed", "phase": "endpoint", "task": "absent",
                    "replayAllowed": False, "nativeActionAllowed": False}
        with patch.object(public, "workflow", return_value=observed) as call:
            result = mcp_server._vm_workflow_impl(
                "windows-msi-owner-public-status-diagnose", {"host": "archlinux"})
        call.assert_called_once_with(mcp_server.REPO_ROOT, "diagnose", {"host": "archlinux"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["evidenceClass"], "causal-diagnostic")
        for poisoned in ({**observed, "task": "secret"},
                         {**observed, "endpoint": "private"},
                         {**observed, "nativeActionAllowed": True}):
            with patch.object(public, "workflow", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl(
                    "windows-msi-owner-public-status-diagnose", {"host": "archlinux"})
            self.assertFalse(rejected["ok"])
            self.assertNotIn("secret", str(rejected))
            self.assertNotIn("private", str(rejected))


if __name__ == "__main__":
    unittest.main()

"""Exact MCP projection for the separate CP117 public-status retry."""

import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_msi_owner_public_status_retry as retry


class WindowsMsiOwnerPublicStatusRetryRouteTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start(); self.addCleanup(guard.stop)

    def test_preflight_exact_host_and_finite_gates(self):
        for state, gate, accepted in (("ready", "ready", True),
                                      ("blocked", "account", False),
                                      ("unknown", "unknown", False)):
            value = {"state": state, "gate": gate, "replayAllowed": False,
                     "nativeActionAllowed": False}
            with patch.object(retry, "workflow", return_value=value) as call:
                result = mcp_server._vm_workflow_impl(
                    "windows-msi-owner-public-status-retry-preflight", {"host": "archlinux"})
            call.assert_called_once_with(mcp_server.REPO_ROOT, "preflight", {"host": "archlinux"})
            self.assertEqual(result["ok"], accepted)
            self.assertEqual(result["gate"], gate)
        with patch.object(retry, "workflow", side_effect=AssertionError("unsafe dispatch")):
            invalid = mcp_server._vm_workflow_impl(
                "windows-msi-owner-public-status-retry-preflight",
                {"host": "archlinux", "task": "foreign"})
        self.assertFalse(invalid["ok"])
        for poison in ({"state": "ready", "gate": "secret", "replayAllowed": False,
                        "nativeActionAllowed": False},
                       {"state": "ready", "gate": "ready", "credential": "secret",
                        "replayAllowed": False, "nativeActionAllowed": False}):
            with patch.object(retry, "workflow", return_value=poison):
                rejected = mcp_server._vm_workflow_impl(
                    "windows-msi-owner-public-status-retry-preflight", {"host": "archlinux"})
            self.assertFalse(rejected["ok"])
            self.assertNotIn("secret", str(rejected))

    def test_start_status_collect_are_bounded_and_non_replayable(self):
        for phase in ("start", "status", "collect"):
            with self.subTest(phase=phase), patch.object(retry, "workflow", return_value={
                "state": "proved", "runtimeRunning": False,
                "replayAllowed": False, "nativeActionAllowed": False}) as call:
                result = mcp_server._vm_workflow_impl(
                    "windows-msi-owner-public-status-retry-" + phase, {"host": "archlinux"})
            call.assert_called_once_with(mcp_server.REPO_ROOT, phase, {"host": "archlinux"})
            self.assertTrue(result["ok"])
        for poison in ({"state": "proved", "runtimeRunning": True,
                        "replayAllowed": False, "nativeActionAllowed": False},
                       {"state": "pending", "private": "secret",
                        "replayAllowed": False, "nativeActionAllowed": False}):
            with patch.object(retry, "workflow", return_value=poison):
                rejected = mcp_server._vm_workflow_impl(
                    "windows-msi-owner-public-status-retry-status", {"host": "archlinux"})
            self.assertFalse(rejected["ok"])
            self.assertNotIn("secret", str(rejected))

    def test_diagnose_projects_only_fixed_task_categories(self):
        observed = {"state": "diagnosed", "phase": "task", "task": "failed",
                    "replayAllowed": False, "nativeActionAllowed": False}
        with patch.object(retry, "workflow", return_value=observed) as call:
            result = mcp_server._vm_workflow_impl(
                "windows-msi-owner-public-status-retry-diagnose", {"host": "archlinux"})
        call.assert_called_once_with(mcp_server.REPO_ROOT, "diagnose", {"host": "archlinux"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["evidenceClass"], "causal-diagnostic")
        for poison in ({**observed, "task": "secret"},
                       {**observed, "rawError": "secret"}):
            with patch.object(retry, "workflow", return_value=poison):
                rejected = mcp_server._vm_workflow_impl(
                    "windows-msi-owner-public-status-retry-diagnose", {"host": "archlinux"})
            self.assertFalse(rejected["ok"])
            self.assertNotIn("secret", str(rejected))

    def test_observe_survives_changed_owner_census_with_finite_stage(self):
        observed = {"state": "diagnosed", "stage": "task-observer",
                    "phase": "task", "task": "failed", "replayAllowed": False,
                    "nativeActionAllowed": False}
        with patch.object(retry, "workflow", return_value=observed) as call:
            result = mcp_server._vm_workflow_impl(
                "windows-msi-owner-public-status-retry-observe", {"host": "archlinux"})
        call.assert_called_once_with(mcp_server.REPO_ROOT, "retry-diagnostic",
                                     {"host": "archlinux"})
        self.assertTrue(result["ok"])
        for value in ({"state": "blocked", "stage": "generation",
                       "replayAllowed": False, "nativeActionAllowed": False},
                      {"state": "unknown", "stage": "task-observer",
                       "replayAllowed": False, "nativeActionAllowed": False}):
            with patch.object(retry, "workflow", return_value=value):
                finite = mcp_server._vm_workflow_impl(
                    "windows-msi-owner-public-status-retry-observe", {"host": "archlinux"})
            self.assertFalse(finite["ok"])
            self.assertEqual(finite["stage"], value["stage"])
        with patch.object(retry, "workflow", return_value={**observed, "raw": "secret"}):
            poisoned = mcp_server._vm_workflow_impl(
                "windows-msi-owner-public-status-retry-observe", {"host": "archlinux"})
        self.assertFalse(poisoned["ok"])
        self.assertNotIn("secret", str(poisoned))


if __name__ == "__main__":
    unittest.main()

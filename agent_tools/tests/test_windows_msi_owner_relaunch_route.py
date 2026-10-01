"""MCP boundary for the fixed one-shot CP117 owner relaunch."""

import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_msi_owner_relaunch as relaunch


class WindowsMsiOwnerRelaunchRouteTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start()
        self.addCleanup(guard.stop)

    def test_exact_host_and_phase_projection(self):
        launched = {"state": "launched", "sourceSha": relaunch._SOURCE,
                    "correlationId": relaunch._CORRELATION,
                    "installedCliSha256": "a" * 64, "ownerPid": 123,
                    "sessionId": 1, "runtimeRunning": False,
                    "replayAllowed": False, "nativeActionAllowed": False}
        for phase in ("launch", "status", "collect"):
            with self.subTest(phase=phase), patch.object(relaunch, "workflow",
                return_value=launched) as call:
                result = mcp_server._vm_workflow_impl(
                    "windows-msi-owner-relaunch-" + phase, {"host": "archlinux"})
            call.assert_called_once_with(mcp_server.REPO_ROOT, phase, {"host": "archlinux"})
            self.assertTrue(result["ok"])
            self.assertFalse(result["nativeActionAllowed"])
        with patch.object(relaunch, "workflow", side_effect=AssertionError("unsafe dispatch")):
            invalid = mcp_server._vm_workflow_impl("windows-msi-owner-relaunch-launch",
                                                   {"host": "archlinux", "command": "quit"})
        self.assertFalse(invalid["ok"])
        for poison in ({**launched, "runtimeRunning": True},
                       {**launched, "privatePath": "secret"},
                       {**launched, "ownerPid": True}):
            with patch.object(relaunch, "workflow", return_value=poison):
                rejected = mcp_server._vm_workflow_impl(
                    "windows-msi-owner-relaunch-status", {"host": "archlinux"})
            self.assertFalse(rejected["ok"])
            self.assertNotIn("secret", str(rejected))

    def test_diagnose_exact_bounded_projection(self):
        observed = {"state": "diagnosed", "phase": "owner-process-count-many",
                    "task": "exact", "owners": "many", "endpoint": "valid",
                    "replayAllowed": False, "nativeActionAllowed": False}
        with patch.object(relaunch, "workflow", return_value=observed) as call:
            result = mcp_server._vm_workflow_impl("windows-msi-owner-relaunch-diagnose",
                                                  {"host": "archlinux"})
        call.assert_called_once_with(mcp_server.REPO_ROOT, "diagnose", {"host": "archlinux"})
        self.assertTrue(result["ok"])
        for poison in ({**observed, "phase": "private"},
                       {**observed, "path": "secret"},
                       {**observed, "nativeActionAllowed": True}):
            with patch.object(relaunch, "workflow", return_value=poison):
                rejected = mcp_server._vm_workflow_impl("windows-msi-owner-relaunch-diagnose",
                                                        {"host": "archlinux"})
            self.assertFalse(rejected["ok"])
            self.assertNotIn("secret", str(rejected))

    def test_detail_projects_only_finite_categories(self):
        observed = {"state": "detailed", "baseOwners": "many",
                    "quotedStateServe": "one", "unquotedStateServe": "none",
                    "otherSubcommand": "none", "unrelated": "one",
                    "ownerIdentity": "exact", "endpoint": "valid",
                    "schemaVersion": "valid", "controllerId": "valid",
                    "port": "valid", "token": "valid",
                    "replayAllowed": False, "nativeActionAllowed": False}
        with patch.object(relaunch, "workflow", return_value=observed) as call:
            result = mcp_server._vm_workflow_impl("windows-msi-owner-relaunch-detail",
                                                  {"host": "archlinux"})
        call.assert_called_once_with(mcp_server.REPO_ROOT, "detail", {"host": "archlinux"})
        self.assertTrue(result["ok"])
        for poison in ({**observed, "unrelated": "secret"},
                       {**observed, "path": "secret"},
                       {**observed, "token": "actual-token"}):
            with patch.object(relaunch, "workflow", return_value=poison):
                rejected = mcp_server._vm_workflow_impl("windows-msi-owner-relaunch-detail",
                                                        {"host": "archlinux"})
            self.assertFalse(rejected["ok"])
            self.assertNotIn("secret", str(rejected))
        with patch.object(relaunch, "workflow", return_value={
                "state": "endpoint-access", "endpoint": "access-denied",
                "replayAllowed": False, "nativeActionAllowed": False}) as call:
            endpoint = mcp_server._vm_workflow_impl("windows-msi-owner-relaunch-endpoint-access",
                                                   {"host": "archlinux"})
        call.assert_called_once_with(mcp_server.REPO_ROOT, "endpoint-access",
                                     {"host": "archlinux"})
        self.assertTrue(endpoint["ok"])
        with patch.object(relaunch, "workflow", return_value={
                "state": "endpoint-access", "endpoint": "raw-token",
                "replayAllowed": False, "nativeActionAllowed": False}):
            invalid = mcp_server._vm_workflow_impl("windows-msi-owner-relaunch-endpoint-access",
                                                   {"host": "archlinux"})
        self.assertFalse(invalid["ok"])


if __name__ == "__main__":
    unittest.main()

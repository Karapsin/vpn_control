"""Finite MCP projection for fixed CP117 owner quit phase diagnosis."""

import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_msi_owner_quit_phase_diagnostic as phase_adapter


class OwnerQuitPhaseRouteTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start()
        self.addCleanup(guard.stop)

    def test_exact_host_and_bounded_phases(self):
        for phase, value in (
            ("start", {"state": "submitted", "replayAllowed": False,
                       "nativeActionAllowed": False}),
            ("status", {"state": "diagnosed", "phase": "endpoint",
                        "replayAllowed": False, "nativeActionAllowed": False}),
            ("collect", {"state": "pending", "replayAllowed": False,
                         "nativeActionAllowed": False}),
        ):
            with self.subTest(phase=phase), patch.object(phase_adapter, "workflow",
                                                       return_value=value) as call:
                result = mcp_server._vm_workflow_impl(
                    "windows-msi-owner-quit-phase-" + phase, {"host": "archlinux"})
            call.assert_called_once_with(mcp_server.REPO_ROOT, phase,
                                         {"host": "archlinux"})
            self.assertEqual(result["state"], value["state"])
            self.assertFalse(result["productAction"])
        with patch.object(phase_adapter, "workflow", side_effect=AssertionError("unsafe")):
            rejected = mcp_server._vm_workflow_impl(
                "windows-msi-owner-quit-phase-start", {"host": "archlinux", "pid": 1})
        self.assertFalse(rejected["ok"])

    def test_private_or_unrecognised_phase_is_unknown(self):
        for value in (
            {"state": "diagnosed", "phase": "secret", "replayAllowed": False,
             "nativeActionAllowed": False},
            {"state": "diagnosed", "phase": "endpoint", "raw": "secret",
             "replayAllowed": False, "nativeActionAllowed": False},
            {"state": "submitted", "replayAllowed": False,
             "nativeActionAllowed": False},
        ):
            with patch.object(phase_adapter, "workflow", return_value=value):
                result = mcp_server._vm_workflow_impl(
                    "windows-msi-owner-quit-phase-status", {"host": "archlinux"})
            self.assertFalse(result["ok"])
            self.assertNotIn("secret", str(result))


if __name__ == "__main__":
    unittest.main()

"""The fixed Arch privilege read rejects foreign and malformed inputs before SSH."""
from __future__ import annotations

import unittest
from unittest import mock

from agent_tools import mcp_server


REQUEST = {"host": "archlinux", "timeoutSeconds": 20}


class WindowsVmVirtFirmwareAdmissionRouteTest(unittest.TestCase):
    def test_exact_read_only_route(self):
        with mock.patch.object(mcp_server, "_agent_module") as module:
            module.return_value.observe.return_value = {
                "state": "sudo-nopasswd-pacman", "host": "archlinux",
                "noninteractivePacmanEligible": True,
                "nativeActionAllowed": False,
            }
            result = mcp_server._vm_workflow_impl("windows-vm-virt-firmware-admission", REQUEST)
            self.assertTrue(result["ok"])
            self.assertFalse(result["nativeActionAllowed"])
            self.assertFalse(result["productAction"])
            module.assert_called_once_with("windows_vm_virt_firmware_admission")
            module.return_value.observe.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)

    def test_invalid_host_timeout_or_extra_key_cannot_dispatch(self):
        with mock.patch.object(mcp_server, "_agent_module") as module:
            for changed in ({"host": "other"}, {"timeoutSeconds": 9},
                            {"timeoutSeconds": 31}, {"timeoutSeconds": True},
                            {"extra": "x"}):
                with self.subTest(changed=changed):
                    result = mcp_server._vm_workflow_impl(
                        "windows-vm-virt-firmware-admission", {**REQUEST, **changed})
                    self.assertFalse(result["ok"])
            module.assert_not_called()

    def test_unknown_or_contradictory_result_does_not_admit(self):
        with mock.patch.object(mcp_server, "_agent_module") as module:
            for value in (
                {"state": "unknown", "nativeActionAllowed": False},
                {"state": "unexpected", "nativeActionAllowed": False},
                {"state": "sudo-listing-inconclusive", "host": "archlinux",
                 "noninteractivePacmanEligible": True, "nativeActionAllowed": False},
                {"state": "sudo-nopasswd-pacman", "host": "archlinux",
                 "noninteractivePacmanEligible": False, "nativeActionAllowed": False},
                {"state": "sudo-nopasswd-pacman", "host": "other",
                 "noninteractivePacmanEligible": True, "nativeActionAllowed": False},
            ):
                with self.subTest(value=value):
                    module.return_value.observe.return_value = value
                    result = mcp_server._vm_workflow_impl("windows-vm-virt-firmware-admission", REQUEST)
                    self.assertFalse(result["ok"])
                    self.assertFalse(result["nativeActionAllowed"])
                    self.assertFalse(result["noninteractivePacmanEligible"])

    def test_observer_exception_has_explicit_false_eligibility(self):
        with mock.patch.object(mcp_server, "_agent_module") as module:
            module.return_value.observe.side_effect = OSError("unavailable")
            result = mcp_server._vm_workflow_impl("windows-vm-virt-firmware-admission", REQUEST)
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "unknown")
        self.assertIs(result["noninteractivePacmanEligible"], False)
        self.assertFalse(result["nativeActionAllowed"])


if __name__ == "__main__":
    unittest.main()

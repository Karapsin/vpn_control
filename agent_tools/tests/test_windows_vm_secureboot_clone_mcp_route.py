"""The clone preflight route cannot accept foreign sources or dispatch mutations."""
from __future__ import annotations

import unittest
from unittest import mock

from agent_tools import mcp_server
from agent_tools.windows_vm_secureboot_clone import BASELINE_RESERVATION, OWNER_PID, OWNER_TICKS


REQUEST = {"host": "archlinux", "ownerPid": OWNER_PID, "ownerStartTicks": OWNER_TICKS,
           "baselineReservationId": BASELINE_RESERVATION, "timeoutSeconds": 30}


class WindowsVmSecurebootCloneRouteTest(unittest.TestCase):
    def test_exact_read_only_dispatch_and_blocked_is_a_valid_receipt(self):
        with mock.patch.object(mcp_server, "_agent_module") as module:
            module.return_value.preflight.return_value = {"state": "blocked", "nativeActionAllowed": False}
            result = mcp_server._vm_workflow_impl("windows-vm-secureboot-clone-preflight", REQUEST)
            self.assertTrue(result["ok"])
            self.assertEqual(result["state"], "blocked")
            self.assertFalse(result["nativeActionAllowed"])
            module.return_value.preflight.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
            module.return_value.preflight.return_value = {"state": "unknown", "nativeActionAllowed": False}
            self.assertFalse(mcp_server._vm_workflow_impl("windows-vm-secureboot-clone-preflight", REQUEST)["ok"])

    def test_invalid_owner_resource_or_extra_input_never_dispatches(self):
        with mock.patch.object(mcp_server, "_agent_module") as module:
            for changed in ({"host": "other"}, {"ownerPid": 1}, {"ownerStartTicks": 1},
                            {"baselineReservationId": "other"}, {"timeoutSeconds": 120},
                            {"sourceDisk": "/home/kardinal/CP117/disk.qcow2"}):
                with self.subTest(changed=changed):
                    result = mcp_server._vm_workflow_impl(
                        "windows-vm-secureboot-clone-preflight", {**REQUEST, **changed})
                    self.assertFalse(result["ok"])
            module.assert_not_called()


if __name__ == "__main__":
    unittest.main()

"""The fixed TPM/Secure Boot read must reject foreign VM inputs before dispatch."""
from __future__ import annotations

import unittest
from unittest import mock

from agent_tools import mcp_server


REQUEST = {"host": "archlinux", "qemuPid": 3369984,
           "startTicks": 45177745, "timeoutSeconds": 30}


class WindowsVmSecurebootInventoryRouteTest(unittest.TestCase):
    def test_exact_read_only_route_and_nonreplayable_unknown(self):
        observed = {"state": "observed", "nativeActionAllowed": False}
        with mock.patch.object(mcp_server, "_agent_module") as module:
            module.return_value.observe.return_value = observed
            result = mcp_server._vm_workflow_impl("windows-vm-secureboot-inventory", REQUEST)
            self.assertTrue(result["ok"])
            self.assertFalse(result["nativeActionAllowed"])
            module.return_value.observe.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
            module.return_value.observe.reset_mock()
            module.return_value.observe.return_value = {"state": "unknown", "nativeActionAllowed": False}
            result = mcp_server._vm_workflow_impl("windows-vm-secureboot-inventory", REQUEST)
            self.assertFalse(result["ok"])

    def test_invalid_host_or_generation_cannot_dispatch(self):
        with mock.patch.object(mcp_server, "_agent_module") as module:
            for changed in ({"host": "other"}, {"qemuPid": 1}, {"startTicks": 1},
                            {"timeoutSeconds": 120}, {"extra": "x"}):
                with self.subTest(changed=changed):
                    result = mcp_server._vm_workflow_impl(
                        "windows-vm-secureboot-inventory", {**REQUEST, **changed})
                    self.assertFalse(result["ok"])
            module.assert_not_called()

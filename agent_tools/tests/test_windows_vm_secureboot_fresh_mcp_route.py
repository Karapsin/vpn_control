"""Fixed MCP route for independent Secure Boot VM cannot target other disks."""
from __future__ import annotations

import unittest
from unittest import mock

from agent_tools import mcp_server
from agent_tools import windows_vm_secureboot_fresh as subject


CORR = "123e4567-e89b-12d3-a456-426614174000"
REQUEST = {"host": "archlinux", "correlationId": CORR, "timeoutSeconds": 60}


class WindowsVmSecurebootFreshRouteTest(unittest.TestCase):
    def test_preflight_start_status_have_only_fixed_dispatch(self):
        with mock.patch.object(mcp_server, "_agent_module") as module:
            module.return_value.preflight.return_value = {
                "state": "blocked", "reason": "host-components-unavailable",
                "missingHostComponents": ["edk2-ovmf-package"],
                "hostComponentAdmission": {"edk2-ovmf-package": "integrity-failed"},
            }
            preflight = mcp_server._vm_workflow_impl("windows-vm-secureboot-fresh-preflight", REQUEST)
            self.assertFalse(preflight["ok"])
            self.assertFalse(preflight["nativeActionAllowed"])
            self.assertEqual(preflight["missingHostComponents"], ["edk2-ovmf-package"])
            self.assertEqual(preflight["hostComponentAdmission"],
                             {"edk2-ovmf-package": "integrity-failed"})
            module.return_value.preflight.assert_called_once_with(
                mcp_server.REPO_ROOT, host="archlinux", correlation_id=CORR, timeout_seconds=60)
            reservation = {"hostAlias": "archlinux", "environment": subject.ENVIRONMENT,
                           "operator": subject.OPERATOR, "requestedMemoryBytes": subject.MEMORY_MIB * 1024 * 1024,
                           "allocationState": "pending", "reservationIdentity": {}}
            module.return_value.start.return_value = {
                "state": "blocked", "reason": "host-components-unavailable",
                "missingHostComponents": ["swtpm-package"],
                "hostComponentAdmission": {"swtpm-package": "integrity-failed"},
                "replayAllowed": False,
            }
            start = mcp_server._vm_workflow_impl("windows-vm-secureboot-fresh-start",
                                                 {**REQUEST, "reservationRequest": reservation})
            self.assertFalse(start["ok"])
            self.assertFalse(start["replayAllowed"])
            self.assertEqual(start["missingHostComponents"], ["swtpm-package"])
            self.assertEqual(start["hostComponentAdmission"],
                             {"swtpm-package": "integrity-failed"})
            module.return_value.start.assert_called_once_with(
                mcp_server.REPO_ROOT, reservation_request=reservation,
                host="archlinux", correlation_id=CORR, timeout_seconds=60)
            module.return_value.status.return_value = {"state": "partial-unknown", "replayAllowed": False}
            status = mcp_server._vm_workflow_impl("windows-vm-secureboot-fresh-status", REQUEST)
            self.assertFalse(status["ok"])
            module.return_value.status.assert_called_once_with(
                mcp_server.REPO_ROOT, host="archlinux", correlation_id=CORR, timeout_seconds=60)

    def test_wrong_host_path_extra_or_missing_reservation_never_dispatch(self):
        with mock.patch.object(mcp_server, "_agent_module") as module:
            for changed in ({"host": "other"}, {"correlationId": "bad"},
                            {"timeoutSeconds": 500}, {"sourceDisk": "/home/kardinal/CP117/disk.qcow2"}):
                with self.subTest(changed=changed):
                    self.assertFalse(mcp_server._vm_workflow_impl(
                        "windows-vm-secureboot-fresh-preflight", {**REQUEST, **changed})["ok"])
            self.assertFalse(mcp_server._vm_workflow_impl("windows-vm-secureboot-fresh-start", REQUEST)["ok"])
            self.assertFalse(mcp_server._vm_workflow_impl(
                "windows-vm-secureboot-fresh-start", {**REQUEST, "reservationRequest": "bad"})["ok"])
            module.assert_not_called()


if __name__ == "__main__":
    unittest.main()

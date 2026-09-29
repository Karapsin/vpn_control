"""MCP admission for read-only disposable Windows install-disk proof."""
import unittest
from unittest.mock import Mock, patch

from agent_tools import mcp_server


class WindowsInstallDiskProofRouteTest(unittest.TestCase):
    def test_fixed_read_only_route(self):
        request = {"host": "archlinux", "timeoutSeconds": 90}
        adapter = Mock()
        adapter.preflight.return_value = {"state": "ready", "replayAllowed": False,
                                          "nativeActionAllowed": False}
        with patch.object(mcp_server, "_agent_module", return_value=adapter) as module:
            result = mcp_server._vm_workflow_impl("windows-vm-setup-install-disk-proof", request)
        module.assert_called_once_with("windows_vm_setup_install_disk_proof")
        adapter.preflight.assert_called_once_with(mcp_server.REPO_ROOT, host="archlinux", timeout_seconds=90)
        self.assertTrue(result["ok"])
        self.assertFalse(result["nativeActionAllowed"])

    def test_foreign_host_and_extra_input_block_before_dispatch(self):
        with patch.object(mcp_server, "_agent_module") as module:
            for request in ({"host": "other", "timeoutSeconds": 90},
                            {"host": "archlinux", "timeoutSeconds": 90, "disk": "/dev/sda"},
                            {"host": "archlinux", "timeoutSeconds": 301}):
                self.assertFalse(mcp_server._vm_workflow_impl(
                    "windows-vm-setup-install-disk-proof", request)["ok"])
            module.assert_not_called()


if __name__ == "__main__":
    unittest.main()

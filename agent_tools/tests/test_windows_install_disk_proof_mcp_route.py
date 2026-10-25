"""MCP admission for read-only disposable Windows install-disk proof."""
import unittest
from unittest.mock import Mock, patch, call

from agent_tools import mcp_server
from agent_tools.tests import route_adapter


class WindowsInstallDiskProofRouteTest(unittest.TestCase):
    def test_fixed_read_only_route(self):
        request = {"host": "archlinux", "timeoutSeconds": 90}
        adapter = Mock()
        adapter.preflight.return_value = {"state": "ready", "replayAllowed": False,
                                          "nativeActionAllowed": False}
        with patch.object(mcp_server, "_agent_module", side_effect=route_adapter.admitted_adapter(adapter)) as module:
            result = mcp_server._vm_workflow_impl("windows-vm-setup-install-disk-proof", request)
        self.assertEqual([call("windows_vm_setup_install_disk_proof")], route_adapter.adapter_calls(module))
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

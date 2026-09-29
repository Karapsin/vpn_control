"""MCP admission for one fixed Windows Setup install-option acknowledgment action."""

import unittest
from unittest.mock import Mock, patch

from agent_tools import mcp_server


class SetupInstallAckRouteTest(unittest.TestCase):
    def test_exact_four_action_routes_and_no_replay_on_unknown(self):
        request = {"host": "archlinux", "nextCorrelationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                   "timeoutSeconds": 60}
        states = {"preflight": "ready", "start": "after-observed",
                  "status": "after-observed", "collect": "collected"}
        for suffix, state in states.items():
            with self.subTest(suffix=suffix):
                adapter = Mock()
                getattr(adapter, suffix).return_value = {"state": state, "replayAllowed": False}
                with patch.object(mcp_server, "_agent_module", return_value=adapter) as module:
                    result = mcp_server._vm_workflow_impl("windows-vm-setup-install-ack-" + suffix, request)
                module.assert_called_once_with("windows_vm_setup_install_ack")
                getattr(adapter, suffix).assert_called_once_with(mcp_server.REPO_ROOT,
                    host="archlinux", next_correlation_id=request["nextCorrelationId"], timeout_seconds=60)
                self.assertTrue(result["ok"])
                self.assertFalse(result["replayAllowed"])
                self.assertFalse(result["productAction"])
        adapter = Mock()
        adapter.start.return_value = {"state": "unknown", "replayAllowed": False}
        with patch.object(mcp_server, "_agent_module", return_value=adapter):
            result = mcp_server._vm_workflow_impl("windows-vm-setup-install-ack-start", request)
        self.assertFalse(result["ok"])
        self.assertFalse(result["replayAllowed"])

    def test_rejects_injected_inputs_before_adapters(self):
        request = {"host": "archlinux", "nextCorrelationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                   "timeoutSeconds": 60}
        with patch.object(mcp_server, "_agent_module") as module:
            for invalid in ({**request, "key": "y"}, {**request, "timeoutSeconds": 301},
                            {**request, "nextCorrelationId": "not-a-uuid"}, {**request, "host": "elsewhere"}):
                result = mcp_server._vm_workflow_impl("windows-vm-setup-install-ack-start", invalid)
                self.assertFalse(result["ok"])
            module.assert_not_called()


if __name__ == "__main__":
    unittest.main()

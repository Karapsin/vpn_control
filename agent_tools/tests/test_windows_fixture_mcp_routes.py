"""Public MCP routing for the fixed CP117 fixture lifecycle."""

import unittest
from unittest.mock import Mock, patch

from agent_tools import mcp_server


class WindowsFixtureRoutesTest(unittest.TestCase):
    _common = {"host": "archlinux", "sourceSha": "a" * 40,
               "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
               "baseMsiArtifactId": "sha256-" + "c" * 64,
               "targetMsiArtifactId": "sha256-" + "d" * 64}
    _lease = "11111111-1111-4111-8111-111111111111"
    _stage = "22222222-2222-4222-8222-222222222222"
    _server = "33333333-3333-4333-8333-333333333333"
    _correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

    def _request(self, action):
        if action.startswith("windows-fixture-owner-network-") or action.startswith("windows-fixture-network-probe-"):
            if action.startswith("windows-fixture-owner-network-"):
                selector = "ownerNetworkCorrelationId"
            else:
                selector = "probeCorrelationId"
            return ({**self._common, "leaseId": self._lease, "stageCorrelationId": self._stage,
                     "serverCorrelationId": self._server, selector: self._correlation,
                     "controllerId": "44444444-4444-4444-8444-444444444444", "ownerPid": 1234,
                     "ownerStartedAtUtc": "2026-09-29T12:00:00Z"} if action.endswith("-start")
                    else {selector: self._correlation})
        if action.startswith("windows-fixture-server-abort-"):
            return ({"leaseId": self._lease, "serverCorrelationId": self._server,
                     "cleanupCorrelationId": self._correlation} if action.endswith("-start")
                    else {"cleanupCorrelationId": self._correlation})
        if action.startswith("windows-fixture-credentials-abort-"):
            return {"correlationId": self._correlation}
        if action.startswith("windows-fixture-server-stop-"):
            return ({"leaseId": self._lease, "serverCorrelationId": self._server,
                     "cleanupCorrelationId": self._correlation} if action.endswith("-start")
                    else {"cleanupCorrelationId": self._correlation})
        if action.startswith("windows-fixture-credentials-cleanup-"):
            return ({"host": "archlinux", "leaseId": self._lease, "stageCorrelationId": self._stage,
                     "correlationId": self._correlation} if action.endswith("-start")
                    else {"correlationId": self._correlation})
        if action.startswith("windows-fixture-stage-"):
            return ({**self._common, "correlationId": self._stage} if action.endswith("-start")
                    else {"correlationId": self._stage})
        if action.startswith("windows-fixture-credentials-"):
            return ({"host": "archlinux", "leaseId": self._lease, "stageCorrelationId": self._stage,
                     "correlationId": self._correlation} if action.endswith("-start")
                    else {"correlationId": self._correlation})
        return ({**self._common, "leaseId": self._lease, "stageCorrelationId": self._stage,
                 "serverCorrelationId": self._server} if action.endswith("-start")
                else {"serverCorrelationId": self._server})

    def test_fixed_routes_dispatch_only_exact_stage_credential_and_server_requests(self):
        cases = (
            ("windows-fixture-stage-start", "windows_update_fixture_stage", "start", "submitted", False),
            ("windows-fixture-stage-status", "windows_update_fixture_stage", "status", "staged-not-server-ready", False),
            ("windows-fixture-stage-collect", "windows_update_fixture_stage", "collect", "staged-not-server-ready", False),
            ("windows-fixture-credentials-start", "windows_fixture_credentials", "start", "submitted", False),
            ("windows-fixture-credentials-status", "windows_fixture_credentials", "status", "ready", False),
            ("windows-fixture-credentials-collect", "windows_fixture_credentials", "collect", "ready", False),
            ("windows-fixture-server-start", "windows_update_fixture_server", "start", "submitted", False),
            ("windows-fixture-server-status", "windows_update_fixture_server", "status", "live", False),
            ("windows-fixture-server-collect", "windows_update_fixture_server", "collect", "live", False),
            ("windows-fixture-server-stop-start", "windows_update_fixture_server", "stop_start", "submitted", False),
            ("windows-fixture-server-stop-status", "windows_update_fixture_server", "stop_status", "stopped", False),
            ("windows-fixture-server-stop-collect", "windows_update_fixture_server", "stop_collect", "stopped", False),
            ("windows-fixture-credentials-cleanup-start", "windows_fixture_credentials", "cleanup_start", "submitted", False),
            ("windows-fixture-credentials-cleanup-status", "windows_fixture_credentials", "cleanup_status", "cleaned", False),
            ("windows-fixture-credentials-cleanup-collect", "windows_fixture_credentials", "cleanup_collect", "cleaned", False),
            ("windows-fixture-server-abort-start", "windows_update_fixture_server", "abort_start", "submitted", False),
            ("windows-fixture-server-abort-status", "windows_update_fixture_server", "abort_status", "stopped", False),
            ("windows-fixture-server-abort-collect", "windows_update_fixture_server", "abort_collect", "stopped", False),
            ("windows-fixture-credentials-abort-start", "windows_fixture_credentials", "abort_start", "submitted", False),
            ("windows-fixture-credentials-abort-status", "windows_fixture_credentials", "abort_status", "aborted-cleaned", False),
            ("windows-fixture-credentials-abort-collect", "windows_fixture_credentials", "abort_collect", "aborted-cleaned", False),
            ("windows-fixture-owner-network-start", "windows_fixture_owner_network", "start", "submitted", False),
            ("windows-fixture-owner-network-status", "windows_fixture_owner_network", "status", "correlated", False),
            ("windows-fixture-owner-network-collect", "windows_fixture_owner_network", "collect", "correlated", False),
            ("windows-fixture-network-probe-start", "windows_fixture_network_probe", "start", "submitted", False),
            ("windows-fixture-network-probe-status", "windows_fixture_network_probe", "status", "correlated", False),
            ("windows-fixture-network-probe-collect", "windows_fixture_network_probe", "collect", "correlated", False),
        )
        for action, module_name, method_name, state, product_action in cases:
            with self.subTest(action=action):
                request = self._request(action)
                adapter = Mock()
                getattr(adapter, method_name).return_value = {"state": state, "replayAllowed": False}
                with patch.object(mcp_server, "_agent_module", return_value=adapter) as module:
                    result = mcp_server._vm_workflow_impl(action, request)
                module.assert_called_once_with(module_name)
                getattr(adapter, method_name).assert_called_once_with(mcp_server.REPO_ROOT, request)
                self.assertTrue(result["ok"])
                self.assertEqual(product_action, result["productAction"])
                self.assertFalse(result["replayAllowed"])

    def test_unknown_and_malformed_requests_fail_closed_before_dispatch(self):
        for action in ("windows-fixture-stage-start", "windows-fixture-credentials-start",
                       "windows-fixture-server-start"):
            with self.subTest(action=action):
                adapter = Mock()
                adapter.start.return_value = {"state": "unknown", "replayAllowed": False}
                with patch.object(mcp_server, "_agent_module", return_value=adapter):
                    result = mcp_server._vm_workflow_impl(action, {"host": "archlinux"})
                    invalid = mcp_server._vm_workflow_impl(action, {"host": "archlinux", "command": "id"})
                self.assertFalse(result["ok"])
                self.assertFalse(invalid["ok"])
                adapter.start.assert_not_called()

    def test_passing_state_with_replay_permission_is_not_promoted(self):
        action = "windows-fixture-server-status"
        adapter = Mock()
        adapter.status.return_value = {"state": "live", "replayAllowed": True}
        with patch.object(mcp_server, "_agent_module", return_value=adapter):
            result = mcp_server._vm_workflow_impl(action, self._request(action))
        self.assertFalse(result["ok"])
        self.assertFalse(result["productAction"])

    def test_owner_network_routes_reject_foreign_or_malformed_admission(self):
        for action in ("windows-fixture-owner-network-start", "windows-fixture-network-probe-start"):
            request = self._request(action)
            with self.subTest(action=action), patch.object(mcp_server, "_agent_module") as module:
                for changed in ({**request, "host": "foreign"}, {**request, "ownerPid": True},
                                {**request, "controllerId": "unbound"},
                                {**request, "ownerStartedAtUtc": "yesterday"},
                                {**request, "command": "id"}):
                    self.assertFalse(mcp_server._vm_workflow_impl(action, changed)["ok"])
                module.assert_not_called()


if __name__ == "__main__":
    unittest.main()

"""Closed read-only routes must preserve uncertainty without publishing raw data."""
import unittest
from types import SimpleNamespace
from unittest import mock
from agent_tools import mcp_server as server

CORRELATION = "d606e111-5cb6-4436-97c8-b0c38ad35ed8"


class ReadonlyDiagnosticRouteTests(unittest.TestCase):
    def test_actual_module_loader_reaches_fixed_readonly_provider(self):
        from agent_tools import ssh_connection_recovery as helper
        receipt = {"nestedState": "absent", "replayAllowed": False,
                   "launchAllowed": False, "nativeActionAllowed": False,
                   "socketState": "absent", "failurePhase": "none"}
        with mock.patch.object(helper, "configured_master_status", return_value={}) as legacy, \
                mock.patch.object(helper, "configured_master_fenced_status", return_value=receipt) as provider:
            result = server._ssh_workflow_impl("connection-master-status", host="archlinux")
        self.assertEqual(result.get("nestedState"), "absent")
        provider.assert_called_once_with(server.REPO_ROOT, "archlinux", 15)

    def invoke(self, action, receipt, **kwargs):
        from agent_tools import ssh_connection_recovery as helper
        provider = mock.Mock(return_value=receipt)
        adapter = SimpleNamespace(configured_master_fenced_status=provider,
                                  configured_status_diagnostic=provider)
        with mock.patch.object(server, "_agent_module", return_value=adapter), \
                mock.patch.object(helper, "configured_master_fenced_status", provider), \
                mock.patch.object(helper, "configured_master_status", return_value={}):
            result = server._ssh_workflow_impl(action, host="archlinux", **kwargs)
        return result, provider

    def test_nested_states_remain_distinct_without_effect_authority(self):
        for state in ("ready", "absent", "unknown"):
            receipt = {"nestedState": state, "replayAllowed": False,
                       "launchAllowed": False, "nativeActionAllowed": False,
                       "socketState": state, "failurePhase": "socket_parser" if state == "unknown" else "none"}
            result, provider = self.invoke("connection-master-status", receipt)
            provider.assert_called_once_with(server.REPO_ROOT, "archlinux", 15)
            self.assertEqual(result["nestedState"], state)
            self.assertIs(result["ok"], state != "unknown")
            self.assertIs(result["nativeActionAllowed"], False)

    def test_refused_cached_socket_is_unknown_without_authentication_claim(self):
        receipt = {"nestedState": "unknown", "socketState": "refused",
                   "failurePhase": "socket_parser", "replayAllowed": False,
                   "launchAllowed": False, "nativeActionAllowed": False}
        result, provider = self.invoke("connection-master-status", receipt)
        provider.assert_called_once_with(server.REPO_ROOT, "archlinux", 15)
        self.assertEqual(result.get("socketState"), "refused")
        self.assertEqual(result.get("nestedState"), "unknown")
        self.assertIs(result["ok"], False)
        self.assertNotIn("authentication_failed", str(result))

    def test_fenced_socket_schema_rejects_inconsistent_or_private_fields(self):
        valid = {"nestedState": "unknown", "socketState": "refused",
                 "failurePhase": "socket_parser", "replayAllowed": False,
                 "launchAllowed": False, "nativeActionAllowed": False}
        changes = ({"nestedState": "ready"}, {"failurePhase": "none"},
                   {"socketState": "private-marker"}, {"raw": "private-marker"},
                   {"failurePhase": "private-marker"})
        for change in changes:
            result, _ = self.invoke("connection-master-status", {**valid, **change})
            self.assertNotIn("socketState", result)
            self.assertNotIn("private-marker", str(result))

    def test_finite_gateway_failure_phase_survives_unknown(self):
        for phase in ("source", "config", "authority", "localmaster", "remotequery", "parser"):
            receipt = {"state": "unknown", "replayAllowed": False,
                       "failurePhase": phase, "nativeActionAllowed": False}
            result, provider = self.invoke("gateway-tmux-status-diagnostic", receipt,
                                          identity={"correlationId": CORRELATION})
            provider.assert_called_once_with(server.REPO_ROOT, {"correlationId": CORRELATION})
            self.assertEqual(result["failurePhase"], phase)
            self.assertIs(result["ok"], False)

    def test_extra_fields_and_untrusted_phase_never_escape(self):
        receipts = [
            {"nestedState": "ready", "replayAllowed": False, "launchAllowed": False,
             "nativeActionAllowed": False, "raw": "private-marker"},
            {"nestedState": [], "replayAllowed": False, "launchAllowed": False, "nativeActionAllowed": False},
            {"nestedState": "ready", "replayAllowed": 0, "launchAllowed": False, "nativeActionAllowed": False},
        ]
        for receipt in receipts:
            result, _ = self.invoke("connection-master-status", receipt)
            self.assertNotIn("nestedState", result)
            self.assertNotIn("private-marker", str(result))
        result, _ = self.invoke("gateway-tmux-status-diagnostic",
                               {"state": "unknown", "replayAllowed": False,
                                "nativeActionAllowed": False, "failurePhase": "private-marker"},
                               identity={"correlationId": CORRELATION})
        self.assertNotIn("failurePhase", result)

    def test_invalid_inputs_do_not_dispatch(self):
        cases = ({"timeout_seconds": True}, {"timeout_seconds": 61},
                 {"identity": {}}, {"transfer": {}}, {"device": "api35"})
        for args in cases:
            result, provider = self.invoke("connection-master-status", {}, **args)
            provider.assert_not_called()
            self.assertIs(result["ok"], False)

    def test_provider_exception_is_private_unknown(self):
        from agent_tools import ssh_connection_recovery as helper
        with mock.patch.object(helper, "configured_master_status", return_value={}), \
                mock.patch.object(helper, "configured_master_fenced_status", side_effect=ValueError("private-marker")):
            result = server._ssh_workflow_impl("connection-master-status", host="archlinux")
        self.assertIs(result["ok"], False)
        self.assertNotIn("private-marker", str(result))

    def test_cli_exposes_same_fixed_route(self):
        with mock.patch.object(server, "ssh_workflow", return_value={"ok": True}) as dispatch:
            self.assertEqual(server.main(["ssh-workflow", "connection-master-status", "--host", "archlinux"]), 0)
        self.assertEqual(dispatch.call_args.args[0], "connection-master-status")

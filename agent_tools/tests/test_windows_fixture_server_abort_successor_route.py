"""The CP117 server-abort successor is reachable only through exact MCP inputs."""

import unittest
from unittest.mock import Mock, patch

from agent_tools import mcp_server


class ServerAbortSuccessorRouteTests(unittest.TestCase):
    CORRELATION = "1a2b3c4d-1111-4222-8333-123456789abc"

    def test_start_and_status_route_to_fixed_module(self):
        inputs = {"successorCleanupCorrelationId": self.CORRELATION}
        for action, method, state in (
            ("windows-fixture-server-abort-successor-start", "start", "submitted"),
            ("windows-fixture-server-abort-successor-status", "status", "cleaned"),
            ("windows-fixture-server-abort-successor-diagnostic", "diagnose", "observed"),
        ):
            with self.subTest(action=action):
                adapter = Mock()
                getattr(adapter, method).return_value = {
                    "state": state, "successorCleanupCorrelationId": self.CORRELATION,
                    "replayAllowed": False, "nativeActionAllowed": False,
                    "productAction": False,
                }
                with patch.object(mcp_server, "_agent_module", return_value=adapter) as loaded:
                    result = mcp_server._vm_workflow_impl(action, inputs)
                loaded.assert_called_once_with("windows_fixture_server_abort_successor")
                getattr(adapter, method).assert_called_once_with(mcp_server.REPO_ROOT, inputs)
                self.assertTrue(result["ok"])
                self.assertFalse(result["productAction"])

    def test_extra_fields_fail_closed_before_native_dispatch(self):
        adapter = Mock()
        with patch.object(mcp_server, "_agent_module", return_value=adapter):
            result = mcp_server._vm_workflow_impl(
                "windows-fixture-server-abort-successor-start",
                {"successorCleanupCorrelationId": self.CORRELATION, "command": "remove-all"},
            )
        self.assertFalse(result["ok"])
        adapter.start.assert_not_called()

    def test_pre_dispatch_resume_route_is_exact(self):
        correlation = "316e6189-5be0-4ea0-bca1-a3905816d815"
        adapter = Mock()
        adapter.start.return_value = {"state": "submitted", "serverCorrelationId": correlation,
                                      "replayAllowed": False, "nativeActionAllowed": False,
                                      "productAction": False}
        with patch.object(mcp_server, "_agent_module", return_value=adapter) as loaded:
            result = mcp_server._vm_workflow_impl("windows-fixture-server-resume-no-dispatch-start",
                                                  {"serverCorrelationId": correlation})
        self.assertTrue(result["ok"])
        loaded.assert_called_once_with("windows_fixture_server_resume")
        adapter.start.assert_called_once_with(mcp_server.REPO_ROOT, {"serverCorrelationId": correlation})

    def test_post_resource_diagnostic_route_is_fixed(self):
        correlation = "316e6189-5be0-4ea0-bca1-a3905816d815"
        adapter = Mock()
        adapter.diagnose.return_value = {"state": "diagnosed", "serverCorrelationId": correlation,
                                         "serverProcessIdentity": "ok", "tlsLoadCertChain": "failed",
                                         "certificateDigestRecheck": "skipped",
                                         "loopbackEphemeralBind": "skipped", "replayAllowed": False,
                                         "nativeActionAllowed": False, "productAction": False}
        with patch.object(mcp_server, "_agent_module", return_value=adapter) as loaded:
            result = mcp_server._vm_workflow_impl("windows-fixture-server-post-resource-diagnostic",
                                                  {"serverCorrelationId": correlation})
        self.assertTrue(result["ok"])
        loaded.assert_called_once_with("windows_fixture_post_resource_diagnostic")
        adapter.diagnose.assert_called_once_with(mcp_server.REPO_ROOT, {"serverCorrelationId": correlation})

    def test_probe_events_acl_route_is_fixed(self):
        correlation = "316e6189-5be0-4ea0-bca1-a3905816d815"
        adapter = Mock()
        adapter.diagnose_events_acl.return_value = {
            "state": "observed", "serverCorrelationId": correlation, "probeEventsAcl": "mismatch",
            "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
        with patch.object(mcp_server, "_agent_module", return_value=adapter) as loaded:
            result = mcp_server._vm_workflow_impl("windows-fixture-server-probe-events-acl-diagnostic",
                                                  {"serverCorrelationId": correlation})
        self.assertTrue(result["ok"])
        loaded.assert_called_once_with("windows_fixture_post_resource_diagnostic")
        adapter.diagnose_events_acl.assert_called_once_with(mcp_server.REPO_ROOT,
                                                              {"serverCorrelationId": correlation})

    def test_acl_preflight_route_is_exact_and_does_not_dispatch_on_extra_input(self):
        correlation = "e848bed2-5bea-47bc-a85a-6cf17b1fcc6a"
        inputs = {"stageCorrelationId": correlation}
        adapter = Mock()
        adapter.preflight.return_value = {
            "state": "ready", "stageCorrelationId": correlation,
            "modes": {"fixture-0700": {"initial": "match", "normalizer": "match"},
                      "control-0777": {"initial": "match", "normalizer": "match"}},
            "replayAllowed": False, "nativeActionAllowed": False,
            "productAction": False,
        }
        with patch.object(mcp_server, "_agent_module", return_value=adapter) as loaded:
            result = mcp_server._vm_workflow_impl("windows-fixture-acl-preflight", inputs)
            invalid = mcp_server._vm_workflow_impl(
                "windows-fixture-acl-preflight",
                {**inputs, "command": "start-server"})
        self.assertTrue(result["ok"])
        self.assertFalse(invalid["ok"])
        loaded.assert_called_once_with("windows_fixture_acl_preflight")
        adapter.preflight.assert_called_once_with(mcp_server.REPO_ROOT, inputs)

    def test_acl_preflight_status_routes_to_read_only_adapter(self):
        inputs = {"stageCorrelationId": "e848bed2-5bea-47bc-a85a-6cf17b1fcc6a"}
        adapter = Mock()
        adapter.status.return_value = {
            "state": "observed", **inputs, "scratch": "zero",
            "signatureValid": True, "signerMatches": True, "shaMatches": True,
            "replayAllowed": False, "nativeActionAllowed": False,
            "productAction": False,
        }
        with patch.object(mcp_server, "_agent_module", return_value=adapter) as loaded:
            result = mcp_server._vm_workflow_impl("windows-fixture-acl-preflight-status", inputs)
        self.assertTrue(result["ok"])
        loaded.assert_called_once_with("windows_fixture_acl_preflight")
        adapter.status.assert_called_once_with(mcp_server.REPO_ROOT, inputs)

    def test_server_acl_preflight_routes_exact_source_bound_request(self):
        inputs = {
            "host": "archlinux",
            "leaseId": "11111111-1111-4111-8111-111111111111",
            "stageCorrelationId": "22222222-2222-4222-8222-222222222222",
            "serverCorrelationId": "33333333-3333-4333-8333-333333333333",
            "sourceSha": "a" * 40,
            "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
            "baseMsiArtifactId": "sha256-" + "c" * 64,
            "targetMsiArtifactId": "sha256-" + "d" * 64,
        }
        adapter = Mock()
        adapter.acl_preflight.return_value = {
            "state": "ready", "sourceSha": inputs["sourceSha"],
            "stageCorrelationId": inputs["stageCorrelationId"],
            "serverReady": False, "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False,
        }
        with patch.object(mcp_server, "_agent_module", return_value=adapter) as loaded:
            result = mcp_server._vm_workflow_impl("windows-fixture-server-acl-preflight", inputs)
        self.assertTrue(result["ok"])
        loaded.assert_called_once_with("windows_update_fixture_server")
        adapter.acl_preflight.assert_called_once_with(mcp_server.REPO_ROOT, inputs)


if __name__ == "__main__":
    unittest.main()

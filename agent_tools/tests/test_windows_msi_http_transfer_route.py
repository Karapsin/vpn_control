"""MCP admission and redaction for the fixed CP117 HTTP transfer workflow."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_tools import mcp_server, windows_msi_http_transfer as transfer
from agent_tools import windows_msi_base_prepare as base


class WindowsMsiHttpTransferRouteTest(unittest.TestCase):
    def setUp(self):
        source_guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        source_guard.start(); self.addCleanup(source_guard.stop)

    def test_fixed_phase_dispatch_and_malformed_inputs_never_dispatch(self):
        request = {"phase": "stage-status", "correlationId": "11111111-1111-4111-8111-111111111111"}
        with patch.object(transfer, "workflow", return_value={"state": "staged", "replayAllowed": False,
                     "nativeActionAllowed": False, "productAction": False}) as workflow:
            result = mcp_server._vm_workflow_impl("windows-msi-http-transfer", request)
        workflow.assert_called_once_with(mcp_server.REPO_ROOT, "stage-status",
                                         {"correlationId": request["correlationId"]})
        self.assertTrue(result["ok"])
        self.assertFalse(result["nativeActionAllowed"])
        self.assertFalse(result["productAction"])
        with patch.object(transfer, "workflow", side_effect=AssertionError("unsafe dispatch")):
            for invalid in ({**request, "phase": "arbitrary"},
                            {**request, "port": 80},
                            {"phase": "stage-status"},
                            {"phase": "listener-start", "correlationId": "bad"}):
                with self.subTest(invalid=invalid):
                    self.assertFalse(mcp_server._vm_workflow_impl("windows-msi-http-transfer", invalid)["ok"])
            base_request = {"host": "archlinux", "correlationId": request["correlationId"],
                            "sourceSha": "a" * 40,
                            "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
                            "baseMsiArtifactId": "sha256-" + "c" * 64,
                            "targetMsiArtifactId": "sha256-" + "d" * 64,
                            "expectedCurrentVersion": "2.1.17"}
            for extra in ({"port": 80}, {"socketPath": "/qga.sock"},
                          {"expectedSid": "S-1-5-21-1-2-3-1002"}):
                with self.subTest(extra=extra):
                    self.assertFalse(mcp_server._vm_workflow_impl(
                        "windows-msi-http-transfer", {"phase": "prepare", **base_request, **extra})["ok"])

    def test_route_rejects_secret_or_extra_result_fields(self):
        request = {"phase": "listener-start", "correlationId": "11111111-1111-4111-8111-111111111111"}
        for secret in ({"path": "/secret"}, {"port": 1234}, {"routeNonce": "secret"},
                       {"expectedSid": "S-1-5-21-1-2-3-1002"}):
            with self.subTest(secret=secret), patch.object(transfer, "workflow", return_value={
                    "state": "listening", **secret, "replayAllowed": False,
                    "nativeActionAllowed": False, "productAction": False}):
                result = mcp_server._vm_workflow_impl("windows-msi-http-transfer", request)
            self.assertFalse(result["ok"])
            self.assertEqual(result["state"], "unknown")
            self.assertNotIn("secret", str(result))

    def test_base_start_from_transfer_is_explicit_product_action(self):
        request = {"host": "archlinux", "correlationId": "11111111-1111-4111-8111-111111111111",
                   "sourceSha": "a" * 40, "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
                   "baseMsiArtifactId": "sha256-" + "c" * 64,
                   "targetMsiArtifactId": "sha256-" + "d" * 64,
                   "expectedCurrentVersion": "2.1.17"}
        with patch.object(base, "start_from_transfer", return_value={"state": "submitted",
                     "correlationId": request["correlationId"], "replayAllowed": False}) as start:
            result = mcp_server._vm_workflow_impl("windows-msi-base-start-from-transfer", request)
        start.assert_called_once_with(mcp_server.REPO_ROOT, request)
        self.assertTrue(result["ok"])
        self.assertTrue(result["productAction"])

    def test_cli_dispatches_fixed_transfer_action(self):
        request = {"phase": "ps5-preflight", "host": "archlinux"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "request.json"
            path.write_text(json.dumps(request))
            output = io.StringIO()
            with patch.object(mcp_server, "vm_workflow", return_value={"tool": "vm_workflow", "ok": True}) as route, \
                    contextlib.redirect_stdout(output):
                code = mcp_server.main(["vm-workflow", "windows-msi-http-transfer", "--inputs-file", str(path)])
        self.assertEqual(code, 0)
        route.assert_called_once_with("windows-msi-http-transfer", request)

    def test_guest_diagnostic_exposes_only_fixed_enums(self):
        request = {"phase": "guest-diagnostic", "correlationId": "11111111-1111-4111-8111-111111111111"}
        observed = {"state": "diagnosed", "task": "terminal", "principal": "exact",
                    "action": "exact", "sid": "exact", "leaf": "absent",
                    "reason": "task-terminal-failed", "replayAllowed": False,
                    "nativeActionAllowed": False, "productAction": False}
        with patch.object(transfer, "workflow", return_value=observed):
            result = mcp_server._vm_workflow_impl("windows-msi-http-transfer", request)
        self.assertTrue(result["ok"])
        self.assertEqual(result["reason"], "task-terminal-failed")
        with patch.object(transfer, "workflow", return_value={**observed, "reason": "secret"}):
            rejected = mcp_server._vm_workflow_impl("windows-msi-http-transfer", request)
        self.assertFalse(rejected["ok"])
        self.assertNotIn("secret", str(rejected))

    def test_guest_diagnostic_detail_is_bounded_and_read_only(self):
        request = {"phase": "guest-diagnostic-detail", "correlationId": "11111111-1111-4111-8111-111111111111"}
        observed = {"state": "diagnosed", "task": "terminal", "principal": "mismatch",
                    "action": "exact", "sid": "exact", "leaf": "unsafe",
                    "reason": "principal-mismatch", "principalUser": "same-sid",
                    "principalLogon": "exact", "principalRunLevel": "exact",
                    "leafAt": "app-root", "leafFault": "owner", "leafOwner": "system",
                    "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
        with patch.object(transfer, "workflow", return_value=observed):
            result = mcp_server._vm_workflow_impl("windows-msi-http-transfer", request)
        self.assertTrue(result["ok"])
        self.assertEqual(result["principalUser"], "same-sid")
        self.assertEqual(result["leafAt"], "app-root")
        self.assertFalse(result["productAction"])

    def test_guest_owner_census_rejects_raw_paths_and_acl(self):
        request = {"phase": "guest-owner-census", "correlationId": "11111111-1111-4111-8111-111111111111"}
        paths = {name: {"kind": "absent", "reparse": "no", "owner": "none"}
                 for name in ("profile", "appdata", "local", "app-root", "stage", "final", "partial")}
        paths["profile"] = {"kind": "directory", "reparse": "no", "owner": "system"}
        observed = {"state": "census", "paths": paths, "replayAllowed": False,
                    "nativeActionAllowed": False, "productAction": False}
        with patch.object(transfer, "workflow", return_value=observed):
            result = mcp_server._vm_workflow_impl("windows-msi-http-transfer", request)
        self.assertTrue(result["ok"])
        self.assertEqual(result["paths"]["profile"]["owner"], "system")
        with patch.object(transfer, "workflow", return_value={**observed, "paths": {
                **paths, "profile": {**paths["profile"], "acl": "private"}}}):
            rejected = mcp_server._vm_workflow_impl("windows-msi-http-transfer", request)
        self.assertFalse(rejected["ok"])
        self.assertNotIn("private", str(rejected))

    def test_listener_diagnostic_exposes_only_bounded_read_only_enums(self):
        request = {"phase": "listener-diagnostic", "correlationId": "11111111-1111-4111-8111-111111111111"}
        observed = {"state": "diagnosed", "binding": "exact", "stageFiles": "allowed",
                    "intent": "exact", "worker": "exited", "ready": "mismatch",
                    "done": "served", "stopped": "absent", "port": "free",
                    "reason": "ready-mismatch", "replayAllowed": False,
                    "nativeActionAllowed": False, "productAction": False}
        with patch.object(transfer, "workflow", return_value=observed):
            result = mcp_server._vm_workflow_impl("windows-msi-http-transfer", request)
        self.assertTrue(result["ok"])
        self.assertEqual(result["reason"], "ready-mismatch")
        self.assertEqual(result["evidenceClass"], "causal-diagnostic")
        self.assertFalse(result["productAction"])
        for poisoned in ({**observed, "port": 1234},
                         {**observed, "reason": "private-endpoint"},
                         {**observed, "path": "/private/route"}):
            with self.subTest(poisoned=poisoned), patch.object(transfer, "workflow", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl("windows-msi-http-transfer", request)
            self.assertFalse(rejected["ok"])
            self.assertEqual(rejected["state"], "unknown")
            self.assertNotIn("private", str(rejected))


if __name__ == "__main__":
    unittest.main()

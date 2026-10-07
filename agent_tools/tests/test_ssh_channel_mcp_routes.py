"""Connection-only MCP routes preserve the native provider's closed admission."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from agent_tools import mcp_server as server
from agent_tools import ssh_fresh_nested_channel as channel
from agent_tools import ssh_channel_selection as selection

CORR = "5ce8351d-ecf7-463f-987a-eb267e7ebfe2"
HEX = CORR.replace("-", "")
SHA = "a" * 64
OUTER = "b" * 64


def ready():
    return {"state": "ready", "correlationId": HEX, "receiptSha256": SHA,
            "outerReceiptSha256": OUTER, "replayAllowed": False,
            "nativeActionAllowed": False}


class ChannelMcpRouteTests(unittest.TestCase):
    def invoke(self, method, result, **kwargs):
        with mock.patch.object(channel, method, return_value=result) as provider:
            value = server._ssh_workflow_impl("connection-channel-" + method,
                host="archlinux", identity={"correlationId": CORR}, **kwargs)
        return value, provider

    def test_actual_provider_import_and_uuid_conversion(self):
        for method in ("prepare", "status"):
            value, provider = self.invoke(method, ready())
            provider.assert_called_once_with(server.REPO_ROOT, "archlinux", HEX,
                                             _private_capture=mock.ANY)
            self.assertTrue(callable(provider.call_args.kwargs["_private_capture"]))
            self.assertIs(value["ok"], True)
            self.assertEqual(value["correlationId"], CORR)
            self.assertIs(value["connectionOnly"], True)
            self.assertIs(value["nativeActionAllowed"], False)

    def test_ended_is_positive_without_replay(self):
        value, _ = self.invoke("status", {"state": "ended", "correlationId": HEX,
            "replayAllowed": False, "nativeActionAllowed": False})
        self.assertEqual(value["state"], "ended")
        self.assertIs(value["ok"], True)
        self.assertIs(value["replayAllowed"], False)

    def test_unknown_finite_phase_and_reason_survive(self):
        for fields in ({"failurePhase": "launch"}, {"reason": "intent_absent"}, {}):
            result = {"state": "unknown", "replayAllowed": False,
                      "nativeActionAllowed": False, **fields}
            value, _ = self.invoke("status", result)
            self.assertIs(value["ok"], False)
            for key, item in fields.items():
                self.assertEqual(value[key], item)

    def test_snapshot_refusal_retains_only_complete_finite_diagnostics(self):
        base = {"state": "unknown", "correlationId": HEX,
                "failurePhase": "master_snapshot", "nativeActionAllowed": False,
                "replayAllowed": False}
        details = {"failureReason": "fd_changed", "exceptionClass": "ValueError", "errno": None}
        value, _ = self.invoke("status", {**base, **details})
        for key, expected in details.items():
            self.assertEqual(value.get(key), expected)
        self.assertEqual(value["failurePhase"], "master_snapshot")
        self.assertIs(value["ok"], False)
        self.assertIs(value["nativeActionAllowed"], False)
        for bad in ({"failureReason": "private-marker"}, {"exceptionClass": "private-marker"},
                    {"errno": True}, {"errno": -1}, {"errno": 256}):
            rejected, _ = self.invoke("status", {**base, **details, **bad})
            self.assertNotIn("private-marker", str(rejected))
            self.assertNotIn("failureReason", rejected)
            self.assertEqual(rejected["reason"], "invalid_channel_result")
        for missing in details:
            partial = {key: item for key, item in details.items() if key != missing}
            rejected, _ = self.invoke("status", {**base, **partial})
            self.assertNotIn("failureReason", rejected)
            self.assertEqual(rejected["reason"], "invalid_channel_result")
        without_phase = {key: item for key, item in {**base, **details}.items() if key != "failurePhase"}
        rejected, _ = self.invoke("status", without_phase)
        self.assertNotIn("failureReason", rejected)
        self.assertEqual(rejected["reason"], "invalid_channel_result")

    def test_extra_private_fields_and_invalid_authority_refuse(self):
        for change in ({"launchCapture": {"raw": "private-marker"}},
                       {"failurePhase": "private-marker"},
                       {"replayAllowed": 0}, {"receiptSha256": "bad"},
                       {"correlationId": "f" * 32}, {"state": []}):
            value, _ = self.invoke("prepare", {**ready(), **change})
            self.assertIs(value["ok"], False)
            self.assertNotIn("private-marker", str(value))
            self.assertNotIn("receiptSha256", value)

    def test_invalid_inputs_do_not_reach_provider(self):
        for method in ("prepare", "status", "ensure"):
            for extra in ({"host": "other"}, {"timeout_seconds": True},
                          {"transfer": {}}, {"device": "api35"},
                          {"identity": {"correlationId": HEX}},
                          {"identity": {"correlationId": CORR, "command": "unsafe"}}):
                inputs = {"host": "archlinux", "identity": {"correlationId": CORR}, **extra}
                with mock.patch.object(channel, "ensure_channel" if method == "ensure" else method) as provider:
                    value = server._ssh_workflow_impl("connection-channel-" + method, **inputs)
                provider.assert_not_called()
                self.assertIs(value["ok"], False)
                self.assertEqual(value["failurePhase"], "input")
                self.assertEqual(value["reason"], "invalid_channel_input")

    def test_provider_exception_never_publishes_private_details(self):
        with mock.patch.object(channel, "status", side_effect=ValueError("private-marker")):
            value = server._ssh_workflow_impl("connection-channel-status", host="archlinux",
                                             identity={"correlationId": CORR})
        self.assertIs(value["ok"], False)
        self.assertNotIn("private-marker", str(value))
        self.assertEqual(value["correlationId"], CORR)
        self.assertEqual(value["requestedCorrelationId"], CORR)

    def ensure(self, result, identity=None):
        with mock.patch.object(channel, "ensure_channel", return_value=result) as provider:
            value = server._ssh_workflow_impl("connection-channel-ensure", host="archlinux",
                identity=identity or {"correlationId": CORR, "receiptSha256": SHA})
        return value, provider

    def test_explicit_renewal_preserves_requested_id_and_hides_options(self):
        new = "f" * 32
        suffix = ("-o", "ControlMaster=no", "-o", "ControlPersist=no", "-o", "ProxyCommand=false")
        result = {"correlationId": new, "receiptSha256": SHA, "outerReceiptSha256": OUTER,
                  "outerOptions": ("-S", "/tmp/private-outer/m", *suffix),
                  "innerOptions": ("-S", "/tmp/vpn-channel-" + new + "/m", *suffix)}
        with mock.patch.object(selection, "select_channel", return_value={
                "state": "selected", "host": "archlinux", "correlationId": new, "receiptSha256": SHA}):
            value, provider = self.ensure(result)
        provider.assert_called_once_with(server.REPO_ROOT, "archlinux", HEX, SHA,
                                         _private_capture=mock.ANY)
        self.assertTrue(callable(provider.call_args.kwargs["_private_capture"]))
        self.assertIs(value["ok"], True)
        self.assertEqual(value["requestedCorrelationId"], CORR)
        self.assertEqual(value["correlationId"].replace("-", ""), new)
        self.assertNotIn("/tmp/", str(value))
        for key in ("outerOptions", "innerOptions"):
            rejected, _ = self.ensure({**result, key: ("-S", "/tmp/unsafe", "command")})
            self.assertIs(rejected["ok"], False)

    def test_ensure_publishes_only_exact_admitted_selection(self):
        suffix = ("-o", "ControlMaster=no", "-o", "ControlPersist=no", "-o", "ProxyCommand=false")
        metadata = {"correlationId": HEX, "receiptSha256": SHA, "outerReceiptSha256": OUTER,
                    "outerOptions": ("-S", "/tmp/private-outer/m", *suffix),
                    "innerOptions": ("-S", "/tmp/vpn-channel-" + HEX + "/m", *suffix)}
        selected = {"state": "selected", "host": "archlinux", "correlationId": HEX, "receiptSha256": SHA}
        with mock.patch.object(selection, "select_channel", return_value=selected) as publish:
            value, _ = self.ensure(metadata)
        publish.assert_called_once_with(server.REPO_ROOT, "archlinux", HEX, SHA)
        self.assertIs(value["selected"], True)
        for invalid in ({**selected, "private": "private-marker"},
                        {**selected, "receiptSha256": "c" * 64},
                        {"state": "unknown", "correlationId": "f" * 32,
                         "nativeActionAllowed": False, "replayAllowed": False},
                        {"state": "unknown", "failurePhase": "master_snapshot",
                         "failureReason": "fd_changed", "exceptionClass": "ValueError", "errno": None,
                         "nativeActionAllowed": False, "replayAllowed": False},
                        {"state": "unknown", "nativeActionAllowed": False, "replayAllowed": False}):
            with mock.patch.object(selection, "select_channel", return_value=invalid):
                value, _ = self.ensure(metadata)
            self.assertIs(value["ok"], False)
            self.assertEqual(value["failurePhase"], "selection")
            self.assertEqual(value["correlationId"], CORR)
            self.assertNotIn("private-marker", str(value))
        with mock.patch.object(selection, "select_channel") as publish:
            rejected, _ = self.ensure({**metadata, "receiptSha256": True})
        publish.assert_not_called()
        self.assertIs(rejected["ok"], False)

    def test_unknown_renewal_retains_new_connection_identity(self):
        new = "f" * 32
        value, _ = self.ensure({"state": "unknown", "correlationId": new,
            "failurePhase": "launch", "replayAllowed": False, "nativeActionAllowed": False})
        self.assertEqual(value["correlationId"].replace("-", ""), new)
        self.assertEqual(value["requestedCorrelationId"], CORR)
        self.assertIs(value["ok"], False)

    def test_null_explicit_receipt_does_not_dispatch(self):
        value, provider = self.ensure({}, {"correlationId": CORR, "receiptSha256": None})
        provider.assert_not_called()
        self.assertEqual(value["failurePhase"], "input")
        self.assertEqual(value["reason"], "invalid_channel_input")

    def test_cli_same_public_action(self):
        with mock.patch.object(server, "ssh_workflow", return_value={"ok": True}) as dispatch:
            self.assertEqual(server.main(["ssh-workflow", "connection-channel-status",
                                         "--host", "archlinux"]), 0)
        self.assertEqual(dispatch.call_args.args[0], "connection-channel-status")


@unittest.skipUnless(os.name == "posix", "POSIX held capture")
class ChannelCaptureTests(unittest.TestCase):
    def test_actual_binary_collector_is_retained_before_provider_projection(self):
        marker = b"PRIVATE_CAPTURE\x00\xff\r\nFAIL: private.native.identity\n"
        def provider(root, host, correlation, *, _private_capture=None):
            capture = channel._collect([sys.executable, "-c",
                "import sys; sys.stdin.buffer.read(); sys.stdout.buffer.write(" + repr(marker) + ")"], b"{}", 3)
            self.assertTrue(capture["complete"])
            self.assertTrue(callable(_private_capture), "normal MCP omitted original raw capture callback")
            _private_capture(capture)
            capsules = list((Path(root) / ".rag_index" / "observation-runs").iterdir())
            self.assertEqual(len(capsules), 1)
            capsule = capsules[0]
            self.assertEqual((capsule / "stdout.private").read_bytes(), marker)
            receipt = json.loads((capsule / "receipt.json").read_bytes())
            self.assertEqual(receipt["returnCode"], 0)
            self.assertNotIn("tests", receipt)
            self.assertEqual(receipt["sourceFingerprint"], hashlib.sha256(Path(channel.__file__).read_bytes()).hexdigest())
            return {"state": "unknown", "correlationId": correlation, "failurePhase": "master_snapshot",
                    "replayAllowed": False, "nativeActionAllowed": False}
        with tempfile.TemporaryDirectory() as root, mock.patch.object(server, "REPO_ROOT", Path(root)), mock.patch.object(channel, "status", side_effect=provider):
            value = server._ssh_workflow_impl("connection-channel-status", host="archlinux", identity={"correlationId": CORR})
        self.assertFalse(value["ok"])
        self.assertNotIn("PRIVATE_CAPTURE", str(value))


    def fixture(self):
        from agent_tools.tests import test_ssh_fresh_nested_channel as fixtures
        fixture = fixtures.FreshChannelTests(methodName="runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_actual_provider_retention_failure_refuses_without_parse_or_selection(self):
        fixture = self.fixture()
        from agent_tools import check_output_retention as retention
        with mock.patch.object(server, "REPO_ROOT", fixture.root), mock.patch.object(channel.subprocess, "Popen", side_effect=fixture.consumer), mock.patch.object(retention, "retain_observation_capture", side_effect=OSError("PRIVATE_STORAGE")), mock.patch.object(selection, "select_channel") as select:
            value = server._ssh_workflow_impl("connection-channel-prepare", host="archlinux",
                    identity={"correlationId": str(__import__("uuid").UUID(fixture.corr))})
        self.assertEqual(value["failurePhase"], "capture_retention")
        self.assertFalse(value["ok"])
        self.assertNotIn("PRIVATE_STORAGE", str(value))
        select.assert_not_called()
        self.assertEqual(len(fixture.calls), 1)

    def test_actual_provider_closes_held_source_guard_after_raw_retention(self):
        fixture = self.fixture()
        from agent_tools import check_output_retention as retention
        real = retention.retain_observation_capture
        def retain_and_drift(*args, **kwargs):
            result = real(*args, **kwargs)
            fixture.f.config_path.write_bytes(fixture.f.config_path.read_bytes() + b" ")
            return result
        with mock.patch.object(server, "REPO_ROOT", fixture.root), mock.patch.object(channel.subprocess, "Popen", side_effect=fixture.consumer), mock.patch.object(retention, "retain_observation_capture", side_effect=retain_and_drift):
            value = server._ssh_workflow_impl("connection-channel-prepare", host="archlinux",
                    identity={"correlationId": str(__import__("uuid").UUID(fixture.corr))})
        self.assertEqual(value["failurePhase"], "closing")
        self.assertFalse(value["ok"])
        capsules = list((fixture.root / ".rag_index" / "observation-runs").iterdir())
        self.assertEqual(len(capsules), 1)
        self.assertEqual((capsules[0] / "stdout.private").read_bytes(), fixture.stdout)

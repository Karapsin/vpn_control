"""Causal checks for the bounded public Android action acceptance scenario."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from contextlib import redirect_stdout

from agent_tools import android_action_acceptance as subject


REQUEST_ID = "692fd13c-d8e8-45a9-aa44-523ac725d919"
OWNER = "e8d73f61-f7bf-4e24-b13a-aff40b1c8e1b"
CORRELATION = "b68a93e0-445d-4cf5-8fee-2f5d90065bd3"
PACKAGE_SHA = "d" * 64


class _PublicProvider:
    """A small-frame provider with a real request-ID deduplication decision."""

    def __init__(self, opening: dict, *, lose_write_number: int | None = None,
                 history: list[dict] | None = None):
        self.owner = OWNER
        self.revision = 2
        self.routing = opening["rules"]
        self.requests: list[dict] = []
        self._transfers: dict[str, bytes] = {}
        self._responses: dict[str, dict] = {}
        self._accepted: dict[str, tuple[str, dict]] = {}
        self._number = 0
        self.lose_write_number = lose_write_number
        self.history = history if history is not None else []
        self.checked_prewrite_journal = 0

    @staticmethod
    def _done(output: str | bytes, returncode: int = 0):
        return SimpleNamespace(returncode=returncode,
                               stdout=output.encode() if isinstance(output, str) else output)

    @staticmethod
    def _bundle(fields: dict[str, str]) -> str:
        return "Result: Bundle[{" + ", ".join(f"{key}={value}" for key, value in fields.items()) + "}]\n"

    def _result(self, request: dict, *, ok: bool = True, code: str = "OK",
                operation_id: str | None = None, data: dict | None = None) -> dict:
        return {"schemaVersion": 1, "controllerId": self.owner,
                "requestId": request["requestId"], "ok": ok, "code": code,
                "message": "", "messageKey": None, "messageArgs": [], "final": True,
                "operationId": operation_id, "configurationRevision": self.revision,
                "restartRequired": False, "data": data or {}, "warnings": []}

    def _execute(self, request: dict) -> dict:
        operation = request["command"]["operation"]
        if operation == "status":
            return self._result(request, data={"runtimeRunning": False,
                                               "runtimeObservation": "stopped"})
        if operation == "operations.list":
            return self._result(request, data={"operations": self.history})
        if operation == "routing.show":
            return self._result(request, data={"routing": {"rules": self.routing}})
        if operation != "routing.import":
            raise AssertionError(f"unexpected operation {operation}")
        payload = request["command"]["arguments"]["input"]
        seen = self._accepted.get(request["requestId"])
        if seen is not None:
            if seen[0] == payload:
                return seen[1]
            return self._result(request, ok=False, code="CONFLICT")
        self.revision += 1
        self.routing = json.loads(payload)["rules"]
        operation_id = "00000000-0000-4000-8000-000000009999"
        result = self._result(request, operation_id=operation_id)
        self._accepted[request["requestId"]] = (payload, result)
        return result

    def run(self, args, **kwargs):
        if args[:3] == ["/fake/adb", "-s", "emulator-5554"] and args[3:] == ["get-state"]:
            return self._done("device\n")
        if args[:5] != ["/fake/adb", "-s", "emulator-5554", "shell", "-T"]:
            raise AssertionError(f"unexpected command {args!r}")
        words = args[5:]
        if words == ["id", "-u"]: return self._done("2000\n")
        probes = {
            ("getprop", "ro.build.version.sdk"): "29",
            ("getprop", "ro.kernel.qemu.avd_name"): "owned-api29",
            ("getprop", "ro.boot.qemu.avd_name"): "",
            ("getprop", "ro.product.cpu.abi"): "x86_64",
            ("pm", "path", "com.kardinal.vpncontrol"): "package:/data/app/owned/base.apk",
            ("sha256sum", "/data/app/owned/base.apk"): PACKAGE_SHA + "  /data/app/owned/base.apk",
        }
        if tuple(words) in probes:
            return self._done(probes[tuple(words)] + "\n")
        if words[0] != "content":
            raise AssertionError(f"unexpected shell command {words!r}")
        action = words[1]
        if action == "call":
            method = words[words.index("--method") + 1]
            if method == "create":
                self._number += 1
                transfer = f"00000000-0000-4000-8000-{self._number:012d}"
                self._transfers[transfer] = b""
                uri = "content://com.kardinal.vpncontrol.control"
                return self._done(self._bundle({"id": transfer, "controllerId": self.owner,
                    "requestUri": f"{uri}/requests/{transfer}",
                    "resultUri": f"{uri}/results/{transfer}"}))
            transfer = words[words.index("--arg") + 1]
            if method == "status": return self._done(self._bundle({"state": "complete"}))
            if method == "discard": return self._done(self._bundle({}))
            raise AssertionError(f"unexpected provider method {method}")
        uri = words[words.index("--uri") + 1]
        transfer = uri.rsplit("/", 1)[1]
        if action == "write":
            request = json.loads(kwargs["input"])
            self.requests.append(request)
            job = self.job
            phase = json.loads((job / "phase.json").read_text())["phase"]
            self.assert_phase(phase)
            self.checked_prewrite_journal += 1
            self._responses[transfer] = self._execute(request)
            if len(self.requests) == self.lose_write_number:
                raise subprocess.TimeoutExpired(args, 60)
            return self._done("")
        if action == "read":
            return self._done(json.dumps(self._responses[transfer]))
        raise AssertionError(f"unexpected content action {action}")

    def assert_phase(self, phase: str) -> None:
        # The opaque transfer record must be durable before content.write.
        record = json.loads((self.job / ("transfer-" + phase + ".json")).read_text())
        assert record["controllerId"] == self.owner
        assert record["requestId"] == self.requests[-1]["requestId"]


def _run_worker(tmp: str, provider: _PublicProvider, *, symlink_job: bool = False) -> tuple[dict, Path]:
    root = Path(tmp); root.chmod(0o700)
    job = root / ("android-document-job-" + CORRELATION)
    if symlink_job:
        target = root / "foreign-job"
        target.mkdir(mode=0o700)
        job.symlink_to(target, target_is_directory=True)
    else:
        job.mkdir(mode=0o700)
    provider.job = job
    opening = {"type": "vpn_control_routing_rules", "version": 7,
               "rules": {"ignore_rules": False, "block_quic_udp_443": False,
                         "proxy_packages": [], "direct_domain_suffixes": []}}
    backup_bytes = json.dumps(opening, separators=(",", ":")).encode()
    assert len(backup_bytes) <= 239
    backup_bytes += b" " * (239 - len(backup_bytes))
    backup = root / "routing.json"
    backup.write_bytes(backup_bytes); backup.chmod(0o600)
    argv = ["remote-worker", "/fake/adb", "emulator-5554", "owned-api29", "29",
            str(root), CORRELATION, PACKAGE_SHA, OWNER, "2", str(backup),
            hashlib.sha256(backup_bytes).hexdigest()]
    output = io.StringIO()
    with mock.patch.object(sys, "argv", argv), \
            mock.patch.object(subprocess, "run", side_effect=provider.run), \
            redirect_stdout(output):
        try:
            exec(subject._REMOTE, {"__name__": "__main__"})
        except SystemExit:
            pass
    return json.loads(output.getvalue()), job


class AndroidActionAcceptanceTest(unittest.TestCase):
    def test_worker_same_uuid_returns_same_commit_and_conflicting_input_is_rejected(self) -> None:
        opening = {"rules": {"ignore_rules": False, "block_quic_udp_443": False,
                             "proxy_packages": [], "direct_domain_suffixes": []}}
        provider = _PublicProvider(opening)
        with tempfile.TemporaryDirectory() as tmp:
            result, job = _run_worker(tmp, provider)
            self.assertEqual(result["state"], "complete")
            self.assertTrue(result["sameRequestRetry"])
            self.assertTrue(result["conflictingRetryRejected"])
            first, retry, conflict = provider.requests[2:5]
            self.assertEqual(first, retry)
            self.assertEqual(first["requestId"], conflict["requestId"])
            self.assertNotEqual(first["command"]["arguments"], conflict["command"]["arguments"])
            self.assertEqual(result["first"]["operationId"],
                             provider._accepted[first["requestId"]][1]["operationId"])
            self.assertEqual(result["first"]["revision"], 3)
            self.assertEqual(result["restore"]["revision"], 4)
            self.assertEqual(provider.checked_prewrite_journal, len(provider.requests))
            self.assertEqual(provider.routing, opening["rules"])
            self.assertEqual(json.loads((job / "phase.json").read_text())["phase"], "closing_status")

    def test_lost_second_write_is_unknown_and_never_replays_or_restores(self) -> None:
        opening = {"rules": {"ignore_rules": False, "block_quic_udp_443": False,
                             "proxy_packages": [], "direct_domain_suffixes": []}}
        # status, history and first import succeed; the second import reaches
        # the provider, then its transport acknowledgement disappears.
        provider = _PublicProvider(opening, lose_write_number=4)
        with tempfile.TemporaryDirectory() as tmp:
            result, job = _run_worker(tmp, provider)
            self.assertEqual(result, {"state": "unknown", "reason": "public_outcome_unknown"})
            self.assertEqual(len(provider.requests), 4)
            self.assertEqual(provider.requests[2], provider.requests[3])
            self.assertEqual(provider.revision, 3)
            self.assertEqual(provider.routing["direct_domain_suffixes"],
                             ["same-request.acceptance.example.test"])
            self.assertEqual(json.loads((job / "phase.json").read_text())["phase"],
                             "same_request_retry")
            self.assertTrue((job / "transfer-same_request_retry.json").exists())

    def test_worker_rejects_symlinked_job_before_public_action(self) -> None:
        opening = {"rules": {"ignore_rules": False, "block_quic_udp_443": False,
                             "proxy_packages": [], "direct_domain_suffixes": []}}
        provider = _PublicProvider(opening)
        with tempfile.TemporaryDirectory() as tmp:
            result, job = _run_worker(tmp, provider, symlink_job=True)
            self.assertEqual(result["state"], "unknown")
            self.assertEqual(provider.requests, [])
            self.assertEqual(list(job.resolve().iterdir()), [], "foreign target must stay untouched")

    def test_worker_rejects_inconsistent_conflict_before_restore(self) -> None:
        opening = {"rules": {"ignore_rules": False, "block_quic_udp_443": False,
                             "proxy_packages": [], "direct_domain_suffixes": []}}
        for malformed in ("ok_true", "revision_changed"):
            class MisreportingProvider(_PublicProvider):
                def _execute(self, request):
                    response = super()._execute(request)
                    if request["command"]["operation"] == "routing.import" and response["code"] == "CONFLICT":
                        response = dict(response)
                        if malformed == "ok_true":
                            response["ok"] = True
                        else:
                            response["configurationRevision"] += 1
                    return response
            with self.subTest(malformed=malformed), tempfile.TemporaryDirectory() as tmp:
                provider = MisreportingProvider(opening)
                result, _ = _run_worker(tmp, provider)
                self.assertEqual(result["state"], "unknown")
                self.assertEqual(len(provider.requests), 5)
                self.assertEqual(provider.routing["direct_domain_suffixes"],
                                 ["same-request.acceptance.example.test"])

    def test_worker_rejects_malformed_retained_history_before_import(self) -> None:
        opening = {"rules": {"ignore_rules": False, "block_quic_udp_443": False,
                             "proxy_packages": [], "direct_domain_suffixes": []}}
        for malformed in (
            {"controllerId": OWNER, "final": True, "phase": "succeeded", "code": "OK"},
            {"controllerId": OWNER, "id": "old-operation", "final": True, "phase": "succeeded"},
            {"controllerId": "foreign-owner", "id": "old-operation", "final": True,
             "phase": "succeeded", "code": "OK"},
        ):
            with self.subTest(malformed=malformed), tempfile.TemporaryDirectory() as tmp:
                provider = _PublicProvider(opening, history=[malformed])
                result, _ = _run_worker(tmp, provider)
                self.assertEqual(result["state"], "unknown")
                self.assertEqual([request["command"]["operation"] for request in provider.requests],
                                 ["status", "operations.list"])

    def test_status_accepts_action_terminal_receipt_without_document_stage_files(self) -> None:
        opening = {"rules": {"ignore_rules": False, "block_quic_udp_443": False,
                             "proxy_packages": [], "direct_domain_suffixes": []}}
        with tempfile.TemporaryDirectory() as tmp:
            result, job = _run_worker(tmp, _PublicProvider(opening))
            self.assertEqual(result["state"], "complete")
            intent = {"fixtureRoot": tmp, "packageSha256": PACKAGE_SHA,
                      "expectedOwner": OWNER, "expectedRevision": 2,
                      "api": 29, "expectedAvd": "owned-api29",
                      "backupSha256": result["opening"]["backupSha256"]}
            for name, value in (("intent.json", intent),
                                ("identity.json", {"pid": 1, "startTicks": 1}),
                                ("result.json", {"state": "complete", "result": result})):
                path = job / name
                path.write_text(json.dumps(value)); path.chmod(0o600)
            command = [sys.executable, "-I", "-B", "-c", "exec(" + repr(subject._STATUS) + ")",
                       tmp, CORRELATION, json.dumps(intent, sort_keys=True, separators=(",", ":"))]
            observed = subprocess.run(command, capture_output=True, check=True, timeout=10)
            self.assertEqual(json.loads(observed.stdout)["state"], "complete")

    def test_request_reuses_exact_identity_and_revision_for_a_transport_retry(self) -> None:
        document = '{"type":"vpn_control_routing_rules","version":7,"rules":{"ignore_rules":false,"block_quic_udp_443":false,"proxy_packages":[],"direct_domain_suffixes":[]}}'
        first = subject._request(REQUEST_ID, OWNER, 2, document)
        second = subject._request(REQUEST_ID, OWNER, 2, document)
        self.assertEqual(first, second)
        self.assertEqual(first["requestId"], REQUEST_ID)
        self.assertEqual(first["controllerId"], OWNER)
        self.assertEqual(first["ifRevision"], 2)
        self.assertEqual(first["command"]["operation"], "routing.import")
        self.assertEqual(first["command"]["arguments"]["input"], document)
        self.assertFalse(first["interactive"])
        self.assertFalse(first["asynchronous"])

    def test_request_conflicting_payload_changes_only_import_input(self) -> None:
        opening = '{"type":"vpn_control_routing_rules","version":7,"rules":{"direct_domain_suffixes":[]}}'
        changed = '{"type":"vpn_control_routing_rules","version":7,"rules":{"direct_domain_suffixes":["example.test"]}}'
        original = subject._request(REQUEST_ID, OWNER, 2, opening)
        conflict = subject._request(REQUEST_ID, OWNER, 2, changed)
        self.assertNotEqual(original["command"]["arguments"], conflict["command"]["arguments"])
        for key in ("schemaVersion", "requestId", "controllerId", "ifRevision", "interactive", "asynchronous"):
            self.assertEqual(original[key], conflict[key])

    def test_missing_status_never_submits_or_authorizes_replay(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = subject.status(tmp, REQUEST_ID)
            self.assertEqual(result["state"], "unknown")
            self.assertFalse(result["replayAllowed"])

    def test_unknown_collection_retains_device_lease_without_remote_replay(self) -> None:
        unknown = {"ok": False, "state": "unknown", "reason": "public_outcome_unknown",
                   "correlationId": CORRELATION, "replayAllowed": False}
        with mock.patch.object(subject, "status", return_value=unknown), \
                mock.patch.object(subject.android_document_acceptance, "_release_device") as release:
            observed = subject.collect("/unused", CORRELATION)
        self.assertEqual(observed, unknown)
        release.assert_not_called()

    def test_start_rejects_stale_backup_or_running_runtime_before_submission(self) -> None:
        profile = {"api": 29, "adb": "/adb", "serial": "emulator-1", "expectedAvd": "owned-api29"}
        config = SimpleNamespace(hosts={"archlinux": SimpleNamespace(
            android_devices={"api29": profile}, fixture_transfer_root=Path("/fixture"))})
        artifact = {"verification": "verified", "artifact": {"platform": "android",
                    "artifactKind": "native-fixture-apk", "sourceSha": "a" * 40,
                    "sha256": "b" * 64}, "location": {"localPath": "/verified.apk"}}
        backup = {"ok": True, "state": "complete", "result": {
            "package": {"baseSha256": "b" * 64},
            "backup": {"sha256": "c" * 64, "size": 239},
            "guard": {"controllerId": OWNER, "configurationRevision": 2}}}
        live = {"ok": True, "result": {"stage": "backup_present", "controllerId": OWNER,
                "configurationRevision": 2, "backup": {"sha256": "c" * 64}}}
        with mock.patch.object(subject.ssh_transport, "load_config", return_value=config), \
                mock.patch.object(subject.ssh_transport, "connection_host", return_value=SimpleNamespace(password=None)), \
                mock.patch.object(subject.android_observation, "_profile", return_value=profile), \
                mock.patch.object(subject.native_artifact_registry, "verify_artifact", return_value=artifact), \
                mock.patch.object(subject.subprocess, "run", return_value=SimpleNamespace(stdout="a" * 40 + "\n")), \
                mock.patch.object(subject.android_package_install, "_inspect_apk"), \
                mock.patch.object(subject.android_admission_readback, "async_collect", return_value=backup), \
                mock.patch.object(subject.android_admission_readback, "readback_status", return_value=live), \
                mock.patch.object(subject.android_public_inspect, "inspect", return_value={
                    "outcome": "admitted", "result": {"runtime": {"running": True}}}), \
                mock.patch.object(subject.android_document_acceptance, "_reserve") as reserve:
            args = ("/unused", "archlinux", "api29", CORRELATION, "sha256-" + "b" * 64,
                    REQUEST_ID, "c" * 64, OWNER, 2)
            with self.assertRaisesRegex(ValueError, "opening readback"):
                subject.start(*args[:6], "d" * 64, *args[7:])
            with self.assertRaisesRegex(ValueError, "owner/runtime"):
                subject.start(*args)
            reserve.assert_not_called()


if __name__ == "__main__":
    unittest.main()

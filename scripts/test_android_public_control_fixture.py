#!/usr/bin/env python3
"""Causal regressions for the small-frame Android public fixture transport."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent / "integration"))
from android_public_control_fixture import (  # noqa: E402
    AndroidPublicControlFixture,
    AdbPublicRunner,
    FixtureOutcomeUnknown,
    FixtureProtocolError,
    DurableTransferRetainer,
    FixtureTransferIdentity,
    RunnerIdentity,
    URI,
)


OWNER = "2fa860f9-ff86-4be4-9b75-81d2649d78b7"
RUNNER = RunnerIdentity("emulator-5596", 2000)


def bundle(**fields: str) -> bytes:
    return ("Result: Bundle[{" + ", ".join(f"{key}={value}" for key, value in fields.items()) + "}]\n").encode()


def request(operation: str, arguments: dict[str, object], *, asynchronous: bool = False, controller: str | None = None) -> dict[str, object]:
    return {"schemaVersion": 1, "requestId": str(uuid.uuid4()), "controllerId": controller,
        "ifRevision": 16, "interactive": False, "asynchronous": asynchronous,
        "command": {"operation": operation, "arguments": arguments}}


def result(request_id: str, *, code: str = "OK", final: bool = True, operation_id: str | None = None) -> bytes:
    return json.dumps({"schemaVersion": 1, "controllerId": OWNER, "requestId": request_id, "ok": code in {"OK", "ACCEPTED"},
        "code": code, "message": "", "messageKey": None, "messageArgs": [], "final": final,
        "operationId": operation_id, "configurationRevision": 16, "restartRequired": False,
        "data": {"phase": "running"} if not final else {}, "warnings": []}, separators=(",", ":")).encode()


class FakeContent:
    def __init__(self, responses: list[bytes] | None = None, *, statuses: list[str] | None = None,
                 write_failure: bool = False, write_exception: Exception | None = None,
                 discard_reply: bytes | None = None):
        self.responses = list(responses or [])
        self.statuses = list(statuses) if statuses is not None else None
        self.write_failure = write_failure
        self.write_exception = write_exception
        self.discard_reply = discard_reply if discard_reply is not None else bundle()
        self.calls: list[tuple[list[str], bytes, bool]] = []
        self.transfers: list[str] = []

    def __call__(self, args, data, cleanup):
        args, data = list(args), bytes(data)
        self.calls.append((args, data, cleanup))
        method = args[args.index("--method") + 1] if args[0] == "call" else None
        if method == "create":
            transfer = str(uuid.uuid4()); self.transfers.append(transfer)
            return bundle(id=transfer, controllerId=OWNER, requestUri=f"{URI}/requests/{transfer}", resultUri=f"{URI}/results/{transfer}")
        if args[0] == "write":
            if self.write_exception is not None:
                raise self.write_exception
            if self.write_failure:
                raise OSError("write disconnected")
            return b""
        if method == "status":
            return bundle(state=self.statuses.pop(0) if self.statuses else "complete")
        if args[0] == "read":
            if not self.responses:
                raise AssertionError("missing response")
            return self.responses.pop(0)
        if method == "discard":
            return self.discard_reply
        raise AssertionError(args)


class AndroidPublicControlFixtureTest(unittest.TestCase):
    def client(self, fake: FakeContent, **kwargs) -> AndroidPublicControlFixture:
        return AndroidPublicControlFixture(fake, RUNNER, **kwargs)

    def test_async_accepted_then_cancel_uses_small_frame_without_document_calls(self):
        operation = str(uuid.uuid4())
        first = request("locations.benchmark", {"id": "3d02b8dc88463aa2921b1da326e8a5653bcacab15d1155358abe17fb7e4c5faf"}, asynchronous=True)
        second = request("operations.cancel", {"id": operation}, controller=OWNER)
        fake = FakeContent([result(first["requestId"], code="ACCEPTED", final=False, operation_id=operation), result(second["requestId"])])
        client = self.client(fake, poll_seconds=0)
        accepted = client.exchange(first)
        self.assertEqual(operation, accepted.result["operationId"])
        cancelled = client.exchange(second)
        self.assertEqual("OK", cancelled.result["code"])
        accepted.cleanup(); cancelled.cleanup()
        commands = [args[0] if args[0] != "call" else args[args.index("--method") + 1] for args, _, _ in fake.calls]
        self.assertEqual(["create", "write", "status", "read", "create", "write", "status", "read", "discard", "discard"], commands)
        self.assertFalse(any("document-" in token for args, _, _ in fake.calls for token in args))
        writes = [data for args, data, _ in fake.calls if args[0] == "write"]
        self.assertEqual(2, len(writes))
        self.assertEqual(operation, json.loads(writes[1])["command"]["arguments"]["id"])

    def test_oversized_request_fails_before_write_and_discards_exact_transfer(self):
        fake = FakeContent()
        with self.assertRaises(FixtureProtocolError):
            self.client(fake).exchange(request("status", {"padding": "x" * 1_048_576}))
        commands = [args[0] if args[0] != "call" else args[args.index("--method") + 1] for args, _, _ in fake.calls]
        self.assertEqual(["create", "discard"], commands)

    def test_foreign_owner_fails_closed_before_write(self):
        fake = FakeContent()
        with self.assertRaises(FixtureProtocolError):
            self.client(fake).exchange(request("status", {}, controller="other-owner"))
        self.assertFalse(any(args[0] == "write" for args, _, _ in fake.calls))

    def test_non_finite_request_json_fails_before_write(self):
        for non_finite in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(non_finite=non_finite):
                fake = FakeContent()
                with self.assertRaises(FixtureProtocolError):
                    self.client(fake).exchange(request("status", {"value": non_finite}))
                commands = [args[0] if args[0] != "call" else args[args.index("--method") + 1] for args, _, _ in fake.calls]
                self.assertEqual(["create", "discard"], commands)

    def test_response_loss_after_write_retains_identity_and_never_discards(self):
        item = request("status", {})
        fake = FakeContent([b'{"bad":true}'])
        with self.assertRaises(FixtureOutcomeUnknown) as raised:
            self.client(fake, poll_seconds=0).exchange(item)
        unknown = raised.exception
        self.assertEqual(item["requestId"], unknown.request_id)
        self.assertEqual(OWNER, unknown.controller_id)
        self.assertEqual(fake.transfers[0], unknown.transfer_id)
        self.assertEqual(1, sum(args[0] == "write" for args, _, _ in fake.calls))
        self.assertFalse(any(args[0] == "call" and args[args.index("--method") + 1] == "discard" for args, _, _ in fake.calls))

    def test_retains_opaque_transfer_before_observation_timeout_without_replay(self):
        item = request("status", {})
        fake = FakeContent(statuses=["pending"])
        retained: list[object] = []
        def retain(record):
            self.assertFalse(any(args[0] == "write" for args, _, _ in fake.calls))
            retained.append(record)
        with patch("android_public_control_fixture.time.monotonic", side_effect=[0.0, 1.0]):
            with self.assertRaises(FixtureOutcomeUnknown) as raised:
                self.client(fake, poll_seconds=0, timeout_seconds=.5).exchange(item, retain_transfer=retain)
        unknown = raised.exception
        self.assertEqual(1, len(retained))
        record = retained[0]
        self.assertEqual(item["requestId"], record.request_id)
        self.assertEqual(OWNER, record.controller_id)
        self.assertEqual(fake.transfers[0], record.transfer_id)
        self.assertEqual(record.transfer_id, unknown.transfer_id)
        commands = [args[0] if args[0] != "call" else args[args.index("--method") + 1] for args, _, _ in fake.calls]
        self.assertEqual(["create", "write", "status"], commands)

    def test_retainer_failure_discards_before_write(self):
        fake = FakeContent()
        retained: list[object] = []

        def fail(identity):
            retained.append(identity)
            raise OSError("ledger unavailable")

        with self.assertRaises(FixtureProtocolError):
            self.client(fake).exchange(request("status", {}), retain_transfer=fail)
        self.assertEqual(1, len(retained))
        commands = [args[0] if args[0] != "call" else args[args.index("--method") + 1] for args, _, _ in fake.calls]
        self.assertEqual(["create", "discard"], commands)

    def test_durable_retainer_retries_short_write_until_the_full_identity_is_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.ndjson"
            identity = FixtureTransferIdentity(str(uuid.uuid4()), OWNER, str(uuid.uuid4()))
            import android_public_control_fixture
            original_write = android_public_control_fixture.os.write
            calls = 0

            def short_then_full(descriptor, payload):
                nonlocal calls
                calls += 1
                if calls == 1:
                    return original_write(descriptor, payload[:1])
                return original_write(descriptor, payload)

            with patch("android_public_control_fixture.os.write", side_effect=short_then_full):
                DurableTransferRetainer(path)(identity)
            self.assertGreaterEqual(calls, 2)
            self.assertEqual({"requestId": identity.request_id, "controllerId": identity.controller_id,
                              "transferId": identity.transfer_id}, json.loads(path.read_text()))

    def test_zero_length_retainer_write_prevents_provider_write(self):
        fake = FakeContent()
        with tempfile.TemporaryDirectory() as directory:
            with patch("android_public_control_fixture.os.write", return_value=0):
                with self.assertRaises(FixtureProtocolError):
                    self.client(fake).exchange(request("status", {}), retain_transfer=DurableTransferRetainer(Path(directory) / "ledger.ndjson"))
        commands = [args[0] if args[0] != "call" else args[args.index("--method") + 1] for args, _, _ in fake.calls]
        self.assertEqual(["create", "discard"], commands)

    def test_durable_retainer_skips_directory_sync_on_windows_but_keeps_file_sync(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.ndjson"
            identity = FixtureTransferIdentity(str(uuid.uuid4()), OWNER, str(uuid.uuid4()))
            with patch("android_public_control_fixture.SUPPORTS_DIRECTORY_FSYNC", False), \
                    patch("android_public_control_fixture.os.fsync") as fsync:
                DurableTransferRetainer(path)(identity)
        self.assertEqual(1, fsync.call_count)

    def test_durable_retainer_survives_observer_timeout_then_cleans_exact_transfer_without_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger, release, events = root / "ledger.ndjson", root / "release", root / "events.ndjson"
            module_root = Path(__file__).resolve().parent / "integration"
            child = textwrap.dedent(
                """
                import json, sys, time, uuid
                from pathlib import Path
                sys.path.insert(0, sys.argv[1])
                from android_public_control_fixture import AndroidPublicControlFixture, DurableTransferRetainer, RunnerIdentity, URI
                ledger, release, events = map(Path, sys.argv[2:5])
                owner = '2fa860f9-ff86-4be4-9b75-81d2649d78b7'
                transfer = '0e810768-6afc-4f4d-8e13-c26f2bde0c2d'
                request_id = '1c7f47e5-5f72-4f6d-9f29-a83029e81717'
                def event(name):
                    with events.open('a', encoding='utf-8') as out:
                        out.write(json.dumps({'event': name, 'transferId': transfer}) + '\\n'); out.flush()
                def bundle(**fields):
                    return ('Result: Bundle[{' + ', '.join(f'{key}={value}' for key, value in fields.items()) + '}]\\n').encode()
                class Content:
                    def __call__(self, args, data, cleanup):
                        method = args[args.index('--method') + 1] if args[0] == 'call' else None
                        if method == 'create':
                            event('create'); return bundle(id=transfer, controllerId=owner, requestUri=f'{URI}/requests/{transfer}', resultUri=f'{URI}/results/{transfer}')
                        if args[0] == 'write': event('write'); return b''
                        if method == 'status': event('status'); return bundle(state='complete' if release.exists() else 'pending')
                        if args[0] == 'read':
                            event('read'); return json.dumps({'schemaVersion':1,'controllerId':owner,'requestId':request_id,'ok':True,'code':'OK','message':'','messageKey':None,'messageArgs':[],'final':True,'operationId':None,'configurationRevision':22,'restartRequired':False,'data':{},'warnings':[]}).encode()
                        if method == 'discard': event('discard'); return bundle()
                        raise RuntimeError(args)
                request = {'schemaVersion':1,'requestId':request_id,'controllerId':None,'ifRevision':None,'interactive':False,'asynchronous':False,'command':{'operation':'status','arguments':{}}}
                response = AndroidPublicControlFixture(Content(), RunnerIdentity('fixture-5596', 2000), poll_seconds=.01, timeout_seconds=10).exchange(request, retain_transfer=DurableTransferRetainer(ledger))
                response.cleanup()
                """
            )
            process = subprocess.Popen([sys.executable, "-c", child, str(module_root), str(ledger), str(release), str(events)],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 5
                while not ledger.exists() and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(ledger.exists(), "child must retain identity before observer timeout")
                with self.assertRaises(subprocess.TimeoutExpired):
                    process.wait(timeout=.05)
                self.assertIsNone(process.poll(), "observer timeout must not terminate the native runner")
                entries = [json.loads(line) for line in ledger.read_text().splitlines()]
                self.assertEqual(1, len(entries))
                self.assertEqual('1c7f47e5-5f72-4f6d-9f29-a83029e81717', entries[0]['requestId'])
                self.assertEqual('0e810768-6afc-4f4d-8e13-c26f2bde0c2d', entries[0]['transferId'])
                release.touch()
                stdout, stderr = process.communicate(timeout=5)
                self.assertEqual(0, process.returncode, stderr or stdout)
                event_rows = [json.loads(line) for line in events.read_text().splitlines()]
                names = [row['event'] for row in event_rows]
                self.assertEqual(1, names.count('write'))
                self.assertEqual(['create', 'write'], names[:2])
                self.assertEqual(['read', 'discard'], names[-2:])
                self.assertTrue(all(row['transferId'] == entries[0]['transferId'] for row in event_rows))
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.communicate(timeout=5)

    def test_uncertain_write_is_not_retried(self):
        fake = FakeContent(write_failure=True)
        with self.assertRaises(FixtureOutcomeUnknown) as raised:
            self.client(fake).exchange(request("status", {}))
        self.assertEqual(fake.transfers[0], raised.exception.transfer_id)
        self.assertEqual(1, sum(args[0] == "write" for args, _, _ in fake.calls))
        self.assertFalse(any(args[0] == "call" and args[args.index("--method") + 1] == "discard" for args, _, _ in fake.calls))

    def test_post_write_adb_timeout_retains_identity_as_unknown(self):
        item = request("status", {})
        fake = FakeContent(write_exception=subprocess.TimeoutExpired(["adb"], 10))
        with self.assertRaises(FixtureOutcomeUnknown) as raised:
            self.client(fake).exchange(item)
        self.assertEqual(item["requestId"], raised.exception.request_id)
        self.assertEqual(fake.transfers[0], raised.exception.transfer_id)
        self.assertIsInstance(raised.exception.__cause__, subprocess.TimeoutExpired)
        self.assertFalse(any(args[0] == "call" and args[args.index("--method") + 1] == "discard" for args, _, _ in fake.calls))

    def test_concrete_runner_passes_bounded_timeouts_including_cleanup(self):
        runner = AdbPublicRunner("adb", "emulator-5596", timeout_seconds=11, cleanup_timeout_seconds=2)
        completed = [
            subprocess.CompletedProcess([], 0, stdout=b"device\n", stderr=b""),
            subprocess.CompletedProcess([], 0, stdout=b"2000\n", stderr=b""),
            subprocess.CompletedProcess([], 0, stdout=b"", stderr=b""),
            subprocess.CompletedProcess([], 0, stdout=b"", stderr=b""),
        ]
        with patch("android_public_control_fixture.subprocess.run", side_effect=completed) as run:
            runner.attest()
            runner(["call", "--uri", URI, "--method", "status"], b"", False)
            runner(["call", "--uri", URI, "--method", "discard"], b"", True)
        self.assertEqual([11, 11, 11, 2], [call.kwargs["timeout"] for call in run.call_args_list])

    def test_cleanup_rejects_unexpected_discard_reply_before_marking_clean(self):
        item = request("status", {})
        fake = FakeContent([result(item["requestId"])], discard_reply=bundle(state="complete"))
        response = self.client(fake, poll_seconds=0).exchange(item)
        with self.assertRaises(FixtureProtocolError):
            response.cleanup()
        self.assertFalse(response._cleaned)

    def test_strict_result_json_rejects_nan_duplicate_keys_and_boolean_schema_version(self):
        item = request("status", {})
        valid = result(item["requestId"]).decode()
        malformed = (
            valid.replace('"schemaVersion":1', '"schemaVersion":NaN', 1),
            valid.replace('{"schemaVersion":1,', '{"schemaVersion":1,"schemaVersion":1,', 1),
            valid.replace('"schemaVersion":1', '"schemaVersion":true', 1),
        )
        for wire in malformed:
            with self.subTest(wire=wire[:40]):
                fake = FakeContent([wire.encode()])
                with self.assertRaises(FixtureOutcomeUnknown):
                    self.client(fake, poll_seconds=0).exchange(item)
                self.assertFalse(any(args[0] == "call" and args[args.index("--method") + 1] == "discard" for args, _, _ in fake.calls))

    def test_runner_identity_requires_public_shell_uid(self):
        with self.assertRaises(FixtureProtocolError):
            RunnerIdentity("emulator-5596", 0)
        with self.assertRaises(FixtureProtocolError):
            AndroidPublicControlFixture(FakeContent(), None)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()

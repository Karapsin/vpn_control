#!/usr/bin/env python3
"""Causal regressions for the small-frame Android public fixture transport."""

from __future__ import annotations

import json
import subprocess
import sys
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
    def __init__(self, responses: list[bytes] | None = None, *, write_failure: bool = False, write_exception: Exception | None = None, discard_reply: bytes | None = None):
        self.responses = list(responses or [])
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
            return bundle(state="complete")
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

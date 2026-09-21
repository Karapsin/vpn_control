#!/usr/bin/env python3
"""Small-frame public Android control-provider fixture transport.

This is test-fixture plumbing for the legacy bounded provider path.  It is not
the packaged CLI transport and must only be used with an authenticated public
UID-2000 ``content`` runner.  Request bytes always enter through ``content
write`` stdin; provider command arguments contain only fixed tokens and opaque
UUIDs.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence


URI = "content://com.kardinal.vpncontrol.control"
MAX_FRAME_BYTES = 1_048_576
SUPPORTS_DIRECTORY_FSYNC = os.name != "nt"
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_BUNDLE = re.compile(r"Result: Bundle\[\{([^{}\r\n]*)}]\s*")
_RESULT_KEYS = {
    "schemaVersion", "controllerId", "requestId", "ok", "code", "message",
    "messageKey", "messageArgs", "final", "operationId", "configurationRevision",
    "restartRequired", "data", "warnings",
}
_REQUEST_KEYS = {"schemaVersion", "requestId", "controllerId", "ifRevision", "interactive", "asynchronous", "command"}


class FixtureProtocolError(RuntimeError):
    """The provider response was malformed before an uncertain write."""


class FixtureOutcomeUnknown(RuntimeError):
    """A request was written but its terminal result cannot be trusted."""

    def __init__(self, message: str, *, request_id: str, controller_id: str, transfer_id: str):
        super().__init__(message)
        self.request_id = request_id
        self.controller_id = controller_id
        self.transfer_id = transfer_id


Content = Callable[[Sequence[str], bytes, bool], bytes | str]
TransferRetainer = Callable[["FixtureTransferIdentity"], None]


@dataclass(frozen=True)
class RunnerIdentity:
    """Identity attested for the public, non-root Android provider runner."""

    serial: str
    uid: int

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", self.serial) or self.uid != 2000:
            raise FixtureProtocolError("runner is not the public shell UID")


class AdbPublicRunner:
    """Concrete ``adb`` content runner that retains a UID-2000 attestation."""

    def __init__(self, adb: str, serial: str, *, timeout_seconds: float = 10.0, cleanup_timeout_seconds: float = 3.0):
        if timeout_seconds <= 0 or cleanup_timeout_seconds <= 0:
            raise ValueError("invalid adb timeout")
        self._adb = adb
        self._serial = serial
        self._timeout_seconds = timeout_seconds
        self._cleanup_timeout_seconds = cleanup_timeout_seconds
        self.identity: RunnerIdentity | None = None

    def attest(self) -> RunnerIdentity:
        state = subprocess.run(
            [self._adb, "-s", self._serial, "get-state"],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=self._timeout_seconds,
        )
        uid = subprocess.run(
            [self._adb, "-s", self._serial, "shell", "-T", "id", "-u"],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=self._timeout_seconds,
        )
        if state.returncode != 0 or state.stdout.strip() != b"device" or uid.returncode != 0 or uid.stdout.strip() != b"2000":
            raise FixtureProtocolError("adb runner did not attest as public shell UID")
        self.identity = RunnerIdentity(self._serial, 2000)
        return self.identity

    def __call__(self, args: Sequence[str], data: bytes, cleanup: bool) -> bytes:
        if self.identity is None:
            raise FixtureProtocolError("adb runner was not attested")
        completed = subprocess.run(
            [self._adb, "-s", self.identity.serial, "shell", "-T", "content", *args],
            check=False, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=self._cleanup_timeout_seconds if cleanup else self._timeout_seconds,
        )
        if completed.returncode != 0:
            raise FixtureProtocolError("adb content command failed")
        return completed.stdout


def _uuid(value: object, label: str) -> str:
    if not isinstance(value, str) or not _UUID.fullmatch(value):
        raise FixtureProtocolError(f"invalid {label}")
    return value


def _text(value: bytes | str) -> str:
    if isinstance(value, str):
        return value
    try:
        return value.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise FixtureProtocolError("provider returned invalid UTF-8") from error


def _bundle(value: bytes | str) -> dict[str, str]:
    match = _BUNDLE.fullmatch(_text(value))
    if not match:
        raise FixtureProtocolError("unexpected provider bundle")
    fields = match.group(1)
    if not fields:
        return {}
    result: dict[str, str] = {}
    for item in fields.split(", "):
        if "=" not in item:
            raise FixtureProtocolError("malformed provider bundle")
        key, field = item.split("=", 1)
        if not key or key in result:
            raise FixtureProtocolError("malformed provider bundle")
        result[key] = field
    return result


def _request_bytes(request: Mapping[str, object], owner: str) -> tuple[dict[str, object], bytes]:
    copied = dict(request)
    if set(copied) != _REQUEST_KEYS:
        raise FixtureProtocolError("invalid request envelope")
    supplied_owner = copied.get("controllerId")
    if supplied_owner is not None and supplied_owner != owner:
        raise FixtureProtocolError("foreign controller")
    copied["controllerId"] = owner
    if (not isinstance(copied.get("schemaVersion"), int) or isinstance(copied.get("schemaVersion"), bool)
            or copied.get("schemaVersion") != 1 or not isinstance(copied.get("requestId"), str)):
        raise FixtureProtocolError("invalid request envelope")
    _uuid(copied["requestId"], "request id")
    if copied["ifRevision"] is not None and (not isinstance(copied["ifRevision"], int) or isinstance(copied["ifRevision"], bool)):
        raise FixtureProtocolError("invalid request envelope")
    if not isinstance(copied["interactive"], bool) or not isinstance(copied["asynchronous"], bool):
        raise FixtureProtocolError("invalid request envelope")
    command = copied["command"]
    if not isinstance(command, Mapping) or set(command) != {"operation", "arguments"} or not isinstance(command["operation"], str) or not command["operation"] or not isinstance(command["arguments"], Mapping):
        raise FixtureProtocolError("invalid request envelope")
    try:
        encoded = json.dumps(copied, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeError) as error:
        raise FixtureProtocolError("request is not UTF-8 JSON") from error
    if len(encoded) > MAX_FRAME_BYTES:
        raise FixtureProtocolError("request exceeds small-frame limit")
    return copied, encoded


def _result(value: bytes | str, request_id: str, owner: str) -> dict[str, object]:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, field in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = field
        return result

    def reject_constant(_: str) -> object:
        raise ValueError("non-finite JSON number")

    try:
        parsed = json.loads(_text(value), object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (json.JSONDecodeError, FixtureProtocolError, ValueError) as error:
        raise FixtureProtocolError("malformed result envelope") from error
    if not isinstance(parsed, dict) or set(parsed) != _RESULT_KEYS:
        raise FixtureProtocolError("malformed result envelope")
    if (not isinstance(parsed.get("schemaVersion"), int) or isinstance(parsed.get("schemaVersion"), bool)
            or parsed.get("schemaVersion") != 1 or parsed.get("controllerId") != owner or parsed.get("requestId") != request_id):
        raise FixtureProtocolError("result identity mismatch")
    if not isinstance(parsed["ok"], bool) or not isinstance(parsed["code"], str) or not parsed["code"]:
        raise FixtureProtocolError("malformed result envelope")
    if not isinstance(parsed["message"], str) or parsed["messageKey"] is not None and not isinstance(parsed["messageKey"], str):
        raise FixtureProtocolError("malformed result envelope")
    if not isinstance(parsed["final"], bool) or not isinstance(parsed["restartRequired"], bool):
        raise FixtureProtocolError("malformed result envelope")
    if not isinstance(parsed["configurationRevision"], int) or isinstance(parsed["configurationRevision"], bool):
        raise FixtureProtocolError("malformed result envelope")
    if parsed["operationId"] is not None:
        _uuid(parsed["operationId"], "operation id")
    if not isinstance(parsed["messageArgs"], list) or not isinstance(parsed["data"], dict) or not isinstance(parsed["warnings"], list):
        raise FixtureProtocolError("malformed result envelope")
    return parsed


@dataclass
class FixtureResponse:
    """A verified result whose transfer remains available for explicit cleanup."""

    result: dict[str, object]
    transfer_id: str
    _cleanup: Callable[[str], None]
    _cleaned: bool = False

    def cleanup(self) -> None:
        if not self._cleaned:
            self._cleanup(self.transfer_id)
            self._cleaned = True


@dataclass(frozen=True)
class FixtureTransferIdentity:
    """Opaque identity retained before a request can become externally visible.

    Native runner code supplies a synchronous retainer that durably records this
    tuple before it performs another provider call.  It contains no request
    payload and lets an interrupted observer recover or discard the exact
    transfer without replaying the request.
    """

    request_id: str
    controller_id: str
    transfer_id: str


class DurableTransferRetainer:
    """Append one opaque transfer identity and flush it before provider write.

    This is deliberately only a crash/observer handoff record.  It does not
    schedule, replay, or inspect requests; the runner still owns the exact
    follow-up read or discard.
    """

    def __init__(self, path: Path):
        self._path = Path(path)

    def __call__(self, identity: FixtureTransferIdentity) -> None:
        encoded = (json.dumps({
            "requestId": identity.request_id,
            "controllerId": identity.controller_id,
            "transferId": identity.transfer_id,
        }, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
        descriptor = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            remaining = memoryview(encoded)
            while remaining:
                count = os.write(descriptor, remaining)
                if count <= 0 or count > len(remaining):
                    raise OSError("ledger write made no progress")
                remaining = remaining[count:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if SUPPORTS_DIRECTORY_FSYNC:
            parent = os.open(self._path.parent, os.O_RDONLY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)


class AndroidPublicControlFixture:
    """One legacy small-frame exchange over an authenticated provider runner."""

    def __init__(self, content: Content, runner_identity: RunnerIdentity, *, poll_seconds: float = 0.1, timeout_seconds: float = 45.0):
        if not isinstance(runner_identity, RunnerIdentity):
            raise FixtureProtocolError("runner identity was not attested")
        if poll_seconds < 0 or timeout_seconds <= 0:
            raise ValueError("invalid polling bounds")
        self._content = content
        self.runner_identity = runner_identity
        self._poll_seconds = poll_seconds
        self._timeout_seconds = timeout_seconds

    def _call(self, method: str, argument: str | None = None, *, cleanup: bool = False) -> dict[str, str]:
        args = ["call", "--uri", URI, "--method", method]
        if argument is not None:
            args.extend(("--arg", argument))
        return _bundle(self._content(args, b"", cleanup))

    def _discard(self, transfer_id: str) -> None:
        if self._call("discard", transfer_id, cleanup=True) != {}:
            raise FixtureProtocolError("discard returned unexpected bundle")

    def exchange(self, request: Mapping[str, object], *, retain_transfer: TransferRetainer | None = None) -> FixtureResponse:
        """Submit once and expose its verified response before caller-directed cleanup.

        Any failure after ``write`` is an unknown outcome.  The client never
        retries that write or replays the request under a new transfer id.
        """
        created = self._call("create")
        if set(created) != {"id", "controllerId", "requestUri", "resultUri"}:
            raise FixtureProtocolError("malformed create response")
        transfer_id = _uuid(created["id"], "transfer id")
        owner = created["controllerId"]
        if not owner or len(owner) > 256 or any(character.isspace() for character in owner):
            self._discard_safely(transfer_id)
            raise FixtureProtocolError("invalid controller")
        request_uri = f"{URI}/requests/{transfer_id}"
        result_uri = f"{URI}/results/{transfer_id}"
        if created["requestUri"] != request_uri or created["resultUri"] != result_uri:
            self._discard_safely(transfer_id)
            raise FixtureProtocolError("provider returned foreign URI")
        try:
            bound, payload = _request_bytes(request, owner)
        except Exception:
            self._discard_safely(transfer_id)
            raise
        identity = FixtureTransferIdentity(
            request_id=bound["requestId"], controller_id=owner, transfer_id=transfer_id,
        )
        if retain_transfer is not None:
            try:
                retain_transfer(identity)
            except Exception as error:
                self._discard_safely(transfer_id)
                raise FixtureProtocolError("transfer retention failed before write") from error
        written = False
        try:
            # A transport exception cannot distinguish a rejected write from one
            # accepted by the provider before its reply was lost.  Treat it as
            # sent and never replay the request.
            written = True
            if _text(self._content(["write", "--uri", request_uri], payload, False)):
                raise FixtureProtocolError("write returned unexpected output")
            deadline = time.monotonic() + self._timeout_seconds
            while True:
                state = self._call("status", transfer_id)
                if set(state) != {"state"}:
                    raise FixtureProtocolError("malformed status response")
                if state["state"] == "complete":
                    break
                if state["state"] not in {"writing", "pending"}:
                    raise FixtureProtocolError("unexpected transfer state")
                if time.monotonic() >= deadline:
                    raise FixtureProtocolError("result timeout")
                time.sleep(self._poll_seconds)
            raw_result = self._content(["read", "--uri", result_uri], b"", False)
            if len(raw_result.encode("utf-8") if isinstance(raw_result, str) else raw_result) > MAX_FRAME_BYTES:
                raise FixtureProtocolError("result exceeds small-frame limit")
            response = _result(raw_result, bound["requestId"], owner)
            return FixtureResponse(response, transfer_id, self._discard)
        except Exception as error:
            if written:
                raise FixtureOutcomeUnknown(
                    "written request outcome is unknown",
                    request_id=bound["requestId"], controller_id=owner, transfer_id=transfer_id,
                ) from error
            self._discard_safely(transfer_id)
            raise
        finally:
            payload = b""

    def _discard_safely(self, transfer_id: str) -> None:
        try:
            self._discard(transfer_id)
        except Exception:
            pass

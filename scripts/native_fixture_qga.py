#!/usr/bin/env python3
"""Bounded, read-only QEMU Guest Agent observations for fixture evidence.

Each request gets one connection.  A lost or incomplete response is deliberately
reported as unknown: the client never replays or cancels a request after it was
issued.  Closing that connection releases the QGA multiplexer slot even when a
remote wrapper has already timed out.
"""

from __future__ import annotations

import json
import math
import os
import secrets
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Mapping


DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024
_READ_ONLY_COMMANDS = {"guest-file-open", "guest-file-read", "guest-file-close", "guest-exec-status"}


class QgaObservationError(RuntimeError):
    """A QGA observation did not produce a trustworthy answer."""


class QgaObservationUnknown(QgaObservationError):
    """The request may have reached QGA, but its result was not observed."""

    def __init__(self, operation: Mapping[str, Any], reason: str):
        super().__init__(f"QGA observation unknown for {operation['execute']}: {reason}")
        self.operation = dict(operation)
        self.reason = reason


class QgaProtocolError(QgaObservationError):
    pass


@dataclass(frozen=True)
class QgaReadOnlyClient:
    socket_path: str
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES

    _handles: list[Any] = field(default_factory=list, init=False, repr=False, compare=False)
    cleanup_errors: list[QgaObservationError] = field(default_factory=list, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if os.name == "nt":
            raise OSError("QGA Unix socket observations are unavailable on Windows")
        if (not self.socket_path or isinstance(self.timeout_seconds, bool)
                or not isinstance(self.timeout_seconds, (int, float))
                or not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0
                or isinstance(self.max_response_bytes, bool) or not isinstance(self.max_response_bytes, int)
                or self.max_response_bytes <= 0):
            raise ValueError("QGA socket path, deadline, and response limit must be positive")

    def __enter__(self) -> "QgaReadOnlyClient":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        try:
            self.close()
        except QgaObservationError:
            if exc is None:
                raise
            # Preserve the original read failure; cleanup evidence remains available
            # on this client. Never replay an uncertain close against a reused handle.


    def close(self) -> None:
        """Close each observed owned handle once, with bounded calls."""
        first_error = None
        for handle in tuple(self._handles):
            try:
                self.guest_file_close(handle)
            except QgaObservationError as error:
                self.cleanup_errors.append(error)
                if first_error is None:
                    first_error = error
        if first_error is not None:
            raise first_error

    def guest_file_open(self, path: str, mode: str = "rb") -> Any:
        if mode not in {"r", "rb"}:
            raise ValueError("read-only QGA client permits only r or rb file modes")
        handle = self._call("guest-file-open", {"path": path, "mode": mode})
        self._handles.append(handle)
        return handle

    def guest_file_read(self, handle: Any, count: int) -> Any:
        if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
            raise ValueError("guest file read count must be positive")
        return self._call("guest-file-read", {"handle": handle, "count": count})

    def guest_file_close(self, handle: Any) -> Any:
        if handle in self._handles:
            self._handles.remove(handle)
        return self._call("guest-file-close", {"handle": handle})

    def guest_exec_status(self, pid: int) -> Any:
        if isinstance(pid, bool) or not isinstance(pid, int) or pid < 0:
            raise ValueError("guest exec pid must be a non-negative integer")
        return self._call("guest-exec-status", {"pid": pid})

    def _call(self, command: str, arguments: Mapping[str, Any]) -> Any:
        if command not in _READ_ONLY_COMMANDS:
            raise ValueError(f"QGA command is outside read-only scope: {command}")
        operation = {"execute": command, "arguments": dict(arguments)}
        encoded = (json.dumps(operation, separators=(",", ":")) + "\n").encode("utf-8")
        deadline = time.monotonic() + self.timeout_seconds
        connection: socket.socket | None = None
        issued = False
        try:
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._with_deadline(connection, deadline)
            connection.connect(self.socket_path)
            self._synchronize(connection, deadline)
            self._with_deadline(connection, deadline)
            connection.sendall(encoded)
            issued = True
            raw = self._read_response(connection, deadline)
        except (socket.timeout, TimeoutError) as error:
            raise QgaObservationUnknown(operation, "deadline expired") from error
        except EOFError as error:
            raise QgaObservationUnknown(operation, "response ended before newline") from error
        except OSError as error:
            reason = "connection failed" if not issued else "connection ended after request"
            raise QgaObservationUnknown(operation, reason) from error
        finally:
            if connection is not None:
                connection.close()
        try:
            response = json.loads(raw)
        except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise QgaProtocolError(f"QGA returned malformed JSON for {command}") from error
        if not isinstance(response, dict):
            raise QgaProtocolError(f"QGA returned a non-object response for {command}")
        if "error" in response:
            raise QgaProtocolError(f"QGA {command} failed: {response['error']}")
        if "return" not in response:
            raise QgaProtocolError(f"QGA response omitted return for {command}")
        return response["return"]

    def _with_deadline(self, connection: socket.socket, deadline: float) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("deadline expired")
        connection.settimeout(remaining)

    def _read_response(self, connection: socket.socket, deadline: float) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while True:
            self._with_deadline(connection, deadline)
            chunk = connection.recv(min(65536, self.max_response_bytes - total + 1))
            if not chunk:
                raise EOFError("response ended before newline")
            newline = chunk.find(b"\n")
            consumed = chunk if newline < 0 else chunk[:newline]
            total += len(consumed)
            if total > self.max_response_bytes:
                raise QgaProtocolError("QGA response exceeded configured byte limit")
            chunks.append(consumed)
            if newline >= 0:
                return b"".join(chunks)

    def _synchronize(self, connection: socket.socket, deadline: float) -> None:
        """Discard stale QGA output before issuing the requested observation.

        QGA documents guest-sync-delimited specifically for a stream left dirty by
        an earlier disconnected client.  The leading 0xFF resets its parser; the
        response sentinel lets this client discard all pre-existing output.
        """
        sync_id = secrets.randbits(63)
        sync = {"execute": "guest-sync-delimited", "arguments": {"id": sync_id}}
        self._with_deadline(connection, deadline)
        connection.sendall(b"\xff" + (json.dumps(sync, separators=(",", ":")) + "\n").encode("utf-8"))
        discarded = 0
        while True:
            self._with_deadline(connection, deadline)
            byte = connection.recv(1)
            if not byte:
                raise EOFError("synchronization response ended")
            discarded += 1
            if discarded > self.max_response_bytes:
                raise QgaProtocolError("QGA synchronization exceeded configured byte limit")
            if byte == b"\xff":
                break
        raw = self._read_response(connection, deadline)
        try:
            response = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise QgaProtocolError("QGA synchronization returned malformed JSON") from error
        if not isinstance(response, dict) or response.get("return") != sync_id:
            raise QgaProtocolError("QGA synchronization did not return the issued id")

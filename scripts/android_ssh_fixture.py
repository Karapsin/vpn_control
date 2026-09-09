"""Private, generation-bound logging for a disposable Android SSH fixture."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol, Sequence


class _Process(Protocol):
    pid: int

    def poll(self) -> int | None: ...

    def terminate(self) -> None: ...


class SshdStartupUnknown(RuntimeError):
    def __init__(self, generation: "SshdLogGeneration", reason: str):
        super().__init__(reason)
        self.generation = generation


class SshdAuthenticationUnknown(RuntimeError):
    def __init__(self, generation: "SshdLogGeneration"):
        super().__init__("Task sshd did not observe current-generation authentication")
        self.generation = generation


@dataclass(frozen=True)
class SshdLogGeneration:
    """Evidence boundary for one sshd process and one fresh private log."""

    pid: int
    generation: str  # Opaque correlation token, never process identity or kill authority.
    log_path: Path
    log_identity: tuple[int, int]
    startup_offset: int | None
    startup_prefix_digest: bytes | None
    process: _Process
    receipt_path: Path | None = None
    receipt_identity: tuple[int, int] | None = None

    def current_authentication_lines(self) -> tuple[str, ...]:
        """Return only successful authentication records written after startup."""
        if self.process.poll() is not None:
            raise RuntimeError("Task sshd process is no longer live")
        if self.startup_offset is None:
            raise RuntimeError("Task sshd startup is not confirmed")
        data = _read_current_file(self.log_path, self.log_identity)
        if len(data) < self.startup_offset:
            raise RuntimeError("Task sshd log was replaced or truncated")
        if hashlib.sha256(data[:self.startup_offset]).digest() != self.startup_prefix_digest:
            raise RuntimeError("Task sshd startup prefix changed")
        return tuple(
            line
            for line in data[self.startup_offset:].decode("utf-8", errors="replace").splitlines()
            if "Accepted publickey for " in line
        )


def _file_identity(stat: os.stat_result) -> tuple[int, int]:
    return stat.st_dev, stat.st_ino


def _read_current_file(path: Path, expected_identity: tuple[int, int]) -> bytes:
    """Read one file only if its path and opened handle are the claimed file."""
    path_identity = _file_identity(path.stat())
    with path.open("rb") as stream:
        handle_identity = _file_identity(os.fstat(stream.fileno()))
        if path_identity != expected_identity or handle_identity != expected_identity:
            raise RuntimeError("Task sshd log was replaced")
        data = stream.read()
    if _file_identity(path.stat()) != expected_identity:
        raise RuntimeError("Task sshd log was replaced")
    return data


def _private_new_file(path: Path, label: str) -> tuple[int, int]:
    if not path.is_absolute() or not path.parent.is_dir():
        raise ValueError(f"Task sshd {label} must have an existing absolute parent directory")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise ValueError(f"Task sshd {label} path must be fresh for each generation") from error
    os.close(descriptor)
    stat = path.stat()
    if os.name == "posix" and stat.st_mode & 0o777 != 0o600:
        raise RuntimeError(f"Task sshd {label} is not owner-only")
    return _file_identity(stat)


@dataclass(frozen=True)
class _ReceiptClaim:
    path: Path
    identity: tuple[int, int]


def _claim_receipt(path: Path) -> _ReceiptClaim:
    identity = _private_new_file(path, "receipt")
    return _ReceiptClaim(path, identity)


def _write_claimed_receipt(claim: _ReceiptClaim, generation: SshdLogGeneration, readiness: str) -> None:
    payload = json.dumps({
        "pid": generation.pid,
        "runToken": generation.generation,
        "logPath": str(generation.log_path),
        "logIdentity": list(generation.log_identity),
        "startupOffset": generation.startup_offset,
        "readiness": readiness,
    }, sort_keys=True) + "\n"
    with claim.path.open("r+b") as stream:
        if _file_identity(os.fstat(stream.fileno())) != claim.identity:
            raise RuntimeError("Task sshd receipt was replaced")
        stream.seek(0)
        stream.truncate(0)
        stream.write(payload.encode("utf-8"))
    if _file_identity(claim.path.stat()) != claim.identity:
        raise RuntimeError("Task sshd receipt was replaced")


def _write_startup_receipt(claim: _ReceiptClaim, generation: SshdLogGeneration, readiness: str) -> None:
    try:
        _write_claimed_receipt(claim, generation, readiness)
    except (OSError, RuntimeError) as error:
        raise SshdStartupUnknown(generation, "Task sshd receipt publication failed") from error


def start_task_sshd(
    *,
    sshd: Path,
    config: Path,
    log_path: Path,
    receipt_path: Path | None = None,
    spawn: Callable[..., _Process] = subprocess.Popen,
    attempts: int = 20,
    pause: Callable[[float], None] = time.sleep,
) -> SshdLogGeneration:
    """Start sshd and return a live capture that the caller must retain to inspect auth."""
    if not sshd.is_absolute() or not config.is_absolute() or attempts < 1:
        raise ValueError("Task sshd executable, config, and attempts are invalid")
    receipt = _claim_receipt(receipt_path) if receipt_path is not None else None
    log_identity = _private_new_file(log_path, "log")
    command: Sequence[str] = (str(sshd), "-D", "-E", str(log_path), "-f", str(config))
    process = spawn(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    pending = SshdLogGeneration(
        process.pid,
        hashlib.sha256(f"{process.pid}:{time.time_ns()}:{uuid.uuid4()}".encode("ascii")).hexdigest(),
        log_path,
        log_identity,
        None,
        None,
        process,
        receipt.path if receipt is not None else None,
        receipt.identity if receipt is not None else None,
    )
    if receipt is not None:
        _write_startup_receipt(receipt, pending, "starting")
    for _ in range(attempts):
        if process.poll() is not None:
            error = SshdStartupUnknown(pending, "Task sshd exited before logging startup")
            if receipt is not None:
                _write_startup_receipt(receipt, pending, "unknown")
            raise error
        try:
            data = _read_current_file(log_path, log_identity)
        except (OSError, RuntimeError) as error:
            unknown = SshdStartupUnknown(pending, str(error))
            if receipt is not None:
                _write_startup_receipt(receipt, pending, "unknown")
            raise unknown from error
        marker = data.find(b"Server listening on ")
        marker_end = data.find(b"\n", marker) + 1 if marker >= 0 else 0
        if marker_end:
            capture = SshdLogGeneration(
                pending.pid, pending.generation, log_path, log_identity, marker_end,
                hashlib.sha256(data[:marker_end]).digest(), process, pending.receipt_path, pending.receipt_identity,
            )
            if receipt is not None:
                _write_startup_receipt(receipt, capture, "ready")
            return capture
        pause(0.05)
    error = SshdStartupUnknown(pending, "Task sshd did not write a startup marker to its private log")
    if receipt is not None:
        _write_startup_receipt(receipt, pending, "unknown")
    raise error


def wait_for_current_authentication(
    generation: SshdLogGeneration,
    *,
    attempts: int,
    pause: Callable[[float], None] = time.sleep,
) -> tuple[str, ...]:
    """Keep the live ``Popen`` handle while waiting for post-start ssh authentication."""
    if attempts < 1:
        raise ValueError("Task sshd authentication attempts are invalid")
    for _ in range(attempts):
        lines = generation.current_authentication_lines()
        if lines:
            if generation.receipt_path is not None and generation.receipt_identity is not None:
                _write_claimed_receipt(
                    _ReceiptClaim(generation.receipt_path, generation.receipt_identity), generation, "authenticated",
                )
            return lines
        pause(0.05)
    if generation.receipt_path is not None and generation.receipt_identity is not None:
        _write_claimed_receipt(
            _ReceiptClaim(generation.receipt_path, generation.receipt_identity), generation, "authentication_missing",
        )
    raise SshdAuthenticationUnknown(generation)


def _main() -> int:
    parser = argparse.ArgumentParser(
        description="Setup-only task sshd launcher; it cannot certify authentication after this process exits.",
    )
    parser.add_argument("--sshd", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    try:
        start_task_sshd(sshd=args.sshd, config=args.config, log_path=args.log, receipt_path=args.receipt)
    except SshdStartupUnknown as error:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())

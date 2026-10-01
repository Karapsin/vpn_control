"""Shared, source-bound one-use transfer journal for large Windows artifacts.

Adapters retain product-specific campaign admission and guest ACL semantics.
This core owns only immutable local provenance, a finite phase receipt, and
strict projection of host/guest receipts.  It is deliberately unable to infer
an artifact path, a guest path, or an owner from caller input.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import uuid
from typing import Any, Mapping


class WindowsLargeArtifactTransferError(ValueError):
    pass


_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_SID = re.compile(r"S-1-5-21-(?:[0-9]+-){3}[0-9]+\Z")
_KINDS = {"msi", "fixture-zip"}
_PHASES = {"prepared", "host-staged", "listening", "guest-created", "download-submitted", "downloaded", "placed", "cleaned", "aborted"}
_UNKNOWN = {"state": "unknown", "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
_E66_CORRELATION = "e66d02a7-a40c-41e0-8f8b-674624f98a54"
_E66_SOURCE = "19be9df22cbab8086c26e5ca907d9569a5a28a08"
_E66_ARTIFACT = "sha256-8facb25a6c90507f35575bec51f23a66889874ad0f1cc3b9749c4933ef5c2262"
_SOURCE_OPEN_FAILURE = {"kind": "base-remote-source-open", "fingerprint":
                        "c6c553f6e19d719427187d9db49f0d584fe7345346b7337e9d879d8f42c02a90"}


def _canonical_uuid(value: Any) -> bool:
    return isinstance(value, str) and bool(_UUID.fullmatch(value)) and str(uuid.UUID(value)) == value


def request(value: Mapping[str, Any]) -> dict[str, Any]:
    fields = {"correlationId", "sourceSha", "artifactId", "kind", "environment", "socketPath", "qemuPid", "startTicks", "expectedSid"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise WindowsLargeArtifactTransferError("Exact large-artifact transfer binding is required.")
    result = dict(value)
    if (not _canonical_uuid(result["correlationId"]) or not isinstance(result["sourceSha"], str) or not _SHA.fullmatch(result["sourceSha"])
            or not isinstance(result["artifactId"], str) or not result["artifactId"].startswith("sha256-") or not _HASH.fullmatch(result["artifactId"][7:])
            or result["kind"] not in _KINDS or result["environment"] != "windows-cp117"
            or not isinstance(result["socketPath"], str) or not re.fullmatch(r"/[A-Za-z0-9._/-]+", result["socketPath"]) or ".." in Path(result["socketPath"]).parts
            or type(result["qemuPid"]) is not int or result["qemuPid"] <= 0 or type(result["startTicks"]) is not int or result["startTicks"] <= 0
            or not isinstance(result["expectedSid"], str) or not _SID.fullmatch(result["expectedSid"])):
        raise WindowsLargeArtifactTransferError("Invalid large-artifact transfer binding.")
    return result


def _dir(root: Path, create: bool) -> Path | None:
    path = root / ".rag_index" / "windows-large-artifact-transfer"
    if not path.exists() and not path.is_symlink():
        if not create: return None
        path.mkdir(parents=True, mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise WindowsLargeArtifactTransferError("Unsafe transfer journal.")
    return path


def _digest(path: Path, expected: str) -> int:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_uid != os.getuid() or not 0 < info.st_size <= 1 << 30:
        raise WindowsLargeArtifactTransferError("Unsafe transfer artifact.")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)); h = hashlib.sha256()
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        for block in iter(lambda: stream.read(1 << 20), b""): h.update(block)
        after = os.fstat(stream.fileno())
    if before.st_ino != info.st_ino or after.st_ino != info.st_ino or after.st_size != info.st_size or h.hexdigest() != expected:
        raise WindowsLargeArtifactTransferError("Transfer artifact changed.")
    return info.st_size


def prepare(root: Path | str, binding: Mapping[str, Any], artifact: Path | str) -> dict[str, Any]:
    root = Path(root).resolve(strict=True); bound = request(binding); artifact = Path(artifact).resolve(strict=True)
    size = _digest(artifact, bound["artifactId"][7:]); directory = _dir(root, True); assert directory
    record = {"binding": bound, "artifactPath": str(artifact), "sha256": bound["artifactId"][7:], "length": size,
              "routeNonce": secrets.token_urlsafe(32), "phase": "prepared"}
    raw = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
    try: fd = os.open(directory / (bound["correlationId"] + ".json"), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError: return {**_UNKNOWN, "correlationId": bound["correlationId"]}
    with os.fdopen(fd, "wb") as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    return {"state": "prepared", "correlationId": bound["correlationId"], "sha256": record["sha256"], "length": size, **{k:v for k,v in _UNKNOWN.items() if k != "state"}}


def read(root: Path | str, correlation_id: str) -> dict[str, Any] | None:
    if not _canonical_uuid(correlation_id): raise WindowsLargeArtifactTransferError("Invalid transfer correlation.")
    directory = _dir(Path(root).resolve(strict=True), False)
    if directory is None: return None
    try: fd = os.open(directory / (correlation_id + ".json"), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError: return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 8192: raise WindowsLargeArtifactTransferError("Unsafe transfer intent.")
        value = json.load(stream)
    required = {"binding", "artifactPath", "sha256", "length", "routeNonce", "phase"}
    permitted = (required, required | {"dispatchFailure"}, required | {"dispatchFailure", "preEffectClose"})
    if not isinstance(value, dict) or set(value) not in permitted: raise WindowsLargeArtifactTransferError("Invalid transfer intent.")
    bound = request(value["binding"])
    if bound["correlationId"] != correlation_id or value["sha256"] != bound["artifactId"][7:] or type(value["length"]) is not int or value["length"] <= 0 or value["phase"] not in _PHASES or not isinstance(value["routeNonce"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", value["routeNonce"]): raise WindowsLargeArtifactTransferError("Invalid transfer intent.")
    _digest(Path(value["artifactPath"]), value["sha256"])
    failure = {"kind": "base-remote-source-open", "fingerprint": "c6c553f6e19d719427187d9db49f0d584fe7345346b7337e9d879d8f42c02a90"}
    if "dispatchFailure" in value and value["dispatchFailure"] != failure:
        raise WindowsLargeArtifactTransferError("Invalid transfer dispatch failure.")
    if ("preEffectClose" in value and (value["preEffectClose"] != {"reason": "source-not-path", "remoteStage": "absent"}
            or value.get("dispatchFailure") != failure)):
        raise WindowsLargeArtifactTransferError("Invalid transfer pre-effect closure.")
    return value


def project(record: Mapping[str, Any], receipt: Mapping[str, Any], phase: str) -> dict[str, Any]:
    """Accept one exact bounded receipt; owner/ACL classes are never caller supplied."""
    if phase not in _PHASES or not isinstance(record, Mapping) or not isinstance(receipt, Mapping): return dict(_UNKNOWN)
    expected = {"state": phase, "sha256": record.get("sha256"), "length": record.get("length"), "owner": "expected", "reparse": "no"}
    if dict(receipt) != expected: return dict(_UNKNOWN)
    return {"state": phase, "correlationId": record["binding"]["correlationId"], "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}


_ORDER = ("prepared", "host-staged", "listening", "guest-created", "download-submitted", "downloaded", "placed", "cleaned")


def advance(root: Path | str, correlation_id: str, phase: str) -> dict[str, Any]:
    """Durably record one monotonic phase before or after its bound effect.

    The adapters decide what observation admits a phase.  This journal supplies
    the one-shot edge: an accepted phase is never silently replayed after a
    lost response.  A replacement is guarded by an exclusive lock and fsynced
    so a later status call can reconcile an interrupted caller.
    """
    if phase not in _PHASES:
        return dict(_UNKNOWN)
    root_path = Path(root).resolve(strict=True)
    record = read(root_path, correlation_id)
    if record is None:
        return dict(_UNKNOWN)
    current = record["phase"]
    if current == phase:
        return dict(_UNKNOWN)
    if current in {"cleaned", "aborted"}:
        return dict(_UNKNOWN)
    if phase == "aborted":
        allowed = current in {"prepared", "host-staged", "listening", "download-submitted"}
    else:
        allowed = current in _ORDER and phase in _ORDER and _ORDER.index(phase) == _ORDER.index(current) + 1
        # MSI has no separate SYSTEM create action.  Fixture ZIP transfers do,
        # so only the MSI ABI may reserve its owner download directly.
        if (current, phase) == ("listening", "download-submitted") and record["binding"]["kind"] == "msi":
            allowed = True
    if not allowed:
        return dict(_UNKNOWN)
    directory = _dir(root_path, False)
    assert directory is not None
    path = directory / (correlation_id + ".json")
    lock_path = directory / (correlation_id + ".lock")
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            return dict(_UNKNOWN)
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX)
        fresh = read(root_path, correlation_id)
        if fresh is None or fresh["phase"] != current:
            return dict(_UNKNOWN)
        fresh["phase"] = phase
        temporary = directory / ("." + correlation_id + ".tmp")
        raw = (json.dumps(fresh, sort_keys=True, separators=(",", ":")) + "\n").encode()
        new_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(new_fd, "wb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        try:
            (directory / ("." + correlation_id + ".tmp")).unlink()
        except FileNotFoundError:
            pass
        os.close(fd)
    return {"state": phase, "correlationId": correlation_id, **{key: value for key, value in _UNKNOWN.items() if key != "state"}}


def close_host_staged_pre_effect(root: Path | str, correlation_id: str) -> dict[str, Any]:
    """Irreversibly preserve the known local dispatch failure without replay.

    The adapter calls this only after its separate, read-only host query proves
    that no remote stage directory was created.  The immutable reason records
    the deterministic adapter boundary and this core never resets a consumed
    one-shot phase back to ``prepared``.
    """
    root_path = Path(root).resolve(strict=True)
    record = read(root_path, correlation_id)
    if record is None or record.get("phase") != "host-staged":
        return dict(_UNKNOWN)
    directory = _dir(root_path, False)
    assert directory is not None
    path = directory / (correlation_id + ".json"); lock_path = directory / (correlation_id + ".lock")
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            return dict(_UNKNOWN)
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX)
        fresh = read(root_path, correlation_id)
        # A host absence query alone cannot prove that a delayed delivery will
        # not occur.  Closure therefore also requires the exact fsynced local
        # pre-dispatch failure receipt.  Historic reservations without it stay
        # armed for controlled recovery rather than being guessed closed.
        failure = {"kind": "base-remote-source-open", "fingerprint": "c6c553f6e19d719427187d9db49f0d584fe7345346b7337e9d879d8f42c02a90"}
        if (fresh is None or fresh.get("phase") != "host-staged" or "preEffectClose" in fresh
                or fresh.get("dispatchFailure") != failure):
            return dict(_UNKNOWN)
        fresh["phase"] = "aborted"
        fresh["preEffectClose"] = {"reason": "source-not-path", "remoteStage": "absent"}
        temporary = directory / ("." + correlation_id + ".tmp")
        raw = (json.dumps(fresh, sort_keys=True, separators=(",", ":")) + "\n").encode()
        new_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(new_fd, "wb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try: os.fsync(parent_fd)
        finally: os.close(parent_fd)
    finally:
        try: (directory / ("." + correlation_id + ".tmp")).unlink()
        except FileNotFoundError: pass
        os.close(fd)
    return {"state": "aborted", "correlationId": correlation_id,
            **{key: value for key, value in _UNKNOWN.items() if key != "state"}}


def record_predispatch_failure(root: Path | str, correlation_id: str) -> dict[str, Any]:
    """Import the one historical e66 source-open failure into the transfer journal.

    The fixed adapter validates the original Codex command transcript and
    fsyncs its import receipt.  This core verifies that receipt again before
    it records the exact failure under the same phase lock used by ``advance``.
    Neither another correlation nor a caller-supplied failure can use this edge.
    """
    if correlation_id != _E66_CORRELATION:
        return dict(_UNKNOWN)
    root_path = Path(root).resolve(strict=True)
    record = read(root_path, correlation_id)
    if (record is None or record.get("phase") != "host-staged"
            or record["binding"].get("sourceSha") != _E66_SOURCE
            or record["binding"].get("artifactId") != _E66_ARTIFACT
            or record["binding"].get("kind") != "fixture-zip"
            or "dispatchFailure" in record or "preEffectClose" in record):
        return dict(_UNKNOWN)
    from . import windows_update_fixture_http_stage as fixture_stage
    try:
        transcript = fixture_stage._e66_transcript(root_path)
        if not fixture_stage._e66_imported(root_path, transcript):
            return dict(_UNKNOWN)
    except (OSError, ValueError, TypeError, KeyError):
        return dict(_UNKNOWN)
    directory = _dir(root_path, False)
    assert directory is not None
    path = directory / (correlation_id + ".json")
    lock_path = directory / (correlation_id + ".lock")
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600):
            return dict(_UNKNOWN)
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX)
        fresh = read(root_path, correlation_id)
        if (fresh is None or fresh.get("phase") != "host-staged"
                or fresh["binding"] != record["binding"]
                or "dispatchFailure" in fresh or "preEffectClose" in fresh
                or not fixture_stage._e66_imported(root_path, fixture_stage._e66_transcript(root_path))):
            return dict(_UNKNOWN)
        fresh["dispatchFailure"] = dict(_SOURCE_OPEN_FAILURE)
        temporary = directory / ("." + correlation_id + ".tmp")
        raw = (json.dumps(fresh, sort_keys=True, separators=(",", ":")) + "\n").encode()
        new_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(new_fd, "wb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try: os.fsync(parent_fd)
        finally: os.close(parent_fd)
    finally:
        try: (directory / ("." + correlation_id + ".tmp")).unlink()
        except FileNotFoundError: pass
        os.close(fd)
    return {"state": "failure-recorded", "correlationId": correlation_id,
            **{key: value for key, value in _UNKNOWN.items() if key != "state"}}


def cleanup_admitted(record: Mapping[str, Any], observed_phase: str) -> bool:
    """Cleanup only after a known terminal state; unknown/lost responses fail closed."""
    return isinstance(record, Mapping) and record.get("phase") in {"downloaded", "placed"} and observed_phase in {"downloaded", "placed"}

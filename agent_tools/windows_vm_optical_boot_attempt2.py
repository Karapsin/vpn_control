"""Fixed second optical boot attempt after terminal proof of the first's pre-effect failure.

This preserves every first-attempt journal and guest receipt. The only native
effect remains the reviewed single reset and space key in windows_vm_optical_boot.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
from typing import Any

try:
    from . import windows_vm_optical_boot as boot
except ImportError:
    import windows_vm_optical_boot as boot  # type: ignore[no-redef]


def _intent(root: str | Path, create: bool) -> Path:
    base = Path(root).resolve() / ".rag_index"
    directory = base / "windows-vm-optical-boot-attempt2"
    if create:
        base.mkdir(mode=0o700, exist_ok=True)
        directory.mkdir(mode=0o700, exist_ok=True)
    for path in (base, directory):
        info = os.lstat(path)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError("Windows optical second-attempt journal is unsafe")
    return directory / "intent.json"


def _payload(correlation_id: str, closure_correlation_id: str) -> dict[str, Any]:
    return {**boot._payload(correlation_id), "attempt": 2,
            "originalCorrelationId": boot.FIRST_CORRELATION,
            "closureCorrelationId": closure_correlation_id}


def _close_intent(root: str | Path, create: bool) -> Path:
    base = Path(root).resolve() / ".rag_index"
    directory = base / "windows-vm-optical-boot-attempt2-pre-effect-close"
    if create:
        base.mkdir(mode=0o700, exist_ok=True)
        directory.mkdir(mode=0o700, exist_ok=True)
    for path in (base, directory):
        info = os.lstat(path)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError("Windows optical second closure journal is unsafe")
    return directory / "intent.json"


def _close_payload(closure_correlation_id: str) -> dict[str, Any]:
    return {"schemaVersion": 1, "host": boot.HOST,
            "originalCorrelationId": boot.SECOND_CORRELATION,
            "closureCorrelationId": closure_correlation_id,
            "firstClosureCorrelationId": boot.FIRST_CLOSURE,
            "vmCorrelationId": boot.VM_CORRELATION,
            "reservationId": boot.RESERVATION_ID, "guest": boot.setup.GUEST,
            "isoSha256": boot.setup.WINDOWS_SHA256, "sampleGapMs": 1000}


def _check(root: str | Path, host: str, correlation_id: str,
           closure_correlation_id: str, timeout_seconds: int) -> None:
    boot._check(host, correlation_id, timeout_seconds)
    boot._check(host, closure_correlation_id, timeout_seconds)
    if correlation_id in (boot.FIRST_CORRELATION, closure_correlation_id):
        raise ValueError("Windows optical second attempt needs a distinct correlation")
    boot._read(boot._intent(root, create=False), boot.FIRST_CORRELATION)
    boot._read(boot._close_intent(root, create=False), closure_correlation_id,
               boot._close_payload(closure_correlation_id))
    boot._reservation(root)
    if boot.setup.status(root, host=host, correlation_id=boot.VM_CORRELATION,
                         timeout_seconds=timeout_seconds).get("state") != "running-observed":
        raise ValueError("Windows baseline VM is not running-observed")
    if boot.close_status(root, host=host, closure_correlation_id=closure_correlation_id,
                         timeout_seconds=timeout_seconds).get("state") != "pre-effect-closed":
        raise ValueError("Windows first optical attempt has no terminal closure")


def preflight(root: str | Path, *, host: str, correlation_id: str,
              closure_correlation_id: str, timeout_seconds: int = 90) -> dict[str, Any]:
    _check(root, host, correlation_id, closure_correlation_id, timeout_seconds)
    result = boot._remote(root, host, correlation_id, "preflight", timeout_seconds,
                          attempt=2, expected_closure=closure_correlation_id)
    return {"correlationId": correlation_id, "closureCorrelationId": closure_correlation_id,
            "state": result["state"], "owner": result.get("owner"),
            "media": result.get("media"), "blankDisk": result.get("blankDisk"),
            "reservationId": result.get("reservationId"),
            "replayAllowed": False, "nativeActionAllowed": False}


def start(root: str | Path, *, host: str, correlation_id: str,
          closure_correlation_id: str, timeout_seconds: int = 90) -> dict[str, Any]:
    _check(root, host, correlation_id, closure_correlation_id, timeout_seconds)
    path = _intent(root, create=True)
    try:
        boot._save(path, correlation_id, _payload(correlation_id, closure_correlation_id))
    except FileExistsError as error:
        raise ValueError("Windows optical second-attempt intent exists; use status") from error
    try:
        result = boot._remote(root, host, correlation_id, "start", timeout_seconds,
                              attempt=2, expected_closure=closure_correlation_id)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        result = {"state": "unknown"}
    return {"correlationId": correlation_id, "closureCorrelationId": closure_correlation_id,
            "state": result["state"], "owner": result.get("owner"),
            "frameHashes": result.get("frameHashes"),
            "replayAllowed": False, "nativeActionAllowed": False}


def status(root: str | Path, *, host: str, correlation_id: str,
           closure_correlation_id: str, timeout_seconds: int = 60) -> dict[str, Any]:
    boot._check(host, correlation_id, timeout_seconds)
    boot._check(host, closure_correlation_id, timeout_seconds)
    boot._read(_intent(root, create=False), correlation_id,
               _payload(correlation_id, closure_correlation_id))
    boot._reservation(root)
    try:
        result = boot._remote(root, host, correlation_id, "status", timeout_seconds,
                              attempt=2, expected_closure=closure_correlation_id)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        result = {"state": "unknown"}
    return {"correlationId": correlation_id, "closureCorrelationId": closure_correlation_id,
            "state": result["state"], "owner": result.get("owner"),
            "frameHashes": result.get("frameHashes"), "phaseEvidence": result.get("phaseEvidence"),
            "replayAllowed": False, "nativeActionAllowed": False}


def phase_probe(root: str | Path, *, host: str, correlation_id: str,
                closure_correlation_id: str, timeout_seconds: int = 60) -> dict[str, Any]:
    """Read-only QMP single-client phase check for a stopped-before-frame attempt."""
    _check(root, host, correlation_id, closure_correlation_id, timeout_seconds)
    boot._read(_intent(root, create=False), correlation_id,
               _payload(correlation_id, closure_correlation_id))
    try:
        result = boot._remote(root, host, correlation_id, "phase-probe", timeout_seconds,
                              attempt=2, expected_closure=closure_correlation_id)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        result = {"state": "unknown"}
    return {"correlationId": correlation_id, "closureCorrelationId": closure_correlation_id,
            "state": result["state"], "owner": result.get("owner"), "probe": result.get("probe"),
            "replayAllowed": False, "nativeActionAllowed": False}


def close_preflight(root: str | Path, *, host: str, closure_correlation_id: str,
                    timeout_seconds: int = 90) -> dict[str, Any]:
    _check(root, host, boot.SECOND_CORRELATION, boot.FIRST_CLOSURE, timeout_seconds)
    boot._check(host, closure_correlation_id, timeout_seconds)
    if closure_correlation_id in (boot.FIRST_CORRELATION, boot.FIRST_CLOSURE,
                                  boot.SECOND_CORRELATION):
        raise ValueError("Second closure needs a distinct correlation")
    boot._read(_intent(root, create=False), boot.SECOND_CORRELATION,
               _payload(boot.SECOND_CORRELATION, boot.FIRST_CLOSURE))
    result = boot._remote(root, host, boot.SECOND_CORRELATION, "close-preflight",
                          timeout_seconds, closure_correlation_id,
                          attempt=2, expected_closure=boot.FIRST_CLOSURE)
    return {"closureCorrelationId": closure_correlation_id,
            "originalCorrelationId": boot.SECOND_CORRELATION,
            "state": result["state"], "owner": result.get("owner"),
            "sampleSha256": result.get("sampleSha256"),
            "sampleIntervalNs": result.get("sampleIntervalNs"),
            "replayAllowed": False, "nativeActionAllowed": False}


def close_start(root: str | Path, *, host: str, closure_correlation_id: str,
                timeout_seconds: int = 90) -> dict[str, Any]:
    _check(root, host, boot.SECOND_CORRELATION, boot.FIRST_CLOSURE, timeout_seconds)
    boot._check(host, closure_correlation_id, timeout_seconds)
    if closure_correlation_id in (boot.FIRST_CORRELATION, boot.FIRST_CLOSURE,
                                  boot.SECOND_CORRELATION):
        raise ValueError("Second closure needs a distinct correlation")
    boot._read(_intent(root, create=False), boot.SECOND_CORRELATION,
               _payload(boot.SECOND_CORRELATION, boot.FIRST_CLOSURE))
    path = _close_intent(root, create=True)
    try:
        boot._save(path, closure_correlation_id, _close_payload(closure_correlation_id))
    except FileExistsError as error:
        raise ValueError("Windows optical second closure intent exists; use status") from error
    try:
        result = boot._remote(root, host, boot.SECOND_CORRELATION, "close-start",
                              timeout_seconds, closure_correlation_id,
                              attempt=2, expected_closure=boot.FIRST_CLOSURE)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        result = {"state": "unknown"}
    return {"closureCorrelationId": closure_correlation_id,
            "originalCorrelationId": boot.SECOND_CORRELATION,
            "state": result["state"], "owner": result.get("owner"),
            "sampleSha256": result.get("sampleSha256"),
            "replayAllowed": False, "nativeActionAllowed": False}


def close_status(root: str | Path, *, host: str, closure_correlation_id: str,
                 timeout_seconds: int = 60) -> dict[str, Any]:
    boot._check(host, closure_correlation_id, timeout_seconds)
    boot._read(_intent(root, create=False), boot.SECOND_CORRELATION,
               _payload(boot.SECOND_CORRELATION, boot.FIRST_CLOSURE))
    boot._read(_close_intent(root, create=False), closure_correlation_id,
               _close_payload(closure_correlation_id))
    boot._reservation(root)
    try:
        result = boot._remote(root, host, boot.SECOND_CORRELATION, "status",
                              timeout_seconds, closure_correlation_id,
                              attempt=2, expected_closure=boot.FIRST_CLOSURE)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        result = {"state": "unknown"}
    state = result["state"] if result["state"] == "pre-effect-closed" else "unknown"
    return {"closureCorrelationId": closure_correlation_id,
            "originalCorrelationId": boot.SECOND_CORRELATION,
            "state": state, "owner": result.get("owner"),
            "replayAllowed": False, "nativeActionAllowed": False}

"""Fixed third optical boot attempt after verified pre-effect closure of attempt two."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
from typing import Any

try:
    from . import windows_vm_optical_boot as boot
    from . import windows_vm_optical_boot_attempt2 as second
except ImportError:
    import windows_vm_optical_boot as boot  # type: ignore[no-redef]
    import windows_vm_optical_boot_attempt2 as second  # type: ignore[no-redef]


def _intent(root: str | Path, create: bool) -> Path:
    base = Path(root).resolve() / ".rag_index"
    directory = base / "windows-vm-optical-boot-attempt3"
    if create:
        base.mkdir(mode=0o700, exist_ok=True)
        directory.mkdir(mode=0o700, exist_ok=True)
    for path in (base, directory):
        info = os.lstat(path)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError("Windows optical third-attempt journal is unsafe")
    return directory / "intent.json"


def _payload(correlation_id: str, closure_correlation_id: str) -> dict[str, Any]:
    return {**boot._payload(correlation_id), "attempt": 3,
            "firstCorrelationId": boot.FIRST_CORRELATION,
            "firstClosureCorrelationId": boot.FIRST_CLOSURE,
            "secondCorrelationId": boot.SECOND_CORRELATION,
            "secondClosureCorrelationId": closure_correlation_id}


def _check(root: str | Path, host: str, correlation_id: str,
           closure_correlation_id: str, timeout_seconds: int) -> None:
    boot._check(host, correlation_id, timeout_seconds)
    boot._check(host, closure_correlation_id, timeout_seconds)
    if correlation_id in (boot.FIRST_CORRELATION, boot.FIRST_CLOSURE,
                          boot.SECOND_CORRELATION, closure_correlation_id):
        raise ValueError("Windows optical third attempt needs a distinct correlation")
    boot._read(boot._intent(root, create=False), boot.FIRST_CORRELATION)
    boot._read(boot._close_intent(root, create=False), boot.FIRST_CLOSURE,
               boot._close_payload(boot.FIRST_CLOSURE))
    boot._read(second._intent(root, create=False), boot.SECOND_CORRELATION,
               second._payload(boot.SECOND_CORRELATION, boot.FIRST_CLOSURE))
    boot._read(second._close_intent(root, create=False), closure_correlation_id,
               second._close_payload(closure_correlation_id))
    boot._reservation(root)
    if boot.setup.status(root, host=host, correlation_id=boot.VM_CORRELATION,
                         timeout_seconds=timeout_seconds).get("state") != "running-observed":
        raise ValueError("Windows baseline VM is not running-observed")
    if second.close_status(root, host=host, closure_correlation_id=closure_correlation_id,
                           timeout_seconds=timeout_seconds).get("state") != "pre-effect-closed":
        raise ValueError("Windows second optical attempt has no terminal closure")


def preflight(root: str | Path, *, host: str, correlation_id: str,
              closure_correlation_id: str, timeout_seconds: int = 90) -> dict[str, Any]:
    _check(root, host, correlation_id, closure_correlation_id, timeout_seconds)
    result = boot._remote(root, host, correlation_id, "preflight", timeout_seconds,
                          attempt=3, expected_closure=closure_correlation_id)
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
        raise ValueError("Windows optical third-attempt intent exists; use status") from error
    try:
        result = boot._remote(root, host, correlation_id, "start", timeout_seconds,
                              attempt=3, expected_closure=closure_correlation_id)
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
                              attempt=3, expected_closure=closure_correlation_id)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        result = {"state": "unknown"}
    return {"correlationId": correlation_id, "closureCorrelationId": closure_correlation_id,
            "state": result["state"], "owner": result.get("owner"),
            "frameHashes": result.get("frameHashes"), "phaseEvidence": result.get("phaseEvidence"),
            "replayAllowed": False, "nativeActionAllowed": False}

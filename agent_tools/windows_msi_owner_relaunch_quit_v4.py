"""Fourth, separately correlated public quit for CP117's fixed owner.

The v3 task is immutable after its recorded failure.  This helper has its own
journal and task name, and is admitted only when the failed v3 task and the
read-only phase diagnosis are bound to the current guest.  Its limited-user
program differs solely in the exact unquoted owner command form.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import fcntl
import stat
from typing import Any, Mapping

from . import windows_msi_base_prepare as base
from . import windows_msi_owner_quit_phase_diagnostic as phase_diagnostic
from . import windows_msi_owner_relaunch as relaunch
from . import windows_msi_owner_relaunch_quit as v1
from . import windows_msi_owner_relaunch_quit_v3 as v3


class WindowsMsiOwnerRelaunchQuitV4Error(ValueError):
    pass


_CORRELATION = "bf8c6d40-1021-4f8e-b2e3-73cdad967788"
_GROUP = ".rag_index/windows-msi-owner-relaunch-quit-v4"
_TASK = "VpnControlCp117OwnerRelaunchQuitV4C32"
_UNKNOWN = {"state": "unknown", "replayAllowed": False, "nativeActionAllowed": False}
_REQUEST = {"host": "archlinux", "correlationId": _CORRELATION,
            "sourceSha": relaunch._SOURCE, "taskName": _TASK,
            "operation": "public-quit-relaunched-owner-v4"}
_REQUEST_SHA256 = hashlib.sha256(json.dumps(
    _REQUEST, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# Keep the original v1/v3 body immutable.  The exact pair created by relaunch
# has a quoted executable in one process and an unquoted executable plus an
# unquoted state directory in the other.
_OLD_OWNER_FORM = "$q=0;$u=0;$argument='--state-dir \"'+$state+'\" serve';$quoted='\"'+$cli+'\" '+$argument;$unquoted=$cli+' '+$argument"
_NEW_OWNER_FORM = "$q=0;$u=0;$quotedArgument='--state-dir \"'+$state+'\" serve';$unquotedArgument='--state-dir '+$state+' serve';$quoted='\"'+$cli+'\" '+$quotedArgument;$unquoted=$cli+' '+$unquotedArgument"
if _OLD_OWNER_FORM not in v1._TASK_PS:
    raise RuntimeError("Reviewed v1 owner form changed.")
_TASK_PS = v1._TASK_PS.replace(_OLD_OWNER_FORM, _NEW_OWNER_FORM)


def _render_remote() -> str:
    """Reuse the reviewed compact v3 transport with a distinct fixed task."""
    remote = v3._REMOTE
    task_count = remote.count(repr(v3._TASK))
    if task_count < 1:
        raise RuntimeError("Reviewed v3 task name changed.")
    remote = remote.replace(repr(v3._TASK), repr(_TASK))
    # v3 rejected a present v3 task.  V4 instead requires its exact failed
    # receipt: limited principal, expected action digest and a nonzero result.
    remote = remote.replace(
        "V2_TASK='VpnControlCp117OwnerRelaunchQuitV2C32'\n",
        "V2_TASK='VpnControlCp117OwnerRelaunchQuitV2C32'\nV3_TASK=" + repr(v3._TASK) + "\nV3_TASK_PS=" + repr(v3._TASK_PS) + "\n",
        1,
    )
    old_body = "body=" + repr(v3._TASK_PS) + ".replace('__SID__',sid).replace('__CLI_HASH__',cli_hash);args="
    new_body = (
        "body=" + repr(_TASK_PS) + ".replace('__SID__',sid).replace('__CLI_HASH__',cli_hash);"
        "v3_body=V3_TASK_PS.replace('__SID__',sid).replace('__CLI_HASH__',cli_hash);"
        "v3_args='-NoProfile -NonInteractive -EncodedCommand '+ps(v3_body);"
        "v3_digest=hashlib.sha256(v3_args.encode()).hexdigest();args="
    )
    if remote.count(old_body) != 1:
        raise RuntimeError("Reviewed v3 task body changed.")
    remote = remote.replace(
        old_body, new_body,
        1,
    )
    prior = "if(Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue){throw 'TASK'};"
    required = ("$t3=Get-ScheduledTask -TaskName '" + v3._TASK + "' -ErrorAction Stop;$a3=@($t3.Actions);"
                "$i3=Get-ScheduledTaskInfo -TaskName '" + v3._TASK + "' -ErrorAction Stop;"
                "if((Sid ([string]$t3.Principal.UserId)) -cne $sid -or $t3.Principal.LogonType.ToString() -cne 'Interactive' -or $t3.Principal.RunLevel.ToString() -cne 'Limited' -or $a3.Count -ne 1 -or $a3[0].Execute -cne $psExe -or (Hash ([string]$a3[0].Arguments)) -cne '\"+v3_digest+\"' -or $i3.LastRunTime -eq [datetime]::MinValue -or $i3.LastTaskResult -eq 0){throw 'V3_RECEIPT'};" + prior)
    if remote.count(prior) != 1:
        raise RuntimeError("Reviewed v3 start gate changed.")
    remote = remote.replace(prior, required, 1)
    # The diagnostic observer is never used for admission in v4.  Its retained
    # read-only rendering must tolerate the known, exact v3 task receipt.
    remote = remote.replace("$gate='v3-task-present';if(Get-ScheduledTask -TaskName '" + _TASK + "' -ErrorAction SilentlyContinue){throw 'GATE'}", "$gate='v4-task-present';if(Get-ScheduledTask -TaskName '" + _TASK + "' -ErrorAction SilentlyContinue){throw 'GATE'}")
    remote = remote.replace("'v3-task-present','ready'", "'v4-task-present','ready'")
    return remote


_REMOTE = _render_remote()


def _admit(root: Path):
    """Bind exact v3 failure and phase 14 before any v4 journal is written."""
    prior = v3._observer(root)
    current = v1._admit(root)
    if prior is None or current is None:
        return None
    config, descriptor, cli_hash, v3_record = prior
    if v3._run(config, descriptor, cli_hash, "status") != {"version": 1, "state": "failed"}:
        return None
    diagnosed = phase_diagnostic.status(root, {"host": "archlinux"})
    if diagnosed != {"state": "diagnosed", "phase": "owner-before", "replayAllowed": False,
                     "nativeActionAllowed": False}:
        return None
    c_config, c_descriptor, c_hash, generation, evidence = current
    if c_descriptor != descriptor or c_hash != cli_hash:
        return None
    if (v3_record.get("sourceSha") != relaunch._SOURCE
            or v3_record.get("guestGeneration") != generation
            or v3_record.get("evidenceSha256") != evidence):
        return None
    return c_config, c_descriptor, c_hash, generation, evidence


def _observer(root: Path):
    """Bind a completed v4 task without requiring its owner to remain alive."""
    record = _read(root)
    base_bound = v1._observer_bound(root)
    prior = v3._observer(root)
    diagnostic = phase_diagnostic._observer(root)
    if record is None or base_bound is None or prior is None or diagnostic is None:
        return None
    config, descriptor, cli_hash, v1_record = base_bound
    p_config, p_descriptor, p_hash, v3_record = prior
    d_config, d_descriptor, d_hash = diagnostic
    if (p_descriptor != descriptor or d_descriptor != descriptor
            or p_hash != cli_hash or d_hash != cli_hash):
        return None
    generation = {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]}
    evidence = hashlib.sha256(json.dumps(generation, sort_keys=True).encode()).hexdigest()
    phase = phase_diagnostic._run(config, descriptor, cli_hash, "status")
    if (v3._run(config, descriptor, cli_hash, "status") != {"version": 1, "state": "failed"}
            or phase != {"version": 1, "state": "finished", "exitCode": 14}):
        return None
    if (record.get("sourceSha") != relaunch._SOURCE
            or record.get("guestGeneration") != generation
            or record.get("evidenceSha256") != evidence
            or v1_record.get("sourceSha") != relaunch._SOURCE
            or v1_record.get("guestGeneration") != generation
            or v1_record.get("evidenceSha256") != evidence
            or v3_record.get("sourceSha") != relaunch._SOURCE
            or v3_record.get("guestGeneration") != generation
            or v3_record.get("evidenceSha256") != evidence):
        return None
    return config, descriptor, cli_hash, record


def _read(root: Path) -> dict[str, Any] | None:
    directory = root / _GROUP
    try:
        info = directory.lstat()
    except FileNotFoundError:
        return None
    if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise WindowsMsiOwnerRelaunchQuitV4Error("Unsafe v4 quit journal.")
    path = directory / (_CORRELATION + ".json")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        raw = stream.read()
    try:
        value = json.loads(raw)
    except (TypeError, ValueError) as error:
        raise WindowsMsiOwnerRelaunchQuitV4Error("Invalid v4 quit journal.") from error
    fields = {"version", "correlationId", "idempotencyKey", "requestSha256", "sourceSha", "guestGeneration", "evidenceSha256", "state"}
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 4096
            or not isinstance(value, dict) or set(value) != fields or value.get("version") != 1
            or value.get("correlationId") != _CORRELATION or value.get("idempotencyKey") != _CORRELATION
            or value.get("requestSha256") != _REQUEST_SHA256 or value.get("sourceSha") != relaunch._SOURCE
            or value.get("state") not in {"intent", "exited"}):
        raise WindowsMsiOwnerRelaunchQuitV4Error("Invalid v4 quit journal.")
    return value


def _write(root: Path, value: Mapping[str, Any], replace: bool = False) -> None:
    # Reuse the reviewed fsync/no-replay writer after temporarily binding the
    # v3 implementation to v4's independent journal constants is unsafe.
    # Keep a small local durable write with exclusive create instead.
    directory = root / _GROUP
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise WindowsMsiOwnerRelaunchQuitV4Error("Unsafe v4 quit journal.")
    path = directory / (_CORRELATION + ".json")
    lock = os.open(directory / ".lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        current = _read(root)
        if (current is not None) != replace or (replace and current.get("state") != "intent"):
            raise WindowsMsiOwnerRelaunchQuitV4Error("V4 intent changed.")
        temp = directory / (_CORRELATION + ".tmp")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write((json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n").encode())
                stream.flush(); os.fsync(stream.fileno())
            os.replace(temp, path)
            parent = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try: os.fsync(parent)
            finally: os.close(parent)
        finally:
            if temp.exists(): temp.unlink()
    finally:
        os.close(lock)


def _run(config: Any, descriptor: tuple[str, str, int, int, str], cli_hash: str, mode: str):
    _env, socket, pid, ticks, sid = descriptor
    raw = base._remote(config, _REMOTE, (socket, str(pid), str(ticks), sid, cli_hash, mode), None, 90)
    try: return json.loads(raw) if raw else None
    except (TypeError, ValueError): return None


def start(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(inputs, Mapping) or dict(inputs) != {"host": "archlinux"}:
        raise WindowsMsiOwnerRelaunchQuitV4Error("Exact CP117 host required.")
    try:
        root = Path(root).resolve(strict=True)
        if _read(root) is not None: return status(root, inputs)
        admitted = _admit(root)
        if admitted is None: return dict(_UNKNOWN)
        config, descriptor, cli_hash, generation, evidence = admitted
        _write(root, {"version": 1, "correlationId": _CORRELATION, "idempotencyKey": _CORRELATION,
                      "requestSha256": _REQUEST_SHA256, "sourceSha": relaunch._SOURCE,
                      "guestGeneration": generation, "evidenceSha256": evidence, "state": "intent"})
        return {"state": "submitted", "replayAllowed": False, "nativeActionAllowed": False} if _run(config, descriptor, cli_hash, "start") == {"version": 1, "state": "submitted"} else dict(_UNKNOWN)
    except (OSError, TypeError, ValueError, KeyError, base.WindowsMsiBasePrepareError, WindowsMsiOwnerRelaunchQuitV4Error):
        return dict(_UNKNOWN)


def status(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(inputs, Mapping) or dict(inputs) != {"host": "archlinux"}:
        raise WindowsMsiOwnerRelaunchQuitV4Error("Exact CP117 host required.")
    try:
        bound = _observer(Path(root).resolve(strict=True))
        if bound is None: return dict(_UNKNOWN)
        observed = _run(bound[0], bound[1], bound[2], "status")
        if observed == {"version": 1, "state": "pending"}: return {"state": "pending", "replayAllowed": False, "nativeActionAllowed": False}
        if observed != {"version": 1, "state": "exited"}: return dict(_UNKNOWN)
        record = bound[3]
        if record["state"] == "intent": done = dict(record); done["state"] = "exited"; _write(Path(root), done, True)
        return {"state": "exited", "runtimeRunning": False, "ownerExited": True, "replayAllowed": False, "nativeActionAllowed": False}
    except (OSError, TypeError, ValueError, KeyError, base.WindowsMsiBasePrepareError, WindowsMsiOwnerRelaunchQuitV4Error):
        return dict(_UNKNOWN)


def collect(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]: return status(root, inputs)


def diagnose(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(inputs, Mapping) or dict(inputs) != {"host": "archlinux"}:
        raise WindowsMsiOwnerRelaunchQuitV4Error("Exact CP117 host required.")
    try:
        bound = _observer(Path(root).resolve(strict=True))
        if bound is None: return dict(_UNKNOWN)
        observed = _run(bound[0], bound[1], bound[2], "diagnose")
        if not isinstance(observed, dict) or set(observed) != {"version", "phase", "task"}:
            return dict(_UNKNOWN)
        return {"state": "diagnosed", "phase": observed["phase"], "task": observed["task"], "replayAllowed": False, "nativeActionAllowed": False}
    except (OSError, TypeError, ValueError, KeyError, base.WindowsMsiBasePrepareError, WindowsMsiOwnerRelaunchQuitV4Error):
        return dict(_UNKNOWN)


def workflow(root: Path | str, action: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if action == "start": return start(root, inputs)
    if action in {"status", "collect"}: return status(root, inputs)
    if action == "diagnose": return diagnose(root, inputs)
    raise WindowsMsiOwnerRelaunchQuitV4Error("Unsupported v4 relaunch-quit action.")

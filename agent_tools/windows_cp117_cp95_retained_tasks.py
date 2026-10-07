"""Read-only proof for the five fixed CP95 tasks retained on CP117.

This is an inventory and terminal observer only.  It never starts, retries,
unregisters, or otherwise changes a task.  The historical acquire route's
ordinary status needs an active fixture campaign, which is deliberately not
used after that campaign is closed.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import re
import stat
import uuid
from pathlib import Path
from typing import Any, Mapping

try:  # Agent-tool modules are also imported by Windows-host test runners.
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - exercised through the public guard.
    _fcntl = None

from . import windows_fixture_python_acquire_transfer as acquire
from . import windows_fixture_python_guest_install as install
from . import windows_msi_base_prepare as base
from . import windows_cp117_lease as lease


class WindowsCp117Cp95RetainedTasksError(ValueError):
    pass


_ACQUIRES = (
    "194eb94d-8b90-485c-ab98-aa0c25ba4bf4",
    "26ced2bf-26bf-456a-92b1-f9234060da13",
    "7b721c91-3c3a-48d0-88eb-b7574e69bcfe",
    "f4930053-c596-4e89-aa3e-9dac87c3220b",
)
_PYTHON = "f4930053-c596-4e89-aa3e-9dac87c3220b"
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_UNKNOWN = {"state": "unknown", "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False}
_PROFILE_NAMES = tuple("acquire-" + item[:8] for item in _ACQUIRES) + ("python-f4930053",)


def _task_spec(profile: str, correlation: str, task: str, execute: str,
               arguments: str, sid: str) -> dict[str, str]:
    return {"profile": profile, "correlationId": correlation, "task": task,
            "actionSha256": hashlib.sha256((execute + "\0" + arguments).encode()).hexdigest(), "sid": sid}


def _acquire_spec(root: Path, correlation: str, descriptor: tuple[Any, ...]) -> dict[str, str] | None:
    record = acquire._read(root, correlation)
    dispatch = acquire._dispatch(root, correlation)
    if record is None or dispatch is None:
        return None
    request = record.get("request")
    if not isinstance(request, Mapping) or request.get("correlationId") != correlation:
        return None
    _env, _socket, _pid, _ticks, sid = descriptor
    try:
        command = acquire._command_for(dispatch, correlation, sid)
    except (KeyError, TypeError, ValueError, acquire.WindowsFixturePythonAcquireTransferError):
        return None
    digest = hashlib.sha256(command.encode()).hexdigest()
    if (not isinstance(dispatch.get("commandSha256"), str)
            or not _HASH.fullmatch(dispatch["commandSha256"])
            or dispatch["commandSha256"] != digest):
        return None
    return _task_spec("acquire-" + correlation[:8], correlation,
                      "VpnControlMcpCp95Acquire-" + correlation,
                      r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                      "-NoProfile -NonInteractive -EncodedCommand " + command, sid)


def _python_spec(root: Path, descriptor: tuple[Any, ...]) -> dict[str, str] | None:
    record = install._read_intent(root, _PYTHON)
    acquire_record = acquire._read(root, _PYTHON)
    if not isinstance(record, Mapping) or acquire_record is None:
        return None
    request = acquire_record.get("request")
    required = {"schemaVersion", "request", "socketPath", "qemuPid", "startTicks", "originalSid",
                "sourceFingerprint", "installerSha256", "installerSize", "commandSha256"}
    if (set(record) != required or record.get("schemaVersion") != 1 or record.get("request") != request
            or record.get("commandSha256") != hashlib.sha256(install._START_PS.encode()).hexdigest()
            or record.get("installerSha256") != install.SHA256 or record.get("installerSize") != install.SIZE_BYTES):
        return None
    env, socket, pid, ticks, sid = descriptor
    if (env != "windows-cp117" or (record.get("socketPath"), record.get("qemuPid"),
            record.get("startTicks"), record.get("originalSid")) != (socket, pid, ticks, sid)):
        return None
    paths = install._paths(_PYTHON)
    return _task_spec("python-f4930053", _PYTHON, paths["task"], paths["installer"],
                      "/quiet InstallAllUsers=0 PrependPath=0 Include_launcher=0 Include_pip=0 Include_test=0", sid)


def _configured_specs(root: Path, descriptor: tuple[Any, ...]) -> list[dict[str, str]] | None:
    if descriptor[0] != "windows-cp117":
        return None
    items = [_acquire_spec(root, correlation, descriptor) for correlation in _ACQUIRES]
    items.append(_python_spec(root, descriptor))
    if any(item is None for item in items):
        return None
    specs = [item for item in items if item is not None]
    if [item["profile"] for item in specs] != list(_PROFILE_NAMES):
        return None
    return specs


def _configuration_phase(root: Path, descriptor: tuple[Any, ...]) -> str:
    """Classify only local fixed-profile binding failures before QGA is used."""
    for correlation in _ACQUIRES:
        try:
            if acquire._read(root, correlation) is None:
                return "local-intent"
            if acquire._dispatch(root, correlation) is None:
                return "dispatch"
            if _acquire_spec(root, correlation, descriptor) is None:
                return "command"
        except (OSError, ValueError, TypeError, KeyError, acquire.WindowsFixturePythonAcquireTransferError):
            return "local-intent"
    try:
        if install._read_intent(root, _PYTHON) is None:
            return "python-intent"
        if _python_spec(root, descriptor) is None:
            return "descriptor"
    except (OSError, ValueError, TypeError, KeyError, install.WindowsFixturePythonGuestInstallError):
        return "python-intent"
    return "local-intent"


def _unknown_phase(phase: str) -> dict[str, Any]:
    return {**_UNKNOWN, "phase": phase}


def _observation_script(specs: list[dict[str, str]]) -> str:
    """Render no caller-controlled task names or commands into the PS5 read."""
    def literal(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"
    entries = ";".join("@{{profile={profile};corr={corr};task={task};action={action};sid={sid}}}".format(
        profile=literal(item["profile"]), corr=literal(item["correlationId"]), task=literal(item["task"]),
        action=literal(item["actionSha256"]), sid=literal(item["sid"]))
        for item in specs)
    return r'''$ErrorActionPreference='Stop'
try {
 $specs=@(@SPECS@);$out=@()
 $installers=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name -match '^(msiexec|consent)\.exe$'})
 $allPs=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name -match '^(powershell|pwsh)\.exe$' -and $_.ProcessId -ne $PID})
 $opaque=@($allPs|Where-Object {-not $_.CommandLine})
 foreach($s in $specs){
  $state='unknown';$result='unknown';$process='unknown'
  try{
   # Scheduled task arguments are normally UTF-16 encoded, so correlation
   # text is not reliably visible in CommandLine.  Any other PowerShell is
   # conservatively blocking; an opaque command line is unknown.
   $process=if($opaque.Count -ne 0){'unknown'}elseif($allPs.Count -eq 0){'absent'}else{'present'}
   $tasks=@(Get-ScheduledTask -TaskPath '\' -TaskName $s.task -ErrorAction Stop)
   if($tasks.Count -eq 0){$state='absent'}elseif($tasks.Count -ne 1){$state='mismatch'}else{
    $t=$tasks[0];$actions=@($t.Actions);$principal=$t.Principal
    $actualSid=if($principal.UserId -match '^S-1-'){([Security.Principal.SecurityIdentifier]::new($principal.UserId)).Value}else{([Security.Principal.NTAccount]::new($principal.UserId)).Translate([Security.Principal.SecurityIdentifier]).Value}
    $triggers=@($t.Triggers|Where-Object {$null -ne $_})
    $h=[Security.Cryptography.SHA256]::Create();try{$actualAction=([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($actions[0].Execute+[char]0+$actions[0].Arguments)))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}
    if($t.TaskPath -cne '\' -or $actions.Count -ne 1 -or $actualAction -cne $s.action -or $actualSid -cne $s.sid -or $principal.LogonType.ToString() -cne 'Interactive' -or $principal.RunLevel.ToString() -cne 'Limited' -or $triggers.Count -ne 0){$state='mismatch'}
    elseif($t.State.ToString() -in @('Running','Queued')){$state='running'}
    elseif($t.State.ToString() -ne 'Ready'){$state='mismatch'}
    else{$info=Get-ScheduledTaskInfo -TaskPath '\' -TaskName $s.task -ErrorAction Stop;$raw=$info.LastTaskResult;if($info.LastRunTime -eq [datetime]::MinValue -or $null -eq $raw){$state='ready-unproven'}else{$kind=[Convert]::GetTypeCode($raw);if($kind -notin @([TypeCode]::SByte,[TypeCode]::Int16,[TypeCode]::Int32,[TypeCode]::Int64,[TypeCode]::Byte,[TypeCode]::UInt16,[TypeCode]::UInt32,[TypeCode]::UInt64)){$state='unknown'}else{$code=[int64]$raw;if($code -lt 0){$code+=4294967296};if($code -eq 267009){$state='ready-unproven'}else{$state='terminal';$result=if($code -eq 0){'succeeded'}else{'failed'}}}}}
   }
  }catch{$state='unknown';$result='unknown';$process='unknown'}
  $out+=([pscustomobject]@{profile=$s.profile;state=$state;result=$result;correlatedProcess=$process})
 }
 [Console]::Out.WriteLine(([pscustomobject]@{version=1;profiles=$out;activeInstallerCount=$installers.Count;opaquePowerShellCount=$opaque.Count}|ConvertTo-Json -Depth 3 -Compress))
}catch{[Console]::Out.WriteLine('{"version":1,"profiles":[],"activeInstallerCount":-1,"opaquePowerShellCount":-1}');exit 1}
'''.replace("@SPECS@", entries)


def _observe_once(root: Path, config: Any, descriptor: tuple[Any, ...], specs: list[dict[str, str]]) -> dict[str, Any] | None:
    _env, socket, pid, ticks, _sid = descriptor
    encoded = base64.b64encode(_observation_script(specs).encode("utf-16le")).decode()
    if len(encoded) >= 30000:
        return None
    raw = base._remote(config, base._READINESS, (socket, str(pid), str(ticks), encoded), None, 30)
    try:
        outer = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None
    value = outer.get("inventory") if isinstance(outer, Mapping) and outer.get("state") == "observed" else None
    if not isinstance(value, Mapping) or set(value) != {"version", "profiles", "activeInstallerCount", "opaquePowerShellCount"} or value.get("version") != 1:
        return None
    profiles = value.get("profiles")
    allowed_states = {"absent", "mismatch", "running", "ready-unproven", "terminal", "unknown"}
    allowed_results = {"unknown", "succeeded", "failed"}
    if (not isinstance(profiles, list) or len(profiles) != len(_PROFILE_NAMES)
            or type(value.get("activeInstallerCount")) is not int or not 0 <= value["activeInstallerCount"] <= 16
            or type(value.get("opaquePowerShellCount")) is not int or not 0 <= value["opaquePowerShellCount"] <= 16):
        return None
    result: list[dict[str, str]] = []
    for expected, item in zip(_PROFILE_NAMES, profiles):
        if (not isinstance(item, Mapping) or set(item) != {"profile", "state", "result", "correlatedProcess"}
                or item.get("profile") != expected or item.get("state") not in allowed_states
                or item.get("result") not in allowed_results or item.get("correlatedProcess") not in {"absent", "present", "unknown"}
                or (item["state"] == "terminal") != (item["result"] in {"succeeded", "failed"})):
            return None
        result.append({"profile": item["profile"], "state": item["state"], "result": item["result"],
                       "correlatedProcess": item["correlatedProcess"]})
    return {"profiles": result, "activeInstallerCount": value["activeInstallerCount"],
            "opaquePowerShellCount": value["opaquePowerShellCount"]}


@contextlib.contextmanager
def _lease_read_lock(root: Path):
    """Hold a non-creating shared lease lock for one complete observation."""
    if _fcntl is None or not hasattr(os, "getuid"):
        raise OSError("Shared lease locking is unavailable on this host.")
    lock: int | None = None
    try:
        directory = root / lease._DIR
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink()
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
            raise OSError("Lease directory is unavailable.")
        lock = os.open(directory / ".environment.lock", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        lock_info = os.fstat(lock)
        if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != os.getuid()
                or stat.S_IMODE(lock_info.st_mode) != 0o600):
            raise OSError("Lease lock is unsafe.")
        _fcntl.flock(lock, _fcntl.LOCK_SH)
        yield directory
    finally:
        if lock is not None:
            os.close(lock)


def _no_active_lease(root: Path) -> bool:
    """Read only: unsupported lock APIs and missing journals never mean absent."""
    try:
        with _lease_read_lock(root) as directory:
            return lease._active(directory) is None
    except (OSError, ValueError, lease.Cp117LeaseError):
        return False


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Require two matching fresh, same-generation observations before ready."""
    if value != {}:
        raise WindowsCp117Cp95RetainedTasksError("CP95 retained-task observer takes no inputs.")
    path = Path(root).resolve(strict=True)
    if _fcntl is None or not hasattr(os, "getuid"):
        return _unknown_phase("platform")
    try:
        config, _target, descriptor = base._descriptor(path)
        with _lease_read_lock(path) as directory:
            if lease._active(directory) is not None:
                return _unknown_phase("active-lease")
            specs = _configured_specs(path, descriptor)
            if specs is None:
                return _unknown_phase(_configuration_phase(path, descriptor))
            first = _observe_once(path, config, descriptor, specs)
            _config_two, _target_two, descriptor_two = base._descriptor(path)
            if descriptor_two != descriptor:
                return _unknown_phase("generation")
            second = _observe_once(path, config, descriptor_two, specs)
            if lease._active(directory) is not None:
                return _unknown_phase("active-lease")
            if _configured_specs(path, descriptor_two) != specs:
                return _unknown_phase("recheck")
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError):
        return _unknown_phase("descriptor")
    if first is None or second is None:
        return _unknown_phase("qga")
    if first != second:
        return _unknown_phase("recheck")
    profiles = first["profiles"]
    safe = (first["activeInstallerCount"] == 0 and first["opaquePowerShellCount"] == 0 and all(
        item["state"] == "terminal" and item["correlatedProcess"] == "absent" for item in profiles))
    if not safe:
        return {**_UNKNOWN, "state": "blocked", "phase": "proof", "profiles": profiles,
                "activeInstallerCount": first["activeInstallerCount"],
                "opaquePowerShellCount": first["opaquePowerShellCount"]}
    return {"state": "ready", "profiles": profiles, "activeInstallerCount": 0, "opaquePowerShellCount": 0,
            "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}


def workflow(root: Path | str, action: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if action == "status":
        return status(root, inputs)
    raise WindowsCp117Cp95RetainedTasksError("Unknown CP95 retained-task action.")

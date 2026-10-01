"""Fixed third public quit attempt for CP117's reviewed relaunched owner.

The earlier quit journal is deliberately not reused: its QGA outcome is
unknown.  This module makes one separately named, time-limited task only after
the long-lived relaunch task is proved to be the exact expected task.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Mapping

from . import windows_msi_base_prepare as base
from . import windows_msi_owner_relaunch as relaunch
from . import windows_msi_owner_relaunch_quit as v1
from .windows_ps_bootstrap import REMOTE_ENCODER_SOURCE


class WindowsMsiOwnerRelaunchQuitV3Error(ValueError):
    pass


_CORRELATION = "38daf3a3-a661-495e-a001-b2b0bdaa9a66"
_GROUP = ".rag_index/windows-msi-owner-relaunch-quit-v3"
_TASK = "VpnControlCp117OwnerRelaunchQuitV3C32"
_V2_TASK = "VpnControlCp117OwnerRelaunchQuitV2C32"
_V1_TASK = v1._TASK
_STATUS_TASKS = ("VpnControlCp117OwnerPublicStatusC32",
                 "VpnControlCp117OwnerPublicStatusRetryC32",
                 "VpnControlCp117OwnerPublicStatusThirdC32")
_STATUS_TASKS_PS = "@(\"" + "\",\"".join(_STATUS_TASKS) + "\")"
_UNKNOWN = {"state": "unknown", "replayAllowed": False, "nativeActionAllowed": False}
_REQUEST = {"host": "archlinux", "correlationId": _CORRELATION,
            "sourceSha": relaunch._SOURCE, "taskName": _TASK,
            "operation": "public-quit-relaunched-owner-v3"}
_REQUEST_SHA256 = hashlib.sha256(json.dumps(_REQUEST, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# The reviewed v1 limited-user program performs the controller-bound public
# quit and independently proves that the owner pair and runtime have exited.
_TASK_PS = v1._TASK_PS


# This preflight observer has no task lifecycle cmdlets and no public CLI
# invocation.  It gives the first closed failure class for an already-durable
# unknown start intent without exposing account/process/command data.
_BOOTSTRAP_DIAGNOSTIC_PS = r'''$ErrorActionPreference='Stop';$gate='scheduler'
try {
 $sid='__SID__';$expectedArgs='__ARGS__';$expectedHash='__ARGS_SHA__';$account='VPNMSIX64\vpncp117';$psExe='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
 function Sid([string]$u){if($u -match '^S-1-'){return ([Security.Principal.SecurityIdentifier]::new($u)).Value};return ([Security.Principal.NTAccount]::new($u)).Translate([Security.Principal.SecurityIdentifier]).Value}
 function Hash([string]$v){return ([BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash([Text.Encoding]::UTF8.GetBytes($v)))).Replace('-','').ToLowerInvariant()}
 if((Get-Service -Name Schedule -ErrorAction Stop).Status.ToString() -cne 'Running'){throw 'GATE'}
 $gate='account-sid';if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18' -or (Sid $account) -cne $sid -or (Hash $expectedArgs) -cne $expectedHash){throw 'GATE'}
 $gate='status-task-present';foreach($x in __STATUS_TASKS_PS__){if(Get-ScheduledTask -TaskName $x -ErrorAction SilentlyContinue){throw 'GATE'}}
 $gate='prior-quit-task-present';foreach($x in @('__V1_TASK__','__V2_TASK__')){if(Get-ScheduledTask -TaskName $x -ErrorAction SilentlyContinue){throw 'GATE'}}
 $gate='relaunch-task';$r=Get-ScheduledTask -TaskName '__RELAUNCH_TASK__' -ErrorAction Stop;$ra=@($r.Actions)
 if($r.State.ToString() -cne 'Running' -or (Sid ([string]$r.Principal.UserId)) -cne $sid -or $r.Principal.LogonType.ToString() -cne 'Interactive' -or $r.Principal.RunLevel.ToString() -cne 'Limited' -or $ra.Count -ne 1 -or $ra[0].Execute -cne 'C:\Users\vpncp117\AppData\Local\vpn-control\vpn-control-cli.exe' -or $ra[0].Arguments -cne '--state-dir "C:\Users\vpncp117\AppData\Local\VpnControl\cp166\state" serve'){throw 'GATE'}
 $gate='v1-process';foreach($p0 in @(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name -ceq 'powershell.exe'})){try{$owner=Invoke-CimMethod -InputObject $p0 -MethodName GetOwnerSid -ErrorAction Stop;if($owner.ReturnValue -ne 0){throw 'GATE'};if($owner.Sid -cne $sid -or $p0.SessionId -ne 1){continue};if($p0.ExecutablePath -cne $psExe){throw 'GATE'};$cmd=[string]$p0.CommandLine;$quoted='"'+$psExe+'" '+$expectedArgs;$unquoted=$psExe+' '+$expectedArgs;if($cmd -ceq $quoted -or $cmd -ceq $unquoted){throw 'GATE'};if($cmd -match '(?i)(?:^| )-EncodedCommand(?: |$)'){throw 'GATE'}}catch{throw 'GATE'}}
 $gate='v3-task-present';if(Get-ScheduledTask -TaskName '__TASK__' -ErrorAction SilentlyContinue){throw 'GATE'}
 $gate='ready'
}catch{if($_.Exception.Message -ne 'GATE'){$gate='observer-unknown'}}
[Console]::Out.WriteLine((@{version=1;gate=$gate}|ConvertTo-Json -Compress))'''
_BOOTSTRAP_DIAGNOSTIC_PS = (_BOOTSTRAP_DIAGNOSTIC_PS
    .replace("__STATUS_TASKS_PS__", _STATUS_TASKS_PS)
    .replace("__V1_TASK__", _V1_TASK)
    .replace("__V2_TASK__", _V2_TASK)
    .replace("__RELAUNCH_TASK__", relaunch._TASK)
    .replace("__TASK__", _TASK))


_REMOTE = base._QGA + REMOTE_ENCODER_SOURCE + r'''import time,hashlib
sock,pid,ticks,sid,cli_hash,mode=sys.argv[1:]
TASK_NAME=__TASK__
V1_TASK=__V1_TASK__
V2_TASK=__V2_TASK__
STATUS_TASKS=__STATUS_TASKS__
STATUS_TASKS_PS=__STATUS_TASKS_PS__
RELAUNCH_TASK=__RELAUNCH_TASK__
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
def ps(value):return base64.b64encode(value.encode('utf-16le')).decode()
def execute(script):
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',compact_ps_bootstrap(script)],'capture-output':True}).get('pid')
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(160):
  seen=call(sock,'guest-exec-status',{'pid':child})
  if seen.get('exited') is True:break
  if seen.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 if seen.get('exitcode')!=0 or seen.get('out-truncated') is True or seen.get('err-truncated') is True:raise ValueError()
 raw=base64.b64decode(seen.get('out-data',''),validate=True);lines=[x for x in decode(raw).splitlines() if x.startswith('{') and x.endswith('}')]
 if len(lines)!=1:raise ValueError()
 return json.loads(lines[0])
try:
 if mode not in ('start','status','diagnose','bootstrap-diagnostic') or not live(sock,pid,ticks):raise ValueError()
 body=TASK_PS.replace('__SID__',sid).replace('__CLI_HASH__',cli_hash);args='-NoProfile -NonInteractive -EncodedCommand '+ps(body);digest=hashlib.sha256(args.encode()).hexdigest()
 if mode=='bootstrap-diagnostic':
  boot=BOOTSTRAP_DIAGNOSTIC_PS.replace('__SID__',sid).replace('__ARGS__',args).replace('__ARGS_SHA__',digest)
 elif mode=='start':
  boot="$ErrorActionPreference='Stop';$n='"+TASK_NAME+"';$sid='"+sid+"';$account='VPNMSIX64\\vpncp117';$psExe='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';$expectedArgs='"+args.replace("'","''")+"';$expectedHash='"+digest+"';function Sid([string]$u){if($u -match '^S-1-'){return ([Security.Principal.SecurityIdentifier]::new($u)).Value};return ([Security.Principal.NTAccount]::new($u)).Translate([Security.Principal.SecurityIdentifier]).Value};function Hash([string]$v){return ([BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash([Text.Encoding]::UTF8.GetBytes($v)))).Replace('-','').ToLowerInvariant()};$resolved=Sid $account;if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18' -or $resolved -cne $sid -or (Hash $expectedArgs) -cne $expectedHash){throw 'IDENTITY'};if((Get-Service -Name Schedule -ErrorAction Stop).Status.ToString() -cne 'Running'){throw 'SCHEDULER'};foreach($x in "+STATUS_TASKS_PS+"){if(Get-ScheduledTask -TaskName $x -ErrorAction SilentlyContinue){throw 'STATUS_TASK'}};foreach($x in @('"+V1_TASK+"','"+V2_TASK+"')){if(Get-ScheduledTask -TaskName $x -ErrorAction SilentlyContinue){throw 'PRIOR_QUIT_TASK'}};$r=Get-ScheduledTask -TaskName '"+RELAUNCH_TASK+"' -ErrorAction Stop;$ra=@($r.Actions);if($r.State.ToString() -cne 'Running' -or (Sid ([string]$r.Principal.UserId)) -cne $sid -or $r.Principal.LogonType.ToString() -cne 'Interactive' -or $r.Principal.RunLevel.ToString() -cne 'Limited' -or $ra.Count -ne 1 -or $ra[0].Execute -cne 'C:\\Users\\vpncp117\\AppData\\Local\\vpn-control\\vpn-control-cli.exe' -or $ra[0].Arguments -cne '--state-dir \"C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\cp166\\state\" serve'){throw 'RELAUNCH'};foreach($p0 in @(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name -ceq 'powershell.exe'})){try{$owner=Invoke-CimMethod -InputObject $p0 -MethodName GetOwnerSid -ErrorAction Stop;if($owner.ReturnValue -ne 0){throw 'PRIOR_QUIT_PROCESS_AMBIGUOUS'};if($owner.Sid -cne $sid -or $p0.SessionId -ne 1){continue};if($p0.ExecutablePath -cne $psExe){throw 'PRIOR_QUIT_PROCESS_AMBIGUOUS'};$cmd=[string]$p0.CommandLine;$quoted='\"'+$psExe+'\" '+$expectedArgs;$unquoted=$psExe+' '+$expectedArgs;if($cmd -ceq $quoted -or $cmd -ceq $unquoted){throw 'PRIOR_QUIT_PROCESS'};if($cmd -match '(?i)(?:^| )-EncodedCommand(?: |$)'){throw 'PRIOR_QUIT_PROCESS_AMBIGUOUS'}}catch{throw $_}};if(Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue){throw 'TASK'};$a=New-ScheduledTaskAction -Execute $psExe -Argument $expectedArgs;$p=New-ScheduledTaskPrincipal -UserId $account -LogonType Interactive -RunLevel Limited;$s=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries;Register-ScheduledTask -TaskName $n -Action $a -Principal $p -Settings $s|Out-Null;Start-ScheduledTask -TaskName $n;[Console]::Out.WriteLine('{\"version\":1,\"state\":\"submitted\"}')"
 elif mode=='status':
  boot="$ErrorActionPreference='Stop';$n='"+TASK_NAME+"';$sid='"+sid+"';$h='"+digest+"';function Sid([string]$u){if($u -match '^S-1-'){return ([Security.Principal.SecurityIdentifier]::new($u)).Value};return ([Security.Principal.NTAccount]::new($u)).Translate([Security.Principal.SecurityIdentifier]).Value};$t=Get-ScheduledTask -TaskName $n -ErrorAction Stop;$a=@($t.Actions);if((Sid ([string]$t.Principal.UserId)) -cne $sid -or $t.Principal.LogonType.ToString() -cne 'Interactive' -or $t.Principal.RunLevel.ToString() -cne 'Limited' -or $a.Count -ne 1 -or $a[0].Execute -cne 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' -or ([BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$a[0].Arguments)))).Replace('-','').ToLowerInvariant() -cne $h){throw 'TASK'};$i=Get-ScheduledTaskInfo -TaskName $n -ErrorAction Stop;if($i.LastRunTime -eq [datetime]::MinValue -or $t.State.ToString() -eq 'Running'){$v='pending'}elseif($i.LastTaskResult -eq 0){$v='exited'}else{$v='failed'};[Console]::Out.WriteLine((@{version=1;state=$v}|ConvertTo-Json -Compress))"
 else:
  boot="$ErrorActionPreference='Stop';$phase='system';try{if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18'){throw 'SYSTEM'};$phase='tasks';$v='absent';if(Get-ScheduledTask -TaskName '"+TASK_NAME+"' -ErrorAction SilentlyContinue){$v='present'};[Console]::Out.WriteLine((@{version=1;phase=$phase;task=$v}|ConvertTo-Json -Compress))}catch{[Console]::Out.WriteLine((@{version=1;phase=$phase;task='ambiguous'}|ConvertTo-Json -Compress))}"
 value=execute(boot)
 allowed={'submitted'} if mode=='start' else ({'pending','exited','failed'} if mode=='status' else None)
 if mode=='diagnose':
  if not isinstance(value,dict) or set(value)!={'version','phase','task'} or value.get('version')!=1 or value.get('phase') not in {'system','tasks'} or value.get('task') not in {'absent','present','ambiguous'}:raise ValueError()
 elif mode=='bootstrap-diagnostic':
  if not isinstance(value,dict) or set(value)!={'version','gate'} or value.get('version')!=1 or value.get('gate') not in {'scheduler','account-sid','status-task-present','prior-quit-task-present','relaunch-task','v1-process','v3-task-present','ready','observer-unknown'}:raise ValueError()
 elif not isinstance(value,dict) or set(value)!={'version','state'} or value.get('version')!=1 or value.get('state') not in allowed:raise ValueError()
 out(value)
except Exception:out({'version':1,'phase':'system','task':'ambiguous'} if mode=='diagnose' else ({'version':1,'gate':'observer-unknown'} if mode=='bootstrap-diagnostic' else {'version':1,'state':'unknown'}))
'''.replace('TASK_PS', repr(_TASK_PS)).replace('BOOTSTRAP_DIAGNOSTIC_PS', repr(_BOOTSTRAP_DIAGNOSTIC_PS)).replace('__TASK__', repr(_TASK)).replace('__V1_TASK__', repr(_V1_TASK)).replace('__V2_TASK__', repr(_V2_TASK)).replace('__STATUS_TASKS__', repr(list(_STATUS_TASKS))).replace('__STATUS_TASKS_PS__', repr(_STATUS_TASKS_PS)).replace('__RELAUNCH_TASK__', repr(relaunch._TASK))


def _directory(root: Path, create: bool) -> Path:
    path = root / _GROUP
    if create: path.mkdir(mode=0o700, parents=True, exist_ok=True)
    elif not path.exists(): raise FileNotFoundError(path)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise WindowsMsiOwnerRelaunchQuitV3Error("Unsafe v3 quit journal.")
    return path


def _path(root: Path, create: bool) -> Path:
    return _directory(root, create) / (_CORRELATION + ".json")


def _read(root: Path) -> dict[str, Any] | None:
    try: path = _path(root, False)
    except FileNotFoundError: return None
    try: fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError: return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno()); raw = stream.read()
    needed = {"version", "correlationId", "idempotencyKey", "requestSha256", "sourceSha", "guestGeneration", "evidenceSha256", "state"}
    try: value = json.loads(raw)
    except (TypeError, ValueError) as error: raise WindowsMsiOwnerRelaunchQuitV3Error("Invalid v3 quit journal.") from error
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 4096 or not isinstance(value, dict) or set(value) != needed or value.get("version") != 1 or value.get("correlationId") != _CORRELATION or value.get("idempotencyKey") != _CORRELATION or value.get("requestSha256") != _REQUEST_SHA256 or value.get("sourceSha") != relaunch._SOURCE or value.get("state") not in {"intent", "exited"}):
        raise WindowsMsiOwnerRelaunchQuitV3Error("Invalid v3 quit journal.")
    return value


def _write(root: Path, value: Mapping[str, Any], replace: bool = False) -> None:
    directory = _directory(root, True); path = _path(root, True)
    lock = os.open(directory / ".lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX); current = _read(root)
        if (current is not None) != replace or (replace and current.get("state") != "intent"): raise WindowsMsiOwnerRelaunchQuitV3Error("V3 intent changed.")
        temporary = path.with_suffix(".tmp"); fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream: stream.write((json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n").encode()); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path); parent = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try: os.fsync(parent)
        finally: os.close(parent)
    finally: os.close(lock)


def _admit(root: Path):
    admitted = v1._admit(root)
    if admitted is None: return None
    config, descriptor, cli_hash, generation, evidence = admitted
    return config, descriptor, cli_hash, generation, evidence


def _observer(root: Path):
    record = _read(root); admitted = relaunch.liveness._admit(root); launch = relaunch._read_intent(root)
    if record is None or admitted is None or not isinstance(launch, dict): return None
    config, descriptor, source, cli_hash = admitted
    generation = {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]}
    evidence = hashlib.sha256(json.dumps(generation, sort_keys=True).encode()).hexdigest()
    if source != relaunch._SOURCE or launch.get("state") not in {"intent", "launched"} or launch.get("guestGeneration") != generation or launch.get("staleRecoveryEvidenceSha256") != evidence or record.get("guestGeneration") != generation or record.get("evidenceSha256") != evidence: return None
    return config, descriptor, cli_hash, record


def _bootstrap_observer(root: Path):
    """Bind a read-only retry diagnosis to this durable attempt and VM."""
    record = _read(root)
    if record is None or record.get("state") != "intent":
        return None
    admitted = _admit(root)
    if admitted is None:
        return None
    config, descriptor, cli_hash, generation, evidence = admitted
    if (record.get("sourceSha") != relaunch._SOURCE
            or record.get("guestGeneration") != generation
            or record.get("evidenceSha256") != evidence):
        return None
    return config, descriptor, cli_hash


def _run(config: Any, descriptor: tuple[str, str, int, int, str], cli_hash: str, mode: str):
    _env, socket, pid, ticks, sid = descriptor
    raw = base._remote(config, _REMOTE, (socket, str(pid), str(ticks), sid, cli_hash, mode), None, 90)
    try: return json.loads(raw) if raw else None
    except (TypeError, ValueError): return None


def start(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(inputs, Mapping) or dict(inputs) != {"host": "archlinux"}: raise WindowsMsiOwnerRelaunchQuitV3Error("Exact CP117 host required.")
    try:
        root = Path(root).resolve(strict=True)
        if _read(root) is not None: return status(root, inputs)
        admitted = _admit(root)
        if admitted is None: return dict(_UNKNOWN)
        config, descriptor, cli_hash, generation, evidence = admitted
        _write(root, {"version": 1, "correlationId": _CORRELATION, "idempotencyKey": _CORRELATION, "requestSha256": _REQUEST_SHA256, "sourceSha": relaunch._SOURCE, "guestGeneration": generation, "evidenceSha256": evidence, "state": "intent"})
        return {"state": "submitted", "replayAllowed": False, "nativeActionAllowed": False} if _run(config, descriptor, cli_hash, "start") == {"version": 1, "state": "submitted"} else dict(_UNKNOWN)
    except (OSError, TypeError, ValueError, KeyError, base.WindowsMsiBasePrepareError, WindowsMsiOwnerRelaunchQuitV3Error): return dict(_UNKNOWN)


def status(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(inputs, Mapping) or dict(inputs) != {"host": "archlinux"}: raise WindowsMsiOwnerRelaunchQuitV3Error("Exact CP117 host required.")
    try:
        root = Path(root).resolve(strict=True); bound = _observer(root)
        if bound is None: return dict(_UNKNOWN)
        config, descriptor, cli_hash, record = bound; observed = _run(config, descriptor, cli_hash, "status")
        if observed == {"version": 1, "state": "pending"}: return {"state": "pending", "replayAllowed": False, "nativeActionAllowed": False}
        if observed != {"version": 1, "state": "exited"}: return dict(_UNKNOWN)
        if record["state"] == "intent": done = dict(record); done["state"] = "exited"; _write(root, done, True)
        return {"state": "exited", "runtimeRunning": False, "ownerExited": True, "replayAllowed": False, "nativeActionAllowed": False}
    except (OSError, TypeError, ValueError, KeyError, base.WindowsMsiBasePrepareError, WindowsMsiOwnerRelaunchQuitV3Error): return dict(_UNKNOWN)


def collect(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]: return status(root, inputs)


def task_result(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Read the bound v3 task outcome without inferring or replaying its effect."""
    if not isinstance(inputs, Mapping) or dict(inputs) != {"host": "archlinux"}:
        raise WindowsMsiOwnerRelaunchQuitV3Error("Exact CP117 host required.")
    try:
        bound = _observer(Path(root).resolve(strict=True))
        if bound is None:
            return dict(_UNKNOWN)
        observed = _run(bound[0], bound[1], bound[2], "status")
        if observed == {"version": 1, "state": "pending"}:
            return {"state": "pending", "replayAllowed": False, "nativeActionAllowed": False}
        if observed == {"version": 1, "state": "exited"}:
            return {"state": "exited", "replayAllowed": False, "nativeActionAllowed": False}
        if observed == {"version": 1, "state": "failed"}:
            return {"state": "failed", "replayAllowed": False, "nativeActionAllowed": False}
        return dict(_UNKNOWN)
    except (OSError, TypeError, ValueError, KeyError, base.WindowsMsiBasePrepareError,
            WindowsMsiOwnerRelaunchQuitV3Error):
        return dict(_UNKNOWN)


def diagnose(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(inputs, Mapping) or dict(inputs) != {"host": "archlinux"}: raise WindowsMsiOwnerRelaunchQuitV3Error("Exact CP117 host required.")
    try:
        bound = _observer(Path(root).resolve(strict=True))
        if bound is None: return dict(_UNKNOWN)
        observed = _run(bound[0], bound[1], bound[2], "diagnose")
        if not isinstance(observed, dict) or set(observed) != {"version", "phase", "task"} or observed.get("version") != 1 or observed.get("phase") not in {"system", "tasks"} or observed.get("task") not in {"absent", "present", "ambiguous"}: return dict(_UNKNOWN)
        return {"state": "diagnosed", "phase": observed["phase"], "task": observed["task"], "replayAllowed": False, "nativeActionAllowed": False}
    except (OSError, TypeError, ValueError, KeyError, base.WindowsMsiBasePrepareError, WindowsMsiOwnerRelaunchQuitV3Error): return dict(_UNKNOWN)


def bootstrap_diagnostic(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Read each original start gate after an unknown durable submission."""
    if not isinstance(inputs, Mapping) or dict(inputs) != {"host": "archlinux"}:
        raise WindowsMsiOwnerRelaunchQuitV3Error("Exact CP117 host required.")
    try:
        bound = _bootstrap_observer(Path(root).resolve(strict=True))
        if bound is None:
            return dict(_UNKNOWN)
        observed = _run(*bound, "bootstrap-diagnostic")
        gates = {"scheduler", "account-sid", "status-task-present", "prior-quit-task-present",
                 "relaunch-task", "v1-process", "v3-task-present", "ready", "observer-unknown"}
        if (not isinstance(observed, dict) or set(observed) != {"version", "gate"}
                or observed.get("version") != 1 or observed.get("gate") not in gates):
            return dict(_UNKNOWN)
        if observed["gate"] == "observer-unknown":
            return dict(_UNKNOWN)
        return {"state": "diagnosed", "gate": observed["gate"], "replayAllowed": False,
                "nativeActionAllowed": False}
    except (OSError, TypeError, ValueError, KeyError, base.WindowsMsiBasePrepareError,
            WindowsMsiOwnerRelaunchQuitV3Error):
        return dict(_UNKNOWN)


def workflow(root: Path | str, action: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if action == "start": return start(root, inputs)
    if action in {"status", "collect"}: return status(root, inputs)
    if action == "task-result": return task_result(root, inputs)
    if action == "diagnose": return diagnose(root, inputs)
    if action == "bootstrap-diagnostic": return bootstrap_diagnostic(root, inputs)
    raise WindowsMsiOwnerRelaunchQuitV3Error("Unsupported v3 relaunch-quit action.")

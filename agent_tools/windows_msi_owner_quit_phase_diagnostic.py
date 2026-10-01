"""One-shot, read-only phase diagnosis for CP117's failed v3 owner quit.

The v3 quit is deliberately never retried here.  A separately named limited
user task repeats its admission checks and maps its first failure to a bounded
task exit code.  It invokes only the controller-bound public ``status`` read.
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
from . import windows_msi_owner_relaunch_quit as v1
from . import windows_msi_owner_relaunch_quit_v3 as v3
from . import windows_msi_owner_relaunch as relaunch
from .windows_ps_bootstrap import REMOTE_ENCODER_SOURCE


class WindowsMsiOwnerQuitPhaseDiagnosticError(ValueError):
    pass


_CORRELATION = "7c35c962-3fd3-42ce-914f-05f6e4a48a42"
_GROUP = ".rag_index/windows-msi-owner-quit-phase-diagnostic"
_TASK = "VpnControlCp117OwnerQuitPhaseDiagnosticC32"
_UNKNOWN = {"state": "unknown", "replayAllowed": False, "nativeActionAllowed": False}
_REQUEST = {"host": "archlinux", "correlationId": _CORRELATION,
            "sourceSha": relaunch._SOURCE, "taskName": _TASK,
            "operation": "read-only-failed-v3-owner-quit-phase-diagnostic"}
_REQUEST_SHA256 = hashlib.sha256(json.dumps(_REQUEST, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
_EXIT_PHASES = {0: "passed", 11: "identity", 12: "ancestors", 13: "cli",
                14: "owner-before", 15: "endpoint", 16: "public-status",
                17: "public-result", 18: "owner-after", 19: "task-error"}


# This is intentionally similar to v1._TASK_PS but never contains the effect
# command.  Each catch boundary emits a fixed exit code; no endpoint contents,
# process data, account names, or public reply are printed or persisted.
_TASK_PS = r'''$ErrorActionPreference='Stop';$phase=19
try {
 $sid='__SID__';$expected='__CLI_HASH__';$install='C:\Users\vpncp117\AppData\Local\vpn-control';$cli=Join-Path $install 'vpn-control-cli.exe';$state='C:\Users\vpncp117\AppData\Local\VpnControl\cp166\state';$endpoint=Join-Path $state 'activation.port'
 function D([string]$path){$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop;if(-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){throw 'BAD'}}
 function Owners {$all=@(Get-CimInstance Win32_Process -ErrorAction Stop);if(@($all|Where-Object {$_.Name -ceq 'vpn-control.exe'}).Count -ne 0){throw 'BAD'};if(@($all|Where-Object {$_.Name -in @('sing-box.exe','msiexec.exe','consent.exe')}).Count -ne 0){throw 'BAD'};$apps=@($all|Where-Object {$_.Name -ceq 'vpn-control-cli.exe'});if($apps.Count -ne 2){throw 'BAD'};$q=0;$u=0;$argument='--state-dir "'+$state+'" serve';$quoted='"'+$cli+'" '+$argument;$unquoted=$cli+' '+$argument;foreach($app in $apps){$owner=Invoke-CimMethod -InputObject $app -MethodName GetOwnerSid -ErrorAction Stop;if($owner.ReturnValue -ne 0 -or $owner.Sid -cne $sid -or $app.SessionId -ne 1 -or $app.ExecutablePath -cne $cli){throw 'BAD'};if($app.CommandLine -ceq $quoted){$q++}elseif($app.CommandLine -ceq $unquoted){$u++}else{throw 'BAD'}};if($q -ne 1 -or $u -ne 1){throw 'BAD'}}
 $phase=11;$identity=[Security.Principal.WindowsIdentity]::GetCurrent();$limited=-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);if($identity.User.Value -cne $sid -or (Get-Process -Id $PID).SessionId -ne 1 -or -not $limited){throw 'BAD'}
 $phase=12;foreach($path in @('C:\Users','C:\Users\vpncp117','C:\Users\vpncp117\AppData','C:\Users\vpncp117\AppData\Local',$install,'C:\Users\vpncp117\AppData\Local\VpnControl','C:\Users\vpncp117\AppData\Local\VpnControl\cp166',$state)){D $path}
 $phase=13;$file=Get-Item -LiteralPath $cli -Force -ErrorAction Stop;if($file.PSIsContainer -or (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or (Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expected){throw 'BAD'}
 $phase=14;Owners
 $phase=15;$leaf=Get-Item -LiteralPath $endpoint -Force -ErrorAction Stop;if($leaf.PSIsContainer -or (($leaf.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or $leaf.Length -lt 2 -or $leaf.Length -gt 4096){throw 'BAD'};$value=Get-Content -LiteralPath $endpoint -Raw -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop;if(($value.schemaVersion -isnot [int] -and $value.schemaVersion -isnot [long]) -or ($value.port -isnot [int] -and $value.port -isnot [long]) -or $value.controllerId -isnot [string] -or $value.token -isnot [string]){throw 'BAD'};$controller=$value.controllerId;$token=$value.token;if($value.schemaVersion -ne 1 -or $controller -notmatch '^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$' -or [guid]::Parse($controller).ToString() -cne $controller -or $value.port -lt 1 -or $value.port -gt 65535 -or $token -notmatch '^[A-Za-z0-9_-]{43}$'){throw 'BAD'}
 $phase=16;$raw=@(& $cli --state-dir $state --json --controller-id $controller --timeout-seconds 15 status 2>$null);if($LASTEXITCODE -ne 0 -or $raw.Count -ne 1 -or $raw[0] -isnot [string] -or $raw[0].Length -lt 2 -or $raw[0].Length -gt 8192){throw 'BAD'}
 $phase=17;$reply=ConvertFrom-Json -InputObject $raw[0] -ErrorAction Stop;if($reply.schemaVersion -ne 1 -or $reply.ok -ne $true -or $reply.final -ne $true -or $reply.code -cne 'OK' -or $reply.controllerId -cne $controller -or $reply.data.runtimeRunning -ne $false){throw 'BAD'}
 $phase=18;Owners
 exit 0
}catch{exit $phase}'''


_REMOTE = base._QGA + REMOTE_ENCODER_SOURCE + r'''import time,hashlib
sock,pid,ticks,sid,cli_hash,mode=sys.argv[1:]
TASK_NAME=__TASK__
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
 if mode not in ('start','status') or not live(sock,pid,ticks):raise ValueError()
 body=TASK_PS.replace('__SID__',sid).replace('__CLI_HASH__',cli_hash);args='-NoProfile -NonInteractive -EncodedCommand '+ps(body);digest=hashlib.sha256(args.encode()).hexdigest()
 if mode=='start':
  boot="$ErrorActionPreference='Stop';$n='"+TASK_NAME+"';$sid='"+sid+"';$account='VPNMSIX64\\vpncp117';function Sid([string]$u){if($u -match '^S-1-'){return ([Security.Principal.SecurityIdentifier]::new($u)).Value};return ([Security.Principal.NTAccount]::new($u)).Translate([Security.Principal.SecurityIdentifier]).Value};if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18' -or (Sid $account) -cne $sid){throw 'IDENTITY'};if((Get-Service -Name Schedule -ErrorAction Stop).Status.ToString() -cne 'Running'){throw 'SCHEDULER'};if(Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue){throw 'TASK'};$a=New-ScheduledTaskAction -Execute 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' -Argument '"+args.replace("'","''")+"';$p=New-ScheduledTaskPrincipal -UserId $account -LogonType Interactive -RunLevel Limited;$s=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries;Register-ScheduledTask -TaskName $n -Action $a -Principal $p -Settings $s|Out-Null;Start-ScheduledTask -TaskName $n;[Console]::Out.WriteLine('{\"version\":1,\"state\":\"submitted\"}')"
 else:
  boot="$ErrorActionPreference='Stop';$n='"+TASK_NAME+"';$sid='"+sid+"';$h='"+digest+"';function Sid([string]$u){if($u -match '^S-1-'){return ([Security.Principal.SecurityIdentifier]::new($u)).Value};return ([Security.Principal.NTAccount]::new($u)).Translate([Security.Principal.SecurityIdentifier]).Value};$t=Get-ScheduledTask -TaskName $n -ErrorAction Stop;$a=@($t.Actions);if((Sid ([string]$t.Principal.UserId)) -cne $sid -or $t.Principal.LogonType.ToString() -cne 'Interactive' -or $t.Principal.RunLevel.ToString() -cne 'Limited' -or $a.Count -ne 1 -or $a[0].Execute -cne 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' -or ([BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$a[0].Arguments)))).Replace('-','').ToLowerInvariant() -cne $h){throw 'TASK'};$i=Get-ScheduledTaskInfo -TaskName $n -ErrorAction Stop;if($i.LastRunTime -eq [datetime]::MinValue -or $t.State.ToString() -eq 'Running'){$v='pending';$e=0}elseif($i.LastTaskResult -eq 0){$v='finished';$e=0}else{$v='finished';$e=[int64]$i.LastTaskResult};[Console]::Out.WriteLine((@{version=1;state=$v;exitCode=$e}|ConvertTo-Json -Compress))"
 value=execute(boot)
 if mode=='start':
  if not isinstance(value,dict) or value!={'version':1,'state':'submitted'}:raise ValueError()
 else:
  if not isinstance(value,dict) or set(value)!={'version','state','exitCode'} or value.get('version')!=1 or value.get('state') not in {'pending','finished'} or type(value.get('exitCode')) is not int:raise ValueError()
 out(value)
except Exception:out({'version':1,'state':'unknown'})
'''.replace('TASK_PS', repr(_TASK_PS)).replace('__TASK__', repr(_TASK))


def _directory(root: Path, create: bool) -> Path:
    path = root / _GROUP
    if create: path.mkdir(mode=0o700, parents=True, exist_ok=True)
    elif not path.exists(): raise FileNotFoundError(path)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise WindowsMsiOwnerQuitPhaseDiagnosticError("Unsafe phase diagnostic journal.")
    return path


def _path(root: Path, create: bool) -> Path: return _directory(root, create) / (_CORRELATION + ".json")


def _read(root: Path) -> dict[str, Any] | None:
    try: path = _path(root, False)
    except FileNotFoundError: return None
    try: fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError: return None
    with os.fdopen(fd, "rb") as stream: info = os.fstat(stream.fileno()); raw = stream.read()
    try: value = json.loads(raw)
    except (TypeError, ValueError) as error: raise WindowsMsiOwnerQuitPhaseDiagnosticError("Invalid phase diagnostic journal.") from error
    fields = {"version", "correlationId", "idempotencyKey", "requestSha256", "sourceSha", "guestGeneration", "evidenceSha256", "state"}
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 4096 or not isinstance(value, dict) or set(value) != fields or value.get("version") != 1 or value.get("correlationId") != _CORRELATION or value.get("idempotencyKey") != _CORRELATION or value.get("requestSha256") != _REQUEST_SHA256 or value.get("sourceSha") != relaunch._SOURCE or value.get("state") != "intent"):
        raise WindowsMsiOwnerQuitPhaseDiagnosticError("Invalid phase diagnostic journal.")
    return value


def _write(root: Path, value: Mapping[str, Any]) -> None:
    directory = _directory(root, True); path = _path(root, True); lock = os.open(directory / ".lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if _read(root) is not None: raise WindowsMsiOwnerQuitPhaseDiagnosticError("Phase diagnosis already armed.")
        temp = path.with_suffix(".tmp"); fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream: stream.write((json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n").encode()); stream.flush(); os.fsync(stream.fileno())
        os.replace(temp, path); parent = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try: os.fsync(parent)
        finally: os.close(parent)
    finally: os.close(lock)


def _admit(root: Path):
    """Require the exact failed v3 task plus the current v1 owner admission."""
    prior = v3._observer(root)
    current = v1._admit(root)
    if prior is None or current is None: return None
    config, descriptor, cli_hash, record = prior
    if v3._run(config, descriptor, cli_hash, "status") != {"version": 1, "state": "failed"}: return None
    c_config, c_descriptor, c_hash, generation, evidence = current
    if c_descriptor != descriptor or c_hash != cli_hash: return None
    if (record.get("sourceSha") != relaunch._SOURCE or record.get("guestGeneration") != generation or record.get("evidenceSha256") != evidence): return None
    return c_config, c_descriptor, c_hash, generation, evidence


def _observer(root: Path):
    record = _read(root)
    prior = v3._observer(root)
    if record is None or prior is None: return None
    config, descriptor, cli_hash, prior_record = prior
    generation = {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]}
    evidence = hashlib.sha256(json.dumps(generation, sort_keys=True).encode()).hexdigest()
    if (prior_record.get("sourceSha") != relaunch._SOURCE or record.get("guestGeneration") != generation or record.get("evidenceSha256") != evidence): return None
    return config, descriptor, cli_hash


def _run(config: Any, descriptor: tuple[str, str, int, int, str], cli_hash: str, mode: str):
    _env, socket, pid, ticks, sid = descriptor
    raw = base._remote(config, _REMOTE, (socket, str(pid), str(ticks), sid, cli_hash, mode), None, 90)
    try: return json.loads(raw) if raw else None
    except (TypeError, ValueError): return None


def _project(observed: Any) -> dict[str, Any]:
    if observed == {"version": 1, "state": "pending", "exitCode": 0}: return {"state": "pending", "replayAllowed": False, "nativeActionAllowed": False}
    if not isinstance(observed, dict) or set(observed) != {"version", "state", "exitCode"} or observed.get("version") != 1 or observed.get("state") != "finished" or type(observed.get("exitCode")) is not int: return dict(_UNKNOWN)
    phase = _EXIT_PHASES.get(observed["exitCode"])
    if phase is None: return dict(_UNKNOWN)
    return {"state": "diagnosed", "phase": phase, "replayAllowed": False, "nativeActionAllowed": False}


def start(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(inputs, Mapping) or dict(inputs) != {"host": "archlinux"}: raise WindowsMsiOwnerQuitPhaseDiagnosticError("Exact CP117 host required.")
    try:
        root = Path(root).resolve(strict=True)
        if _read(root) is not None: return status(root, inputs)
        admitted = _admit(root)
        if admitted is None: return dict(_UNKNOWN)
        config, descriptor, cli_hash, generation, evidence = admitted
        _write(root, {"version": 1, "correlationId": _CORRELATION, "idempotencyKey": _CORRELATION, "requestSha256": _REQUEST_SHA256, "sourceSha": relaunch._SOURCE, "guestGeneration": generation, "evidenceSha256": evidence, "state": "intent"})
        return {"state": "submitted", "replayAllowed": False, "nativeActionAllowed": False} if _run(config, descriptor, cli_hash, "start") == {"version": 1, "state": "submitted"} else dict(_UNKNOWN)
    except (OSError, TypeError, ValueError, KeyError, base.WindowsMsiBasePrepareError, WindowsMsiOwnerQuitPhaseDiagnosticError): return dict(_UNKNOWN)


def status(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(inputs, Mapping) or dict(inputs) != {"host": "archlinux"}: raise WindowsMsiOwnerQuitPhaseDiagnosticError("Exact CP117 host required.")
    try:
        bound = _observer(Path(root).resolve(strict=True))
        return _project(_run(*bound, "status")) if bound is not None else dict(_UNKNOWN)
    except (OSError, TypeError, ValueError, KeyError, base.WindowsMsiBasePrepareError, WindowsMsiOwnerQuitPhaseDiagnosticError): return dict(_UNKNOWN)


def collect(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]: return status(root, inputs)


def workflow(root: Path | str, action: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if action == "start": return start(root, inputs)
    if action in {"status", "collect"}: return status(root, inputs)
    raise WindowsMsiOwnerQuitPhaseDiagnosticError("Unsupported owner quit phase diagnostic action.")

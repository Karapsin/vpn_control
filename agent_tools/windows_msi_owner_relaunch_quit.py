"""One-shot public quit for the fixed, relaunched CP117 CLI owner.

The only guest mutation is one limited-user scheduled task.  Its durable host
intent is written and fsynced before QGA receives the creation request.  A
lost QGA response is therefore permanently unknown; ``status`` and ``collect``
only observe the exact task and never submit a second quit.
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
from . import windows_msi_owner_public_status as public_status
from . import windows_msi_owner_relaunch as relaunch


class WindowsMsiOwnerRelaunchQuitError(ValueError):
    pass


_CORRELATION = "44ac1ea9-b18b-4203-9cef-9e38c5d45970"
_GROUP = ".rag_index/windows-msi-owner-relaunch-quit"
_TASK = "VpnControlCp117OwnerRelaunchQuitC32"
_UNKNOWN = {"state": "unknown", "replayAllowed": False, "nativeActionAllowed": False}
_REQUEST = {"host": "archlinux", "correlationId": _CORRELATION,
            "sourceSha": relaunch._SOURCE, "taskName": _TASK,
            "operation": "public-quit-relaunched-owner"}
_REQUEST_SHA256 = hashlib.sha256(json.dumps(_REQUEST, sort_keys=True,
                                            separators=(",", ":")).encode()).hexdigest()


# This program runs as the fixed original interactive user.  It validates the
# exact two-owner shape before issuing the public command.  The postcondition
# is deliberately bounded: the owner pair, GUI, runtime and endpoint must all
# be gone.  It never calls Stop-Process or any runtime control command.
_TASK_PS = r'''$ErrorActionPreference='Stop'
try {
 $sid='__SID__';$expected='__CLI_HASH__';$install='C:\Users\vpncp117\AppData\Local\vpn-control';$cli=Join-Path $install 'vpn-control-cli.exe';$state='C:\Users\vpncp117\AppData\Local\VpnControl\cp166\state';$endpoint=Join-Path $state 'activation.port'
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent();$limited=-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
 if($identity.User.Value -cne $sid -or (Get-Process -Id $PID).SessionId -ne 1 -or -not $limited){throw 'IDENTITY'}
 function D([string]$path){$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop;if(-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){throw 'ANCESTOR'}}
 function Owners {
  $all=@(Get-CimInstance Win32_Process -ErrorAction Stop)
  if(@($all|Where-Object {$_.Name -ceq 'vpn-control.exe'}).Count -ne 0){throw 'GUI'}
  if(@($all|Where-Object {$_.Name -in @('sing-box.exe','msiexec.exe','consent.exe')}).Count -ne 0){throw 'RUNTIME'}
  $apps=@($all|Where-Object {$_.Name -ceq 'vpn-control-cli.exe'});if($apps.Count -ne 2){throw 'OWNER'}
  $q=0;$u=0;$argument='--state-dir "'+$state+'" serve';$quoted='"'+$cli+'" '+$argument;$unquoted=$cli+' '+$argument
  foreach($app in $apps){$owner=Invoke-CimMethod -InputObject $app -MethodName GetOwnerSid -ErrorAction Stop;if($owner.ReturnValue -ne 0 -or $owner.Sid -cne $sid -or $app.SessionId -ne 1 -or $app.ExecutablePath -cne $cli){throw 'OWNER'};if($app.CommandLine -ceq $quoted){$q++}elseif($app.CommandLine -ceq $unquoted){$u++}else{throw 'OWNER'}}
  if($q -ne 1 -or $u -ne 1){throw 'OWNER'}
 }
 foreach($path in @('C:\Users','C:\Users\vpncp117','C:\Users\vpncp117\AppData','C:\Users\vpncp117\AppData\Local',$install,'C:\Users\vpncp117\AppData\Local\VpnControl','C:\Users\vpncp117\AppData\Local\VpnControl\cp166',$state)){D $path}
 $file=Get-Item -LiteralPath $cli -Force -ErrorAction Stop;if($file.PSIsContainer -or (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or (Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expected){throw 'CLI'}
 Owners
 $leaf=Get-Item -LiteralPath $endpoint -Force -ErrorAction Stop;if($leaf.PSIsContainer -or (($leaf.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or $leaf.Length -lt 2 -or $leaf.Length -gt 4096){throw 'ENDPOINT'}
 $value=Get-Content -LiteralPath $endpoint -Raw -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop
 if(($value.schemaVersion -isnot [int] -and $value.schemaVersion -isnot [long]) -or ($value.port -isnot [int] -and $value.port -isnot [long]) -or $value.controllerId -isnot [string] -or $value.token -isnot [string]){throw 'ENDPOINT'}
 $controller=$value.controllerId;$token=$value.token
 if($value.schemaVersion -ne 1 -or $controller -notmatch '^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$' -or [guid]::Parse($controller).ToString() -cne $controller -or $value.port -lt 1 -or $value.port -gt 65535 -or $token -notmatch '^[A-Za-z0-9_-]{43}$'){throw 'ENDPOINT'}
 $raw=@(& $cli --state-dir $state --json --controller-id $controller --timeout-seconds 15 quit 2>$null)
 if($LASTEXITCODE -ne 0 -or $raw.Count -ne 1 -or $raw[0] -isnot [string] -or $raw[0].Length -lt 2 -or $raw[0].Length -gt 8192){throw 'PUBLIC'}
 $reply=ConvertFrom-Json -InputObject $raw[0] -ErrorAction Stop
 if($reply.schemaVersion -ne 1 -or $reply.ok -ne $true -or $reply.final -ne $true -or $reply.code -cne 'OK' -or $reply.controllerId -cne $controller){throw 'RESULT'}
 for($i=0;$i -lt 80;$i++){
  Start-Sleep -Milliseconds 250;$all=@(Get-CimInstance Win32_Process -ErrorAction Stop)
  $apps=@($all|Where-Object {$_.Name -ceq 'vpn-control-cli.exe'});$gui=@($all|Where-Object {$_.Name -ceq 'vpn-control.exe'});$runtime=@($all|Where-Object {$_.Name -in @('sing-box.exe','msiexec.exe','consent.exe')})
  if($apps.Count -eq 0 -and $gui.Count -eq 0 -and $runtime.Count -eq 0 -and -not (Test-Path -LiteralPath $endpoint)){exit 0}
 }
 throw 'POST_EXIT'
}catch{exit 1}'''


_DIAGNOSE_PS = r'''$ErrorActionPreference='Stop';$phase='system'
try {
 $sid='__SID__';$name='__TASK__';$relaunch='VpnControlCp117OwnerRelaunchC32';$prior=@('VpnControlCp117OwnerPublicStatusC32','VpnControlCp117OwnerPublicStatusRetryC32','VpnControlCp117OwnerPublicStatusThirdC32')
 if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18'){throw 'SYSTEM'}
 $phase='tasks';$state='absent';if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){$state='present'}
 foreach($old in $prior){if(Get-ScheduledTask -TaskName $old -ErrorAction SilentlyContinue){$state='prior-present'}}
 $owner=Get-ScheduledTask -TaskName $relaunch -ErrorAction Stop;if($owner.State.ToString() -eq 'Running'){$state='owner-task-running'}
 [Console]::Out.WriteLine((@{version=1;phase=$phase;task=$state}|ConvertTo-Json -Compress))
}catch{[Console]::Out.WriteLine((@{version=1;phase=$phase;task='ambiguous'}|ConvertTo-Json -Compress))}'''


_REMOTE = base._QGA + r'''import time,hashlib
sock,pid,ticks,sid,cli_hash,mode=sys.argv[1:]
TASK_NAME='__TASK__'
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
def ps(value):return base64.b64encode(value.encode('utf-16le')).decode()
def execute(script):
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',ps(script)],'capture-output':True}).get('pid')
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(160):
  seen=call(sock,'guest-exec-status',{'pid':child})
  if seen.get('exited') is True:break
  if seen.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 if seen.get('exitcode')!=0 or seen.get('out-truncated') is True or seen.get('err-truncated') is True:raise ValueError()
 raw=base64.b64decode(seen.get('out-data',''),validate=True);lines=[line for line in decode(raw).splitlines() if line.startswith('{') and line.endswith('}')]
 if len(lines)!=1:raise ValueError()
 return json.loads(lines[0])
try:
 if mode not in ('start','status','diagnose') or not live(sock,pid,ticks):raise ValueError()
 body=TASK_PS.replace('__SID__',sid).replace('__CLI_HASH__',cli_hash);args='-NoProfile -NonInteractive -EncodedCommand '+ps(body);digest=hashlib.sha256(args.encode()).hexdigest()
 if mode=='diagnose':
  value=execute(DIAGNOSE_PS.replace('__SID__',sid).replace('__TASK__',TASK_NAME))
  if not isinstance(value,dict) or set(value)!={'version','phase','task'} or value.get('version')!=1 or value.get('phase') not in {'system','tasks'} or value.get('task') not in {'absent','present','prior-present','owner-task-running','ambiguous'}:raise ValueError()
  out(value);raise SystemExit
 if mode=='start':
  boot="$ErrorActionPreference='Stop';$n='"+TASK_NAME+"';$sid='"+sid+"';$account='VPNMSIX64\\vpncp117';$resolved=([Security.Principal.NTAccount]::new($account)).Translate([Security.Principal.SecurityIdentifier]).Value;if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18' -or $resolved -cne $sid){throw 'IDENTITY'};if((Get-Service -Name Schedule -ErrorAction Stop).Status.ToString() -cne 'Running'){throw 'SCHEDULER'};foreach($x in @('VpnControlCp117OwnerPublicStatusC32','VpnControlCp117OwnerPublicStatusRetryC32','VpnControlCp117OwnerPublicStatusThirdC32')){if(Get-ScheduledTask -TaskName $x -ErrorAction SilentlyContinue){throw 'PRIOR'}};$owner=Get-ScheduledTask -TaskName 'VpnControlCp117OwnerRelaunchC32' -ErrorAction Stop;if($owner.State.ToString() -eq 'Running'){throw 'OWNER_TASK'};if(Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue){throw 'TASK'};$a=New-ScheduledTaskAction -Execute 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' -Argument '"+args.replace("'","''")+"';$p=New-ScheduledTaskPrincipal -UserId $account -LogonType Interactive -RunLevel Limited;$s=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries;Register-ScheduledTask -TaskName $n -Action $a -Principal $p -Settings $s|Out-Null;Start-ScheduledTask -TaskName $n;[Console]::Out.WriteLine('{\"version\":1,\"state\":\"submitted\"}')"
 else:
  boot="$ErrorActionPreference='Stop';$n='"+TASK_NAME+"';$sid='"+sid+"';$h='"+digest+"';$t=Get-ScheduledTask -TaskName $n -ErrorAction Stop;$u=[string]$t.Principal.UserId;if($u -match '^S-1-'){$p=([Security.Principal.SecurityIdentifier]::new($u)).Value}else{$p=([Security.Principal.NTAccount]::new($u)).Translate([Security.Principal.SecurityIdentifier]).Value};$a=@($t.Actions);if($p -cne $sid -or $t.Principal.LogonType.ToString() -cne 'Interactive' -or $t.Principal.RunLevel.ToString() -cne 'Limited' -or $a.Count -ne 1 -or $a[0].Execute -cne 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' -or ([BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$a[0].Arguments)))).Replace('-','').ToLowerInvariant() -cne $h){throw 'TASK'};$i=Get-ScheduledTaskInfo -TaskName $n -ErrorAction Stop;if($i.LastRunTime -eq [datetime]::MinValue -or $t.State.ToString() -eq 'Running'){$r='pending'}elseif($i.LastTaskResult -eq 0){$r='exited'}else{$r='failed'};[Console]::Out.WriteLine((@{version=1;state=$r}|ConvertTo-Json -Compress))"
 value=execute(boot);allowed={'submitted'} if mode=='start' else {'pending','exited','failed'}
 if not isinstance(value,dict) or set(value)!={'version','state'} or value.get('version')!=1 or value.get('state') not in allowed:raise ValueError()
 out(value)
except SystemExit:pass
except Exception:
 out({'version':1,'state':'unknown'} if mode!='diagnose' else {'version':1,'phase':'system','task':'ambiguous'})
'''.replace('TASK_PS', repr(_TASK_PS)).replace('DIAGNOSE_PS', repr(_DIAGNOSE_PS)).replace('__TASK__', _TASK)


def _directory(root: Path, create: bool) -> Path:
    path = root / _GROUP
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    elif not path.exists():
        raise FileNotFoundError(path)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or path.is_symlink() or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise WindowsMsiOwnerRelaunchQuitError("Unsafe relaunch-quit journal.")
    return path


def _path(root: Path, create: bool) -> Path:
    return _directory(root, create) / (_CORRELATION + ".json")


def _read(root: Path) -> dict[str, Any] | None:
    try:
        path = _path(root, False)
    except FileNotFoundError:
        return None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 4096):
            raise WindowsMsiOwnerRelaunchQuitError("Unsafe relaunch-quit journal.")
        raw = stream.read()
    try:
        value = json.loads(raw)
    except (TypeError, ValueError) as error:
        raise WindowsMsiOwnerRelaunchQuitError("Invalid relaunch-quit journal.") from error
    required = {"version", "correlationId", "idempotencyKey", "requestSha256", "sourceSha",
                "guestGeneration", "evidenceSha256", "state"}
    if (not isinstance(value, dict) or set(value) != required or value.get("version") != 1
            or value.get("correlationId") != _CORRELATION or value.get("idempotencyKey") != _CORRELATION
            or value.get("requestSha256") != _REQUEST_SHA256 or value.get("sourceSha") != relaunch._SOURCE
            or value.get("state") not in {"intent", "exited"}):
        raise WindowsMsiOwnerRelaunchQuitError("Invalid relaunch-quit journal.")
    return value


def _write(root: Path, value: Mapping[str, Any], *, replace: bool = False) -> None:
    directory = _directory(root, True); path = _path(root, True)
    lock = os.open(directory / ".lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX); current = _read(root)
        if (current is not None) != replace or (replace and current.get("state") != "intent"):
            raise WindowsMsiOwnerRelaunchQuitError("Relaunch-quit intent changed.")
        temporary = path.with_suffix(".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write((json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n").encode())
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        os.close(lock)


def _admit(root: Path):
    admitted = relaunch._admit(root)
    launch = relaunch._read_intent(root)
    if admitted is None or not isinstance(launch, dict) or launch.get("state") not in {"intent", "launched"}:
        return None
    config, descriptor, cli_hash, evidence = admitted
    generation = {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]}
    if launch.get("guestGeneration") != generation or launch.get("staleRecoveryEvidenceSha256") != evidence:
        return None
    exact = {"state": "detailed", "baseOwners": "none", "quotedStateServe": "one",
             "unquotedStateServe": "one", "otherSubcommand": "none", "unrelated": "none",
             "ownerIdentity": "exact", "replayAllowed": False, "nativeActionAllowed": False}
    detail = relaunch.detail(root, {"host": "archlinux"})
    if not isinstance(detail, dict) or any(detail.get(key) != value for key, value in exact.items()):
        return None
    # QGA/SYSTEM cannot read the original user's private activation endpoint.
    # Its exact redaction is an admission fact; the limited interactive task
    # performs the non-reparse/content/schema check immediately before quit.
    if (detail.get("endpoint") != "invalid"
            or any(detail.get(key) != "ambiguous" for key in ("schemaVersion", "controllerId", "port", "token"))):
        return None
    live = relaunch.liveness.observe(root, {"host": "archlinux"})
    required = {"state": "blocked", "sourceSha": relaunch._SOURCE,
                "correlationId": relaunch.stale_lock._CORRELATION, "ownerProcesses": "many",
                "installerProcesses": "none", "consentProcesses": "none", "runtimeProcesses": "none",
                "stateLeaves": "both", "runtimeOff": True, "replayAllowed": False,
                "nativeActionAllowed": False}
    if live != required:
        return None
    return config, descriptor, cli_hash, generation, evidence


def _run(config: Any, descriptor: tuple[str, str, int, int, str], cli_hash: str, mode: str):
    _env, socket, pid, ticks, sid = descriptor
    raw = base._remote(config, _REMOTE, (socket, str(pid), str(ticks), sid, cli_hash, mode), None, 90)
    try:
        value = json.loads(raw) if raw else {}
    except (TypeError, ValueError):
        return None
    if not isinstance(value, dict) or value.get("version") != 1:
        return None
    return value


def _observer_bound(root: Path):
    """Bind the fixed task after quit without requiring its owner to remain alive.

    ``_admit`` is deliberately stricter and is used immediately before the
    effect.  Reusing it here would make a successful public quit impossible to
    prove because its two original owner processes are expected to have exited.
    """
    record = _read(root)
    admitted = relaunch.liveness._admit(root)
    launch = relaunch._read_intent(root)
    if record is None or admitted is None or not isinstance(launch, dict):
        return None
    config, descriptor, source, cli_hash = admitted
    if source != relaunch._SOURCE or not relaunch._SHA256.fullmatch(str(cli_hash)):
        return None
    generation = {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]}
    evidence = hashlib.sha256(json.dumps(generation, sort_keys=True).encode()).hexdigest()
    if (launch.get("state") not in {"intent", "launched"} or launch.get("sourceSha") != source
            or launch.get("guestGeneration") != generation
            or launch.get("staleRecoveryEvidenceSha256") != evidence
            or record.get("sourceSha") != source or record.get("guestGeneration") != generation
            or record.get("evidenceSha256") != evidence):
        return None
    return config, descriptor, cli_hash, record


def start(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(inputs, Mapping) or dict(inputs) != {"host": "archlinux"}:
        raise WindowsMsiOwnerRelaunchQuitError("Exact CP117 host required.")
    try:
        root = Path(root).resolve(strict=True)
        if _read(root) is not None:
            return status(root, inputs)
        admitted = _admit(root)
        if admitted is None:
            return dict(_UNKNOWN)
        config, descriptor, cli_hash, generation, evidence = admitted
        record = {"version": 1, "correlationId": _CORRELATION, "idempotencyKey": _CORRELATION,
                  "requestSha256": _REQUEST_SHA256, "sourceSha": relaunch._SOURCE,
                  "guestGeneration": generation, "evidenceSha256": evidence, "state": "intent"}
        _write(root, record)
        observed = _run(config, descriptor, cli_hash, "start")
        return {"state": "submitted", "replayAllowed": False, "nativeActionAllowed": False} if observed == {"version": 1, "state": "submitted"} else dict(_UNKNOWN)
    except (OSError, TypeError, ValueError, KeyError, base.WindowsMsiBasePrepareError,
            WindowsMsiOwnerRelaunchQuitError):
        return dict(_UNKNOWN)


def status(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(inputs, Mapping) or dict(inputs) != {"host": "archlinux"}:
        raise WindowsMsiOwnerRelaunchQuitError("Exact CP117 host required.")
    try:
        bound = _observer_bound(Path(root).resolve(strict=True))
        if bound is None:
            return dict(_UNKNOWN)
        config, descriptor, cli_hash, record = bound
        observed = _run(config, descriptor, cli_hash, "status")
        if observed == {"version": 1, "state": "pending"}:
            return {"state": "pending", "replayAllowed": False, "nativeActionAllowed": False}
        if observed != {"version": 1, "state": "exited"}:
            return dict(_UNKNOWN)
        if record["state"] == "intent":
            done = dict(record); done["state"] = "exited"; _write(Path(root).resolve(strict=True), done, replace=True)
        return {"state": "exited", "runtimeRunning": False, "ownerExited": True,
                "replayAllowed": False, "nativeActionAllowed": False}
    except (OSError, TypeError, ValueError, KeyError, base.WindowsMsiBasePrepareError,
            WindowsMsiOwnerRelaunchQuitError):
        return dict(_UNKNOWN)


def collect(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    return status(root, inputs)


def diagnose(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(inputs, Mapping) or dict(inputs) != {"host": "archlinux"}:
        raise WindowsMsiOwnerRelaunchQuitError("Exact CP117 host required.")
    try:
        bound = _observer_bound(Path(root).resolve(strict=True))
        if bound is None:
            return dict(_UNKNOWN)
        config, descriptor, cli_hash, _record = bound
        observed = _run(config, descriptor, cli_hash, "diagnose")
        if (not isinstance(observed, dict) or set(observed) != {"version", "phase", "task"}
                or observed.get("phase") not in {"system", "tasks"}
                or observed.get("task") not in {"absent", "present", "prior-present", "owner-task-running", "ambiguous"}):
            return dict(_UNKNOWN)
        return {"state": "diagnosed", "phase": observed["phase"], "task": observed["task"],
                "replayAllowed": False, "nativeActionAllowed": False}
    except (OSError, TypeError, ValueError, KeyError, base.WindowsMsiBasePrepareError,
            WindowsMsiOwnerRelaunchQuitError):
        return dict(_UNKNOWN)


def workflow(root: Path | str, action: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if action == "start": return start(root, inputs)
    if action in {"status", "collect"}: return status(root, inputs)
    if action == "diagnose": return diagnose(root, inputs)
    raise WindowsMsiOwnerRelaunchQuitError("Unsupported relaunch-quit action.")

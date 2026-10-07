"""One fixed, durable recovery for CP117's orphaned QEMU guest agent lock.

This module owns the fixed one-shot reservation, protected SYSTEM task, and
read-only recovery observations. It may restart only the exactly admitted guest
QEMU service; it never touches an application or VPN runtime.
"""
from __future__ import annotations

import hashlib
import gzip
import base64
import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from . import windows_cp117_staged_fixture_retire as retire
from . import windows_cp117_retirement_guards as guards
from . import windows_msi_base_prepare as base
from . import windows_cp117_protected_journal as journal


class WindowsCp117GuestAgentRecoveryError(ValueError):
    pass


_RECOVERY = "8dbecc32-6ad2-4e0b-a068-84a550fa850d"
_DIR = ".rag_index/windows-cp117-guest-agent-recovery"
_UNKNOWN = {"state": "unknown", "replayAllowed": False, "nativeActionAllowed": False,
            "productAction": False}

# QGA transports only a protected, finite task receipt.  The scheduled task is
# SYSTEM-owned and survives the qemu-ga stop that disconnects this wrapper.
_REMOTE_PS = base._QGA + r'''import base64,json,sys,time
sock,pid,ticks,encoded=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
phase='guest-exec'
try:
 if not live(sock,pid,ticks):raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-Command',encoded],'capture-output':True})['pid']
 phase='guest-status'
 for _ in range(80):
  item=call(sock,'guest-exec-status',{'pid':child})
  if item.get('exited') is True:break
  if item.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 phase='powershell-terminal'
 if item.get('exitcode')!=0 or item.get('out-truncated',False) is not False or item.get('err-truncated',False) is not False:raise ValueError()
 phase='json-shape'
 value=json.loads(decode(base64.b64decode(item.get('out-data',''),validate=True)))
 if not isinstance(value,dict):raise ValueError()
 out({'state':'observed','receipt':value})
except Exception:out({'state':'diagnosed','phase':phase})
'''


def _run_ps(config: Any, descriptor: tuple[Any, ...], script: str) -> Mapping[str, Any] | None:
    try:
        encoded = _launcher(script)
        if len(encoded) > 28000:
            return {"_phase": "oversize"}
        raw = base._remote(config, _REMOTE_PS, (str(descriptor[1]), str(descriptor[2]), str(descriptor[3]), encoded), None, 60)
        value = json.loads(raw) if raw is not None else None
        if isinstance(value, dict) and value.get("state") == "observed" and isinstance(value.get("receipt"), dict):
            return value["receipt"]
        if isinstance(value, dict) and value.get("state") == "diagnosed" and value.get("phase") in {"guest-exec", "guest-status", "powershell-terminal", "json-shape"}:
            return {"_phase": value["phase"]}
        return None
    except (OSError, ValueError, TypeError, base.WindowsMsiBasePrepareError):
        return None


def _service_census_script() -> str:
    return r'''$ErrorActionPreference='Stop';$s=@(Get-CimInstance Win32_Service -Filter "Name = 'qemu-ga'" -ErrorAction Stop);if($s.Count -ne 1){throw 'SERVICE'};$p=Get-CimInstance Win32_Process -Filter ('ProcessId = '+[string]$s[0].ProcessId) -ErrorAction Stop;$other=@(Get-Process powershell -ErrorAction SilentlyContinue|Where-Object {$_.Id -ne $PID});$apps=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name -match '^(vpn-control|vpn-control-cli|msiexec|consent|sing-box)\.exe$'});$tasks=@(Get-ScheduledTask -ErrorAction Stop|Where-Object {$_.TaskName -match '^VpnControlMcpFixture(Server|Update)'});[Console]::Out.WriteLine((@{name=$s[0].Name;state=$s[0].State;startName=$s[0].StartName;pid=[int]$s[0].ProcessId;startTicks=[int64]$p.CreationDate.ToFileTimeUtc();path=$p.ExecutablePath;otherPowerShellCount=[int]$other.Count;appCount=[int]$apps.Count;taskCount=[int]$tasks.Count}|ConvertTo-Json -Compress))'''


def protected_journal_validator_powershell(correlation: str = _RECOVERY) -> str:
    """Use the shared exact protected directory/leaf authority."""
    return journal.powershell(r"C:\ProgramData\VpnControlCp117-guest-agent-"+correlation,
                              ("binding.json", "child.json", "terminal.json")) + "\nfunction AssertRecoveryJournal([bool]$create){if($create){Initialize-SecureJournal}else{[void](Assert-Root $JournalRoot)}}"


def _restart_task_body(identity: Mapping[str, Any], intent_sha256: str, correlation: str = _RECOVERY) -> str:
    """Task journals its identity before the service mutation and its outcome after."""
    source = protected_journal_validator_powershell(correlation) + r'''
AssertRecoveryJournal $false
$expected=@DIGEST@;$correlation=@CORR@;$taskName=@TASK@
$binding=Read-SecureJson 'binding.json'
if((($binding.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'actionSha256,intentSha256,recoveryCorrelationId,service' -or $binding.intentSha256 -cne $expected -or $binding.recoveryCorrelationId -cne $correlation){throw 'BINDING'}
$task=Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop
$actions=@($task.Actions);if($task.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or $task.Principal.LogonType.ToString() -cne 'ServiceAccount' -or $task.Principal.RunLevel.ToString() -cne 'Highest' -or $actions.Count -ne 1 -or $actions[0].Execute -cne 'powershell.exe'){throw 'TASK'}
$actionHash=([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::Unicode.GetBytes($actions[0].Arguments)))).Replace('-','').ToLowerInvariant()
if($actionHash -cne $binding.actionSha256){throw 'ACTION'}
$self=Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID) -ErrorAction Stop
Write-SecureJsonCreate 'child.json' (([ordered]@{recoveryCorrelationId=$correlation;binding=$expected;actionSha256=$actionHash;childPid=[int]$PID;childStartTicks=[int64]$self.CreationDate.ToFileTimeUtc()})|ConvertTo-Json -Compress)
$outcome='failed';$afterIdentity=$null
try {
 for($attempt=0;$attempt -lt 20;$attempt++){$other=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name -in @('powershell.exe','pwsh.exe') -and $_.ProcessId -ne $PID});if($other.Count -eq 0){break};Start-Sleep -Milliseconds 250}
 if($other.Count -ne 0){throw 'BUSY'}
 $apps=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name -match '^(vpn-control|vpn-control-cli|msiexec|consent|sing-box)\.exe$'})
 $fixtureTasks=@(Get-ScheduledTask -ErrorAction Stop|Where-Object {$_.TaskName -match '^VpnControlMcpFixture(Server|Update)'})
 if($apps.Count -ne 0 -or $fixtureTasks.Count -ne 0){throw 'BUSY'}
 $service=Get-CimInstance Win32_Service -Filter "Name = 'qemu-ga'" -ErrorAction Stop
 $process=Get-CimInstance Win32_Process -Filter ('ProcessId='+[string]$service.ProcessId) -ErrorAction Stop
 if($service.State -cne 'Running' -or $service.StartName -notin @('LocalSystem','NT AUTHORITY\SYSTEM') -or [int]$service.ProcessId -ne @PID@ -or [int64]$process.CreationDate.ToFileTimeUtc() -ne @TICKS@ -or $process.ExecutablePath -cne @PATH@ -or $process.Name -notmatch '^qemu-ga\.exe$'){throw 'IDENTITY'}
 Stop-Service -Name $service.Name -ErrorAction Stop
 Start-Service -Name $service.Name -ErrorAction Stop
 $after=Get-CimInstance Win32_Service -Filter "Name = 'qemu-ga'" -ErrorAction Stop
 $newProcess=Get-CimInstance Win32_Process -Filter ('ProcessId='+[string]$after.ProcessId) -ErrorAction Stop
 if($after.State -cne 'Running' -or $after.StartName -notin @('LocalSystem','NT AUTHORITY\SYSTEM') -or [int]$after.ProcessId -le 0 -or [int]$after.ProcessId -eq @PID@ -or [int64]$newProcess.CreationDate.ToFileTimeUtc() -le @TICKS@ -or $newProcess.ExecutablePath -cne @PATH@ -or $newProcess.Name -notmatch '^qemu-ga\.exe$'){throw 'RESTART'}
 $afterIdentity=[ordered]@{name=$after.Name;state=$after.State;startName=$after.StartName;pid=[int]$after.ProcessId;startTicks=[int64]$newProcess.CreationDate.ToFileTimeUtc();path=$newProcess.ExecutablePath}
 $outcome='restarted'
} catch {$outcome='failed'}
Write-SecureJsonCreate 'terminal.json' (([ordered]@{recoveryCorrelationId=$correlation;binding=$expected;actionSha256=$actionHash;childPid=[int]$PID;childStartTicks=[int64]$self.CreationDate.ToFileTimeUtc();outcome=$outcome;service=$afterIdentity})|ConvertTo-Json -Compress -Depth 4)
if($outcome -cne 'restarted'){exit 1}
'''
    return (source.replace('@DIGEST@', guards._ps_literal(intent_sha256))
            .replace('@CORR@', guards._ps_literal(correlation))
            .replace('@TASK@', guards._ps_literal('VpnControlCp117GuestAgentRecovery-' + correlation))
            .replace('@PID@', str(identity['pid'])).replace('@TICKS@', str(identity['startTicks']))
            .replace('@PATH@', guards._ps_literal(identity['path'])))


def _launcher(source: str) -> str:
    """Keep the real source intact in a deterministic compressed transport."""
    packed=base64.b64encode(gzip.compress(source.encode('utf-16le'),mtime=0)).decode()
    launcher=("$z=[Convert]::FromBase64String('"+packed+"');$i=[IO.MemoryStream]::new([byte[]]$z);$g=[IO.Compression.GzipStream]::new($i,[IO.Compression.CompressionMode]::Decompress);$o=[IO.MemoryStream]::new();$g.CopyTo($o);$g.Dispose();$i.Dispose();$s=[Text.Encoding]::Unicode.GetString($o.ToArray());$o.Dispose();&([scriptblock]::Create($s))")
    return launcher


def _encode_ps(source: str) -> str:
    encoded=base64.b64encode(_launcher(source).encode('utf-16le')).decode()
    if len(encoded)>30000:raise WindowsCp117GuestAgentRecoveryError('compressed task exceeds Windows transport bound')
    return encoded


def _task_arguments(identity: Mapping[str, Any], intent_sha256: str, correlation: str = _RECOVERY) -> str:
    return '-NoProfile -NonInteractive -Command "' + _launcher(_restart_task_body(identity,intent_sha256,correlation)) + '"'


def _action_sha(identity: Mapping[str, Any], intent_sha256: str, correlation: str = _RECOVERY) -> str:
    return hashlib.sha256(_task_arguments(identity,intent_sha256,correlation).encode('utf-16le')).hexdigest()


def _restart_task_script(identity: Mapping[str, Any], intent_sha256: str, correlation: str = _RECOVERY) -> str:
    task='VpnControlCp117GuestAgentRecovery-'+correlation
    arguments=_task_arguments(identity,intent_sha256,correlation)
    digest=_action_sha(identity,intent_sha256,correlation)
    binding={'recoveryCorrelationId':correlation,'intentSha256':intent_sha256,'actionSha256':digest,'service':identity}
    return protected_journal_validator_powershell(correlation) + r'''
AssertRecoveryJournal $true
if(@(Get-ChildItem -LiteralPath $JournalRoot -Force).Count -ne 0 -or (Get-ScheduledTask -TaskName @TASK@ -TaskPath '\' -ErrorAction SilentlyContinue)){throw 'REPLAY'}
Write-SecureJsonCreate 'binding.json' @BINDING@
$action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument @ARGUMENTS@
$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName @TASK@ -TaskPath '\' -Action $action -Principal $principal|Out-Null
Start-ScheduledTask -TaskName @TASK@ -TaskPath '\'
[Console]::Out.WriteLine((@{state='submitted';actionSha256=@HASH@}|ConvertTo-Json -Compress))
'''.replace('@TASK@',guards._ps_literal(task)).replace('@BINDING@',guards._ps_literal(json.dumps(binding,sort_keys=True,separators=(',',':')))).replace('@ARGUMENTS@',guards._ps_literal(arguments)).replace('@HASH@',guards._ps_literal(digest))


def _remote_status_script(correlation: str = _RECOVERY) -> str:
    return protected_journal_validator_powershell(correlation) + r'''
AssertRecoveryJournal $false
$binding=Read-SecureJson 'binding.json';$child=Read-SecureJson 'child.json';$terminal=Read-SecureJson 'terminal.json'
if((($binding.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'actionSha256,intentSha256,recoveryCorrelationId,service' -or (($child.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'actionSha256,binding,childPid,childStartTicks,recoveryCorrelationId' -or (($terminal.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'actionSha256,binding,childPid,childStartTicks,outcome,recoveryCorrelationId,service'){throw 'SCHEMA'}
if($binding.recoveryCorrelationId -cne @CORR@ -or $child.recoveryCorrelationId -cne @CORR@ -or $terminal.recoveryCorrelationId -cne @CORR@ -or $child.binding -cne $binding.intentSha256 -or $terminal.binding -cne $binding.intentSha256 -or $child.actionSha256 -cne $binding.actionSha256 -or $terminal.actionSha256 -cne $binding.actionSha256 -or $terminal.childPid -ne $child.childPid -or $terminal.childStartTicks -ne $child.childStartTicks -or $child.childPid -le 0 -or $child.childStartTicks -le 0){throw 'BINDING'}
$task=Get-ScheduledTask -TaskName @TASK@ -TaskPath '\' -ErrorAction Stop;$actions=@($task.Actions)
if($task.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or $task.Principal.LogonType.ToString() -cne 'ServiceAccount' -or $task.Principal.RunLevel.ToString() -cne 'Highest' -or $actions.Count -ne 1 -or $actions[0].Execute -cne 'powershell.exe' -or $task.State.ToString() -cne 'Ready'){throw 'TASK'}
$hash=([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::Unicode.GetBytes($actions[0].Arguments)))).Replace('-','').ToLowerInvariant()
if($hash -cne $binding.actionSha256){throw 'ACTION'}
$liveChild=@(Get-CimInstance Win32_Process -Filter ('ProcessId='+[string]$child.childPid) -ErrorAction Stop)
if($liveChild.Count -ne 0 -and [int64]$liveChild[0].CreationDate.ToFileTimeUtc() -eq $child.childStartTicks){throw 'CHILD_LIVE'}
$service=Get-CimInstance Win32_Service -Filter "Name = 'qemu-ga'" -ErrorAction Stop
$process=Get-CimInstance Win32_Process -Filter ('ProcessId='+[string]$service.ProcessId) -ErrorAction Stop
if($process.Name -notmatch '^qemu-ga\.exe$'){throw 'SERVICE'}
$identity=[ordered]@{name=$service.Name;state=$service.State;startName=$service.StartName;pid=[int]$service.ProcessId;startTicks=[int64]$process.CreationDate.ToFileTimeUtc();path=$process.ExecutablePath}
foreach($key in @('name','state','startName','pid','startTicks','path')){if($identity[$key] -cne $terminal.service.$key){throw 'SERVICE'}}
[Console]::Out.WriteLine((@{binding=$binding.intentSha256;terminalBinding=$terminal.binding;outcome=$terminal.outcome;taskSystem=$true;taskState='Ready';actionSha256=$hash;service=$identity;recoveryCorrelationId=@CORR@;childPid=[int]$child.childPid;childStartTicks=[int64]$child.childStartTicks}|ConvertTo-Json -Compress -Depth 4))
'''.replace('@CORR@',guards._ps_literal(correlation)).replace('@TASK@',guards._ps_literal('VpnControlCp117GuestAgentRecovery-'+correlation))

def _directory(root: Path) -> Path:
    return guards.secure_directory(root / _DIR)


def _intent_path(root: Path) -> Path:
    return _directory(root) / "intent.json"


def _terminal_path(root: Path) -> Path:
    return _directory(root) / "terminal.json"


def _identity(service: Mapping[str, Any]) -> dict[str, Any] | None:
    """Accept only one fresh LocalSystem qemu-ga identity without raw values."""
    required = {"name", "state", "startName", "pid", "startTicks", "path"}
    if not isinstance(service, Mapping) or set(service) != required:
        return None
    if (not isinstance(service["name"], str) or service["name"].casefold() != "qemu-ga" or service["state"] != "Running"
            or service["startName"] not in {"LocalSystem", r"NT AUTHORITY\SYSTEM"}
            or type(service["pid"]) is not int or service["pid"] <= 0
            or type(service["startTicks"]) is not int or service["startTicks"] <= 0
            or not isinstance(service["path"], str) or not service["path"]):
        return None
    return dict(service)


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _plan(root: Path) -> tuple[Any, tuple[Any, ...], dict[str, Any], dict[str, Any]] | None:
    config, _target, descriptor = base._descriptor(root)
    observed = _run_ps(config, descriptor, _service_census_script())
    fields={"name","state","startName","pid","startTicks","path"}
    if (not isinstance(observed, dict) or set(observed) != fields | {"otherPowerShellCount","appCount","taskCount"}
            or any(type(observed[key]) is not int or observed[key] != 0 for key in ("otherPowerShellCount","appCount","taskCount"))):
        return None
    identity=_identity({key:observed[key] for key in fields})
    if identity is None:return None
    intent={"recoveryCorrelationId":_RECOVERY,"service":identity,
            "guestGeneration":{"socketPath":descriptor[1],"qemuPid":descriptor[2],"startTicks":descriptor[3]}}
    return config,descriptor,identity,intent


def _sources(identity: Mapping[str, Any], intent: Mapping[str, Any], correlation: str = _RECOVERY) -> dict[str,str]:
    digest=_digest(intent)
    return {"validator":protected_journal_validator_powershell(correlation),"census":_service_census_script(),
            "task":_restart_task_body(identity,digest,correlation),"submit":_restart_task_script(identity,digest,correlation),
            "status":_remote_status_script(correlation)}


def _parse_results(config: Any, descriptor: tuple[Any,...], identity: Mapping[str,Any], intent: Mapping[str,Any], correlation: str = _RECOVERY) -> dict[str,str]:
    results={}
    for name,source in _sources(identity,intent,correlation).items():
        packed=base64.b64encode(gzip.compress(source.encode('utf-16le'),mtime=0)).decode()
        program=("$z=[Convert]::FromBase64String('"+packed+"');$i=[IO.MemoryStream]::new([byte[]]$z);$g=[IO.Compression.GzipStream]::new($i,[IO.Compression.CompressionMode]::Decompress);$o=[IO.MemoryStream]::new();$g.CopyTo($o);$s=[Text.Encoding]::Unicode.GetString($o.ToArray());$tokens=$null;$errors=$null;[Management.Automation.Language.Parser]::ParseInput($s,[ref]$tokens,[ref]$errors)|Out-Null;[Console]::Out.WriteLine((@{valid=($errors.Count -eq 0)}|ConvertTo-Json -Compress));$g.Dispose();$i.Dispose();$o.Dispose()")
        try:
            observed = _run_ps(config,descriptor,program)
            results[name] = "valid" if observed == {"valid":True} else "invalid" if observed == {"valid":False} else observed["_phase"] if isinstance(observed,dict) and set(observed)=={"_phase"} else "transport"
        except WindowsCp117GuestAgentRecoveryError:
            results[name] = "oversize"
    return results


def _parse_sources(config:Any,descriptor:tuple[Any,...],identity:Mapping[str,Any],intent:Mapping[str,Any],correlation: str = _RECOVERY)->bool:
    return all(value == "valid" for value in _parse_results(config,descriptor,identity,intent,correlation).values())


def parser(root: Path | str, value: Mapping[str,Any]) -> dict[str,Any]:
    if value!={}:raise WindowsCp117GuestAgentRecoveryError('fixed recovery parser takes no inputs')
    try:
        plan=_plan(Path(root).resolve(strict=True))
        if plan is not None:
            scripts = _parse_results(*plan)
            return {**_UNKNOWN,"state":"passed" if all(value == "valid" for value in scripts.values()) else "diagnosed", "phase":"parser", "scripts":scripts, "recoveryCorrelationId":_RECOVERY}
    except (OSError,ValueError,KeyError,TypeError,base.WindowsMsiBasePrepareError):pass
    return {**_UNKNOWN,"state":"unknown","phase":"parser"}


def _journal_preflight(config: Any, descriptor: tuple[Any,...], correlation: str = _RECOVERY) -> bool:
    script=protected_journal_validator_powershell(correlation)+r'''
$parent=Split-Path -Parent $JournalRoot
if(-not (Test-Path -LiteralPath $parent -PathType Container)){throw 'PARENT'}
Assert-Ancestors $parent
if(Test-Path -LiteralPath $JournalRoot){[void](Assert-Root $JournalRoot);if(@(Get-ChildItem -LiteralPath $JournalRoot -Force).Count -ne 0){throw 'REPLAY'}}
if(Get-ScheduledTask -TaskName @TASK@ -TaskPath '\' -ErrorAction SilentlyContinue){throw 'REPLAY'}
[Console]::Out.WriteLine('{"ready":true}')
'''.replace('@TASK@',guards._ps_literal('VpnControlCp117GuestAgentRecovery-'+correlation))
    return _run_ps(config,descriptor,script)=={"ready":True}

def _ready(root: Path, tree: Mapping[str, Any], lock: Mapping[str, Any]) -> bool:
    """Require two independent idle observations before the service task exists."""
    admitted = retire._admitted(root)
    if admitted is None or not retire._recovery_fresh(root, admitted[0], admitted[2]):
        return False
    return (tree == {"state": "remaining-result-only"}
            and lock == {"cause": "low-hresult-32", "lockingProcess": "qemu-ga", "count": 1,
                         "qemuGaExactLocalSystem": True})


def preflight(root: Path | str, tree: Mapping[str, Any], lock_before: Mapping[str, Any] | None = None,
              lock_after: Mapping[str, Any] | None = None, service: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Read-only admission.  The caller obtains all observations independently."""
    path = Path(root).resolve(strict=True)
    if tree == {} and lock_before is None and lock_after is None and service is None:
        admitted = retire._admitted(path)
        if admitted is None:
            return {**_UNKNOWN, "state": "blocked", "phase": "binding"}
        if not retire._recovery_fresh(path, admitted[0], admitted[2]):
            return {**_UNKNOWN, "state": "blocked", "phase": "fresh"}
        tree_observation = retire.diagnose_tree(path, {})
        expected_tree = {"root": "present", "bundle": "absent", "content": "absent", "result": "present",
                         "serverState": "absent", "probeEvents": "absent", "unexpectedRootCount": 0,
                         "contentFileCount": 0, "probeEntryCount": 0, "otherPowerShellCount": 0}
        if (tree_observation.get("state") != "observed"
                or any(tree_observation.get(key) != expected for key, expected in expected_tree.items())):
            return {**_UNKNOWN, "state": "blocked", "phase": "tree"}
        lock_one, lock_two = retire.diagnose_locks(path, {}), retire.diagnose_locks(path, {})
        expected_lock = {"cause": "low-hresult-32", "lockingProcess": "qemu-ga", "count": 1,
                         "qemuGaExactLocalSystem": True}
        if (lock_one.get("state") != "observed" or lock_two.get("state") != "observed"
                or any(lock_one.get(key) != expected for key, expected in expected_lock.items())
                or any(lock_two.get(key) != expected for key, expected in expected_lock.items())):
            return {**_UNKNOWN, "state": "blocked", "phase": "lock"}
        plan = _plan(path)
        if plan is None:
            return {**_UNKNOWN, "state": "blocked", "phase": "census"}
        if not _journal_preflight(plan[0], plan[1]):
            return {**_UNKNOWN, "state": "blocked", "phase": "journal"}
        return {**_UNKNOWN, "state": "ready", "recoveryCorrelationId": _RECOVERY}
    if lock_before is None or lock_after is None or service is None:
        return {**_UNKNOWN, "state": "blocked"}
    if not (_ready(path, tree, lock_before) and lock_before == lock_after and _identity(service) is not None):
        return {**_UNKNOWN, "state": "blocked"}
    return {**_UNKNOWN, "state": "ready", "recoveryCorrelationId": _RECOVERY}


def start(root: Path | str, tree: Mapping[str, Any], lock_before: Mapping[str, Any] | None = None,
          lock_after: Mapping[str, Any] | None = None, service: Mapping[str, Any] | None = None,
          submit: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Reserve before the protected SYSTEM task is submitted; never replay it."""
    path = Path(root).resolve(strict=True)
    if tree == {} and lock_before is None and lock_after is None and service is None and submit is None:
        if preflight(path, {})["state"] != "ready":
            return {**_UNKNOWN, "state": "blocked"}
        plan = _plan(path)
        if plan is None:
            return dict(_UNKNOWN)
        config, descriptor, identity, intent = plan
        if not _parse_sources(config, descriptor, identity, intent):
            return {**_UNKNOWN, "state": "blocked", "phase": "parser"}
        if guards.secure_read(_intent_path(path)) is not None:
            return dict(_UNKNOWN)
        guards.secure_write_create(_intent_path(path), intent)
        action_hash = _action_sha(identity, _digest(intent))
        guards.secure_write_create(_directory(path) / "action.json", {"intentSha256": _digest(intent), "actionSha256": action_hash})
        remote = _run_ps(config, descriptor, _restart_task_script(identity, _digest(intent)))
        if not isinstance(remote, dict) or remote.get("state") != "submitted" or set(remote) != {"state", "actionSha256"} or remote.get("actionSha256") != action_hash:
            return dict(_UNKNOWN)
        # Bind the exact remote action fingerprint before any later status can
        # promote its terminal receipt.  A lost write leaves the action unknown.
        return {**_UNKNOWN, "state": "submitted", "recoveryCorrelationId": _RECOVERY}
    if lock_before is None or lock_after is None or service is None or submit is None:
        return {**_UNKNOWN, "state": "blocked"}
    terminal = guards.secure_read(_terminal_path(path))
    if terminal is not None:
        return {**_UNKNOWN, "state": "terminal"}
    if guards.secure_read(_intent_path(path)) is not None:
        return dict(_UNKNOWN)
    if preflight(path, tree, lock_before, lock_after, service)["state"] != "ready":
        return {**_UNKNOWN, "state": "blocked"}
    identity = _identity(service)
    assert identity is not None
    intent = {"recoveryCorrelationId": _RECOVERY, "service": identity,
              "tree": dict(tree), "lock": dict(lock_before)}
    guards.secure_write_create(_intent_path(path), intent)
    # The remote task must retain this exact bound identity before it stops its
    # own guest-agent transport.  A lost response remains unknown forever.
    result = submit({"recoveryCorrelationId": _RECOVERY, "service": identity,
                     "intentSha256": _digest(intent)})
    if not isinstance(result, Mapping) or result.get("state") != "submitted":
        return dict(_UNKNOWN)
    return {**_UNKNOWN, "state": "submitted", "recoveryCorrelationId": _RECOVERY}


def record_terminal(root: Path | str, intent_sha256: str, service: Mapping[str, Any], outcome: str) -> None:
    """Persist only a verified exact task terminal result, once."""
    path = Path(root).resolve(strict=True)
    intent = guards.secure_read(_intent_path(path))
    identity = _identity(service)
    if (not isinstance(intent, dict) or identity is None or _digest(intent) != intent_sha256
            or intent.get("service") != identity or outcome not in {"restarted", "failed"}):
        raise WindowsCp117GuestAgentRecoveryError("guest-agent terminal binding is invalid")
    guards.secure_write_create(_terminal_path(path), {"intentSha256": intent_sha256, "outcome": outcome})


def _restarted_identity(before: Mapping[str, Any], after: Any) -> bool:
    identity = _identity(after) if isinstance(after, Mapping) else None
    return (identity is not None and identity["pid"] != before["pid"]
            and identity["startTicks"] > before["startTicks"]
            and identity["path"] == before["path"])


def status(root: Path | str, value: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Public state deliberately carries no process, path, or task details."""
    path = Path(root).resolve(strict=True)
    if value not in (None, {}):
        raise WindowsCp117GuestAgentRecoveryError("fixed recovery status takes no inputs")
    terminal = guards.secure_read(_terminal_path(path))
    if value == {}:
        try:
            config, _target, descriptor = base._descriptor(path)
            observed = _run_ps(config, descriptor, _remote_status_script())
            intent = guards.secure_read(_intent_path(path))
            action = guards.secure_read(_directory(path) / "action.json")
            if (not isinstance(observed, dict) or not isinstance(intent, dict)
                    or not isinstance(action, dict) or set(action) != {"intentSha256", "actionSha256"}
                    or action["intentSha256"] != _digest(intent)
                    or action["actionSha256"] != _action_sha(intent["service"], _digest(intent))
                    or observed.get("actionSha256") != action["actionSha256"]
                    or observed.get("binding") != _digest(intent) or observed.get("terminalBinding") != _digest(intent)
                    or observed.get("outcome") != "restarted" or observed.get("taskSystem") is not True
                    or observed.get("taskState") != "Ready"
                    or not _restarted_identity(intent["service"], observed.get("service"))): return dict(_UNKNOWN)
            expected_fields = {"binding", "terminalBinding", "outcome", "taskSystem", "taskState", "actionSha256", "service", "recoveryCorrelationId", "childPid", "childStartTicks"}
            if (set(observed) != expected_fields or observed["recoveryCorrelationId"] != _RECOVERY
                    or type(observed["childPid"]) is not int or observed["childPid"] <= 0
                    or type(observed["childStartTicks"]) is not int or observed["childStartTicks"] <= 0
                    or intent.get("guestGeneration") != {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]}):
                return dict(_UNKNOWN)
            if terminal is None:
                record_terminal(path, _digest(intent), intent["service"], "restarted")
                terminal = guards.secure_read(_terminal_path(path))
            elif terminal != {"intentSha256": _digest(intent), "outcome": "restarted"}:
                return dict(_UNKNOWN)
        except (OSError, ValueError, KeyError, TypeError, base.WindowsMsiBasePrepareError): return dict(_UNKNOWN)
    if terminal is not None:
        return {**_UNKNOWN, "state": "terminal"}
    if guards.secure_read(_intent_path(path)) is not None:
        return {**_UNKNOWN, "state": "submitted"}
    return dict(_UNKNOWN)


def workflow(root:Path|str,action:str,value:Mapping[str,Any])->dict[str,Any]:
    if value != {}: raise WindowsCp117GuestAgentRecoveryError('fixed recovery takes no inputs')
    if action=='preflight':return preflight(root,value)
    if action=='parser':return parser(root,value)
    if action=='diagnose':return diagnose(root,value)
    if action=='journal':return diagnose_journal(root,value)
    if action=='start':return start(root,value)
    if action=='status':return status(root,value)
    raise WindowsCp117GuestAgentRecoveryError('unknown guest-agent recovery action')


def diagnose(root:Path|str,value:Mapping[str,Any])->dict[str,Any]:
    if value != {}:raise WindowsCp117GuestAgentRecoveryError('fixed recovery diagnostic takes no inputs')
    try:
        config,_target,descriptor=base._descriptor(Path(root).resolve(strict=True))
        observed=_run_ps(config,descriptor,_service_census_script())
        if isinstance(observed,dict) and set(observed)=={"_phase"}:
            return {**_UNKNOWN,"state":"diagnosed","phase":observed["_phase"]}
        fields={"name","state","startName","pid","startTicks","path"}
        if isinstance(observed,dict) and set(observed)==fields|{"otherPowerShellCount","appCount","taskCount"}:
            identity=_identity({key:observed[key] for key in fields})
            return {**_UNKNOWN,"state":"diagnosed","phase":"census-ready" if identity is not None else "service-identity"}
    except (OSError,ValueError,KeyError,TypeError,base.WindowsMsiBasePrepareError):pass
    return {**_UNKNOWN,"state":"diagnosed","phase":"transport"}


_JOURNAL_CODES = {"ready", "PARENT", "REPLAY", "ANCESTOR_REPARSE", "ROOT_TYPE", "ROOT_REPARSE", "ROOT_ACL_PROTECTED", "ROOT_OWNER", "ROOT_ACL_COUNT", "ROOT_ACL", "LEAF", "LEAF_TYPE", "LEAF_REPARSE", "LEAF_SIZE", "LEAF_OWNER", "LEAF_ACL_COUNT", "LEAF_ACL", "TREE", "runtime-error", "missing-binding", "missing-child", "missing-terminal", "reserved-complete", "ROOT_ABSENT", "identity-translation", "method-binding", "access-denied", "io-error"}

def _journal_diagnostic_script(reserved: bool) -> str:
    checks = ("if(-not(Test-Path -LiteralPath $JournalRoot)){" + journal.acl_construction_powershell() + ";throw 'ROOT_ABSENT'};[void](Assert-Root $JournalRoot);" +
              ";".join("if(-not(Test-Path -LiteralPath (Join-Path $JournalRoot '"+leaf+"'))){throw 'missing-"+name+"'};[void](Read-SecureJson '"+leaf+"')" for leaf,name in (("binding.json","binding"),("child.json","child"),("terminal.json","terminal"))) + ";$code='reserved-complete'" if reserved else
              "$parent=Split-Path -Parent $JournalRoot;if(-not(Test-Path -LiteralPath $parent -PathType Container)){throw 'PARENT'};Assert-Ancestors $parent;if(Test-Path -LiteralPath $JournalRoot){[void](Assert-Root $JournalRoot);if(@(Get-ChildItem -LiteralPath $JournalRoot -Force).Count -ne 0){throw 'REPLAY'}};$code='ready'")
    return protected_journal_validator_powershell()+"\ntry{"+checks+"}catch{$code=if($_.Exception.Message -cin @("+','.join(guards._ps_literal(x) for x in sorted(_JOURNAL_CODES))+") ){$_.Exception.Message}else{switch($_.Exception.GetBaseException().GetType().Name){'IdentityNotMappedException'{'identity-translation'} 'MethodException'{'method-binding'} 'UnauthorizedAccessException'{'access-denied'} 'IOException'{'io-error'} default{'runtime-error'}}}};[Console]::Out.WriteLine((@{guard=$code}|ConvertTo-Json -Compress))"


def diagnose_journal(root:Path|str,value:Mapping[str,Any])->dict[str,Any]:
    if value != {}:raise WindowsCp117GuestAgentRecoveryError('fixed journal diagnostic takes no inputs')
    try:
        config,_target,descriptor=base._descriptor(Path(root).resolve(strict=True))
        script=_journal_diagnostic_script(guards.secure_read(_intent_path(Path(root).resolve(strict=True))) is not None)
        observed=_run_ps(config,descriptor,script)
        if isinstance(observed,dict) and set(observed)=={"_phase"}:
            return {**_UNKNOWN,"state":"diagnosed","phase":observed["_phase"]}
        if isinstance(observed,dict) and set(observed)=={"guard"} and observed["guard"] in _JOURNAL_CODES:
            return {**_UNKNOWN,"state":"diagnosed","phase":"journal","guard":observed["guard"]}
    except (OSError,ValueError,TypeError,KeyError,base.WindowsMsiBasePrepareError):pass
    return {**_UNKNOWN,"state":"diagnosed","phase":"transport"}

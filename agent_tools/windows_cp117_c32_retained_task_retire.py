"""One-shot, evidence-preserving retirement of c32's single retained task.

The guest result leaf is deliberately retained.  This tool only archives and
removes ``VpnControlMcpBase-c32...``; it does not change c32 archive admission.
Consequently an archive observer needs an explicit ``task absent, leaf retained``
projection before its successful terminal can make a later campaign admissible.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import gzip
import json
import os
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

try:  # importing this module must remain safe on a Windows host
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - exercised by import simulation
    _fcntl = None

from . import windows_cp117_c32_absence as absence
from . import windows_cp117_lease as lease
from . import windows_cp117_protected_journal as journal
from . import windows_cp117_retirement_guards as guards
from . import windows_msi_base_prepare as base

_C32 = "c32cb108-4d48-407e-9153-40774559ba50"
_RETIREMENT = "d8917ee1-667f-4ee6-9af7-b8d33f3e6fb9"
_TASK = "VpnControlMcpBase-" + _C32
_DIR = ".rag_index/windows-cp117-c32-retained-task-retire"
_ROOT = r"C:\ProgramData\VpnControlCp117-retirement-" + _RETIREMENT
_LEAVES = ("binding.json", "archive.json", "terminal.json")
_UNKNOWN = {"state": "unknown", "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False}


class C32RetainedTaskRetireError(ValueError):
    pass


def _intent_path(root: Path) -> Path:
    return root / _DIR / "intent.json"


def _ps(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _sha(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(dict(value), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _binding(root: Path, descriptor: tuple[Any, ...]) -> dict[str, Any] | None:
    if (not isinstance(descriptor, tuple) or len(descriptor) != 5 or descriptor[0] != "windows-cp117"
            or not isinstance(descriptor[1], str) or type(descriptor[2]) is not int or descriptor[2] <= 0
            or type(descriptor[3]) is not int or descriptor[3] <= 0 or not isinstance(descriptor[4], str)):
        return None
    intent = base._private_intent(root, _C32)
    if not isinstance(intent, Mapping):
        return None
    if tuple(intent.get(k) for k in ("environment", "socketPath", "pid", "startTicks", "expectedSid")) != descriptor:
        return None
    action = base._terminal_task_arguments_sha(_C32, intent)
    if not isinstance(action, str) or len(action) != 64 or any(c not in "0123456789abcdef" for c in action):
        return None
    return {"retirementCorrelationId": _RETIREMENT, "c32CorrelationId": _C32,
            "generation": {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3], "sid": descriptor[4]},
            "actionSha256": action}


@contextlib.contextmanager
def _lease_lock(root: Path):
    """Take a noncreating shared lock; missing or unsafe leases remain unknown."""
    if _fcntl is None or not hasattr(os, "getuid"):
        raise OSError("shared locks unsupported")
    directory = root / lease._DIR
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise OSError("unsafe lease directory")
    fd = os.open(directory / ".environment.lock", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise OSError("unsafe lease lock")
        _fcntl.flock(fd, _fcntl.LOCK_SH)
        yield directory
    finally:
        os.close(fd)


def _no_lease(root: Path) -> bool:
    try:
        with _lease_lock(root) as directory:
            return lease._active(directory) is None
    except (OSError, ValueError, lease.Cp117LeaseError):
        return False


def _mutation_script(binding: Mapping[str, Any]) -> str:
    """Snapshot, write/read protected evidence, revalidate, then unregister once."""
    secure = journal.powershell(_ROOT, _LEAVES)
    # No product, installer, service, or process action appears in this source.
    return secure + r'''
$ErrorActionPreference='Stop';$task=@TASK@;$sid=@SID@;$expected=@ACTION@;$retire=@RETIRE@
function Task-Proof([bool]$requirePresent){
 $rows=@(Get-ScheduledTask -TaskPath '\' -TaskName $task -ErrorAction SilentlyContinue)
 if(-not $requirePresent){if($rows.Count -ne 0){throw 'TASK_PRESENT'};return}
 if($rows.Count -ne 1){throw 'TASK_COUNT'};$t=$rows[0];$a=@($t.Actions);$tr=@($t.Triggers|Where-Object {$null-ne $_});$p=$t.Principal
 if($a.Count-ne 1 -or $tr.Count-ne 0 -or $a[0].Execute -cne 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'){throw 'TASK_SHAPE'}
 $actual=([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($a[0].Arguments)))).Replace('-','').ToLowerInvariant()
 $actualSid=if($p.UserId -match '^S-1-'){$p.UserId}else{([Security.Principal.NTAccount]::new($p.UserId)).Translate([Security.Principal.SecurityIdentifier]).Value}
 $info=Get-ScheduledTaskInfo -TaskPath '\' -TaskName $task -ErrorAction Stop
 if($actual-cne $expected -or $actualSid-cne $sid -or $p.LogonType.ToString()-cne 'Interactive' -or $p.RunLevel.ToString()-cne 'Limited' -or $t.State.ToString()-cne 'Ready' -or $info.LastRunTime.Year-lt 2020 -or $info.LastTaskResult-ne 0){throw 'TASK_BINDING'}
 return $t
}
function No-ActiveWork(){
 $ps=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.ProcessId-ne $PID -and $_.Name -match '^(powershell|pwsh|msiexec|consent)\.exe$'})
 if($ps.Count-ne 0){throw 'ACTIVE_PROCESS'}
}
Task-Proof $true|Out-Null;No-ActiveWork
$xml=Export-ScheduledTask -TaskName $task -TaskPath '\';$raw=[Text.Encoding]::UTF8.GetBytes($xml)
if($raw.Length-lt 1-or $raw.Length-gt 131072){throw 'XML_SIZE'}
$hash=([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($raw))).Replace('-','').ToLowerInvariant()
$out=[IO.MemoryStream]::new();$zip=[IO.Compression.GzipStream]::new($out,[IO.Compression.CompressionMode]::Compress);$zip.Write($raw,0,$raw.Length);$zip.Dispose();$packed=$out.ToArray();if($packed.Length-lt 1-or $packed.Length-gt 8192){throw 'XML_COMPRESSED_SIZE'}
$binding=@{retirementCorrelationId=$retire;c32CorrelationId=@C32@;actionSha256=$expected}|ConvertTo-Json -Compress
$archive=@{retirementCorrelationId=$retire;task=$task;actionSha256=$expected;xmlSha256=$hash;xmlLength=$raw.Length;xmlGzipBase64=[Convert]::ToBase64String($packed)}|ConvertTo-Json -Compress
Write-SecureJsonCreate 'binding.json' $binding;Write-SecureJsonCreate 'archive.json' $archive
$read=Read-SecureJson 'archive.json';if($read.retirementCorrelationId-cne $retire -or $read.task-cne $task -or $read.actionSha256-cne $expected -or $read.xmlSha256-cne $hash -or [int]$read.xmlLength-ne $raw.Length){throw 'ARCHIVE_READ'}
$z=[Convert]::FromBase64String([string]$read.xmlGzipBase64);$in=[IO.MemoryStream]::new([byte[]]$z);$gz=[IO.Compression.GzipStream]::new($in,[IO.Compression.CompressionMode]::Decompress);$copy=[IO.MemoryStream]::new();try{$gz.CopyTo($copy);$again=$copy.ToArray()}finally{$gz.Dispose();$in.Dispose();$copy.Dispose()};if($again.Length-ne $raw.Length -or ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($again))).Replace('-','').ToLowerInvariant()-cne $hash){throw 'ARCHIVE_HASH'}
Task-Proof $true|Out-Null;No-ActiveWork
$againXml=[Text.Encoding]::UTF8.GetBytes((Export-ScheduledTask -TaskName $task -TaskPath '\'));if((([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($againXml))).Replace('-','').ToLowerInvariant())-cne $hash){throw 'TASK_CHANGED'}
Unregister-ScheduledTask -TaskPath '\' -TaskName $task -Confirm:$false;Task-Proof $false;No-ActiveWork
Write-SecureJsonCreate 'terminal.json' (@{retirementCorrelationId=$retire;state='removed';actionSha256=$expected;xmlSha256=$hash}|ConvertTo-Json -Compress)
[Console]::Out.WriteLine('{"state":"terminal"}')
'''.replace("@TASK@", _ps(_TASK)).replace("@SID@", _ps(str(binding["generation"]["sid"]))).replace("@ACTION@", _ps(str(binding["actionSha256"]))).replace("@RETIRE@", _ps(_RETIREMENT)).replace("@C32@", _ps(_C32))


def _reader_script(binding: Mapping[str, Any]) -> str:
    secure = journal.powershell(_ROOT, _LEAVES)
    return secure + r'''
$ErrorActionPreference='Stop';$task=@TASK@;$retire=@RETIRE@;$expected=@ACTION@
$b=Read-SecureJson 'binding.json';$a=Read-SecureJson 'archive.json';$t=Read-SecureJson 'terminal.json'
if($b.retirementCorrelationId-cne $retire -or $b.c32CorrelationId-cne @C32@ -or $b.actionSha256-cne $expected -or $a.retirementCorrelationId-cne $retire -or $a.task-cne $task -or $a.actionSha256-cne $expected -or $t.retirementCorrelationId-cne $retire -or $t.state-cne 'removed' -or $t.actionSha256-cne $expected -or $t.xmlSha256-cne $a.xmlSha256){throw 'JOURNAL'}
$raw=[IO.MemoryStream]::new();$z=[Convert]::FromBase64String([string]$a.xmlGzipBase64);$i=[IO.MemoryStream]::new([byte[]]$z);$g=[IO.Compression.GzipStream]::new($i,[IO.Compression.CompressionMode]::Decompress);try{$g.CopyTo($raw);$bytes=$raw.ToArray()}finally{$g.Dispose();$i.Dispose();$raw.Dispose()};if($bytes.Length-lt 1-or $bytes.Length-gt 131072 -or $bytes.Length-ne [int]$a.xmlLength){throw 'ARCHIVE'};$h=([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($bytes))).Replace('-','').ToLowerInvariant();if($h-cne $a.xmlSha256){throw 'HASH'}
if(@(Get-ScheduledTask -TaskPath '\' -TaskName $task -ErrorAction SilentlyContinue).Count-ne 0){throw 'TASK_PRESENT'}
$ps=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.ProcessId-ne $PID -and $_.Name -match '^(powershell|pwsh|msiexec|consent)\.exe$'});if($ps.Count-ne 0){throw 'ACTIVE_PROCESS'}
[Console]::Out.WriteLine('{"state":"terminal"}')
'''.replace("@TASK@", _ps(_TASK)).replace("@RETIRE@", _ps(_RETIREMENT)).replace("@C32@", _ps(_C32)).replace("@ACTION@", _ps(str(binding["actionSha256"])))


def _parse_script(source: str) -> str:
    """Parse compressed source in PS5; it never invokes the mutation body."""
    packed = base64.b64encode(gzip.compress(source.encode("utf-8"), mtime=0)).decode("ascii")
    return ("$z=[Convert]::FromBase64String('" + packed + "');$i=[IO.MemoryStream]::new([byte[]]$z);"
            "$g=[IO.Compression.GzipStream]::new($i,[IO.Compression.CompressionMode]::Decompress);$o=[IO.MemoryStream]::new();"
            "try{$g.CopyTo($o);$s=[Text.Encoding]::UTF8.GetString($o.ToArray())}finally{$g.Dispose();$i.Dispose();$o.Dispose()};"
            "$t=$null;$e=$null;[Management.Automation.Language.Parser]::ParseInput($s,[ref]$t,[ref]$e)|Out-Null;"
            "[Console]::Out.WriteLine((@{valid=(@($e).Count-eq 0)}|ConvertTo-Json -Compress))")


def _run(config: Any, descriptor: tuple[Any, ...], source: str) -> Mapping[str, Any] | None:
    encoded = base64.b64encode(source.encode("utf-16le")).decode("ascii")
    if len(encoded) >= 30000:
        return None
    raw = base._remote(config, base._READINESS, (descriptor[1], str(descriptor[2]), str(descriptor[3]), encoded), None, 30)
    try:
        outer = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None
    value = outer.get("inventory") if isinstance(outer, Mapping) and outer.get("state") == "observed" else None
    return dict(value) if isinstance(value, Mapping) else None


def _parse(config: Any, descriptor: tuple[Any, ...], source: str) -> bool:
    result = _run(config, descriptor, _parse_script(source))
    return result == {"valid": True}


# The mutation is dispatched only under the already-existing remote campaign
# shared lock.  This is separate from the parser/read-only transport.
_REMOTE_DISPATCH = base._QGA + r'''import base64,fcntl,json,os,stat,sys,time
root,env,sock,pid,ticks,encoded=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if env!='windows-cp117' or not live(sock,pid,ticks) or len(encoded)>=30000:raise ValueError()
 group=os.path.join(root,env,'windows-cp117-campaign')
 for path in (root,os.path.join(root,env),group):
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 fd=os.open(os.path.join(group,'.environment.lock'),os.O_RDONLY|os.O_NOFOLLOW)
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError()
  fcntl.flock(fd,fcntl.LOCK_SH)
  if os.path.lexists(os.path.join(group,'active.json')) or not live(sock,pid,ticks):raise ValueError()
  child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
  if type(child) is not int or child<=0:raise ValueError()
  for _ in range(80):
   state=call(sock,'guest-exec-status',{'pid':child})
   if state.get('exited') is True:break
   if state.get('exited') is not False:raise ValueError()
   time.sleep(.25)
  else:raise ValueError()
  if (not live(sock,pid,ticks) or os.path.lexists(os.path.join(group,'active.json')) or state.get('exitcode')!=0 or state.get('out-truncated',False) is not False or state.get('err-truncated',False) is not False):raise ValueError()
  raw=base64.b64decode(state.get('out-data',''),validate=True)
  if len(raw)>1024:raise ValueError()
  value=json.loads(decode(raw))
  if value!={'state':'terminal'}:raise ValueError()
  out({'state':'observed','receipt':value})
 finally:os.close(fd)
except Exception:out({'state':'unknown'})
'''

def _dispatch(root: Path, config: Any, descriptor: tuple[Any, ...], source: str) -> Mapping[str, Any] | None:
    """Dispatch once while remote and local campaign locks remain read-held."""
    encoded = base64.b64encode(source.encode("utf-16le")).decode("ascii")
    if len(encoded) >= 30000:
        return None
    _config, target, current = base._descriptor(root)
    if current != descriptor:
        return None
    raw = base._remote(config, _REMOTE_DISPATCH,
                       (str(target.fixture_transfer_root), descriptor[0], descriptor[1], str(descriptor[2]), str(descriptor[3]), encoded),
                       None, 60)
    try:
        value = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None
    receipt = value.get("receipt") if isinstance(value, Mapping) and value.get("state") == "observed" else None
    return dict(receipt) if isinstance(receipt, Mapping) else None


def _ready(root: Path) -> tuple[Any, tuple[Any, ...], dict[str, Any], str] | tuple[None, None, None, str]:
    if _fcntl is None or not hasattr(os, "getuid"):
        return None, None, None, "platform"
    try:
        config, target, descriptor = base._descriptor(root)
        binding = _binding(root, descriptor)
        if binding is None: return None, None, None, "binding"
        if not _no_lease(root): return None, None, None, "lease"
        proof = absence.retained_terminal(root, config, target, descriptor)
        if proof.get("state") != "retained-terminal": return None, None, None, "terminal"
        source = _mutation_script(binding)
        # Both prospective mutation (including snapshot) and terminal reader are
        # parsed before the create-only intent can permit a guest dispatch.
        if not _parse(config, descriptor, source) or not _parse(config, descriptor, _reader_script(binding)):
            return None, None, None, "parser"
        return config, descriptor, binding, "ready"
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError):
        return None, None, None, "descriptor"


def preflight(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if value != {}: raise C32RetainedTaskRetireError("fixed c32 retirement takes no inputs")
    path = Path(root).resolve(strict=True)
    if guards.secure_read(_intent_path(path)) is not None:
        return {**_UNKNOWN, "state": "blocked", "phase": "intent"}
    _, _, _, phase = _ready(path)
    return ({**_UNKNOWN, "state": "ready", "retirementCorrelationId": _RETIREMENT, "task": _TASK}
            if phase == "ready" else {**_UNKNOWN, "state": "blocked", "phase": phase})


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if value != {}: raise C32RetainedTaskRetireError("fixed c32 retirement takes no inputs")
    path = Path(root).resolve(strict=True)
    try:
        # This lock deliberately spans revalidation, reservation and the only
        # guest mutation.  Missing/unsafe locks do not cause a fallback.
        with _lease_lock(path) as directory:
            existing = guards.secure_read(_intent_path(path))
            if existing is not None:
                return status(path, {})
            if lease._active(directory) is not None:
                return {**_UNKNOWN, "state": "blocked", "phase": "lease"}
            config, descriptor, binding, phase = _ready(path)
            if phase != "ready": return {**_UNKNOWN, "state": "blocked", "phase": phase}
            if lease._active(directory) is not None:
                return {**_UNKNOWN, "state": "blocked", "phase": "lease"}
            source = _mutation_script(binding)
            intent = {"retirementCorrelationId": _RETIREMENT, "binding": binding, "bindingSha256": _sha(binding),
                      "mutationSha256": hashlib.sha256(source.encode()).hexdigest()}
            guards.secure_write_create(_intent_path(path), intent)
            # An uncertain submission consumes this intent forever.
            _config2, _target2, second = base._descriptor(path)
            if second != descriptor or lease._active(directory) is not None:
                return {**_UNKNOWN, "phase": "generation"}
            result = _dispatch(path, config, descriptor, source)
            if result != {"state": "terminal"}: return dict(_UNKNOWN)
    except (OSError, ValueError, KeyError, guards.RetirementGuardError, base.WindowsMsiBasePrepareError, lease.Cp117LeaseError):
        return dict(_UNKNOWN)
    return status(path, {})


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if value != {}: raise C32RetainedTaskRetireError("fixed c32 retirement takes no inputs")
    path = Path(root).resolve(strict=True)
    try:
        intent = guards.secure_read(_intent_path(path))
        if not isinstance(intent, Mapping) or set(intent) != {"retirementCorrelationId", "binding", "bindingSha256", "mutationSha256"}:
            return dict(_UNKNOWN)
        config, _target, descriptor = base._descriptor(path); binding = _binding(path, descriptor)
        fresh_mutation = hashlib.sha256(_mutation_script(binding).encode()).hexdigest()
        if (binding is None or intent["retirementCorrelationId"] != _RETIREMENT or intent["binding"] != binding
                or intent["bindingSha256"] != _sha(binding) or not isinstance(intent.get("mutationSha256"), str)
                or intent["mutationSha256"] != fresh_mutation):
            return {**_UNKNOWN, "phase": "generation"}
        if not _no_lease(path): return {**_UNKNOWN, "phase": "lease"}
        if not _parse(config, descriptor, _reader_script(binding)): return {**_UNKNOWN, "phase": "parser"}
        reader = _reader_script(binding)
        first = _run(config, descriptor, reader)
        if first != {"state": "terminal"}: return {**_UNKNOWN, "phase": "remote"}
        _c2, _t2, middle = base._descriptor(path)
        if middle != descriptor or not _no_lease(path): return {**_UNKNOWN, "phase": "recheck"}
        second_result = _run(config, descriptor, reader)
        if second_result != first: return {**_UNKNOWN, "phase": "recheck"}
        _c3, _t3, second = base._descriptor(path)
        if second != descriptor or not _no_lease(path): return {**_UNKNOWN, "phase": "recheck"}
        return {"state": "terminal", "retirementCorrelationId": _RETIREMENT, "task": _TASK,
                "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
    except (OSError, ValueError, TypeError, KeyError, guards.RetirementGuardError, base.WindowsMsiBasePrepareError):
        return dict(_UNKNOWN)


def workflow(root: Path | str, action: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if action == "preflight": return preflight(root, inputs)
    if action == "start": return start(root, inputs)
    if action == "status": return status(root, inputs)
    raise C32RetainedTaskRetireError("unknown fixed c32 task-retirement action")


def post_state_requires_archive_projection() -> dict[str, Any]:
    return {**_UNKNOWN, "state": "blocked", "phase": "archive-post-state", "baseTask": "absent", "guestLeaf": "present"}

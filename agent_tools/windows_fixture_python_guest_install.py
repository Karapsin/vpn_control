"""CP117's one-shot, per-user Python 3.13.15 installer route.

This is deliberately not a package runner.  It accepts no URL, executable
path, command line, account, or installer version.  A fresh correlation names
the already-staged private installer and one limited InteractiveToken task.
The local journal is written before either the guest journal or Task Scheduler
can observe an installer effect; uncertainty is therefore terminal and is
observed with :func:`status`, never replayed.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
from typing import Any, Mapping

from . import windows_msi_base_prepare as base
from . import windows_update_fixture_server as server
from . import windows_fixture_python_acquire_transfer as transfer


class WindowsFixturePythonGuestInstallError(ValueError):
    pass


VERSION = "3.13.15"
SIZE_BYTES = 29_452_944
SHA256 = "edec09c4853aeae9ac36efb8c9f95b6b8e2fee65eee56d9767a8b7c69c574403"
_GROUP = ".rag_index/windows-fixture-python-guest-install"
_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_ARTIFACT = re.compile(r"sha256-[0-9a-f]{64}\Z")
_SID = re.compile(r"S-1-5-21-(?:[0-9]+-){3}[0-9]+\Z")


def _canonical(value: object) -> bool:
    return isinstance(value, str) and bool(_UUID.fullmatch(value)) and str(uuid.UUID(value)) == value


def _request(value: Mapping[str, Any]) -> dict[str, str]:
    fields = {"host", "leaseId", "stageCorrelationId", "serverCorrelationId", "correlationId", "sourceSha",
              "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId"}
    if not isinstance(value, Mapping) or set(value) != fields or value.get("host") != "archlinux":
        raise WindowsFixturePythonGuestInstallError("CP95 requires only its exact CP117 binding fields.")
    if not all(_canonical(value[name]) for name in ("leaseId", "stageCorrelationId", "serverCorrelationId", "correlationId")):
        raise WindowsFixturePythonGuestInstallError("CP95 correlation is invalid.")
    if len({value["leaseId"], value["stageCorrelationId"], value["serverCorrelationId"], value["correlationId"]}) != 4:
        raise WindowsFixturePythonGuestInstallError("CP95 correlations must be distinct.")
    for name, pattern in (("sourceSha", _SHA), ("fixtureReceiptArtifactId", _ARTIFACT),
                          ("baseMsiArtifactId", _ARTIFACT), ("targetMsiArtifactId", _ARTIFACT)):
        if not isinstance(value[name], str) or not pattern.fullmatch(value[name]):
            raise WindowsFixturePythonGuestInstallError("CP95 binding is invalid.")
    return dict(value)


def _paths(correlation: str) -> dict[str, str]:
    leaf = r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-python-bootstrap-" + correlation
    return {"leaf": leaf, "installer": leaf + r"\python-3.13.15-amd64.exe",
            "task": "VpnControlMcpCp95Python-" + correlation,
            "guestIntent": leaf + r"\cp95-intent.json",
            "python": r"C:\Users\vpncp117\AppData\Local\Programs\Python\Python313\python.exe"}


def _intent_path(root: Path, correlation: str) -> Path:
    return root / _GROUP / (correlation + ".json")


def _read_intent(root: Path, correlation: str) -> dict[str, Any] | None:
    try:
        fd = os.open(_intent_path(root, correlation), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 8192:
            raise WindowsFixturePythonGuestInstallError("CP95 intent is unsafe.")
        try: record = json.load(stream)
        except (TypeError, ValueError) as error: raise WindowsFixturePythonGuestInstallError("CP95 intent is invalid.") from error
    if not isinstance(record, dict) or record.get("request", {}).get("correlationId") != correlation:
        raise WindowsFixturePythonGuestInstallError("CP95 intent is invalid.")
    return record


def _reserve(root: Path, record: Mapping[str, Any]) -> None:
    directory = root / _GROUP; directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise WindowsFixturePythonGuestInstallError("CP95 journal is unsafe.")
    lock = os.open(directory / ".environment.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        raw = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if len(raw) > 8192: raise WindowsFixturePythonGuestInstallError("CP95 intent is too large.")
        fd = os.open(_intent_path(root, record["request"]["correlationId"]), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        parent = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)); os.fsync(parent); os.close(parent)
    finally: os.close(lock)


# The fixed PS5 command records a guest intent before registering/running the
# task.  The task's action is only the pinned installer and CP95 arguments.
_PRIVATE_TREE_PS = r'''function Assert-PrivateTree([string]$leaf,[string]$installer,[string]$sid){
 $profile='C:\Users\vpncp117';$paths=@($profile,(Join-Path $profile 'AppData'),(Join-Path $profile 'AppData\Local'),(Join-Path $profile 'AppData\Local\VpnControl'),$leaf,$installer)
 $allowed=@($sid,'S-1-5-18','S-1-5-32-544')
 $writeMask=[Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData -bor [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor [Security.AccessControl.FileSystemRights]::WriteAttributes -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
 for($index=0;$index -lt $paths.Count;$index++){$path=$paths[$index];$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop;if(($item.Attributes-band [IO.FileAttributes]::ReparsePoint)){throw 'REPARSE'};$acl=Get-Acl -LiteralPath $path -ErrorAction Stop;$owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;if(($index -lt 4 -and $allowed -notcontains $owner) -or ($index -ge 4 -and $owner -cne $sid)){throw 'OWNER'};foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $allowed -notcontains $rule.IdentityReference.Value -and ($rule.FileSystemRights -band $writeMask) -ne 0 -and ($rule.IdentityReference.Value -cne 'S-1-3-0' -or ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0)){throw 'ACL'}}}
}'''

_START_PS = _PRIVATE_TREE_PS + r'''$ErrorActionPreference='Stop';$p=@PATHS@;$sid=@SID@;$sha=@SHA@;$size=@SIZE@
Assert-PrivateTree $p.leaf $p.installer $sid
$i=Get-Item -LiteralPath $p.installer -Force;if($i.PSIsContainer){throw 'INSTALLER_TYPE'}
if($i.Length -ne $size -or (Get-FileHash -LiteralPath $p.installer -Algorithm SHA256).Hash.ToLowerInvariant() -cne $sha){throw 'INSTALLER_HASH'}
if((Get-ScheduledTask -TaskName $p.task -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $p.guestIntent)){throw 'EXISTING'}
$intent=@{version=1;installerSha256=$sha;installerSize=$size;originalSid=$sid;task=$p.task}|ConvertTo-Json -Compress
[IO.File]::WriteAllText($p.guestIntent,$intent,[Text.UTF8Encoding]::new($false))
$action=New-ScheduledTaskAction -Execute $p.installer -Argument '/quiet InstallAllUsers=0 PrependPath=0 Include_launcher=0 Include_pip=0 Include_test=0'
$principal=New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName $p.task -Action $action -Principal $principal|Out-Null
Start-ScheduledTask -TaskName $p.task
@{version=1;state='submitted'}|ConvertTo-Json -Compress'''

_STATUS_PS = _PRIVATE_TREE_PS + r'''$ErrorActionPreference='Stop';$p=@PATHS@;$sid=@SID@;$sha=@SHA@;$size=@SIZE@
$out=@{version=1;intent='absent';private='absent';task='absent';installer='absent';result='absent';registry='absent';python='absent'}
try{Assert-PrivateTree $p.leaf $p.installer $sid;$out.private='verified'}catch{}
try{$intent=Get-Content -LiteralPath $p.guestIntent -Raw -ErrorAction Stop|ConvertFrom-Json;if($intent.version -eq 1 -and $intent.installerSha256 -ceq $sha -and $intent.installerSize -eq $size -and $intent.originalSid -ceq $sid -and $intent.task -ceq $p.task){$out.intent='verified'}}catch{}
try{$i=Get-Item -LiteralPath $p.installer -Force;if($out.private -eq 'verified' -and !$i.PSIsContainer -and $i.Length -eq $size -and (Get-FileHash -LiteralPath $p.installer -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $sha){$out.installer='verified'}}catch{}
try{$t=Get-ScheduledTask -TaskPath '\' -TaskName $p.task -ErrorAction Stop;$a=$t.Actions[0];$q=$t.Principal;$principalSid=if($q.UserId -match '^S-1-'){([Security.Principal.SecurityIdentifier]::new($q.UserId)).Value}else{([Security.Principal.NTAccount]::new($q.UserId)).Translate([Security.Principal.SecurityIdentifier]).Value};if($t.TaskPath -ceq '\' -and $t.Actions.Count -eq 1 -and $a.Execute -ceq $p.installer -and $a.Arguments -ceq '/quiet InstallAllUsers=0 PrependPath=0 Include_launcher=0 Include_pip=0 Include_test=0' -and $principalSid -ceq $sid -and $q.LogonType.ToString() -ceq 'Interactive' -and $q.RunLevel.ToString() -ceq 'Limited'){$out.task=($t.State.ToString().ToLowerInvariant());$info=Get-ScheduledTaskInfo -TaskPath '\' -TaskName $p.task -ErrorAction Stop;if($out.task -in @('running','queued')){$out.result='running'}elseif($out.task -eq 'ready' -and $info.LastRunTime -ne [datetime]::MinValue -and $info.LastTaskResult -eq 0){$out.result='succeeded'}elseif($out.task -eq 'ready' -and $info.LastRunTime -ne [datetime]::MinValue -and $info.LastTaskResult -ne 267009){$out.result='failed'}else{$out.result='unknown'}}}catch{}
try{$key='Registry::HKEY_USERS\'+$sid+'\Software\Python\PythonCore\3.13\InstallPath';$v=(Get-ItemProperty -LiteralPath $key -ErrorAction Stop).'(default)';if($v -and [IO.Path]::GetFullPath((Join-Path $v 'python.exe')) -ceq $p.python){$out.registry='verified'}}catch{}
try{$x=Get-Item -LiteralPath $p.python -Force;$signature=Get-AuthenticodeSignature -LiteralPath $p.python;if($out.private -eq 'verified' -and !$x.PSIsContainer -and $x.VersionInfo.ProductVersion -match '^3\.13\.15(?:\.0)?(?:\s|$)' -and $signature.Status -eq 'Valid' -and $signature.SignerCertificate.Subject -match 'O=Python Software Foundation'){$out.python='verified'}}catch{}
$out|ConvertTo-Json -Compress'''

_DIAGNOSE_PS = r'''$ErrorActionPreference='Stop';$sid=@SID@;$leaf=@LEAF@;$installer=@INSTALLER@;$sha=@SHA@;$size=@SIZE@
$paths=@('C:\Users\vpncp117','C:\Users\vpncp117\AppData','C:\Users\vpncp117\AppData\Local','C:\Users\vpncp117\AppData\Local\VpnControl',$leaf,$installer)
$names=@('profile','appdata','local','vpncontrol','leaf','installer')
$allowed=@($sid,'S-1-5-18','S-1-5-32-544')
$out=@{version=1;phase='complete';reason='none'}
for($i=0;$i -lt $paths.Count;$i++){
 $out.phase=$names[$i];$out.reason='missing-or-unreadable'
 try{$item=Get-Item -LiteralPath $paths[$i] -Force -ErrorAction Stop}catch{break}
 if(($item.Attributes-band [IO.FileAttributes]::ReparsePoint)){$out.reason='reparse';break}
 if($i -lt 5 -and !$item.PSIsContainer){$out.reason='type';break}
 if($i -eq 5 -and $item.PSIsContainer){$out.reason='type';break}
 $out.reason='acl-unreadable'
 try{$acl=Get-Acl -LiteralPath $paths[$i] -ErrorAction Stop;$owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;$rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))}catch{break}
 if(($i -lt 4 -and $allowed -notcontains $owner) -or ($i -ge 4 -and $owner -cne $sid)){$out.reason='foreign-owner';break}
 $foreign=@($rules|Where-Object {$allowed -notcontains $_.IdentityReference.Value})
 if($foreign.Count -gt 0){$writeMask=[Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData -bor [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor [Security.AccessControl.FileSystemRights]::WriteAttributes -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership;$writers=@($foreign|Where-Object {$_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and ($_.FileSystemRights -band $writeMask) -ne 0 -and ($_.IdentityReference.Value -cne 'S-1-3-0' -or ($_.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0)});if($writers.Count -gt 0){$out.reason='acl-foreign-write';break}}
 $out.reason='none'
}
if($out.reason -eq 'none'){
 $out.phase='digest';$out.reason='digest-mismatch'
 try{$item=Get-Item -LiteralPath $installer -Force -ErrorAction Stop;if($item.Length -eq $size -and (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $sha){$out.phase='complete';$out.reason='none'}}catch{}
}
$out|ConvertTo-Json -Compress'''


def _encoded(script: str, paths: Mapping[str, str], sid: str) -> str:
    literals = ";".join("$%s=%s" % (key, server.public._ps_literal(value)) for key, value in paths.items())
    script = script.replace("@PATHS@", "@{" + ";".join("%s=%s" % (key, server.public._ps_literal(value)) for key, value in paths.items()) + "}")
    script = script.replace("@SID@", server.public._ps_literal(sid)).replace("@SHA@", server.public._ps_literal(SHA256)).replace("@SIZE@", str(SIZE_BYTES))
    return base64.b64encode(script.encode("utf-16le")).decode("ascii")


def diagnose(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read a finite first-failure category for an existing install intent."""
    root = Path(root).resolve(strict=True)
    if not isinstance(value, Mapping) or set(value) != {"correlationId"} or not _canonical(value.get("correlationId")):
        raise WindowsFixturePythonGuestInstallError("CP117 install diagnostic requires its correlation.")
    correlation = value["correlationId"]
    record = _read_intent(root, correlation)
    if record is None:
        return {"state": "intent-absent", "correlationId": correlation, "replayAllowed": False}
    try:
        config, target, (env, socket, pid, ticks, sid) = base._descriptor(root)
        if (env != "windows-cp117" or (socket, pid, ticks, sid) !=
                (record.get("socketPath"), record.get("qemuPid"), record.get("startTicks"), record.get("originalSid"))):
            raise WindowsFixturePythonGuestInstallError("CP117 generation changed.")
        paths = _paths(correlation)
        script = (_DIAGNOSE_PS.replace("@SID@", server.public._ps_literal(sid))
                  .replace("@LEAF@", server.public._ps_literal(paths["leaf"]))
                  .replace("@INSTALLER@", server.public._ps_literal(paths["installer"]))
                  .replace("@SHA@", server.public._ps_literal(SHA256)).replace("@SIZE@", str(SIZE_BYTES)))
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        raw = base._remote(config, _REMOTE, (str(target.fixture_transfer_root), env, socket, str(pid), str(ticks), encoded), None, 40)
        outer = json.loads(raw) if raw is not None else None
        detail = outer.get("value") if isinstance(outer, dict) and outer.get("state") == "observed" else None
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        detail = None
    phases = {"profile", "appdata", "local", "vpncontrol", "leaf", "installer", "digest", "complete"}
    reasons = {"none", "missing-or-unreadable", "reparse", "type", "acl-unreadable", "foreign-owner", "acl-foreign-write", "acl-creator-owner-template", "acl-foreign-read", "acl-deny", "digest-mismatch"}
    if (not isinstance(detail, dict) or set(detail) != {"version", "phase", "reason"}
            or detail.get("version") != 1 or detail.get("phase") not in phases or detail.get("reason") not in reasons
            or (detail["phase"] == "complete") != (detail["reason"] == "none")):
        return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    return {"state": "observed", "correlationId": correlation,
            "phase": detail["phase"], "reason": detail["reason"], "replayAllowed": False}


_REMOTE = base._QGA + r'''import time
root,env,sock,pid,ticks,encoded=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if env!='windows-cp117' or not live(sock,pid,ticks):raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 for _ in range(160):
  result=call(sock,'guest-exec-status',{'pid':child})
  if result.get('exited') is True:break
  time.sleep(.2)
 else:raise ValueError()
 if result.get('exitcode')!=0 or result.get('out-truncated') is not False or result.get('err-truncated') is not False:raise ValueError()
 raw=base64.b64decode(result.get('out-data',''),validate=True)
 if not 0<len(raw)<=2048:raise ValueError()
 out({'state':'observed','value':json.loads(decode(raw))})
except Exception:out({'state':'unknown'})'''


def _observe(root: Path, record: Mapping[str, Any]) -> dict[str, str] | None:
    config, target, (env, socket, pid, ticks, sid) = base._descriptor(root)
    if (env != "windows-cp117" or sid != record.get("originalSid") or
            (socket, pid, ticks) != (record.get("socketPath"), record.get("qemuPid"), record.get("startTicks"))):
        return None
    raw = base._remote(config, _REMOTE, (str(target.fixture_transfer_root), env, socket, str(pid), str(ticks), _encoded(_STATUS_PS, _paths(record["request"]["correlationId"]), sid)), None, 40)
    try: outer = json.loads(raw) if raw is not None else None; value = outer.get("value") if isinstance(outer, dict) and outer.get("state") == "observed" else None
    except (TypeError, ValueError): value = None
    if not isinstance(value, dict) or set(value) != {"version", "intent", "private", "task", "installer", "result", "registry", "python"} or value.get("version") != 1:
        return None
    if value["intent"] not in {"absent", "verified"} or value["private"] not in {"absent", "verified"} or value["task"] not in {"absent", "ready", "running", "queued", "disabled"} or value["installer"] not in {"absent", "verified"} or value["result"] not in {"absent", "running", "succeeded", "failed", "unknown"} or value["registry"] not in {"absent", "verified"} or value["python"] not in {"absent", "verified"}:
        return None
    return {key: value[key] for key in ("intent", "private", "task", "installer", "result", "registry", "python")}


def _completion(task: str, last_task_result: int | None) -> str:
    """Map an exact Task Scheduler observation to the bounded CP95 result."""
    if task in {"running", "queued"}:
        return "running"
    if task == "ready" and last_task_result == 0:
        return "succeeded"
    if task == "ready" and isinstance(last_task_result, int) and last_task_result != 267009:
        return "failed"
    return "unknown"


def _admit(root: Path, request: Mapping[str, str]) -> tuple[dict[str, Any], tuple[Any, ...]]:
    pair, guest = server._admit_campaign(root, request, require_credentials=True)
    if server._python_candidates(root, request):
        raise WindowsFixturePythonGuestInstallError("CP95 requires a zero Python inventory.")
    return pair, guest


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    root = Path(root).resolve(strict=True); request = _request(value); correlation = request["correlationId"]
    prior = _read_intent(root, correlation)
    if prior is not None:
        if prior.get("request") != request: raise WindowsFixturePythonGuestInstallError("CP95 correlation binds another request.")
        return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    pair, (socket, pid, ticks, sid) = _admit(root, request)
    acquired = transfer._read(root, correlation)
    if acquired is None or acquired.get("request") != request or transfer.status(root, {"correlationId": correlation}).get("state") != "downloaded":
        raise WindowsFixturePythonGuestInstallError("CP117 pinned installer transfer is not verified.")
    if not _SID.fullmatch(sid): raise WindowsFixturePythonGuestInstallError("CP95 original SID is invalid.")
    record = {"schemaVersion": 1, "request": request, "socketPath": socket, "qemuPid": pid, "startTicks": ticks, "originalSid": sid,
              "sourceFingerprint": pair["sourceFingerprint"], "installerSha256": SHA256, "installerSize": SIZE_BYTES,
              "commandSha256": hashlib.sha256(_START_PS.encode()).hexdigest()}
    _reserve(root, record)  # durable local intent before guest intent/task effect
    config, target, (env, now_socket, now_pid, now_ticks, now_sid) = base._descriptor(root)
    if (env, now_socket, now_pid, now_ticks, now_sid) != ("windows-cp117", socket, pid, ticks, sid):
        return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    raw = base._remote(config, _REMOTE, (str(target.fixture_transfer_root), env, socket, str(pid), str(ticks), _encoded(_START_PS, _paths(correlation), sid)), None, 40)
    try: observed = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError): observed = None
    if not isinstance(observed, dict) or observed.get("state") != "observed" or observed.get("value") != {"version": 1, "state": "submitted"}:
        return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    return {"state": "submitted", "correlationId": correlation, "replayAllowed": False}


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    root = Path(root).resolve(strict=True)
    if not isinstance(value, Mapping) or set(value) != {"correlationId"} or not _canonical(value.get("correlationId")):
        raise WindowsFixturePythonGuestInstallError("CP95 status requires its exact correlation.")
    record = _read_intent(root, value["correlationId"])
    if record is None: return {"state": "intent-absent", "correlationId": value["correlationId"], "replayAllowed": False}
    observed = _observe(root, record)
    if observed is None: return {"state": "unknown", "correlationId": value["correlationId"], "replayAllowed": False}
    state = "blocked" if observed["intent"] != "verified" or observed["private"] != "verified" or observed["task"] in {"absent", "disabled"} else "succeeded" if (observed["task"] == "ready" and
                             all(observed[k] == "verified" for k in ("installer", "registry", "python")) and
                             observed["result"] == "succeeded") else "failed" if observed["result"] == "failed" else "running" if observed["task"] in {"running", "queued"} and observed["result"] == "running" else "blocked"
    return {"state": state, "correlationId": value["correlationId"], "intent": observed["intent"], "private": observed["private"], "task": observed["task"], "installer": observed["installer"], "result": observed["result"], "registry": observed["registry"], "python": observed["python"], "replayAllowed": False}


def collect(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Finite public projection; this does not retry or expose guest paths."""
    result = status(root, value)
    return {key: result[key] for key in ("state", "correlationId", "replayAllowed")}

"""Fail-closed retirement of one lost CP117 download submission.

This is deliberately a single-correlation recovery adapter.  It never repeats
the scheduled download or runs an installer.  The disposable guest leaf is
kept as evidence: only an exact empty ``download``/``server-state`` tree is
accepted before the host transfer leaf can be retired.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Mapping

from . import windows_cp117_lease as lease
from . import windows_msi_base_prepare as base
from . import windows_update_fixture_http_stage as http


class WindowsUpdateFixtureDownloadAbortError(ValueError):
    pass


_CORRELATION = "af3360e5-a53b-4cd2-b91a-4c6abfd6b118"
_SOURCE = "19be9df22cbab8086c26e5ca907d9569a5a28a08"
_LEASE = "67cb7008-f9e4-436a-bfa8-683e79bbe21d"
_GROUP = ".rag_index/windows-update-fixture-download-abort"
_UNKNOWN = {"state": "unknown", "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False}

# A separate host program is required: the general cleanup admits a served
# listener, which is unsafe for this failed download.  The pending marker is
# durable before removal so a lost SSH response can only be finalized, never
# replay the cleanup from an ambiguous state.
_REMOTE_ABORT = r'''import base64,hashlib,json,os,re,secrets,shutil,stat,sys
root,corr,digest,size,encoded,action=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
def d(p):
 i=os.lstat(p)
 if not stat.S_ISDIR(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o700:raise ValueError()
def j(p,n):
 i=os.lstat(p)
 if not stat.S_ISREG(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o600 or not 0<i.st_size<=n:raise ValueError()
 with open(p,'rb') as f:return json.load(f)
def bundle(p,n,h):
 i=os.lstat(p)
 if not stat.S_ISREG(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o600 or i.st_size!=n:raise ValueError()
 fd=os.open(p,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0));d=hashlib.sha256()
 with os.fdopen(fd,'rb') as f:
  before=os.fstat(f.fileno())
  for part in iter(lambda:f.read(1048576),b''):d.update(part)
  after=os.fstat(f.fileno())
 if before.st_ino!=i.st_ino or after.st_ino!=i.st_ino or after.st_size!=i.st_size or d.hexdigest()!=h:raise ValueError()
try:
 b=json.loads(base64.b64decode(encoded,validate=True));n=int(size)
 if action not in ('status','cleanup') or not os.path.isabs(root) or not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',corr) or not re.fullmatch(r'[0-9a-f]{64}',digest) or not 0<n<=1075838976 or not isinstance(b,dict) or b.get('correlationId')!=corr or b.get('bundleSha256')!=digest:raise ValueError()
 parent=os.path.join(root,'windows-cp117');g=os.path.join(parent,'windows-update-fixture-http-stage');a=os.path.join(parent,'windows-update-fixture-stage');s=os.path.join(g,corr);m=os.path.join(g,corr+'.download-aborted.json')
 for p in (root,parent,g,a):d(p)
 base={'correlationId':corr,'bindingSha256':hashlib.sha256(json.dumps(b,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'served':False}
 def save(v):
  t=m+'.tmp-'+secrets.token_hex(12);fd=os.open(t,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  with os.fdopen(fd,'wb') as f:f.write((json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode());f.flush();os.fsync(f.fileno())
  os.replace(t,m);fd=os.open(g,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(fd);os.close(fd)
 if os.path.lexists(m):
  v=j(m,512)
  if not isinstance(v,dict) or v.get('state') not in ('pending','cleaned') or {k:x for k,x in v.items() if k!='state'}!=base:raise ValueError()
  if v['state']=='cleaned':
   if os.path.lexists(s):raise ValueError()
   out({'state':'cleaned'});raise SystemExit
  if action=='status':out({'state':'pending'});raise SystemExit
  if os.path.lexists(s):
   # A crash can interrupt rmtree after the durable pending marker.  Only
   # the original regular-file manifest is removable on recovery; any new
   # name, link, or directory leaves the marker pending and fails closed.
   d(s);names=set(os.listdir(s))
   if not names<={'bundle.zip','binding.json','listener-ready.json','listener-done.json'} or any(not os.path.isfile(os.path.join(s,x)) or os.path.islink(os.path.join(s,x)) for x in names):raise ValueError()
   if 'binding.json' in names and j(os.path.join(s,'binding.json'),512)!={'sha256':digest,'length':n}:raise ValueError()
   if 'listener-done.json' in names and j(os.path.join(s,'listener-done.json'),128)!={'served':False}:raise ValueError()
   if 'bundle.zip' in names:bundle(os.path.join(s,'bundle.zip'),n,digest)
   shutil.rmtree(s)
  save(dict(base,state='cleaned'));out({'state':'cleaned'});raise SystemExit
 if action=='status':out({'state':'absent'});raise SystemExit
 d(s);d(os.path.join(a,corr))
 if j(os.path.join(a,corr,'binding.json'),4096)!=b or j(os.path.join(s,'binding.json'),512)!={'sha256':digest,'length':n} or j(os.path.join(s,'listener-done.json'),128)!={'served':False}:raise ValueError()
 names=set(os.listdir(s))
 if names!={'bundle.zip','binding.json','listener-ready.json','listener-done.json'} or any(not os.path.isfile(os.path.join(s,x)) or os.path.islink(os.path.join(s,x)) for x in names):raise ValueError()
 bundle(os.path.join(s,'bundle.zip'),n,digest)
 save(dict(base,state='pending'));shutil.rmtree(s);save(dict(base,state='cleaned'));out({'state':'cleaned'})
except Exception:out({'state':'unknown'})
'''

# Read-only SYSTEM observation.  It refuses anything except the tree made by
# ``_create_script``: root with two empty real directories, no scheduled task,
# no bundle, no installer and no running sing-box/vpn-control runtime.
_REMOTE_GUEST_EMPTY = base._QGA + r'''import base64,json,re,time
sock,pid,ticks,corr=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if not live(sock,pid,ticks) or not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',corr):raise ValueError()
 ps="$ErrorActionPreference='Stop';$c='"+corr+"';$r='C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-update-fixture-'+$c;$n='VpnControlMcpFixtureHttp-'+$c;$task=Get-ScheduledTask -TaskPath '\\' -TaskName $n -ErrorAction SilentlyContinue;$procs=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name -in @('msiexec.exe','vpn-control.exe','sing-box.exe')});$boot=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name -in @('powershell.exe','pwsh.exe') -and $_.ProcessId -ne $PID});$state='unknown';try{$i=Get-Item -LiteralPath $r -Force -ErrorAction Stop;if(-not ($i -is [IO.DirectoryInfo]) -or (($i.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0)){throw 'ROOT'};$kids=@($i.GetFileSystemInfos());if($kids.Count -ne 2 -or @($kids|Where-Object {$_.Name -notin @('download','server-state') -or -not ($_ -is [IO.DirectoryInfo]) -or (($_.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0)}).Count -ne 0){throw 'CHILD'};if(@($kids|ForEach-Object {@($_.GetFileSystemInfos()).Count}|Where-Object {$_ -ne 0}).Count -ne 0){throw 'DESC'};$state='empty-created'}catch{$state='unknown'};$q=if($null -eq $task){'absent'}else{'present'};$p=if($procs.Count -eq 0){'absent'}else{'present'};$b=if($boot.Count -eq 0){'absent'}else{'present'};[Console]::Out.WriteLine((@{state=$state;task=$q;processes=$p;bootstrap=$b}|ConvertTo-Json -Compress))"
 enc=base64.b64encode(ps.encode('utf-16le')).decode();child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',enc],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(120):
  v=call(sock,'guest-exec-status',{'pid':child})
  if v.get('exited') is True:break
  if v.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 if v.get('exitcode')!=0 or v.get('out-truncated') is not False or v.get('err-truncated') is not False:raise ValueError()
 x=json.loads(base64.b64decode(v.get('out-data',''),validate=True))
 if not isinstance(x,dict) or set(x)!={'state','task','processes','bootstrap'} or x.get('state') not in ('empty-created','unknown') or x.get('task') not in ('absent','present') or x.get('processes') not in ('absent','present') or x.get('bootstrap') not in ('absent','present'):raise ValueError()
 out(x)
except Exception:out({'state':'unknown','task':'unknown','processes':'unknown'})
'''

# This runs as SYSTEM but can only unregister the one fixed task after the
# read-only diagnostic has bound its owner and action fingerprint.  It does
# not start, stop, or otherwise alter the download action.
_REMOTE_TASK_CLEANUP = base._QGA + r'''import base64,json,re,time
sock,pid,ticks,corr,sid,expected,mode=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if mode not in ('status','cleanup') or not live(sock,pid,ticks) or not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',corr) or not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+',sid) or not re.fullmatch(r'[0-9a-f]{64}',expected):raise ValueError()
 ps="$ErrorActionPreference='Stop';$n='VpnControlMcpFixtureHttp-"+corr+"';$sid='"+sid+"';$expected='"+expected+"';$t=Get-ScheduledTask -TaskPath '\\' -TaskName $n -ErrorAction SilentlyContinue;if($null -eq $t){[Console]::Out.WriteLine('{\"state\":\"absent\"}');exit 0};$u=[string]$t.Principal.UserId;if($u -match '^S-1-'){$actual=([Security.Principal.SecurityIdentifier]::new($u)).Value}else{$actual=([Security.Principal.NTAccount]::new($u)).Translate([Security.Principal.SecurityIdentifier]).Value};$a=@($t.Actions);if($actual -cne $sid -or $a.Count -ne 1){throw 'BINDING'};$h=[Security.Cryptography.SHA256]::Create();try{$got=([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($a[0].Execute+[char]0+$a[0].Arguments)))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()};if($got -cne $expected){throw 'ACTION'};$i=Get-ScheduledTaskInfo -TaskPath '\\' -TaskName $n -ErrorAction Stop;$rawResult=$i.LastTaskResult;if($null -eq $rawResult){throw 'TASK_INFO'};$typeCode=[Convert]::GetTypeCode($rawResult);if($typeCode -notin @([TypeCode]::SByte,[TypeCode]::Int16,[TypeCode]::Int32,[TypeCode]::Int64,[TypeCode]::Byte,[TypeCode]::UInt16,[TypeCode]::UInt32,[TypeCode]::UInt64)){throw 'TASK_INFO'};$taskResult=[int64]$rawResult;if($taskResult -lt -2147483648 -or $taskResult -gt 4294967295){throw 'TASK_INFO'};if($taskResult -lt 0){$taskResult+=4294967296};if($t.State -ne 'Ready' -or $taskResult -eq 0){throw 'TERMINAL'};$result='failed';if('"+mode+"' -ceq 'cleanup'){Unregister-ScheduledTask -TaskPath '\\' -TaskName $n -Confirm:$false;$result='cleaned'};[Console]::Out.WriteLine((@{state=$result}|ConvertTo-Json -Compress))"
 enc=base64.b64encode(ps.encode('utf-16le')).decode();child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',enc],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(120):
  v=call(sock,'guest-exec-status',{'pid':child})
  if v.get('exited') is True:break
  if v.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 if v.get('exitcode')!=0 or v.get('out-truncated') is not False or v.get('err-truncated') is not False:raise ValueError()
 x=json.loads(base64.b64decode(v.get('out-data',''),validate=True))
 if x not in ({'state':'absent'},{'state':'failed'},{'state':'cleaned'}):raise ValueError()
 out(x)
except Exception:out({'state':'unknown'})
'''


def _request(value: Mapping[str, Any]) -> None:
    if not isinstance(value, Mapping) or value != {"correlationId": _CORRELATION}:
        raise WindowsUpdateFixtureDownloadAbortError("Download abort requires its exact correlationId.")


def _directory(root: Path, create: bool) -> Path | None:
    path = root / _GROUP
    if not path.exists() and not path.is_symlink():
        if not create: return None
        path.mkdir(mode=0o700, parents=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise WindowsUpdateFixtureDownloadAbortError("Download abort journal is unsafe.")
    return path


def _receipt(root: Path, value: Mapping[str, Any], *, create: bool) -> bool:
    directory = _directory(root, create)
    if directory is None: return False
    path = directory / (_CORRELATION + ".json")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        if not create: return False
        raw = (json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n").encode()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        parent = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)); os.fsync(parent); os.close(parent)
        return True
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 8192:
            raise WindowsUpdateFixtureDownloadAbortError("Download abort receipt is unsafe.")
        return json.load(stream) == dict(value)


def _task_receipt(root: Path, value: Mapping[str, Any], *, create: bool) -> bool:
    """Separate durable intent for task deletion, never confused with host cleanup."""
    directory = _directory(root, create)
    if directory is None: return False
    path = directory / (_CORRELATION + ".task.json")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        if not create: return False
        raw = (json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n").encode()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        parent = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)); os.fsync(parent); os.close(parent)
        return True
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 8192: raise WindowsUpdateFixtureDownloadAbortError("Task cleanup receipt is unsafe.")
        return json.load(stream) == dict(value)


def _guest(config: Any, descriptor: tuple[Any, ...]) -> str:
    try:
        _env, socket, pid, ticks, _sid = descriptor
        raw = base._remote(config, _REMOTE_GUEST_EMPTY, (socket, str(pid), str(ticks), _CORRELATION), None, 90)
        observed = json.loads(raw) if raw is not None else None
        if observed == {"state": "empty-created", "task": "absent", "processes": "absent", "bootstrap": "absent"}: return "empty"
        if isinstance(observed, dict) and observed.get("task") == "present": return "task-present"
        if isinstance(observed, dict) and observed.get("bootstrap") == "present": return "bootstrap-present"
        if isinstance(observed, dict) and observed.get("processes") == "present": return "runtime-or-installer-present"
    except (OSError, ValueError, TypeError, base.WindowsMsiBasePrepareError): pass
    return "unknown"


def _guest_task_failed(config: Any, descriptor: tuple[Any, ...]) -> str:
    """Read the same immutable guest leaf while the exact failed task exists."""
    try:
        _env, socket, pid, ticks, _sid = descriptor
        raw = base._remote(config, _REMOTE_GUEST_EMPTY, (socket, str(pid), str(ticks), _CORRELATION), None, 90)
        observed = json.loads(raw) if raw is not None else None
        if observed == {"state": "empty-created", "task": "present", "processes": "absent", "bootstrap": "absent"}: return "failed-task-safe"
        if observed == {"state": "empty-created", "task": "absent", "processes": "absent", "bootstrap": "absent"}: return "task-absent-safe"
    except (OSError, ValueError, TypeError, base.WindowsMsiBasePrepareError): pass
    return "unknown"


def _task_admission(root: Path) -> tuple[str, tuple[Any, ...] | None]:
    """Bind the terminal failed task before making its one destructive call."""
    try:
        root_path, record, config, target = http._record(root, _CORRELATION)
        descriptor = base._descriptor(root_path)[2]
        core = http.large_transfer.read(root_path, _CORRELATION)
        if record.get("leaseId") != _LEASE or record["request"].get("sourceSha") != _SOURCE or core is None or core.get("phase") != "download-submitted": return "binding", None
        diagnostic = http.guest_download_diagnostic(root_path, {"correlationId": _CORRELATION})
        if not (diagnostic.get("phase") in {"task-failed", "task-absent"} and diagnostic.get("download") == "absent" and diagnostic.get("listener") == "stopped" and diagnostic.get("listenerServed") == "false"):
            return "diagnostic-" + str(diagnostic.get("phase", "unknown")), None
        guest = _guest_task_failed(config, descriptor)
        if diagnostic.get("phase") == "task-failed" and guest != "failed-task-safe": return "guest-not-safe", None
        if diagnostic.get("phase") == "task-absent" and guest != "task-absent-safe": return "guest-not-safe", None
        _state, _served, port = http._listener_forensic(root_path, config, target, _CORRELATION, record["routeNonce"])
        if type(port) is not int: return "endpoint", None
        # A submitted task must be compared against the immutable command it
        # actually registered.  The HTTP helper selects that frozen script for
        # its one historical correlation and the current builder elsewhere.
        script = http._submitted_download_script(correlation_id=_CORRELATION, sid=descriptor[4], sha256=record["bundleSha256"], length=record["bundleSize"], port=port, path="/" + record["routeNonce"])
        action = http._task_action_fingerprint(*http._download_task_action(script))
        evidence = {"correlationId": _CORRELATION, "task": "failed-cleanup", "actionSha256": action,
                    "guestGeneration": {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]}}
        if diagnostic.get("phase") == "task-absent":
            return ("cleaned", (root_path, record, config, target, descriptor)) if _task_receipt(root_path, evidence, create=False) else ("task-absent-unbound", None)
        return "ready", (root_path, record, config, target, descriptor, evidence)
    except (AttributeError, OSError, ValueError, KeyError, TypeError, http.WindowsUpdateFixtureHttpStageError, base.WindowsMsiBasePrepareError):
        return "unknown", None


def task_cleanup_status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    _request(value); phase, _details = _task_admission(Path(root).resolve(strict=True))
    return {"state": "diagnosed", "correlationId": _CORRELATION, "phase": phase,
            "cleanupAllowed": phase == "ready", **{k:v for k,v in _UNKNOWN.items() if k != "state"}}


def task_cleanup(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    _request(value)
    try:
        phase, details = _task_admission(Path(root).resolve(strict=True))
        if phase == "cleaned": return {"state":"cleaned", "correlationId":_CORRELATION, **{k:v for k,v in _UNKNOWN.items() if k != "state"}}
        if phase != "ready" or details is None: return {**_UNKNOWN, "correlationId": _CORRELATION}
        root_path, _record, config, _target, descriptor, evidence = details
        if not _task_receipt(root_path, evidence, create=True): return {**_UNKNOWN, "correlationId": _CORRELATION}
        raw = base._remote(config, _REMOTE_TASK_CLEANUP, (descriptor[1], str(descriptor[2]), str(descriptor[3]), _CORRELATION, descriptor[4], evidence["actionSha256"], "cleanup"), None, 90)
        observed = json.loads(raw) if raw is not None else None
        if observed != {"state":"cleaned"}: return {**_UNKNOWN, "correlationId": _CORRELATION}
        return {"state":"cleaned", "correlationId":_CORRELATION, **{k:v for k,v in _UNKNOWN.items() if k != "state"}}
    except (AttributeError, OSError, ValueError, KeyError, TypeError, http.WindowsUpdateFixtureHttpStageError, base.WindowsMsiBasePrepareError):
        return {**_UNKNOWN, "correlationId": _CORRELATION}


def _host(root: Path, record: Mapping[str, Any], descriptor: tuple[Any, ...], config: Any, target: Any, action: str) -> str:
    try:
        binding = base64.b64encode(json.dumps(http._authority_binding(record, descriptor), sort_keys=True, separators=(",", ":")).encode()).decode()
        raw = base._remote(config, _REMOTE_ABORT, (str(target.fixture_transfer_root), _CORRELATION, record["bundleSha256"], str(record["bundleSize"]), binding, action), None, 45)
        value = json.loads(raw) if raw is not None else None
        return value["state"] if value in ({"state": "absent"}, {"state": "pending"}, {"state": "cleaned"}) else "unknown"
    except (OSError, ValueError, TypeError, base.WindowsMsiBasePrepareError): return "unknown"


def _campaign_record(root: Path, record: Mapping[str, Any], descriptor: tuple[Any, ...]) -> Mapping[str, Any] | None:
    """Read the full validated lease under its own lock.

    ``lease.inspect`` intentionally projects correlation and terminal evidence
    away for public status.  Recovery needs those exact local receipts, so it
    uses the lease module's validated private reader while holding its lock.
    """
    directory, lock = lease._locked(root)
    try:
        current = lease._active(directory)
        if current is None:
            current = lease._closed(directory, _LEASE)
        if not isinstance(current, Mapping): return None
        expected = base._campaign_identity({**record["request"], "correlationId": _LEASE}, descriptor)
        if current.get("identity") != expected: return None
        return dict(current)
    finally:
        os.close(lock)


def _retired_binding(root: Path) -> tuple[Path, dict[str, Any], Any, Any, tuple[Any, ...]]:
    """Load immutable bindings after the stage role is pending or released."""
    root_path = Path(root).resolve(strict=True); record = http._read(root_path, _CORRELATION)
    if record is None: raise WindowsUpdateFixtureDownloadAbortError("Download intent is absent.")
    http._artifact(Path(record["bundlePath"]), record["bundleSha256"], record["bundleSize"])
    request = http._request(record["request"]); config, target, descriptor = base._descriptor(root_path)
    pair = http.stage.public._admit_pair(root_path, request["sourceSha"], request["fixtureReceiptArtifactId"], request["baseMsiArtifactId"], request["targetMsiArtifactId"])
    intent = http.stage._read_intent(root_path, _CORRELATION); core = http.large_transfer.read(root_path, _CORRELATION)
    if (record.get("leaseId") != _LEASE or request.get("sourceSha") != _SOURCE or intent is None
            or intent.get("request") != request or intent.get("leaseId") != _LEASE
            or intent.get("sourceFingerprint") != pair.get("sourceFingerprint")
            or core is None or core.get("phase") != "download-submitted"
            or core.get("binding") != http._large_binding(record, descriptor)):
        raise WindowsUpdateFixtureDownloadAbortError("Download binding changed.")
    return root_path, record, config, target, descriptor


def _admission(root: Path) -> tuple[str, tuple[Any, ...] | None]:
    try:
        fallback = False
        try:
            root_path, record, config, target = http._record(root, _CORRELATION, campaign_mode="stage-or-idle")
            descriptor = base._descriptor(root_path)[2]
        except (OSError, ValueError, KeyError, TypeError, http.WindowsUpdateFixtureHttpStageError, base.WindowsMsiBasePrepareError):
            root_path, record, config, target, descriptor = _retired_binding(root)
            fallback = True
        core = http.large_transfer.read(root_path, _CORRELATION)
        if record.get("leaseId") != _LEASE or record["request"].get("sourceSha") != _SOURCE: return "binding", None
        if core is None or core.get("phase") != "download-submitted": return "shared-phase", None
        evidence = {"correlationId": _CORRELATION, "leaseId": _LEASE, "sourceSha": _SOURCE,
                    "bundleSha256": record["bundleSha256"], "sourceFingerprint": record["sourceFingerprint"],
                    "guestGeneration": {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]},
                    "listener": "stopped-unserved", "guestLeaf": "retained-empty-created", "task": "absent", "runtimeAndInstaller": "absent"}
        digest = hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        preclean = _receipt(root_path, evidence, create=False)
        marker = _host(root_path, record, descriptor, config, target, "status") if preclean else "absent"
        campaign = _campaign_record(root_path, record, descriptor)
        if campaign is None: return "campaign", None
        if fallback and not (campaign.get("state") == "pending-finish" or (
                campaign.get("state") == "active" and campaign.get("role") is None
                and campaign.get("lastOutcome") == "failed-cleaned"
                and campaign.get("lastEvidenceSha256") == digest)):
            return "retired-binding-invalid", None
        guest = _guest(config, descriptor)
        if guest != "empty": return "guest-" + guest, None
        if (campaign.get("state") == "active" and campaign.get("role") is None
                and campaign.get("lastOutcome") == "failed-cleaned" and campaign.get("lastEvidenceSha256") == digest):
            return ("retired", (root_path, record, config, target, descriptor, evidence, digest)) if preclean and marker == "cleaned" else ("retired-marker", None)
        if campaign.get("state") == "pending-finish":
            return ("pending-finish", (root_path, record, config, target, descriptor, evidence, digest)) if preclean and marker == "cleaned" else ("pending-finish-marker", None)
        if not (campaign.get("state") == "role-active" and campaign.get("role") == "stage" and campaign.get("correlationId") == _CORRELATION):
            return "campaign", None
        # Once the host leaf is durably gone, its old listener receipt is no
        # longer readable; the immutable local receipt and cleaned marker are
        # the only safe recovery evidence.
        if preclean and marker == "cleaned":
            return "ready-cleaned", (root_path, record, config, target, descriptor, evidence, digest)
        listener, served, _port = http._listener_forensic(root_path, config, target, _CORRELATION, record["routeNonce"])
        if (listener, served) != ("stopped", "false"): return "listener-" + listener, None
        if marker == "cleaned": return "ready-cleaned", (root_path, record, config, target, descriptor, evidence, digest)
        if marker in {"absent", "pending"}: return "ready" if marker == "absent" else "ready-pending", (root_path, record, config, target, descriptor, evidence, digest)
    except (AttributeError, OSError, ValueError, KeyError, TypeError, http.WindowsUpdateFixtureHttpStageError, base.WindowsMsiBasePrepareError, lease.Cp117LeaseError): pass
    return "unknown", None


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    _request(value); phase, _details = _admission(Path(root).resolve(strict=True))
    return {"state": "diagnosed", "correlationId": _CORRELATION, "phase": phase,
            "abortAllowed": phase in {"ready", "ready-pending", "ready-cleaned"}, **{k:v for k,v in _UNKNOWN.items() if k != "state"}}


def abort(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    _request(value)
    try:
        task_phase, _task_details = _task_admission(Path(root).resolve(strict=True))
        if task_phase != "cleaned": return {**_UNKNOWN, "correlationId": _CORRELATION}
        phase, details = _admission(Path(root).resolve(strict=True))
        if phase == "retired" and details is not None:
            return {"state": "retired", "correlationId": _CORRELATION, **{k:v for k,v in _UNKNOWN.items() if k != "state"}}
        if phase == "pending-finish" and details is not None:
            root_path, _record, config, target, _descriptor, _evidence, _digest = details
            if lease.reconcile(root_path, _LEASE, base._campaign_remote(config, target)).get("state") != "active":
                return {**_UNKNOWN, "correlationId": _CORRELATION}
            phase, details = _admission(root_path)
            if phase == "retired" and details is not None:
                return {"state": "retired", "correlationId": _CORRELATION, **{k:v for k,v in _UNKNOWN.items() if k != "state"}}
        if phase not in {"ready", "ready-pending", "ready-cleaned"} or details is None: return {**_UNKNOWN, "correlationId": _CORRELATION}
        root_path, record, config, target, descriptor, evidence, digest = details
        if not _receipt(root_path, evidence, create=True): return {**_UNKNOWN, "correlationId": _CORRELATION}
        if phase != "ready-cleaned" and _host(root_path, record, descriptor, config, target, "cleanup") != "cleaned": return {**_UNKNOWN, "correlationId": _CORRELATION}
        finished = lease.finish_role(root_path, _LEASE, "stage", _CORRELATION, digest, "failed-cleaned", base._campaign_remote(config, target))
        if finished.get("state") != "active": return {**_UNKNOWN, "correlationId": _CORRELATION}
        return {"state": "retired", "correlationId": _CORRELATION, "cleanupReceiptSha256": digest, **{k:v for k,v in _UNKNOWN.items() if k != "state"}}
    except (AttributeError, OSError, ValueError, KeyError, TypeError, http.WindowsUpdateFixtureHttpStageError, base.WindowsMsiBasePrepareError, lease.Cp117LeaseError):
        return {**_UNKNOWN, "correlationId": _CORRELATION}


def workflow(root: Path | str, action: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if action == "status": return status(root, inputs)
    if action == "abort": return abort(root, inputs)
    if action == "task-cleanup-status": return task_cleanup_status(root, inputs)
    if action == "task-cleanup": return task_cleanup(root, inputs)
    raise WindowsUpdateFixtureDownloadAbortError("Unknown download abort action.")

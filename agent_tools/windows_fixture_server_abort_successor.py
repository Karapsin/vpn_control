"""One-shot CP117 successor for a reaped server-abort QGA child.

The original server-start and abort submission are historical facts.  This
adapter never retries either one.  It can only remove their exact failed
original-user task after preserving a new, local intent and proving the old
QGA child was reaped, the server is gone, and the campaign still owns the
server-start role.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping

from . import windows_cp117_lease as lease
from . import windows_msi_base_prepare as base
from . import windows_update_fixture_server as server


class WindowsFixtureServerAbortSuccessorError(ValueError):
    pass


_SERVER = "2c438d90-9a77-4acd-b4d7-ab354b85a04a"
_ABORT = "710f7aaa-f92d-4fef-9f7c-57cf6e405624"
_HISTORICAL_SUCCESSOR = "bbc75e43-e220-44e8-ab60-ddc3876ba5fb"
_REPLACEMENT_SERVER = "316e6189-5be0-4ea0-bca1-a3905816d815"
_DIR = ".rag_index/windows-fixture-server-abort-successor"
_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_UNKNOWN = {"state": "unknown", "replayAllowed": False, "nativeActionAllowed": False,
            "productAction": False}

# The guest-side journal is deliberately small and has one mutable operation:
# unregistering the fixed scheduled task after its original owner/action hash
# has been read.  It records the child before the response can be lost.
_REMOTE = base._QGA + r'''import base64,json,os,re,stat,sys,time
root,server_corr,old_corr,new_corr,sock,pid,ticks,sid,action,python_path,args64=sys.argv[1:]
def out(v):print(json.dumps(v,sort_keys=True,separators=(',',':')))
def regular(path,limit):
 i=os.lstat(path)
 if not stat.S_ISREG(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o600 or not 0<i.st_size<=limit:raise ValueError()
 with open(path,encoding='utf-8') as stream:return json.load(stream)
def directory(path):
 i=os.lstat(path)
 if not stat.S_ISDIR(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o700:raise ValueError()
def save(path,value):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'w',encoding='utf-8') as f:json.dump(value,f,sort_keys=True,separators=(',',':'));f.write('\n');f.flush();os.fsync(f.fileno())
 parent=os.open(os.path.dirname(path),os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(parent);os.close(parent)
try:
 if action not in ('start','status','verify') or not live(sock,pid,ticks) or any(not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',x) for x in (server_corr,old_corr,new_corr)) or not python_path or not base64.b64decode(args64,validate=True):raise ValueError()
 job=os.path.join(root,'windows-cp117','windows-update-fixture-server',server_corr);directory(job)
 old=os.path.join(job,'cleanup-'+old_corr);directory(old);binding=regular(os.path.join(old,'binding.json'),16384);dispatch=regular(os.path.join(old,'dispatch.json'),16384)
 if set(binding)!={'leaseId','role','roleCorrelationId','serverCorrelationId','cleanupCorrelationId','socketPath','qemuPid','startTicks','commandSha256','verifyCommandSha256','dispatchMode'} or binding.get('role')!='server-start' or binding.get('roleCorrelationId')!=server_corr or binding.get('serverCorrelationId')!=server_corr or binding.get('cleanupCorrelationId')!=old_corr or binding.get('socketPath')!=sock or binding.get('qemuPid')!=int(pid) or binding.get('startTicks')!=int(ticks) or not re.fullmatch(r'[0-9a-f]{64}',str(binding.get('commandSha256'))) or not re.fullmatch(r'[0-9a-f]{64}',str(binding.get('verifyCommandSha256'))) or binding.get('dispatchMode')!='dispatched' or set(dispatch)!={'pid'} or type(dispatch['pid']) is not int or dispatch['pid']<=0:raise ValueError()
 task='VpnControlMcpFixtureServer-'+server_corr
 # A reaped QGA child is not enough.  Take a new SYSTEM observation of the
 # fixed task and every process command line containing its correlation.  The
 # latter is also the listener check because the fixed server owns its socket.
 check="$ErrorActionPreference='Stop';$t=Get-ScheduledTask -TaskPath '\\' -TaskName '"+task+"' -ErrorAction SilentlyContinue;$old=Get-CimInstance Win32_Process -Filter ('ProcessId='+[string]"+str(dispatch['pid'])+") -ErrorAction SilentlyContinue;$a=@($t.Actions);$expected=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+args64+"'));$p=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.ProcessId -ne $PID -and $_.CommandLine -like '*"+server_corr+"*'});if($null -ne $old -or $null -eq $t -or $a.Count -ne 1 -or $a[0].Execute -cne '"+python_path.replace("'","''")+"' -or $a[0].Arguments -cne $expected -or $t.State -ne 'Ready' -or [int64](Get-ScheduledTaskInfo -TaskPath '\\' -TaskName '"+task+"').LastTaskResult -eq 0 -or $p.Count -ne 0){exit 7}"
 def invoke(ps):
  encoded=base64.b64encode(ps.encode('utf-16le')).decode();child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
  if type(child) is not int or child<=0:raise ValueError()
  for _ in range(120):
   result=call(sock,'guest-exec-status',{'pid':child})
   if result.get('exited') is True:return result
   if result.get('exited') is not False:raise ValueError()
   time.sleep(.25)
  raise ValueError()
 group=os.path.join(job,'successor-'+new_corr);marker=os.path.join(group,'binding.json')
 if os.path.exists(marker):
  saved=regular(marker,4096)
  if saved!={'serverCorrelationId':server_corr,'priorCleanupCorrelationId':old_corr,'successorCleanupCorrelationId':new_corr,'socketPath':sock,'qemuPid':int(pid),'startTicks':int(ticks),'originalSid':sid}:raise ValueError()
  terminal=os.path.join(group,'terminal.json')
  if os.path.exists(terminal):
   result=regular(terminal,4096)
   if set(result)!={'exitcode'} or type(result['exitcode']) is not int:raise ValueError()
   # A lost status response must not make the next observer poll a QGA child
   # that the guest agent has already reaped.
   if action!='verify':out({'state':'terminal','exitcode':result.get('exitcode')});raise SystemExit(0)
  else:
   child=regular(os.path.join(group,'dispatch.json'),4096);result=call(sock,'guest-exec-status',{'pid':child['pid']})
   if result.get('exited') is False:out({'state':'running'});raise SystemExit(0)
   if result.get('exited') is not True or type(result.get('exitcode')) is not int:raise ValueError()
   save(terminal,{'exitcode':result['exitcode']})
  verify="$ErrorActionPreference='Stop';$t=Get-ScheduledTask -TaskPath '\\' -TaskName '"+task+"' -ErrorAction SilentlyContinue;$p=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.ProcessId -ne $PID -and $_.CommandLine -like '*"+server_corr+"*'});if($null -ne $t -or $p.Count -ne 0){exit 9}"
  # Return immediately after the immutable terminal is saved.  A fresh
  # verifier runs only in the next invocation, never between child reaping
  # and reporting its result.
  if action!='verify':out({'state':'terminal','exitcode':result.get('exitcode')});raise SystemExit(0)
  fresh=invoke(verify)
  if fresh.get('exitcode')!=0:raise ValueError()
  out({'state':'terminal','exitcode':result.get('exitcode')});raise SystemExit(0)
 if invoke(check).get('exitcode')!=0:out({'state':'blocked','reason':'server-or-task-not-safe'});raise SystemExit(0)
 if action!='start':out({'state':'ready'});raise SystemExit(0)
 os.mkdir(group,0o700)
 parent=os.open(job,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(parent);os.close(parent)
 saved={'serverCorrelationId':server_corr,'priorCleanupCorrelationId':old_corr,'successorCleanupCorrelationId':new_corr,'socketPath':sock,'qemuPid':int(pid),'startTicks':int(ticks),'originalSid':sid}
 save(marker,saved)
 ps="$ErrorActionPreference='Stop';$n='"+task+"';$sid='"+sid+"';$t=Get-ScheduledTask -TaskPath '\\' -TaskName $n -ErrorAction Stop;$a=@($t.Actions);$expected=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+args64+"'));$u=[string]$t.Principal.UserId;if($u -match '^S-1-'){$actual=([Security.Principal.SecurityIdentifier]::new($u)).Value}else{$actual=([Security.Principal.NTAccount]::new($u)).Translate([Security.Principal.SecurityIdentifier]).Value};if($actual -cne $sid -or $a.Count -ne 1 -or $a[0].Execute -cne '"+python_path.replace("'","''")+"' -or $a[0].Arguments -cne $expected){throw 'OWNER_OR_ACTION'};$i=Get-ScheduledTaskInfo -TaskPath '\\' -TaskName $n -ErrorAction Stop;if($t.State -ne 'Ready' -or [int64]$i.LastTaskResult -eq 0){throw 'TERMINAL'};Unregister-ScheduledTask -TaskPath '\\' -TaskName $n -Confirm:$false;$gone=Get-ScheduledTask -TaskPath '\\' -TaskName $n -ErrorAction SilentlyContinue;if($null -ne $gone){throw 'PRESENT'}"
 encoded=base64.b64encode(ps.encode('utf-16le')).decode();child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 save(os.path.join(group,'dispatch.json'),{'pid':child})
 out({'state':'submitted'})
except SystemExit:raise
except Exception:out({'state':'unknown'})
'''


_REMOTE_JOURNAL_DIAGNOSTIC = base._QGA + r'''import json,os,re,stat,sys
root,server_corr,old_corr,new_corr,sock,pid,ticks=sys.argv[1:]
def out(v):print(json.dumps(v,sort_keys=True,separators=(',',':')))
def kind(path):
 try:i=os.lstat(path)
 except FileNotFoundError:return 'absent'
 if not stat.S_ISREG(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o600 or not 0<i.st_size<=4096:return 'mismatch'
 return 'present'
try:
 if not live(sock,pid,ticks) or any(not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',x) for x in (server_corr,old_corr,new_corr)):raise ValueError()
 job=os.path.join(root,'windows-cp117','windows-update-fixture-server',server_corr)
 group=os.path.join(job,'successor-'+new_corr)
 info=os.lstat(group)
 if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 binding=kind(os.path.join(group,'binding.json'));dispatch=kind(os.path.join(group,'dispatch.json'));terminal=kind(os.path.join(group,'terminal.json'))
 exitcode='absent';code=None
 if terminal=='present':
  with open(os.path.join(group,'terminal.json'),encoding='utf-8') as stream:value=json.load(stream)
  if set(value)=={'exitcode'} and type(value['exitcode']) is int and 0<=value['exitcode']<=65535:
   code=value['exitcode'];exitcode='zero' if code==0 else 'nonzero'
  else:exitcode='invalid'
 out({'state':'observed','binding':binding,'dispatch':dispatch,'terminal':terminal,'terminalResult':exitcode,'terminalExitCode':code})
except Exception:out({'state':'unknown'})
'''


def _request(value: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {"successorCleanupCorrelationId"}:
        raise WindowsFixtureServerAbortSuccessorError("Exact successor cleanup correlation is required.")
    correlation = value.get("successorCleanupCorrelationId")
    if (not isinstance(correlation, str) or not _UUID.fullmatch(correlation)
            or correlation in {_SERVER, _ABORT}):
        raise WindowsFixtureServerAbortSuccessorError("Successor cleanup correlation is invalid.")
    return {"successorCleanupCorrelationId": correlation}


def _path(root: Path, correlation: str) -> Path:
    return root / _DIR / (correlation + ".json")


def _read(root: Path, correlation: str) -> dict[str, Any] | None:
    try: fd = os.open(_path(root, correlation), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError: return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 4096):
            raise WindowsFixtureServerAbortSuccessorError("Successor cleanup intent is unsafe.")
        value = json.load(stream)
    return value if isinstance(value, dict) else None


def _reserve(root: Path, record: Mapping[str, Any]) -> str:
    directory = root / _DIR; directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise WindowsFixtureServerAbortSuccessorError("Successor cleanup journal is unsafe.")
    path = _path(root, record["request"]["successorCleanupCorrelationId"])
    prior = _read(root, record["request"]["successorCleanupCorrelationId"])
    if prior is not None:
        if prior != dict(record):
            raise WindowsFixtureServerAbortSuccessorError("Successor cleanup intent changed.")
        return "existing"
    raw = (json.dumps(dict(record), sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    parent = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try: os.fsync(parent)
    finally: os.close(parent)
    return "created"


def _terminal_path(root: Path, correlation: str) -> Path:
    return root / _DIR / (correlation + ".terminal.json")


def _terminal(root: Path, correlation: str) -> dict[str, Any] | None:
    try: fd = os.open(_terminal_path(root, correlation), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError: return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 1024):
            raise WindowsFixtureServerAbortSuccessorError("Successor cleanup terminal receipt is unsafe.")
        value = json.load(stream)
    if (not isinstance(value, dict) or set(value) != {"exitcode"}
            or type(value["exitcode"]) is not int or not 0 <= value["exitcode"] <= 65535):
        raise WindowsFixtureServerAbortSuccessorError("Successor cleanup terminal receipt is invalid.")
    return value


def _save_terminal(root: Path, correlation: str, value: Mapping[str, Any]) -> None:
    expected = {"exitcode": value.get("exitcode")}
    if type(expected["exitcode"]) is not int or not 0 <= expected["exitcode"] <= 65535:
        raise WindowsFixtureServerAbortSuccessorError("Successor cleanup terminal result is invalid.")
    prior = _terminal(root, correlation)
    if prior is not None:
        if prior != expected: raise WindowsFixtureServerAbortSuccessorError("Successor cleanup terminal changed.")
        return
    path = _terminal_path(root, correlation)
    raw = (json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try: os.fsync(parent)
    finally: os.close(parent)


def _admission(root: Path) -> tuple[Any, Any, tuple[Any, ...], dict[str, Any]]:
    intent = server._read_intent(root, _SERVER); prior = server._read_cleanup_intent(root, _ABORT)
    if intent is None or prior is None or prior.get("mode") != "abort":
        raise WindowsFixtureServerAbortSuccessorError("Original server cleanup intent is unavailable.")
    request = server._request(intent.get("request", {})); cleanup = server._cleanup_request(prior.get("request", {}))
    if (cleanup.get("serverCorrelationId") != _SERVER or request.get("serverCorrelationId") != _SERVER
            or prior.get("serverRequest") != request):
        raise WindowsFixtureServerAbortSuccessorError("Server cleanup correlation changed.")
    config, target, descriptor = base._descriptor(root); env, socket, pid, ticks, sid = descriptor
    if (env != "windows-cp117" or any(prior.get(k) != v for k, v in (("socketPath", socket), ("qemuPid", pid), ("startTicks", ticks), ("originalSid", sid)))):
        raise WindowsFixtureServerAbortSuccessorError("Server cleanup guest generation changed.")
    directory, lock = lease._locked(root)
    try:
        current = lease._active(directory); expected = base._campaign_identity({**request, "correlationId": request["leaseId"]}, descriptor)
        if (current is None or current.get("identity") != expected or current.get("state") != "role-active"
                or current.get("role") != "server-start" or current.get("correlationId") != _SERVER
                or current.get("server") != "starting" or current.get("credentials") != "ready"):
            raise WindowsFixtureServerAbortSuccessorError("CP117 server-start role is no longer held.")
        if not lease._remote_confirm(base._campaign_remote(config, target), "status", current, None):
            raise WindowsFixtureServerAbortSuccessorError("CP117 server-start remote role is no longer held.")
    finally: os.close(lock)
    return config, target, descriptor, request


def _observe(root: Path, config: Any, target: Any, descriptor: tuple[Any, ...], successor: str, action: str) -> dict[str, Any] | None:
    _env, socket, pid, ticks, sid = descriptor
    try:
        intent = server._read_intent(root, _SERVER)
        if not isinstance(intent, Mapping) or not isinstance(intent.get("pythonPath"), str): return None
        descriptor_tls = server._private_tls_descriptor(root, intent["request"])
        arguments = server._launch_arguments(intent["request"], descriptor_tls)
        encoded_arguments = base64.b64encode(arguments.encode()).decode("ascii")
        raw = base._remote(config, _REMOTE, (str(target.fixture_transfer_root), _SERVER, _ABORT, successor,
                                              socket, str(pid), str(ticks), sid, action, intent["pythonPath"], encoded_arguments), None, 60)
        result = json.loads(raw) if raw is not None else None
    except (OSError, ValueError, TypeError, base.WindowsMsiBasePrepareError): return None
    return result if isinstance(result, dict) else None


def _unknown(correlation: str) -> dict[str, Any]:
    return {**_UNKNOWN, "successorCleanupCorrelationId": correlation}


def _digest(request: Mapping[str, str], descriptor: tuple[Any, ...], exitcode: int) -> str:
    if type(exitcode) is not int or not 0 <= exitcode <= 65535:
        raise WindowsFixtureServerAbortSuccessorError("Successor terminal code is invalid.")
    return hashlib.sha256(json.dumps({"request": request, "guest": descriptor[1:], "exitcode": exitcode},
                                     sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _completed(root: Path, lease_id: str, digest: str) -> bool:
    directory, lock = lease._locked(root)
    try:
        current = lease._active(directory)
        return (isinstance(current, Mapping) and current.get("state") == "active"
                and current.get("role") is None and current.get("server") == "stopped"
                and current.get("lastOutcome") == "failed-cleaned"
                and current.get("lastEvidenceSha256") == digest
                and current.get("identity", {}).get("leaseId") == lease_id)
    finally: os.close(lock)


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    request = _request(value); correlation = request["successorCleanupCorrelationId"]
    try:
        root_path = Path(root).resolve(strict=True); config, target, descriptor, server_request = _admission(root_path)
        record = {"version": 1, "request": request, "serverCorrelationId": _SERVER,
                  "priorCleanupCorrelationId": _ABORT, "serverRequest": server_request,
                  "guestGeneration": {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]}}
        if _reserve(root_path, record) != "created": return _unknown(correlation)
        observed = _observe(root_path, config, target, descriptor, correlation, "start")
        return ({"state": "submitted", "successorCleanupCorrelationId": correlation, **{k:v for k,v in _UNKNOWN.items() if k != "state"}}
                if observed == {"state": "submitted"} else _unknown(correlation))
    except (OSError, ValueError, KeyError, TypeError, WindowsFixtureServerAbortSuccessorError, lease.Cp117LeaseError, base.WindowsMsiBasePrepareError):
        return _unknown(correlation)


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    request = _request(value); correlation = request["successorCleanupCorrelationId"]
    try:
        root_path = Path(root).resolve(strict=True)
        # A response loss during finish leaves only the lease transition
        # pending.  Reconcile that exact transition; it never reruns cleanup.
        stored_terminal = _terminal(root_path, correlation)
        if stored_terminal is not None:
            intent = server._read_intent(root_path, _SERVER)
            if not isinstance(intent, Mapping): return _unknown(correlation)
            server_request = server._request(intent.get("request", {}))
            config, target, descriptor = base._descriptor(root_path)
            digest = _digest(request, descriptor, stored_terminal["exitcode"])
            record = _read(root_path, correlation)
            if record != {"version": 1, "request": request, "serverCorrelationId": _SERVER,
                           "priorCleanupCorrelationId": _ABORT, "serverRequest": server_request,
                           "guestGeneration": {"socketPath": descriptor[1], "qemuPid": descriptor[2],
                                               "startTicks": descriptor[3]}}:
                return _unknown(correlation)
            if _completed(root_path, server_request["leaseId"], digest):
                return {"state":"cleaned", "successorCleanupCorrelationId":correlation, "cleanupReceiptSha256":digest, **{k:v for k,v in _UNKNOWN.items() if k != "state"}}
            directory, lock = lease._locked(root_path)
            try: current = lease._active(directory)
            finally: os.close(lock)
            if (isinstance(current, Mapping) and current.get("state") == "pending-finish"
                    and current.get("identity", {}).get("leaseId") == server_request["leaseId"]
                    and current.get("lastOutcome") == "failed-cleaned"
                    and current.get("lastEvidenceSha256") == digest
                    and current.get("server") == "stopped"):
                lease.reconcile(root_path, server_request["leaseId"], base._campaign_remote(config, target))
                if _completed(root_path, server_request["leaseId"], digest):
                    return {"state":"cleaned", "successorCleanupCorrelationId":correlation, "cleanupReceiptSha256":digest, **{k:v for k,v in _UNKNOWN.items() if k != "state"}}
        config, target, descriptor, server_request = _admission(root_path)
        record = _read(root_path, correlation)
        expected = {"version": 1, "request": request, "serverCorrelationId": _SERVER,
                    "priorCleanupCorrelationId": _ABORT, "serverRequest": server_request,
                    "guestGeneration": {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]}}
        if record != expected: return _unknown(correlation)
        terminal = _terminal(root_path, correlation)
        observed = _observe(root_path, config, target, descriptor, correlation, "verify" if terminal is not None else "status")
        if observed == {"state": "running"}: return {"state":"running", "successorCleanupCorrelationId":correlation, **{k:v for k,v in _UNKNOWN.items() if k != "state"}}
        if (isinstance(observed, dict) and set(observed) == {"state", "exitcode"}
                and observed["state"] == "terminal" and type(observed["exitcode"]) is int
                and 0 <= observed["exitcode"] <= 65535):
            terminal_code = observed["exitcode"]
            # A terminal receipt still needs a fresh observation from the fixed
            # remote journal.  The status program reports terminal only after
            # the task is absent; no local receipt can manufacture that fact.
            if terminal is None:
                _save_terminal(root_path, correlation, observed)
                # The terminal QGA result is durable before this fresh verifier
                # runs; later status calls cannot query a reaped child again.
                observed = _observe(root_path, config, target, descriptor, correlation, "verify")
                if observed != {"state": "terminal", "exitcode": terminal_code}:
                    return _unknown(correlation)
            digest = _digest(request, descriptor, terminal_code)
            # The original server-start role remains held until the successor
            # has both a durable terminal and a fresh SYSTEM absence proof.
            # `finish_role` persists the reviewed terminal evidence remotely
            # before releasing the next server-start admission.
            finished = lease.finish_role(root_path, server_request["leaseId"], "server-start", _SERVER,
                                         digest, "failed-cleaned", base._campaign_remote(config, target))
            if finished.get("state") != "active": return _unknown(correlation)
            return {"state":"cleaned", "successorCleanupCorrelationId":correlation, "cleanupReceiptSha256":digest, **{k:v for k,v in _UNKNOWN.items() if k != "state"}}
    except (OSError, ValueError, KeyError, TypeError, WindowsFixtureServerAbortSuccessorError, lease.Cp117LeaseError, base.WindowsMsiBasePrepareError): pass
    return _unknown(correlation)


def diagnose(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read the exact successor journal without polling a reaped QGA child."""
    request = _request(value); correlation = request["successorCleanupCorrelationId"]
    common = {"successorCleanupCorrelationId": correlation, "replayAllowed": False,
              "nativeActionAllowed": False, "productAction": False}
    try:
        root_path = Path(root).resolve(strict=True)
        if _read(root_path, correlation) is None:
            return {"state": "diagnosed", "phase": "local-intent", **common}
        config, target, descriptor, _ = _admission(root_path)
        raw = base._remote(config, _REMOTE_JOURNAL_DIAGNOSTIC,
                           (str(target.fixture_transfer_root), _SERVER, _ABORT, correlation,
                            descriptor[1], str(descriptor[2]), str(descriptor[3])), None, 30)
        result = json.loads(raw) if raw is not None else None
        if (isinstance(result, dict) and set(result) == {"state", "binding", "dispatch", "terminal", "terminalResult", "terminalExitCode"}
                and result.get("state") == "observed" and all(result.get(k) in {"absent", "present", "mismatch"}
                                                         for k in ("binding", "dispatch", "terminal"))
                and result.get("terminalResult") in {"absent", "zero", "nonzero", "invalid"}
                and ((result["terminalExitCode"] is None and result["terminalResult"] in {"absent", "invalid"})
                     or (type(result["terminalExitCode"]) is int and 0 <= result["terminalExitCode"] <= 65535
                         and result["terminalResult"] == ("zero" if result["terminalExitCode"] == 0 else "nonzero")))):
            return {**result, **common}
        return {"state": "diagnosed", "phase": "remote-journal", **common}
    except (OSError, ValueError, KeyError, TypeError, lease.Cp117LeaseError,
            base.WindowsMsiBasePrepareError, WindowsFixtureServerAbortSuccessorError):
        return {"state": "diagnosed", "phase": "admission", **common}


def allows_server_restart(root: Path | str, prior_correlation: str, lease_id: str,
                          prior_intent: Mapping[str, Any]) -> bool:
    """Admit this failed server's successor only after fresh absence proof."""
    if prior_correlation != _SERVER or not _UUID.fullmatch(lease_id):
        return False
    try:
        root_path = Path(root).resolve(strict=True)
        prior_request = server._request(prior_intent.get("request", {}))
        if (prior_request["serverCorrelationId"] != _SERVER
                or prior_request["leaseId"] != lease_id):
            return False
        config, target, descriptor = base._descriptor(root_path)
        expected_identity = base._campaign_identity(
            {**prior_request, "correlationId": lease_id}, descriptor)
        directory, lock = lease._locked(root_path)
        try:
            current = lease._active(directory)
            if (not isinstance(current, Mapping) or current.get("identity") != expected_identity
                    or current.get("state") != "active" or current.get("role") is not None
                    or current.get("server") != "stopped" or current.get("credentials") != "ready"
                    or current.get("lastOutcome") != "failed-cleaned"):
                return False
            evidence_sha = current.get("lastEvidenceSha256")
        finally:
            os.close(lock)
        matches = []
        for path in (root_path / _DIR).glob("*.json"):
            correlation = path.stem
            if not _UUID.fullmatch(correlation):
                continue
            record = _read(root_path, correlation)
            if (not isinstance(record, dict) or record.get("serverCorrelationId") != _SERVER
                    or record.get("serverRequest") != prior_request
                    or record.get("guestGeneration") != {"socketPath": descriptor[1],
                                                          "qemuPid": descriptor[2],
                                                          "startTicks": descriptor[3]}):
                continue
            terminal = _terminal(root_path, correlation)
            if terminal is not None and _digest(record["request"], descriptor, terminal["exitcode"]) == evidence_sha:
                matches.append((correlation, terminal["exitcode"]))
        if len(matches) != 1:
            return False
        remote = base._campaign_remote(config, target)
        if not lease._remote_confirm(remote, "status", current, None):
            return False
        correlation, exitcode = matches[0]
        return _observe(root_path, config, target, descriptor, correlation, "verify") == {
            "state": "terminal", "exitcode": exitcode}
    except (OSError, ValueError, KeyError, TypeError, WindowsFixtureServerAbortSuccessorError,
            lease.Cp117LeaseError, base.WindowsMsiBasePrepareError):
        return False


def allows_cleanup_reservation(root: Path | str, prior_correlation: str, lease_id: str,
                               prior_intent: Mapping[str, Any],
                               candidate_intent: Mapping[str, Any] | None) -> bool:
    """Allow one new abort cleanup after the fixed historical successor proof.

    This is deliberately narrower than server restart admission: it admits only
    the historical abort cleanup for `_SERVER`, after its fixed successor,
    while the active role is the fixed replacement server-start.  It only reads
    journals and observations; it never claims, finishes, or mutates a role.
    """
    if prior_correlation != _ABORT or not _UUID.fullmatch(lease_id):
        return False
    try:
        root_path = Path(root).resolve(strict=True)
        prior_request = server._cleanup_request(prior_intent.get("request", {}))
        old_request = server._request(prior_intent.get("serverRequest", {}))
        expected_prior = {
            "schemaVersion": 1, "mode": "abort", "request": prior_request,
            "serverRequest": old_request, "environment": "windows-cp117",
            "socketPath": prior_intent.get("socketPath"), "qemuPid": prior_intent.get("qemuPid"),
            "startTicks": prior_intent.get("startTicks"), "originalSid": prior_intent.get("originalSid"),
            "serverPid": 0, "serverProcessStartIdentity": "", "serverPort": 0,
            "commandSha256": prior_intent.get("commandSha256"),
            "verifyCommandSha256": prior_intent.get("verifyCommandSha256"),
        }
        if (dict(prior_intent) != expected_prior or prior_request != {
                "leaseId": lease_id, "serverCorrelationId": _SERVER,
                "cleanupCorrelationId": _ABORT} or old_request["leaseId"] != lease_id
                or old_request["serverCorrelationId"] != _SERVER
                or not all(isinstance(prior_intent[key], str) and server._HASH.fullmatch(prior_intent[key])
                           for key in ("commandSha256", "verifyCommandSha256"))):
            return False
        if not isinstance(candidate_intent, Mapping):
            return False
        current_request = server._cleanup_request(candidate_intent.get("request", {}))
        current_server = server._request(candidate_intent.get("serverRequest", {}))
        expected_current_server = {**old_request, "serverCorrelationId": _REPLACEMENT_SERVER}
        expected_current = {
            "schemaVersion": 1, "mode": "abort", "request": current_request,
            "serverRequest": current_server, "environment": "windows-cp117",
            "socketPath": candidate_intent.get("socketPath"), "qemuPid": candidate_intent.get("qemuPid"),
            "startTicks": candidate_intent.get("startTicks"), "originalSid": candidate_intent.get("originalSid"),
            "serverPid": 0, "serverProcessStartIdentity": "", "serverPort": 0,
            "commandSha256": candidate_intent.get("commandSha256"),
            "verifyCommandSha256": candidate_intent.get("verifyCommandSha256"),
        }
        if (dict(candidate_intent) != expected_current or current_server != expected_current_server
                or current_request["leaseId"] != lease_id
                or current_request["serverCorrelationId"] != _REPLACEMENT_SERVER
                or current_request["cleanupCorrelationId"] in {_ABORT, _REPLACEMENT_SERVER}
                or not all(isinstance(candidate_intent[key], str) and server._HASH.fullmatch(candidate_intent[key])
                           for key in ("commandSha256", "verifyCommandSha256"))):
            return False
        config, target, descriptor = base._descriptor(root_path)
        if (descriptor[0] != "windows-cp117"
                or (prior_intent["socketPath"], prior_intent["qemuPid"], prior_intent["startTicks"], prior_intent["originalSid"])
                   != descriptor[1:]
                or (candidate_intent["socketPath"], candidate_intent["qemuPid"], candidate_intent["startTicks"], candidate_intent["originalSid"])
                   != descriptor[1:]):
            return False
        successor_record = _read(root_path, _HISTORICAL_SUCCESSOR)
        expected_successor = {
            "version": 1, "request": {"successorCleanupCorrelationId": _HISTORICAL_SUCCESSOR},
            "serverCorrelationId": _SERVER, "priorCleanupCorrelationId": _ABORT,
            "serverRequest": old_request,
            "guestGeneration": {"socketPath": descriptor[1], "qemuPid": descriptor[2],
                                "startTicks": descriptor[3]},
        }
        terminal = _terminal(root_path, _HISTORICAL_SUCCESSOR)
        if successor_record != expected_successor or terminal is None:
            return False
        digest = _digest(successor_record["request"], descriptor, terminal["exitcode"])
        expected_identity = base._campaign_identity(
            {**current_server, "correlationId": lease_id}, descriptor)
        directory, lock = lease._locked(root_path)
        try:
            current = lease._active(directory)
            if (not isinstance(current, Mapping) or current.get("identity") != expected_identity
                    or current.get("state") != "role-active" or current.get("role") != "server-start"
                    or current.get("correlationId") != _REPLACEMENT_SERVER
                    or current.get("server") != "starting" or current.get("credentials") != "ready"
                    or current.get("lastOutcome") != "failed-cleaned"
                    or current.get("lastEvidenceSha256") != digest):
                return False
        finally:
            os.close(lock)
        remote = base._campaign_remote(config, target)
        return (lease._remote_confirm(remote, "status", current, None)
                and _observe(root_path, config, target, descriptor, _HISTORICAL_SUCCESSOR, "verify")
                == {"state": "terminal", "exitcode": terminal["exitcode"]})
    except (OSError, ValueError, KeyError, TypeError, WindowsFixtureServerAbortSuccessorError,
            lease.Cp117LeaseError, base.WindowsMsiBasePrepareError):
        return False


def workflow(root: Path | str, action: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if action == "start": return start(root, inputs)
    if action == "status": return status(root, inputs)
    if action == "diagnostic": return diagnose(root, inputs)
    raise WindowsFixtureServerAbortSuccessorError("Unknown server abort successor action.")

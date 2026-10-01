"""Durable CP117 campaign admission shared by MSI and fixture routes.

This module does not start a guest action. It is an internal coordination
primitive, not a public MCP action: native adapters must first verify registered
artifacts, the exact guest generation, and terminal/cleanup receipts before
calling ``begin``, ``finish_role`` or ``close``. A caller-provided hash or legacy
marker alone is never native admission. An uncertain transport result is sticky.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
from typing import Any, Callable, Mapping


class Cp117LeaseError(ValueError):
    pass


_DIR = ".rag_index/windows-cp117-campaign"
_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_ARTIFACT = re.compile(r"sha256-[0-9a-f]{64}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_OPERATOR = re.compile(r"[a-z][a-z0-9_-]{1,63}\Z")
_ROLES = {"base", "stage", "credentials", "credentials-cleanup", "server-start", "server-stop", "owner-network", "network-probe", "target", "public"}
_Remote = Callable[[str, Mapping[str, Any]], bytes | None]


def remote_role_guard() -> str:
    """Fixed read-only host guard for native route scripts, before guest effects.

    The route keeps its durable local claim; this guard checks the matching
    remote claim under the shared journal lock. It creates no paths and returns
    no caller-provided proof. Native adapters must pass their verified identity.
    """
    return r'''import fcntl,json,os,stat
def require_campaign_role(root,env,lease,role,corr,source,receipt_id,base_id,target_id,sock,pid,ticks):
 if env!='windows-cp117' or role not in ('base','stage','credentials','credentials-cleanup','server-start','server-stop','owner-network','network-probe','target','public') or not isinstance(lease,str) or not isinstance(corr,str):raise ValueError()
 parent=os.path.join(root,env);group=os.path.join(parent,'windows-cp117-campaign')
 for path in (root,parent,group):
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 lock=os.open(os.path.join(group,'.environment.lock'),os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 try:
  info=os.fstat(lock)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError()
  fcntl.flock(lock,fcntl.LOCK_SH)
  fd=os.open(os.path.join(group,'active.json'),os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
  try:
   info=os.fstat(fd)
   if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>16384:raise ValueError()
   with os.fdopen(fd,'r',encoding='utf-8') as file:record=json.load(file)
   fd=-1
  finally:
   if fd>=0:os.close(fd)
  identity=record['identity']
  expected={'host':'archlinux','environment':env,'leaseId':lease,'operator':'windows-base',
   'sourceSha':source,'fixtureReceiptArtifactId':receipt_id,'baseMsiArtifactId':base_id,
   'targetMsiArtifactId':target_id,'socketPath':sock,'qemuPid':int(pid),'startTicks':int(ticks)}
  if set(record)!={'version','identity','sequence','state','role','correlationId','server','credentials','lastEvidenceSha256','lastOutcome'}:raise ValueError()
  if type(record['sequence']) is not int or record['sequence']<=0:raise ValueError()
  server={'server-start':'starting','server-stop':'stopping','owner-network':'live','network-probe':'live','target':'live','public':'live'}.get(role,'stopped')
  credentials={'credentials':'absent','credentials-cleanup':'ready','server-start':'ready','server-stop':'ready','owner-network':'ready','network-probe':'ready','target':'ready','public':'ready'}.get(role,'absent')
  if record['version']!=1 or record['state']!='role-active' or record['role']!=role or record['correlationId']!=corr or record['server']!=server or record['credentials']!=credentials or identity!=expected:raise ValueError()
 finally:os.close(lock)
'''


# Appended to windows_msi_base_prepare._QGA by ``remote_program``. The caller
# passes this exact script through the configured, positively bound SSH route.
# There are no QGA guest-exec or product actions in the lease program.
_REMOTE_BODY = r'''import fcntl
root,env,action,encoded=sys.argv[1:]
def out(value):print(json.dumps(value,sort_keys=True,separators=(',',':')))
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def safe_dir(path):
 info=os.lstat(path)
 return stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o700
def record(path):
 info=os.lstat(path)
 if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>16384:raise ValueError()
 return json.load(open(path,encoding='utf-8'))
def save(path,value):
 temp=path+'.'+secrets.token_hex(8)+'.tmp'
 fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'w',encoding='utf-8') as file:json.dump(value,file,sort_keys=True,separators=(',',':'));file.write('\n');file.flush();os.fsync(file.fileno())
 os.replace(temp,path);parent=os.open(os.path.dirname(path),os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(parent);os.close(parent)
try:
 if env!='windows-cp117' or action not in ('reserve','claim','finish','close','status','finalize'):raise ValueError()
 payload=json.loads(base64.b64decode(encoded,validate=True))
 if set(payload)!={'action','desired','priorSha256'} or payload['action']!=action:raise ValueError()
 desired=payload['desired'];identity=desired['identity']
 if identity['host']!='archlinux' or identity['environment']!=env or not live(identity['socketPath'],str(identity['qemuPid']),str(identity['startTicks'])):raise ValueError()
 parent=os.path.join(root,env);group=os.path.join(parent,'windows-cp117-campaign')
 for path in (root,parent,group):
  if action not in ('status','finalize') and not os.path.exists(path):os.mkdir(path,0o700)
  if not safe_dir(path):raise ValueError()
 flags=os.O_RDWR|getattr(os,'O_NOFOLLOW',0)
 if action not in ('status','finalize'):flags|=os.O_CREAT
 fd=os.open(os.path.join(group,'.environment.lock'),flags,0o600)
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError()
  fcntl.flock(fd,fcntl.LOCK_EX)
  active=os.path.join(group,'active.json')
  closed=os.path.join(group,identity['leaseId']+'.closed.json')
  if action=='status':
   if os.path.exists(closed) and os.path.exists(active):raise ValueError()
   path=closed if desired['state']=='closed' and os.path.exists(closed) else active
   if digest(record(path))!=digest(desired):raise ValueError()
   if desired['state']=='closed' and path==active:
    out({'version':1,'action':action,'leaseId':identity['leaseId'],'recordSha256':digest(desired),'state':'transitional'})
    raise SystemExit(0)
  elif action=='finalize':
   if desired['state']!='closed' or os.path.exists(closed) or digest(record(active))!=digest(desired):raise ValueError()
   os.replace(active,closed);parentfd=os.open(group,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(parentfd);os.close(parentfd)
  elif action=='reserve':
   if os.path.exists(active) or os.path.exists(os.path.join(group,identity['leaseId']+'.closed.json')) or payload['priorSha256'] is not None:raise ValueError()
   if desired['state']!='active' or desired['sequence']!=0 or desired['role'] is not None or desired['server']!='stopped' or desired['credentials']!='absent' or desired['lastEvidenceSha256'] is not None or desired['lastOutcome'] is not None:raise ValueError()
  else:
   old=record(active)
   if digest(old)!=payload['priorSha256'] or old['identity']!=identity or desired['sequence']!=old['sequence']+1:raise ValueError()
   if action=='claim':
    role=desired['role']
    allowed=(old['server']=='stopped' and role in ('base','stage','credentials','credentials-cleanup','server-start')) or (old['server']=='live' and role in ('owner-network','network-probe','target','public','server-stop'))
    if role=='server-start' and old['credentials']!='ready':raise ValueError()
    if role in ('owner-network','network-probe') and old['credentials']!='ready':raise ValueError()
    if role=='credentials' and old['credentials']!='absent':raise ValueError()
    if role=='credentials-cleanup' and old['credentials']!='ready':raise ValueError()
    server=('starting' if role=='server-start' else 'stopping' if role=='server-stop' else old['server'])
    if not (old['state']=='active' and old['role'] is None and desired['state']=='role-active' and allowed and desired['correlationId'] and desired['server']==server and desired['credentials']==old['credentials'] and desired['lastEvidenceSha256']==old['lastEvidenceSha256'] and desired['lastOutcome']==old['lastOutcome']):raise ValueError()
   if action=='finish':
    server=('live' if old['role']=='server-start' and desired['lastOutcome']=='succeeded' else 'stopped' if old['role'] in ('server-start','server-stop') else old['server'])
    credentials=('ready' if old['role']=='credentials' and desired['lastOutcome']=='succeeded' else 'cleaned' if old['role']=='credentials-cleanup' and desired['lastOutcome']=='succeeded' else old['credentials'])
    if not (old['state']=='role-active' and desired['state']=='active' and desired['role'] is None and desired['correlationId'] is None and desired['server']==server and desired['credentials']==credentials and desired['lastOutcome'] in ('succeeded','failed-cleaned','unknown-cleaned') and (old['role'] not in ('server-stop','credentials-cleanup') or desired['lastOutcome']=='succeeded') and (old['role']=='base' or desired['lastOutcome']!='unknown-cleaned') and isinstance(desired['lastEvidenceSha256'],str) and len(desired['lastEvidenceSha256'])==64):raise ValueError()
   if action=='close' and not (old['state']=='active' and old['role'] is None and old['server']=='stopped' and old['credentials']!='ready' and desired['state']=='closed' and desired['role'] is None and desired['correlationId'] is None and desired['credentials']==old['credentials'] and isinstance(desired['lastEvidenceSha256'],str) and len(desired['lastEvidenceSha256'])==64):raise ValueError()
  if action=='close':
   if os.path.exists(closed):raise ValueError()
   save(active,desired);os.replace(active,closed);parentfd=os.open(group,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(parentfd);os.close(parentfd)
  elif action not in ('status','finalize'):save(active,desired)
 finally:os.close(fd)
 out({'version':1,'action':action,'leaseId':identity['leaseId'],'recordSha256':digest(desired),'state':'confirmed'})
except Exception:out({'version':1,'state':'unknown'})
'''


def remote_program() -> str:
    from . import windows_msi_base_prepare
    return windows_msi_base_prepare._QGA + _REMOTE_BODY


def remote_arguments(transfer_root: Path | str, action: str, payload: Mapping[str, Any]) -> tuple[str, ...]:
    import base64
    if action not in {"reserve", "claim", "finish", "close", "status", "finalize"}:
        raise Cp117LeaseError("Unknown CP117 remote lease action.")
    encoded = base64.b64encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).decode()
    if len(encoded) > 8192: raise Cp117LeaseError("CP117 remote lease payload is too large.")
    return (str(transfer_root), "windows-cp117", action, encoded)


def _identity(value: Mapping[str, Any]) -> dict[str, Any]:
    fields = {"host", "environment", "leaseId", "operator", "sourceSha",
              "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId",
              "socketPath", "qemuPid", "startTicks"}
    if not isinstance(value, Mapping) or set(value) != fields or value.get("host") != "archlinux" or value.get("environment") != "windows-cp117":
        raise Cp117LeaseError("CP117 campaign identity requires exact fields.")
    for name, pattern in (("leaseId", _UUID), ("operator", _OPERATOR), ("sourceSha", _SHA),
                          ("fixtureReceiptArtifactId", _ARTIFACT), ("baseMsiArtifactId", _ARTIFACT),
                          ("targetMsiArtifactId", _ARTIFACT)):
        if not isinstance(value[name], str) or not pattern.fullmatch(value[name]):
            raise Cp117LeaseError("Invalid CP117 campaign " + name + ".")
    if str(uuid.UUID(value["leaseId"])) != value["leaseId"]:
        raise Cp117LeaseError("CP117 lease ID is not canonical.")
    if not isinstance(value["socketPath"], str) or not value["socketPath"].startswith("/") or "\x00" in value["socketPath"]:
        raise Cp117LeaseError("CP117 QGA socket is invalid.")
    for name in ("qemuPid", "startTicks"):
        if type(value[name]) is not int or value[name] <= 0:
            raise Cp117LeaseError("CP117 QEMU generation is invalid.")
    return dict(value)


def _directory(root: Path) -> Path:
    path = root / _DIR
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise Cp117LeaseError("CP117 campaign journal is unsafe.")
    return path


def _read(path: Path) -> dict[str, Any] | None:
    try: fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError: return None
    with os.fdopen(fd, "rb") as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16384:
            raise Cp117LeaseError("CP117 campaign receipt is unsafe.")
        try: value = json.load(file)
        except (TypeError, ValueError) as error: raise Cp117LeaseError("CP117 campaign receipt is invalid.") from error
    if not isinstance(value, dict): raise Cp117LeaseError("CP117 campaign receipt is invalid.")
    return value


def _write(path: Path, value: Mapping[str, Any], *, create: bool = False) -> None:
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(data) > 16384: raise Cp117LeaseError("CP117 campaign receipt is too large.")
    temp = path.parent / ("." + path.name + "." + str(uuid.uuid4()) + ".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(data); file.flush(); os.fsync(file.fileno())
        if create and path.exists(): raise Cp117LeaseError("CP117 campaign identity is already reserved.")
        os.replace(temp, path)
        parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try: os.fsync(parent)
        finally: os.close(parent)
    finally:
        try: temp.unlink()
        except FileNotFoundError: pass


def _locked(root: Path):
    directory = _directory(root)
    fd = os.open(directory / ".environment.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        os.close(fd); raise Cp117LeaseError("CP117 campaign lock is unsafe.")
    fcntl.flock(fd, fcntl.LOCK_EX)
    return directory, fd


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _remote_result(remote: _Remote, action: str, desired: Mapping[str, Any], prior: Mapping[str, Any] | None) -> str:
    request = {"action": action, "desired": dict(desired), "priorSha256": _digest(prior) if prior is not None else None}
    try: raw = remote(action, request)
    except (OSError, ValueError): return "unknown"
    if raw is None or len(raw) > 4096: return "unknown"
    try: response = json.loads(raw)
    except (TypeError, ValueError): return "unknown"
    expected = {"version": 1, "action": action, "leaseId": desired["identity"]["leaseId"],
                "recordSha256": _digest(desired)}
    if response == {**expected, "state": "confirmed"}: return "confirmed"
    if action == "status" and response == {**expected, "state": "transitional"}: return "transitional"
    return "unknown"


def _remote_confirm(remote: _Remote, action: str, desired: Mapping[str, Any], prior: Mapping[str, Any] | None) -> bool:
    return _remote_result(remote, action, desired, prior) == "confirmed"


def _active(directory: Path) -> dict[str, Any] | None:
    record = _read(directory / "active.json")
    if record is not None and (set(record) != {"version", "identity", "sequence", "state", "role", "correlationId", "server", "credentials", "lastEvidenceSha256", "lastOutcome"}
                               or record["version"] != 1 or _identity(record["identity"]) != record["identity"]
                               or type(record["sequence"]) is not int or record["sequence"] < 0
                               or record["state"] not in {"pending-remote", "active", "pending-role", "role-active", "pending-finish", "pending-close", "closed", "unknown"}
                               or record["role"] not in ({None} | _ROLES)
                               or (record["correlationId"] is not None and not _UUID.fullmatch(record["correlationId"]))
                               or record["server"] not in {"stopped", "starting", "live", "stopping", "unknown"}
                               or record["credentials"] not in {"absent", "ready", "cleaned"}
                               or record["lastOutcome"] not in {None, "succeeded", "failed-cleaned", "unknown-cleaned"}
                               or (record["lastEvidenceSha256"] is not None and
                                   (not isinstance(record["lastEvidenceSha256"], str) or not _HASH.fullmatch(record["lastEvidenceSha256"])))):
        raise Cp117LeaseError("CP117 campaign active receipt is invalid.")
    if record is not None and (directory / (record["identity"]["leaseId"] + ".closed.json")).exists():
        raise Cp117LeaseError("CP117 campaign has conflicting active and closed receipts.")
    return record


def _closed(directory: Path, lease_id: str) -> dict[str, Any] | None:
    record = _read(directory / (lease_id + ".closed.json"))
    if record is None: return None
    if (set(record) != {"version", "identity", "sequence", "state", "role", "correlationId",
                        "server", "credentials", "lastEvidenceSha256", "lastOutcome"}
            or record["version"] != 1 or record["state"] != "closed"
            or _identity(record["identity"]) != record["identity"]
            or record["identity"]["leaseId"] != lease_id
            or type(record["sequence"]) is not int or record["sequence"] <= 0
            or record["role"] is not None or record["correlationId"] is not None
            or record["server"] != "stopped"
            or record["credentials"] not in {"absent", "cleaned"}
            or not isinstance(record["lastEvidenceSha256"], str)
            or not _HASH.fullmatch(record["lastEvidenceSha256"])):
        raise Cp117LeaseError("CP117 campaign closed receipt is invalid.")
    return record


def _begin(root: Path | str, identity: Mapping[str, Any], remote: _Remote) -> dict[str, Any]:
    """Reserve once. A lost remote response leaves a non-replayable local intent."""
    root = Path(root).resolve(strict=True); bound = _identity(identity)
    directory, lock = _locked(root)
    try:
        if _active(directory) is not None or _closed(directory, bound["leaseId"]) is not None:
            raise Cp117LeaseError("CP117 has an active, unknown, or reused campaign.")
        pending = {"version": 1, "identity": bound, "sequence": 0, "state": "pending-remote",
                   "role": None, "correlationId": None, "server": "stopped", "credentials": "absent", "lastEvidenceSha256": None,
                   "lastOutcome": None}
        _write(directory / "active.json", pending, create=True)
        desired = dict(pending, state="active")
        if not _remote_confirm(remote, "reserve", desired, None):
            return {"state": "unknown", "leaseId": bound["leaseId"], "replayAllowed": False}
        _write(directory / "active.json", desired)
        return {"state": "active", "leaseId": bound["leaseId"], "replayAllowed": False}
    finally: os.close(lock)


def begin(root: Path | str, identity: Mapping[str, Any], remote: _Remote) -> dict[str, Any]:
    """Internal only; route adapter must prove artifact and guest admission."""
    return _begin(root, identity, remote)


def inspect(root: Path | str, lease_id: str) -> dict[str, Any]:
    if not isinstance(lease_id, str) or not _UUID.fullmatch(lease_id): raise Cp117LeaseError("Invalid CP117 lease ID.")
    directory, lock = _locked(Path(root).resolve(strict=True))
    try:
        record = _active(directory)
        if record is None or record["identity"]["leaseId"] != lease_id:
            closed = _closed(directory, lease_id)
            if closed is not None:
                return {"state": "closed", "leaseId": lease_id, "replayAllowed": False}
            return {"state": "unknown", "leaseId": lease_id, "replayAllowed": False}
        return {"state": record["state"], "leaseId": lease_id, "sequence": record["sequence"],
                "role": record["role"], "server": record["server"], "replayAllowed": False}
    finally: os.close(lock)


def _local_finalize_close(directory: Path, desired: Mapping[str, Any]) -> None:
    active = directory / "active.json"
    closed = directory / (desired["identity"]["leaseId"] + ".closed.json")
    if closed.exists():
        if _read(closed) != desired or active.exists():
            raise Cp117LeaseError("CP117 close receipt is inconsistent.")
        return
    if _read(active) != desired:
        _write(active, desired)
    os.replace(active, closed)
    parent = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try: os.fsync(parent)
    finally: os.close(parent)


def reconcile(root: Path | str, lease_id: str, remote: _Remote) -> dict[str, Any]:
    """Read back one pending transition; never resubmit its remote mutation."""
    directory, lock = _locked(Path(root).resolve(strict=True))
    try:
        pending = _active(directory)
        if pending is None:
            closed = _closed(directory, lease_id)
            if closed is None:
                raise Cp117LeaseError("CP117 has no matching pending transition.")
            if not _remote_confirm(remote, "status", closed, None):
                return {"state": "unknown", "leaseId": lease_id, "replayAllowed": False}
            return {"state": "closed", "leaseId": lease_id, "replayAllowed": False}
        if pending is None or pending["identity"]["leaseId"] != lease_id or pending["state"] not in {
                "pending-remote", "pending-role", "pending-finish", "pending-close", "closed"}:
            raise Cp117LeaseError("CP117 has no matching pending transition.")
        state = {"pending-remote": "active", "pending-role": "role-active",
                 "pending-finish": "active", "pending-close": "closed", "closed": "closed"}[pending["state"]]
        desired = dict(pending, state=state)
        remote_state = _remote_result(remote, "status", desired, None)
        if remote_state == "transitional" and state == "closed":
            remote_state = _remote_result(remote, "finalize", desired, None)
        if remote_state != "confirmed":
            return {"state": "unknown", "leaseId": lease_id, "replayAllowed": False}
        if state == "closed":
            _local_finalize_close(directory, desired)
        else: _write(directory / "active.json", desired)
        return {"state": state, "leaseId": lease_id, "replayAllowed": False}
    finally: os.close(lock)


def _advance(root: Path | str, lease_id: str, expected: dict[str, Any], desired: dict[str, Any], action: str, remote: _Remote) -> dict[str, Any]:
    directory, lock = _locked(Path(root).resolve(strict=True))
    try:
        current = _active(directory)
        if current != expected or current["identity"]["leaseId"] != lease_id:
            raise Cp117LeaseError("CP117 campaign is not in the required phase.")
        pending = dict(desired, state="pending-close" if action == "close" else
                       "pending-finish" if action == "finish" else "pending-role")
        _write(directory / "active.json", pending)
        if not _remote_confirm(remote, action, desired, current):
            return {"state": "unknown", "leaseId": lease_id, "replayAllowed": False}
        if action == "close":
            _local_finalize_close(directory, desired)
        else: _write(directory / "active.json", desired)
        return {"state": desired["state"], "leaseId": lease_id, "replayAllowed": False}
    finally: os.close(lock)


def claim_role(root: Path | str, lease_id: str, role: str, correlation_id: str, remote: _Remote) -> dict[str, Any]:
    if role not in _ROLES or not isinstance(correlation_id, str) or not _UUID.fullmatch(correlation_id):
        raise Cp117LeaseError("CP117 route identity is invalid.")
    directory, lock = _locked(Path(root).resolve(strict=True))
    try:
        current = _active(directory)
        if current is None or current["identity"]["leaseId"] != lease_id or current["state"] != "active" or current["role"] is not None:
            raise Cp117LeaseError("CP117 route is active or unknown.")
        if role in {"base", "stage", "credentials", "credentials-cleanup", "server-start"} and current["server"] != "stopped":
            raise Cp117LeaseError("CP117 fixture server is already active or unknown.")
        if role == "credentials" and current["credentials"] != "absent":
            raise Cp117LeaseError("CP117 credentials are already active or unknown.")
        if role == "credentials-cleanup" and current["credentials"] != "ready":
            raise Cp117LeaseError("CP117 credentials are not ready for cleanup.")
        if role == "server-start" and current["credentials"] != "ready":
            raise Cp117LeaseError("CP117 fixture credentials are not verified ready.")
        if role in {"owner-network", "network-probe"} and current["credentials"] != "ready":
            raise Cp117LeaseError("CP117 owner network credentials are not verified ready.")
        if role in {"owner-network", "network-probe", "target", "public", "server-stop"} and current["server"] != "live":
            raise Cp117LeaseError("CP117 fixture server is not verified live.")
        desired = dict(current, sequence=current["sequence"] + 1, state="role-active", role=role,
                       correlationId=correlation_id, server="starting" if role == "server-start" else
                       "stopping" if role == "server-stop" else current["server"])
    finally: os.close(lock)
    return _advance(root, lease_id, current, desired, "claim", remote)


def finish_role(root: Path | str, lease_id: str, role: str, correlation_id: str,
                terminal_receipt_sha256: str, outcome: str, remote: _Remote) -> dict[str, Any]:
    """Internal only; route adapter must validate terminal state and cleanup."""
    if (role not in _ROLES or not isinstance(correlation_id, str) or not _UUID.fullmatch(correlation_id)
            or not isinstance(terminal_receipt_sha256, str) or not _HASH.fullmatch(terminal_receipt_sha256)
            or outcome not in {"succeeded", "failed-cleaned", "unknown-cleaned"}
            or (role in {"server-stop", "credentials-cleanup"} and outcome != "succeeded")
            or (outcome == "unknown-cleaned" and role != "base")):
        raise Cp117LeaseError("CP117 terminal role evidence is invalid.")
    directory, lock = _locked(Path(root).resolve(strict=True))
    try:
        current = _active(directory)
        if current is None or current["identity"]["leaseId"] != lease_id or current["state"] != "role-active" or current["role"] != role or current["correlationId"] != correlation_id:
            raise Cp117LeaseError("CP117 route terminal identity changed.")
        desired = dict(current, sequence=current["sequence"] + 1, state="active", role=None,
                       correlationId=None, server="live" if role == "server-start" and outcome == "succeeded" else
                       "stopped" if role in {"server-start", "server-stop"} else current["server"],
                       credentials="ready" if role == "credentials" and outcome == "succeeded" else
                       "cleaned" if role == "credentials-cleanup" else current["credentials"],
                       lastEvidenceSha256=terminal_receipt_sha256, lastOutcome=outcome)
    finally: os.close(lock)
    # The trusted route validates terminal_receipt_sha256 before calling this API.
    return _advance(root, lease_id, current, desired, "finish", remote)


def close(root: Path | str, lease_id: str, cleanup: Mapping[str, Any], remote: _Remote,
          *, expected_current: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Close a verified idle campaign, optionally requiring its exact admitted record.

    The expected record is checked under the local lease lock, then `_advance`
    compares the same record again under its own lock before remote dispatch.
    A role transition between admission and close therefore cannot reuse an
    earlier terminal proof.
    """
    fields = {"guestGeneration", "serverStopped", "credentialsCleaned", "protectedJobsTerminalCleaned",
              "activeInstallerProcessesAbsent", "cleanupReceiptSha256"}
    if not isinstance(cleanup, Mapping) or set(cleanup) != fields or cleanup.get("serverStopped") is not True or cleanup.get("credentialsCleaned") is not True or cleanup.get("protectedJobsTerminalCleaned") is not True or cleanup.get("activeInstallerProcessesAbsent") is not True or not isinstance(cleanup.get("cleanupReceiptSha256"), str) or not _HASH.fullmatch(cleanup["cleanupReceiptSha256"]):
        raise Cp117LeaseError("CP117 cleanup proof is incomplete.")
    directory, lock = _locked(Path(root).resolve(strict=True))
    try:
        current = _active(directory)
        if (current is None or (expected_current is not None and
                (not isinstance(expected_current, Mapping) or current != dict(expected_current)))
                or current["identity"]["leaseId"] != lease_id or current["state"] != "active"
                or current["role"] is not None or current["server"] != "stopped"
                or current["credentials"] == "ready"
                or cleanup["guestGeneration"] != {"socketPath": current["identity"]["socketPath"],
                    "qemuPid": current["identity"]["qemuPid"], "startTicks": current["identity"]["startTicks"]}):
            raise Cp117LeaseError("CP117 campaign cleanup identity is not complete.")
        desired = dict(current, sequence=current["sequence"] + 1, state="closed",
                       lastEvidenceSha256=cleanup["cleanupReceiptSha256"])
    finally: os.close(lock)
    return _advance(root, lease_id, current, desired, "close", remote)


def attest_legacy_closed(root: Path | str, proof: Mapping[str, Any]) -> dict[str, Any]:
    """Archive a prior terminal route without deleting or replaying its journal.

    The caller must obtain ``proof`` from a fixed read-only reconciliation route.
    This local marker is not consulted by ``begin`` and cannot authorize another
    campaign. Historical directories by themselves are never classified as
    active or closed; remote reconciliation remains a separate integration gate.
    """
    fields = {"correlationId", "guestGeneration", "terminalJobId", "terminalPhase",
              "cleanupCode", "activeInstallerProcessesAbsent", "evidenceSha256"}
    if (not isinstance(proof, Mapping) or set(proof) != fields or
            not isinstance(proof.get("correlationId"), str) or not _UUID.fullmatch(proof["correlationId"]) or
            not isinstance(proof.get("terminalJobId"), str) or not _UUID.fullmatch(proof["terminalJobId"]) or
            proof.get("terminalPhase") not in {"Succeeded", "Failed", "Cancelled"} or
            proof.get("cleanupCode") != "OK" or proof.get("activeInstallerProcessesAbsent") is not True or
            not isinstance(proof.get("evidenceSha256"), str) or not _HASH.fullmatch(proof["evidenceSha256"]) or
            not isinstance(proof.get("guestGeneration"), dict) or
            set(proof["guestGeneration"]) != {"socketPath", "qemuPid", "startTicks"}):
        raise Cp117LeaseError("Legacy CP117 closure proof is incomplete.")
    directory, lock = _locked(Path(root).resolve(strict=True))
    try:
        path = directory / (proof["correlationId"] + ".legacy-closed.json")
        old = _read(path)
        if old is not None:
            if old != dict(proof): raise Cp117LeaseError("Legacy CP117 closure proof changed.")
            return {"state": "closed", "correlationId": proof["correlationId"]}
        _write(path, proof, create=True)
        return {"state": "closed", "correlationId": proof["correlationId"]}
    finally: os.close(lock)

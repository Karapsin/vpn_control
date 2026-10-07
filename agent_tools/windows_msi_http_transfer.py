"""One-use, source-bound CP117 MSI transfer stage (no product action)."""
from __future__ import annotations

import hashlib
import base64
import gzip
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tempfile
import uuid
from typing import Any, Mapping

from . import windows_msi_base_prepare as base
from . import windows_msi_public_scenario
from . import windows_large_artifact_transfer as large_transfer


class WindowsMsiHttpTransferError(ValueError):
    pass


_DIR = ".rag_index/windows-msi-http-transfer"
_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_SID = re.compile(r"S-1-5-21-(?:[0-9]+-){3}[0-9]+\Z")
_FIELDS = {"correlationId", "sourceSha", "baseMsiArtifactId", "environment",
           "socketPath", "qemuPid", "startTicks", "expectedSid"}
_UNKNOWN = {"state": "unknown", "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False}


def _large_binding(record: Mapping[str, Any]) -> dict[str, Any]:
    """Map the historical MSI ABI to the shared immutable transfer binding."""
    return {"correlationId": record["correlationId"], "sourceSha": record["sourceSha"],
            "artifactId": record["baseMsiArtifactId"], "kind": "msi",
            "environment": record["environment"], "socketPath": record["socketPath"],
            "qemuPid": record["qemuPid"], "startTicks": record["startTicks"],
            "expectedSid": record["expectedSid"]}


def _large_advance(root: Path, record: Mapping[str, Any], phase: str) -> None:
    """Best-effort mirror for legacy direct callers; workflow admission requires it."""
    try:
        large_transfer.advance(root, record["correlationId"], phase)
    except (OSError, ValueError, large_transfer.WindowsLargeArtifactTransferError):
        pass


def _request(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _FIELDS:
        raise WindowsMsiHttpTransferError("Exact CP117 transfer inputs required.")
    result = dict(value)
    if (not isinstance(result["correlationId"], str)
            or not _UUID.fullmatch(result["correlationId"])
            or str(uuid.UUID(result["correlationId"])) != result["correlationId"]
            or not isinstance(result["sourceSha"], str) or not _SHA.fullmatch(result["sourceSha"])
            or not isinstance(result["baseMsiArtifactId"], str)
            or not result["baseMsiArtifactId"].startswith("sha256-")
            or not _HASH.fullmatch(result["baseMsiArtifactId"][7:])
            or result["environment"] != "windows-cp117"
            or not isinstance(result["socketPath"], str)
            or not re.fullmatch(r"/[A-Za-z0-9._/-]+", result["socketPath"])
            or ".." in Path(result["socketPath"]).parts
            or type(result["qemuPid"]) is not int or result["qemuPid"] <= 0
            or type(result["startTicks"]) is not int or result["startTicks"] <= 0
            or not isinstance(result["expectedSid"], str)
            or not _SID.fullmatch(result["expectedSid"])):
        raise WindowsMsiHttpTransferError("Invalid CP117 transfer binding.")
    return result


def _private_dir(root: Path, create: bool) -> Path | None:
    parent = root / ".rag_index"
    if parent.exists() or parent.is_symlink():
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise WindowsMsiHttpTransferError("Unsafe transfer journal parent.")
    path = root / _DIR
    if not path.exists() and not path.is_symlink():
        if not create:
            return None
        path.mkdir(parents=True, mode=0o700)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise WindowsMsiHttpTransferError("Unsafe private transfer journal.")
    return path


def _write_once(path: Path, value: Mapping[str, Any]) -> bool:
    raw = (json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(raw) > 8192:
        raise WindowsMsiHttpTransferError("Transfer intent too large.")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    return True


def _read(path: Path) -> dict[str, Any] | None:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 8192):
            raise WindowsMsiHttpTransferError("Unsafe transfer intent.")
        value = json.load(stream)
    if not isinstance(value, dict):
        raise WindowsMsiHttpTransferError("Invalid transfer intent.")
    return value


def _artifact(path: Path, expected: str | None = None) -> tuple[str, int]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or not 0 < info.st_size <= 1 << 30:
        raise WindowsMsiHttpTransferError("Unsafe MSI artifact.")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    digest = hashlib.sha256()
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if before.st_ino != info.st_ino or before.st_dev != info.st_dev:
            raise WindowsMsiHttpTransferError("MSI artifact changed.")
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    if (after.st_size != info.st_size or after.st_mtime_ns != info.st_mtime_ns
            or after.st_ino != info.st_ino):
        raise WindowsMsiHttpTransferError("MSI artifact changed.")
    actual = digest.hexdigest()
    if expected is not None and actual != expected:
        raise WindowsMsiHttpTransferError("MSI digest mismatch.")
    return actual, info.st_size


def prepare(root: Path, request: Mapping[str, Any], artifact: Path) -> dict[str, Any]:
    binding = _request(request)
    artifact = Path(artifact)
    digest, length = _artifact(artifact, binding["baseMsiArtifactId"][7:])
    directory = _private_dir(Path(root), True)
    assert directory is not None
    record = {**binding, "artifactPath": str(artifact.absolute()), "sha256": digest,
              "length": length, "routeNonce": secrets.token_urlsafe(32)}
    if not _write_once(directory / (binding["correlationId"] + ".json"), record):
        return dict(_UNKNOWN)
    # Keep the existing journal and remote ABI intact, but make the shared
    # source-bound journal authoritative for one-shot phase reconciliation.
    mirrored = large_transfer.prepare(root, _large_binding(record), artifact)
    if mirrored.get("state") != "prepared":
        return dict(_UNKNOWN)
    return {"state": "prepared", "correlationId": binding["correlationId"],
            "sha256": digest, "length": length, "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False}


def _intent(root: Path, correlation: str) -> dict[str, Any] | None:
    if not isinstance(correlation, str) or not _UUID.fullmatch(correlation):
        return None
    directory = _private_dir(Path(root), False)
    if directory is None:
        return None
    record = _read(directory / (correlation + ".json"))
    if record is None:
        return None
    binding = _request({key: record.get(key) for key in _FIELDS})
    if (binding["correlationId"] != correlation or set(record) != _FIELDS | {"artifactPath", "sha256", "length", "routeNonce"}
            or not isinstance(record["artifactPath"], str) or not Path(record["artifactPath"]).is_absolute()
            or record["sha256"] != binding["baseMsiArtifactId"][7:]
            or type(record["length"]) is not int or not 0 < record["length"] <= 1 << 30
            or not isinstance(record["routeNonce"], str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", record["routeNonce"])):
        raise WindowsMsiHttpTransferError("Invalid transfer intent.")
    return record


def status(root: Path, correlation: str) -> dict[str, Any]:
    try:
        record = _intent(root, correlation)
    except (OSError, ValueError):
        return dict(_UNKNOWN)
    if record is None:
        return dict(_UNKNOWN)
    return {"state": "prepared", "correlationId": correlation, "sha256": record["sha256"],
            "length": record["length"], "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False}


_REMOTE_COMMON = r'''import fcntl,hashlib,json,os,re,socket,stat,sys
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
def setup():
 if len(sys.argv)!=12:raise ValueError()
 root,env,corr,source,artifact,sock,pid,ticks,sid,digest,size=sys.argv[1:]
 if (env!='windows-cp117' or not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',corr)
  or not re.fullmatch(r'[0-9a-f]{40}',source) or artifact!='sha256-'+digest
  or not re.fullmatch(r'[0-9a-f]{64}',digest) or not re.fullmatch(r'/[A-Za-z0-9._/-]+',sock)
  or '..' in sock.split('/') or not pid.isdigit() or int(pid)<=0 or not ticks.isdigit() or int(ticks)<=0
  or not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+',sid) or not size.isdigit()
  or not 0<int(size)<=1073741824 or not os.path.isabs(root)):raise ValueError()
 group=os.path.join(root,env,'windows-msi-http-transfer');stage=os.path.join(group,corr)
 binding={'environment':env,'correlationId':corr,'sourceSha':source,'baseMsiArtifactId':artifact,'socketPath':sock,'qemuPid':int(pid),'startTicks':int(ticks),'expectedSid':sid,'sha256':digest,'length':int(size)}
 return root,group,stage,binding
def safe_dir(path,create=False):
 if create and not os.path.lexists(path):os.mkdir(path,0o700)
 i=os.lstat(path)
 if not stat.S_ISDIR(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o700:raise ValueError()
def parents(root,group,create=False):
 safe_dir(root)
 p=os.path.join(root,'windows-cp117');safe_dir(p,create);safe_dir(group,create)
def read_file(path):
 fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 with os.fdopen(fd,'rb') as f:
  i=os.fstat(f.fileno())
  if not stat.S_ISREG(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o600 or i.st_size>8192:raise ValueError()
  return f.read()
def write_once(path,raw):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
def inspect(stage,binding,allow_phase=False):
 safe_dir(stage)
 names=set(os.listdir(stage))
 allowed={'binding.json','base.msi','complete.json'}
 if allow_phase:allowed|={'download-intent.json','worker.json','listener-ready.json','listener-done.json','listener-stopped.json','task-cleaned.json'}
 if not {'binding.json'}<=names or names-allowed:raise ValueError()
 if json.loads(read_file(os.path.join(stage,'binding.json'))) != binding:raise ValueError()
 p=os.path.join(stage,'base.msi')
 if 'base.msi' not in names:return 'partial'
 fd=os.open(p,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0));h=hashlib.sha256();count=0
 with os.fdopen(fd,'rb') as f:
  i=os.fstat(f.fileno())
  if not stat.S_ISREG(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o600:raise ValueError()
  for chunk in iter(lambda:f.read(1048576),b''):h.update(chunk);count+=len(chunk)
 if count<binding['length']:return 'partial'
 if count>binding['length'] or h.hexdigest()!=binding['sha256']:return 'hash-mismatch'
 if 'complete.json' not in names:return 'partial'
 if json.loads(read_file(os.path.join(stage,'complete.json'))) != {'sha256':binding['sha256'],'length':binding['length']}:raise ValueError()
 return 'staged'
def stage_lock(group,corr,create=False):
 p=os.path.join(group,corr+'.lock')
 flags=os.O_RDWR|getattr(os,'O_NOFOLLOW',0)
 if create:flags|=os.O_CREAT|os.O_EXCL
 fd=os.open(p,flags,0o600)
 i=os.fstat(fd)
 if not stat.S_ISREG(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o600:raise ValueError()
 fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 return fd
def ticks_of(pid):
 try:
  raw=open('/proc/'+str(pid)+'/stat','rb').read().split()
  return raw[21].decode() if len(raw)>=22 and raw[2] not in (b'Z',b'X') else ''
 except OSError:return ''
def socket_inodes(pid):
 result=set()
 try:names=os.listdir('/proc/'+str(pid)+'/fd')
 except OSError:return result
 for name in names:
  try:
   value=os.readlink('/proc/'+str(pid)+'/fd/'+name)
   if value.startswith('socket:[') and value.endswith(']'):result.add(value[8:-1])
  except OSError:pass
 return result
def listeners(port):
 result=set()
 for path in ('/proc/net/tcp','/proc/net/tcp6'):
  for line in open(path).read().splitlines()[1:]:
   fields=line.split()
   if len(fields)>=10 and fields[3]=='0A':
    local=fields[1].split(':')
    if len(local)==2 and int(local[1],16)==port:result.add(fields[9])
 return result
def free_port(port):
 probe=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
 probe.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 try:probe.bind(('127.0.0.1',port))
 finally:probe.close()
def owned_listener(pid,ticks,port):
 if ticks_of(pid)!=ticks:return False
 bound=listeners(port)
 return len(bound)==1 and next(iter(bound)) in socket_inodes(pid)
'''

_REMOTE_STAGE = _REMOTE_COMMON + r'''
try:
 root,group,stage,binding=setup();parents(root,group,True)
 if os.path.lexists(stage) or os.path.lexists(os.path.join(group,binding['correlationId']+'.closed.json')):raise ValueError()
 lock=stage_lock(group,binding['correlationId'],True)
 os.mkdir(stage,0o700);safe_dir(stage)
 write_once(os.path.join(stage,'binding.json'),json.dumps(binding,separators=(',',':'),sort_keys=True).encode())
 p=os.path.join(stage,'base.msi');fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 h=hashlib.sha256();remaining=binding['length']
 with os.fdopen(fd,'wb') as f:
  while remaining:
   chunk=sys.stdin.buffer.read(min(1048576,remaining))
   if not chunk:break
   f.write(chunk);h.update(chunk);remaining-=len(chunk)
  f.flush();os.fsync(f.fileno())
 if remaining or h.hexdigest()!=binding['sha256'] or sys.stdin.buffer.read(1):raise ValueError()
 write_once(os.path.join(stage,'complete.json'),json.dumps({'sha256':binding['sha256'],'length':binding['length']},separators=(',',':'),sort_keys=True).encode())
 out({'state':'staged','sha256':binding['sha256'],'length':binding['length']})
except Exception:out({'state':'unknown'})
'''

_REMOTE_STATUS = _REMOTE_COMMON + r'''
try:
 root,group,stage,binding=setup()
 safe_dir(root)
 parent=os.path.join(root,'windows-cp117')
 if os.path.lexists(parent):safe_dir(parent)
 if os.path.lexists(group):safe_dir(group)
 if not os.path.lexists(stage):out({'state':'absent'})
 else:
  parents(root,group);state=inspect(stage,binding)
  out({'state':state,'sha256':binding['sha256'],'length':binding['length']} if state=='staged' else {'state':state})
except Exception:out({'state':'unknown'})
'''

_REMOTE_CLEANUP = _REMOTE_COMMON + r'''
try:
 root,group,stage,binding=setup();parents(root,group)
 lock=stage_lock(group,binding['correlationId'])
 state=inspect(stage,binding)
 if state not in ('partial','hash-mismatch','staged'):raise ValueError()
 for name in ('complete.json','base.msi','binding.json'):
  p=os.path.join(stage,name)
  if os.path.lexists(p):os.unlink(p)
 os.rmdir(stage)
 write_once(os.path.join(group,binding['correlationId']+'.closed.json'),json.dumps(binding,separators=(',',':'),sort_keys=True).encode())
 out({'state':'cleaned'})
except Exception:out({'state':'unknown'})
'''

_REMOTE_TERMINAL_CLEANUP = _REMOTE_COMMON + r'''
try:
 terminal=sys.argv.pop()
 if not re.fullmatch(r'[0-9a-f]{64}',terminal):raise ValueError()
 root,group,stage,binding=setup();parents(root,group)
 lock=stage_lock(group,binding['correlationId'])
 if inspect(stage,binding,True)!='staged':raise ValueError()
 names=set(os.listdir(stage))
 allowed={'binding.json','base.msi','complete.json','download-intent.json','worker.json',
          'listener-ready.json','listener-done.json','listener-stopped.json','task-cleaned.json'}
 if names-allowed or not {'download-intent.json','worker.json','listener-stopped.json','task-cleaned.json'}<=names:raise ValueError()
 worker=json.loads(read_file(os.path.join(stage,'worker.json')))
 stopped=json.loads(read_file(os.path.join(stage,'listener-stopped.json')))
 marker=json.loads(read_file(os.path.join(stage,'download-intent.json')))
 cleaned=json.loads(read_file(os.path.join(stage,'task-cleaned.json')))
 if (set(worker)!={'pid','startTicks','pathSha256'} or worker!=stopped
  or set(marker)!={'pathSha256'} or marker['pathSha256']!=worker['pathSha256']
  or type(worker['pid']) is not int or worker['pid']<=0 or not re.fullmatch(r'[0-9]+',worker['startTicks'])
  or ticks_of(worker['pid'])==worker['startTicks']
  or cleaned!={'terminalReceiptSha256':terminal,'guestTask':'absent','guestMsi':'absent'}):raise ValueError()
 if 'listener-ready.json' in names:
  ready=json.loads(read_file(os.path.join(stage,'listener-ready.json')))
  if (set(ready)!={'pid','startTicks','port','pathSha256'} or ready['pid']!=worker['pid']
   or ready['startTicks']!=worker['startTicks'] or ready['pathSha256']!=worker['pathSha256']
   or type(ready['port']) is not int or not 1<=ready['port']<=65535):raise ValueError()
  free_port(ready['port'])
 for name in sorted(names):os.unlink(os.path.join(stage,name))
 os.rmdir(stage)
 write_once(os.path.join(group,binding['correlationId']+'.closed.json'),json.dumps({'binding':binding,'terminalReceiptSha256':terminal},separators=(',',':'),sort_keys=True).encode())
 out({'state':'cleaned','terminalReceiptSha256':terminal})
except Exception:out({'state':'unknown'})
'''

_REMOTE_PRE_BASE_STATUS = _REMOTE_COMMON + r'''
try:
 root,group,stage,binding=setup();parents(root,group)
 if inspect(stage,binding,True)!='staged':raise ValueError()
 names=set(os.listdir(stage))
 if 'task-cleaned.json' in names or not {'download-intent.json','worker.json','listener-stopped.json'}<=names:raise ValueError()
 worker=json.loads(read_file(os.path.join(stage,'worker.json')))
 stopped=json.loads(read_file(os.path.join(stage,'listener-stopped.json')))
 marker=json.loads(read_file(os.path.join(stage,'download-intent.json')))
 if (set(worker)!={'pid','startTicks','pathSha256'} or worker!=stopped
  or set(marker)!={'pathSha256'} or marker['pathSha256']!=worker['pathSha256']
  or type(worker['pid']) is not int or worker['pid']<=0 or not re.fullmatch(r'[0-9]+',worker['startTicks'])
  or ticks_of(worker['pid'])==worker['startTicks']):raise ValueError()
 if 'listener-ready.json' in names:
  ready=json.loads(read_file(os.path.join(stage,'listener-ready.json')))
  if (set(ready)!={'pid','startTicks','port','pathSha256'} or ready['pid']!=worker['pid']
   or ready['startTicks']!=worker['startTicks'] or ready['pathSha256']!=worker['pathSha256']
   or type(ready['port']) is not int or not 1<=ready['port']<=65535):raise ValueError()
  free_port(ready['port'])
 out({'state':'staged-for-base','sha256':binding['sha256'],'length':binding['length']})
except Exception:out({'state':'unknown'})
'''

_REMOTE_TERMINAL_MARK = _REMOTE_COMMON + r'''
try:
 terminal=sys.argv.pop()
 if not re.fullmatch(r'[0-9a-f]{64}',terminal):raise ValueError()
 root,group,stage,binding=setup();parents(root,group)
 lock=stage_lock(group,binding['correlationId'])
 if inspect(stage,binding,True)!='staged':raise ValueError()
 worker=json.loads(read_file(os.path.join(stage,'worker.json')))
 stopped=json.loads(read_file(os.path.join(stage,'listener-stopped.json')))
 marker=json.loads(read_file(os.path.join(stage,'download-intent.json')))
 if (set(worker)!={'pid','startTicks','pathSha256'} or worker!=stopped
  or set(marker)!={'pathSha256'} or marker['pathSha256']!=worker['pathSha256']
  or type(worker['pid']) is not int or worker['pid']<=0 or not re.fullmatch(r'[0-9]+',worker['startTicks'])
  or ticks_of(worker['pid'])==worker['startTicks']):raise ValueError()
 if os.path.lexists(os.path.join(stage,'listener-ready.json')):
  ready=json.loads(read_file(os.path.join(stage,'listener-ready.json')))
  if type(ready.get('port')) is not int or not 1<=ready['port']<=65535:raise ValueError()
  free_port(ready['port'])
 value={'terminalReceiptSha256':terminal,'guestTask':'absent','guestMsi':'absent'}
 write_once(os.path.join(stage,'task-cleaned.json'),json.dumps(value,separators=(',',':'),sort_keys=True).encode())
 out({'state':'marked','terminalReceiptSha256':terminal})
except Exception:out({'state':'unknown'})
'''

_REMOTE_TERMINAL_STATUS = _REMOTE_COMMON + r'''
try:
 terminal=sys.argv.pop()
 if not re.fullmatch(r'[0-9a-f]{64}',terminal):raise ValueError()
 root,group,stage,binding=setup();parents(root,group)
 if os.path.lexists(stage):
  if inspect(stage,binding,True)!='staged':raise ValueError()
  value=json.loads(read_file(os.path.join(stage,'task-cleaned.json')))
  if value!={'terminalReceiptSha256':terminal,'guestTask':'absent','guestMsi':'absent'}:raise ValueError()
  out({'state':'marked','terminalReceiptSha256':terminal})
 else:
  closed=json.loads(read_file(os.path.join(group,binding['correlationId']+'.closed.json')))
  if closed!={'binding':binding,'terminalReceiptSha256':terminal}:raise ValueError()
  out({'state':'cleaned','terminalReceiptSha256':terminal})
except Exception:out({'state':'unknown'})
'''

_REMOTE_ABORT_CLEANUP = _REMOTE_COMMON + r'''
try:
 root,group,stage,binding=setup();parents(root,group)
 lock=stage_lock(group,binding['correlationId'])
 if inspect(stage,binding,True)!='staged':raise ValueError()
 names=set(os.listdir(stage))
 allowed={'binding.json','base.msi','complete.json','download-intent.json','worker.json',
          'listener-ready.json','listener-done.json','listener-stopped.json'}
 if names-allowed or not {'download-intent.json','worker.json','listener-stopped.json'}<=names:raise ValueError()
 worker=json.loads(read_file(os.path.join(stage,'worker.json')))
 stopped=json.loads(read_file(os.path.join(stage,'listener-stopped.json')))
 marker=json.loads(read_file(os.path.join(stage,'download-intent.json')))
 if (set(worker)!={'pid','startTicks','pathSha256'} or worker!=stopped
  or set(marker)!={'pathSha256'} or marker['pathSha256']!=worker['pathSha256']
  or type(worker['pid']) is not int or worker['pid']<=0 or not re.fullmatch(r'[0-9]+',worker['startTicks'])
  or ticks_of(worker['pid'])==worker['startTicks']):raise ValueError()
 if 'listener-ready.json' in names:
  ready=json.loads(read_file(os.path.join(stage,'listener-ready.json')))
  if (set(ready)!={'pid','startTicks','port','pathSha256'} or ready['pid']!=worker['pid']
   or ready['startTicks']!=worker['startTicks'] or ready['pathSha256']!=worker['pathSha256']
   or type(ready['port']) is not int or not 1<=ready['port']<=65535):raise ValueError()
  free_port(ready['port'])
 for name in sorted(names):os.unlink(os.path.join(stage,name))
 os.rmdir(stage)
 write_once(os.path.join(group,binding['correlationId']+'.closed.json'),json.dumps({'binding':binding,'outcome':'aborted'},separators=(',',':'),sort_keys=True).encode())
 out({'state':'aborted-cleaned'})
except Exception:out({'state':'unknown'})
'''

_REMOTE_ABORT_STATUS = _REMOTE_COMMON + r'''
try:
 root,group,stage,binding=setup();parents(root,group)
 if os.path.lexists(stage):
  if inspect(stage,binding,True)!='staged':raise ValueError()
  out({'state':'present'})
 else:
  closed=json.loads(read_file(os.path.join(group,binding['correlationId']+'.closed.json')))
  if closed!={'binding':binding,'outcome':'aborted'}:raise ValueError()
  out({'state':'aborted-cleaned'})
except Exception:out({'state':'unknown'})
'''

# The worker has a single unguessable origin-form path and serves one GET from
# the already verified private stage.  It never accepts a caller-supplied path.
_HTTP_WORKER = r'''import hashlib,http.server,json,os,stat,sys,time
stage=sys.argv[1]
raw=sys.stdin.buffer.read(1025)
v=json.loads(raw) if 0<len(raw)<=1024 else None
if not isinstance(v,dict) or set(v)!={'path','sha256','length'}:raise SystemExit(2)
path=v['path'];expected=v['sha256'];length=v['length']
def once(name,value):
 p=os.path.join(stage,name);fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'wb') as f:f.write(json.dumps(value,separators=(',',':'),sort_keys=True).encode());f.flush();os.fsync(f.fileno())
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  if self.path!=path or self.headers.get('Proxy-Connection') is not None:
   self.send_response(404);self.end_headers();return
  fd=os.open(os.path.join(stage,'base.msi'),os.O_RDONLY|getattr(os,'O_NOFOLLOW',0));h=hashlib.sha256()
  with os.fdopen(fd,'rb') as f:
   i=os.fstat(f.fileno())
   if not stat.S_ISREG(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o600 or i.st_size!=length:
    self.send_error(500);return
   for chunk in iter(lambda:f.read(1048576),b''):h.update(chunk)
   if h.hexdigest()!=expected:
    self.send_error(500);return
   f.seek(0);h=hashlib.sha256()
   self.send_response(200);self.send_header('Content-Length',str(length));self.send_header('Connection','close');self.end_headers()
   for chunk in iter(lambda:f.read(1048576),b''):
    self.wfile.write(chunk);h.update(chunk)
  self.server.served=(h.hexdigest()==expected);self.server.attempted=True
 def do_CONNECT(self):self.send_error(405)
class Server(http.server.HTTPServer):allow_reuse_address=False
server=Server(('127.0.0.1',0),Handler);server.timeout=.2;server.served=False;server.attempted=False
ticks=open('/proc/self/stat','rb').read().split()[21].decode()
once('listener-ready.json',{'pid':os.getpid(),'startTicks':ticks,'port':server.server_address[1],'pathSha256':hashlib.sha256(path.encode()).hexdigest()})
deadline=time.monotonic()+90
while time.monotonic()<deadline and not server.attempted:server.handle_request()
server.server_close();once('listener-done.json',{'served':server.served})
'''

_REMOTE_LISTEN_START = _REMOTE_COMMON + r'''import base64,subprocess,time
try:
 root,group,stage,binding=setup();parents(root,group);safe_dir(stage)
 if inspect(stage,binding,True)!='staged':raise ValueError()
 lock=stage_lock(group,binding['correlationId'])
 if os.path.lexists(os.path.join(stage,'download-intent.json')):raise ValueError()
 raw=sys.stdin.buffer.read(1025);v=json.loads(raw) if 0<len(raw)<=1024 else None
 if not isinstance(v,dict) or set(v)!={'path'} or not re.fullmatch(r'/[A-Za-z0-9_-]{32,128}',v['path']):raise ValueError()
 write_once(os.path.join(stage,'download-intent.json'),json.dumps({'pathSha256':hashlib.sha256(v['path'].encode()).hexdigest()},separators=(',',':'),sort_keys=True).encode())
 worker=base64.b64decode('WORKER_B64')
 child=subprocess.Popen((sys.executable,'-c',worker.decode(),stage),stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,close_fds=True)
 child_ticks=ticks_of(child.pid)
 if not child_ticks:raise ValueError()
 write_once(os.path.join(stage,'worker.json'),json.dumps({'pid':child.pid,'startTicks':child_ticks,'pathSha256':hashlib.sha256(v['path'].encode()).hexdigest()},separators=(',',':'),sort_keys=True).encode())
 payload=json.dumps({'path':v['path'],'sha256':binding['sha256'],'length':binding['length']},separators=(',',':')).encode()
 child.stdin.write(payload);child.stdin.close()
 for _ in range(100):
  if os.path.lexists(os.path.join(stage,'listener-ready.json')):break
  if child.poll() is not None:raise ValueError()
  time.sleep(.02)
 else:raise ValueError()
 ready=json.loads(read_file(os.path.join(stage,'listener-ready.json')))
 ticks=ticks_of(child.pid)
 if (set(ready)!={'pid','startTicks','port','pathSha256'} or ready['pid']!=child.pid or ready['startTicks']!=ticks
  or type(ready['port']) is not int or not 1<=ready['port']<=65535
  or ready['pathSha256']!=hashlib.sha256(v['path'].encode()).hexdigest()
  or not owned_listener(child.pid,child_ticks,ready['port'])):raise ValueError()
 out({'state':'listening','port':ready['port'],'path':v['path']})
except Exception:out({'state':'unknown'})
'''

_REMOTE_LISTEN_STATUS = _REMOTE_COMMON + r'''import signal
try:
 root,group,stage,binding=setup();parents(root,group)
 if inspect(stage,binding,True)!='staged':raise ValueError()
 marker=json.loads(read_file(os.path.join(stage,'download-intent.json')))
 worker=json.loads(read_file(os.path.join(stage,'worker.json')))
 if (set(marker)!={'pathSha256'} or set(worker)!={'pid','startTicks','pathSha256'}
  or worker['pathSha256']!=marker['pathSha256'] or type(worker['pid']) is not int or worker['pid']<=0
  or not re.fullmatch(r'[0-9]+',worker['startTicks'])):raise ValueError()
 ready_path=os.path.join(stage,'listener-ready.json')
 stopped_path=os.path.join(stage,'listener-stopped.json')
 if os.path.lexists(stopped_path):
  if json.loads(read_file(stopped_path))!=worker:raise ValueError()
  if os.path.lexists(ready_path):
   prior=json.loads(read_file(ready_path));free_port(prior['port'])
  out({'state':'stopped'});raise SystemExit(0)
 if not os.path.lexists(ready_path):
  out({'state':'starting' if ticks_of(worker['pid'])==worker['startTicks'] else 'failed'});raise SystemExit(0)
 ready=json.loads(read_file(ready_path))
 if (set(ready)!={'pid','startTicks','port','pathSha256'} or ready['pid']!=worker['pid']
  or ready['startTicks']!=worker['startTicks'] or ready['pathSha256']!=marker['pathSha256']
  or type(ready['port']) is not int or not 1<=ready['port']<=65535):raise ValueError()
 done=os.path.join(stage,'listener-done.json')
 if os.path.lexists(done):
  value=json.loads(read_file(done))
  if set(value)!={'served'} or type(value['served']) is not bool:raise ValueError()
  free_port(ready['port'])
  out({'state':'served' if value['served'] else 'stopped','port':ready['port'],'pathSha256':ready['pathSha256']})
 else:
  if not owned_listener(ready['pid'],ready['startTicks'],ready['port']):raise ValueError()
  out({'state':'listening','port':ready['port'],'pathSha256':ready['pathSha256']})
except Exception:out({'state':'unknown'})
'''

_REMOTE_LISTEN_DIAGNOSTIC = _REMOTE_COMMON + r'''
view={'state':'diagnosed','binding':'unknown','stageFiles':'unknown','intent':'unknown',
      'worker':'unknown','ready':'unknown','done':'unknown','stopped':'unknown',
      'port':'unknown','reason':'observation-error'}
try:
 root,group,stage,binding=setup();parents(root,group);safe_dir(stage)
 names=set(os.listdir(stage))
 allowed={'binding.json','base.msi','complete.json','download-intent.json','worker.json',
          'listener-ready.json','listener-done.json','listener-stopped.json','task-cleaned.json'}
 view['stageFiles']='allowed' if names<=allowed else 'foreign'
 observed=json.loads(read_file(os.path.join(stage,'binding.json')))
 view['binding']='exact' if observed==binding else 'mismatch'
 if view['binding']!='exact':view['reason']='binding-mismatch';out(view);raise SystemExit(0)
 intent=None;worker=None;ready=None
 if 'download-intent.json' not in names:view['intent']='absent'
 else:
  intent=json.loads(read_file(os.path.join(stage,'download-intent.json')))
  view['intent']='exact' if set(intent)=={'pathSha256'} and re.fullmatch(r'[0-9a-f]{64}',intent['pathSha256']) else 'mismatch'
 if 'worker.json' not in names:view['worker']='absent'
 else:
  worker=json.loads(read_file(os.path.join(stage,'worker.json')))
  if (set(worker)!={'pid','startTicks','pathSha256'} or type(worker['pid']) is not int or worker['pid']<=0
   or not isinstance(worker['startTicks'],str) or not re.fullmatch(r'[0-9]+',worker['startTicks'])
   or view['intent']!='exact' or worker['pathSha256']!=intent['pathSha256']):view['worker']='mismatch'
  else:
   ticks=ticks_of(worker['pid'])
   view['worker']='live' if ticks==worker['startTicks'] else 'exited' if not ticks else 'reused'
 if 'listener-ready.json' not in names:view['ready']='absent'
 else:
  ready=json.loads(read_file(os.path.join(stage,'listener-ready.json')))
  if (not isinstance(ready,dict) or set(ready)!={'pid','startTicks','port','pathSha256'}
   or worker is None or view['worker'] in ('mismatch','absent')
   or ready['pid']!=worker['pid'] or ready['startTicks']!=worker['startTicks']
   or ready['pathSha256']!=worker['pathSha256'] or type(ready['port']) is not int
   or not 1<=ready['port']<=65535):view['ready']='mismatch'
  else:
   view['ready']='exact'
   if owned_listener(worker['pid'],worker['startTicks'],ready['port']):view['port']='owned'
   else:
    try:free_port(ready['port']);view['port']='free'
    except OSError:view['port']='foreign'
 if 'listener-done.json' not in names:view['done']='absent'
 else:
  done=json.loads(read_file(os.path.join(stage,'listener-done.json')))
  view['done']='served' if done=={'served':True} else 'unserved' if done=={'served':False} else 'mismatch'
 if 'listener-stopped.json' not in names:view['stopped']='absent'
 else:
  stopped=json.loads(read_file(os.path.join(stage,'listener-stopped.json')))
  view['stopped']='exact' if worker is not None and stopped==worker else 'mismatch'
 if view['stageFiles']=='foreign':view['reason']='foreign-files'
 elif view['intent']=='mismatch':view['reason']='intent-mismatch'
 elif view['worker']=='mismatch':view['reason']='worker-mismatch'
 elif view['ready']=='mismatch':view['reason']='ready-mismatch'
 elif view['done']=='mismatch':view['reason']='done-mismatch'
 elif view['stopped']=='mismatch':view['reason']='stopped-mismatch'
 elif view['port']=='foreign':view['reason']='port-foreign'
 elif view['stopped']=='exact':view['reason']='explicitly-stopped'
 elif view['done']=='served' and view['port']=='free':view['reason']='served-awaiting-stop'
 elif view['done']=='served' and view['port']=='owned':view['reason']='worker-open-after-serve'
 elif view['done']=='unserved' and view['port']=='free':view['reason']='unserved-awaiting-stop'
 elif view['done']=='absent' and view['worker']=='exited':view['reason']='worker-exited-no-done'
 elif view['done']=='absent' and view['worker']=='live' and view['port']=='owned':view['reason']='listening'
 elif view['done']=='absent' and view['worker']=='live':view['reason']='worker-live-no-done'
 out(view)
except Exception:out(view)
'''

_LISTENER_DIAGNOSTIC_FIELDS = {"state", "binding", "stageFiles", "intent", "worker", "ready",
                               "done", "stopped", "port", "reason"}
_LISTENER_DIAGNOSTIC_ENUMS = {
    "binding": {"exact", "mismatch", "unknown"},
    "stageFiles": {"allowed", "foreign", "unknown"},
    "intent": {"exact", "absent", "mismatch", "unknown"},
    "worker": {"live", "exited", "reused", "absent", "mismatch", "unknown"},
    "ready": {"exact", "absent", "mismatch", "unknown"},
    "done": {"served", "unserved", "absent", "mismatch", "unknown"},
    "stopped": {"exact", "absent", "mismatch", "unknown"},
    "port": {"owned", "free", "foreign", "unknown"},
    "reason": {"observation-error", "binding-mismatch", "foreign-files", "intent-mismatch",
               "worker-mismatch", "ready-mismatch", "done-mismatch", "stopped-mismatch",
               "port-foreign", "explicitly-stopped", "served-awaiting-stop",
               "worker-open-after-serve", "unserved-awaiting-stop", "worker-exited-no-done",
               "listening", "worker-live-no-done"},
}


def _project_listener_diagnostic(raw: bytes | None) -> dict[str, Any]:
    if raw is None or len(raw) > 1024:
        return dict(_UNKNOWN)
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return dict(_UNKNOWN)
    if not isinstance(value, dict) or set(value) != _LISTENER_DIAGNOSTIC_FIELDS or value.get("state") != "diagnosed":
        return dict(_UNKNOWN)
    for key, allowed in _LISTENER_DIAGNOSTIC_ENUMS.items():
        if not isinstance(value[key], str) or value[key] not in allowed:
            return dict(_UNKNOWN)
    return {**value, "replayAllowed": False, "nativeActionAllowed": False,
            "productAction": False}

_REMOTE_LISTEN_STOP = _REMOTE_COMMON + r'''import signal,time
try:
 root,group,stage,binding=setup();parents(root,group)
 if inspect(stage,binding,True)!='staged':raise ValueError()
 marker=json.loads(read_file(os.path.join(stage,'download-intent.json')))
 worker=json.loads(read_file(os.path.join(stage,'worker.json')))
 if (set(marker)!={'pathSha256'} or set(worker)!={'pid','startTicks','pathSha256'}
  or marker['pathSha256']!=worker['pathSha256'] or type(worker['pid']) is not int or worker['pid']<=0
  or not re.fullmatch(r'[0-9]+',worker['startTicks'])):raise ValueError()
 ready_path=os.path.join(stage,'listener-ready.json');port=None
 if os.path.lexists(ready_path):
  ready=json.loads(read_file(ready_path))
  if (set(ready)!={'pid','startTicks','port','pathSha256'} or ready['pid']!=worker['pid']
   or ready['startTicks']!=worker['startTicks'] or ready['pathSha256']!=marker['pathSha256']
   or type(ready['port']) is not int or not 1<=ready['port']<=65535):raise ValueError()
  port=ready['port']
 ticks=ticks_of(worker['pid'])
 if ticks==worker['startTicks']:
  if port is not None:
   if os.path.lexists(os.path.join(stage,'listener-done.json')):free_port(port)
   elif not owned_listener(worker['pid'],worker['startTicks'],port):raise ValueError()
  os.killpg(worker['pid'],signal.SIGTERM)
  for _ in range(100):
   if ticks_of(worker['pid'])!=ticks:break
   time.sleep(.02)
  else:raise ValueError()
 if port is not None:free_port(port)
 write_once(os.path.join(stage,'listener-stopped.json'),json.dumps(worker,separators=(',',':'),sort_keys=True).encode())
 out({'state':'stopped'})
except Exception:out({'state':'unknown'})
'''

import base64 as _base64
_REMOTE_LISTEN_START = _REMOTE_LISTEN_START.replace('WORKER_B64', _base64.b64encode(_HTTP_WORKER.encode()).decode())

_GUEST_DOWNLOAD_PS = r'''$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Net.Http
$sid='@SID@';$corr='@CORR@';$digest='@DIGEST@';$length=@SIZE@
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne $sid) { throw 'SID' }
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if ((Get-Process -Id $PID).SessionId -ne 1 -or ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'TOKEN' }
$profile='C:\Users\vpncp117';$local=Join-Path $profile 'AppData\Local'
if (-not [string]::Equals([IO.Path]::GetFullPath($env:LOCALAPPDATA).TrimEnd('\'),$local,[StringComparison]::OrdinalIgnoreCase)) { throw 'LOCALAPPDATA' }
function Assert-OwnedDirectory([string]$p,[bool]$allowSystemProfile=$false) {
 $item=Get-Item -LiteralPath $p -Force -ErrorAction Stop
 if (-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'REPARSE' }
 $owner=([Security.Principal.NTAccount]::new((Get-Acl -LiteralPath $p).Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
 if ($owner -cne $sid -and -not ($allowSystemProfile -and $owner -ceq 'S-1-5-18')) { throw 'OWNER' }
}
Assert-OwnedDirectory $profile $true;Assert-OwnedDirectory (Join-Path $profile 'AppData');Assert-OwnedDirectory $local
$appRoot=Join-Path $local 'VpnControl'
if (-not [IO.Directory]::Exists($appRoot)) { [void][IO.Directory]::CreateDirectory($appRoot) }
Assert-OwnedDirectory $appRoot
$dir=Join-Path $appRoot ('mcp-base-'+$corr)
if (-not [IO.Directory]::Exists($dir)) { [void][IO.Directory]::CreateDirectory($dir) }
Assert-OwnedDirectory $dir
$partial=Join-Path $dir 'base.msi.partial';$final=Join-Path $dir 'base.msi'
if (@(Get-ChildItem -LiteralPath $dir -Force).Count -ne 0) { throw 'FOREIGN_LEAF' }
if ([IO.File]::Exists($partial) -or [IO.File]::Exists($final)) { throw 'EXISTS' }
$handler=[Net.Http.HttpClientHandler]::new();$handler.UseProxy=$false
$client=[Net.Http.HttpClient]::new($handler);$client.Timeout=[TimeSpan]::FromSeconds(75)
try {
 $url='http://10.0.2.2:@PORT@/@PATH@'
 $response=$client.GetAsync($url,[Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
 try {
  if (-not $response.IsSuccessStatusCode -or $response.Content.Headers.ContentLength -ne $length) { throw 'HTTP' }
  $inputStream=$response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
  try {
   $output=[IO.FileStream]::new($partial,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
   $sha=[Security.Cryptography.SHA256]::Create();$count=[int64]0
   try {
    $buffer=New-Object byte[] 65536
    while (($n=$inputStream.Read($buffer,0,$buffer.Length)) -gt 0) {
     $count+=$n;if ($count -gt $length) { throw 'LENGTH' }
     $output.Write($buffer,0,$n);[void]$sha.TransformBlock($buffer,0,$n,$buffer,0)
    }
    [void]$sha.TransformFinalBlock((New-Object byte[] 0),0,0)
    $actual=([BitConverter]::ToString($sha.Hash)).Replace('-','').ToLowerInvariant()
    $output.Flush($true)
   } finally { $output.Dispose();$sha.Dispose() }
  } finally { $inputStream.Dispose() }
 } finally { $response.Dispose() }
 if ($count -ne $length -or $actual -cne $digest) { throw 'DIGEST' }
 $item=Get-Item -LiteralPath $partial -Force
 if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'REPARSE' }
 [IO.File]::Move($partial,$final)
 [Console]::Out.WriteLine(([pscustomobject]@{state='downloaded';sha256=$actual;length=$count}|ConvertTo-Json -Compress))
} finally { $client.Dispose();$handler.Dispose() }
'''

_HISTORICAL_CORRELATION = "2a5f795a-0601-475c-af97-3c32bccd1e27"
_HISTORICAL_DOWNLOAD_SHA256 = "fbcbd2301a53388e9c5b886331a4d341a8161d3db3053078401a99a9005ee8d2"


def _historical_download_script() -> str:
    """Pinned pre-profile-owner-exception script for one already-dispatched task."""
    changes = (
        ("function Assert-OwnedDirectory([string]$p,[bool]$allowSystemProfile=$false)",
         "function Assert-OwnedDirectory([string]$p)"),
        ("if ($owner -cne $sid -and -not ($allowSystemProfile -and $owner -ceq 'S-1-5-18')) { throw 'OWNER' }",
         "if ($owner -cne $sid) { throw 'OWNER' }"),
        ("Assert-OwnedDirectory $profile $true;", "Assert-OwnedDirectory $profile;"),
    )
    script = _GUEST_DOWNLOAD_PS
    for current, historical in changes:
        if script.count(current) != 1:
            raise WindowsMsiHttpTransferError("Historical transfer script identity drifted.")
        script = script.replace(current, historical)
    if hashlib.sha256(script.encode()).hexdigest() != _HISTORICAL_DOWNLOAD_SHA256:
        raise WindowsMsiHttpTransferError("Historical transfer script digest drifted.")
    return script


def _action_args_sha(script: str, sid: str, correlation: str, digest: str,
                     length: int, port: int, path: str) -> str:
    for key, value in (("SID", sid), ("CORR", correlation), ("DIGEST", digest),
                       ("SIZE", str(length)), ("PORT", str(port)), ("PATH", path[1:])):
        script = script.replace("@" + key + "@", value)
    command = "-NoProfile -NonInteractive -EncodedCommand " + base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return hashlib.sha256(command.encode("utf-8")).hexdigest()


def _historical_action_hash(correlation: str, sid: str, digest: str, length: int,
                            port: int, path: str) -> str | None:
    if correlation != _HISTORICAL_CORRELATION:
        return None
    return _action_args_sha(_historical_download_script(), sid, correlation, digest, length, port, path)

_REMOTE_GUEST_DOWNLOAD = base._QGA + base._TRANSFER_NETWORK_QEMU_TOPOLOGY + r'''import time
sock,pid,ticks,sid,corr,port,path,digest,size=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if (not live(sock,pid,ticks) or not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+',sid)
  or not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',corr)
  or not port.isdigit() or not 1<=int(port)<=65535
  or not re.fullmatch(r'/[A-Za-z0-9_-]{32,128}',path)
  or not re.fullmatch(r'[0-9a-f]{64}',digest) or not size.isdigit() or not 0<int(size)<=1073741824):raise ValueError()
 user_network(pid)
 script=base64.b64decode('PS_B64').decode()
 for key,value in (('SID',sid),('CORR',corr),('DIGEST',digest),('SIZE',size),('PORT',port),('PATH',path[1:])):script=script.replace('@'+key+'@',value)
 encoded=base64.b64encode(script.encode('utf-16le')).decode('ascii')
 if len(encoded)>30000:raise ValueError()
 task='VpnControlMcpTransfer-'+corr
 bootstrap="$ErrorActionPreference='Stop';$task='"+task+"';$account='VPNMSIX64\\vpncp117';$resolved=([Security.Principal.NTAccount]::new($account)).Translate([Security.Principal.SecurityIdentifier]).Value;if($resolved -cne '"+sid+"'){throw 'SID_MISMATCH'};if(Get-ScheduledTask -TaskPath '\\' -TaskName $task -ErrorAction SilentlyContinue){throw 'EXISTS'};$action=New-ScheduledTaskAction -Execute 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' -Argument ('-NoProfile -NonInteractive -EncodedCommand "+encoded+"');$principal=New-ScheduledTaskPrincipal -UserId $account -LogonType Interactive -RunLevel Limited;$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries;Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings|Out-Null;Start-ScheduledTask -TaskName $task;[Console]::Out.WriteLine('{\"state\":\"submitted\"}')"
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(bootstrap.encode('utf-16le')).decode()],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(200):
  item=call(sock,'guest-exec-status',{'pid':child})
  if item.get('exited') is True:break
  if item.get('exited') is not False:raise ValueError()
  time.sleep(.5)
 else:raise ValueError()
 if (set(item)-{'exited','exitcode','out-data','err-data','out-truncated','err-truncated'}
  or type(item.get('exitcode')) is not int or item['exitcode']!=0
  or item.get('out-truncated',False) is not False or item.get('err-truncated',False) is not False):raise ValueError()
 raw=base64.b64decode(item.get('out-data',''),validate=True)
 if not 0<len(raw)<=512:raise ValueError()
 lines=[v for v in decode(raw).splitlines() if v.startswith('{') and v.endswith('}')]
 value=json.loads(lines[0]) if len(lines)==1 else None
 if value!={'state':'submitted'}:raise ValueError()
 out(value)
except Exception:out({'state':'unknown'})
'''
_REMOTE_GUEST_DOWNLOAD = _REMOTE_GUEST_DOWNLOAD.replace('PS_B64', _base64.b64encode(_GUEST_DOWNLOAD_PS.encode()).decode())

_GUEST_STATUS_PS = r'''$ErrorActionPreference='Stop'
$sid='@SID@';$corr='@CORR@';$digest='@DIGEST@';$length=@SIZE@;$mode='@MODE@'
$resolved=([Security.Principal.NTAccount]::new('VPNMSIX64\vpncp117')).Translate([Security.Principal.SecurityIdentifier]).Value
if ($resolved -cne $sid) { throw 'SID_MISMATCH' }
function PrincipalSid([string]$userId) {
 if ($userId -match '^S-1-') { return ([Security.Principal.SecurityIdentifier]::new($userId)).Value }
 return ([Security.Principal.NTAccount]::new($userId)).Translate([Security.Principal.SecurityIdentifier]).Value
}
$task=Get-ScheduledTask -TaskPath '\' -TaskName ('VpnControlMcpTransfer-'+$corr) -ErrorAction SilentlyContinue
if ($mode -ceq 'before') {
 if ($null -eq $task) { throw 'TASK' }
 $principalSid=PrincipalSid ([string]($task.Principal.UserId))
 if ($principalSid -cne $sid -or $task.Principal.LogonType -cne 'Interactive' -or $task.Principal.RunLevel -cne 'Limited') { throw 'TASK' }
 $actions=@($task.Actions)
 if ($actions.Count -ne 1 -or $actions[0].Execute -cne 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe') { throw 'ACTION' }
 $argsHash=([BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash([Text.Encoding]::UTF8.GetBytes($actions[0].Arguments)))).Replace('-','').ToLowerInvariant()
 if ($argsHash -cne '@ARGS_SHA@') { throw 'ARGUMENTS' }
 $running=($task.State -eq 'Running')
} elseif ($mode -ceq 'after') {
 if ($null -ne $task) { throw 'TASK_PRESENT' };$running=$false
} else { throw 'MODE' }
$profile='C:\Users\vpncp117';$local=Join-Path $profile 'AppData\Local'
function Assert-Owned([string]$p,[bool]$directory,[bool]$allowSystemProfile=$false) {
 $item=Get-Item -LiteralPath $p -Force -ErrorAction Stop
 if ($item.PSIsContainer -ne $directory -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'REPARSE' }
 $owner=([Security.Principal.NTAccount]::new((Get-Acl -LiteralPath $p).Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
 if ($owner -cne $sid -and -not ($allowSystemProfile -and $owner -ceq 'S-1-5-18')) { throw 'OWNER' }
}
Assert-Owned $profile $true $true;Assert-Owned (Join-Path $profile 'AppData') $true;Assert-Owned $local $true
$appRoot=Join-Path $local 'VpnControl'
if (-not [IO.Directory]::Exists($appRoot)) { [Console]::Out.WriteLine($(if($running){'{"state":"running"}'}else{'{"state":"absent"}'}));exit 0 }
Assert-Owned $appRoot $true
$dir=Join-Path $appRoot ('mcp-base-'+$corr)
if (-not [IO.Directory]::Exists($dir)) { [Console]::Out.WriteLine($(if($running){'{"state":"running"}'}else{'{"state":"absent"}'}));exit 0 }
Assert-Owned $dir $true
$partial=Join-Path $dir 'base.msi.partial';$final=Join-Path $dir 'base.msi'
if ([IO.File]::Exists($partial) -and [IO.File]::Exists($final)) { throw 'BOTH' }
if ([IO.File]::Exists($final)) { $p=$final;$complete=$true }
elseif ([IO.File]::Exists($partial)) { $p=$partial;$complete=$false }
else { [Console]::Out.WriteLine($(if($running){'{"state":"running"}'}else{'{"state":"absent"}'}));exit 0 }
Assert-Owned $p $false
$info=Get-Item -LiteralPath $p -Force
if ($running) { [Console]::Out.WriteLine('{"state":"running"}');exit 0 }
if (-not $complete) { [Console]::Out.WriteLine('{"state":"partial"}');exit 0 }
$actual=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()
if ($info.Length -ne $length -or $actual -cne $digest) { [Console]::Out.WriteLine('{"state":"hash-mismatch"}');exit 0 }
[Console]::Out.WriteLine(([pscustomobject]@{state=$(if($mode -ceq 'after'){'ready-for-base'}else{'downloaded'});sha256=$actual;length=$info.Length}|ConvertTo-Json -Compress))
'''

_REMOTE_GUEST_STATUS = base._QGA + r'''import time
sock,pid,ticks,sid,corr,port,path,digest,size,args_hash,mode=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if (not live(sock,pid,ticks) or not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+',sid)
  or not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',corr)
  or not port.isdigit() or not 1<=int(port)<=65535 or not re.fullmatch(r'/[A-Za-z0-9_-]{32,128}',path)
  or not re.fullmatch(r'[0-9a-f]{64}',digest) or not size.isdigit() or not 0<int(size)<=1073741824
  or not re.fullmatch(r'[0-9a-f]{64}',args_hash) or mode not in ('before','after')):raise ValueError()
 script=base64.b64decode('PS_B64').decode()
 for key,value in (('SID',sid),('CORR',corr),('DIGEST',digest),('SIZE',size),('ARGS_SHA',args_hash),('MODE',mode)):script=script.replace('@'+key+'@',value)
 encoded=base64.b64encode(script.encode('utf-16le')).decode('ascii')
 if len(encoded)>30000:raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(200):
  item=call(sock,'guest-exec-status',{'pid':child})
  if item.get('exited') is True:break
  if item.get('exited') is not False:raise ValueError()
  time.sleep(.5)
 else:raise ValueError()
 if (set(item)-{'exited','exitcode','out-data','err-data','out-truncated','err-truncated'}
  or type(item.get('exitcode')) is not int or item['exitcode']!=0
  or item.get('out-truncated',False) is not False or item.get('err-truncated',False) is not False):raise ValueError()
 raw=base64.b64decode(item.get('out-data',''),validate=True)
 if not 0<len(raw)<=512:raise ValueError()
 lines=[v for v in decode(raw).splitlines() if v.startswith('{') and v.endswith('}')]
 value=json.loads(lines[0]) if len(lines)==1 else None
 if not isinstance(value,dict) or value.get('state') not in ('absent','running','partial','hash-mismatch','downloaded','ready-for-base'):raise ValueError()
 if value['state'] in ('downloaded','ready-for-base'):
  if value!={'state':'downloaded' if mode=='before' else 'ready-for-base','sha256':digest,'length':int(size)}:raise ValueError()
 elif set(value)!={'state'}:raise ValueError()
 out(value)
except Exception:out({'state':'unknown'})
'''
_REMOTE_GUEST_STATUS = _REMOTE_GUEST_STATUS.replace('PS_B64', _base64.b64encode(_GUEST_STATUS_PS.encode()).decode())

_GUEST_DIAGNOSTIC_PS = r'''$ErrorActionPreference='Stop'
$sid='@SID@';$corr='@CORR@';$digest='@DIGEST@';$length=@SIZE@
$account='VPNMSIX64\vpncp117'
$view=[ordered]@{state='diagnosed';task='unknown';principal='unknown';action='unknown';sid='unknown';leaf='unknown';reason='observation-error';principalUser='unknown';principalLogon='unknown';principalRunLevel='unknown';leafAt='unknown';leafFault='unknown';leafOwner='none'}
try {
 try {
  $resolved=([Security.Principal.NTAccount]::new($account)).Translate([Security.Principal.SecurityIdentifier]).Value
  $view.sid=$(if($resolved -ceq $sid){'exact'}else{'mismatch'})
 } catch { $view.sid='unknown' }
 $name='VpnControlMcpTransfer-'+$corr
 $task=Get-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction SilentlyContinue
 $taskFailed=$false;$taskNeverRan=$false
 if ($null -eq $task) { $view.task='absent' }
 else {
  $view.task=$(if ($task.State -eq 'Running') {'running'} else {'terminal'})
  $view.principalLogon=$(if($task.Principal.LogonType -eq 'Interactive'){'exact'}else{'mismatch'})
  $view.principalRunLevel=$(if($task.Principal.RunLevel -eq 'Limited'){'exact'}else{'mismatch'})
  if ($task.Principal.UserId -ceq $account) { $view.principalUser='exact-string' }
  else {
   try {
    $userId=[string]($task.Principal.UserId)
    if ($userId -match '^S-1-') { $userSid=([Security.Principal.SecurityIdentifier]::new($userId)).Value }
    else { $userSid=([Security.Principal.NTAccount]::new($userId)).Translate([Security.Principal.SecurityIdentifier]).Value }
    $view.principalUser=$(if($userSid -ceq $sid){'same-sid'}else{'different-sid'})
   } catch { $view.principalUser='unresolved' }
  }
  $view.principal=$(if(($view.principalUser -in @('exact-string','same-sid')) -and $view.principalLogon -eq 'exact' -and $view.principalRunLevel -eq 'exact'){'exact'}else{'mismatch'})
  $actions=@($task.Actions)
  if ($actions.Count -eq 1 -and $actions[0].Execute -ceq 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe') {
   $sha=[Security.Cryptography.SHA256]::Create()
   try { $hash=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($actions[0].Arguments)))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
   $view.action=$(if($hash -ceq '@ARGS_SHA@'){'exact'}else{'mismatch'})
  } else { $view.action='mismatch' }
  if ($view.task -eq 'terminal') {
   try {
    $taskInfo=Get-ScheduledTaskInfo -TaskPath '\' -TaskName $name -ErrorAction Stop
    $taskFailed=($taskInfo.LastTaskResult -ne 0)
    $taskNeverRan=($taskInfo.LastRunTime.Year -lt 2000)
   } catch { $taskFailed=$true }
  }
 }
 function Owned([string]$p,[bool]$directory,[string]$at,[bool]$allowSystemProfile=$false) {
  $item=Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
  if ($null -eq $item) { $view.leafAt=$at;$view.leafFault='missing';return $false }
  if ($item.PSIsContainer -ne $directory) { $view.leafAt=$at;$view.leafFault='type';return $false }
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $view.leafAt=$at;$view.leafFault='reparse';return $false }
  try {
   $ownerName=(Get-Acl -LiteralPath $p -ErrorAction Stop).Owner
   if ($ownerName -match '^S-1-') { $owner=([Security.Principal.SecurityIdentifier]::new($ownerName)).Value }
   else { $owner=([Security.Principal.NTAccount]::new($ownerName)).Translate([Security.Principal.SecurityIdentifier]).Value }
  } catch { $view.leafAt=$at;$view.leafFault='owner-unresolved';$view.leafOwner='unresolved';return $false }
  if ($owner -cne $sid -and -not ($allowSystemProfile -and $owner -ceq 'S-1-5-18')) {
   $view.leafAt=$at;$view.leafFault='owner';$view.leafOwner=$(if($owner -ceq 'S-1-5-18'){'system'}else{'other'});return $false
  }
  return $true
 }
 $profile='C:\Users\vpncp117';$local=Join-Path $profile 'AppData\Local';$appRoot=Join-Path $local 'VpnControl';$dir=Join-Path $appRoot ('mcp-base-'+$corr)
 if (-not (Owned $profile $true 'profile' $true) -or -not (Owned (Join-Path $profile 'AppData') $true 'appdata') -or -not (Owned $local $true 'local')) { $view.leaf='unsafe' }
 elseif (-not [IO.Directory]::Exists($appRoot)) { $view.leaf='absent' }
 elseif (-not (Owned $appRoot $true 'app-root')) { $view.leaf='unsafe' }
 elseif (-not [IO.Directory]::Exists($dir)) { $view.leaf='absent' }
 elseif (-not (Owned $dir $true 'stage')) { $view.leaf='unsafe' }
 else {
  $partial=Join-Path $dir 'base.msi.partial';$final=Join-Path $dir 'base.msi'
  if ([IO.File]::Exists($partial) -and [IO.File]::Exists($final)) { $view.leaf='unsafe';$view.leafAt='both';$view.leafFault='collision' }
  elseif ([IO.File]::Exists($final)) {
   if (-not (Owned $final $false 'final')) { $view.leaf='unsafe' }
   else {
    $size=(Get-Item -LiteralPath $final -Force).Length
    $hash=(Get-FileHash -LiteralPath $final -Algorithm SHA256).Hash.ToLowerInvariant()
    $view.leaf=$(if($size -eq $length -and $hash -ceq $digest){'full'}else{'hash-mismatch'})
   }
  } elseif ([IO.File]::Exists($partial)) {
   $view.leaf=$(if(Owned $partial $false 'partial'){'partial'}else{'unsafe'})
  } else { $view.leaf='absent' }
 }
 if ($view.sid -eq 'mismatch') { $view.reason='sid-mismatch' }
 elseif ($view.sid -eq 'unknown') { $view.reason='sid-unavailable' }
 elseif ($view.task -eq 'absent') { $view.reason='task-absent' }
 elseif ($view.principal -eq 'mismatch') { $view.reason='principal-mismatch' }
 elseif ($view.action -eq 'mismatch') { $view.reason='action-mismatch' }
 elseif ($view.task -eq 'running') { $view.reason='task-running' }
 elseif ($view.leaf -eq 'unsafe') { $view.reason='leaf-unsafe' }
 elseif ($taskNeverRan) { $view.reason='task-not-run' }
 elseif ($taskFailed) { $view.reason='task-terminal-failed' }
 elseif ($view.leaf -eq 'absent') { $view.reason='leaf-absent' }
 elseif ($view.leaf -eq 'partial') { $view.reason='leaf-partial' }
 elseif ($view.leaf -eq 'hash-mismatch') { $view.reason='leaf-hash-mismatch' }
 elseif ($view.leaf -eq 'full') { $view.reason='ready' }
} catch { $view.reason='observation-error' }
[Console]::Out.WriteLine(([pscustomobject]$view|ConvertTo-Json -Compress))
'''

_GUEST_OWNER_CENSUS_PS = r'''$ErrorActionPreference='Stop'
$sid='@SID@';$corr='@CORR@'
$profile='C:\Users\vpncp117';$appdata=Join-Path $profile 'AppData';$local=Join-Path $appdata 'Local'
$appRoot=Join-Path $local 'VpnControl';$stage=Join-Path $appRoot ('mcp-base-'+$corr)
$fixed=[ordered]@{profile=$profile;appdata=$appdata;local=$local;'app-root'=$appRoot;stage=$stage;final=(Join-Path $stage 'base.msi');partial=(Join-Path $stage 'base.msi.partial')}
$paths=[ordered]@{}
foreach($entry in $fixed.GetEnumerator()) {
 $p=$entry.Value;$view=[ordered]@{kind='unknown';reparse='unknown';owner='none'}
 try {
  try { $item=Get-Item -LiteralPath $p -Force -ErrorAction Stop }
  catch [System.Management.Automation.ItemNotFoundException] { $item=$null }
  if ($null -eq $item) { $view.kind='absent' }
  else {
   $view.kind=$(if($item.PSIsContainer){'directory'}else{'file'})
   $view.reparse=$(if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){'yes'}else{'no'})
   if ($view.reparse -eq 'no') {
    try {
     $ownerName=(Get-Acl -LiteralPath $p -ErrorAction Stop).Owner
     if ($ownerName -match '^S-1-') { $owner=([Security.Principal.SecurityIdentifier]::new($ownerName)).Value }
     else { $owner=([Security.Principal.NTAccount]::new($ownerName)).Translate([Security.Principal.SecurityIdentifier]).Value }
     $view.owner=$(if($owner -ceq $sid){'expected'}elseif($owner -ceq 'S-1-5-18'){'system'}else{'other'})
    } catch { $view.owner='unresolved' }
   }
  }
 } catch { $view.kind='unknown';$view.reparse='unknown';$view.owner='unresolved' }
 $paths[$entry.Key]=[pscustomobject]$view
}
[Console]::Out.WriteLine(([pscustomobject]@{state='census';paths=[pscustomobject]$paths}|ConvertTo-Json -Compress -Depth 4))
'''

_CENSUS_NAMES = {"profile", "appdata", "local", "app-root", "stage", "final", "partial"}
_CENSUS_KIND = {"directory", "file", "absent", "unknown"}
_CENSUS_REPARSE = {"yes", "no", "unknown"}
_CENSUS_OWNER = {"expected", "system", "other", "unresolved", "none"}


def _project_owner_census(raw: bytes | None) -> dict[str, Any]:
    if raw is None or len(raw) > 2048:
        return dict(_UNKNOWN)
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return dict(_UNKNOWN)
    if not isinstance(value, dict) or set(value) != {"state", "paths"} or value.get("state") != "census":
        return dict(_UNKNOWN)
    paths = value.get("paths")
    if not isinstance(paths, dict) or set(paths) != _CENSUS_NAMES:
        return dict(_UNKNOWN)
    for name in _CENSUS_NAMES:
        entry = paths[name]
        if (not isinstance(entry, dict) or set(entry) != {"kind", "reparse", "owner"}
                or any(not isinstance(part, str) for part in entry.values())
                or entry["kind"] not in _CENSUS_KIND or entry["reparse"] not in _CENSUS_REPARSE
                or entry["owner"] not in _CENSUS_OWNER):
            return dict(_UNKNOWN)
    return {"state": "census", "paths": paths, "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False}

_DIAGNOSTIC_TASK = {"absent", "running", "terminal", "unknown"}
_DIAGNOSTIC_MATCH = {"exact", "mismatch", "unknown"}
_DIAGNOSTIC_LEAF = {"absent", "partial", "full", "hash-mismatch", "unsafe", "unknown"}
_DIAGNOSTIC_USER = {"exact-string", "same-sid", "different-sid", "unresolved", "unknown"}
_DIAGNOSTIC_AT = {"profile", "appdata", "local", "app-root", "stage", "final", "partial", "both", "none", "unknown"}
_DIAGNOSTIC_FAULT = {"owner", "owner-unresolved", "reparse", "type", "missing", "collision", "none", "unknown"}
_DIAGNOSTIC_OWNER = {"system", "other", "unresolved", "none"}
_DIAGNOSTIC_REASON = {"observation-error", "sid-mismatch", "sid-unavailable", "task-absent",
                      "principal-mismatch", "action-mismatch", "task-running", "leaf-unsafe",
                      "task-not-run", "task-terminal-failed", "leaf-absent", "leaf-partial",
                      "leaf-hash-mismatch", "ready"}


def _project_guest_diagnostic(raw: bytes | None) -> dict[str, Any]:
    if raw is None or len(raw) > 1024:
        return dict(_UNKNOWN)
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return dict(_UNKNOWN)
    fields = {"state", "task", "principal", "action", "sid", "leaf", "reason",
              "principalUser", "principalLogon", "principalRunLevel", "leafAt", "leafFault", "leafOwner"}
    if (not isinstance(value, dict) or set(value) != fields or value.get("state") != "diagnosed"
            or any(not isinstance(value[key], str) for key in fields)
            or value.get("task") not in _DIAGNOSTIC_TASK
            or value.get("principal") not in _DIAGNOSTIC_MATCH
            or value.get("action") not in _DIAGNOSTIC_MATCH
            or value.get("sid") not in _DIAGNOSTIC_MATCH
            or value.get("leaf") not in _DIAGNOSTIC_LEAF
            or value.get("reason") not in _DIAGNOSTIC_REASON
            or value.get("principalUser") not in _DIAGNOSTIC_USER
            or value.get("principalLogon") not in _DIAGNOSTIC_MATCH
            or value.get("principalRunLevel") not in _DIAGNOSTIC_MATCH
            or value.get("leafAt") not in _DIAGNOSTIC_AT
            or value.get("leafFault") not in _DIAGNOSTIC_FAULT
            or value.get("leafOwner") not in _DIAGNOSTIC_OWNER):
        return dict(_UNKNOWN)
    return {**value, "replayAllowed": False, "nativeActionAllowed": False,
            "productAction": False}


_REMOTE_GUEST_DIAGNOSTIC_TEMPLATE = base._QGA + r'''import time
sock,pid,ticks,sid,corr,port,path,digest,size,args_hash=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if (not live(sock,pid,ticks) or not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+',sid)
  or not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',corr)
  or not port.isdigit() or not 1<=int(port)<=65535 or not re.fullmatch(r'/[A-Za-z0-9_-]{32,128}',path)
  or not re.fullmatch(r'[0-9a-f]{64}',digest) or not size.isdigit() or not 0<int(size)<=1073741824
  or not re.fullmatch(r'[0-9a-f]{64}',args_hash)):raise ValueError()
 script=base64.b64decode('PS_B64').decode()
 for key,value in (('SID',sid),('CORR',corr),('DIGEST',digest),('SIZE',size),('ARGS_SHA',args_hash)):script=script.replace('@'+key+'@',value)
 encoded=base64.b64encode(script.encode('utf-16le')).decode()
 if len(encoded)>30000:raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(200):
  item=call(sock,'guest-exec-status',{'pid':child})
  if item.get('exited') is True:break
  if item.get('exited') is not False:raise ValueError()
  time.sleep(.5)
 else:raise ValueError()
 if (set(item)-{'exited','exitcode','out-data','err-data','out-truncated','err-truncated'}
  or type(item.get('exitcode')) is not int or item['exitcode']!=0
  or item.get('out-truncated',False) is not False or item.get('err-truncated',False) is not False):raise ValueError()
 raw=base64.b64decode(item.get('out-data',''),validate=True)
 if not 0<len(raw)<=2048:raise ValueError()
 lines=[v for v in decode(raw).splitlines() if v.startswith('{') and v.endswith('}')]
 value=json.loads(lines[0]) if len(lines)==1 else None
 if not isinstance(value,dict) or set(value)!=EXPECTED_FIELDS:raise ValueError()
 out(value)
except Exception:out({'state':'unknown'})
'''
_REMOTE_GUEST_DIAGNOSTIC = (_REMOTE_GUEST_DIAGNOSTIC_TEMPLATE
                            .replace('PS_B64', _base64.b64encode(_GUEST_DIAGNOSTIC_PS.encode()).decode())
                            .replace('EXPECTED_FIELDS', repr({"state", "task", "principal", "action", "sid",
                                                              "leaf", "reason", "principalUser", "principalLogon",
                                                              "principalRunLevel", "leafAt", "leafFault", "leafOwner"})))
_REMOTE_OWNER_CENSUS = (_REMOTE_GUEST_DIAGNOSTIC_TEMPLATE
                        .replace('PS_B64', _base64.b64encode(_GUEST_OWNER_CENSUS_PS.encode()).decode())
                        .replace('EXPECTED_FIELDS', repr({"state", "paths"})))

_GUEST_TASK_CLEANUP_PS = r'''$ErrorActionPreference='Stop'
$sid='@SID@';$corr='@CORR@';$digest='@DIGEST@';$length=@SIZE@
$resolved=([Security.Principal.NTAccount]::new('VPNMSIX64\vpncp117')).Translate([Security.Principal.SecurityIdentifier]).Value
if ($resolved -cne $sid) { throw 'SID_MISMATCH' }
function PrincipalSid([string]$userId) {
 if ($userId -match '^S-1-') { return ([Security.Principal.SecurityIdentifier]::new($userId)).Value }
 return ([Security.Principal.NTAccount]::new($userId)).Translate([Security.Principal.SecurityIdentifier]).Value
}
$name='VpnControlMcpTransfer-'+$corr
$task=Get-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction Stop
$principalSid=PrincipalSid ([string]($task.Principal.UserId))
if ($principalSid -cne $sid -or $task.Principal.LogonType -cne 'Interactive' -or $task.Principal.RunLevel -cne 'Limited' -or $task.State -eq 'Running') { throw 'TASK' }
$actions=@($task.Actions)
if ($actions.Count -ne 1 -or $actions[0].Execute -cne 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe') { throw 'ACTION' }
$sha=[Security.Cryptography.SHA256]::Create()
try { $actualArgs=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($actions[0].Arguments)))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
if ($actualArgs -cne '@ARGS_SHA@') { throw 'ARGUMENTS' }
$profile='C:\Users\vpncp117';$local=Join-Path $profile 'AppData\Local'
function Assert-Owned([string]$p,[bool]$directory,[bool]$allowSystemProfile=$false) {
 $item=Get-Item -LiteralPath $p -Force -ErrorAction Stop
 if ($item.PSIsContainer -ne $directory -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'REPARSE' }
 $owner=([Security.Principal.NTAccount]::new((Get-Acl -LiteralPath $p).Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
 if ($owner -cne $sid -and -not ($allowSystemProfile -and $owner -ceq 'S-1-5-18')) { throw 'OWNER' }
}
Assert-Owned $profile $true $true;Assert-Owned (Join-Path $profile 'AppData') $true;Assert-Owned $local $true
$appRoot=Join-Path $local 'VpnControl';$dir=Join-Path $appRoot ('mcp-base-'+$corr);$msi=Join-Path $dir 'base.msi'
Assert-Owned $appRoot $true;Assert-Owned $dir $true;Assert-Owned $msi $false
if ([IO.File]::Exists((Join-Path $dir 'base.msi.partial'))) { throw 'PARTIAL' }
$info=Get-Item -LiteralPath $msi -Force
if ($info.Length -ne $length -or (Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant() -cne $digest) { throw 'MSI' }
Unregister-ScheduledTask -TaskPath '\' -TaskName $name -Confirm:$false -ErrorAction Stop
if (Get-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction SilentlyContinue) { throw 'PRESENT' }
[Console]::Out.WriteLine('{"state":"task-cleaned"}')
'''

_REMOTE_GUEST_TASK_CLEANUP = base._QGA + r'''import time
sock,pid,ticks,sid,corr,port,path,digest,size,args_hash=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if (not live(sock,pid,ticks) or not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+',sid)
  or not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',corr)
  or not port.isdigit() or not 1<=int(port)<=65535 or not re.fullmatch(r'/[A-Za-z0-9_-]{32,128}',path)
  or not re.fullmatch(r'[0-9a-f]{64}',digest) or not size.isdigit() or not 0<int(size)<=1073741824
  or not re.fullmatch(r'[0-9a-f]{64}',args_hash)):raise ValueError()
 script=base64.b64decode('PS_B64').decode()
 for key,value in (('SID',sid),('CORR',corr),('DIGEST',digest),('SIZE',size),('ARGS_SHA',args_hash)):script=script.replace('@'+key+'@',value)
 encoded=base64.b64encode(script.encode('utf-16le')).decode()
 if len(encoded)>30000:raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(200):
  item=call(sock,'guest-exec-status',{'pid':child})
  if item.get('exited') is True:break
  if item.get('exited') is not False:raise ValueError()
  time.sleep(.5)
 else:raise ValueError()
 if (set(item)-{'exited','exitcode','out-data','err-data','out-truncated','err-truncated'}
  or type(item.get('exitcode')) is not int or item['exitcode']!=0
  or item.get('out-truncated',False) is not False or item.get('err-truncated',False) is not False):raise ValueError()
 raw=base64.b64decode(item.get('out-data',''),validate=True)
 if not 0<len(raw)<=512:raise ValueError()
 lines=[v for v in decode(raw).splitlines() if v.startswith('{') and v.endswith('}')]
 if len(lines)!=1 or json.loads(lines[0])!={'state':'task-cleaned'}:raise ValueError()
 out({'state':'task-cleaned'})
except Exception:out({'state':'unknown'})
'''
_REMOTE_GUEST_TASK_CLEANUP = _REMOTE_GUEST_TASK_CLEANUP.replace('PS_B64', _base64.b64encode(_GUEST_TASK_CLEANUP_PS.encode()).decode())

_GUEST_ABORT_PS = r'''$ErrorActionPreference='Stop'
$sid='@SID@';$corr='@CORR@';$digest='@DIGEST@';$length=@SIZE@
$account='VPNMSIX64\vpncp117'
if (([Security.Principal.NTAccount]::new($account)).Translate([Security.Principal.SecurityIdentifier]).Value -cne $sid) { throw 'SID_MISMATCH' }
function PrincipalSid([string]$userId) {
 if ($userId -match '^S-1-') { return ([Security.Principal.SecurityIdentifier]::new($userId)).Value }
 return ([Security.Principal.NTAccount]::new($userId)).Translate([Security.Principal.SecurityIdentifier]).Value
}
$name='VpnControlMcpTransfer-'+$corr
$task=Get-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction Stop
$principalSid=PrincipalSid ([string]($task.Principal.UserId))
if ($principalSid -cne $sid -or $task.Principal.LogonType -cne 'Interactive' -or $task.Principal.RunLevel -cne 'Limited' -or $task.State -eq 'Running') { throw 'TASK' }
$actions=@($task.Actions)
if ($actions.Count -ne 1 -or $actions[0].Execute -cne 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe') { throw 'ACTION' }
$sha=[Security.Cryptography.SHA256]::Create()
try { $actualArgs=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($actions[0].Arguments)))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
if ($actualArgs -cne '@ARGS_SHA@') { throw 'ARGUMENTS' }
$profile='C:\Users\vpncp117';$local=Join-Path $profile 'AppData\Local';$appRoot=Join-Path $local 'VpnControl';$dir=Join-Path $appRoot ('mcp-base-'+$corr)
function Assert-Owned([string]$p,[bool]$directory,[bool]$allowSystemProfile=$false) {
 $item=Get-Item -LiteralPath $p -Force -ErrorAction Stop
 if ($item.PSIsContainer -ne $directory -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'REPARSE' }
 $owner=([Security.Principal.NTAccount]::new((Get-Acl -LiteralPath $p).Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
 if ($owner -cne $sid -and -not ($allowSystemProfile -and $owner -ceq 'S-1-5-18')) { throw 'OWNER' }
}
Assert-Owned $profile $true $true;Assert-Owned (Join-Path $profile 'AppData') $true;Assert-Owned $local $true
$leaves=@()
if ([IO.Directory]::Exists($appRoot)) {
 Assert-Owned $appRoot $true
 if ([IO.Directory]::Exists($dir)) {
  Assert-Owned $dir $true
  $names=@(Get-ChildItem -LiteralPath $dir -Force | ForEach-Object {$_.Name})
  if (@($names | Where-Object {$_ -cne 'base.msi.partial' -and $_ -cne 'base.msi'}).Count -ne 0) { throw 'FOREIGN_LEAF' }
  foreach($leaf in @('base.msi.partial','base.msi')) {
   $p=Join-Path $dir $leaf
   if ([IO.File]::Exists($p)) { Assert-Owned $p $false;$leaves+=,$p }
  }
 }
}
$final=Join-Path $dir 'base.msi'
if ([IO.File]::Exists($final)) {
 $info=Get-Item -LiteralPath $final -Force
 if ($info.Length -eq $length -and (Get-FileHash -LiteralPath $final -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $digest) { throw 'VALID_MSI' }
}
Unregister-ScheduledTask -TaskPath '\' -TaskName $name -Confirm:$false -ErrorAction Stop
if (Get-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction SilentlyContinue) { throw 'TASK_PRESENT' }
foreach($p in $leaves) { [IO.File]::Delete($p) }
if ([IO.File]::Exists((Join-Path $dir 'base.msi.partial')) -or [IO.File]::Exists($final)) { throw 'LEAF_PRESENT' }
[Console]::Out.WriteLine('{"state":"aborted"}')
'''

_REMOTE_GUEST_ABORT = base._QGA + r'''import time
sock,pid,ticks,sid,corr,port,path,digest,size,args_hash=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if (not live(sock,pid,ticks) or not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+',sid)
  or not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',corr)
  or not port.isdigit() or not 1<=int(port)<=65535 or not re.fullmatch(r'/[A-Za-z0-9_-]{32,128}',path)
  or not re.fullmatch(r'[0-9a-f]{64}',digest) or not size.isdigit() or not 0<int(size)<=1073741824
  or not re.fullmatch(r'[0-9a-f]{64}',args_hash)):raise ValueError()
 script=base64.b64decode('PS_B64').decode()
 for key,value in (('SID',sid),('CORR',corr),('DIGEST',digest),('SIZE',size),('ARGS_SHA',args_hash)):script=script.replace('@'+key+'@',value)
 encoded=base64.b64encode(script.encode('utf-16le')).decode()
 if len(encoded)>30000:raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(200):
  item=call(sock,'guest-exec-status',{'pid':child})
  if item.get('exited') is True:break
  if item.get('exited') is not False:raise ValueError()
  time.sleep(.5)
 else:raise ValueError()
 if (set(item)-{'exited','exitcode','out-data','err-data','out-truncated','err-truncated'}
  or type(item.get('exitcode')) is not int or item['exitcode']!=0
  or item.get('out-truncated',False) is not False or item.get('err-truncated',False) is not False):raise ValueError()
 raw=base64.b64decode(item.get('out-data',''),validate=True)
 if not 0<len(raw)<=512:raise ValueError()
 lines=[v for v in decode(raw).splitlines() if v.startswith('{') and v.endswith('}')]
 if len(lines)!=1 or json.loads(lines[0])!={'state':'aborted'}:raise ValueError()
 out({'state':'aborted'})
except Exception:out({'state':'unknown'})
'''
_REMOTE_GUEST_ABORT = _REMOTE_GUEST_ABORT.replace('PS_B64', _base64.b64encode(_GUEST_ABORT_PS.encode()).decode())

_GUEST_FILE_CLEANUP_PS = r'''$ErrorActionPreference='Stop'
$sid='@SID@';$corr='@CORR@';$digest='@DIGEST@';$length=@SIZE@
if (Get-ScheduledTask -TaskPath '\' -TaskName ('VpnControlMcpTransfer-'+$corr) -ErrorAction SilentlyContinue) { throw 'TRANSFER_TASK' }
if (@(Get-CimInstance Win32_Process -Filter "name='msiexec.exe'").Count -ne 0) { throw 'INSTALLER' }
$profile='C:\Users\vpncp117';$local=Join-Path $profile 'AppData\Local';$appRoot=Join-Path $local 'VpnControl';$dir=Join-Path $appRoot ('mcp-base-'+$corr)
function Assert-Owned([string]$p,[bool]$directory,[bool]$allowSystemProfile=$false) {
 $item=Get-Item -LiteralPath $p -Force -ErrorAction Stop
 if ($item.PSIsContainer -ne $directory -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'REPARSE' }
 $owner=([Security.Principal.NTAccount]::new((Get-Acl -LiteralPath $p).Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
 if ($owner -cne $sid -and -not ($allowSystemProfile -and $owner -ceq 'S-1-5-18')) { throw 'OWNER' }
}
Assert-Owned $profile $true $true;Assert-Owned (Join-Path $profile 'AppData') $true;Assert-Owned $local $true;Assert-Owned $appRoot $true;Assert-Owned $dir $true
$msi=Join-Path $dir 'base.msi';$partial=Join-Path $dir 'base.msi.partial'
if ([IO.File]::Exists($partial)) { throw 'PARTIAL' }
Assert-Owned $msi $false
$info=Get-Item -LiteralPath $msi -Force
if ($info.Length -ne $length -or (Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant() -cne $digest) { throw 'MSI' }
[IO.File]::Delete($msi)
if ([IO.File]::Exists($msi) -or [IO.File]::Exists($partial)) { throw 'REMAINING' }
[Console]::Out.WriteLine('{"state":"file-cleaned"}')
'''

_REMOTE_GUEST_FILE_CLEANUP = base._QGA + r'''import time
sock,pid,ticks,sid,corr,digest,size,terminal=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if (not live(sock,pid,ticks) or not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+',sid)
  or not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',corr)
  or not re.fullmatch(r'[0-9a-f]{64}',digest) or not size.isdigit() or not 0<int(size)<=1073741824
  or not re.fullmatch(r'[0-9a-f]{64}',terminal)):raise ValueError()
 script=base64.b64decode('PS_B64').decode()
 for key,value in (('SID',sid),('CORR',corr),('DIGEST',digest),('SIZE',size)):script=script.replace('@'+key+'@',value)
 encoded=base64.b64encode(script.encode('utf-16le')).decode()
 if len(encoded)>30000:raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(200):
  item=call(sock,'guest-exec-status',{'pid':child})
  if item.get('exited') is True:break
  if item.get('exited') is not False:raise ValueError()
  time.sleep(.5)
 else:raise ValueError()
 if (set(item)-{'exited','exitcode','out-data','err-data','out-truncated','err-truncated'}
  or type(item.get('exitcode')) is not int or item['exitcode']!=0
  or item.get('out-truncated',False) is not False or item.get('err-truncated',False) is not False):raise ValueError()
 raw=base64.b64decode(item.get('out-data',''),validate=True)
 if not 0<len(raw)<=512:raise ValueError()
 lines=[v for v in decode(raw).splitlines() if v.startswith('{') and v.endswith('}')]
 if len(lines)!=1 or json.loads(lines[0])!={'state':'file-cleaned'}:raise ValueError()
 out({'state':'file-cleaned','terminalReceiptSha256':terminal})
except Exception:out({'state':'unknown'})
'''
_REMOTE_GUEST_FILE_CLEANUP = _REMOTE_GUEST_FILE_CLEANUP.replace('PS_B64', _base64.b64encode(_GUEST_FILE_CLEANUP_PS.encode()).decode())


def _remote_args(record: Mapping[str, Any], transfer_root: Path) -> tuple[str, ...]:
    return (str(transfer_root), record["environment"], record["correlationId"], record["sourceSha"],
            record["baseMsiArtifactId"], record["socketPath"], str(record["qemuPid"]),
            str(record["startTicks"]), record["expectedSid"], record["sha256"], str(record["length"]))


def _admit_current(root: Path, record: Mapping[str, Any], transfer_root: Path) -> Any:
    current_config, target, descriptor = base._descriptor(root)
    if (descriptor != (record["environment"], record["socketPath"], record["qemuPid"],
                       record["startTicks"], record["expectedSid"])
            or Path(target.fixture_transfer_root) != Path(transfer_root)):
        raise WindowsMsiHttpTransferError("CP117 guest generation changed.")
    head = subprocess.run(("git", "rev-parse", "HEAD"), cwd=root, capture_output=True,
                          text=True, timeout=5, check=True).stdout.strip()
    if head != record["sourceSha"]:
        raise WindowsMsiHttpTransferError("Source checkpoint changed.")
    registered = windows_msi_public_scenario._verified_location(
        root, record["baseMsiArtifactId"], "desktop-package", record["sourceSha"])
    if registered.resolve(strict=True) != Path(record["artifactPath"]).resolve(strict=True):
        raise WindowsMsiHttpTransferError("MSI artifact location changed.")
    return current_config


def _base_terminal(root: Path, record: Mapping[str, Any]) -> str:
    """Derive the same exact observed terminal evidence as base.finish_observed."""
    intent = base._private_intent(root, record["correlationId"])
    if (intent is None or intent.get("leaseId") != record["correlationId"]
            or intent.get("request", {}).get("sourceSha") != record["sourceSha"]
            or intent.get("request", {}).get("baseMsiArtifactId") != record["baseMsiArtifactId"]
            or not isinstance(intent.get("pair"), Mapping)
            or not isinstance(intent["pair"].get("baseVersion"), str)):
        raise WindowsMsiHttpTransferError("Base terminal intent is unbound.")
    observed = base.status(root, {"correlationId": record["correlationId"]})
    if observed.get("state") == "unknown":
        observed = base.terminal_reconcile(root, {"correlationId": record["correlationId"]})
    if (observed.get("state") != "terminal" or observed.get("result") != "PASSED"
            or observed.get("stage") != "READBACK" or observed.get("exitCode") != 0
            or observed.get("sourceSha") != record["sourceSha"]
            or observed.get("baseArtifactId") != record["baseMsiArtifactId"]):
        raise WindowsMsiHttpTransferError("Base terminal readback is unavailable.")
    idle = base.readiness(root, {"host": "archlinux", "expectedCurrentVersion": intent["pair"]["baseVersion"]})
    if (idle.get("state") != "ready" or idle.get("activeCount") != 0
            or idle.get("installedVersion") != intent["pair"]["baseVersion"]):
        raise WindowsMsiHttpTransferError("Base terminal guest is not idle.")
    evidence = {"terminal": observed, "idle": idle, "leaseId": record["correlationId"]}
    return hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _remote_result(config: Any, program: str, args: tuple[str, ...], source: Path | None,
                   allowed: set[str], record: Mapping[str, Any]) -> dict[str, Any]:
    raw = base._remote(config, program, args, source, 120)
    if raw is None or len(raw) > 1024:
        return dict(_UNKNOWN)
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return dict(_UNKNOWN)
    if not isinstance(value, dict) or value.get("state") not in allowed:
        return dict(_UNKNOWN)
    if value["state"] in {"staged", "staged-for-base"}:
        if (set(value) != {"state", "sha256", "length"}
                or value["sha256"] != record["sha256"]
                or type(value["length"]) is not int or value["length"] != record["length"]):
            return dict(_UNKNOWN)
    elif set(value) != {"state"}:
        return dict(_UNKNOWN)
    return {**value, "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}


def remote_stage(root: Path, config: Any, transfer_root: Path, correlation_id: str, artifact: Path) -> dict[str, Any]:
    try:
        record = _intent(root, correlation_id)
        if record is None or str(Path(artifact).absolute()) != record["artifactPath"]:
            return dict(_UNKNOWN)
        digest, length = _artifact(Path(artifact), record["sha256"])
        if length != record["length"]:
            return dict(_UNKNOWN)
        fresh_config = _admit_current(Path(root), record, Path(transfer_root))
        directory = _private_dir(Path(root), False)
        assert directory is not None
        if not _write_once(directory / (correlation_id + ".dispatch.json"),
                           {"correlationId": correlation_id, "sha256": digest, "length": length}):
            return dict(_UNKNOWN)
        result = _remote_result(fresh_config, _REMOTE_STAGE, _remote_args(record, transfer_root),
                                Path(artifact), {"staged", "unknown"}, record)
        if result.get("state") == "staged":
            _large_advance(Path(root), record, "host-staged")
        return result
    except (OSError, ValueError, subprocess.SubprocessError):
        return dict(_UNKNOWN)


def remote_stage_status(root: Path, config: Any, transfer_root: Path, correlation_id: str) -> dict[str, Any]:
    try:
        record = _intent(root, correlation_id)
        if record is None:
            return dict(_UNKNOWN)
        fresh_config = _admit_current(Path(root), record, Path(transfer_root))
        return _remote_result(fresh_config, _REMOTE_STATUS, _remote_args(record, transfer_root), None,
                              {"absent", "partial", "hash-mismatch", "staged", "unknown"}, record)
    except (OSError, ValueError, subprocess.SubprocessError):
        return dict(_UNKNOWN)


def remote_stage_cleanup(root: Path, config: Any, transfer_root: Path, correlation_id: str) -> dict[str, Any]:
    try:
        record = _intent(root, correlation_id)
        directory = _private_dir(Path(root), False)
        if record is None or directory is None or _read(directory / (correlation_id + ".dispatch.json")) is None:
            return dict(_UNKNOWN)
        fresh_config = _admit_current(Path(root), record, Path(transfer_root))
        return _remote_result(fresh_config, _REMOTE_CLEANUP, _remote_args(record, transfer_root), None,
                              {"cleaned", "unknown"}, record)
    except (OSError, ValueError, subprocess.SubprocessError):
        return dict(_UNKNOWN)


def _phase_result(raw: bytes | None, states: set[str], path: str | None = None,
                  path_sha: str | None = None) -> dict[str, Any]:
    if raw is None or len(raw) > 1024:
        return dict(_UNKNOWN)
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return dict(_UNKNOWN)
    if not isinstance(value, dict) or value.get("state") not in states:
        return dict(_UNKNOWN)
    if value["state"] in {"listening", "served", "stopped"} and "port" in value:
        if (set(value) != ({"state", "port", "path"} if path is not None else {"state", "port", "pathSha256"})
                or type(value["port"]) is not int or not 1 <= value["port"] <= 65535):
            return dict(_UNKNOWN)
        if path is not None:
            if value["path"] != path:
                return dict(_UNKNOWN)
        elif path_sha is None or value["pathSha256"] != path_sha:
            return dict(_UNKNOWN)
    elif set(value) != {"state"}:
        return dict(_UNKNOWN)
    return {**value, "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}


def listener_start(root: Path, config: Any, transfer_root: Path, correlation_id: str) -> dict[str, Any]:
    """Reserve exactly one loopback listener after the staged bytes are verified."""
    try:
        record = _intent(root, correlation_id)
        if record is None:
            return dict(_UNKNOWN)
        fresh_config = _admit_current(Path(root), record, Path(transfer_root))
        staged = remote_stage_status(root, fresh_config, transfer_root, correlation_id)
        if staged.get("state") != "staged":
            return dict(_UNKNOWN)
        directory = _private_dir(Path(root), False)
        assert directory is not None
        path = "/" + record["routeNonce"]
        if not _write_once(directory / (correlation_id + ".listener.json"),
                           {"correlationId": correlation_id, "pathSha256": hashlib.sha256(path.encode()).hexdigest()}):
            return dict(_UNKNOWN)
        _large_advance(Path(root), record, "listening")
        payload = json.dumps({"path": path}, separators=(",", ":")).encode()
        with tempfile.NamedTemporaryFile(mode="wb", prefix="vpn-control-msi-listener-", delete=True) as stream:
            os.chmod(stream.name, 0o600)
            stream.write(payload); stream.flush(); os.fsync(stream.fileno())
            raw = base._remote(fresh_config, _REMOTE_LISTEN_START, _remote_args(record, transfer_root),
                               Path(stream.name), 15)
        return _phase_result(raw, {"listening", "unknown"}, path)
    except (OSError, ValueError, subprocess.SubprocessError):
        return dict(_UNKNOWN)


def _listener_join(root: Path, transfer_root: Path, correlation_id: str) -> tuple[Any, dict[str, Any], str] | None:
    record = _intent(root, correlation_id)
    directory = _private_dir(Path(root), False)
    if record is None or directory is None:
        return None
    path = "/" + record["routeNonce"]
    marker = _read(directory / (correlation_id + ".listener.json"))
    if marker != {"correlationId": correlation_id, "pathSha256": hashlib.sha256(path.encode()).hexdigest()}:
        return None
    config = _admit_current(Path(root), record, Path(transfer_root))
    return config, record, path


def listener_status(root: Path, config: Any, transfer_root: Path, correlation_id: str) -> dict[str, Any]:
    try:
        joined = _listener_join(root, transfer_root, correlation_id)
        if joined is None:
            return dict(_UNKNOWN)
        fresh_config, record, path = joined
        raw = base._remote(fresh_config, _REMOTE_LISTEN_STATUS, _remote_args(record, transfer_root), None, 15)
        return _phase_result(raw, {"starting", "failed", "listening", "served", "stopped", "unknown"}, None,
                             hashlib.sha256(path.encode()).hexdigest())
    except (OSError, ValueError, subprocess.SubprocessError):
        return dict(_UNKNOWN)


def listener_diagnostic(root: Path, config: Any, transfer_root: Path,
                        correlation_id: str) -> dict[str, Any]:
    """Read-only bounded account of listener receipts and process/port state."""
    try:
        joined = _listener_join(root, transfer_root, correlation_id)
        if joined is None:
            return dict(_UNKNOWN)
        fresh_config, record, _ = joined
        raw = base._remote(fresh_config, _REMOTE_LISTEN_DIAGNOSTIC,
                           _remote_args(record, transfer_root), None, 15)
        return _project_listener_diagnostic(raw)
    except (OSError, ValueError, subprocess.SubprocessError):
        return dict(_UNKNOWN)


def listener_stop(root: Path, config: Any, transfer_root: Path, correlation_id: str) -> dict[str, Any]:
    try:
        joined = _listener_join(root, transfer_root, correlation_id)
        if joined is None:
            return dict(_UNKNOWN)
        fresh_config, record, _ = joined
        observed = listener_status(root, fresh_config, transfer_root, correlation_id)
        if observed.get("state") not in {"starting", "failed", "listening", "served", "stopped"}:
            return dict(_UNKNOWN)
        if observed["state"] == "stopped" and "port" not in observed:
            return observed
        raw = base._remote(fresh_config, _REMOTE_LISTEN_STOP, _remote_args(record, transfer_root), None, 15)
        return _phase_result(raw, {"stopped", "unknown"})
    except (OSError, ValueError, subprocess.SubprocessError):
        return dict(_UNKNOWN)


def _guest_args(record: Mapping[str, Any], port: int | None = None, path: str | None = None) -> tuple[str, ...]:
    prefix = (record["socketPath"], str(record["qemuPid"]), str(record["startTicks"]),
              record["expectedSid"], record["correlationId"])
    if port is not None and path is not None:
        return prefix + (str(port), path, record["sha256"], str(record["length"]))
    return prefix + (record["sha256"], str(record["length"]))


def guest_download(root: Path, config: Any, transfer_root: Path, correlation_id: str) -> dict[str, Any]:
    """Dispatch one guest HTTP download; uncertainty is reconciled by status."""
    try:
        joined = _listener_join(root, transfer_root, correlation_id)
        if joined is None:
            return dict(_UNKNOWN)
        fresh_config, record, path = joined
        observed = listener_status(root, fresh_config, transfer_root, correlation_id)
        if observed.get("state") != "listening":
            return dict(_UNKNOWN)
        port = observed["port"]
        directory = _private_dir(Path(root), False)
        assert directory is not None
        action_sha = _action_args_sha(_GUEST_DOWNLOAD_PS, record["expectedSid"], correlation_id,
                                      record["sha256"], record["length"], port, path)
        if not _write_once(directory / (correlation_id + ".guest-dispatch.json"),
                           {"correlationId": correlation_id, "sha256": record["sha256"],
                            "length": record["length"], "port": port,
                            "pathSha256": hashlib.sha256(path.encode()).hexdigest(),
                            "actionArgsSha256": action_sha,
                            "actionScriptSha256": hashlib.sha256(_GUEST_DOWNLOAD_PS.encode()).hexdigest(),
                            "sourceSha": record["sourceSha"],
                            "baseMsiArtifactId": record["baseMsiArtifactId"],
                            "qemuPid": record["qemuPid"], "startTicks": record["startTicks"],
                            "expectedSid": record["expectedSid"]}):
            return dict(_UNKNOWN)
        # This is intentionally before guest-exec: a lost QGA response must
        # reconcile through status, never submit a second owner download.
        _large_advance(Path(root), record, "download-submitted")
        raw = base._remote(fresh_config, _REMOTE_GUEST_DOWNLOAD,
                           _guest_args(record, port, path), None, 120)
        return _guest_result(raw, {"submitted", "unknown"}, record)
    except (OSError, ValueError, subprocess.SubprocessError):
        return dict(_UNKNOWN)


def _guest_result(raw: bytes | None, states: set[str], record: Mapping[str, Any]) -> dict[str, Any]:
    if raw is None or len(raw) > 1024:
        return dict(_UNKNOWN)
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return dict(_UNKNOWN)
    if not isinstance(value, dict) or value.get("state") not in states:
        return dict(_UNKNOWN)
    if value["state"] in {"downloaded", "ready-for-base"}:
        if (set(value) != {"state", "sha256", "length"}
                or value["sha256"] != record["sha256"]
                or type(value["length"]) is not int or value["length"] != record["length"]):
            return dict(_UNKNOWN)
    elif set(value) != {"state"}:
        return dict(_UNKNOWN)
    return {**value, "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}


def guest_download_status(root: Path, config: Any, transfer_root: Path, correlation_id: str) -> dict[str, Any]:
    try:
        joined = _listener_join(root, transfer_root, correlation_id)
        if joined is None:
            return dict(_UNKNOWN)
        fresh_config, record, path = joined
        marker = _guest_dispatch_marker(root, record, path)
        if marker is None:
            return dict(_UNKNOWN)
        raw = base._remote(fresh_config, _REMOTE_GUEST_STATUS,
                           _task_args(record, marker, path) + ("before",), None, 120)
        result = _guest_result(raw, {"absent", "running", "partial", "hash-mismatch", "downloaded", "unknown"}, record)
        if result.get("state") == "downloaded":
            _large_advance(Path(root), record, "downloaded")
        return result
    except (OSError, ValueError, subprocess.SubprocessError):
        return dict(_UNKNOWN)


def guest_diagnostic(root: Path, config: Any, transfer_root: Path, correlation_id: str) -> dict[str, Any]:
    """Read-only bounded explanation for an uncertain transfer task or guest leaf."""
    try:
        joined = _listener_join(root, transfer_root, correlation_id)
        if joined is None:
            return dict(_UNKNOWN)
        fresh_config, record, path = joined
        marker = _guest_dispatch_marker(root, record, path)
        if marker is None:
            return dict(_UNKNOWN)
        raw = base._remote(fresh_config, _REMOTE_GUEST_DIAGNOSTIC,
                           _task_args(record, marker, path), None, 120)
        return _project_guest_diagnostic(raw)
    except (OSError, ValueError, subprocess.SubprocessError):
        return dict(_UNKNOWN)


def guest_owner_census(root: Path, config: Any, transfer_root: Path,
                       correlation_id: str) -> dict[str, Any]:
    """Read-only ownership and reparse census of seven fixed guest leaves."""
    try:
        joined = _listener_join(root, transfer_root, correlation_id)
        if joined is None:
            return dict(_UNKNOWN)
        fresh_config, record, path = joined
        marker = _guest_dispatch_marker(root, record, path)
        if marker is None:
            return dict(_UNKNOWN)
        raw = base._remote(fresh_config, _REMOTE_OWNER_CENSUS,
                           _task_args(record, marker, path), None, 120)
        return _project_owner_census(raw)
    except (OSError, ValueError, subprocess.SubprocessError):
        return dict(_UNKNOWN)


def _guest_dispatch_marker(root: Path, record: Mapping[str, Any], path: str) -> dict[str, Any] | None:
    directory = _private_dir(Path(root), False)
    if directory is None:
        return None
    marker = _read(directory / (record["correlationId"] + ".guest-dispatch.json"))
    old_fields = {"correlationId", "sha256", "length", "port", "pathSha256"}
    new_fields = old_fields | {"actionArgsSha256", "actionScriptSha256", "sourceSha",
                               "baseMsiArtifactId", "qemuPid", "startTicks", "expectedSid"}
    if (not isinstance(marker, dict) or set(marker) not in (old_fields, new_fields)
            or marker["correlationId"] != record["correlationId"] or marker["sha256"] != record["sha256"]
            or marker["length"] != record["length"] or type(marker["port"]) is not int
            or not 1 <= marker["port"] <= 65535
            or marker["pathSha256"] != hashlib.sha256(path.encode()).hexdigest()):
        return None
    if set(marker) == old_fields:
        action_sha = _historical_action_hash(record["correlationId"], record["expectedSid"],
                                             record["sha256"], record["length"], marker["port"], path)
        if action_sha is None:
            return None
        return {**marker, "actionArgsSha256": action_sha,
                "actionScriptSha256": _HISTORICAL_DOWNLOAD_SHA256}
    if (marker["sourceSha"] != record["sourceSha"]
            or marker["baseMsiArtifactId"] != record["baseMsiArtifactId"]
            or marker["qemuPid"] != record["qemuPid"] or marker["startTicks"] != record["startTicks"]
            or marker["expectedSid"] != record["expectedSid"]
            or not isinstance(marker["actionArgsSha256"], str)
            or not _HASH.fullmatch(marker["actionArgsSha256"])
            or not isinstance(marker["actionScriptSha256"], str)
            or not _HASH.fullmatch(marker["actionScriptSha256"])):
        return None
    return marker


def _task_args(record: Mapping[str, Any], marker: Mapping[str, Any], path: str) -> tuple[str, ...]:
    return _guest_args(record, marker["port"], path) + (marker["actionArgsSha256"],)


def guest_task_cleanup(root: Path, config: Any, transfer_root: Path, correlation_id: str) -> dict[str, Any]:
    """Remove only the exact completed transfer task; retain base.msi for base.start."""
    try:
        joined = _listener_join(root, transfer_root, correlation_id)
        if joined is None:
            return dict(_UNKNOWN)
        fresh_config, record, path = joined
        marker = _guest_dispatch_marker(root, record, path)
        if marker is None or guest_download_status(root, fresh_config, transfer_root, correlation_id).get("state") != "downloaded":
            return dict(_UNKNOWN)
        listener = listener_status(root, fresh_config, transfer_root, correlation_id)
        if listener.get("state") not in {"served", "stopped"}:
            return dict(_UNKNOWN)
        directory = _private_dir(Path(root), False)
        assert directory is not None
        if not _write_once(directory / (correlation_id + ".task-cleanup.dispatch.json"),
                           {"correlationId": correlation_id, "sha256": record["sha256"],
                            "port": marker["port"], "pathSha256": marker["pathSha256"]}):
            return dict(_UNKNOWN)
        raw = base._remote(fresh_config, _REMOTE_GUEST_TASK_CLEANUP,
                           _task_args(record, marker, path), None, 120)
        return _guest_result(raw, {"task-cleaned", "unknown"}, record)
    except (OSError, ValueError, subprocess.SubprocessError):
        return dict(_UNKNOWN)


def guest_task_status(root: Path, config: Any, transfer_root: Path, correlation_id: str) -> dict[str, Any]:
    """Read-only bridge admission: transfer task absent, exact user-owned MSI ready."""
    try:
        joined = _listener_join(root, transfer_root, correlation_id)
        if joined is None:
            return dict(_UNKNOWN)
        fresh_config, record, path = joined
        marker = _guest_dispatch_marker(root, record, path)
        directory = _private_dir(Path(root), False)
        if marker is None or directory is None:
            return dict(_UNKNOWN)
        cleanup = _read(directory / (correlation_id + ".task-cleanup.dispatch.json"))
        if cleanup != {"correlationId": correlation_id, "sha256": record["sha256"],
                       "port": marker["port"], "pathSha256": marker["pathSha256"]}:
            return dict(_UNKNOWN)
        raw = base._remote(fresh_config, _REMOTE_GUEST_STATUS,
                           _task_args(record, marker, path) + ("after",), None, 120)
        return _guest_result(raw, {"absent", "partial", "hash-mismatch", "ready-for-base", "unknown"}, record)
    except (OSError, ValueError, subprocess.SubprocessError):
        return dict(_UNKNOWN)


def guest_abort(root: Path, config: Any, transfer_root: Path, correlation_id: str) -> dict[str, Any]:
    """Abort only a stopped failed transfer task and its partial/mismatched leaf."""
    try:
        joined = _listener_join(root, transfer_root, correlation_id)
        if joined is None:
            return dict(_UNKNOWN)
        fresh_config, record, path = joined
        marker = _guest_dispatch_marker(root, record, path)
        if marker is None:
            return dict(_UNKNOWN)
        observed = guest_download_status(root, fresh_config, transfer_root, correlation_id)
        if observed.get("state") not in {"absent", "partial", "hash-mismatch"}:
            return dict(_UNKNOWN)
        listener = listener_status(root, fresh_config, transfer_root, correlation_id)
        if listener.get("state") != "stopped" or "port" in listener:
            return dict(_UNKNOWN)
        directory = _private_dir(Path(root), False)
        assert directory is not None
        if not _write_once(directory / (correlation_id + ".abort.dispatch.json"),
                           {"correlationId": correlation_id, "sha256": record["sha256"],
                            "port": marker["port"], "pathSha256": marker["pathSha256"],
                            "observedState": observed["state"]}):
            return dict(_UNKNOWN)
        raw = base._remote(fresh_config, _REMOTE_GUEST_ABORT,
                           _task_args(record, marker, path), None, 120)
        return _guest_result(raw, {"aborted", "unknown"}, record)
    except (OSError, ValueError, subprocess.SubprocessError):
        return dict(_UNKNOWN)


def guest_abort_status(root: Path, config: Any, transfer_root: Path, correlation_id: str) -> dict[str, Any]:
    """Reconcile the exact one-use abort without replaying task or file mutation."""
    try:
        joined = _listener_join(root, transfer_root, correlation_id)
        if joined is None:
            return dict(_UNKNOWN)
        fresh_config, record, path = joined
        marker = _guest_dispatch_marker(root, record, path)
        directory = _private_dir(Path(root), False)
        if marker is None or directory is None:
            return dict(_UNKNOWN)
        abort = _read(directory / (correlation_id + ".abort.dispatch.json"))
        if (not isinstance(abort, dict) or set(abort) != {"correlationId", "sha256", "port", "pathSha256", "observedState"}
                or abort["correlationId"] != correlation_id or abort["sha256"] != record["sha256"]
                or abort["port"] != marker["port"] or abort["pathSha256"] != marker["pathSha256"]
                or abort["observedState"] not in {"absent", "partial", "hash-mismatch"}):
            return dict(_UNKNOWN)
        raw = base._remote(fresh_config, _REMOTE_GUEST_STATUS,
                           _task_args(record, marker, path) + ("after",), None, 120)
        observed = _guest_result(raw, {"absent", "partial", "hash-mismatch", "unknown"}, record)
        if observed.get("state") != "absent":
            return dict(_UNKNOWN)
        return {"state": "aborted", "correlationId": correlation_id,
                "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
    except (OSError, ValueError, subprocess.SubprocessError):
        return dict(_UNKNOWN)


def abort_cleanup(root: Path, config: Any, transfer_root: Path, correlation_id: str) -> dict[str, Any]:
    """Close an aborted transfer stage only before any base installer intent."""
    try:
        record = _intent(root, correlation_id)
        if record is None or base._private_intent(Path(root), correlation_id) is not None:
            return dict(_UNKNOWN)
        fresh_config = _admit_current(Path(root), record, Path(transfer_root))
        if (guest_abort_status(root, fresh_config, transfer_root, correlation_id).get("state") != "aborted"
                or listener_status(root, fresh_config, transfer_root, correlation_id).get("state") != "stopped"):
            return dict(_UNKNOWN)
        directory = _private_dir(Path(root), False)
        assert directory is not None
        if not _write_once(directory / (correlation_id + ".abort-cleanup.dispatch.json"),
                           {"correlationId": correlation_id, "sourceSha": record["sourceSha"],
                            "baseMsiArtifactId": record["baseMsiArtifactId"]}):
            return dict(_UNKNOWN)
        raw = base._remote(fresh_config, _REMOTE_ABORT_CLEANUP,
                           _remote_args(record, transfer_root), None, 15)
        return _phase_result(raw, {"aborted-cleaned", "unknown"})
    except (OSError, ValueError, subprocess.SubprocessError):
        return dict(_UNKNOWN)


def abort_cleanup_status(root: Path, config: Any, transfer_root: Path, correlation_id: str) -> dict[str, Any]:
    try:
        record = _intent(root, correlation_id)
        if record is None:
            return dict(_UNKNOWN)
        fresh_config = _admit_current(Path(root), record, Path(transfer_root))
        directory = _private_dir(Path(root), False)
        if directory is None or _read(directory / (correlation_id + ".abort-cleanup.dispatch.json")) != {
                "correlationId": correlation_id, "sourceSha": record["sourceSha"],
                "baseMsiArtifactId": record["baseMsiArtifactId"]}:
            return dict(_UNKNOWN)
        raw = base._remote(fresh_config, _REMOTE_ABORT_STATUS,
                           _remote_args(record, transfer_root), None, 15)
        return _phase_result(raw, {"present", "aborted-cleaned", "unknown"})
    except (OSError, ValueError, subprocess.SubprocessError):
        return dict(_UNKNOWN)


def ready_for_base(root: Path, config: Any, transfer_root: Path, correlation_id: str) -> dict[str, Any]:
    """Read-only, exact source and guest handoff proof for base.start."""
    try:
        joined = _listener_join(root, transfer_root, correlation_id)
        if joined is None:
            return dict(_UNKNOWN)
        fresh_config, record, _ = joined
        listener = listener_status(root, fresh_config, transfer_root, correlation_id)
        if listener.get("state") != "stopped" or "port" in listener:
            return dict(_UNKNOWN)
        guest = guest_task_status(root, fresh_config, transfer_root, correlation_id)
        if guest.get("state") != "ready-for-base":
            return dict(_UNKNOWN)
        staged = _remote_result(fresh_config, _REMOTE_PRE_BASE_STATUS,
                                _remote_args(record, transfer_root), None,
                                {"staged-for-base", "unknown"}, record)
        if staged.get("state") != "staged-for-base":
            return dict(_UNKNOWN)
        return {"state": "ready-for-base", "correlationId": correlation_id,
                "sourceSha": record["sourceSha"],
                "baseMsiArtifactId": record["baseMsiArtifactId"],
                "sha256": record["sha256"], "length": record["length"],
                "guestPath": (r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-base-"
                              + correlation_id + r"\base.msi"),
                "replayAllowed": False, "nativeActionAllowed": False,
                "productAction": False}
    except (OSError, ValueError, subprocess.SubprocessError):
        return dict(_UNKNOWN)


def _terminal_intent(root: Path, record: Mapping[str, Any]) -> str | None:
    directory = _private_dir(Path(root), False)
    if directory is None:
        return None
    value = _read(directory / (record["correlationId"] + ".terminal.json"))
    if (not isinstance(value, dict) or set(value) != {"correlationId", "sourceSha", "baseMsiArtifactId", "terminalReceiptSha256"}
            or value["correlationId"] != record["correlationId"]
            or value["sourceSha"] != record["sourceSha"]
            or value["baseMsiArtifactId"] != record["baseMsiArtifactId"]
            or not isinstance(value["terminalReceiptSha256"], str)
            or not _HASH.fullmatch(value["terminalReceiptSha256"])):
        return None
    return value["terminalReceiptSha256"]


def guest_file_cleanup(root: Path, config: Any, transfer_root: Path, correlation_id: str) -> dict[str, Any]:
    """After exact base terminal readback, remove only its verified guest MSI."""
    try:
        joined = _listener_join(root, transfer_root, correlation_id)
        if joined is None:
            return dict(_UNKNOWN)
        fresh_config, record, _ = joined
        terminal = _base_terminal(Path(root), record)
        if (guest_task_status(root, fresh_config, transfer_root, correlation_id).get("state") != "ready-for-base"
                or listener_status(root, fresh_config, transfer_root, correlation_id).get("state") != "stopped"):
            return dict(_UNKNOWN)
        directory = _private_dir(Path(root), False)
        assert directory is not None
        if not _write_once(directory / (correlation_id + ".terminal.json"),
                           {"correlationId": correlation_id, "sourceSha": record["sourceSha"],
                            "baseMsiArtifactId": record["baseMsiArtifactId"],
                            "terminalReceiptSha256": terminal}):
            return dict(_UNKNOWN)
        raw = base._remote(fresh_config, _REMOTE_GUEST_FILE_CLEANUP,
                           _guest_args(record) + (terminal,), None, 120)
        result = _terminal_result(raw, {"file-cleaned", "unknown"}, terminal)
        return result
    except (OSError, ValueError, subprocess.SubprocessError):
        return dict(_UNKNOWN)


def _terminal_result(raw: bytes | None, states: set[str], terminal: str) -> dict[str, Any]:
    if raw is None or len(raw) > 1024:
        return dict(_UNKNOWN)
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return dict(_UNKNOWN)
    if not isinstance(value, dict) or value.get("state") not in states:
        return dict(_UNKNOWN)
    if value["state"] == "unknown":
        if set(value) != {"state"}:
            return dict(_UNKNOWN)
    elif value["state"] == "file-cleaned":
        if value != {"state": "file-cleaned", "terminalReceiptSha256": terminal}:
            return dict(_UNKNOWN)
    elif value != {"state": value["state"], "terminalReceiptSha256": terminal}:
        return dict(_UNKNOWN)
    return {**value, "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}


def guest_file_cleanup_status(root: Path, config: Any, transfer_root: Path, correlation_id: str) -> dict[str, Any]:
    try:
        joined = _listener_join(root, transfer_root, correlation_id)
        if joined is None:
            return dict(_UNKNOWN)
        fresh_config, record, path = joined
        terminal = _terminal_intent(Path(root), record)
        marker = _guest_dispatch_marker(Path(root), record, path)
        if terminal is None or marker is None:
            return dict(_UNKNOWN)
        raw = base._remote(fresh_config, _REMOTE_GUEST_STATUS,
                           _task_args(record, marker, path) + ("after",), None, 120)
        observed = _guest_result(raw, {"absent", "partial", "hash-mismatch", "unknown"}, record)
        if observed.get("state") != "absent":
            return dict(_UNKNOWN)
        return {"state": "file-absent", "terminalReceiptSha256": terminal,
                "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
    except (OSError, ValueError, subprocess.SubprocessError):
        return dict(_UNKNOWN)


def terminal_cleanup(root: Path, config: Any, transfer_root: Path, correlation_id: str) -> dict[str, Any]:
    """Close only the owner-private Arch transfer stage after guest file absence."""
    try:
        record = _intent(root, correlation_id)
        if record is None:
            return dict(_UNKNOWN)
        fresh_config = _admit_current(Path(root), record, Path(transfer_root))
        terminal = _terminal_intent(Path(root), record)
        if (terminal is None or guest_file_cleanup_status(root, fresh_config, transfer_root, correlation_id).get("state") != "file-absent"):
            return dict(_UNKNOWN)
        directory = _private_dir(Path(root), False)
        assert directory is not None
        if not _write_once(directory / (correlation_id + ".terminal-cleanup.dispatch.json"),
                           {"correlationId": correlation_id, "terminalReceiptSha256": terminal}):
            return dict(_UNKNOWN)
        args = _remote_args(record, transfer_root) + (terminal,)
        marked = _terminal_result(base._remote(fresh_config, _REMOTE_TERMINAL_MARK, args, None, 15),
                                  {"marked", "unknown"}, terminal)
        if marked.get("state") != "marked":
            return dict(_UNKNOWN)
        return _terminal_result(base._remote(fresh_config, _REMOTE_TERMINAL_CLEANUP, args, None, 15),
                                {"cleaned", "unknown"}, terminal)
    except (OSError, ValueError, subprocess.SubprocessError):
        return dict(_UNKNOWN)


def terminal_cleanup_status(root: Path, config: Any, transfer_root: Path, correlation_id: str) -> dict[str, Any]:
    try:
        record = _intent(root, correlation_id)
        if record is None:
            return dict(_UNKNOWN)
        fresh_config = _admit_current(Path(root), record, Path(transfer_root))
        terminal = _terminal_intent(Path(root), record)
        directory = _private_dir(Path(root), False)
        if terminal is None or directory is None or _read(directory / (correlation_id + ".terminal-cleanup.dispatch.json")) != {
                "correlationId": correlation_id, "terminalReceiptSha256": terminal}:
            return dict(_UNKNOWN)
        return _terminal_result(base._remote(fresh_config, _REMOTE_TERMINAL_STATUS,
                                            _remote_args(record, transfer_root) + (terminal,), None, 15),
                                {"marked", "cleaned", "unknown"}, terminal)
    except (OSError, ValueError, subprocess.SubprocessError):
        return dict(_UNKNOWN)


def terminal_cleanup_collect(root: Path, config: Any, transfer_root: Path, correlation_id: str) -> dict[str, Any]:
    """Resume only a marked cleanup after an uncertain first transport result."""
    try:
        observed = terminal_cleanup_status(root, config, transfer_root, correlation_id)
        if observed.get("state") == "cleaned":
            return observed
        if observed.get("state") != "marked":
            return dict(_UNKNOWN)
        record = _intent(root, correlation_id)
        if record is None:
            return dict(_UNKNOWN)
        fresh_config = _admit_current(Path(root), record, Path(transfer_root))
        terminal = _terminal_intent(Path(root), record)
        if terminal != observed.get("terminalReceiptSha256"):
            return dict(_UNKNOWN)
        return _terminal_result(base._remote(fresh_config, _REMOTE_TERMINAL_CLEANUP,
                                            _remote_args(record, transfer_root) + (terminal,), None, 15),
                                {"cleaned", "unknown"}, terminal)
    except (OSError, ValueError, subprocess.SubprocessError):
        return dict(_UNKNOWN)


def _ps5_preflight_script(*, diagnostic: bool = False, census: bool = False,
                          cleanup: bool = False) -> str:
    """Parse fixed transfer PowerShell bodies on the guest without executing them."""
    values = {"SID": "S-1-5-21-1-2-3-1002", "CORR": "11111111-1111-4111-8111-111111111111",
              "DIGEST": "a" * 64, "SIZE": "12345", "PORT": "23456", "PATH": "x" * 40,
              "ARGS_SHA": "b" * 64, "MODE": "before"}
    bodies = []
    if sum((diagnostic, census, cleanup)) > 1:
        raise WindowsMsiHttpTransferError("Transfer parser batch is ambiguous.")
    templates = ((_GUEST_OWNER_CENSUS_PS,) if census else
                 (_GUEST_DIAGNOSTIC_PS,) if diagnostic else
                 (_GUEST_ABORT_PS, _GUEST_FILE_CLEANUP_PS) if cleanup else
                 (_GUEST_DOWNLOAD_PS, _GUEST_STATUS_PS, _GUEST_TASK_CLEANUP_PS))
    for template in templates:
        body = template
        for key, value in values.items():
            body = body.replace("@" + key + "@", value)
        if re.search(r"@[A-Z_]+@", body):
            raise WindowsMsiHttpTransferError("Transfer parser sample is unresolved.")
        bodies.append(base64.b64encode(gzip.compress(body.encode("utf-16le"), mtime=0)).decode())
    packed = ",".join("'" + value + "'" for value in bodies)
    return r'''$ErrorActionPreference='Stop'
try {
 foreach($item in @(@PACKED@)) {
  $raw=[Convert]::FromBase64String($item)
  $inputStream=[IO.MemoryStream]::new([byte[]]$raw)
  $decompressor=[IO.Compression.GzipStream]::new($inputStream,[IO.Compression.CompressionMode]::Decompress)
  $outputStream=[IO.MemoryStream]::new();$decompressor.CopyTo($outputStream)
  $body=[Text.Encoding]::Unicode.GetString($outputStream.ToArray())
  $decompressor.Dispose();$inputStream.Dispose();$outputStream.Dispose()
  $tokens=$null;$errors=$null
  [System.Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors)|Out-Null
  if($errors.Count -ne 0){throw 'SYNTAX'}
 }
 [Console]::Out.WriteLine('{"version":1,"code":"OK"}')
} catch { [Console]::Out.WriteLine('{"version":1,"code":"FAILED"}');exit 1 }
'''.replace("@PACKED@", packed)


def ps5_preflight(root: Path) -> dict[str, Any]:
    try:
        root = Path(root).resolve(strict=True)
        config, _target, descriptor = base._descriptor(root)
        expected_checks = ["ps5-parse", "gzip", "utf8-pipeline"]
        for batch in ("main", "cleanup", "diagnostic", "census"):
            script = _ps5_preflight_script(diagnostic=batch == "diagnostic", census=batch == "census",
                                           cleanup=batch == "cleanup")
            encoded = base64.b64encode(script.encode("utf-16le")).decode()
            if len(encoded) >= 30000:
                return dict(_UNKNOWN)
            raw = base._remote(config, windows_msi_public_scenario._REMOTE_PREFLIGHT,
                               (descriptor[1], str(descriptor[2]), str(descriptor[3]), encoded), None, 30)
            if raw is None or len(raw) > 1024:
                return dict(_UNKNOWN)
            value = json.loads(raw)
            if (not isinstance(value, dict) or set(value) != {"state", "checks"}
                    or value.get("state") != "passed" or value.get("checks") != expected_checks):
                return dict(_UNKNOWN)
        return {"state": "passed", "checks": expected_checks,
                "replayAllowed": False, "nativeActionAllowed": False,
                "productAction": False}
    except (OSError, ValueError, subprocess.SubprocessError):
        return dict(_UNKNOWN)


_PHASES = {
    "stage-start": remote_stage, "stage-status": remote_stage_status,
    "listener-start": listener_start, "listener-status": listener_status,
    "listener-diagnostic": listener_diagnostic,
    "listener-stop": listener_stop, "guest-download": guest_download,
    "guest-status": guest_download_status, "guest-diagnostic": guest_diagnostic,
    "guest-diagnostic-detail": guest_diagnostic,
    "guest-owner-census": guest_owner_census,
    "guest-task-cleanup": guest_task_cleanup,
    "guest-task-status": guest_task_status, "ready-for-base": ready_for_base,
    "guest-abort": guest_abort, "guest-abort-status": guest_abort_status,
    "abort-cleanup": abort_cleanup, "abort-cleanup-status": abort_cleanup_status,
    "guest-file-cleanup": guest_file_cleanup,
    "guest-file-cleanup-status": guest_file_cleanup_status,
    "terminal-cleanup": terminal_cleanup,
    "terminal-cleanup-status": terminal_cleanup_status,
}

_PUBLIC_STATES = {"prepared", "staged", "absent", "partial", "hash-mismatch", "diagnosed", "census",
                  "listening", "starting", "failed", "served", "stopped", "submitted",
                  "running", "downloaded", "task-cleaned", "ready-for-base", "aborted",
                  "aborted-cleaned", "file-cleaned", "file-absent", "marked", "cleaned",
                  "present", "passed"}


_DIGEST_PHASES = {"prepare", "stage-start", "stage-status", "guest-status",
                  "guest-task-status", "ready-for-base"}
_TERMINAL_PHASES = {"guest-file-cleanup", "guest-file-cleanup-status",
                    "terminal-cleanup", "terminal-cleanup-status"}


def _public_result(value: Mapping[str, Any], correlation: str | None = None,
                   action: str = "") -> dict[str, Any]:
    """Keep private listener address and guest path outside MCP responses."""
    if not isinstance(value, Mapping) or value.get("state") not in _PUBLIC_STATES:
        return dict(_UNKNOWN)
    result: dict[str, Any] = {"state": value["state"], "replayAllowed": False,
                              "nativeActionAllowed": False, "productAction": False}
    if correlation is not None:
        if not _UUID.fullmatch(correlation):
            return dict(_UNKNOWN)
        if "correlationId" in value and value["correlationId"] != correlation:
            return dict(_UNKNOWN)
        result["correlationId"] = correlation
    if action in _DIGEST_PHASES:
        for key, pattern in (("sourceSha", _SHA),
                             ("baseMsiArtifactId", re.compile(r"sha256-[0-9a-f]{64}\Z")),
                             ("sha256", _HASH)):
            if key in value:
                if not isinstance(value[key], str) or not pattern.fullmatch(value[key]):
                    return dict(_UNKNOWN)
                result[key] = value[key]
        if "length" in value:
            if type(value["length"]) is not int or not 0 < value["length"] <= 1 << 30:
                return dict(_UNKNOWN)
            result["length"] = value["length"]
    if action in _TERMINAL_PHASES and "terminalReceiptSha256" in value:
        terminal = value["terminalReceiptSha256"]
        if not isinstance(terminal, str) or not _HASH.fullmatch(terminal):
            return dict(_UNKNOWN)
        result["terminalReceiptSha256"] = terminal
    if action == "guest-diagnostic" and value["state"] == "diagnosed":
        for key, allowed in (("task", _DIAGNOSTIC_TASK), ("principal", _DIAGNOSTIC_MATCH),
                             ("action", _DIAGNOSTIC_MATCH), ("sid", _DIAGNOSTIC_MATCH),
                             ("leaf", _DIAGNOSTIC_LEAF), ("reason", _DIAGNOSTIC_REASON)):
            if not isinstance(value.get(key), str) or value[key] not in allowed:
                return dict(_UNKNOWN)
            result[key] = value[key]
    if action == "guest-diagnostic-detail" and value["state"] == "diagnosed":
        for key, allowed in (("task", _DIAGNOSTIC_TASK), ("principal", _DIAGNOSTIC_MATCH),
                             ("action", _DIAGNOSTIC_MATCH), ("sid", _DIAGNOSTIC_MATCH),
                             ("leaf", _DIAGNOSTIC_LEAF), ("reason", _DIAGNOSTIC_REASON),
                             ("principalUser", _DIAGNOSTIC_USER),
                             ("principalLogon", _DIAGNOSTIC_MATCH),
                             ("principalRunLevel", _DIAGNOSTIC_MATCH),
                             ("leafAt", _DIAGNOSTIC_AT), ("leafFault", _DIAGNOSTIC_FAULT),
                             ("leafOwner", _DIAGNOSTIC_OWNER)):
            if not isinstance(value.get(key), str) or value[key] not in allowed:
                return dict(_UNKNOWN)
            result[key] = value[key]
    if action == "guest-owner-census" and value["state"] == "census":
        validated = _project_owner_census(json.dumps({"state": "census", "paths": value.get("paths")}).encode())
        if validated.get("state") != "census":
            return dict(_UNKNOWN)
        result["paths"] = validated["paths"]
    if action == "listener-diagnostic" and value["state"] == "diagnosed":
        for key, allowed in _LISTENER_DIAGNOSTIC_ENUMS.items():
            if not isinstance(value.get(key), str) or value[key] not in allowed:
                return dict(_UNKNOWN)
            result[key] = value[key]
    return result


def workflow(root: Path | str, action: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Fixed MCP façade: derive every path, credential, token and guest selector."""
    if not isinstance(action, str) or not isinstance(inputs, Mapping):
        raise WindowsMsiHttpTransferError("Invalid transfer workflow request.")
    if action == "ps5-preflight":
        if dict(inputs) != {"host": "archlinux"}:
            raise WindowsMsiHttpTransferError("PS5 preflight requires exact host.")
        root = Path(root).resolve(strict=True)
        return _public_result(ps5_preflight(root), action=action)
    if action == "prepare":
        request = base._request(inputs)
        try:
            root = Path(root).resolve(strict=True)
            config, target, descriptor = base._descriptor(root)
            from . import windows_cp117_source_campaign as source_campaign
            source_artifact = None
            try:
                source_artifact = source_campaign.transfer_admission(root, request)
            except source_campaign.WindowsCp117SourceCampaignError:
                pass
            if source_artifact is None:
                base._require_reconciled_legacy(root, descriptor, request["expectedCurrentVersion"])
                base._require_base_route_free(root, config, target, descriptor)
                ready = base.readiness(root, {"host": "archlinux",
                                              "expectedCurrentVersion": request["expectedCurrentVersion"]})
                if (ready.get("state") != "ready" or ready.get("ready") is not True
                        or ready.get("installedVersion") != request["expectedCurrentVersion"]
                        or ready.get("productCount") != 1 or ready.get("activeCount") != 0
                        or ready.get("activeProcesses") != []):
                    return dict(_UNKNOWN)
                _pair, artifact, _size = base._admit(root, request)
            else:
                artifact = source_artifact
            binding = {"correlationId": request["correlationId"], "sourceSha": request["sourceSha"],
                       "baseMsiArtifactId": request["baseMsiArtifactId"], "environment": descriptor[0],
                       "socketPath": descriptor[1], "qemuPid": descriptor[2],
                       "startTicks": descriptor[3], "expectedSid": descriptor[4]}
            _admit_current(root, {**binding, "artifactPath": str(artifact.absolute())},
                           Path(target.fixture_transfer_root))
            return _public_result(prepare(root, binding, artifact), request["correlationId"], action)
        except (OSError, ValueError, subprocess.SubprocessError):
            return dict(_UNKNOWN)
    if action not in _PHASES or set(inputs) != {"correlationId"}:
        raise WindowsMsiHttpTransferError("Transfer phase requires exact correlationId.")
    correlation = inputs["correlationId"]
    if not isinstance(correlation, str) or not _UUID.fullmatch(correlation):
        raise WindowsMsiHttpTransferError("Invalid transfer correlationId.")
    try:
        root = Path(root).resolve(strict=True)
        record = _intent(root, correlation)
        if record is None:
            return dict(_UNKNOWN)
        config, target, _descriptor = base._descriptor(root)
        transfer_root = Path(target.fixture_transfer_root)
        _admit_current(root, record, transfer_root)
        if action == "stage-start":
            return _public_result(remote_stage(root, config, transfer_root, correlation,
                                               Path(record["artifactPath"])), correlation, action)
        if action == "terminal-cleanup":
            prior = terminal_cleanup_status(root, config, transfer_root, correlation)
            if prior.get("state") in {"marked", "cleaned"}:
                return _public_result(terminal_cleanup_collect(root, config, transfer_root, correlation),
                                      correlation, action)
        return _public_result(_PHASES[action](root, config, transfer_root, correlation), correlation, action)
    except (OSError, ValueError, subprocess.SubprocessError):
        return dict(_UNKNOWN)

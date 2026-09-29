"""One-shot repair of the pinned Arch swtpm package for the Windows fixture.

The fixed route is deliberately narrower than a package manager: it repairs
only an installed ``extra/swtpm=0.10.2-1`` that failed ``pacman -Qkk`` and
only while no swtpm process exists.  No VM is inspected, stopped, or changed.
"""
from __future__ import annotations

import json
import os
import base64
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Mapping

try:
    from . import ssh_transport
    from . import windows_vm_virt_firmware_install
    from . import windows_vm_secureboot_fresh
except ImportError:  # CLI fallback
    import ssh_transport  # type: ignore[no-redef]
    import windows_vm_virt_firmware_install  # type: ignore[no-redef]
    import windows_vm_secureboot_fresh  # type: ignore[no-redef]

HOST = "archlinux"; PACKAGE = "swtpm"; VERSION = "0.10.2-1"; REPOSITORY = "extra"
CREDENTIAL_RELATIVE_PATH = Path(".codex") / "arch-sudo.local"
_UUID = re.compile(r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$")
_MAX_CREDENTIAL_BYTES = 512

# All remote diagnostics are discarded.  This program publishes only a small
# typed outcome, so sudo/password and pacman messages cannot leak into logs.
_REMOTE = r'''import json,subprocess,sys
HOST='archlinux';PACKAGE='swtpm';VERSION='0.10.2-1';REPOSITORY='extra';MODE=__MODE__;CORR=__CORR__
def emit(state,signature=False,integrity=False,active=False):
 print(json.dumps({'schemaVersion':1,'host':HOST,'correlationId':CORR,'state':state,'package':PACKAGE,'version':VERSION,'pacmanSignatureVerified':signature,'packageIntegrityVerified':integrity,'activeSwtpmProcesses':active},separators=(',',':'),sort_keys=True))
def run(argv,output=False):
 return subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE if output else subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30,check=False,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C'})
def installed():
 r=run(['/usr/bin/pacman','-Q',PACKAGE],True)
 return r.returncode==0 and len(r.stdout)<=128 and r.stdout.decode('utf-8','strict').strip()==PACKAGE+' '+VERSION
def active():
 # Process names are bounded and never emitted; any failure fails closed.
 r=run(['/usr/bin/pgrep','-x','swtpm'],True)
 return True if r.returncode==0 else False if r.returncode==1 else None
try:
 running=active()
 if running is None: emit('process-census-unavailable');raise SystemExit
 if running: emit('active-swtpm-processes',active=True);raise SystemExit
 if MODE=='start':
  # Recheck both package facts before accepting private input.  A separate
  # observer may have repaired it after this operation's preflight.
  if not installed(): emit('package-not-exact');raise SystemExit
  if run(['/usr/bin/pacman','-Qkk',PACKAGE]).returncode==0: emit('already-healthy',integrity=True);raise SystemExit
  secret=sys.stdin.buffer.read(513)
  if not 1<=len(secret)<=512 or b'\0' in secret: raise ValueError()
  # Do not add --needed: exact same-version reinstall must be signed.
  r=subprocess.run(['/usr/bin/sudo','-S','-p','','--','/usr/bin/pacman','-S','--noconfirm',REPOSITORY+'/'+PACKAGE+'='+VERSION],input=secret,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=180,check=False,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C'})
  if r.returncode: emit('transaction-failed');raise SystemExit
  signature=True
 else: signature=False
 if not installed(): emit('package-not-exact',signature);raise SystemExit
 running=active()
 if running is None: emit('process-census-unavailable',signature);raise SystemExit
 if running: emit('active-swtpm-processes',signature,active=True);raise SystemExit
 integrity=run(['/usr/bin/pacman','-Qkk',PACKAGE]).returncode==0
 emit('verified' if integrity else 'integrity-failed',signature,integrity)
except (OSError,ValueError,UnicodeDecodeError,subprocess.TimeoutExpired): emit('unknown')
'''

# This observer examines only the fixed secure-boot fixture's known TPM socket.
# It never publishes command lines, descriptor targets, or any other path.
_OWNER_OBSERVE_REMOTE = r'''import json,os,stat,time
TPM_SOCKET=__TPM_SOCKET__;GUEST=__GUEST__;MAX_PROCS=8192;MAX_SWTPM=16;MAX_FDS=8192
def ticks(pid):
 try:return int(open('/proc/%d/stat'%pid,encoding='ascii').read(4096).rsplit(')',1)[1].split()[19])
 except (OSError,ValueError,IndexError):return None
def visibility():
 try:
  if os.readlink('/proc/1/ns/pid')!=os.readlink('/proc/self/ns/pid'):return 'proc-visibility-incomplete'
  with open('/proc/self/mountinfo',encoding='ascii') as f: rows=f.read(1048576).splitlines()
  if len(rows)>=65536:return 'proc-visibility-incomplete'
  proc=[line for line in rows if ' - proc ' in line and line.split(' - ',1)[0].split()[4]=='/proc']
  if len(proc)!=1:return 'proc-visibility-incomplete'
  options={token for field in proc[0].replace(' - ',' ').split() for token in field.split(',')}
  return 'complete' if 'subset=pid' not in options and not any(item.startswith('hidepid=') and item!='hidepid=0' for item in options) else 'proc-visibility-incomplete'
 except (OSError,IndexError,ValueError):return 'proc-visibility-incomplete'
def unix():
 table={}
 with open('/proc/net/unix',encoding='ascii') as f:
  data=f.read(1048577)
 if len(data)>1048576:raise ValueError()
 for line in data.splitlines()[1:]:
  fields=line.split()
  if len(fields)>=7 and fields[6].isdigit():table[int(fields[6])]=fields[7] if len(fields)>=8 else None
 return table
def private_receipt(path,limit):
 info=os.lstat(path)
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size<2 or info.st_size>limit:raise ValueError()
 with open(path,encoding='utf-8') as f:return json.load(f)
def live_qemu(pid,start):
 before=ticks(pid)
 if before!=start:return False
 try:comm=open('/proc/%d/comm'%pid,encoding='ascii').read(128).strip()
 except OSError:return False
 return comm=='qemu-system-x86_64' and ticks(pid)==start
def task_claim(pid,start):
 try:
  guest=os.lstat(GUEST);tpm=os.lstat(GUEST+'/tpm')
  if not stat.S_ISDIR(guest.st_mode) or not stat.S_ISDIR(tpm.st_mode) or guest.st_uid!=os.geteuid() or tpm.st_uid!=os.geteuid() or stat.S_IMODE(guest.st_mode)!=0o700 or stat.S_IMODE(tpm.st_mode)!=0o700: return False
  receipt=private_receipt(GUEST+'/swtpm-started.json',256)
  qemu=private_receipt(GUEST+'/qemu-started.json',256)
  return receipt=={'pid':pid,'startTicks':start} and type(qemu.get('pid')) is int and qemu['pid']>0 and type(qemu.get('startTicks')) is int and qemu['startTicks']>0 and live_qemu(qemu['pid'],qemu['startTicks'])
 except (OSError,ValueError,TypeError):return False
def relationship(pid,start,table):
 names=os.listdir('/proc/%d/fd'%pid)
 if len(names)>MAX_FDS:raise ValueError()
 linked=False;unattributed=False
 for name in names:
  link=os.readlink('/proc/%d/fd/%s'%(pid,name))
  if not link.startswith('socket:[') or not link.endswith(']'):continue
  inode=int(link[8:-1]);path=table.get(inode)
  if path==TPM_SOCKET:linked=True
  elif path is not None:unattributed=True
 return 'task-owned-swtpm-socket' if linked and task_claim(pid,start) else 'unattributed-vm-or-socket-path' if linked or unattributed else 'no-visible-socket-path'
try:
 reason=visibility();complete=reason=='complete';table=unix();items=[];entries=[name for name in os.listdir('/proc') if name.isdecimal()]
 if len(entries)>MAX_PROCS:raise ValueError('census-capacity')
 for name in entries:
  pid=int(name)
  try: comm=open('/proc/%d/comm'%pid,encoding='ascii').read(128).strip()
  except FileNotFoundError:
   if os.path.exists('/proc/%d'%pid):complete=False;reason='process-read-unavailable'
   continue
  except OSError:complete=False;reason='process-read-unavailable';continue
  if comm!='swtpm':continue
  if len(items)>=MAX_SWTPM:complete=False;reason='census-capacity';break
  start=ticks(pid)
  try:
   uid=os.stat('/proc/%d'%pid).st_uid
   if start is None or uid<0:raise ValueError()
   relation=relationship(pid,start,table)
   if ticks(pid)!=start:raise ValueError()
   items.append({'pid':pid,'startTicks':start,'uid':uid,'relationship':relation})
  except (OSError,ValueError):
   complete=False;reason='fd-census-incomplete';items.append({'pid':pid,'startTicks':start,'uid':None,'relationship':'unattributed-vm-or-socket-path'})
 print(json.dumps({'schemaVersion':1,'host':'archlinux','censusComplete':complete,'censusReason':None if complete else reason,'observedAtUnixMs':int(time.time()*1000),'processes':items},sort_keys=True,separators=(',',':')))
except (OSError,ValueError) as error:
 reason=str(error) if str(error) in ('census-capacity',) else 'census-unavailable'
 print(json.dumps({'schemaVersion':1,'host':'archlinux','censusComplete':False,'censusReason':reason,'observedAtUnixMs':int(time.time()*1000),'processes':[]},sort_keys=True,separators=(',',':')))
'''

def _validate(host: str, correlation_id: str, timeout_seconds: int) -> None:
    if host != HOST or not isinstance(correlation_id, str) or not _UUID.fullmatch(correlation_id) or type(timeout_seconds) is not int or not 10 <= timeout_seconds <= 300:
        raise ValueError("swtpm repair requires fixed host, canonical correlation and bounded timeout.")

def _credential_path(root: str | Path) -> Path:
    return Path(root).resolve() / CREDENTIAL_RELATIVE_PATH

def _read_credential(root: str | Path) -> bytes:
    path = _credential_path(root)
    if not path.is_absolute(): raise ValueError("Arch sudo credential path is unsafe.")
    try: parent=os.open(path.parent, os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0))
    except OSError as error: raise ValueError("Arch sudo credential parent is unsafe.") from error
    try:
        directory=os.fstat(parent)
        if not stat.S_ISDIR(directory.st_mode) or directory.st_uid!=os.getuid() or directory.st_mode&0o022: raise ValueError("Arch sudo credential parent is unsafe.")
        try: named=os.stat(path.name,dir_fd=parent,follow_symlinks=False); fd=os.open(path.name,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0),dir_fd=parent)
        except OSError as error: raise ValueError("Arch sudo credential is unavailable.") from error
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(named.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or not 0<info.st_size<=_MAX_CREDENTIAL_BYTES or (named.st_dev,named.st_ino,named.st_mtime_ns,named.st_size)!=(info.st_dev,info.st_ino,info.st_mtime_ns,info.st_size): raise ValueError("Arch sudo credential is unsafe.")
            value=os.read(fd,_MAX_CREDENTIAL_BYTES+1)
            if len(value)!=info.st_size or b'\0' in value: raise ValueError("Arch sudo credential is unsafe.")
            return value
        finally: os.close(fd)
    finally: os.close(parent)

def _credential_metadata(root: str | Path) -> bool:
    path=_credential_path(root)
    try:
        fd=os.open(path.parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0))
        try:
            parent=os.fstat(fd); item=os.stat(path.name,dir_fd=fd,follow_symlinks=False)
            return stat.S_ISDIR(parent.st_mode) and parent.st_uid==os.getuid() and not parent.st_mode&0o022 and stat.S_ISREG(item.st_mode) and item.st_uid==os.getuid() and stat.S_IMODE(item.st_mode)==0o600 and 0<item.st_size<=_MAX_CREDENTIAL_BYTES
        finally: os.close(fd)
    except OSError: return False

def _journal(root: str | Path, *, create: bool) -> Path:
    directory=Path(root).resolve()/'.rag_index'/'windows-vm-swtpm-repair'
    if create: directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    info=os.lstat(directory)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: raise ValueError("swtpm repair journal directory is unsafe.")
    return directory/'intent.json'

def _intent(correlation_id: str) -> dict[str, Any]:
    return {'schemaVersion':1,'correlationId':correlation_id,'host':HOST,'repository':REPOSITORY,'package':PACKAGE,'version':VERSION}

def _save_intent(path: Path, correlation_id: str) -> None:
    data=json.dumps(_intent(correlation_id),sort_keys=True,separators=(',',':')).encode();fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    try: os.write(fd,data);os.fsync(fd)
    finally: os.close(fd)
    parent=os.open(path.parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
    try: os.fsync(parent)
    finally: os.close(parent)

def _read_intent(path: Path, correlation_id: str) -> None:
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    try:
        info=os.fstat(fd);raw=os.read(fd,info.st_size+1)
    finally: os.close(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>2048 or len(raw)!=info.st_size or json.loads(raw)!=_intent(correlation_id): raise ValueError("swtpm repair intent is unsafe.")

def _remote(root: str | Path, correlation_id: str, mode: str, timeout_seconds: int, *, credential: bytes | None = None) -> dict[str, Any]:
    program=_REMOTE.replace('__MODE__',repr(mode)).replace('__CORR__',repr(correlation_id));config=ssh_transport.load_config(Path(root).resolve(strict=True))
    if HOST not in config.hosts or ssh_transport.connection_host(config,HOST).password is not None: raise ValueError("Configured Arch transport is unavailable.")
    argv=ssh_transport.build_ssh_argv(config,HOST,min(timeout_seconds,60),command=('/usr/bin/python3','-c','exec('+repr(program)+')'),ssh_binary='/usr/bin/ssh',nested_ssh_binary='/usr/bin/ssh')
    run=subprocess.run(argv,input=credential,stdin=subprocess.DEVNULL if credential is None else None,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout_seconds,check=False)
    if run.returncode or not 0<len(run.stdout)<=1024: raise ValueError("swtpm repair transport is unknown.")
    value=json.loads(run.stdout);required={'schemaVersion','host','correlationId','state','package','version','pacmanSignatureVerified','packageIntegrityVerified','activeSwtpmProcesses'}
    states={'verified','already-healthy','integrity-failed','package-not-exact','active-swtpm-processes','process-census-unavailable','transaction-failed','unknown'}
    if not isinstance(value,Mapping) or set(value)!=required or value.get('schemaVersion')!=1 or value.get('host')!=HOST or value.get('correlationId')!=correlation_id or value.get('state') not in states or value.get('package')!=PACKAGE or value.get('version')!=VERSION or any(type(value.get(k)) is not bool for k in ('pacmanSignatureVerified','packageIntegrityVerified','activeSwtpmProcesses')): raise ValueError("swtpm repair response is invalid.")
    return dict(value)

def owner_observe(root: str | Path, *, host: str, timeout_seconds: int = 30) -> dict[str, Any]:
    """Return bounded, read-only identities for all visible swtpm processes."""
    if host != HOST or type(timeout_seconds) is not int or not 10 <= timeout_seconds <= 60:
        raise ValueError("swtpm owner observation requires fixed host and bounded timeout.")
    config = ssh_transport.load_config(Path(root).resolve(strict=True))
    if HOST not in config.hosts or ssh_transport.connection_host(config, HOST).password is not None:
        raise ValueError("Configured Arch transport is unavailable.")
    socket = windows_vm_secureboot_fresh.GUEST + "/tpm/swtpm.sock"
    program = (_OWNER_OBSERVE_REMOTE.replace("__TPM_SOCKET__", repr(socket))
               .replace("__GUEST__", repr(windows_vm_secureboot_fresh.GUEST)))
    encoded = base64.b64encode(program.encode("utf-8")).decode("ascii")
    argv = ssh_transport.build_ssh_argv(config, HOST, min(timeout_seconds, 60),
        command=("/usr/bin/python3", "-c", "import base64;exec(base64.b64decode(" + repr(encoded) + "))"),
        ssh_binary="/usr/bin/ssh", nested_ssh_binary="/usr/bin/ssh")
    try:
        run = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=timeout_seconds, check=False)
        value = json.loads(run.stdout)
        if run.returncode or not isinstance(value, Mapping) or set(value) != {
                "schemaVersion", "host", "censusComplete", "censusReason", "observedAtUnixMs", "processes"} or \
                value.get("schemaVersion") != 1 or value.get("host") != HOST or \
                type(value.get("censusComplete")) is not bool or \
                type(value.get("observedAtUnixMs")) is not int or value["observedAtUnixMs"] < 0 or \
                not isinstance(value.get("processes"), list) or len(value["processes"]) > 16:
            raise ValueError("swtpm owner observation is invalid.")
        if value["censusComplete"]:
            if value.get("censusReason") is not None:
                raise ValueError("swtpm owner observation reason is contradictory.")
        elif value.get("censusReason") not in {"proc-visibility-incomplete", "process-read-unavailable", "fd-census-incomplete", "census-capacity", "census-unavailable"}:
            raise ValueError("swtpm owner observation reason is invalid.")
        processes: list[dict[str, Any]] = []
        saw_process = bool(value["processes"])
        complete = value["censusComplete"]
        seen: set[int] = set()
        for item in value["processes"]:
            if (not isinstance(item, Mapping) or set(item) != {"pid", "startTicks", "uid", "relationship"} or
                    type(item.get("pid")) is not int or item["pid"] <= 0 or item["pid"] in seen or
                    type(item.get("startTicks")) is not int or item["startTicks"] <= 0 or
                    type(item.get("uid")) is not int or item["uid"] < 0 or
                    item.get("relationship") not in {"task-owned-swtpm-socket", "unattributed-vm-or-socket-path", "no-visible-socket-path"}):
                raise ValueError("swtpm owner observation process is invalid.")
            seen.add(item["pid"]); processes.append(dict(item))
        return {"host": HOST, "state": "observed" if complete else "unknown", "censusReason": value["censusReason"],
                "censusComplete": complete, "activeSwtpmProcesses": saw_process or len(processes) > 0,
                "processes": processes, "nativeActionAllowed": False}
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return {"host": HOST, "state": "unknown", "censusReason": "census-unavailable", "censusComplete": False,
                "activeSwtpmProcesses": False, "processes": [], "nativeActionAllowed": False}

def _policy(root: str | Path, timeout_seconds: int) -> bool:
    # The firmware installer owns the bounded pacman-conf fallback: an unset
    # extra-local value inherits the global effective SigLevel, while an
    # explicit unreadable extra override fails closed.
    return windows_vm_virt_firmware_install._signature_policy_state(root, timeout_seconds).startswith("required-trusted-")

def _state(result: Mapping[str, Any], correlation_id: str) -> dict[str, Any]:
    return {'correlationId':correlation_id,'host':HOST,'state':result.get('state','unknown'),'package':PACKAGE,'version':VERSION,'pacmanSignatureVerified':result.get('pacmanSignatureVerified') is True,'packageIntegrityVerified':result.get('packageIntegrityVerified') is True,'activeSwtpmProcesses':result.get('activeSwtpmProcesses') is True,'replayAllowed':False,'nativeActionAllowed':False}

def preflight(root: str | Path, *, host: str, correlation_id: str, timeout_seconds: int = 60) -> dict[str, Any]:
    _validate(host,correlation_id,timeout_seconds)
    try: _read_intent(_journal(root,create=False),correlation_id);state='intent-existing';remote=None
    except FileNotFoundError:
        try: remote=_remote(root,correlation_id,'status',timeout_seconds);state='ready' if remote['state']=='integrity-failed' and not remote['activeSwtpmProcesses'] else remote['state']
        except (OSError,ValueError,subprocess.TimeoutExpired,json.JSONDecodeError): remote=None;state='transport-unavailable'
    if state=='ready' and not _policy(root,timeout_seconds): state='signature-policy-rejected'
    if state=='ready' and not _credential_metadata(root): state='credential-metadata-invalid'
    return {'correlationId':correlation_id,'host':HOST,'state':state,'packageIntegrityFailed':remote is not None and remote.get('state')=='integrity-failed','activeSwtpmProcesses':remote is not None and remote.get('activeSwtpmProcesses') is True,'safeStartAllowed':state=='ready','newCorrelationRequired':True,'nativeActionAllowed':False}

def start(root: str | Path, *, host: str, correlation_id: str, timeout_seconds: int = 180) -> dict[str, Any]:
    _validate(host,correlation_id,timeout_seconds)
    try: _read_intent(_journal(root,create=False),correlation_id);raise ValueError("swtpm repair intent already exists; use exact status.")
    except FileNotFoundError: pass
    observation=_remote(root,correlation_id,'status',timeout_seconds)
    if observation['state']!='integrity-failed' or observation['activeSwtpmProcesses']: raise ValueError("swtpm repair precondition is no longer safe.")
    if not _policy(root,timeout_seconds): raise ValueError("Arch pacman signature policy is unavailable.")
    credential=_read_credential(root);path=_journal(root,create=True)
    try: _save_intent(path,correlation_id)
    except FileExistsError as error: raise ValueError("swtpm repair intent already exists; use exact status.") from error
    try: result=_remote(root,correlation_id,'start',timeout_seconds,credential=credential)
    except (OSError,ValueError,subprocess.TimeoutExpired,json.JSONDecodeError): result={'state':'unknown'}
    return _state(result,correlation_id)

def status(root: str | Path, *, host: str, correlation_id: str, timeout_seconds: int = 60) -> dict[str, Any]:
    _validate(host,correlation_id,timeout_seconds)
    try: _read_intent(_journal(root,create=False),correlation_id)
    except FileNotFoundError: return _state({'state':'intent-absent'},correlation_id)
    try: result=_remote(root,correlation_id,'status',timeout_seconds)
    except (OSError,ValueError,subprocess.TimeoutExpired,json.JSONDecodeError): result={'state':'unknown'}
    return _state(result,correlation_id)

"""One-shot repair of the pinned Arch swtpm package for the Windows fixture.

The fixed route is deliberately narrower than a package manager: it repairs
only an installed ``extra/swtpm=0.10.2-1`` that failed ``pacman -Qkk`` and
only while no swtpm process exists.  No VM is inspected, stopped, or changed.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Mapping

try:
    from . import ssh_transport
    from . import windows_vm_virt_firmware_install
except ImportError:  # CLI fallback
    import ssh_transport  # type: ignore[no-redef]
    import windows_vm_virt_firmware_install  # type: ignore[no-redef]

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

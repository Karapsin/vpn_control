"""One separate, non-replaying reconciliation for CP117's armed stale lock."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Mapping

from . import windows_msi_owner_liveness as liveness
from . import windows_msi_stale_lock_recovery as stale
from . import windows_msi_base_prepare as base

class WindowsMsiStaleLockReconcileError(ValueError): pass

_CORRELATION = 'a4d4e22d-25aa-44b5-9b09-e17b249e4225'
_GROUP = '.rag_index/windows-msi-stale-lock-reconcile'
_UNKNOWN = {'state':'unknown','replayAllowed':False,'nativeActionAllowed':False}

_STATUS_PS=r'''$ErrorActionPreference='Stop'
$state='C:\Users\vpncp117\AppData\Local\VpnControl\cp166\state';$lock=Join-Path $state 'vpn-control.lock';$endpoint=Join-Path $state 'activation.port'
function SafeDirectory([string]$path){$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop;if(-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){throw 'DIR'}}
function Absent([string]$path){try{Get-Item -LiteralPath $path -Force -ErrorAction Stop|Out-Null;throw 'PRESENT'}catch{if($_.CategoryInfo.Category -ne [System.Management.Automation.ErrorCategory]::ObjectNotFound){throw 'UNREADABLE'}}}
try{foreach($path in @('C:\Users','C:\Users\vpncp117','C:\Users\vpncp117\AppData','C:\Users\vpncp117\AppData\Local','C:\Users\vpncp117\AppData\Local\VpnControl','C:\Users\vpncp117\AppData\Local\VpnControl\cp166',$state)){SafeDirectory $path};Absent $lock;Absent $endpoint;$all=@(Get-CimInstance Win32_Process -ErrorAction Stop);if(@($all|Where-Object {$_.Name -in @('vpn-control.exe','vpn-control-cli.exe','msiexec.exe','consent.exe','sing-box.exe')}).Count -ne 0){throw 'PROCESS'};[Console]::Out.WriteLine('{"version":1,"state":"absent"}')}
catch{[Console]::Out.WriteLine('{"version":1,"state":"unknown"}')}
'''
_REMOTE_STATUS=base._QGA+r'''import time
sock,pid,ticks=sys.argv[1:]
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
try:
 if not live(sock,pid,ticks):raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(STATUS_PS.encode('utf-16le')).decode()],'capture-output':True}).get('pid')
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(160):
  observed=call(sock,'guest-exec-status',{'pid':child})
  if observed.get('exited') is True:break
  if observed.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 if type(observed.get('exitcode')) is not int or observed['exitcode']!=0 or observed.get('out-truncated') is True or observed.get('err-truncated') is True:raise ValueError()
 raw=base64.b64decode(observed.get('out-data',''),validate=True);lines=[line for line in decode(raw).splitlines() if line.startswith('{') and line.endswith('}')]
 if len(lines)!=1:raise ValueError()
 value=json.loads(lines[0])
 if not isinstance(value,dict) or set(value)!={'version','state'} or value.get('version')!=1 or value.get('state')!='absent':raise ValueError()
 out(value)
except Exception:out({'version':1,'state':'unknown'})
'''.replace('STATUS_PS',repr(_STATUS_PS))

def _directory(root: Path, create: bool = True) -> Path:
    path=root/_GROUP
    if create: path.mkdir(mode=0o700,parents=True,exist_ok=True)
    info=path.lstat()
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink() or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: raise WindowsMsiStaleLockReconcileError('Reconcile journal is unsafe.')
    return path

def _path(root: Path, create: bool = True) -> Path: return _directory(root,create)/(_CORRELATION+'.json')

def _read(root: Path) -> dict[str,Any]|None:
    try: path=_path(root,False)
    except FileNotFoundError: return None
    try: fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    except FileNotFoundError: return None
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>4096: raise WindowsMsiStaleLockReconcileError('Reconcile receipt is unsafe.')
        try: value=json.load(stream)
        except (TypeError,ValueError) as error: raise WindowsMsiStaleLockReconcileError('Reconcile receipt is invalid.') from error
    required={'version','correlationId','oldCorrelationId','sourceSha','guestGeneration','evidenceSha256','state'}
    if not isinstance(value,dict) or set(value)!=required or value.get('version')!=1 or value.get('correlationId')!=_CORRELATION or value.get('oldCorrelationId')!=stale._CORRELATION or value.get('sourceSha')!=stale._SOURCE or value.get('state') not in {'intent','recovered'}: raise WindowsMsiStaleLockReconcileError('Reconcile receipt is invalid.')
    return value

def _write(root: Path,value: Mapping[str,Any],replace: bool=False) -> None:
    directory=_directory(root); path=_path(root); lock=os.open(directory/'.environment.lock',os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX); current=_read(root)
        if (current is not None) != replace or (replace and current.get('state')!='intent'): raise WindowsMsiStaleLockReconcileError('Reconcile receipt changed.')
        temporary=path.with_suffix('.tmp'); data=(json.dumps(dict(value),sort_keys=True,separators=(',',':'))+'\n').encode()
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
        with os.fdopen(fd,'wb') as stream: stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path); parent=os.open(directory,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(parent);os.close(parent)
    finally:
        try: temporary.unlink()
        except (FileNotFoundError,UnboundLocalError): pass
        os.close(lock)

def _admit(root: Path) -> tuple[Any,tuple[str,str,int,int,str],str]|None:
    admitted=stale._admit(root)
    if admitted is None: return None
    old=stale._read_intent(root)
    config,descriptor,cli_hash=admitted
    if old is None or old.get('state')!='intent' or not stale._matches_current(old,descriptor): return None
    return config,descriptor,cli_hash

def _record(descriptor: tuple[str,str,int,int,str],state: str) -> dict[str,Any]:
    generation,evidence=stale._evidence(descriptor)
    return {'version':1,'correlationId':_CORRELATION,'oldCorrelationId':stale._CORRELATION,'sourceSha':stale._SOURCE,'guestGeneration':generation,'evidenceSha256':evidence,'state':state}

def _matches(record: Mapping[str,Any],descriptor: tuple[str,str,int,int,str]) -> bool:
    return record.get('guestGeneration')==stale._evidence(descriptor)[0] and record.get('evidenceSha256')==stale._evidence(descriptor)[1]

def _safe_proof(root: Path) -> bool:
    value=stale.diagnose(root,{'host':'archlinux'})
    return value=={'state':'diagnosed','category':'safe-proven','replayAllowed':False,'nativeActionAllowed':False}

def _guest_absent(config: Any,descriptor: tuple[str,str,int,int,str]) -> bool:
    _env,socket,pid,ticks,_sid=descriptor
    try:
        raw=base._remote(config,_REMOTE_STATUS,(socket,str(pid),str(ticks)),None,60);value=json.loads(raw) if raw is not None else {}
        return isinstance(value,dict) and set(value)=={'version','state'} and value.get('version')==1 and value.get('state')=='absent'
    except (TypeError,ValueError,KeyError): return False

def _liveness_absent(root: Path) -> bool:
    value=liveness.observe(root,{'host':'archlinux'})
    return (value.get('state')=='absent' and value.get('sourceSha')==stale._SOURCE and value.get('correlationId')==stale._CORRELATION
            and all(value.get(key)=='none' for key in ('ownerProcesses','installerProcesses','consentProcesses','runtimeProcesses'))
            and value.get('stateLeaves')=='none' and value.get('runtimeOff') is True and value.get('replayAllowed') is False and value.get('nativeActionAllowed') is False)

def status(root: Path|str,inputs: Mapping[str,Any]) -> dict[str,Any]:
    """Read-only exact terminal proof; inaccessible paths remain unknown."""
    if not isinstance(inputs,Mapping) or dict(inputs)!={'host':'archlinux'}: raise WindowsMsiStaleLockReconcileError('Exact CP117 host is required.')
    try:
        root=Path(root).resolve(strict=True); admitted=_admit(root)
        if admitted is None: return dict(_UNKNOWN)
        config,descriptor,_cli=admitted; record=_read(root)
        if record is None or not _matches(record,descriptor): return dict(_UNKNOWN)
        if not _guest_absent(config,descriptor) or not _liveness_absent(root): return dict(_UNKNOWN)
        return {'state':'terminal-proven','replayAllowed':False,'nativeActionAllowed':False}
    except (OSError,ValueError,TypeError,KeyError,WindowsMsiStaleLockReconcileError): return dict(_UNKNOWN)

def close(root: Path|str,inputs: Mapping[str,Any]) -> dict[str,Any]:
    """Durably close only a fresh read-only terminal proof; never retries deletion."""
    try:
        root=Path(root).resolve(strict=True); admitted=_admit(root)
        if admitted is None or status(root,inputs).get('state')!='terminal-proven': return dict(_UNKNOWN)
        _config,descriptor,_cli=admitted; record=_read(root)
        if record is None or not _matches(record,descriptor): return dict(_UNKNOWN)
        if record['state']=='recovered': return {'state':'recovered','replayAllowed':False,'nativeActionAllowed':False}
        done=_record(descriptor,'recovered'); _write(root,done,replace=True)
        return {'state':'recovered','replayAllowed':False,'nativeActionAllowed':False}
    except (OSError,ValueError,TypeError,KeyError,WindowsMsiStaleLockReconcileError): return dict(_UNKNOWN)

def reconcile(root: Path|str,inputs: Mapping[str,Any]) -> dict[str,Any]:
    """Run the new one-shot only after exact old intent and safe proof."""
    if not isinstance(inputs,Mapping) or dict(inputs)!={'host':'archlinux'}: raise WindowsMsiStaleLockReconcileError('Exact CP117 host is required.')
    try:
        root=Path(root).resolve(strict=True); admitted=_admit(root)
        if admitted is None: return dict(_UNKNOWN)
        config,descriptor,cli_hash=admitted; prior=_read(root)
        if prior is not None:
            return close(root,inputs) if prior.get('state')=='recovered' else dict(_UNKNOWN)
        if not _safe_proof(root): return dict(_UNKNOWN)
        _write(root,_record(descriptor,'intent'))
        # Reuses the reviewed typed uint32, exclusive same-handle guest removal.
        if stale._run(config,descriptor,cli_hash,'remove')!='removed': return dict(_UNKNOWN)
        return close(root,inputs)
    except (OSError,ValueError,TypeError,KeyError,WindowsMsiStaleLockReconcileError): return dict(_UNKNOWN)

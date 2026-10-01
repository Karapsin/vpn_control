"""Third, separately correlated read-only CP117 public-status observation.

It neither closes nor recovers either earlier unknown one-shot.  It may only
create its own fixed original-user task after all three fixed task names are
absent and the live read-only admission remains exact.
"""
from __future__ import annotations
import fcntl, hashlib, json, os, stat
from pathlib import Path
from typing import Any, Mapping
from . import windows_msi_owner_public_status as first
from . import windows_msi_owner_public_status_retry as retry

class WindowsMsiOwnerPublicStatusThirdError(ValueError): pass
_CORRELATION='3a7b048d-aec4-4f07-845c-86677dd90f9';_GROUP='.rag_index/windows-msi-owner-public-status-third'
_REQUEST={'host':'archlinux','correlationId':_CORRELATION,'sourceSha':first.relaunch._SOURCE,'taskName':first._THIRD_TASK,'operation':'read-only-public-status'}
_REQUEST_SHA256=hashlib.sha256(json.dumps(_REQUEST,sort_keys=True,separators=(',',':')).encode()).hexdigest()
_UNKNOWN={'state':'unknown','replayAllowed':False,'nativeActionAllowed':False}

_ACTIVE_REMOTE=first.base._QGA+r'''import time
sock,pid,ticks,sid=sys.argv[1:]
def ps(x):return base64.b64encode(x.encode('utf-16le')).decode()
def out(x):print(json.dumps(x,separators=(',',':'),sort_keys=True))
try:
 if not live(sock,pid,ticks):raise ValueError()
 script="""$ErrorActionPreference='Stop';try{$n=0;foreach($x in @(Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\" -ErrorAction Stop)){if($x.SessionId -eq 1 -and $x.CommandLine -like '*-NoProfile -NonInteractive -EncodedCommand*'){$o=Invoke-CimMethod -InputObject $x -MethodName GetOwnerSid -ErrorAction Stop;if($o.ReturnValue -eq 0 -and $o.Sid -ceq '__SID__'){$n++}}};$v=if($n -eq 0){'none'}elseif($n -le 16){'present'}else{'ambiguous'};[Console]::Out.WriteLine((@{version=1;active=$v}|ConvertTo-Json -Compress))}catch{[Console]::Out.WriteLine('{\"version\":1,\"active\":\"ambiguous\"}')}""".replace('__SID__',sid)
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',ps(script)],'capture-output':True}).get('pid')
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(160):
  seen=call(sock,'guest-exec-status',{'pid':child})
  if seen.get('exited') is True:break
  if seen.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 if seen.get('exitcode')!=0 or seen.get('out-truncated') is True:raise ValueError()
 raw=base64.b64decode(seen.get('out-data',''),validate=True);lines=[x for x in decode(raw).splitlines() if x.startswith('{') and x.endswith('}')]
 if len(lines)!=1:raise ValueError()
 value=json.loads(lines[0])
 if not isinstance(value,dict) or set(value)!={'version','active'} or value.get('version')!=1 or value.get('active') not in {'none','present','ambiguous'}:raise ValueError()
 out(value)
except Exception:out({'version':1,'active':'ambiguous'})
'''

def _directory(root:Path,create:bool)->Path:
 p=root/_GROUP
 if create:p.mkdir(mode=0o700,parents=True,exist_ok=True)
 i=p.lstat()
 if not stat.S_ISDIR(i.st_mode) or p.is_symlink() or i.st_uid!=os.getuid() or stat.S_IMODE(i.st_mode)!=0o700:raise WindowsMsiOwnerPublicStatusThirdError('Unsafe third journal.')
 return p
def _path(root:Path,create:bool)->Path:return _directory(root,create)/(_CORRELATION+'.json')
def _read(root:Path)->dict|None:
 try:p=_path(root,False)
 except FileNotFoundError:return None
 try:fd=os.open(p,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 except FileNotFoundError:return None
 with os.fdopen(fd,'rb') as s:
  i=os.fstat(s.fileno())
  if not stat.S_ISREG(i.st_mode) or i.st_uid!=os.getuid() or stat.S_IMODE(i.st_mode)!=0o600 or i.st_size>4096:raise WindowsMsiOwnerPublicStatusThirdError('Unsafe third journal.')
  raw=s.read()
 try:v=json.loads(raw)
 except (TypeError,ValueError):raise WindowsMsiOwnerPublicStatusThirdError('Invalid third journal.')
 fields={'version','correlationId','idempotencyKey','requestSha256','sourceSha','guestGeneration','evidenceSha256','state'}
 if not isinstance(v,dict) or set(v)!=fields or v.get('version')!=1 or v.get('correlationId')!=_CORRELATION or v.get('idempotencyKey')!=_CORRELATION or v.get('requestSha256')!=_REQUEST_SHA256 or v.get('sourceSha')!=first.relaunch._SOURCE or v.get('state')!='intent':raise WindowsMsiOwnerPublicStatusThirdError('Invalid third journal.')
 return v
def _write(root:Path,v:dict)->None:
 d=_directory(root,True);p=_path(root,True);lock=os.open(d/'.lock',os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
 try:
  fcntl.flock(lock,fcntl.LOCK_EX)
  if _read(root) is not None:raise WindowsMsiOwnerPublicStatusThirdError('Third intent exists.')
  fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  with os.fdopen(fd,'wb') as s:s.write((json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode());s.flush();os.fsync(s.fileno())
  parent=os.open(d,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
  try:os.fsync(parent)
  finally:os.close(parent)
 finally:os.close(lock)
def _active(config:Any,desc:tuple[str,str,int,int,str])->str|None:
 raw=first.base._remote(config,_ACTIVE_REMOTE,(desc[1],str(desc[2]),str(desc[3]),desc[4]),None,60)
 try:v=json.loads(raw) if raw else {}
 except (TypeError,ValueError):return None
 return v.get('active') if isinstance(v,dict) and set(v)=={'version','active'} and v.get('version')==1 and v.get('active') in {'none','present','ambiguous'} else None
def _admit(root:Path,for_start:bool=False):
 a=first._admit(root)
 old=first.diagnose(root,{'host':'archlinux'})
 if a is None or old!={'state':'diagnosed','phase':'task','task':'absent','replayAllowed':False,'nativeActionAllowed':False}:return None
 config,desc,hash_,gen,evidence=a
 if first._diagnostic_named(config,desc,hash_,first._RETRY_TASK)!={'phase':'task','task':'absent'}:return None
 if for_start and first._diagnostic_named(config,desc,hash_,first._THIRD_TASK)!={'phase':'task','task':'absent'}:return None
 if for_start and (retry._preflight(config,desc)!={'state':'ready','gate':'ready'} or _active(config,desc)!='none'):return None
 return config,desc,hash_,gen,evidence
def start(root:Path|str,inputs:Mapping[str,Any])->dict:
 if not isinstance(inputs,Mapping) or dict(inputs)!={'host':'archlinux'}:raise WindowsMsiOwnerPublicStatusThirdError('Exact CP117 host required.')
 try:
  root=Path(root).resolve()
  if _read(root) is not None:return status(root,inputs)
  a=_admit(root,for_start=True)
  if a is None:return dict(_UNKNOWN)
  config,desc,hash_,gen,evidence=a;_write(root,{'version':1,'correlationId':_CORRELATION,'idempotencyKey':_CORRELATION,'requestSha256':_REQUEST_SHA256,'sourceSha':first.relaunch._SOURCE,'guestGeneration':gen,'evidenceSha256':evidence,'state':'intent'})
  return status(root,inputs) if first._run_named(config,desc,hash_,'start',first._THIRD_TASK)=='submitted' else dict(_UNKNOWN)
 except (OSError,ValueError,TypeError,KeyError,WindowsMsiOwnerPublicStatusThirdError):return dict(_UNKNOWN)
def status(root:Path|str,inputs:Mapping[str,Any])->dict:
 if not isinstance(inputs,Mapping) or dict(inputs)!={'host':'archlinux'}:raise WindowsMsiOwnerPublicStatusThirdError('Exact CP117 host required.')
 try:
  root=Path(root).resolve();a=_admit(root);r=_read(root)
  if a is None or r is None:return dict(_UNKNOWN)
  config,desc,hash_,gen,evidence=a
  if r.get('guestGeneration')!=gen or r.get('evidenceSha256')!=evidence:return dict(_UNKNOWN)
  v=first._run_named(config,desc,hash_,'status',first._THIRD_TASK)
  if v=='proved':return {'state':'proved','runtimeRunning':False,'replayAllowed':False,'nativeActionAllowed':False}
  return {'state':'pending','replayAllowed':False,'nativeActionAllowed':False} if v=='pending' else dict(_UNKNOWN)
 except (OSError,ValueError,TypeError,KeyError,WindowsMsiOwnerPublicStatusThirdError):return dict(_UNKNOWN)
def collect(root:Path|str,inputs:Mapping[str,Any])->dict:return status(root,inputs)

def _observer_admit(root: Path):
 """Bind a task-only observer without reapplying live owner admission.

 The one-shot already has a durable intent.  An owner-process census can drift
 after that submission, so it is not evidence that the existing task may be
 retried.  This binding deliberately uses only the source-bound base record,
 the relaunch generation receipt, and this third attempt's fixed request.
 """
 record = _read(root)
 if record is None:
  return None, 'third-intent'
 admitted = first.relaunch.liveness._admit(root)
 if admitted is None:
  return None, 'base-binding'
 config, desc, source, cli_hash = admitted
 if source != first.relaunch._SOURCE or not first.relaunch._SHA256.fullmatch(str(cli_hash)):
  return None, 'source-hash'
 launch = first.relaunch._read_intent(root)
 if not isinstance(launch, dict):
  return None, 'relaunch-intent'
 generation = {'socketPath': desc[1], 'qemuPid': desc[2], 'startTicks': desc[3]}
 evidence = hashlib.sha256(json.dumps(generation, sort_keys=True).encode()).hexdigest()
 if (launch.get('sourceSha') != source or launch.get('guestGeneration') != generation
     or launch.get('staleRecoveryEvidenceSha256') != evidence
     or record.get('sourceSha') != source or record.get('guestGeneration') != generation
     or record.get('evidenceSha256') != evidence):
  return None, 'generation'
 return (config, desc, cli_hash), 'task-observer'

def third_diagnostic(root: Path | str, inputs: Mapping[str, Any]) -> dict:
 """Observe the fixed third task after response loss; never submit it again."""
 if not isinstance(inputs, Mapping) or dict(inputs) != {'host': 'archlinux'}:
  raise WindowsMsiOwnerPublicStatusThirdError('Exact CP117 host required.')
 try:
  root = Path(root).resolve()
  bound, stage = _observer_admit(root)
  if bound is None:
   return {'state': 'blocked', 'stage': stage, 'replayAllowed': False, 'nativeActionAllowed': False}
  found = first._diagnostic_named(*bound, first._THIRD_TASK)
  if found is None:
   return {'state': 'unknown', 'stage': 'task-observer', 'replayAllowed': False, 'nativeActionAllowed': False}
  return {'state': 'diagnosed', 'stage': 'task-observer', **found,
          'replayAllowed': False, 'nativeActionAllowed': False}
 except (OSError, ValueError, TypeError, KeyError, WindowsMsiOwnerPublicStatusThirdError):
  return {'state': 'unknown', 'stage': 'task-observer', 'replayAllowed': False, 'nativeActionAllowed': False}

def workflow(root:Path|str,action:str,inputs:Mapping[str,Any])->dict:
 if action=='start':return start(root,inputs)
 if action in {'status','collect'}:return status(root,inputs)
 if action=='third-diagnostic':return third_diagnostic(root,inputs)
 raise WindowsMsiOwnerPublicStatusThirdError('Unsupported third action.')

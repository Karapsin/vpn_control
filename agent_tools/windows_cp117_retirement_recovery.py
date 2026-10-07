"""One-shot recovery for CP117's result-only staged-fixture retirement remnant."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from . import windows_cp117_retirement_guards as guards
from . import windows_cp117_staged_fixture_retire as retire
from . import windows_cp117_guest_agent_recovery as guest_agent_recovery
from . import windows_cp117_guest_agent_recovery_successor as service_successor
from . import windows_cp117_protected_journal as protected_journal


class RetirementRecoveryError(ValueError): pass


_DIR = ".rag_index/windows-cp117-retirement-recovery"
_RECOVERY = "f72ecafe-1890-4e17-a954-1d045dfa0ea3"
_UNKNOWN = {"state":"unknown","replayAllowed":False,"nativeActionAllowed":False,"productAction":False}

_REMOTE = retire.base._QGA + r'''import base64,json,sys,time
sock,pid,ticks,encoded=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if not live(sock,pid,ticks):raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 for _ in range(80):
  item=call(sock,'guest-exec-status',{'pid':child})
  if item.get('exited') is True:break
  if item.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 if item.get('exitcode')!=0 or item.get('out-truncated',False) or item.get('err-truncated',False):raise ValueError()
 value=json.loads(decode(base64.b64decode(item.get('out-data',''),validate=True)))
 out({'state':'observed','receipt':value})
except Exception:out({'state':'unknown'})
'''

_REMOTE_DELETE = retire.base._QGA + r'''import base64,json,os,stat,sys,time
root,env,recovery,sock,pid,ticks,action,expected,encoded,reader=sys.argv[1:];expected=json.loads(expected)
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
def write(path,v,create=False):
 raw=json.dumps(v,sort_keys=True,separators=(',',':')).encode()
 if len(raw)<2 or len(raw)>16384:raise ValueError()
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 dfd=os.open(os.path.dirname(path),os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0));os.fsync(dfd);os.close(dfd)
def safe_dir(path):
 i=os.lstat(path)
 if not stat.S_ISDIR(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o700:raise ValueError()
def mkdir(path,parent):
 try:os.mkdir(path,0o700)
 except FileExistsError:pass
 safe_dir(path);fd=os.open(parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0));os.fsync(fd);os.close(fd)
try:
 if not live(sock,pid,ticks):raise ValueError()
 safe_dir(root)
 envdir=os.path.join(root,env);mkdir(envdir,root)
 parent=os.path.join(envdir,'windows-cp117-result-retirement-recovery')
 mkdir(parent,envdir);d=os.path.join(parent,recovery);mkdir(d,parent)
 if expected.get('recoveryCorrelationId')!=recovery or expected.get('actionSha256')!=action or expected.get('environment')!=env:raise ValueError()
 write(os.path.join(d,'binding.json'),expected,True)
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child)is not int or child<=0:raise ValueError()
 write(os.path.join(d,'child.json'),{'recoveryCorrelationId':recovery,'childPid':child,'socketPath':sock,'qemuPid':int(pid),'startTicks':int(ticks)},True)
 for _ in range(120):
  s=call(sock,'guest-exec-status',{'pid':child})
  if s.get('exited') is True:break
  if s.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:out({'state':'unknown'});raise SystemExit()
 reader_child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',reader],'capture-output':True})['pid']
 for _ in range(80):
  r=call(sock,'guest-exec-status',{'pid':reader_child})
  if r.get('exited') is True:break
  if r.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:out({'state':'unknown'});raise SystemExit()
 if r.get('exitcode')!=0:out({'state':'unknown'});raise SystemExit()
 terminal=json.loads(decode(base64.b64decode(r.get('out-data',''),validate=True)))
 if s.get('exitcode')!=0 or terminal!={'recoveryCorrelationId':recovery,'state':'removed','childPid':child,'qemuPid':int(pid),'startTicks':int(ticks),'actionSha256':action,'intentSha256':expected['intentSha256']}:out({'state':'unknown'});raise SystemExit()
 write(os.path.join(d,'terminal.json'),{'recoveryCorrelationId':recovery,'state':'removed','childPid':child,'actionSha256':action,'intentSha256':expected['intentSha256']},True)
 out({'state':'terminal'})
except Exception:out({'state':'unknown'})
'''

def _read(path: Path) -> dict[str, Any] | None: return guards.secure_read(path)

def _admitted(root: Path):
    admitted = retire._admitted(root)
    if admitted is None: return None
    intent, active, descriptor = admitted
    return intent, active, descriptor

def _census(root: Path, intent: Mapping[str, Any], descriptor: tuple[Any,...]) -> bool:
    try:
        script=guest_agent_recovery._launcher(guards.remaining_result_census_powershell(intent,retire._STAGE,descriptor[4]))
        raw=retire.base._remote(retire.base._descriptor(root)[0],_REMOTE,(descriptor[1],str(descriptor[2]),str(descriptor[3]),base64.b64encode(guest_agent_recovery._launcher(script).encode('utf-16le')).decode()),None,30)
        value=json.loads(raw) if raw else {}
        if value.get('state')!='observed': return False
        guards.validate_remaining_result_census(value.get('receipt'),retire._STAGE,descriptor[4]); return True
    except (OSError,ValueError,TypeError,KeyError,guards.RetirementGuardError): return False

def _service_terminal(root: Path, descriptor: tuple[Any,...]) -> bool:
    """Require the peer's fresh protected remote task observer.

    This consumes only its public terminal state.  The peer verifies the
    SYSTEM task, action digest, protected binding and restarted service before
    publishing that state; a local receipt alone is never sufficient here.
    """
    try:
        observed=service_successor.status(root,{})
        return isinstance(observed,dict) and observed.get("state")=="terminal"
    except (OSError,ValueError,TypeError,KeyError):
        return False

def _deletion_plan(intent: Mapping[str,Any], descriptor: tuple[Any,...]) -> tuple[str, str]:
    """Return the immutable guest action and its UTF-16LE digest.

    The digest deliberately covers the census and deletion together.  It is
    placed in the host binding before guest-exec, so a timeout has an
    observable, non-replayable action identity.
    """
    census=guards.remaining_result_census_powershell(intent,retire._STAGE,descriptor[4])
    census=census.replace("|ConvertTo-Json -Compress -Depth 4", "|Out-Null")
    journal=protected_journal.powershell(_guest_journal_root(),["terminal.json"])
    template=census+";"+journal+("; $r='"+guards.stage_root(retire._STAGE)+"';$f=Join-Path $r 'result.json';$n=@(Get-ChildItem -LiteralPath $r -Force -ErrorAction Stop);if($n.Count -ne 1 -or $n[0].Name -cne 'result.json'){throw 'TREE'};$p=(Get-Process -Id $PID).Id;Initialize-SecureJournal;Remove-Item -LiteralPath $f -Force -ErrorAction Stop;Remove-Item -LiteralPath $r -Force -ErrorAction Stop;if(Test-Path -LiteralPath $r){throw 'PRESENT'};$j=@{recoveryCorrelationId='"+_RECOVERY+"';state='removed';childPid=$p;qemuPid="+str(descriptor[2])+";startTicks="+str(descriptor[3])+";actionSha256='@ACTION@';intentSha256='@INTENT@'}|ConvertTo-Json -Compress;Write-SecureJsonCreate 'terminal.json' $j")
    # The submitted script carries its canonical action digest.  Hashing the
    # marker form avoids a self-referential value while still binding every
    # executable byte and both durable terminal fields.
    action=hashlib.sha256(template.replace('@ACTION@','').replace('@INTENT@','').encode('utf-16le')).hexdigest()
    binding=_binding(descriptor,action)
    return template.replace('@ACTION@',action).replace('@INTENT@',binding['intentSha256']),action

def _guest_journal_root() -> str:
    return r"C:\ProgramData\VpnControlCp117-retirement-"+_RECOVERY

def _guest_terminal_reader() -> str:
    return protected_journal.powershell(_guest_journal_root(),["terminal.json"])+";$nodes=@(Get-ChildItem -LiteralPath $JournalRoot -Force -ErrorAction Stop);if($nodes.Count -ne 1 -or $nodes[0].Name -cne 'terminal.json'){throw 'LEAVES'};Read-SecureJson 'terminal.json'|ConvertTo-Json -Compress -Depth 4"

def _binding(descriptor: tuple[Any,...], action: str) -> dict[str, Any]:
    value={"recoveryCorrelationId":_RECOVERY,"environment":descriptor[0],"socketPath":descriptor[1],"qemuPid":descriptor[2],"startTicks":descriptor[3],"sid":descriptor[4],"actionSha256":action}
    return {**value,"intentSha256":hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()}

def _remove_result(root: Path, intent: Mapping[str,Any], descriptor: tuple[Any,...], action: str) -> bool:
    """Dispatch the immutable action once; the remote journal survives loss."""
    script, computed=_deletion_plan(intent,descriptor)
    if computed!=action: return False
    try:
        config,target,_=retire.base._descriptor(root)
        reader=base64.b64encode(guest_agent_recovery._launcher(_guest_terminal_reader()).encode('utf-16le')).decode()
        raw=retire.base._remote(config,_REMOTE_DELETE,(str(target.fixture_transfer_root),descriptor[0],_RECOVERY,descriptor[1],str(descriptor[2]),str(descriptor[3]),action,json.dumps(_binding(descriptor,action),sort_keys=True,separators=(',',':')),base64.b64encode(guest_agent_recovery._launcher(script).encode('utf-16le')).decode(),reader),None,120)
        return json.loads(raw)=={"state":"terminal"}
    except (OSError,ValueError,TypeError,KeyError): return False

def _root_absent(root: Path, descriptor: tuple[Any,...]) -> bool:
    script="$r='"+guards.stage_root(retire._STAGE)+"';[Console]::Out.WriteLine((@{absent=(-not (Test-Path -LiteralPath $r))}|ConvertTo-Json -Compress))"
    try:
        raw=retire.base._remote(retire.base._descriptor(root)[0],_REMOTE,(descriptor[1],str(descriptor[2]),str(descriptor[3]),base64.b64encode(guest_agent_recovery._launcher(script).encode('utf-16le')).decode()),None,30)
        return json.loads(raw)=={"state":"observed","receipt":{"absent":True}}
    except (OSError,ValueError,TypeError,KeyError): return False

def _remote_observation(root: Path, descriptor: tuple[Any,...], action: str) -> str | None:
    """Read only the recovery journal that survives deletion of the guest root."""
    try:
        config,target,_=retire.base._descriptor(root)
        program="""import json,os,stat,sys
r,e,c,expected=sys.argv[1:];expected=json.loads(expected);d=os.path.join(r,e,'windows-cp117-result-retirement-recovery',c);p=os.path.join(d,'terminal.json')
try:
 for q in (r,os.path.join(r,e),os.path.join(r,e,'windows-cp117-result-retirement-recovery'),d):
  i=os.lstat(q)
  if not stat.S_ISDIR(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o700:raise ValueError()
 def load(q):
  i=os.lstat(q)
  if not stat.S_ISREG(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o600 or i.st_size<2 or i.st_size>16384:raise ValueError()
  fd=os.open(q,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0));return json.load(os.fdopen(fd))
 names=sorted(os.listdir(d));cp=os.path.join(d,'child.json');tp=os.path.join(d,'terminal.json');has_child=os.path.exists(cp);has_terminal=os.path.exists(tp)
 if names not in (['binding.json'],['binding.json','child.json'],['binding.json','child.json','terminal.json']):raise ValueError()
 b=load(os.path.join(d,'binding.json'))
 if has_child:
  child=load(cp);ok=b==expected and child.get('recoveryCorrelationId')==c and child.get('socketPath')==expected['socketPath'] and child.get('qemuPid')==expected['qemuPid'] and child.get('startTicks')==expected['startTicks'] and type(child.get('childPid')) is int and child['childPid']>0
  if has_terminal:
   v=load(tp);ok=ok and v=={'recoveryCorrelationId':c,'state':'removed','childPid':child['childPid'],'actionSha256':expected['actionSha256'],'intentSha256':expected['intentSha256']}
 else:ok=b==expected
 print(json.dumps({'state':('terminal' if has_terminal else 'after-delete')} if ok else {'state':'unknown'}))
except Exception:print('{\"state\":\"unknown\"}')"""
        raw=retire.base._remote(config,program,(str(target.fixture_transfer_root),descriptor[0],_RECOVERY,json.dumps(_binding(descriptor,action),sort_keys=True,separators=(',',':'))),None,30)
        host=json.loads(raw)
        if host=={"state":"after-delete"}: return "after-delete"
        if host!={"state":"terminal"}: return None
        reader=base64.b64encode(guest_agent_recovery._launcher(_guest_terminal_reader()).encode('utf-16le')).decode()
        guest=retire.base._remote(config,_REMOTE,(descriptor[1],str(descriptor[2]),str(descriptor[3]),reader),None,30)
        expected={"recoveryCorrelationId":_RECOVERY,"state":"removed","qemuPid":descriptor[2],"startTicks":descriptor[3],"actionSha256":action,"intentSha256":_binding(descriptor,action)["intentSha256"]}
        value=json.loads(guest) if guest else {}
        receipt=value.get("receipt") if value.get("state")=="observed" else None
        return "terminal" if isinstance(receipt,dict) and set(receipt)=={"recoveryCorrelationId","state","childPid","qemuPid","startTicks","actionSha256","intentSha256"} and type(receipt.get("childPid")) is int and receipt["childPid"]>0 and all(receipt.get(key)==item for key,item in expected.items()) else None
    except (OSError,ValueError,TypeError,KeyError):return None

def _remote_terminal(root: Path, descriptor: tuple[Any,...], action: str) -> bool:
    return _remote_observation(root,descriptor,action)=="terminal"

def _parse_sources(root: Path, intent: Mapping[str,Any], descriptor: tuple[Any,...]) -> bool:
    action,_digest=_deletion_plan(intent,descriptor)
    sources=(action,_guest_terminal_reader(),guards.remaining_result_census_powershell(intent,retire._STAGE,descriptor[4]))
    config=retire.base._descriptor(root)[0]
    for source in sources:
        packed=base64.b64encode(source.encode('utf-16le')).decode()
        script="$s=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('"+packed+"'));$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseInput($s,[ref]$t,[ref]$e);[Console]::Out.WriteLine((@{valid=($e.Count -eq 0)}|ConvertTo-Json -Compress))"
        if guest_agent_recovery._run_ps(config,descriptor,script)!={"valid":True}:return False
    return True

def parser(root:Path|str,value:Mapping[str,Any])->dict[str,Any]:
    if value!={}:raise RetirementRecoveryError('fixed parser takes no inputs')
    path=Path(root).resolve(strict=True)
    try:
        admitted=_admitted(path)
        if admitted is None:return {**_UNKNOWN,'state':'blocked','phase':'binding'}
        valid=_parse_sources(path,admitted[0],admitted[2])
        return {**_UNKNOWN,'state':'passed' if valid else 'blocked','phase':'parser'}
    except (OSError,ValueError,KeyError,TypeError):return {**_UNKNOWN,'state':'blocked','phase':'parser'}


def preflight(root: Path|str, value: Mapping[str,Any]) -> dict[str,Any]:
    if value!={}: raise RetirementRecoveryError("Fixed recovery takes no inputs.")
    path=Path(root).resolve(strict=True); admitted=_admitted(path)
    if admitted is None:return {**_UNKNOWN,"state":"blocked","reason":"admission"}
    intent,_active,descriptor=admitted
    if not retire._recovery_fresh(path,intent,descriptor):return {**_UNKNOWN,"state":"blocked","phase":"fresh"}
    if not _service_terminal(path,descriptor):return {**_UNKNOWN,"state":"blocked","phase":"service"}
    if not _census(path,intent,descriptor):return {**_UNKNOWN,"state":"blocked","phase":"census"}
    return {**_UNKNOWN,"state":"ready","stageCorrelationId":retire._STAGE,"leaseId":retire._LEASE}

def start(root: Path|str,value:Mapping[str,Any])->dict[str,Any]:
    if value!={}: raise RetirementRecoveryError("Fixed recovery takes no inputs.")
    path=Path(root).resolve(strict=True)
    if preflight(path,{})["state"]!="ready": return {**_UNKNOWN,"state":"blocked"}
    journal=guards.secure_directory(path/_DIR)
    if _read(journal/"intent.json") is not None:return dict(_UNKNOWN)
    admitted=_admitted(path)
    if admitted is None:return dict(_UNKNOWN)
    intent,active,descriptor=admitted
    if not retire._recovery_fresh(path,intent,descriptor) or not _service_terminal(path,descriptor) or not _census(path,intent,descriptor):return dict(_UNKNOWN)
    if not _parse_sources(path,intent,descriptor):return {**_UNKNOWN,"state":"blocked","phase":"parser"}
    _script,action=_deletion_plan(intent,descriptor)
    # This durable record is intentionally written before guest-exec.  A lost
    # reply consumes the one shot and status can only observe its journal.
    guards.secure_write_create(journal/"intent.json",{"stageCorrelationId":retire._STAGE,"leaseId":retire._LEASE,"recoveryCorrelationId":_RECOVERY,"recovery":"result-only","binding":_binding(descriptor,action)})
    if not _remove_result(path,intent,descriptor,action):return dict(_UNKNOWN)
    # Root absence is a distinct post-mutation fact; recovery_fresh retains
    # durable admission and idle-product checks without asserting the old root.
    if not _root_absent(path,descriptor):return dict(_UNKNOWN)
    # The remote terminal is deliberately outside the deleted stage root.
    if not _remote_terminal(path,descriptor,action):return dict(_UNKNOWN)
    guards.secure_write_create(journal/"guest-terminal.json",{"stageCorrelationId":retire._STAGE,"state":"removed"})
    return finish(path,{})

def finish(root: Path|str,value:Mapping[str,Any])->dict[str,Any]:
    """Complete host cleanup after an already-observed guest terminal.

    Every host side effect has its own durable submission record.  In
    particular a failure after lease-close submission is observation-only.
    """
    if value!={}: raise RetirementRecoveryError("Fixed recovery takes no inputs.")
    path=Path(root).resolve(strict=True);journal=guards.secure_directory(path/_DIR)
    local=_read(journal/"intent.json")
    if not isinstance(local,dict) or not isinstance(local.get("binding"),dict): return {**_UNKNOWN,"state":"not-started"}
    admitted=_admitted(path)
    if admitted is None:return dict(_UNKNOWN)
    intent,active,descriptor=admitted
    _script,action=_deletion_plan(intent,descriptor)
    if local.get("binding")!=_binding(descriptor,action):return dict(_UNKNOWN)
    if not _remote_terminal(path,descriptor,action) or not _root_absent(path,descriptor):return dict(_UNKNOWN)
    if _read(journal/"guest-terminal.json") is None:
        guards.secure_write_create(journal/"guest-terminal.json",{"stageCorrelationId":retire._STAGE,"state":"removed"})
    if _read(journal/"host-remove-intent.json") is None:
        guards.secure_write_create(journal/"host-remove-intent.json",{"stageCorrelationId":retire._STAGE,"action":"remove-host"})
        if not retire._remove_host(path):return dict(_UNKNOWN)
        guards.secure_write_create(journal/"host-removed.json",{"stageCorrelationId":retire._STAGE,"state":"removed"})
    if _read(journal/"host-removed.json") is None:return dict(_UNKNOWN)
    receipt={"stageCorrelationId":retire._STAGE,"leaseId":retire._LEASE,"removed":True}
    if _read(path/retire._DIR/"receipt.json") is None: guards.secure_write_create(path/retire._DIR/"receipt.json",receipt)
    elif _read(path/retire._DIR/"receipt.json")!=receipt:return dict(_UNKNOWN)
    if _read(journal/"lease-close-intent.json") is None:
        guards.secure_write_create(journal/"lease-close-intent.json",{"stageCorrelationId":retire._STAGE,"leaseId":retire._LEASE,"action":"close-lease"})
        if not retire._close(path,active,descriptor):return dict(_UNKNOWN)
    observed=retire.status(path,{})
    return observed if observed.get("state")=="retired" else dict(_UNKNOWN)

def status(root:Path|str,value:Mapping[str,Any])->dict[str,Any]:
    if value!={}:raise RetirementRecoveryError("Fixed recovery takes no inputs.")
    path=Path(root).resolve(strict=True)
    if _read(path/_DIR/"intent.json") is None:return {**_UNKNOWN,"state":"not-started"}
    local=_read(path/_DIR/"intent.json")
    receipt=_read(path/retire._DIR/"receipt.json")
    if receipt=={"stageCorrelationId":retire._STAGE,"leaseId":retire._LEASE,"removed":True}:
        observed=retire.status(path,{})
        return observed if observed.get("state")=="retired" else dict(_UNKNOWN)
    admitted=_admitted(path)
    if isinstance(local,dict) and isinstance(local.get("binding"),dict) and admitted is not None:
        intent,_active,descriptor=admitted
        _script,action=_deletion_plan(intent,descriptor)
        if local["binding"]==_binding(descriptor,action) and _root_absent(path,descriptor):
            proof=_remote_observation(path,descriptor,action)
            if receipt is None and proof=="terminal":return {**_UNKNOWN,"state":"guest-terminal","stageCorrelationId":retire._STAGE,"leaseId":retire._LEASE}
            # The operation can die after removing the root and before the
            # truthful guest terminal is create-only written.  Keep that
            # evidence distinct: no replay and no host cleanup may follow it.
            if receipt is None and proof=="after-delete":return {**_UNKNOWN,"state":"after-delete","stageCorrelationId":retire._STAGE,"leaseId":retire._LEASE}
    if receipt=={"stageCorrelationId":retire._STAGE,"leaseId":retire._LEASE,"removed":True}:
        if admitted is not None:
            observed=retire.status(path,{})
            if observed.get("state")=="retired": return observed
    return dict(_UNKNOWN)

def workflow(root:Path|str,action:str,inputs:Mapping[str,Any])->dict[str,Any]:
    if action=="parser":return parser(root,inputs)
    if action=="preflight":return preflight(root,inputs)
    if action=="start":return start(root,inputs)
    if action=="status":return status(root,inputs)
    if action=="finish":return finish(root,inputs)
    raise RetirementRecoveryError("Unknown result-only retirement recovery action.")

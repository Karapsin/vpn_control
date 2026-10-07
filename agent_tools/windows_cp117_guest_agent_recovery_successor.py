"""Fixed successor for the consumed CP117 guest-agent recovery attempt.

The original recovery is historical evidence only.  This module has a new
correlation, journal and task, and cannot invoke the original start route.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping

from . import windows_cp117_guest_agent_recovery as original
from . import windows_cp117_protected_journal as protected_journal
from . import windows_cp117_staged_fixture_retire as retire
from . import windows_cp117_retirement_guards as guards

_RECOVERY = "c2c0e5c9-77aa-4bd2-91a1-fb7540aa9f58"
_DIR = ".rag_index/windows-cp117-guest-agent-recovery-successor"
_ROOT = r"C:\ProgramData\VpnControlCp117-guest-agent-" + _RECOVERY
_TASK = "VpnControlCp117GuestAgentRecovery-" + _RECOVERY
_UNKNOWN = {"state":"unknown","replayAllowed":False,"nativeActionAllowed":False,"productAction":False}

class SuccessorError(ValueError): pass

def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",", ":")).encode()).hexdigest()

def _directory(root: Path) -> Path: return guards.secure_directory(root/_DIR)
def _read(root: Path, name: str): return guards.secure_read(_directory(root)/name)

def _validator() -> str:
    return protected_journal.powershell(_ROOT,("binding.json","child.json","terminal.json")) + "\nfunction AssertJournal([bool]$create){if($create){Initialize-SecureJournal}else{[void](Assert-Root $JournalRoot)}}"

def _body(identity: Mapping[str,Any], digest: str) -> str:
    return original._restart_task_body(identity,digest,_RECOVERY)


def _arguments(identity: Mapping[str,Any], digest: str) -> str:
    return original._task_arguments(identity,digest,_RECOVERY)

def _action(identity: Mapping[str,Any], digest: str) -> str:
    return original._action_sha(identity,digest,_RECOVERY)

def _submit_script(identity: Mapping[str,Any], intent: Mapping[str,Any]) -> str:
    return original._restart_task_script(identity,_digest(intent),_RECOVERY)


def _status_script() -> str:
    return original._remote_status_script(_RECOVERY)


def _old_admissible(root: Path, descriptor: tuple[Any,...], identity: Mapping[str,Any]) -> bool:
    """Accept only the immutable consumed original attempt and no old guest task."""
    intent=guards.secure_read(root/original._DIR/'intent.json');action=guards.secure_read(root/original._DIR/'action.json')
    if not isinstance(intent,dict) or set(intent)!={"recoveryCorrelationId","service","guestGeneration"} or not isinstance(action,dict) or set(action)!={"intentSha256","actionSha256"}: return False
    if not isinstance(action['actionSha256'],str) or not re.fullmatch(r'[0-9a-f]{64}',action['actionSha256']) or intent.get("recoveryCorrelationId")!=original._RECOVERY or action.get("intentSha256")!=original._digest(intent) or intent.get("service")!=identity: return False
    generation=intent.get("guestGeneration")
    if generation!={"socketPath":descriptor[1],"qemuPid":descriptor[2],"startTicks":descriptor[3]}: return False
    # The old protected root must be absent; the old scheduled task must also
    # be absent before a successor is admissible.
    script=("$old="+guards._ps_literal(r"C:\ProgramData\VpnControlCp117-guest-agent-"+original._RECOVERY)+";$task="+guards._ps_literal("VpnControlCp117GuestAgentRecovery-"+original._RECOVERY)+";[Console]::Out.WriteLine((@{rootAbsent=(-not(Test-Path -LiteralPath $old));taskAbsent=(@(Get-ScheduledTask -ErrorAction Stop|Where-Object {$_.TaskName -ceq $task -and $_.TaskPath -ceq '\\'}).Count -eq 0)}|ConvertTo-Json -Compress))")
    config=original.base._descriptor(root)[0];seen=original._run_ps(config,descriptor,script)
    return seen=={"rootAbsent":True,"taskAbsent":True} and guards.secure_read(root/original._DIR/'terminal.json') is None

def _plan(root: Path):
    config,_target,descriptor=original.base._descriptor(root);seen=original._run_ps(config,descriptor,original._service_census_script())
    keys={"name","state","startName","pid","startTicks","path"}
    if not isinstance(seen,dict) or set(seen)!=keys|{"otherPowerShellCount","appCount","taskCount"} or any(seen[k]!=0 for k in ("otherPowerShellCount","appCount","taskCount")): return None
    identity=original._identity({k:seen[k] for k in keys})
    if identity is None:return None
    return config,descriptor,identity,{"recoveryCorrelationId":_RECOVERY,"service":identity,"guestGeneration":{"socketPath":descriptor[1],"qemuPid":descriptor[2],"startTicks":descriptor[3]}}

def preflight(root: Path|str, value: Mapping[str,Any]) -> dict[str,Any]:
    if value!={}:raise SuccessorError("fixed successor takes no inputs")
    path=Path(root).resolve(strict=True)
    try:
        admitted=retire._admitted(path)
        if admitted is None:return {**_UNKNOWN,"state":"blocked","phase":"binding"}
        if not retire._recovery_fresh(path,admitted[0],admitted[2]):return {**_UNKNOWN,"state":"blocked","phase":"fresh"}
        one,two=retire.diagnose_locks(path,{}),retire.diagnose_locks(path,{})
        expected={"cause":"low-hresult-32","lockingProcess":"qemu-ga","count":1,"qemuGaExactLocalSystem":True}
        if any(one.get(k)!=v or two.get(k)!=v for k,v in expected.items()) or one.get('state')!='observed' or two.get('state')!='observed':return {**_UNKNOWN,"state":"blocked","phase":"lock"}
        plan=_plan(path)
        if plan is None:return {**_UNKNOWN,"state":"blocked","phase":"census"}
        if not _old_admissible(path,plan[1],plan[2]):return {**_UNKNOWN,"state":"blocked","phase":"predecessor"}
        if not original._journal_preflight(plan[0],plan[1],_RECOVERY):return {**_UNKNOWN,"state":"blocked","phase":"journal"}
        return {**_UNKNOWN,"state":"ready","recoveryCorrelationId":_RECOVERY}
    except (OSError,ValueError,KeyError,TypeError): return {**_UNKNOWN,"state":"blocked"}

def start(root: Path|str,value:Mapping[str,Any])->dict[str,Any]:
    if value!={}:raise SuccessorError("fixed successor takes no inputs")
    path=Path(root).resolve(strict=True)
    if preflight(path,{}).get("state")!="ready":return {**_UNKNOWN,"state":"blocked"}
    directory=_directory(path)
    if guards.secure_read(directory/'intent.json') is not None:return dict(_UNKNOWN)
    plan=_plan(path)
    if plan is None:return dict(_UNKNOWN)
    config,descriptor,identity,intent=plan
    if not _old_admissible(path,descriptor,identity):return dict(_UNKNOWN)
    if not original._parse_sources(config,descriptor,identity,intent,_RECOVERY):return {**_UNKNOWN,"state":"blocked","phase":"parser"}
    guards.secure_write_create(directory/'intent.json',intent)
    action=_action(identity,_digest(intent));guards.secure_write_create(directory/'action.json',{"intentSha256":_digest(intent),"actionSha256":action})
    observed=original._run_ps(config,descriptor,_submit_script(identity,intent))
    if observed!={"state":"submitted","actionSha256":action}:return dict(_UNKNOWN)
    return {**_UNKNOWN,"state":"submitted","recoveryCorrelationId":_RECOVERY}

def parser(root: Path|str,value:Mapping[str,Any])->dict[str,Any]:
    if value!={}:raise SuccessorError("fixed successor takes no inputs")
    try:
        plan=_plan(Path(root).resolve(strict=True))
        if plan is None:return {**_UNKNOWN,"state":"unknown","phase":"parser"}
        values=original._parse_results(plan[0],plan[1],plan[2],plan[3],_RECOVERY)
        return {**_UNKNOWN,"state":"passed" if all(v=="valid" for v in values.values()) else "diagnosed","phase":"parser","scripts":values,"recoveryCorrelationId":_RECOVERY}
    except (OSError,ValueError,KeyError,TypeError):return {**_UNKNOWN,"state":"unknown","phase":"parser"}

def status(root:Path|str,value:Mapping[str,Any])->dict[str,Any]:
    if value!={}:raise SuccessorError("fixed successor takes no inputs")
    path=Path(root).resolve(strict=True);intent=_read(path,'intent.json');action=_read(path,'action.json')
    if not isinstance(intent,dict) or not isinstance(action,dict) or action.get("intentSha256")!=_digest(intent):return {**_UNKNOWN,"state":"not-started"}
    identity=original._identity(intent.get("service",{}))
    if identity is None or action!={"intentSha256":_digest(intent),"actionSha256":_action(identity,_digest(intent))}:return dict(_UNKNOWN)
    try:
        config,_target,descriptor=original.base._descriptor(path)
        if intent.get("guestGeneration")!={"socketPath":descriptor[1],"qemuPid":descriptor[2],"startTicks":descriptor[3]}:return dict(_UNKNOWN)
        seen=original._run_ps(config,descriptor,_status_script())
        fields={"binding","terminalBinding","outcome","taskSystem","taskState","actionSha256","service","recoveryCorrelationId","childPid","childStartTicks"}
        if (not isinstance(seen,dict) or set(seen)!=fields or seen['binding']!=_digest(intent)
            or seen['terminalBinding']!=_digest(intent) or seen['actionSha256']!=action['actionSha256']
            or seen['outcome']!='restarted' or seen['taskSystem'] is not True or seen['taskState']!='Ready'
            or seen['recoveryCorrelationId']!=_RECOVERY or type(seen['childPid']) is not int or seen['childPid']<=0
            or type(seen['childStartTicks']) is not int or seen['childStartTicks']<=0
            or not original._restarted_identity(identity,seen['service'])):return dict(_UNKNOWN)
        expected={"intentSha256":_digest(intent),"outcome":"restarted"}
        terminal=_read(path,'terminal.json')
        if terminal is None:guards.secure_write_create(_directory(path)/'terminal.json',expected)
        elif terminal!=expected:return dict(_UNKNOWN)
        return {**_UNKNOWN,"state":"terminal","recoveryCorrelationId":_RECOVERY}
    except (OSError,ValueError,TypeError,KeyError):return dict(_UNKNOWN)

def workflow(root:Path|str,action:str,inputs:Mapping[str,Any])->dict[str,Any]:
    if action=="preflight":return preflight(root,inputs)
    if action=="parser":return parser(root,inputs)
    if action=="start":return start(root,inputs)
    if action=="status":return status(root,inputs)
    raise SuccessorError("unknown successor action")

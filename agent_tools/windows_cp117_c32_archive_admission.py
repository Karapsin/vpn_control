"""Fixed read-only admission for archiving CP117's completed c32 base record."""
from __future__ import annotations
from pathlib import Path
from typing import Any, Mapping
import uuid
from . import windows_cp117_campaign_rebase as rebase
from . import windows_cp117_lease as lease
from . import windows_msi_base_prepare as base
from . import windows_update_fixture_stage as stage
from . import windows_update_fixture_stage_recovery as recovery
from . import windows_msi_http_transfer as transfer
from . import windows_msi_public_scenario as public
from . import windows_cp117_c32_absence as absence

_C32="c32cb108-4d48-407e-9153-40774559ba50"
_UNKNOWN={"state":"unknown","replayAllowed":False,"nativeActionAllowed":False,"productAction":False}

def _request(root: Path, new_lease: str) -> dict[str,str] | None:
    if not isinstance(new_lease,str): return None
    try:
        if str(uuid.UUID(new_lease))!=new_lease:return None
    except ValueError:return None
    intent=stage._read_intent(root,recovery._CORRELATION)
    if not isinstance(intent,dict) or intent.get("leaseId")!=_C32:return None
    old=intent.get("request")
    if not isinstance(old,dict):return None
    fields=("sourceSha","fixtureReceiptArtifactId","baseMsiArtifactId","targetMsiArtifactId")
    if any(not isinstance(old.get(k),str) for k in fields):return None
    record=base._private_intent(root,_C32)
    old_base=record.get("request") if isinstance(record,dict) else None
    # Stage and base requests have different procedural fields.  Compare only
    # their authoritative shared artifact/source identity plus c32's baseline.
    if (not isinstance(old_base,dict) or old_base.get("correlationId")!=_C32
            or old_base.get("expectedCurrentVersion")!="2.1.17"
            or any(old_base.get(k)!=old[k] for k in fields)):return None
    return {"host":"archlinux","leaseId":new_lease,"previousLeaseId":_C32,**{k:old[k] for k in fields}}

def diagnose(root: Path|str,value: Mapping[str,Any])->dict[str,Any]:
    """Finite local phase diagnostic; it never contacts guest or remote lease."""
    if not isinstance(value,Mapping) or set(value)!={"leaseId"}:raise ValueError("fixed archive diagnostic requires its new lease only")
    path=Path(root).resolve(strict=True);request=_request(path,value["leaseId"])
    if request is None:return {**_UNKNOWN,"state":"observed","phase":"request"}
    try:
        _config,_target,descriptor=base._descriptor(path)
        try:
            _intent,_pair,terminal,cleanup=rebase._history(path,request,descriptor)
        except Exception:
            return {**_UNKNOWN,"state":"observed","phase":"history"}
        record=transfer._intent(path,_C32)
        bound=transfer._terminal_intent(path,record) if record is not None else None
        if bound!=terminal:return {**_UNKNOWN,"state":"observed","phase":"transfer-binding"}
        directory=transfer._private_dir(path,False)
        dispatch=transfer._read(directory/(_C32+".terminal-cleanup.dispatch.json")) if directory is not None else None
        if dispatch!={"correlationId":_C32,"terminalReceiptSha256":terminal}:
            return {**_UNKNOWN,"state":"observed","phase":"terminal-cleanup-dispatch"}
        return {**_UNKNOWN,"state":"observed","phase":"local-ready","baseTerminalReceiptSha256":terminal,"cleanupReceiptSha256":cleanup}
    except (OSError,ValueError,KeyError,TypeError,base.WindowsMsiBasePrepareError):return {**_UNKNOWN,"state":"unknown"}

def _historical_cleanup_status(root: Path, config: Any, target: Any, descriptor: tuple[Any,...], terminal: str) -> dict[str,Any]:
    """Read c32's terminal status without the current-HEAD transfer admission."""
    record=transfer._intent(root,_C32)
    if not isinstance(record,dict) or record.get("environment")!=descriptor[0] or record.get("socketPath")!=descriptor[1] or record.get("qemuPid")!=descriptor[2] or record.get("startTicks")!=descriptor[3]:return dict(_UNKNOWN)
    intent=base._private_intent(root,_C32)
    request=intent.get("request") if isinstance(intent,dict) else None
    if (not isinstance(request,dict) or request.get("correlationId")!=_C32 or request.get("expectedCurrentVersion")!="2.1.17"
            or record.get("correlationId")!=_C32 or record.get("sourceSha")!=request.get("sourceSha")
            or record.get("baseMsiArtifactId")!=request.get("baseMsiArtifactId") or record.get("expectedSid")!=descriptor[4]):return dict(_UNKNOWN)
    # Registry lookup binds the old package location to its registered source;
    # it deliberately does not compare that source with the current checkout.
    artifact=public._verified_location(root,request["baseMsiArtifactId"],"desktop-package",request["sourceSha"])
    if artifact.resolve(strict=True)!=Path(record["artifactPath"]).resolve(strict=True):return dict(_UNKNOWN)
    directory=transfer._private_dir(root,False)
    if directory is None or transfer._read(directory/(_C32+".terminal-cleanup.dispatch.json"))!={"correlationId":_C32,"terminalReceiptSha256":terminal}:return dict(_UNKNOWN)
    raw=base._remote(config,transfer._REMOTE_TERMINAL_STATUS,transfer._remote_args(record,target.fixture_transfer_root)+(terminal,),None,15)
    return transfer._terminal_result(raw,{"marked","cleaned","unknown"},terminal)

def preflight(root: Path|str,value: Mapping[str,Any])->dict[str,Any]:
    if not isinstance(value,Mapping) or set(value)!={"leaseId"}:raise ValueError("fixed archive admission requires its new lease only")
    path=Path(root).resolve(strict=True)
    phase="request"
    try:
        request=_request(path,value["leaseId"])
        if request is None:return {**_UNKNOWN,"state":"blocked","phase":phase}
        phase="history"
        config,target,descriptor=base._descriptor(path)
        _intent,_pair,terminal,cleanup=rebase._history(path,request,descriptor)
        phase="closed"
        rebase._previous_closed_readonly(path,request,descriptor,config,target,cleanup)
        phase="cleanup"
        cleaned=_historical_cleanup_status(path,config,target,descriptor,terminal)
        if cleaned.get("state")!="cleaned" or cleaned.get("terminalReceiptSha256")!=terminal:
            return {**_UNKNOWN,"state":"blocked","phase":phase}
        phase="host-history"
        host=host_status(path,config,target,descriptor)
        if host.get("state") not in {"absent","retained"}:
            return {**_UNKNOWN,"state":"blocked","phase":phase,**{k:host[k] for k in ("hostFailure","hostKnownMask","hostEntryCount","hostFileMode") if k in host}}
        phase="absence"
        absent=absence.observe(path,config,target,descriptor)
        all_absent=absent.get("state")=="observed" and all(absent.get(k)=="absent" for k in ("baseTask","transferTask","guestLeaf","baseMsi","correlationProcess"))
        retained_candidate=(absent.get("state")=="observed" and absent.get("baseTask")=="present" and absent.get("guestLeaf")=="present"
            and all(absent.get(k)=="absent" for k in ("transferTask","baseMsi","correlationProcess")))
        retained=retained_candidate and absence.retained_terminal(path,config,target,descriptor).get("state")=="retained-terminal"
        post_retired_candidate=(absent.get("state")=="observed" and absent.get("baseTask")=="absent" and absent.get("guestLeaf")=="present"
            and all(absent.get(k)=="absent" for k in ("transferTask","baseMsi","correlationProcess")))
        post_retired=(post_retired_candidate and absence.post_retirement_terminal(path,config,target,descriptor).get("state")=="post-retirement-terminal")
        if not all_absent and not retained and not post_retired:
            fields=("baseTask","transferTask","guestLeaf","baseMsi","correlationProcess")
            census={k:absent[k] for k in fields} if absent.get("state")=="observed" else "unknown"
            diagnostic=absence.diagnose_retained(path,config,target,descriptor) if retained_candidate else {}
            detail={"retainedGuard":diagnostic["guard"],"retainedPhase":diagnostic.get("phase","transport")} if retained_candidate else {}
            return {**_UNKNOWN,"state":"blocked","phase":phase,"absence":census,"hostBaseStage":host["state"],**detail}
        return {**_UNKNOWN,"state":"ready","correlationId":_C32,"baseTerminalReceiptSha256":terminal,"hostBaseStage":host["state"]}
    except (OSError,ValueError,KeyError,TypeError,base.WindowsMsiBasePrepareError,lease.Cp117LeaseError,rebase.WindowsCp117CampaignRebaseError):return {**_UNKNOWN,"state":"blocked","phase":phase}

_HOST_CENSUS = r'''import json,os,stat,sys
root,env,corr,expected_text=sys.argv[1:]
phase='parents';mask='00';count=0;file_mode='unobserved'
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
def directory(p):
 i=os.lstat(p)
 if not stat.S_ISDIR(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o700:raise ValueError()
def read(p):
 global file_mode
 fd=os.open(p,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 with os.fdopen(fd,'rb') as f:
  i=os.fstat(f.fileno());file_mode=format(stat.S_IMODE(i.st_mode),'04o')
  if not stat.S_ISREG(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode) not in (0o600,0o644) or not 0<i.st_size<=8192:raise ValueError()
  return json.load(f)
try:
 if env!='windows-cp117' or corr!='c32cb108-4d48-407e-9153-40774559ba50':raise ValueError()
 parent=os.path.join(root,env);group=os.path.join(parent,'windows-msi-base');leaf=os.path.join(group,corr)
 directory(root);directory(parent)
 if not os.path.lexists(group):out({'state':'absent'});raise SystemExit(0)
 directory(group)
 phase='group'
 names=set(os.listdir(group))- {'.environment.lock'}
 if not names:out({'state':'absent'});raise SystemExit(0)
 if names!={corr}:raise ValueError()
 phase='leaf';directory(leaf)
 entries=set(os.listdir(leaf));mask=''.join('1' if n in entries else '0' for n in ('binding.json','dispatch.json'));count=min(9,len(entries))
 if entries!={'binding.json','dispatch.json'}:raise ValueError()
 phase='binding'
 if read(os.path.join(leaf,'binding.json'))!=json.loads(expected_text):raise ValueError()
 phase='dispatch'
 dispatch=read(os.path.join(leaf,'dispatch.json'))
 if set(dispatch)!={'pid'} or type(dispatch['pid']) is not int or dispatch['pid']<=0:raise ValueError()
 out({'state':'retained'})
except Exception:out({'state':'unknown','phase':phase,'knownMask':mask,'entryCount':count,'fileMode':file_mode})
'''

def host_status(root: Path, config: Any, target: Any, descriptor: tuple[Any,...]) -> dict[str,Any]:
    """Inspect the original host base binding without removing historical files."""
    import json
    intent=base._private_intent(root,_C32)
    if intent is None:return dict(_UNKNOWN)
    request=intent['request'];pair=intent['pair']
    expected={'socketPath':descriptor[1],'pid':descriptor[2],'startTicks':descriptor[3],
        'sourceSha':request['sourceSha'],'sourceFingerprint':pair['sourceFingerprint'],
        'receiptArtifactId':request['fixtureReceiptArtifactId'],'baseArtifactId':request['baseMsiArtifactId'],
        'targetArtifactId':request['targetMsiArtifactId'],'commandSha256':intent['commandSha256'],'expectedSid':descriptor[4]}
    raw=base._remote(config,_HOST_CENSUS,(str(target.fixture_transfer_root),descriptor[0],_C32,
        json.dumps(expected,separators=(',',':'),sort_keys=True)),None,15)
    try:
        value=json.loads(raw) if raw is not None else None
    except (ValueError,TypeError):return dict(_UNKNOWN)
    if isinstance(value,dict) and set(value)=={'state','phase','knownMask','entryCount','fileMode'} and value['state']=='unknown' and value['phase'] in {'parents','group','leaf','binding','dispatch'} and value['knownMask'] in {'00','01','10','11'} and type(value['entryCount']) is int and 0<=value['entryCount']<=9 and value['fileMode'] in {'unobserved','0600','0644','0664','0666'}:
        return {**_UNKNOWN,'hostFailure':value['phase'],'hostKnownMask':value['knownMask'],'hostEntryCount':value['entryCount'],'hostFileMode':value['fileMode']}
    if not isinstance(value,dict) or set(value)!={'state'} or value['state'] not in {'absent','retained'}:return dict(_UNKNOWN)
    archive_directory=root/'.rag_index/windows-cp117-c32-host-archive'
    if archive_directory.exists() or archive_directory.is_symlink():
        from . import windows_cp117_c32_host_archive as archive
        proof=archive.status(root,{})
        if value['state']!='absent' or proof!={**_UNKNOWN,'state':'archived'}:return dict(_UNKNOWN)
    return {**_UNKNOWN,**value}

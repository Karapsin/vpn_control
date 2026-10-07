"""Fenced metadata reconciliation of an already retired API29 endpoint.

No mount, stage removal, adbd root/unroot, app stop, or installer operation.
The consumed cleanup keeps its unknown outcome and original receipts.
"""
from __future__ import annotations
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
from . import android_endpoint_admission as endpoint
from . import android_owned_endpoint_bind_recovery as recovery

PROOF='04cfe9aa-9427-47b3-8325-848b7cd26247'
PROOF_SHA='156626763407c2c5814a4fa530daa9f2639017fac234cc345226377a803eb464'
ENDPOINT_SHA='8274fffd51310221658a60686c8ffe4858ee4f5baa87197132b118df096cfca7'
BIND_SHA='eb038ed44e150f0a053805abc107f9092122a61112aa43bb8f905b58e69c3f4b'
READY_SHA='8719f50c686320759d489cd45e1c81c02574ca32e789e48c1a4b045782abd384'
_MUTATORS={'checkpoint','mount_exact','unmount_exact','release_exact_lease','finish_cleaned','cleanup_before_mount','readmit_cleanup','readmission_mount_diagnostic','recover_endpoint','recover_endpoint_locked','mount_failure_diagnostic','cleanup_readmitted_effects','cleanup_effects','remaining_endpoint','operate'}
_REMOTE=r'''
RET=__RET__;RET_ID=__ID__;TREE_BODY=__TREE__
retbase=job/('remaining-retired-'+RET_ID)
remote_intent_raw=private(job/'intent.json',8192)
ret_source_proof_pins=None

def retpath(suffix):return pathlib.Path(str(retbase)+suffix)
def retfail(reason):emit('unknown',reason,retiredCorrelationId=RET_ID,originalOutcome='unknown',replayAllowed=False)
def retired_release_guard():
 terminal=retpath('.terminal.json');release=retpath('.release.json')
 if not os.path.lexists(terminal) or not os.path.lexists(release):retfail('retired_lease_changed')
 value=json.loads(private(release,8192))
 if value!={'schema':1,'binding':RET['binding'],'terminalPin':remaining_pin(terminal,65536),'lease':RET['leasePin']}:retfail('retired_release_changed')

def retcontrols():
 global ret_source_proof_pins
 plan=retired_records_guard()
 if plan!=BUNDLE['baseline']['plan']:retfail('retired_plan_changed')
 sourcepins={}
 for proof in BUNDLE['proofs']:
  pin=remaining_pin(job/proof['name'],1048576)
  if pin['sha256']!=proof['sha256']:retfail('retired_source_proof_changed')
  sourcepins[proof['name']]=pin
 if ret_source_proof_pins is not None and sourcepins!=ret_source_proof_pins:retfail('retired_source_proof_changed')
 if os.path.lexists(retpath('.admission.json')) and json.loads(private(retpath('.admission.json'),65536)).get('snapshot',{}).get('proofPins')!=sourcepins:retfail('retired_source_proof_changed')
 ret_source_proof_pins=sourcepins;RET['snapshot']['proofPins']=sourcepins
 for group in BUNDLE['history']:
  hjob=root/('android-endpoint-'+group['correlationId']);i=hjob.lstat()
  if group.get('directory') and [i.st_dev,i.st_ino,i.st_mode,i.st_uid]!=group['directory']:retfail('retired_history_changed')
  for name,wanted in group['pins'].items():
   got=remaining_pin(hjob/name,32768)
   if group.get('permissionFingerprint'):
    gen=list(got['generation']);gen[5]=stat.S_IMODE(gen[5]);got={'fingerprint':gen,'sha256':got['sha256']}
   if got!=wanted:retfail('retired_history_changed')
 if remaining_pin(job/('remaining-stage-'+remaining['correlationId']+'.json'),65536)!=RET['readyPin']:retfail('retired_ready_changed')
 for suffix,pin in RET['journalPins'].items():
  if remaining_pin(job/('remaining-stage-'+remaining['correlationId']+'.'+suffix),65536)!=pin:retfail('retired_journal_changed')
 for suffix in ('terminal.json','release.json'):
  if os.path.lexists(job/('remaining-stage-'+remaining['correlationId']+'.'+suffix)):retfail('retired_historical_outcome_changed')
 proof=job/RET['proofName']
 if remaining_pin(proof,524288)!=RET['proofPin']:retfail('retired_proof_changed')
 request=json.loads(private(retpath('.request.json'),8192)) if os.path.lexists(retpath('.request.json')) else None
 if request is not None and request!={'schema':1,'binding':RET['binding']}:retfail('retired_request_changed')

def retprincipal():
 generation=shell('/system/bin/stat','-c','%u:%g:%a:%d:%i:%h:%s:%Y:%Z:%F','/system/xbin/su')
 digest=shell('/system/bin/sha256sum','/system/xbin/su')
 if generation!=RET['principal']['generation'] or digest!=RET['principal']['sha256']+'  /system/xbin/su':retfail('retired_principal_changed')

def retstock(plan,inside):
 retprincipal();ns=['/system/xbin/su','0,0','/system/bin/nsenter','-t',plan['zygote']['pid'],'-m','--'] if inside else []
 words=[*ns,'/system/bin/sh','-c',TREE_BODY];outer=' '.join(shlex.quote(x) for x in words)
 text=shell('/system/bin/sh','-c',shlex.quote(outer));retprincipal()
 stock={**BUNDLE['stock'],'membership':RET['insideMember'] if inside else BUNDLE['stock']['membership']}
 try:parsed=_parse_tree(text,plan,stock,False,inside)
 except ValueError:retfail('retired_stock_changed')
 return hashlib.sha256(json.dumps(parsed,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def retsnapshot():
 global observed_readmission_owner
 retcontrols();identity('2000');installed()
 plan=retired_records_guard();before=remaining_native(plan,True,'2000')
 if before!=RET['native']:retfail('retired_native_changed')
 observed_readmission_owner=RET['public']['owner']
 public=remaining_public('2000')
 if public!=RET['public']:retfail('retired_owner_changed')
 stock={'outside':retstock(plan,False),'inside':retstock(plan,True)}
 after=remaining_native(plan,True,'2000');retcontrols()
 if before!=after or stock!=RET['stockFingerprints']:retfail('retired_native_changed')
 return {'public':public,'native':after,'stock':stock,'binding':RET['binding'],'proofPins':ret_source_proof_pins}

def retadmission():
 path=retpath('.admission.json');pin=remaining_pin(path,65536);value=json.loads(private(path,65536))
 if value!={'schema':1,'kind':'retired-endpoint-fresh-owner','binding':RET['binding'],'snapshot':RET['snapshot']}:retfail('retired_admission_changed')
 return pin

def retired_dispatch():
 lock_fd=lease_lock()
 try:
  retcontrols()
  if action=='retired-admit':
   if any(os.path.lexists(retpath(x)) for x in ('.request.json','.admission.json','.attempt.json','.terminal.json','.release.json','.collect.json')):retfail('retired_already_recorded')
   first=retsnapshot();second=retsnapshot()
   if first!=second:retfail('retired_observation_changed')
   record(retpath('.request.json'),{'schema':1,'binding':RET['binding']})
   if retsnapshot()!=second:retfail('retired_observation_changed')
   record(retpath('.admission.json'),{'schema':1,'kind':'retired-endpoint-fresh-owner','binding':RET['binding'],'snapshot':second})
   emit('ready','retired_admitted',retiredCorrelationId=RET_ID,admissionPin=retadmission(),originalOutcome='unknown')
  admission=retadmission()
  if action=='retired-complete':
   if any(os.path.lexists(retpath(x)) for x in ('.attempt.json','.terminal.json','.release.json','.collect.json')):retfail('retired_attempt_recorded')
   if retsnapshot()!=RET['snapshot']:retfail('retired_admission_stale')
   record(retpath('.attempt.json'),{'schema':1,'binding':RET['binding'],'admissionPin':admission})
   attempt=remaining_pin(retpath('.attempt.json'),8192)
   if retsnapshot()!=RET['snapshot'] or retadmission()!=admission or remaining_pin(retpath('.attempt.json'),8192)!=attempt:retfail('retired_admission_stale')
   record(retpath('.terminal.json'),{'schema':1,'kind':'retired-endpoint-reconciled','binding':RET['binding'],'admissionPin':admission,'attemptPin':attempt,'snapshot':RET['snapshot'],'originalOutcome':'unknown'})
  if not os.path.lexists(retpath('.terminal.json')):
   if os.path.lexists(retpath('.attempt.json')):retfail('retired_completion_unknown')
   if retsnapshot()!=RET['snapshot']:retfail('retired_admission_stale')
   emit('ready','retired_admitted',retiredCorrelationId=RET_ID,admissionPin=admission,originalOutcome='unknown')
  terminal=json.loads(private(retpath('.terminal.json'),65536));terminal_pin=remaining_pin(retpath('.terminal.json'),65536)
  attempt_pin=remaining_pin(retpath('.attempt.json'),8192)
  if terminal!={'schema':1,'kind':'retired-endpoint-reconciled','binding':RET['binding'],'admissionPin':admission,'attemptPin':attempt_pin,'snapshot':RET['snapshot'],'originalOutcome':'unknown'} or json.loads(private(retpath('.attempt.json'),8192))!={'schema':1,'binding':RET['binding'],'admissionPin':admission}:retfail('retired_terminal_changed')
  if retsnapshot()!=RET['snapshot']:retfail('retired_post_changed')
  if action=='retired-collect':
   if os.path.lexists(retpath('.collect.json')):retfail('retired_collect_recorded')
   if not os.path.lexists(lease) or remaining_pin(lease,1024)!=RET['leasePin']:retfail('retired_lease_changed')
   record(retpath('.collect.json'),{'schema':1,'binding':RET['binding'],'terminalPin':terminal_pin})
   collect_pin=remaining_pin(retpath('.collect.json'),8192)
   if retsnapshot()!=RET['snapshot'] or retadmission()!=admission or remaining_pin(retpath('.attempt.json'),8192)!=attempt_pin or remaining_pin(retpath('.terminal.json'),65536)!=terminal_pin or remaining_pin(retpath('.collect.json'),8192)!=collect_pin:retfail('retired_post_changed')
   record(retpath('.release.json'),{'schema':1,'binding':RET['binding'],'terminalPin':terminal_pin,'lease':RET['leasePin']})
   release_pin=remaining_pin(retpath('.release.json'),8192)
   if retsnapshot()!=RET['snapshot'] or retadmission()!=admission or remaining_pin(retpath('.attempt.json'),8192)!=attempt_pin or remaining_pin(retpath('.terminal.json'),65536)!=terminal_pin or remaining_pin(retpath('.collect.json'),8192)!=collect_pin or remaining_pin(retpath('.release.json'),8192)!=release_pin:retfail('retired_post_changed')
   retcontrols()
   if retadmission()!=admission or remaining_pin(retpath('.terminal.json'),65536)!=terminal_pin or remaining_pin(retpath('.attempt.json'),8192)!=attempt_pin or remaining_pin(retpath('.collect.json'),8192)!=collect_pin or remaining_pin(retpath('.release.json'),8192)!=release_pin:retfail('retired_post_changed')
   if remaining_pin(lease,1024)!=RET['leasePin']:retfail('retired_lease_changed')
   lease.unlink()
   if os.path.lexists(lease):retfail('retired_lease_changed')
   retired_release_guard();retcontrols()
  emit('reconciled','retired_metadata_complete',retiredCorrelationId=RET_ID,terminalPin=terminal_pin,terminal=terminal,releasePin=remaining_pin(retpath('.release.json'),8192) if os.path.lexists(retpath('.release.json')) else None,release=json.loads(private(retpath('.release.json'),8192)) if os.path.lexists(retpath('.release.json')) else None,leaseReleased=not os.path.lexists(lease),originalOutcome='unknown',oldCleanupReplayed=False)
 finally:release_lock(lock_fd)
retired_dispatch()
'''

def _member(text):
    lines=text.splitlines();start=lines.index('__FDINFO__');end=lines.index('__MOUNTS__');fd=[x.split(':',1)[1].strip() for x in lines[start+1:end] if x.startswith('mnt_id:')]
    mounts=lines[end+1:lines.index('__FILES__')];found=[]
    for line in mounts:
        a,b=line.split(' - ');f=a.split();tail=b.split()
        if len(fd)==1 and f[0]==fd[0]:found.append({'fields':f,'filesystem':tail[0],'source':tail[1],'options':tail[2]})
    if len(found)!=1:raise ValueError('retired_descriptor_changed')
    return found[0]

def _prepare(root,identifier,allow_unobserved=False):
    root=Path(root).absolute()
    if not isinstance(identifier,str) or not recovery.UUID.fullmatch(identifier):raise ValueError('retired_correlation_invalid')
    if identifier in {PROOF,recovery.ORIGINAL,recovery.REMAINING}:raise ValueError('retired_distinct_correlation')
    bundle,pins=recovery._proof_bundle(root);snapshots={}
    for module,wanted in ((endpoint,ENDPOINT_SHA),(recovery,BIND_SHA)):
        path=Path(module.__file__).absolute();snapshot=recovery._source_snapshot(path)
        if snapshot[0]['sha256']!=wanted:raise ValueError('retired_consumed_source_changed')
        snapshots[str(path)]=snapshot
    for name in ('android_diagnostic_composition.py',Path(__file__).name):
        path=Path(__file__).absolute().with_name(name);snapshots[str(path)]=recovery._source_snapshot(path)
    path=root/'.runtime/parity-evidence/android-current'/('api29-remaining-partial-cleanup-diagnostic-'+PROOF+'.json');pin=recovery._private(path,524288);proof=pin[0];pins.append((path,pin))
    if pin[1]!=PROOF_SHA or proof.get('diagnosticCorrelationId')!=PROOF or proof.get('endpointCorrelationId')!=recovery.ORIGINAL or proof.get('remainingCorrelationId')!=recovery.REMAINING or proof.get('promoted') is not False:raise ValueError('retired_proof_changed')
    obs=proof['observations']
    if len(obs)!=2 or any(x['uid']!='2000' or x['mountLayout']['references'] or x['mountLayout']['owned'] for x in obs):raise ValueError('retired_not_observed')
    record=endpoint._recovery_local_snapshot(endpoint._remaining_path(root,recovery.REMAINING));intentpin=endpoint._recovery_local_snapshot(endpoint._intent_path(root,recovery.ORIGINAL));intent=intentpin[0]
    if not endpoint._remaining_receipt(record[0],{'correlationId':recovery.REMAINING,'originalIntentSha256':intentpin[1]},intent) or record[0]['remotePin']['sha256']!=READY_SHA:raise ValueError('retired_ready_changed')
    for i,x in enumerate(obs):
        if x['records']!=obs[0]['records'] or not x['records']['attempt.json']['present'] or not x['records']['unroot.json']['present'] or x['records']['terminal.json']['present'] or x['records']['release.json']['present']:raise ValueError('retired_journal_changed')
        if any(r['returncode']!=1 or r['stdout'] for r in x['stageStats']+[x['stageHash']]):raise ValueError('retired_stage_present')
        status=x['public']['unpinnedStatus']['json']
        if status.get('ok') is not True or status.get('code')!='OK' or status.get('final') is not True or status.get('configurationRevision')!=0 or status.get('data',{}).get('runtimeRunning') is not False or status.get('data',{}).get('runtimeObservation')!='stopped':raise ValueError('retired_public_changed')
        if i and any(status[k]!=obs[0]['public']['unpinnedStatus']['json'][k] for k in ('controllerId','configurationRevision','data')):raise ValueError('retired_owner_drift')
    plan=bundle['baseline']['plan'];inside=_member(obs[0]['trees']['inside'])
    # Authenticate namespace-private parent against the original before-unmount inventory.
    parents=[]
    for item in pins[0][1][0]['capture']:
        if item['view']!='inside':continue
        lines=base64.b64decode(item['stdout']).decode('utf-8','strict').splitlines();owned=[line for line in lines if line.startswith('664 ')]
        if len(owned)!=2 or owned[0]!=owned[1]:raise ValueError('retired_parent_changed')
        parentid=owned[0].split()[1];matching=[line for line in lines if line.startswith(parentid+' ') and ' - ' in line]
        if len(matching)!=2 or matching[0]!=matching[1]:raise ValueError('retired_parent_changed')
        left,right=matching[0].split(' - ');tail=right.split();parents.append({'fields':left.split(),'filesystem':tail[0],'source':tail[1],'options':tail[2]})
    if len(parents)!=2 or parents[0]!=parents[1] or inside!=parents[0]:raise ValueError('retired_parent_changed')
    admitted_parent=parents[0]
    fingerprints=[]
    for x in obs:
        value={}
        for view in ('outside','inside'):
            stock={**bundle['stock'],'membership':admitted_parent if view=='inside' else bundle['stock']['membership']};parsed=recovery._parse_tree(x['trees'][view],plan,stock,False,view=='inside');value[view]=hashlib.sha256(json.dumps(parsed,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        fingerprints.append(value)
    if fingerprints[0]!=fingerprints[1]:raise ValueError('retired_stock_drift')
    native=obs[0]['records']['unroot.json']['value']['post']['native'];oldpub=obs[0]['records']['unroot.json']['value']['post']['public'];public={**oldpub,'owner':status['controllerId']}
    if native.get('stageGeneration') is not None or native.get('caGeneration') is not None or native.get('targetIdentity')!='64258:1142:2:directory':raise ValueError('retired_native_changed')
    source={str(Path(path).relative_to(root)):snapshot[0]['sha256'] for path,snapshot in snapshots.items()}
    binding={'schema':1,'correlationId':identifier,'endpointCorrelationId':recovery.ORIGINAL,'remainingCorrelationId':recovery.REMAINING,'originalIntentSha256':intentpin[1],'readySha256':READY_SHA,'proofSha256':PROOF_SHA,'source':source,'public':public}
    ret={'binding':binding,'public':public,'native':native,'principal':bundle['principal'],'readyPin':record[0]['remotePin'],'leasePin':record[0]['receipt']['snapshot']['records']['lease'],'journalPins':{k:x['pin'] for k,x in obs[0]['records'].items() if x['present']},'insideMember':inside,'stockFingerprints':fingerprints[0],'proofName':'remaining-partial-cleanup-diagnostic-'+PROOF+'.json','proofPin':{'generation':list(pin[2]),'sha256':pin[1]},'snapshot':{'binding':binding,'public':public,'native':native,'stock':fingerprints[0]}}
    # A new readmission observation supplies CURRENT remote generation explicitly.
    observation_path=root/'.rag_index/android-retired-endpoint'/(identifier+'.proof-observation.json')
    if allow_unobserved:ret['proofPin']={'sha256':PROOF_SHA}
    else:
        observation=recovery._private(observation_path,8192);value=observation[0]
        if value.get('schema')!=1 or value.get('correlationId')!=identifier or value.get('historicalGeneration')!='unavailable' or value.get('source')!=source or value.get('currentPin',{}).get('sha256')!=PROOF_SHA or set(value.get('currentPin',{}))!={'generation','sha256'}:raise ValueError('retired_current_proof_observation_required')
        ret['proofPin']=value['currentPin'];binding['currentProofPin']=value['currentPin'];pins.append((observation_path,observation))
    return bundle,ret,pins,snapshots,intent,record,intentpin

def _program(bundle,ret,identifier,snapshots):
    source=recovery._program(bundle,'2d059d95-84f0-4088-b327-238eb2462a80',snapshots)
    if not source.endswith('operate()\n'):raise ValueError('retired_dispatch_changed')
    source=source[:-len('operate()\n')]
    if source.count('\nBUNDLE=')!=1:raise ValueError('retired_bind_dependency_changed')
    source=source.split('\nBUNDLE=',1)[0]+'\nBUNDLE='+repr(bundle)+'\n';tree=ast.parse(source);original=source
    guard=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='remaining_records_guard');old=ast.get_source_segment(original,guard)
    clone=old.replace('def remaining_records_guard(', 'def retired_records_guard(',1)
    needle="elif not os.path.lexists(job/('remaining-stage-'+remaining['correlationId']+'.release.json')): unknown('remaining_record_changed')"
    if clone.count(needle)!=1:raise ValueError('retired_guard_dependency_changed')
    clone=clone.replace(needle,'else:retired_release_guard()',1)
    part="  if not os.path.lexists(lease):\n   terminal=job/('remaining-stage-'+remaining['correlationId']+'.terminal.json');release=json.loads(private(job/('remaining-stage-'+remaining['correlationId']+'.release.json'),8192))\n   if release!={'schema':1,'terminalSha256':remaining_pin(terminal,65536)['sha256'],'receiptSha256':remaining['receiptPin']['sha256'],'lease':receipt['snapshot']['records']['lease']}: unknown('remaining_release_changed')"
    if clone.count(part)!=1:raise ValueError('retired_guard_dependency_changed')
    clone=clone.replace(part,'  if not os.path.lexists(lease):retired_release_guard()',1)
    for node in reversed(tree.body):
        if isinstance(node,ast.FunctionDef) and node.name in _MUTATORS:source=source.replace(ast.get_source_segment(original,node),'',1)
    own=snapshots[str(Path(__file__).absolute())][1];template=ast.literal_eval(next(n.value for n in ast.parse(own).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_REMOTE' for t in n.targets)))
    additions=clone+'\n'+template.replace('__RET__',repr(ret)).replace('__ID__',repr(identifier)).replace('__TREE__',repr(recovery._TREE_BODY))
    # Pin remote proof descriptor on first read and retain it through each guard.
    additions=additions.replace("if remaining_pin(proof,524288)!=RET['proofPin']:retfail('retired_proof_changed')", "current=remaining_pin(proof,524288)\n if current['sha256']!=RET['proofPin']['sha256'] or len(RET['proofPin'])>1 and current!=RET['proofPin']:retfail('retired_proof_changed')\n RET['proofPin']=current",1)
    scope={};path=Path(__file__).absolute().with_name('android_diagnostic_composition.py');exec(compile(snapshots[str(path)][1],str(path),'exec'),scope)
    return scope['compose_readonly_diagnostic'](source,additions)


def _call(root,identifier,action):
    if action not in {'retired-admit','retired-complete','retired-status','retired-collect','retired-observe-proof'}:raise ValueError('retired_action_invalid')
    root=Path(root).absolute();bundle,ret,pins,snapshots,intent,ready,original=_prepare(root,identifier,allow_unobserved=action=='retired-observe-proof');directory=root/'.rag_index/android-retired-endpoint';directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    info=directory.lstat();directorypin=recovery._directory_fp(directory)
    if not __import__('stat').S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or __import__('stat').S_IMODE(info.st_mode)!=0o700:raise ValueError('retired_local_directory_changed')
    request=directory/(identifier+'.request.json');fence=directory/(identifier+'.'+action+'.attempt.json')
    value={'schema':1,'binding':ret['binding']}
    if action=='retired-observe-proof':
        if os.path.lexists(directory/(identifier+'.proof-observation.json')):raise ValueError('retired_proof_observation_exists')
    elif action=='retired-admit':
        if os.path.lexists(request):return {'state':'unknown','reason':'retired_local_attempt_recorded','replayAllowed':False}
        recovery._write(request,value)
    elif not os.path.lexists(request) or recovery._private(request)[0]!=value:raise ValueError('retired_local_request_changed')
    requestpin=recovery._private(request) if action!='retired-observe-proof' else None
    if action not in {'retired-status','retired-observe-proof'}:
        if os.path.lexists(fence):return {'state':'unknown','reason':'retired_local_attempt_recorded','replayAllowed':False}
        recovery._write(fence,value)
    fencepin=recovery._private(fence) if action not in {'retired-status','retired-observe-proof'} else None
    config=endpoint.ssh_transport.load_config(root)
    with endpoint._shared_device_lease(root,intent['host'],intent['device']) as lease:
        released=not os.path.lexists(lease)
        if released and action!='retired-status':raise ValueError('retired_local_lease_absent')
        closed=_closed_local(root,identifier,ret,intent) if released else None
        leasepin=endpoint._recovery_local_snapshot(lease) if not released else None
        oldcontrols=_old_local_controls(root,intent,original,ready)
        closedpin=recovery._private(directory/(identifier+'.closed.json')) if released else None
        def guard():
            endpoint._readmission_local_guard(root,intent,lease,terminal=released)
            if _old_local_controls(root,intent,original,ready)!=oldcontrols:raise ValueError('retired_original_local_control_changed')
            if released and (recovery._private(directory/(identifier+'.closed.json'))!=closedpin or _closed_local(root,identifier,ret,intent)!=closed):raise ValueError('retired_local_closed_changed')
            if recovery._directory_fp(directory)!=directorypin:raise ValueError('retired_local_directory_changed')
            if leasepin is not None and endpoint._recovery_local_snapshot(lease)!=leasepin or endpoint._recovery_local_snapshot(endpoint._intent_path(root,recovery.ORIGINAL))!=original or endpoint._recovery_local_snapshot(endpoint._remaining_path(root,recovery.REMAINING))!=ready or requestpin is not None and recovery._private(request)!=requestpin or fencepin is not None and recovery._private(fence)!=fencepin:raise ValueError('retired_local_control_changed')
            for path,pin in pins:
                if recovery._private(path,524288)!=pin:raise ValueError('retired_local_proof_changed')
            for path,snapshot in snapshots.items():
                if recovery._source(Path(path))!=snapshot[0]:raise ValueError('retired_local_source_changed')
        guard();program=_program(bundle,ret,identifier,snapshots)
        if action=='retired-observe-proof':
            if not program.endswith('retired_dispatch()\n'):raise ValueError('retired_dispatch_changed')
            program=program[:-len('retired_dispatch()\n')]+"\nretcontrols();identity('2000');installed();retcontrols();emit('observed','retired_current_proof_observed',retiredCorrelationId=RET_ID,currentPin=RET['proofPin'],historicalGeneration='unavailable')\n"
        expected={**intent['remote'],'cleanupRemaining':{**ready[0]['receipt']['binding'],'receipt':ready[0]['receipt'],'receiptPin':ready[0]['remotePin']}}
        remote=endpoint._endpoint_python_command(endpoint.android_observation._canonical_cli_environment_source()+program,action,intent['remoteRoot'],intent['device'],recovery.ORIGINAL,json.dumps(expected,separators=(',',':')))
        if str(config.hosts[intent['host']].fixture_transfer_root)!=intent['remoteRoot'] or endpoint.ssh_transport.connection_host(config,intent['host']).password is not None:raise ValueError('retired_route_changed')
        argv=endpoint.ssh_transport.build_ssh_argv(config,intent['host'],60,command=remote);guard()
        try:
            code,output=endpoint.android_observation._run_probe(argv,24000);guard()
            if code:raise ValueError('retired_transport_failed')
            result=json.loads(output)
        except (OSError,TimeoutError,RuntimeError,ValueError):
            guard();return {'state':'unknown','reason':'retired_transport_unknown','replayAllowed':False,'originalOutcome':'unknown'}
        if result.get('correlationId')!=recovery.ORIGINAL or result.get('retiredCorrelationId') not in (None,identifier):raise ValueError('retired_response_changed')
        if action=='retired-observe-proof' and result.get('reason')=='retired_current_proof_observed':
            if result.get('currentPin',{}).get('sha256')!=PROOF_SHA or set(result.get('currentPin',{}))!={'generation','sha256'} or result.get('historicalGeneration')!='unavailable':raise ValueError('retired_current_proof_invalid')
            recovery._write(directory/(identifier+'.proof-observation.json'),{'schema':1,'correlationId':identifier,'historicalGeneration':'unavailable','currentPin':result['currentPin'],'source':ret['binding']['source']})
        if result.get('state')=='reconciled' and result.get('leaseReleased') is True:
            remoteclosed=_validate_remote_closed(result,ret)
            remote_path=directory/(identifier+'.remote-closed.json')
            if os.path.lexists(remote_path):
                if _remote_closed_local(directory,identifier)[0]!=remoteclosed:raise ValueError('retired_remote_closed_changed')
            else:
                recovery._write(remote_path,remoteclosed);remote_pin=recovery._private(remote_path)
                recovery._write(directory/(identifier+'.remote-closed.pin.json'),{'schema':1,'sha256':remote_pin[1],'generation':list(remote_pin[2])})
        recovery._write(directory/(identifier+'.'+action+'.reply-'+__import__('uuid').uuid4().hex+'.json'),result)
        return result

def admit(root,identifier):return _call(root,identifier,'retired-admit')
def complete(root,identifier):return _call(root,identifier,'retired-complete')
def status(root,identifier):return _call(root,identifier,'retired-status')
def collect(root,identifier):return _call(root,identifier,'retired-collect')

def observe_proof(root,identifier):return _call(root,identifier,'retired-observe-proof')


def _old_local_controls(root,intent,original,ready):
    paths=[endpoint._intent_path(root,recovery.ORIGINAL),endpoint._remaining_path(root,recovery.REMAINING,'.request.json'),endpoint._remaining_path(root,recovery.REMAINING),endpoint._remaining_path(root,recovery.REMAINING,'.attempt.json')]
    values=[endpoint._recovery_local_snapshot(p) for p in paths]
    binding={'correlationId':recovery.REMAINING,'originalIntentSha256':original[1]}
    if values[0]!=original or values[2]!=ready or values[1][0]!={'schema':1,'endpointCorrelationId':recovery.ORIGINAL,'binding':binding} or values[3][0]!={'schema':1,'receiptSha256':ready[1]} or os.path.lexists(endpoint._remaining_path(root,recovery.REMAINING,'.closed.json')):raise ValueError('retired_original_local_control_changed')
    return values

def _valid_remote_pin(pin):
    if not isinstance(pin,dict) or set(pin)!={'generation','sha256'} or not isinstance(pin['generation'],list) or len(pin['generation'])!=8 or any(type(v) is not int or v<0 for v in pin['generation']) or not isinstance(pin['sha256'],str) or not re.fullmatch(r'[0-9a-f]{64}',pin['sha256']):return False
    return __import__('stat').S_ISREG(pin['generation'][5]) and __import__('stat').S_IMODE(pin['generation'][5])==0o600 and pin['generation'][7]==1

def _validate_remote_closed(result,ret):
    terminal=result.get('terminal');release=result.get('release');tp=result.get('terminalPin');rp=result.get('releasePin')
    if result.get('state')!='reconciled' or result.get('reason')!='retired_metadata_complete' or result.get('retiredCorrelationId')!=ret['binding']['correlationId'] or result.get('correlationId')!=recovery.ORIGINAL or result.get('leaseReleased') is not True or result.get('originalOutcome')!='unknown' or result.get('oldCleanupReplayed') is not False:raise ValueError('retired_remote_closed_unverified')
    for pin,value in ((tp,terminal),(rp,release)):
        if not _valid_remote_pin(pin) or pin['generation'][2]!=len((json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()) or hashlib.sha256((json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()).hexdigest()!=pin['sha256']:raise ValueError('retired_remote_closed_unverified')
    if not isinstance(terminal,dict) or set(terminal)!={'schema','kind','binding','admissionPin','attemptPin','snapshot','originalOutcome'} or terminal['schema']!=1 or terminal['kind']!='retired-endpoint-reconciled' or terminal['binding']!=ret['binding'] or terminal['originalOutcome']!='unknown':raise ValueError('retired_remote_closed_unverified')
    if not _valid_remote_pin(terminal['admissionPin']) or not _valid_remote_pin(terminal['attemptPin']):raise ValueError('retired_remote_closed_unverified')
    snap=terminal['snapshot'];expected=ret['snapshot']
    if not isinstance(snap,dict) or set(snap)!=set(expected)|{'proofPins'} or any(snap.get(k)!=v for k,v in expected.items()) or not isinstance(snap.get('proofPins'),dict) or not snap['proofPins']:raise ValueError('retired_remote_closed_unverified')
    if release!={'schema':1,'binding':ret['binding'],'terminalPin':tp,'lease':ret['leasePin']}:raise ValueError('retired_remote_closed_unverified')
    return {'schema':1,'binding':ret['binding'],'terminal':terminal,'terminalPin':tp,'release':release,'releasePin':rp,'originalOutcome':'unknown'}

def _remote_closed_local(directory,identifier):
    path=directory/(identifier+'.remote-closed.json');proof=recovery._private(path);pin=recovery._private(directory/(identifier+'.remote-closed.pin.json'))
    if pin[0]!={'schema':1,'sha256':proof[1],'generation':list(proof[2])}:raise ValueError('retired_remote_closed_generation_changed')
    return proof

def _closed_local(root,identifier,ret,intent):
    directory=root/'.rag_index/android-retired-endpoint';remote=_remote_closed_local(directory,identifier);closed=recovery._private(directory/(identifier+'.closed.json'));fence=recovery._private(directory/(identifier+'.local-release.attempt.json'))
    body=closed[0];expected={'owner':'android-endpoint','correlationId':recovery.ORIGINAL,'host':intent['host'],'device':intent['device']}
    if set(body)!={'schema','binding','remoteProofPin','localLease','originalOutcome'} or body.get('schema')!=1 or body.get('binding')!=ret['binding'] or body.get('remoteProofPin')!={'sha256':remote[1],'generation':list(remote[2])} or body.get('originalOutcome')!='unknown' or body.get('localLease',{}).get('body')!=expected or set(body.get('localLease',{}))!={'body','sha256','generation'} or fence[0]!={'schema':1,'binding':ret['binding'],'remoteProofPin':body['remoteProofPin'],'localLease':body['localLease']}:raise ValueError('retired_local_closed_unverified')
    gen=body['localLease']['generation']
    if not isinstance(gen,list) or len(gen)!=8 or any(type(v) is not int or v<0 for v in gen) or gen[5]!=0o600 or gen[7]!=1 or not re.fullmatch(r'[0-9a-f]{64}',body['localLease']['sha256']):raise ValueError('retired_local_closed_unverified')
    _validate_remote_closed({'state':'reconciled','reason':'retired_metadata_complete','retiredCorrelationId':identifier,'correlationId':recovery.ORIGINAL,'leaseReleased':True,'oldCleanupReplayed':False,**remote[0]},ret)
    return closed

def _release_local_locked(root,identifier,ret,intent,original,ready,lease,guard):
    directory=root/'.rag_index/android-retired-endpoint';fence=directory/(identifier+'.local-release.attempt.json');closed=directory/(identifier+'.closed.json')
    if os.path.lexists(fence) or os.path.lexists(closed):return {'state':'unknown','reason':'retired_local_release_attempt_recorded','replayAllowed':False,'originalOutcome':'unknown'}
    guard();remote_path=directory/(identifier+'.remote-closed.json');remote=_remote_closed_local(directory,identifier)
    _validate_remote_closed({'state':'reconciled','reason':'retired_metadata_complete','retiredCorrelationId':identifier,'correlationId':recovery.ORIGINAL,'leaseReleased':True,'oldCleanupReplayed':False,**remote[0]},ret)
    pin=endpoint._recovery_local_snapshot(lease);expected={'owner':'android-endpoint','correlationId':recovery.ORIGINAL,'host':intent['host'],'device':intent['device']}
    if pin[0]!=expected:raise ValueError('retired_local_claim_changed')
    locallease={'body':pin[0],'sha256':pin[1],'generation':list(pin[2])};remoteproof={'sha256':remote[1],'generation':list(remote[2])}
    value={'schema':1,'binding':ret['binding'],'remoteProofPin':remoteproof,'localLease':locallease}
    recovery._write(fence,value);fencepin=recovery._private(fence);guard()
    if endpoint._recovery_local_snapshot(lease)!=pin or recovery._private(remote_path)!=remote or recovery._private(fence)!=fencepin:raise ValueError('retired_local_claim_changed')
    recovery._write(closed,{**value,'originalOutcome':'unknown'});closedpin=recovery._private(closed);guard()
    if endpoint._recovery_local_snapshot(lease)!=pin or recovery._private(remote_path)!=remote or recovery._private(fence)!=fencepin or recovery._private(closed)!=closedpin:raise ValueError('retired_local_claim_changed')
    lease.unlink()
    if os.path.lexists(lease):raise ValueError('retired_local_claim_changed')
    _closed_local(root,identifier,ret,intent);guard(True)
    return {'state':'reconciled','reason':'retired_local_claim_released','retiredCorrelationId':identifier,'originalOutcome':'unknown','localLeaseReleased':True,'remoteEffects':False,'replayAllowed':False}

def release_local(root,identifier):
    root=Path(root).absolute();bundle,ret,pins,snapshots,intent,ready,original=_prepare(root,identifier);directory=root/'.rag_index/android-retired-endpoint';directorypin=recovery._directory_fp(directory)
    request=directory/(identifier+'.request.json');requestpin=recovery._private(request)
    if requestpin[0]!={'schema':1,'binding':ret['binding']}:raise ValueError('retired_local_request_changed')
    with endpoint._shared_device_lease(root,intent['host'],intent['device']) as lease:
        if not os.path.lexists(lease):
            _closed_local(root,identifier,ret,intent)
            return {'state':'unknown','reason':'retired_local_release_attempt_recorded','originalOutcome':'unknown','replayAllowed':False}
        oldcontrols=_old_local_controls(root,intent,original,ready)
        def guard(released=False):
            endpoint._readmission_local_guard(root,intent,lease,terminal=released)
            if released:_closed_local(root,identifier,ret,intent)
            if recovery._directory_fp(directory)!=directorypin or recovery._private(request)!=requestpin or _old_local_controls(root,intent,original,ready)!=oldcontrols:raise ValueError('retired_local_control_changed')
            for path,pin in pins:
                if recovery._private(path,524288)!=pin:raise ValueError('retired_local_proof_changed')
            for path,snapshot in snapshots.items():
                if recovery._source(Path(path))!=snapshot[0]:raise ValueError('retired_local_source_changed')
        return _release_local_locked(root,identifier,ret,intent,original,ready,lease,guard)

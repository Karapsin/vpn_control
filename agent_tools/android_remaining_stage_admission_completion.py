"""Metadata-only completion of b059's measured interrupted remaining admission.

Native reads are admitted through the original guards. This helper never removes
stages, changes privilege, unmounts, or releases the original device lease.
"""
from __future__ import annotations
import ast
import hashlib
import json
import os
from pathlib import Path
from . import android_endpoint_admission as endpoint
from . import android_owned_endpoint_bind_recovery as recovery

POST='43f432a4-4cc5-40c8-ad29-0702570a3d35'
POST_SHA='1779891a9f2c387389139f654d2cdaf3a2ebaccaa26eb36f2158b5c0cd15aa15'
BIND_RECOVERY='2d059d95-84f0-4088-b327-238eb2462a80'
RECOVERY_SHA='eb038ed44e150f0a053805abc107f9092122a61112aa43bb8f905b58e69c3f4b'

_REMOTE=r'''
META=__META__;COMPLETION_ID=__COMPLETION_ID__
completion_intent=job/('remaining-admission-completion-'+COMPLETION_ID+'.json')
completion_attempt=job/('remaining-admission-completion-'+COMPLETION_ID+'.attempt.json')
completion_terminal=job/('remaining-admission-completion-'+COMPLETION_ID+'.terminal.json')
completion_reserve=job/'remaining-admission-completion-reservation.json'
ready_path=job/('remaining-stage-'+remaining['correlationId']+'.json')
completion_intent_pin=None;completion_attempt_pin=None;completion_proof_pin=None;completion_reserve_pin=None;completion_ready_pin=None

def completion_controls(allow_ready=False):
 private_guard()
 if native_directories()!=BUNDLE['receipt']['snapshot']['directories']:fail('completion_directory_changed')
 for suffix in ('attempt.json','unroot.json','terminal.json','release.json'):
  if os.path.lexists(job/('remaining-stage-'+remaining['correlationId']+'.'+suffix)):fail('completion_cleanup_already_recorded')
 if not allow_ready and os.path.lexists(ready_path):fail('completion_ready_already_recorded')
 if json.loads(private(job/'remaining-stage-admission.json',8192))!={key:remaining[key] for key in ('correlationId','originalIntentSha256')}:fail('completion_original_binding_changed')
 for path,pin in ((completion_intent,completion_intent_pin),(completion_attempt,completion_attempt_pin)):
  if pin is not None and remaining_pin(path,65536)!=pin:fail('completion_journal_changed')
 if os.path.lexists(completion_reserve) and json.loads(private(completion_reserve,8192))!=META['binding']:fail('completion_other_correlation_recorded')
 if completion_reserve_pin is not None and remaining_pin(completion_reserve,8192)!=completion_reserve_pin:fail('completion_reservation_changed')
 if completion_ready_pin is not None and remaining_pin(ready_path,65536)!=completion_ready_pin:fail('completion_ready_changed')
 for label,name in [('attemptPin','owned-bind-'+NEW_ID+'.attempt.json'),('commandPin','owned-bind-'+NEW_ID+'.command.json')]:
  if remaining_pin(job/name,16384)!=META['post'][label]:fail('completion_bind_effect_changed')
 proofpath=job/META['post']['name'];proofpin=remaining_pin(proofpath,1048576)
 if proofpin['sha256']!=META['post']['sha256'] or completion_proof_pin is not None and proofpin!=completion_proof_pin:fail('completion_stock_proof_changed')
 proof=json.loads(private(proofpath,1048576))
 if proof.get('kind')!='readonly-owned-bind-postcondition-diagnostic' or proof.get('diagnosticCorrelationId')!=META['post']['correlationId'] or proof.get('endpointCorrelationId')!=correlation or proof.get('bindRecoveryCorrelationId')!=NEW_ID or proof.get('source')!=BUNDLE['source'] or proof.get('promoted') is not False or proof.get('summary',{}).get('authoritativeObservationsEqual') is not True:fail('completion_stock_proof_changed')
 for observation in proof.get('observations',[]):
  if any(observation[view+'Facts']['authoritativeFingerprint']!=META['post'][view+'Fingerprint'] for view in ('inside','outside')):fail('completion_stock_proof_changed')
 if len(proof.get('observations',[]))!=2:fail('completion_stock_proof_changed')
 return proofpin

def completion_tree(inside):
 ns=['/system/xbin/su','0,0','/system/bin/nsenter','-t','6654','-m','--'] if inside else []
 outer=' '.join(shlex.quote(word) for word in [*ns,'/system/bin/sh','-c',TREE_BODY]);principal_pin()
 text=native_read(['/system/bin/sh','-c',shlex.quote(outer)]);principal_pin()
 stock=dict(BUNDLE['stock'])
 if inside:stock['membership']=META['post']['insideMembership']
 try:parsed=_parse_tree(text,plan,stock,False,inside)
 except (ValueError,IndexError):fail('completion_stock_tree_changed')
 fingerprint=hashlib.sha256(json.dumps(parsed,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 if fingerprint!=META['post'][('inside' if inside else 'outside')+'Fingerprint']:fail('completion_stock_tree_changed')
 return fingerprint

def completion_snapshot(allow_ready=False):
 completion_controls(allow_ready)
 snapshot=remaining_snapshot()
 if snapshot['public']!=META['post']['public']:fail('completion_owner_changed')
 if snapshot['native']['stageGeneration']!=BUNDLE['baseline']['stageGeneration']:fail('completion_stage_changed')
 first=completion_tree(False);second=completion_tree(True)
 closing=remaining_snapshot()
 completion_controls(allow_ready)
 if snapshot!=closing:fail('completion_observation_changed')
 return {'remainingSnapshot':snapshot,'outsideFingerprint':first,'insideFingerprint':second,'proofPin':remaining_pin(job/META['post']['name'],1048576),'directories':native_directories()}

def complete_metadata():
 global plan,remote_intent_raw,completion_intent_pin,completion_attempt_pin,completion_proof_pin,completion_reserve_pin,completion_ready_pin
 descriptor=lease_lock()
 try:
  remote_intent_raw=private(job/'intent.json',8192);plan=private_guard()
  if action=='remaining-admission-complete':
   if any(os.path.lexists(path) for path in (completion_intent,completion_attempt,completion_terminal,completion_reserve)):fail('completion_already_recorded')
   completion_proof_pin=completion_controls();first=completion_snapshot();second=completion_snapshot()
   if first!=second:fail('completion_observation_changed')
   record(completion_reserve,META['binding'])
   intent={'schema':1,'kind':'remaining-admission-metadata-completion','binding':META['binding'],'source':META['source'],'snapshot':second,'reservationPin':remaining_pin(completion_reserve,8192)}
   record(completion_intent,intent);completion_intent_pin=remaining_pin(completion_intent,65536);completion_reserve_pin=intent['reservationPin']
   if completion_snapshot()!=second:fail('completion_observation_changed')
   record(completion_attempt,{'schema':1,'intentSha256':completion_intent_pin['sha256']})
   completion_attempt_pin=remaining_pin(completion_attempt,8192)
   if completion_snapshot()!=second or remaining_pin(completion_reserve,8192)!=intent['reservationPin']:fail('completion_observation_changed')
   receipt={'schema':1,'kind':'android-endpoint-remaining-stage','binding':dict(remaining),'snapshot':second['remainingSnapshot']}
   # The only completed admission effect is a create-only metadata receipt.
   record(ready_path,receipt)
  elif action!='remaining-admission-status':fail('completion_action_invalid')
  intent=json.loads(private(completion_intent,65536));completion_intent_pin=remaining_pin(completion_intent,65536)
  if intent.get('schema')!=1 or intent.get('kind')!='remaining-admission-metadata-completion' or intent.get('binding')!=META['binding'] or intent.get('source')!=META['source'] or remaining_pin(completion_reserve,8192)!=intent.get('reservationPin'):fail('completion_intent_changed')
  completion_proof_pin=intent['snapshot']['proofPin'];completion_reserve_pin=intent['reservationPin']
  if not os.path.lexists(completion_attempt):fail('completion_metadata_not_attempted')
  completion_attempt_pin=remaining_pin(completion_attempt,8192)
  if json.loads(private(completion_attempt,8192))!={'schema':1,'intentSha256':completion_intent_pin['sha256']}:fail('completion_attempt_changed')
  if not os.path.lexists(ready_path):fail('completion_metadata_unknown')
  wanted={'schema':1,'kind':'android-endpoint-remaining-stage','binding':dict(remaining),'snapshot':intent['snapshot']['remainingSnapshot']}
  receiptpin=remaining_pin(ready_path,65536);completion_ready_pin=receiptpin
  if json.loads(private(ready_path,65536))!=wanted or completion_snapshot(True)!=intent['snapshot'] or remaining_pin(ready_path,65536)!=receiptpin:fail('completion_ready_changed')
  terminal={'schema':1,'binding':META['binding'],'intentPin':completion_intent_pin,'attemptPin':completion_attempt_pin,'readyPin':receiptpin}
  if os.path.lexists(completion_terminal):
   if json.loads(private(completion_terminal,8192))!=terminal:fail('completion_terminal_changed')
  else:record(completion_terminal,terminal)
  emit('ready','remaining_admission_completed',completionCorrelationId=COMPLETION_ID,remaining=wanted,remainingReceiptPin=receiptpin,originalOutcome='unknown',stageRetired=False,leaseReleased=False,replayAllowed=False)
 finally:release_lock(descriptor)
complete_metadata()
'''

def _prepare(root,completion_id):
    if not isinstance(completion_id,str) or not recovery.UUID.fullmatch(completion_id) or completion_id in {POST,BIND_RECOVERY,recovery.ORIGINAL,recovery.REMAINING}:raise ValueError('completion_distinct_correlation_required')
    bundle,proofpins=recovery._proof_bundle(root)
    postpath=root/'.runtime/parity-evidence/android-current'/('api29-owned-bind-post-diagnostic-'+POST+'.json');postpin=recovery._private(postpath)
    if postpin[1]!=POST_SHA:raise ValueError('completion_post_proof_changed')
    post=postpin[0]
    if post.get('kind')!='readonly-owned-bind-postcondition-diagnostic' or post.get('endpointCorrelationId')!=recovery.ORIGINAL or post.get('bindRecoveryCorrelationId')!=BIND_RECOVERY or post.get('diagnosticCorrelationId')!=POST or post.get('promoted') is not False or post['summary']['authoritativeObservationsEqual'] is not True:raise ValueError('completion_post_proof_invalid')
    if not post['summary']['inside']['targetEqualsStock'] or not post['summary']['inside']['stockTreeMatchesExceptMembership'] or not post['summary']['inside']['membershipEqualsAdmittedParent']:raise ValueError('completion_post_proof_invalid')
    envelopepath=root/'.rag_index/android-owned-endpoint-bind'/(BIND_RECOVERY+'.json');envelopepin=recovery._private(envelopepath);envelope=envelopepin[0]
    bundle.update(envelope);bundle.update(binding=envelope['receipt']['binding'],source=envelope['receipt']['source'])
    if bundle['source']!={'helperSha256':RECOVERY_SHA,'endpointSha256':recovery.ENDPOINT_SHA} or post['source']!=bundle['source'] or post['admissionPin']!=bundle['receiptPin'] or post['reservationPin']!=bundle['reservationPin']:raise ValueError('completion_consumed_source_changed')
    proofpins.extend([(postpath,postpin),(envelopepath,envelopepin)])
    paths=(Path(recovery.__file__).absolute(),Path(endpoint.__file__).absolute(),Path(__file__).absolute(),root/'agent_tools/android_diagnostic_composition.py')
    snapshots={str(path):recovery._source_snapshot(path) for path in paths}
    if snapshots[str(paths[0])][0]['sha256']!=RECOVERY_SHA:raise ValueError('completion_consumed_source_changed')
    meta={'source':{str(path.relative_to(root)):snapshots[str(path)][0]['sha256'] for path in paths},'post':{'name':'owned-bind-post-diagnostic-'+POST+'.json','correlationId':POST,'sha256':POST_SHA,'attemptPin':post['attemptPin'],'commandPin':post['commandPin'],'insideMembership':post['admittedParentMembership'],'public':envelope['receipt']['snapshot']['public']}}
    for view in ('outside','inside'):
        fingerprints=[observation[view+'Facts']['authoritativeFingerprint'] for observation in post['observations']]
        if len(fingerprints)!=2 or fingerprints[0]!=fingerprints[1] or fingerprints[0] is None:raise ValueError('completion_post_proof_invalid')
        meta['post'][view+'Fingerprint']=fingerprints[0]
    return bundle,meta,proofpins,snapshots

def _program(bundle,meta,completion_id,snapshots):
    prefix=recovery._program(bundle,BIND_RECOVERY,snapshots)
    owntext=snapshots[str(Path(__file__).absolute())][1].decode('utf-8','strict');tree=ast.parse(owntext)
    template=ast.literal_eval(next(node.value for node in tree.body if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='_REMOTE' for target in node.targets)))
    if not prefix.endswith('operate()\n'):raise ValueError('completion_dispatch_changed')
    composition={};path=Path(endpoint.__file__).absolute().with_name('android_diagnostic_composition.py');exec(compile(snapshots[str(path)][1],str(path),'exec'),composition)
    return composition['compose_readonly_diagnostic'](prefix[:-len('operate()\n')],template.replace('__META__',repr(meta)).replace('__COMPLETION_ID__',repr(completion_id)))

def _call(root,completion_id,action):
    root=Path(root).resolve();bundle,meta,proofpins,snapshots=_prepare(root,completion_id)
    original=endpoint._intent_path(root,recovery.ORIGINAL);op=endpoint._recovery_local_snapshot(original);intent=op[0]
    oldrequest=endpoint._remaining_path(root,recovery.REMAINING,'.request.json');rp=endpoint._recovery_local_snapshot(oldrequest)
    binding={'correlationId':recovery.REMAINING,'originalIntentSha256':op[1]}
    if rp[0]!={'schema':1,'endpointCorrelationId':recovery.ORIGINAL,'binding':binding}:raise ValueError('completion_original_binding_changed')
    meta['binding']={'correlationId':completion_id,'endpointCorrelationId':recovery.ORIGINAL,'remainingCorrelationId':recovery.REMAINING,'originalIntentSha256':op[1],'postProofSha256':POST_SHA}
    local=root/'.rag_index/android-remaining-stage-completion';local.mkdir(mode=0o700,parents=True,exist_ok=True);directorypin=recovery._directory_fp(local);parentpin=recovery._directory_fp(local.parent)
    request=local/(completion_id+'.request.json');attempt=local/(completion_id+'.attempt.json');receipt=local/(completion_id+'.json');reserve=local/'reservation.json'
    with endpoint._shared_device_lease(root,intent['host'],intent['device']) as lease:
        lp=endpoint._recovery_local_snapshot(lease)
        value={'schema':1,'binding':meta['binding'],'source':meta['source']}
        if action=='remaining-admission-complete':
            if any(os.path.lexists(path) for path in (request,attempt,receipt,reserve)):raise ValueError('completion_local_already_recorded')
            recovery._write(reserve,value);recovery._write(request,value);recovery._write(attempt,value)
        requestpin=recovery._private(request,8192);attemptpin=recovery._private(attempt,8192);reservepin=recovery._private(reserve,8192)
        if any(pin[0]!=value for pin in (requestpin,attemptpin,reservepin)):raise ValueError('completion_local_journal_changed')
        receiptpin=recovery._private(receipt,262144) if os.path.lexists(receipt) else None
        def guard():
            endpoint._readmission_local_guard(root,intent,lease)
            if recovery._directory_fp(local)!=directorypin or recovery._directory_fp(local.parent)!=parentpin:raise ValueError('completion_local_directory_changed')
            for path,pin in ((original,op),(oldrequest,rp),(lease,lp)):
                if endpoint._recovery_local_snapshot(path)!=pin:raise ValueError('completion_local_original_changed')
            for path,pin in [*proofpins,(request,requestpin),(attempt,attemptpin),(reserve,reservepin),*(([(receipt,receiptpin)]) if receiptpin else [])]:
                if recovery._private(path)!=pin:raise ValueError('completion_local_private_changed')
            for path,pin in snapshots.items():
                if recovery._source(Path(path))!=pin[0]:raise ValueError('completion_local_source_changed')
        guard();config=endpoint.ssh_transport.load_config(root);host=intent['host']
        if str(config.hosts[host].fixture_transfer_root)!=intent['remoteRoot'] or endpoint.ssh_transport.connection_host(config,host).password is not None:raise ValueError('completion_route_changed')
        program=_program(bundle,meta,completion_id,snapshots);expected={**intent['remote'],'cleanupRemaining':binding}
        command=endpoint._endpoint_python_command(endpoint.android_observation._canonical_cli_environment_source()+program,action,intent['remoteRoot'],intent['device'],recovery.ORIGINAL,json.dumps(expected,separators=(',',':')))
        argv=endpoint.ssh_transport.build_ssh_argv(config,host,60,command=command);guard()
        try:
            code,output=endpoint.android_observation._run_probe(argv,24000);guard()
            if code:raise ValueError('completion_transport_failed')
            result=json.loads(output)
        except (OSError,TimeoutError,RuntimeError,ValueError):
            guard();return {'state':'unknown','reason':'completion_transport_unknown','originalOutcome':'unknown','replayAllowed':False}
        if result.get('correlationId')!=recovery.ORIGINAL or result.get('completionCorrelationId') not in (None,completion_id):raise ValueError('completion_response_changed')
        if result.get('state')=='ready':
            envelope={'receipt':result['remaining'],'remotePin':result['remainingReceiptPin']}
            if not endpoint._remaining_receipt(envelope,binding,intent):raise ValueError('completion_ready_receipt_invalid')
            if receiptpin is None:recovery._write(receipt,{'schema':1,'binding':meta['binding'],'source':meta['source'],'remainingEnvelope':envelope})
            elif receiptpin[0]!= {'schema':1,'binding':meta['binding'],'source':meta['source'],'remainingEnvelope':envelope}:raise ValueError('completion_local_ready_changed')
        return {**result,'originalOutcome':'unknown','replayAllowed':False,'stageRetired':False,'leaseReleased':False}

def complete(root,completion_id):return _call(root,completion_id,'remaining-admission-complete')
def status(root,completion_id):return _call(root,completion_id,'remaining-admission-status')

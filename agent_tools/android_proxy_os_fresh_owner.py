"""Explicit fresh-owner admission for a new OS getter correlation.

The consumed 4f77 attempt remains failed/unknown; compiler/DEX and historical
binding bytes remain unchanged. Only two positive current public readbacks may
admit the new execution owner. Staging/getter source remains the reviewed one.
"""
from __future__ import annotations
import ast
import base64
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
from agent_tools import android_proxy_os_observation as frozen
from agent_tools import android_installer_failed_check_retirement as old

FAILED='4f77a912-98c5-411d-aab6-7b7eecce22b6'
FROZEN_SHA='11d72ae85282669ed6ed62805bbb01f16b1300f8abc9bfcec672fd8ed16a474d'
FROZEN_SOURCE_SHA='1fcd64715c82693a35cc77b0d64942d7c697683210c172932d2a09cb7acf3326'
FAILED_PIN={'bytes':49164,'generation':[66307,103945900,49164,1791014391239968414,1791014391239968414,384,1000,1],'sha256':'35e8d6cfff6624ee83360f9b28a68408c1be205212fa40c400e54ab0045d6d6b'}
_UUID=re.compile(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}')


def measure_owner(public):
    """No CONFLICT adoption: require two complete positive stopped/final snapshots."""
    snapshots=[]
    for _ in range(2):
        state=public('status');history=public('operations','list')
        for envelope in (state,history):
            if not isinstance(envelope,dict) or envelope.get('ok') is not True or envelope.get('final') is not True or envelope.get('code')!='OK' or not isinstance(envelope.get('controllerId'),str) or not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',envelope['controllerId']) or type(envelope.get('configurationRevision')) is not int or envelope['configurationRevision']<0:raise ValueError('fresh_owner_envelope_unsafe')
        if (state['controllerId'],state['configurationRevision'])!=(history['controllerId'],history['configurationRevision']):raise ValueError('fresh_owner_pair_drift')
        data=state.get('data');history_data=history.get('data');ops=history_data.get('operations') if isinstance(history_data,dict) else None
        if not isinstance(data,dict) or data.get('runtimeRunning') is not False or data.get('runtimeObservation')!='stopped':raise ValueError('fresh_owner_runtime_not_stopped')
        if not isinstance(ops,list) or any(not isinstance(item,dict) or item.get('final') is not True for item in ops):raise ValueError('fresh_owner_operations_not_final')
        snapshots.append({'owner':state['controllerId'],'revision':state['configurationRevision'],'statusData':data,'operations':ops})
    if snapshots[0]!=snapshots[1]:raise ValueError('fresh_owner_snapshot_drift')
    return {'owner':snapshots[0]['owner'],'revision':snapshots[0]['revision'],'snapshotSha256':hashlib.sha256(json.dumps(snapshots[0],sort_keys=True,separators=(',',':')).encode()).hexdigest(),'snapshotCount':2,'runtimeObservation':'stopped','allOperationsFinal':True}


def remote_source() -> str:
    source=frozen.remote_source()
    if hashlib.sha256(source.encode()).hexdigest()!=FROZEN_SOURCE_SHA:raise ValueError('consumed_observer_source_changed')
    constants={n.targets[0].id:ast.literal_eval(n.value) for n in ast.parse(source).body[:3]}
    checks=constants['CHECKS'];marker="phase='metadata-owner-admission'"
    opening='\n'+inspect.getsource(measure_owner)+r"""
phase='fresh-owner-failed-history-binding'
failed_path=root/'android-failed-check-retirement-diagnostic-4f77a912-98c5-411d-aab6-7b7eecce22b6'/'receipt.json'
failed_raw,failed_pin=snapshot_file(failed_path,1048576)
if {**failed_pin,'bytes':len(failed_raw)}!=FRESH_FAILED_PIN:raise ValueError('fresh_owner_failed_history_changed')
failed=json.loads(failed_raw)
if failed.get('diagnosticCorrelationId')!='4f77a912-98c5-411d-aab6-7b7eecce22b6' or failed.get('diagnosticSourceSha256')!=FRESH_FROZEN_SOURCE_SHA or failed.get('currentFailurePhase')!='metadata-owner-admission' or failed.get('originalOutcome')!='unknown' or failed.get('serviceCapture') is not None or failed.get('exception',{}).get('type')!='ValueError' or base64.b64decode(failed['exception']['message']['base64'],validate=True)!=b'metadata_owner_changed':raise ValueError('fresh_owner_failed_history_binding_changed')
phase='fresh-owner-positive-admission'
fresh_owner_admission=measure_owner(public_cli)
mode=diagnostic.get('freshOwnerMode')
if mode=='observe':
 admitted=diagnostic['freshAdmission']
 admitted_path=root/('android-failed-check-retirement-diagnostic-'+admitted['correlationId'])/'receipt.json'
 admitted_raw,admitted_pin=snapshot_file(admitted_path,1048576)
 if {**admitted_pin,'bytes':len(admitted_raw)}!=admitted['receiptPin']:raise ValueError('fresh_owner_admission_generation_changed')
 admitted_value=json.loads(admitted_raw)
 if admitted_value.get('diagnosticSourceSha256')!=diagnostic['diagnosticSourceSha256'] or admitted_value.get('exception') is not None or admitted_value.get('currentFailurePhase')!='fresh-owner-admitted' or admitted_value.get('freshOwnerAdmission')!=fresh_owner_admission or admitted_value.get('originalOutcome')!='unknown':raise ValueError('fresh_owner_admission_drift')
elif mode!='admit':raise ValueError('fresh_owner_mode_invalid')
# Historical binding/closing readback stay unchanged. This execution's owner
# comes exclusively from the new positive admission, never a CONFLICT payload.
owner=fresh_owner_admission['owner'];revision=fresh_owner_admission['revision']
"""
    checks=checks.replace(marker,opening+'\n'+marker,1)
    split=checks.index("phase='proxy-os-artifact-admission'")
    observe_checks=checks
    admit_checks=checks[:split]+r"""
phase='fresh-owner-closing-admission'
if measure_owner(public_cli)!=fresh_owner_admission:raise ValueError('fresh_owner_closing_drift')
if snapshot_file(failed_path,1048576)[1]!=failed_pin:raise ValueError('fresh_owner_failed_history_generation_changed')
guard_files(pins,paths,parents);verify_manifest();fixture_stopped(output)
phase='fresh-owner-admitted'
"""
    observe_checks+=r"""
phase='fresh-owner-observation-final-guard'
if measure_owner(public_cli)!=fresh_owner_admission:raise ValueError('fresh_owner_closing_drift')
if snapshot_file(failed_path,1048576)[1]!=failed_pin or snapshot_file(admitted_path,1048576)[1]!=admitted_pin:raise ValueError('fresh_owner_history_or_admission_changed')
"""
    bootstrap=source[source.index('import base64,fcntl,hashlib,json,os,pathlib,stat,subprocess,sys'):]
    bootstrap=bootstrap.replace('effective_proxy=None;','effective_proxy=None;fresh_owner_admission=None;',1)
    bootstrap=bootstrap.replace('exec(CHECKS,globals())',"exec(ADMIT_CHECKS if diagnostic.get('freshOwnerMode')=='admit' else CHECKS,globals())",1)
    bootstrap=bootstrap.replace("'effectiveProxy':effective_proxy,", "'effectiveProxy':effective_proxy,'freshOwnerAdmission':fresh_owner_admission,",1)
    bootstrap=bootstrap.replace('os.fsync(directory);os.close(directory);os.fsync(fd);os.close(fd)',"os.fsync(directory);os.close(directory);os.fsync(fd);os.close(fd)\n receipt_raw,receipt_pin=snapshot_file(root/name/'receipt.json',4194304)",1)
    bootstrap=bootstrap.replace("'receiptSha256':hashlib.sha256(payload).hexdigest(),", "'receiptSha256':hashlib.sha256(payload).hexdigest(),'receiptPin':{**receipt_pin,'bytes':len(receipt_raw)},'freshOwnerAdmission':fresh_owner_admission,",1)
    extra=source[source.index('PROBE_JAVA_SHA='):source.index('import base64,fcntl,hashlib,json,os,pathlib,stat,subprocess,sys')]
    return ('ORIGINAL_SHA='+repr(constants['ORIGINAL_SHA'])+'\nPREFIX='+repr(constants['PREFIX'])+'\nCHECKS='+repr(observe_checks)+'\nADMIT_CHECKS='+repr(admit_checks)+'\n'
        +'FRESH_FAILED_PIN='+repr(FAILED_PIN)+'\nFRESH_FROZEN_SOURCE_SHA='+repr(FROZEN_SOURCE_SHA)+'\n'+extra+bootstrap)


def _directory(root: Path, correlation: str) -> Path:
    if not _UUID.fullmatch(correlation) or correlation in (FAILED,frozen.ADMISSION,frozen.OS_OBSERVATION):raise ValueError('new_fresh_owner_correlation_required')
    base=root/'.rag_index'/'android-proxy-os-fresh-owner'
    if not base.exists():base.mkdir(mode=0o700)
    fd=old._directory(base);os.close(fd)
    return base/correlation


CONSUMED_REQUEST_PIN = {'generation':[16777234,111494687,534,1791014371065831149,1791014371065831149,384,503,1],'sha256':'e2ea52e200126538b3179d4013e62eb1b70604b6318bed7cbbee77e0af1753d4','bytes':534}

def _retained(root: Path) -> tuple[dict,dict,list]:
    if frozen.regular_pin(Path(frozen.__file__))['sha256']!=FROZEN_SHA:raise ValueError('consumed_helper_file_changed')
    base=root/'.rag_index'/'android-proxy-os-observation'/FAILED
    raw,intent_gen,intent_sha=old.private_snapshot(base/'intent.json',65536);intent=json.loads(raw);intent_bytes=len(raw)
    raw,artifact_gen,artifact_sha=old.private_snapshot(base/'artifact.json',65536);artifact=json.loads(raw);artifact_bytes=len(raw)
    raw,request_gen,request_sha=old.private_snapshot(base/'observe-request.json',65536);request=json.loads(raw);request_bytes=len(raw)
    intent_identity={'generation':intent_gen,'sha256':intent_sha}
    if {'generation':request_gen,'sha256':request_sha,'bytes':len(raw)}!=CONSUMED_REQUEST_PIN:raise ValueError('consumed_observe_request_changed')
    if request.get('correlationId')!=FAILED or request.get('remoteSourceSha256')!=FROZEN_SOURCE_SHA or request.get('originalOutcome')!='unknown' or request.get('intentPin')!=intent_identity or request.get('artifactPin')!={'generation':artifact_gen,'sha256':artifact_sha}:raise ValueError('consumed_observe_binding_changed')
    if artifact.get('intentPin')!=intent_identity or artifact.get('javaSha256')!=frozen.JAVA_SHA or artifact.get('primarySource')!=frozen.PRIMARY or artifact.get('artifactPin',{}).get('path')!=intent.get('artifactPath'):raise ValueError('consumed_compilation_binding_changed')
    if intent.get('correlationId')!=FAILED or intent.get('remoteSourceSha256')!=FROZEN_SOURCE_SHA or intent.get('javaSha256')!=frozen.JAVA_SHA or artifact.get('correlationId')!=FAILED:raise ValueError('failed_compilation_binding_changed')
    inputs=list(intent['localPins'])
    for name,generation,digest,length in (('intent.json',intent_gen,intent_sha,intent_bytes),('artifact.json',artifact_gen,artifact_sha,artifact_bytes),('observe-request.json',request_gen,request_sha,request_bytes)):
        pin=frozen._private_pin(base/name,65536)
        if (pin['generation'],pin['sha256'],pin['bytes'])!=(generation,digest,length):raise ValueError('consumed_snapshot_changed')
        inputs.append(pin)
    for key in ('artifactPin','compilerReceiptPin'):
        pin=artifact[key];actual=frozen._private_pin(Path(pin['path']),16384 if key=='artifactPin' else 65536)
        if any(actual[k]!=pin[k] for k in ('generation','sha256')):raise ValueError('failed_artifact_generation_changed')
        inputs.append(actual)
    failure=root/'.runtime'/'parity-evidence'/'android-current'/'api35-proxy-probe-4f77-receipt.json'
    pin=frozen._private_pin(failure,1048576)
    if pin['sha256']!=FAILED_PIN['sha256'] or pin['bytes']!=FAILED_PIN['bytes']:raise ValueError('failed_private_receipt_changed')
    inputs.append(pin);inputs.append(frozen.regular_pin(Path(__file__)));frozen._guard(inputs)
    return intent,artifact,inputs


def _call(root: Path, directory: Path, original: dict, artifact: dict, inputs: list,
          mode: str, correlation: str, admission: dict | None) -> dict:
    from agent_tools import ssh_transport
    dispatch=original['dispatch'];binding=original['binding'];config=ssh_transport.load_config(root)
    if str(config.hosts[dispatch['host']].fixture_transfer_root)!=dispatch['fixtureRoot'] or ssh_transport.connection_host(config,dispatch['host']).password is not None:raise ValueError('probe_route_changed')
    dex,_,digest=old.private_snapshot(Path(artifact['artifactPin']['path']),16384)
    diagnostic={'diagnosticCorrelationId':correlation,'originalAdapterSha256':binding['adapterSha256'],'diagnosticSourceSha256':hashlib.sha256(remote_source().encode()).hexdigest(),
        'freshOwnerMode':mode,'metadataIdentity':old._OS_METADATA_IDENTITY,'metadataIdentityCapsulePin':{'sha256':old._OS_METADATA_CAPSULE_SHA},
        'probeArtifact':{'correlationId':correlation,'javaSha256':frozen.JAVA_SHA,'artifactSha256':digest,'dexBase64':base64.b64encode(dex).decode(),'primarySource':frozen.PRIMARY}}
    if admission is not None:diagnostic['freshAdmission']=admission
    packet={**dispatch['remote'],'retirementBinding':binding,'diagnosticBinding':diagnostic}
    with old._local_lock(root,dispatch['host'],dispatch['device']) as (lease,guard):
        frozen._guard(inputs);guard()
        lease_pin=frozen._private_pin(lease,1024)
        if {k:lease_pin[k] for k in ('generation','sha256')}!=binding['localLeasePin']:raise ValueError('original_lease_changed')
        inputs=inputs+[lease_pin]
        old._save(directory/'request.json',{'correlationId':correlation,'mode':mode,'sourceSha256':diagnostic['diagnosticSourceSha256'],'admission':admission,'inputPins':inputs,'originalOutcome':'unknown'})
        request_pin=frozen._private_pin(directory/'request.json',65536);inputs+= [request_pin]
        argv=ssh_transport.build_ssh_argv(config,dispatch['host'],60,command=('python3','-I','-B','-c',frozen.source_carrier(remote_source()),'diagnose',dispatch['fixtureRoot'],dispatch['host'],dispatch['device'],dispatch['correlationId'],json.dumps(packet,sort_keys=True,separators=(',',':'))))
        if any(len(x.encode())>=131072 for x in argv):raise ValueError('fresh_owner_transport_argument_bounds')
        frozen._guard(inputs);guard()
        code,out=old.diagnostic_transport(argv,directory/'transport.json',{'correlationId':correlation,'mode':mode,'sourceSha256':diagnostic['diagnosticSourceSha256']})
        frozen._guard(inputs);guard()
    try:value=json.loads(out) if code==0 and len(out)<=16384 else None
    except (ValueError,UnicodeError):value=None
    old._save(directory/'result.json',value if isinstance(value,dict) else {'state':'unknown','originalOutcome':'unknown'})
    if not isinstance(value,dict) or value.get('diagnosticCorrelationId')!=correlation or value.get('admissionCorrelationId')!=frozen.ADMISSION or value.get('state')!='diagnosed':return {'ok':False,'state':'unknown','originalOutcome':'unknown'}
    return {'ok':value.get('errorType') is None,**value,'originalOutcome':'unknown','proxyRestorationPerformed':False}


def admit(root: Path | str, correlation: str) -> dict:
    root=Path(root).resolve();directory=_directory(root,correlation);original,artifact,inputs=_retained(root)
    directory.mkdir(mode=0o700)
    old._save(directory/'intent.json',{'schema':1,'correlationId':correlation,'mode':'admit','original':original,'artifact':artifact,'inputPins':inputs,'sourceSha256':hashlib.sha256(remote_source().encode()).hexdigest(),'originalOutcome':'unknown'})
    inputs+=[frozen._private_pin(directory/'intent.json',65536)]
    return _call(root,directory,original,artifact,inputs,'admit',correlation,None)


def observe(root: Path | str, admission_correlation: str, observation_correlation: str) -> dict:
    root=Path(root).resolve();base=_directory(root,admission_correlation);directory=_directory(root,observation_correlation)
    if admission_correlation==observation_correlation:raise ValueError('separate_observation_required')
    raw,_,_=old.private_snapshot(base/'intent.json',65536);intent=json.loads(raw)
    raw,_,_=old.private_snapshot(base/'result.json',16384);result=json.loads(raw)
    source_sha=hashlib.sha256(remote_source().encode()).hexdigest()
    if intent.get('mode')!='admit' or intent.get('correlationId')!=admission_correlation or intent.get('sourceSha256')!=source_sha or result.get('diagnosticCorrelationId')!=admission_correlation or result.get('errorType') is not None or result.get('currentFailurePhase')!='fresh-owner-admitted' or result.get('state')!='diagnosed' or not isinstance(result.get('freshOwnerAdmission'),dict):raise ValueError('positive_fresh_owner_admission_required')
    inputs=intent['inputPins']+[frozen._private_pin(base/name,65536) for name in ('intent.json','request.json','result.json')]
    frozen._guard(inputs)
    original,artifact,retained=_retained(root);inputs+=retained
    directory.mkdir(mode=0o700)
    admission={'correlationId':admission_correlation,'receiptPin':result['receiptPin']}
    old._save(directory/'intent.json',{'schema':1,'correlationId':observation_correlation,'mode':'observe','admission':admission,'sourceSha256':source_sha,'inputPins':inputs,'originalOutcome':'unknown'})
    inputs+=[frozen._private_pin(directory/'intent.json',65536)]
    return _call(root,directory,original,artifact,inputs,'observe',observation_correlation,admission)


def remote_collector_source() -> str:
    return frozen.remote_collector_source().replace("'proxy-os-final-guard')", "'proxy-os-final-guard','fresh-owner-failed-history-binding','fresh-owner-positive-admission','fresh-owner-closing-admission','fresh-owner-admitted','fresh-owner-observation-final-guard')",1)


def collect(root: Path | str, correlation: str, collection: str, *, kind: str = 'status', offset: int = 0, expected_pin: dict | None = None) -> dict:
    """Read existing fresh-owner admission/observer evidence; no getter replay."""
    from agent_tools import ssh_transport
    root=Path(root).resolve();directory=_directory(root,correlation)
    if not _UUID.fullmatch(collection) or collection==correlation or kind not in ('status','receipt','connectivity') or type(offset) is not int or offset<0 or kind!='status' and not isinstance(expected_pin,dict):raise ValueError('fresh_owner_collection_invalid')
    intent_pin=frozen._private_pin(directory/'intent.json',65536);request_pin=frozen._private_pin(directory/'request.json',65536)
    request=json.loads(old.private_snapshot(directory/'request.json',65536)[0]);sha=hashlib.sha256(remote_source().encode()).hexdigest()
    if request.get('correlationId')!=correlation or request.get('sourceSha256')!=sha:raise ValueError('fresh_owner_collection_source_changed')
    retained=root/'.rag_index'/'android-proxy-os-observation'/FAILED/'intent.json'
    prior_pin=frozen._private_pin(retained,65536);original=json.loads(old.private_snapshot(retained,65536)[0]);dispatch=original['dispatch']
    inputs=[intent_pin,request_pin,prior_pin];frozen._guard(inputs)
    old._save(directory/('collection-'+collection+'.json'),{'correlationId':correlation,'kind':kind,'offset':offset,'expectedPin':expected_pin,'requestPin':request_pin})
    argv=ssh_transport.build_ssh_argv(ssh_transport.load_config(root),dispatch['host'],60,command=('python3','-I','-B','-c','exec('+repr(remote_collector_source())+')',dispatch['fixtureRoot'],correlation,kind,str(offset),json.dumps(expected_pin),sha))
    code,out=old.diagnostic_transport(argv,directory/('collection-'+collection+'-transport.json'),{'correlationId':correlation,'collectionCorrelationId':collection})
    frozen._guard(inputs)
    try:value=json.loads(out) if code==0 and len(out)<=4096 else None
    except (ValueError,UnicodeError):value=None
    result=directory/('collection-'+collection+'-result.json');old._save(result,value if isinstance(value,dict) else {'state':'unknown'})
    if not isinstance(value,dict) or value.get('diagnosticCorrelationId')!=correlation:return {'ok':False,'state':'unknown','resultPath':str(result)}
    return {'ok':value.get('state')!='unknown',**{k:v for k,v in value.items() if k!='chunk'},'resultPath':str(result)}

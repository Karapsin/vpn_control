"""One owned stage retirement after a proved deleted-mount recovery.

This has its own immutable transaction and never promotes an old endpoint journal.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

from agent_tools import android_endpoint_admission as endpoint

# Exact dependencies reviewed with endpoint8274fffd; new definitions/prelude
# require review. Consumed stage requests additionally retain whole-file pins.
_REVIEWED_PRELUDE_SHA = '8aac8c95318813e8d716ace21069f987fe3802eb5cc6d35b6a7f8a7ced3c8762'
_REVIEWED_DEFINITIONS = {'adb_call': '86daf9d044c8bb6640658fa6453e98d03a16a5266760e8e6341b5760547d238d',
 'canonical_rules': '230865df1322ed8c2e2d34fa77588c60d38f4c21290795c71334c99bf52e77dc',
 'checkpoint': 'eaec66bfe9415f7e3ae73a6f14423d3be723fc98307a6e5e60ed938e7be730ba',
 'command': '04426b1c273d586085db41658cc1aaba6b0043ba3fbd1528eb58e29968881a30',
 'command_failure': 'f4025c1b5b4f69dca08925ea734dc0f1fc0d6c2f4cdc97f9f8cd381681049730',
 'command_phase': '169706c3f012339e2035d5e74e2ff9b256698286051c70ec42292fd670e4134f',
 'emit': '584a84a726cef0c37823af3aefbc1babba7d0ae5ca553af761a85b903dc0cc9b',
 'exact_lease_present': 'e03d29b6567f00619e9ccfa092ffa305e70bfaf85bf6f148c16a94224f686060',
 'fixed_principal_preflight': '4c82d26c4be177e74241fe30976f4cde1c2fd0d33cc78ddb353e30e1836e7b26',
 'fixture_routes': '75fe1ebf5cc68ebea009d5f46afe7ed323e5e2b969c25d0d5568a396f786a6cd',
 'guard': '2d0bc39a20abbc26e4e368de78c8d9411c22199eca27c5e5d3e3952679bb180c',
 'host_fixture_leaf': '6f6c565f3464159c374bfbf6d7aea711ca9437d88d4e1e8c0e452c2baa29cdeb',
 'identity': 'ef76ead309f339b9ffd3318038e4004ab6c8df65d24dcb3d1ad5a253caeb9f30',
 'installed': 'cc86e13e232b6b9bcc6bf729b987020cd8ebfaa13d59b9f1ee1dfc534478ad16',
 'lease_lock': '57768a5a9e34a95da484ab6cbd67aa7a3497c52267adf7e5c324f2fcc7b72b23',
 'mount_diagnostic_gate': '51af2d025a216ae2e64a2fb75b8eae3c607ee0e64c46303500aee1614f8342ca',
 'mount_exact': '07d9155fa6f6dedf5b164d9f473a93188e88de9afbc61f9fe3cf04d9da95f759',
 'mount_layout': 'fcc594947d353fbbd62938a688ed0722702d0fa7a354e7ba73a053bed47bcf25',
 'mount_observation_generation': '377e316d2aa8a2690205a01dc8c0a78969b94d88cbf8c6b10471762e5d105728',
 'mount_observation_reader': '13c8fea1b0fbea5915f2b908114a7ff61df3dfe309249402078f5b1397db6e80',
 'mount_observed': '42d5eef050bd6bbc4e20a3a5b8b417217b004975b13bef860dd9058ecd5df84e',
 'mount_target_preflight': 'e859211af806fc12202c74692bf257f400c97d522ccb9e09fcc6d456e86fc42e',
 'namespace_member': '24b522431213963f9bb58fdab52ce7edc3b3d21fbb1ffb66abda5341b4b440bc',
 'principal_extra': '6785e5935a8e25a08a2081c6c5542f233c23b1bd1550171962b69be30c880b4a',
 'private': '3f1ba1615140a07158d1d2ae5d29fced25d70929260379094f3e0575ec5ad504',
 'public': '8dd66000fbd797f31c27cd74f812e0ffa4e7b5181718b667a333572a96107ae0',
 'public_argv': '6c2b094fe97c6d18fb9d22be960d6c23174d1e1f995db26c390c4951d1a1b59f',
 'public_words': '4f3ea32ef3a0ae1f559c6cfb7137fbb372235fe3e81b7d54c11453b7a0951495',
 'readmission_principal_preflight': 'c15ca5e606d4d78e115f28a2ae2e66d7edefe10e8987d55afb84f6dc13f818f2',
 'readmission_public_proof': 'a9fb53a25cb270f9428360af427c2082ecc5408587161d80e28d6c0077817174',
 'readmission_receipt_path': '55d0a35be0db55bef748809cc589b9f720661531700e3da384ac1ffd03ae59da',
 'readmission_records_guard': 'f3742e4ac3d355c93da50eade0fff2855b693b9594d5dd30e75e68c0b41ed428',
 'readmission_snapshot': 'd4cba6717149e79d322c1d1cf4e2bcc28597426760118ed6896525620ca0ac50',
 'readmission_unowned_target_proof': 'c7f491a5ba073542030dac54acdb744c852a6684b414ccc774aec5715560a1fc',
 'record': 'd15c0c0098c93fb9167e00d69df6581ca7674c701e667513099b71ecb78e31e8',
 'recovery_native': 'f5054f4f17409982ceb5428616136c5b73cc8d1d127553085632240a4902d666',
 'recovery_records': 'cd953e7868b61b88154a35048bc0c19e7a3409167c451739d0f193c79e9e2d47',
 'release_lock': '8f61065727d5949cda0af7cfc85953ce8b229d95acb2ad233e87d43173818257',
 'remaining_fp': '171a922e228acdb9e52e15aaedcf0d27312a076d3e5fb23bcb83ed406d76d9e3',
 'remaining_pin': '153673d9cfe1252c2e54f199139debbea5268d0ab991ae0a1a4400e03b79ce36',
 'remaining_records_guard': 'e83a4638e24449fdf84091afa9b5a1046972fb6636e43feb47f084f2fd4cbc81',
 'rooted_public_read': '34f91562961aeae592eb4cd873d64b392b0512987ba3a21d5b1d4c701d6f0750',
 'routes': '41c4814b40f638ae23c46b7c4d9fdbf1ecae80258b06a696f90c7db91e455b1a',
 'shell': 'b4dd6ae82dffb7253a843cb3e71bc57c1e2c4607782c525d66eebf36701a5404',
 'staging_identity': 'eb606865f929f59a432f227cc3f52d5c9ba6aafc63d34f93f9c05658f14be340',
 'step': '3e303f68645001058c6f7fd4c6e003fc75951c65cd0c6e9b7416356abda02353',
 'unknown': 'ead86bd34b7dcba17c2e364210e60f922fe38c946994b6ab1741e1326cd6c554',
 'validate_mount': '3b9977a0f7a5e7330eecd2c995a43c2a80c7a8e9fce4b57732241468f9cbda24',
 'zygote_identity': '5aa2e979da92c6ed758e1041d87e94f4bec2258f7509a030600e5b1f60bdcede'}

_STAGE_REMOTE = r'''
stage_original_evidence='unobserved'
base_emit=emit
def emit(state,reason=None,**extra):
 if isinstance(stage_diagnostic,dict):extra['originalCommandEvidence']=stage_original_evidence
 base_emit(state,reason,**extra)
stage_command_stack=[]
base_command=command
base_command_failure=command_failure
def command(argv,timeout=30,max_bytes=1048576,env=None):
 stage_command_stack.append(list(argv))
 try:return base_command(argv,timeout,max_bytes,env)
 finally:stage_command_stack.pop()
def command_failure(reason,outcome,stderr=b'',public_failure=None,stdout=b'',returncode=None):
 # Nested UID/adapter probes may overwrite the outer command phase. The
 # active stack identifies the actual failing command without changing it.
 if stage_command_stack:step(command_phase(stage_command_stack[-1]))
 if isinstance(stage_binding,dict) and isinstance(stage_binding.get('stageCorrelationId'),str):
  evidence_id=stage_diagnostic.get('correlationId') if isinstance(stage_diagnostic,dict) else stage_binding['stageCorrelationId']
  evidence_path=job/('recovered-stage-'+evidence_id+'.command-failure.json')
  if not os.path.lexists(evidence_path):
   argv=json.dumps(stage_command_stack[-1] if stage_command_stack else [],separators=(',',':')).encode()
   capture={'schema':1,'endpointCorrelationId':correlation,'stageCorrelationId':stage_binding['stageCorrelationId'],'diagnosticCorrelationId':stage_diagnostic.get('correlationId') if isinstance(stage_diagnostic,dict) else None,'sourceSha256':stage_binding.get('sourceSha256'),'originalIntentSha256':recovery.get('originalIntentSha256') if isinstance(recovery,dict) else None,'recoveryCorrelationId':recovery.get('correlationId') if isinstance(recovery,dict) else None,'diagnosticBinding':stage_diagnostic,'argv':base64.b64encode(argv[:2048]).decode(),'argvSha256':hashlib.sha256(argv).hexdigest(),'stdout':base64.b64encode(stdout[:1024]).decode(),'stderr':base64.b64encode(stderr[:1024]).decode(),'stdoutSha256':hashlib.sha256(stdout).hexdigest(),'stderrSha256':hashlib.sha256(stderr).hexdigest(),'truncated':len(argv)>2048 or len(stdout)>1024 or len(stderr)>1024,'phase':diagnostic_phase,'outcome':outcome,'returncode':returncode if type(returncode)is int and -255<=returncode<=255 else None}
   raw=json.dumps(capture,sort_keys=True,separators=(',',':')).encode()
   if len(raw)<=8192:record(evidence_path,capture)
 base_command_failure(reason,outcome,stderr,public_failure)
stage_retired=False
stage_terminal=False
stage_uid='0'
stage_pins={}
stage_receipt=None
stage_lease_pin=None
base_shell=shell
base_exact_lease=exact_lease_present

def stage_pin(path,limit=8192):
 before=path.lstat();raw=private(path,limit);after=path.lstat()
 def fp(s):return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,stat.S_IMODE(s.st_mode),s.st_uid,s.st_nlink]
 if fp(before)!=fp(after):unknown('stage_record_changed')
 return {'fingerprint':fp(after),'sha256':hashlib.sha256(raw).hexdigest()},raw

def stage_records():
 for name,pin in stage_pins.items():
  if stage_pin(pathlib.Path(name))[0]!=pin:unknown('stage_record_changed')
 recovery_records()
 if stage_terminal:
  if os.path.lexists(lease):unknown('stage_lease_present')
 else:
  if exact_lease_present() is None or stage_pin(lease,1024)[0]!=stage_lease_pin:unknown('stage_lease_changed')

def stage_binary():
 info=base_shell('stat','-c','%u:%g:%a:%d:%i:%F','/system/xbin/su')
 digest=base_shell('sha256sum','/system/xbin/su')
 if not re.fullmatch(r'0:2000:4750:[0-9]+:[1-9][0-9]*:regular file',info) or not re.fullmatch(r'[0-9a-f]{64}  /system/xbin/su',digest):unknown('stage_principal_changed')
 return [info,digest]

def shell(*words):
 privileged=stage_uid=='2000' and (words[:1] in (('nsenter',),('/system/bin/nsenter',),('/system/bin/sh',)) or
   words[:1] in (('cat',),('readlink',)) and len(words)==2 and words[1].startswith('/proc/'))
 if not privileged:return base_shell(*words)
 if stage_binary()!=stage_receipt['principal']:unknown('stage_principal_changed')
 result=base_shell('/system/xbin/su','0,0',*words)
 if stage_binary()!=stage_receipt['principal']:unknown('stage_principal_changed')
 return result

def readmission_unowned_target_proof(plan,retired=False):
 # This relaxation exists only in this recovery-bound program; ordinary
 # endpoint admission still requires its own unrelated target mount proof.
 raw=shell('cat','/proc/'+plan['zygote']['pid']+'/mountinfo')
 layout=mount_layout(plan,raw)
 if layout['references']:unknown('stage_mount_referenced')
 if layout['targets']:unknown('stage_target_overlay_present')
 return hashlib.sha256(raw.encode()).hexdigest()

def stage_public():
 readmission_public_proof(stage_uid)

def stage_native():
 return recovery_native(post=True)

def stage_proof():
 stage_records();stage_public();native=stage_native();stage_public();stage_records()
 return native

def stage_dispatch():
 global stage_retired,stage_terminal,stage_uid,stage_receipt,readmission,observed_readmission_owner,expected,readmission_stage_retired,stage_lease_pin,stage_original_evidence
 if not isinstance(stage_binding,dict) or set(stage_binding)!={'schema','stageCorrelationId','action','recoverySha256','sourceSha256','localLease','receipt'} or type(stage_binding['schema']) is not int or stage_binding['schema']!=1 or stage_binding['action'] not in {'admit','cleanup','status','collect','diagnostic'}:unknown('stage_binding_invalid')
 stage_id=stage_binding['stageCorrelationId']
 if not isinstance(stage_id,str) or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',stage_id) or stage_id in {correlation,recovery['correlationId'],recovery['historicalCorrelationId']}:unknown('stage_binding_invalid')
 if stage_binding['recoverySha256']!=hashlib.sha256(json.dumps(recovery['receipt'],sort_keys=True,separators=(',',':')).encode()).hexdigest():unknown('stage_recovery_changed')
 path=job/('recovered-stage-'+stage_id+'.json');attempt=job/('recovered-stage-'+stage_id+'.attempt.json');complete=job/('recovered-stage-'+stage_id+'.complete.json')
 if stage_binding['action']=='status' and not os.path.lexists(lock):unknown('stage_lock_unverified')
 descriptor=lease_lock()
 try:
  recovery_path=job/('mount-recovery-'+recovery['correlationId']+'.json');recovery_complete=job/('mount-recovery-'+recovery['correlationId']+'.complete.json')
  for item in (job/'intent.json',job/'mount-intent.json',job/'stage-owned.json',job/'mount-failure.json',recovery_path,recovery_complete):
   pin,raw=stage_pin(item);stage_pins[str(item)]=pin
  retained=json.loads(private(recovery_path,8192));terminal=json.loads(private(recovery_complete,8192))
  if retained!=recovery['receipt'] or terminal!={'schema':1,'receiptSha256':stage_pins[str(recovery_path)]['sha256'],'post':terminal.get('post')} or not isinstance(terminal['post'],dict):unknown('stage_recovery_changed')
  stage_lease_pin=stage_pin(lease,1024)[0] if os.path.lexists(lease) else None
  opening=retained['snapshot']['public'];expected={**expected,'owner':opening['owner'],'revision':opening['revision']};observed_readmission_owner=opening['owner']
  readmission={**readmission,'receipt':{'snapshot':opening}}
  if stage_binding['action']=='diagnostic':
   if not isinstance(stage_diagnostic,dict) or set(stage_diagnostic)!={'correlationId','requestSha256','currentSourceSha256'} or not all(isinstance(stage_diagnostic.get(key),str) and re.fullmatch(r'[0-9a-f]{64}',stage_diagnostic[key]) for key in ('requestSha256','currentSourceSha256')):unknown('stage_binding_invalid')
   diagnostic_id=stage_diagnostic['correlationId']
   if not isinstance(diagnostic_id,str) or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',diagnostic_id) or diagnostic_id in {stage_id,correlation,recovery['correlationId'],recovery['historicalCorrelationId']}:unknown('stage_binding_invalid')
   if os.path.lexists(attempt) or os.path.lexists(complete):unknown('stage_diagnostic_effect_attempt_present')
   original_capture=job/('recovered-stage-'+stage_id+'.command-failure.json')
   evidence='present' if os.path.lexists(original_capture) else 'unavailable'
   stage_original_evidence=evidence
   if evidence=='present':
    capture=json.loads(private(original_capture,8192))
    if capture.get('schema')!=1 or capture.get('endpointCorrelationId')!=correlation or capture.get('stageCorrelationId')!=stage_id:unknown('stage_record_changed')
   first=readmission_snapshot();second=readmission_snapshot()
   if first!=second or first['owner']!=opening['owner'] or first['revision']!=opening['revision'] or first['rulesSha256']!=opening['rulesSha256']:unknown('stage_public_changed')
   first_native=stage_proof();second_native=stage_proof()
   if first_native!=second_native or second_native!=terminal['post']:unknown('stage_recovery_changed')
   emit('partial','stage_diagnostic_observed',stageCorrelationId=stage_id,originalCommandEvidence=evidence,receiptPresent=os.path.lexists(path))
  if stage_binding['action']=='admit':
   if any(os.path.lexists(item) for item in (path,attempt,complete)):unknown('stage_already_recorded')
   if shell('id','-u')!='0':unknown('stage_requires_root')
   # Only this new immutable admission may discover a replacement owner.
   # The completed recovery's native proof and original full rules remain pins.
   readmission={key:value for key,value in readmission.items() if key!='receipt'};observed_readmission_owner=None
   first=readmission_snapshot()
   if not isinstance(first.get('owner'),str) or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',first['owner']) or type(first.get('revision'))is not int or first['revision']<0 or first['rulesSha256']!=opening['rulesSha256']:unknown('stage_public_changed')
   expected={**expected,'owner':first['owner'],'revision':first['revision']};observed_readmission_owner=first['owner'];readmission={**readmission,'receipt':{'snapshot':first}}
   first_native=stage_proof();second=readmission_snapshot();second_native=stage_proof()
   if first!=second or first_native!=second_native or second_native!=terminal['post']:unknown('stage_recovery_changed')
   principal=stage_binary()
   help_result=subprocess.run([adb,'-s',serial,'shell','-T','/system/xbin/su','--help'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=False)
   if help_result.returncode!=0 or len(help_result.stdout)>4096 or len(help_result.stderr)>4096 or help_result.stdout and help_result.stderr or (help_result.stdout or help_result.stderr).decode('utf-8','strict').strip()!=AOSP_HELP:unknown('stage_principal_changed')
   if stage_binary()!=principal:unknown('stage_principal_changed')
   stage_receipt={'schema':1,'kind':'android-recovered-endpoint-stage','binding':{key:value for key,value in stage_binding.items() if key not in {'action','receipt'}},'records':dict(stage_pins),'snapshot':second,'native':second_native,'principal':principal,'lease':stage_lease_pin}
   record(path,stage_receipt);emit('ready',stageReceipt=stage_receipt)
  stage_receipt=json.loads(private(path,8192))
  if type(stage_receipt.get('schema')) is not int or stage_receipt.get('schema')!=1 or stage_receipt.get('kind')!='android-recovered-endpoint-stage' or stage_receipt!=stage_binding['receipt'] or stage_receipt.get('binding')!={key:value for key,value in stage_binding.items() if key not in {'action','receipt'}} or stage_receipt.get('records')!=stage_pins:unknown('stage_receipt_changed')
  expected={**expected,'owner':stage_receipt['snapshot']['owner'],'revision':stage_receipt['snapshot']['revision']};observed_readmission_owner=expected['owner'];readmission={**readmission,'receipt':{'snapshot':stage_receipt['snapshot']}}
  if stage_lease_pin is not None and stage_lease_pin!=stage_receipt['lease']:unknown('stage_lease_changed')
  stage_lease_pin=stage_receipt['lease']
  receipt_sha=hashlib.sha256(private(path,8192)).hexdigest();stage_pins[str(path)]=stage_pin(path)[0]
  fence={'schema':1,'receiptSha256':receipt_sha}
  if stage_binding['action']=='cleanup':
   if os.path.lexists(attempt) or os.path.lexists(complete):unknown('stage_attempt_already_recorded')
   if readmission_snapshot()!=stage_receipt['snapshot'] or stage_proof()!=stage_receipt['native']:unknown('stage_receipt_stale')
   record(attempt,fence);stage_pins[str(attempt)]=stage_pin(attempt)[0]
   if readmission_snapshot()!=stage_receipt['snapshot'] or stage_proof()!=stage_receipt['native']:unknown('stage_receipt_stale')
   shell('rm','-r',stage_receipt['snapshot']['mount']['staging']);stage_retired=True;readmission_stage_retired=True
   if stage_proof()!=stage_receipt['native']:unknown('stage_retirement_unverified')
   adb_call('unroot',timeout=30);adb_call('wait-for-device',timeout=30);stage_uid='2000'
   first=stage_proof();second=stage_proof()
   if first!=second or second!=stage_receipt['native']:unknown('stage_terminal_unverified')
   record(complete,{'schema':1,'receiptSha256':receipt_sha,'native':second,'records':dict(stage_pins)})
   # Release only the pinned original lease after immutable terminal proof.
   complete_pin=stage_pin(complete)[0]
   lease_pin=stage_pin(lease,1024)[0];stage_records();stage_proof()
   if stage_pin(complete)[0]!=complete_pin:unknown('stage_terminal_changed')
   if stage_pin(lease,1024)[0]!=lease_pin:unknown('stage_lease_changed')
   lease.unlink();stage_terminal=True
   emit('cleaned',stageCorrelationId=stage_id,terminalSha256=hashlib.sha256(private(complete,8192)).hexdigest(),terminalFingerprint=stage_pin(complete)[0]['fingerprint'])
  if not os.path.lexists(attempt):
   if readmission_snapshot()!=stage_receipt['snapshot'] or stage_proof()!=stage_receipt['native']:unknown('stage_receipt_stale')
   emit('partial','stage_ready',stageCorrelationId=stage_id)
  if json.loads(private(attempt,1024))!=fence:unknown('stage_receipt_changed')
  stage_pins[str(attempt)]=stage_pin(attempt)[0]
  if not os.path.lexists(complete):unknown('stage_attempt_uncertain')
  complete_pin,complete_raw=stage_pin(complete);marker=json.loads(complete_raw)
  if type(marker.get('schema')) is not int or marker.get('schema')!=1 or marker.get('receiptSha256')!=receipt_sha or marker.get('native')!=stage_receipt['native'] or marker.get('records')!=stage_pins:unknown('stage_terminal_changed')
  stage_retired=True;readmission_stage_retired=True;stage_uid='2000';stage_terminal=not os.path.lexists(lease)
  first=stage_proof();second=stage_proof()
  if first!=second or second!=stage_receipt['native']:unknown('stage_terminal_unverified')
  if not stage_terminal:
   if stage_binding['action']!='collect':unknown('stage_lease_present')
   stage_records();stage_proof()
   if stage_pin(complete)[0]!=complete_pin:unknown('stage_terminal_changed')
   if stage_pin(lease,1024)[0]!=stage_lease_pin:unknown('stage_lease_changed')
   lease.unlink();stage_terminal=True
  emit('cleaned',stageCorrelationId=stage_id,terminalSha256=hashlib.sha256(private(complete,8192)).hexdigest(),terminalFingerprint=stage_pin(complete)[0]['fingerprint'])
 finally:release_lock(descriptor)
'''


def _dependency_parts(source: str):
    """Retain executed prelude and statically referenced function definitions."""
    marker="try:\n item=job.lstat()"
    if source.count(marker)!=1:raise ValueError('Endpoint dispatch boundary changed')
    prefix=source[:source.index(marker)]
    tree=ast.parse(prefix)
    definitions={node.name:node for node in tree.body if isinstance(node,ast.FunctionDef)}
    if any(node.decorator_list for node in definitions.values()):
        raise ValueError('Endpoint decorated definition changed')
    if len(definitions)!=sum(isinstance(node,ast.FunctionDef) for node in tree.body):
        raise ValueError('Endpoint definitions duplicated')
    if any(isinstance(node,(ast.ClassDef,ast.AsyncFunctionDef)) for node in tree.body):
        raise ValueError('Endpoint definition kind changed')
    prelude=[node for node in tree.body if not isinstance(node,ast.FunctionDef)]
    loads=lambda node:{item.id for item in ast.walk(node) if isinstance(item,ast.Name) and isinstance(item.ctx,ast.Load)}
    roots=[ast.parse(_STAGE_REMOTE),*prelude]
    needed=set().union(*(loads(node) for node in roots)) & definitions.keys()
    while True:
        expanded=needed | set().union(*(loads(definitions[name]) for name in needed)) & definitions.keys()
        if expanded==needed:break
        needed=expanded
    # No dynamic global lookup is admitted into this statically selected program.
    # Attribute access to known modules (e.g. os.O_NOFOLLOW) is covered by the
    # exact reviewed source segment; it cannot choose another global definition.
    for node in [*prelude,*(definitions[name] for name in needed)]:
        for call in ast.walk(node):
            if isinstance(call,ast.Call) and isinstance(call.func,ast.Name) and call.func.id in {'eval','exec','globals','locals'}:
                raise ValueError('Endpoint dynamic global lookup changed')
    # AST columns are UTF-8 byte offsets. Build line offsets once; repeated
    # get_source_segment scans the entire large program for every definition.
    raw=prefix.encode();lines=raw.splitlines(keepends=True);offsets=[0]
    for line in lines:offsets.append(offsets[-1]+len(line))
    segment=lambda node:raw[offsets[node.lineno-1]+node.col_offset:offsets[node.end_lineno-1]+node.end_col_offset].decode()
    prelude_source='\n'.join(segment(node) for node in prelude)+'\n'
    selected={name:segment(definitions[name]) for name in sorted(needed)}
    ordered='\n'.join(segment(node) for node in tree.body if not isinstance(node,ast.FunctionDef) or node.name in needed)+'\n'
    return prelude_source,selected,ordered


def _reviewed_prefix(source: str) -> str:
    prelude,definitions,ordered=_dependency_parts(source)
    digest=lambda value:hashlib.sha256(value.encode()).hexdigest()
    if digest(prelude)!=_REVIEWED_PRELUDE_SHA or {name:digest(code) for name,code in definitions.items()}!=_REVIEWED_DEFINITIONS:
        raise ValueError('Reviewed endpoint dependency changed')
    return ordered


def _replace_once(source: str, before: str, after: str) -> str:
    if source.count(before)!=1:raise ValueError('Reviewed stage rewrite changed')
    return source.replace(before,after,1)


def _remote_source() -> str:
    source = _reviewed_prefix(endpoint._REMOTE)
    source = _replace_once(source,"recovery=expected.pop('cleanupRecovery',None)", "stage_binding=expected.pop('recoveredStageCleanup',None)\nstage_diagnostic=expected.pop('recoveredStageDiagnostic',None)\nrecovery=expected.pop('cleanupRecovery',None)")
    source = _replace_once(source,"or exact_lease_present() is None: unknown('recovery_original_changed')", "or (not stage_terminal and exact_lease_present() is None): unknown('recovery_original_changed')")
    native_node=next(node for node in ast.parse(source).body if isinstance(node,ast.FunctionDef) and node.name=='recovery_native')
    native=ast.get_source_segment(source,native_node)
    original_native=native
    native=_replace_once(native,"identity('0');installed()", "identity(stage_uid);installed()")
    opening="if staging_identity(current['staging'])!=current['stagingIdentity'] or shell('sha256sum',current['staging']+'/'+expected['caStoreName']).split()!=[expected['caSha256'],current['staging']+'/'+expected['caStoreName']]: unknown('recovery_current_stage_changed')"
    native=_replace_once(native,opening,"if not stage_retired and (staging_identity(current['staging'])!=current['stagingIdentity'] or shell('sha256sum',current['staging']+'/'+expected['caStoreName']).split()!=[expected['caSha256'],current['staging']+'/'+expected['caStoreName']]): unknown('recovery_current_stage_changed')")
    closing="if staging_identity(current['staging'])!=current['stagingIdentity'] or shell('sha256sum',current['staging']+'/'+expected['caStoreName']).split()!=[expected['caSha256'],current['staging']+'/'+expected['caStoreName']] or shell('cat','/proc/'+old['zygote']['pid']+'/mountinfo')!=raw:"
    native=_replace_once(native,closing,"if (not stage_retired and (staging_identity(current['staging'])!=current['stagingIdentity'] or shell('sha256sum',current['staging']+'/'+expected['caStoreName']).split()!=[expected['caSha256'],current['staging']+'/'+expected['caStoreName']])) or shell('cat','/proc/'+old['zygote']['pid']+'/mountinfo')!=raw:")
    native=_replace_once(native,"result=subprocess.run([adb,'-s',serial,'shell','-T',*ns", "result=subprocess.run([adb,'-s',serial,'shell','-T',*(['/system/xbin/su','0,0'] if stage_uid=='2000' else []),*ns")
    native=_replace_once(native," raw=shell('cat'", " if stage_retired:\n  for prefix in ([],ns):\n   absence='if [ -e '+shlex.quote(current['staging'])+' ] || [ -L '+shlex.quote(current['staging'])+' ]; then echo present; else echo absent; fi'\n   outer=' '.join(shlex.quote(word) for word in [*prefix,'/system/bin/sh','-c',absence])\n   if shell('/system/bin/sh','-c',shlex.quote(outer))!='absent':unknown('stage_retirement_unverified')\n raw=shell('cat'")
    source=_replace_once(source,original_native,native)
    source=_replace_once(source,"command_failure('command_failed','nonzero',result.stderr,failure)","command_failure('command_failed','nonzero',result.stderr,failure,result.stdout,result.returncode)")
    return source+_STAGE_REMOTE+"\ntry:\n item=job.lstat()\n if not stat.S_ISDIR(item.st_mode) or item.st_uid!=os.getuid() or stat.S_IMODE(item.st_mode)!=0o700:unknown('job_unsafe')\n remote_intent_raw=private(job/'intent.json',8192)\n if json.loads(remote_intent_raw)!=stored_expected:unknown('intent_changed')\n stage_dispatch()\nexcept (OSError,ValueError,KeyError,TypeError,IndexError):unknown('stage_unverified')\n"


def _remote(root: Path, intent: dict[str, Any], action: str) -> dict[str, Any]:
    config=endpoint.ssh_transport.load_config(root)
    host=intent['host']
    if endpoint.ssh_transport.connection_host(config,host).password is not None or str(config.hosts[host].fixture_transfer_root)!=intent['remoteRoot']:
        raise ValueError('Stage transport changed')
    command=endpoint._endpoint_python_command(endpoint.android_observation._canonical_cli_environment_source()+_remote_source(), 'recovery-status',intent['remoteRoot'],intent['device'],intent['correlationId'],json.dumps(intent['remote'],sort_keys=True,separators=(',',':')))
    argv=endpoint.ssh_transport.build_ssh_argv(config,host,60,command=command)
    if max(len(x.encode()) for x in argv)>=65536:raise ValueError('Stage transport argument exceeded')
    code,out=endpoint.android_observation._run_probe(argv,_transport_budget(action))
    value=json.loads(out) if code==0 else {}
    if not isinstance(value,dict) or value.get('correlationId')!=intent['correlationId']:raise ValueError('Stage response unverified')
    return value


def _transport_budget(action: str) -> int:
    profiles=endpoint._READMISSION_COMMAND_BOUNDS
    seconds=lambda name:sum(t*n for t,n in profiles[name].items())
    # stage_proof calls two public proofs and one native proof. Cleanup calls
    # it twice before rm, once before unroot, twice after, once before unlink.
    # A shell native observation verifies su stat/hash before and after each
    # privileged command: at most five commands per existing native command.
    # Two added absent-stage probes have the same five-command bound.
    native=profiles['recovery-native']
    shell_native=5*(native[30]+2)*30+native[10]
    proofs={'admit':2,'cleanup':6,'status':2,'collect':3,'diagnostic':2}[action]
    snapshots={'admit':2,'cleanup':2,'status':1,'collect':1,'diagnostic':2}[action]
    return 60+snapshots*seconds('root-snapshot')+proofs*(2*seconds('root-public')+shell_native)+3*30+10


def _validate_admitted_receipt(receipt, requested, recovery, intent):
    if not isinstance(receipt,dict) or set(receipt)!={'schema','kind','binding','records','snapshot','native','principal','lease'} or type(receipt.get('schema')) is not int or receipt['schema']!=1 or receipt['kind']!='android-recovered-endpoint-stage' or receipt['binding']!=requested:
        raise ValueError('Stage receipt envelope invalid')
    snapshot=receipt['snapshot'];native=receipt['native'];opening=recovery['snapshot']
    if (not isinstance(snapshot,dict) or not isinstance(native,dict) or set(native)!=set(opening['native']) or
        not isinstance(snapshot.get('owner'),str) or not endpoint._UUID.fullmatch(snapshot['owner']) or
        type(snapshot.get('revision')) is not int or snapshot['revision']<0 or snapshot.get('uid')!='0' or
        type(snapshot.get('api')) is not int or snapshot['api']!=29 or snapshot.get('avd')!=intent['remote']['avd'] or
        snapshot.get('abi')!='x86_64' or snapshot.get('reversePorts')!=[] or snapshot.get('namespaceObservation')!='verified' or
        snapshot.get('mountObservation')!='owned-stage-unreferenced' or snapshot.get('rulesSha256')!=opening['public']['rulesSha256'] or
        native.get('historicalRecords')!=opening['native']['historicalRecords'] or native.get('historicalMount')!=opening['native']['historicalMount'] or
        native.get('currentMount')!=opening['native']['currentMount'] or snapshot.get('mount')!=native.get('currentMount') or native.get('targetEntry') is not None or
        not isinstance(native.get('mountinfoSha256'),str) or not endpoint._SHA.fullmatch(native['mountinfoSha256']) or snapshot.get('unownedTargetMountsSha256')!=native['mountinfoSha256']):
        raise ValueError('Stage admitted snapshot invalid')
    identity=native.get('targetIdentity');original=opening['native']['historicalMount']['stagingIdentity'].split(':')[2:]
    if not isinstance(identity,list) or len(identity)!=4 or identity[3]!='directory' or any(not isinstance(x,str) or not x.isdecimal() for x in identity[:3]) or int(identity[2])<1 or identity[:2]==original:
        raise ValueError('Stage admitted target invalid')
    principal=receipt['principal']
    if not isinstance(principal,list) or len(principal)!=2 or not all(isinstance(x,str) for x in principal) or not endpoint.re.fullmatch(r'0:2000:4750:[0-9]+:[1-9][0-9]*:regular file',principal[0]) or not endpoint.re.fullmatch(r'[0-9a-f]{64}  /system/xbin/su',principal[1]):
        raise ValueError('Stage admitted principal invalid')
    job=intent['remoteRoot']+'/android-endpoint-'+intent['correlationId']
    names={'intent.json','mount-intent.json','stage-owned.json','mount-failure.json','mount-recovery-'+recovery['binding']['correlationId']+'.json','mount-recovery-'+recovery['binding']['correlationId']+'.complete.json'}
    if not isinstance(receipt['records'],dict) or set(receipt['records'])!={job+'/'+name for name in names}:
        raise ValueError('Stage record paths invalid')
    for pin in [*receipt['records'].values(),receipt['lease']]:
        if not isinstance(pin,dict) or set(pin)!={'fingerprint','sha256'} or not isinstance(pin['sha256'],str) or not endpoint._SHA.fullmatch(pin['sha256']) or not isinstance(pin['fingerprint'],list) or len(pin['fingerprint'])!=8 or any(type(x)is not int or x<0 for x in pin['fingerprint']) or pin['fingerprint'][5]!=0o600 or pin['fingerprint'][7]!=1:
            raise ValueError('Stage private generation invalid')


def _call(root: Path | str, correlation_id: str, historical_id: str, recovery_id: str,
          stage_id: str, action: str, diagnostic_id: str | None = None) -> dict[str, Any]:
    root=Path(root).resolve()
    ids=(correlation_id,historical_id,recovery_id,stage_id)
    if diagnostic_id is not None and (not isinstance(diagnostic_id,str) or not endpoint._UUID.fullmatch(diagnostic_id) or diagnostic_id in ids):raise ValueError('Stage diagnostic requires a fifth distinct canonical correlation')
    if not all(isinstance(x,str) and endpoint._UUID.fullmatch(x) for x in ids) or len(set(ids))!=4:
        raise ValueError('Stage cleanup requires four distinct canonical correlations')
    extra={'stageCorrelationId':stage_id,'recoveryCorrelationId':recovery_id,'replayAllowed':False,'observationOnly':action in {'status','diagnostic'}}
    if diagnostic_id is not None:extra['diagnosticCorrelationId']=diagnostic_id
    directory=root/'.rag_index/android-endpoint-admission'
    original=directory/(correlation_id+'.json')
    try:
        original_pin=endpoint._recovery_local_snapshot(original)
        intent=original_pin[0]
        local_lock=root/'.rag_index/android-native-device-leases'/('lock-'+intent['host']+'-'+intent['device']+'.json')
        if action=='status' and not os.path.lexists(local_lock):raise ValueError('Stage lock absent')
        with endpoint._shared_device_lease(root,intent['host'],intent['device']):
            if endpoint._recovery_local_snapshot(original)!=original_pin:raise ValueError('Stage original generation changed')
            return _call_locked(root,ids,action,extra,diagnostic_id)
    except (OSError,RuntimeError,ValueError,KeyError,TypeError):
        return endpoint._response('unknown',correlation_id,'stage_local_unverified',**extra)


def _call_locked(root,ids,action,extra,diagnostic_id=None):
    # Reject unreviewed dependencies or rewrite drift before consuming a request
    # or a cleanup fence. Old requests keep their complete source generation pins.
    _remote_source()
    correlation_id,historical_id,recovery_id,stage_id=ids
    directory=root/'.rag_index/android-endpoint-admission'
    paths=[directory/(correlation_id+'.json'),directory/(historical_id+'.json'),directory/('mount-recovery-'+recovery_id+'.request.json'),directory/('mount-recovery-'+recovery_id+'.json'),directory/('mount-recovery-'+recovery_id+'.attempt.json')]
    pins=[endpoint._recovery_local_snapshot(path) for path in paths]
    intent,old,request,recovery,attempt=[pin[0] for pin in pins]
    if intent.get('correlationId')!=correlation_id or old.get('correlationId')!=historical_id:
        raise ValueError('Stage originals changed')
    recovery_binding={'correlationId':recovery_id,'historicalCorrelationId':historical_id,'originalIntentSha256':pins[0][1],'historicalIntentSha256':pins[1][1],'historicalExpected':old['remote']}
    if request!={'schema':1,'endpointCorrelationId':correlation_id,'binding':recovery_binding} or recovery.get('binding')!=recovery_binding or attempt!={'schema':1,'receiptSha256':pins[3][1]}:
        raise ValueError('Stage recovery binding changed')
    source_paths=(Path(endpoint.__file__),Path(__file__))
    def source_pin(path):
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise ValueError('Stage source unsafe')
        raw=path.read_bytes();after=path.lstat()
        fp=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns,stat.S_IMODE(x.st_mode),x.st_uid,x.st_nlink)
        if fp(info)!=fp(after):raise ValueError('Stage source generation changed')
        return {'sha256':hashlib.sha256(raw).hexdigest(),'fingerprint':list(fp(after))}
    source_pins=[source_pin(path) for path in source_paths]
    source_sha=hashlib.sha256(json.dumps(source_pins,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    local_lease=root/'.rag_index/android-native-device-leases'/('lease-'+intent['host']+'-'+intent['device']+'.json')
    terminal_path=directory/('recovered-stage-'+stage_id+'.complete.json')
    lease_pin=endpoint._recovery_local_snapshot(local_lease) if os.path.lexists(local_lease) else None
    local_terminal=endpoint._recovery_local_snapshot(terminal_path) if os.path.lexists(terminal_path) else None
    anchor_path=directory/('recovered-stage-'+stage_id+'.collected.json')
    anchor=endpoint._recovery_local_snapshot(anchor_path) if os.path.lexists(anchor_path) else None
    if anchor is not None and (local_terminal is None or anchor[0]!={'schema':1,'terminalSha256':local_terminal[1],'terminalFingerprint':list(local_terminal[2])}):raise ValueError('Stage terminal generation changed')
    if lease_pin is None and anchor is None:raise ValueError('Stage terminal anchor absent')
    if lease_pin is None and (action not in {'status','collect'} or action=='status' and local_terminal is None):raise ValueError('Stage lease absent')
    endpoint._readmission_local_guard(root,intent,local_lease,terminal=lease_pin is None)
    request_path=directory/('recovered-stage-'+stage_id+'.request.json')
    claimed_lease={'sha256':lease_pin[1],'fingerprint':list(lease_pin[2])} if lease_pin is not None else None
    if action!='admit':
        original_claim=endpoint._recovery_local_snapshot(request_path)[0].get('localLease')
        if claimed_lease is not None and claimed_lease!=original_claim:raise ValueError('Stage local lease generation changed')
        claimed_lease=original_claim
    current_source_sha=source_sha
    if action=='diagnostic':source_sha=endpoint._recovery_local_snapshot(request_path)[0]['sourceSha256']
    if not isinstance(source_sha,str) or not endpoint._SHA.fullmatch(source_sha):raise ValueError('Stage original source binding invalid')
    requested={'schema':1,'stageCorrelationId':stage_id,'recoverySha256':hashlib.sha256(json.dumps(recovery,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'sourceSha256':source_sha,'localLease':claimed_lease}
    receipt_path=directory/('recovered-stage-'+stage_id+'.json')
    fence_path=directory/('recovered-stage-'+stage_id+'.attempt.json')
    if action=='admit':
        if any(os.path.lexists(p) for p in (request_path,receipt_path,fence_path,terminal_path)):
            return endpoint._response('unknown',correlation_id,'stage_already_recorded',**extra)
        endpoint.android_native_fixture.write_private_plan(request_path,requested)
    request_pin=endpoint._recovery_local_snapshot(request_path)
    if request_pin[0]!=requested:raise ValueError('Stage request changed')
    receipt_pin=endpoint._recovery_local_snapshot(receipt_path) if action not in {'admit','diagnostic'} or action=='diagnostic' and os.path.lexists(receipt_path) else None
    if receipt_pin is not None and receipt_pin[0].get('binding')!=requested:raise ValueError('Stage receipt binding')
    if action=='cleanup':
        if os.path.lexists(fence_path):return endpoint._response('unknown',correlation_id,'stage_attempt_already_recorded',**extra)
        endpoint.android_native_fixture.write_private_plan(fence_path,{'schema':1,'receiptSha256':receipt_pin[1]})
    fence_pin=endpoint._recovery_local_snapshot(fence_path) if os.path.lexists(fence_path) else None
    if fence_pin is not None and (receipt_pin is None or fence_pin[0]!={'schema':1,'receiptSha256':receipt_pin[1]}):raise ValueError('Stage fence changed')
    def guard():
        if pins!=[endpoint._recovery_local_snapshot(path) for path in paths] or source_pins!=[source_pin(path) for path in source_paths] or request_pin!=endpoint._recovery_local_snapshot(request_path):raise ValueError('Stage generation changed')
        if receipt_pin is not None and receipt_pin!=endpoint._recovery_local_snapshot(receipt_path):raise ValueError('Stage receipt changed')
        if fence_pin is not None and fence_pin!=endpoint._recovery_local_snapshot(fence_path):raise ValueError('Stage fence changed')
        if local_terminal is not None and local_terminal!=endpoint._recovery_local_snapshot(terminal_path):raise ValueError('Stage terminal changed')
        if anchor is not None and anchor!=endpoint._recovery_local_snapshot(anchor_path):raise ValueError('Stage terminal anchor changed')
        if lease_pin is not None:
            if lease_pin!=endpoint._recovery_local_snapshot(local_lease):raise ValueError('Stage lease changed')
            endpoint._readmission_local_guard(root,intent,local_lease)
        else:endpoint._readmission_local_guard(root,intent,local_lease,terminal=True)
        for parent in (correlation_id,historical_id):
            if endpoint._runtime_parent_correlation(root,parent) is not None:raise ValueError('Stage runtime child')
    guard()
    binding={**requested,'action':action,'receipt':receipt_pin[0] if receipt_pin else None}
    dispatch={**intent,'remote':{**intent['remote'],'cleanupRecovery':{**recovery_binding,'receipt':recovery},'recoveredStageCleanup':binding}}
    if action=='diagnostic':dispatch['remote']['recoveredStageDiagnostic']={'correlationId':diagnostic_id,'requestSha256':request_pin[1],'currentSourceSha256':current_source_sha}
    value=_remote(root,dispatch,action);guard()
    if value.get('correlationId')!=correlation_id:raise ValueError('Stage response correlation')
    if action=='admit' and value.get('state')=='ready':
        receipt=value.get('stageReceipt')
        _validate_admitted_receipt(receipt,requested,recovery,intent)
        endpoint.android_native_fixture.write_private_plan(receipt_path,receipt)
        return endpoint._response('ready',correlation_id,stageOnly=True,**extra)
    if value.get('state')=='cleaned' and value.get('stageCorrelationId')==stage_id:
        sha=value.get('terminalSha256');fingerprint=value.get('terminalFingerprint')
        if not isinstance(sha,str) or not endpoint._SHA.fullmatch(sha) or not isinstance(fingerprint,list) or len(fingerprint)!=8 or any(type(x)is not int for x in fingerprint):raise ValueError('Stage terminal pin invalid')
        complete={'schema':1,'receiptSha256':receipt_pin[1],'remoteSha256':sha,'remoteFingerprint':fingerprint,'sourceSha256':source_sha}
        if local_terminal is None:
            if action not in {'cleanup','collect'}:raise ValueError('Uncollected stage terminal')
            endpoint.android_native_fixture.write_private_plan(terminal_path,complete)
            published_terminal=endpoint._recovery_local_snapshot(terminal_path)
        else:published_terminal=local_terminal
        if published_terminal[0]!=complete:raise ValueError('Stage terminal changed')
        anchored={'schema':1,'terminalSha256':published_terminal[1],'terminalFingerprint':list(published_terminal[2])}
        if anchor is None:
            endpoint.android_native_fixture.write_private_plan(anchor_path,anchored)
            published_anchor=endpoint._recovery_local_snapshot(anchor_path)
        else:published_anchor=anchor
        if published_anchor[0]!=anchored:raise ValueError('Stage terminal anchor binding changed')
        # Immediate generation/hash guard under the held shared lock, only
        # after the remote immutable terminal proof, retires this exact lease.
        guard()
        if endpoint._recovery_local_snapshot(terminal_path)!=published_terminal or endpoint._recovery_local_snapshot(anchor_path)!=published_anchor:raise ValueError('Stage terminal generation changed')
        if lease_pin is not None:
            if endpoint._recovery_local_snapshot(local_lease)!=lease_pin:raise ValueError('Stage lease generation changed')
            local_lease.unlink()
        return endpoint._response('cleaned',correlation_id,device={'uid':'2000','api':29,'avd':intent['remote']['avd']},stageOnly=True,**extra)
    if action=='diagnostic' and value.get('state')=='partial' and value.get('reason')=='stage_diagnostic_observed' and value.get('stageCorrelationId')==stage_id and value.get('originalCommandEvidence') in {'present','unavailable'} and type(value.get('receiptPresent')) is bool:
        return endpoint._response('partial',correlation_id,'stage_diagnostic_observed',originalCommandEvidence=value['originalCommandEvidence'],receiptPresent=value['receiptPresent'],**extra)
    if action=='diagnostic' and value.get('originalCommandEvidence') in {'unobserved','unavailable','present'}:extra['originalCommandEvidence']=value['originalCommandEvidence']
    reason=value.get('reason')
    allowed={'stage_ready','stage_already_recorded','stage_attempt_already_recorded','stage_attempt_uncertain','stage_record_changed','stage_binding_invalid','stage_recovery_changed','stage_requires_root','stage_public_changed','stage_receipt_changed','stage_receipt_stale','stage_retirement_unverified','stage_terminal_unverified','stage_lease_changed','stage_lease_present','stage_principal_changed','stage_mount_referenced','stage_target_overlay_present','stage_terminal_changed','stage_unverified','stage_diagnostic_effect_attempt_present'}
    return endpoint._response('partial' if value.get('state')=='partial' and reason=='stage_ready' else 'unknown',correlation_id,reason if reason in allowed else endpoint._readmission_reason(reason),**extra,**endpoint._bounded_readmission_diagnostics(value))


def admit(root,correlation_id,historical_id,recovery_id,stage_id):
    return _call(root,correlation_id,historical_id,recovery_id,stage_id,'admit')


def cleanup_once(root,correlation_id,historical_id,recovery_id,stage_id):
    return _call(root,correlation_id,historical_id,recovery_id,stage_id,'cleanup')


def status(root,correlation_id,historical_id,recovery_id,stage_id):
    return _call(root,correlation_id,historical_id,recovery_id,stage_id,'status')


def collect(root,correlation_id,historical_id,recovery_id,stage_id):
    return _call(root,correlation_id,historical_id,recovery_id,stage_id,'collect')


def diagnostic(root,correlation_id,historical_id,recovery_id,stage_id,diagnostic_id):
    return _call(root,correlation_id,historical_id,recovery_id,stage_id,'diagnostic',diagnostic_id)

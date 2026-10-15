"""New orphan observation admitted by one measured exact SSH-G warning.

The consumed observer and diagnostic remain immutable. Remote source changes
only ssh_options by adding -T. All original orphan guards remain byte-for-byte.
The new operation binds their exact measured result and all historical leaf
pins; fresh ancestry pins describe this separately reviewed operation after the
new companion was added, never a reinterpretation of consumed parent history.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
from contextlib import ExitStack
from agent_tools import ssh_nested_socket_retirement as frozen
from agent_tools import ssh_nested_socket_route_diagnostic as diagnostic
from agent_tools import ssh_transport as transport, ssh_recovery_adoption as adoption, ssh_connection_session as session
from agent_tools.private_inventory_lock import Directory,Snapshot,InventoryLock,lock_directory

FROZEN_SHA='356985224da09aa4306e0c018b5afd92a86f018312df34bc68685d7da6188731'
DIAGNOSTIC_SHA='d23217e1c64f3fd74fb049a721945885acabb3e82774a2eeb3ee32870d736160'
REMOTE_SHA='a77429b890a4aec4a325a640d010f7d1bbfe151729b1826d09777f5bf5d93bc7'
DIAGNOSTIC_REMOTE_SHA='e2a969fa4ae0b0155d3f3d996dec9e8f871413ef87debe3bfcdc5995bda9700c'
MEASURED='a4cffd8a-f795-440b-8e95-432eeb5b9455'
MEASURED_PINS={
 'intent.json':{'generation':[16777234,111541485,33152,503,20,1,11398,1791024458959246541,1791024458959246541],'size':11398,'sha256':'5cb6ea5c86f7097bee43ff42d7c239ec23b8502a36f16af6a80cec2957ceb9b3'},
 'result.json':{'generation':[16777234,111541488,33152,503,20,1,7185,1791024459211597263,1791024459211597263],'size':7185,'sha256':'ec06ca7e23555150fa183951bc87e66a01ca172ce29a2298f6bfd5c96c41e8c2'}}
OUTPUT_PINS={'stdout':{'bytes':4245,'sha256':'3d783807b7d1d1ebcdb49a109c2214415a7c432c5586c9c74a3362c984a8a1cc'},
             'stderr':{'bytes':72,'sha256':'d0e14941dee288cc8de19e48436cdf3c2e7939d4b98136c44d954b5f8be73d8a'}}


def remote_source():
    if frozen.file_pin(Path(frozen.__file__),body=True)['sha256']!=FROZEN_SHA:raise ValueError('consumed_observer_changed')
    source=frozen.remote_source()
    if hashlib.sha256(source.encode()).hexdigest()!=REMOTE_SHA:raise ValueError('consumed_remote_changed')
    old="return ['ssh','-F',spec['configFile']";new="return ['ssh','-T','-F',spec['configFile']"
    if source.count(old)!=1:raise ValueError('noninteractive_rewrite_count_changed')
    return source.replace(old,new,1)


def measured_value(intent,result):
    if intent.get('correlationId')!=MEASURED or intent.get('failedCorrelationId')!=diagnostic.FAILED or intent.get('remoteSourceSha256')!=DIAGNOSTIC_REMOTE_SHA or intent.get('observerRetried')is not False or intent.get('mutationPerformed')is not False:
        raise ValueError('measured_intent_changed')
    if result.get('correlationId')!=MEASURED or result.get('remoteSourceSha256')!=DIAGNOSTIC_REMOTE_SHA or result.get('intent')!=MEASURED_PINS['intent.json'] or result.get('host')!=intent.get('host'):
        raise ValueError('measured_result_changed')
    value=result['result']
    if value.get('state')!='fixed-route-diagnostic' or type(value.get('returnCode'))is not int or value['returnCode']!=0 or value.get('category')!='exact-nonterminal-warning' or value.get('fixedArgsWithoutTTYOverride')is not True or value.get('observerRetried')is not False or value.get('mutationPerformed')is not False:
        raise ValueError('measured_warning_not_positive')
    for name,expected in OUTPUT_PINS.items():
        cap=value[name];raw=base64.b64decode(cap['base64'],validate=True)
        if cap!=diagnostic.captured(raw) or {k:cap[k] for k in ('bytes','sha256')}!=expected:raise ValueError('measured_capture_changed')
    if base64.b64decode(value['stderr']['base64'],validate=True)!=diagnostic.WARNING:raise ValueError('measured_warning_changed')
    return value


def observe(root: Path|str,host: str,correlation: str) -> dict:
    if not isinstance(correlation,str) or not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',correlation) or correlation in (MEASURED,diagnostic.FAILED):raise ValueError('new_observation_uuid_required')
    root=Path(root).resolve(strict=True)
    with ExitStack() as stack:
        directory=stack.enter_context(Directory(root));receipts=stack.enter_context(lock_directory(directory));ownership=stack.enter_context(InventoryLock(receipts))
        source=stack.enter_context(Snapshot(directory,transport.CONFIG_FILENAME));stack.source=source
        group=root/'.rag_index/ssh-nested-socket-noninteractive-observation';group.mkdir(mode=0o700,exist_ok=True)
        group_directory=stack.enter_context(Directory(group));journal=group/correlation;journal.mkdir(mode=0o700);output=stack.enter_context(Directory(journal))
        measured_dir=stack.enter_context(Directory(root/'.rag_index/ssh-nested-socket-route-diagnostic'/MEASURED))
        snapshots={name:stack.enter_context(Snapshot(measured_dir,name)) for name in MEASURED_PINS}
        for name,expected in MEASURED_PINS.items():
            if snapshots[name].pin()!=expected:raise ValueError('consumed_measurement_changed')
        intent=adoption._json(snapshots['intent.json'].body);result=adoption._json(snapshots['result.json'].body)
        measured_value(intent,result)
        if intent['host']!=host or intent['inventory']!=source.pin():raise ValueError('measured_route_changed')
        pins={}
        # Historical complete leaf generations and bodies remain exact. Fresh
        # ancestry records account explicitly for new reviewed companion files.
        for path,expected in intent['inputPins'].items():
            pin=frozen.file_pin(path,body=True,private=path.endswith(('.stdout','.stderr')))
            if any(pin[k]!=expected[k] for k in ('generation','bytes','sha256')):raise ValueError('consumed_input_changed')
            pins[path]=pin
        for module,expected in ((frozen,FROZEN_SHA),(diagnostic,DIAGNOSTIC_SHA)):
            if frozen.file_pin(Path(module.__file__),body=True)['sha256']!=expected:raise ValueError('consumed_source_changed')
        pins[str(Path(__file__))]=frozen.file_pin(Path(__file__),body=True)
        config=adoption._validate_candidate(source.body,root);target,binding,histories=frozen._owned_binding(root,config,host,stack)
        if binding!=intent['binding']:raise ValueError('measured_ownership_changed')
        remote=remote_source().replace('spec=json.loads(sys.argv[1]);','spec=json.loads(sys.argv[1]);spec["configFile"]=str(Path.home()/".ssh/config") if spec["configFile"]=="~/.ssh/config" else spec["configFile"];',1)
        remote_sha=hashlib.sha256(remote.encode()).hexdigest()
        spec={'controlPath':str(target.remote_control_path),'remoteHostAlias':target.remote_host_alias,'configFile':str(target.remote_config_file) if target.remote_config_file else '~/.ssh/config'}
        def guard():
            ownership.guard();source.guard();output.guard();group_directory.guard()
            for snapshot in snapshots.values():snapshot.guard()
            for history in histories:history.guard()
            for path,pin in pins.items():
                if frozen.file_pin(path,body=True,private=path.endswith(('.stdout','.stderr')))!=pin:raise ValueError('observation_authority_changed')
        guard()
        request={'schema':1,'host':host,'correlationId':correlation,'measuredDiagnosticId':MEASURED,'measurementPins':MEASURED_PINS,
                 'inventory':source.pin(),'binding':binding,'inputPins':pins,'remoteSourceSha256':remote_sha,'repair':'exact-fixed-ssh-options-add-T-only','archiveAllowed':False}
        adoption._write_receipt(output,'intent.json',request);request_source=stack.enter_context(Snapshot(output,'intent.json'))
        prefix,endpoint=session._outer_prefix(config,transport.connection_host(config,target.gateway))
        argv=[*prefix,'-o','ControlMaster=no','-o','ControlPath=none','-o','ClearAllForwardings=yes','-o','PermitLocalCommand=no','-o','UpdateHostKeys=no',endpoint,
              shlex.join(('python3','-I','-B','-c',remote,json.dumps(spec,sort_keys=True)))]
        guard();request_source.guard();completed=subprocess.run(argv,capture_output=True,timeout=25);guard();request_source.guard()
        for name,body in (('stdout',completed.stdout),('stderr',completed.stderr)):
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=output.fd)
            with os.fdopen(fd,'wb') as stream:stream.write(body);stream.flush();os.fsync(stream.fileno())
        os.fsync(output.fd)
        if completed.returncode!=0 or len(completed.stdout)>65536:raise ValueError('new_orphan_observation_unknown')
        value=adoption._json(completed.stdout)
        if value.get('state')!='owned-orphan-observed' or value.get('controlPath')!=spec['controlPath'] or value.get('mutationPerformed')is not False or value.get('credentialRead')is not False:raise ValueError('new_orphan_binding_changed')
        proof={'schema':1,'host':host,'correlationId':correlation,'intent':request_source.pin(),'remoteSourceSha256':remote_sha,'result':value,'originalObservationOutcome':'unknown','archiveAllowed':False}
        guard();request_source.guard();pin=adoption._write_receipt(output,'result.json',proof);guard();request_source.guard()
    return {'ok':True,'state':'owned-orphan-observed','correlationId':correlation,'proofSha256':pin['sha256'],'mutationPerformed':False,'archiveAllowed':False}


def retire(*args,**kwargs):
    raise ValueError('separate_archive_proof_review_required')

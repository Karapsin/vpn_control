"""Read-only collection of one already admitted managed existing-instance start.

This collector cannot submit a start, wake a guest, connect TPM control, or issue
a QGA request. Its separate internal dispatch builder remains unqualified until
actual native acceptance; it grants no published capability. It joins the original native intent/manager ACK to a fresh selected
listener census and actual managed lineage. A dispatcher remains gated until
this collector and renewed guest admission have native qualification.
"""
from dataclasses import dataclass
import inspect
import ast
import weakref
import json
import math
from pathlib import Path
import subprocess
import time
from uuid import UUID,uuid5

from . import readiness_windows_lifecycle as lifecycle
from . import readiness_windows_host_jobs as host
from . import readiness_windows_tpm_owner as owner
from . import ssh_transport as transport
from . import windows_vm_deploy as deploy


_EXECUTING_CODE=inspect.currentframe().f_code
_HOST_ORIGINALS=weakref.WeakKeyDictionary()


def _need(value):
    if not value:raise ValueError('windows_managed_start_original_unresolved')


@dataclass(frozen=True,eq=False)
class OriginalManagedStart:
    _body:object

    def as_dict(self):return lifecycle._plain(self._body)


def original(binding,lineage,clean,operation,recovery_id):
    """Build finite expected-original identity; grants no dispatch authority."""
    _need(type(binding)is dict and binding.get('provider')=='libvirt-windows'
          and type(lineage)is lifecycle.ExistingLineage and type(clean)is lifecycle.CleanStopped)
    lifecycle.validate_lineage(binding,lineage.as_dict());lifecycle.validate_clean_stopped(binding,lineage,clean.as_dict())
    _need(lifecycle._uuid(operation)and lifecycle._digest(recovery_id)
          and operation==str(uuid5(UUID(binding['spec']['deploymentId']),recovery_id)))
    body={'binding':binding,'lineage':lineage.as_dict(),'clean':clean.as_dict(),'intent':{
        'schemaVersion':1,'kind':'windows-existing-start-v1','operationId':operation,'recoveryId':recovery_id,
        'machine':binding['spec']['deploymentId'],'hostBoot':binding['context']['hostBootId'],
        'lineageSha256':lifecycle._lineage_sha(lineage),'cleanPoweroffOperationId':clean.as_dict()['operationId'],
        'replayAllowed':False}}
    return OriginalManagedStart(lifecycle._freeze(json.loads(json.dumps(body,allow_nan=False))))


def _admission(value):
    _need(type(value)is OriginalManagedStart)
    body=value.as_dict()
    _need(type(body)is dict and set(body)=={'binding','lineage','clean','intent'}and type(body['intent'])is dict)
    try:
        lineage=lifecycle.validate_lineage(body['binding'],body['lineage'])
        clean=lifecycle.validate_clean_stopped(body['binding'],lineage,body['clean'])
        rebuilt=original(body['binding'],lineage,clean,body['intent']['operationId'],body['intent']['recoveryId'])
        _need(rebuilt.as_dict()==body)
    except owner.WitnessExpired:raise
    except Exception:raise ValueError('windows_managed_start_original_unresolved')from None
    return body


def attach_host_original(admission,original_job):
    """Join a pure expected plan to its exact retained reviewed HOST Program."""
    body=_admission(admission);record,source,_=host._load(original_job);ns=record['namespace'];binding=body['binding'];intent=body['intent']
    _need(record['purpose']=='windows-persisted-managed-start'and record['operationId']==intent['operationId']
        and record['recoveryId']==intent['recoveryId']and ns['vmRoot']==binding['spec']['root']
        and ns['vmRootIdentity']==body['lineage']['rootIdentity']and ns['binding']['machine']==intent['machine']
        and UUID(ns['binding']['boot'])==UUID(intent['hostBoot'])
        and ns['binding']['target']=='windows-host:'+binding['spec']['host']+':'+intent['machine'])
    expected={'SPEC':binding['spec'],'OPERATION':intent['operationId'],'LIFECYCLE_RID':intent['recoveryId'],
              'LIFECYCLE_LINEAGE':body['lineage'],'LIFECYCLE_CLEAN':body['clean']}
    actual={}
    for node in ast.parse(source).body:
        if isinstance(node,ast.Assign)and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)and node.targets[0].id in expected:
            key=node.targets[0].id;_need(key not in actual);actual[key]=ast.literal_eval(node.value)
    _need(actual==expected)
    result=OriginalManagedStart(lifecycle._freeze(body));_HOST_ORIGINALS[result]=original_job;return result


def _host_original(admission):
    _need(type(admission)is OriginalManagedStart and admission in _HOST_ORIGINALS)
    original_job=_HOST_ORIGINALS[admission];host._load(original_job)
    # Re-derive the exact source/target match without transferring authority to
    # a public DTO. The returned opaque object retains its original files.
    attach_host_original(admission,original_job)
    return original_job


def _observe_host(source,record):
    import contextlib,io,json
    def need(value):
        if not value:raise ValueError('instance_lifecycle_original_start_unknown')
    def pairs(rows):
        value={}
        for key,item in rows:need(key not in value);value[key]=item
        return value
    output=io.StringIO()
    with contextlib.redirect_stdout(output):exec(compile(source,'original managed HOST observer','exec'),{'__name__':'original_managed_host_observer'})
    reply=json.loads(output.getvalue(),object_pairs_hook=pairs);status=reply['status']
    need(status.get('state')in {'running','terminal'}and status.get('operationId')==record['operationId']
        and status.get('binding')==record['namespace']['binding']and status.get('replayAllowed')is False)
    if status['state']=='terminal':need(status['terminal']['exitCode']==0 and type(status['terminal']['exitCode'])is int and status['terminal']['streamsClosed']is True)
    actor=status.get('owner');need(type(actor)is dict and set(actor)=={'pid','birth'}and type(actor['pid'])is int and actor['pid']>0 and type(actor['birth'])is str)
    return {'operationId':record['operationId'],'programSha256':record['programSha256'],
        'ownerSourceSha256':record['namespace']['ownerSourceSha256'],'namespaceGeneration':record['namespace']['generation'],'owner':actor}


def dispatch_program(admission,resource_admission,*,prior_closures=()):
    """Internal once-only direct-qualification Program; grants no public cap.

    A manager ACK is pending evidence. It cannot create Ready; collect() must
    observe this exact original HOST execution and a fresh privileged witness.
    """
    body=_admission(admission)
    return lifecycle._existing_start_program(body['binding'],lifecycle.validate_lineage(body['binding'],body['lineage']),
        lifecycle.validate_clean_stopped(body['binding'],lifecycle.validate_lineage(body['binding'],body['lineage']),body['clean']),
        body['intent']['operationId'],body['intent']['recoveryId'],resource_admission,prior_closures=prior_closures,managed_plan=admission)


def _original(expected,root,read,process,current_actor,manager,socket_pin,domain,generation,private):
    """Finite original journal/actual manager generation gate; no publication."""
    import os
    def need(value):
        if not value:raise ValueError('instance_lifecycle_original_start_unknown')
    prefix='existing-start-'+expected['operationId'];intent_name=prefix+'.intent.json';ack_name=prefix+'.manager-ack.json'
    before={name:list(generation(private(root/name)))for name in (intent_name,ack_name)}
    intent=read(intent_name);ack=read(ack_name)
    need(intent==expected and type(ack)is dict and set(ack)=={'operationId','recoveryId','domainId','actor','manager','socketIdentity','replayAllowed'}
         and ack['operationId']==expected['operationId']and ack['recoveryId']==expected['recoveryId']
         and ack['replayAllowed']is False and type(ack['domainId'])is int and ack['domainId']>0
         and ack['domainId']==domain.ID()and ack['actor']==current_actor and ack['manager']==manager
         and ack['socketIdentity']==list(socket_pin))
    need(type(current_actor)is dict and type(manager)is dict);process(current_actor);process(manager)
    need(before=={name:list(generation(private(root/name)))for name in (intent_name,ack_name)})
    return {'intentGeneration':before[intent_name],'ackGeneration':before[ack_name],
            'actor':{key:current_actor[key]for key in ('pid','startTicks','executableGeneration')},
            'manager':{key:manager[key]for key in ('pid','startTicks','executableGeneration')},
            'managerSocketIdentity':list(socket_pin),'domainId':ack['domainId']}


def _validate_projection(value):
    _need(type(value)is dict and set(value)in ({'intentGeneration','ackGeneration','actor','manager','managerSocketIdentity','domainId'},
        {'intentGeneration','ackGeneration','actor','manager','managerSocketIdentity','domainId','hostOwner'})
          and lifecycle._pin(value['intentGeneration'],9)and lifecycle._pin(value['ackGeneration'],9)
          and lifecycle._pin(value['managerSocketIdentity'],5)and type(value['domainId'])is int and value['domainId']>0)
    for name in ('actor','manager'):
        row=value[name];_need(type(row)is dict and set(row)=={'pid','startTicks','executableGeneration'}
            and all(type(row[k])is int and row[k]>0 for k in ('pid','startTicks'))and lifecycle._pin(row['executableGeneration'],9))
    if 'hostOwner'in value:
        row=value['hostOwner'];_need(type(row)is dict and set(row)=={'operationId','programSha256','ownerSourceSha256','namespaceGeneration','owner'}
            and lifecycle._uuid(row['operationId'])and lifecycle._digest(row['programSha256'])and lifecycle._digest(row['ownerSourceSha256'])
            and lifecycle._pin(row['namespaceGeneration'],2)and type(row['owner'])is dict and set(row['owner'])=={'pid','birth'}
            and type(row['owner']['pid'])is int and row['owner']['pid']>0 and type(row['owner']['birth'])is str)
    return json.loads(json.dumps(value))


def _validate_request(admission,value):
    _need(type(admission)is OriginalManagedStart and type(value)is dict and set(value)=={'original','request'})
    projection=_validate_projection(value['original']);request=owner.validate_request(value['request']);body=_admission(admission)
    _need(request['machine']==body['intent']['machine']and request['hostBoot']==body['intent']['hostBoot']
          and request['root']==body['binding']['spec']['root']
          and request['qemu']['pid']==projection['actor']['pid']and request['qemu']['birth']==projection['actor']['startTicks']
          and request['qemu']['executableGeneration']==projection['actor']['executableGeneration']
          and (projection['actor']['pid'],projection['actor']['startTicks'])!=
              (body['lineage']['qemu']['pid'],body['lineage']['qemu']['startTicks']))
    if admission in _HOST_ORIGINALS:
        record=_host_original(admission).as_dict();row=projection.get('hostOwner');_need(type(row)is dict)
        _need(row['operationId']==record['operationId']and row['programSha256']==record['programSha256']
            and row['ownerSourceSha256']==record['namespace']['ownerSourceSha256']and row['namespaceGeneration']==record['namespace']['generation'])
    return {'original':projection,'request':request}


def program(admission,*,request=None,witness=None,publish=False):
    """Pure original-only packet. Native main's operator lock covers each gate."""
    _need(type(admission)is OriginalManagedStart and type(publish)is bool);body=_admission(admission);binding=body['binding'];intent=body['intent']
    first=request is None and witness is None
    _need(not publish or admission in _HOST_ORIGINALS)
    _need((first and not publish)or not first and request is not None and type(witness)is owner.OwnerWitness)
    if not first:
        request=_validate_request(admission,request);witness.validate(request['request'])
    source=lifecycle.libvirt_lineage_program(binding,intent['operationId'],request_only=first,owner_witness=witness)
    source=source.decode();start=source.index('        print(json.dumps(_capture_libvirt_lineage(')
    end=source.index('\n        return\n',start)
    expression=source[start:end][len('        print(json.dumps('):-2]
    branch="""        original_before=_managed_original(MANAGED_EXPECTED,root,read,process,current_actor,manager,socket_pin,domain,generation,private)
        require((current_actor['pid'],current_actor['startTicks'])!=(MANAGED_OLD_ACTOR['pid'],MANAGED_OLD_ACTOR['startTicks']),
                'instance_lifecycle_original_start_unknown')
        if MANAGED_PRIOR_PROJECTION is not None:
            require(original_before==MANAGED_PRIOR_PROJECTION,'instance_lifecycle_original_start_unknown')
        observed="""+expression+"""
        original_after=_managed_original(MANAGED_EXPECTED,root,read,process,current_actor,manager,socket_pin,domain,generation,private)
        vm_guard();process(current_actor);process(manager)
        require(original_before==original_after,'instance_lifecycle_original_start_unknown')
        print(json.dumps({'original':original_after,'request':observed}if MANAGED_PRIOR_PROJECTION is None else
                         {'original':original_after,'lineage':observed}))"""
    if admission in _HOST_ORIGINALS:
        original_job=_host_original(admission);record=original_job.as_dict()
        branch=branch.replace('        original_before=_managed_original(', '        host_before=_observe_host(MANAGED_HOST_SOURCE,MANAGED_HOST_RECORD)\n        original_before=_managed_original(',1)
        branch=branch.replace("        require((current_actor", "        original_before['hostOwner']=host_before\n        require((current_actor",1)
        branch=branch.replace('        vm_guard();process(current_actor);process(manager)', "        original_after['hostOwner']=_observe_host(MANAGED_HOST_SOURCE,MANAGED_HOST_RECORD)\n        vm_guard();process(current_actor);process(manager)",1)
    if publish:
        _need(admission in _HOST_ORIGINALS)
        addition="""        require(observed['executables']==MANAGED_EXPECTED_LINEAGE['executables']and observed['firmware']['generation']==MANAGED_EXPECTED_LINEAGE['firmware']['generation'],
                'instance_lifecycle_binary_changed')
        for name,value in (('existing-start-'+OPERATION+'.qemu-started.json',observed['qemu']),
                           ('existing-start-'+OPERATION+'.tpm-started.json',observed['tpm'])):
            if os.path.lexists(root/name):require(read(name)==value,'instance_lifecycle_original_start_unknown')
            else:save(name,value)
        publication={'schemaVersion':1,'kind':'windows-existing-start-observation-v1','state':'guest-admission-required',
            'operationId':OPERATION,'recoveryId':MANAGED_EXPECTED['recoveryId'],'machine':SPEC['deploymentId'],
            'hostBoot':CONTEXT['hostBootId'],'actor':observed['qemu'],'tpm':observed['tpm'],'guestReady':False,'replayAllowed':False}
        name='existing-start-'+OPERATION+'.result.json'
        if os.path.lexists(root/name):require(read(name)==publication,'instance_lifecycle_original_start_unknown')
        else:save(name,publication)
"""
        marker="        print(json.dumps({'original':original_after,";_need(branch.count(marker)==1)
        branch=branch.replace(marker,addition+marker,1)
    source=source[:start]+branch+source[end:]
    prefix='MANAGED_EXPECTED='+repr(intent)+'\nMANAGED_EXPECTED_LINEAGE='+repr(body['lineage'])+'\nMANAGED_OLD_ACTOR='+repr({k:body['lineage']['qemu'][k]for k in ('pid','startTicks')})+'\n'
    prefix+='MANAGED_PRIOR_PROJECTION='+repr(None if first else request['original'])+'\n'
    if admission in _HOST_ORIGINALS:
        prefix+='MANAGED_HOST_RECORD='+repr(record)+'\nMANAGED_HOST_SOURCE='+repr(host.operation_program(original_job))+'\n'+inspect.getsource(_observe_host)+'\n'
    prefix+=inspect.getsource(_original).replace('def _original(', 'def _managed_original(',1)+'\n'
    packet=(prefix+source).encode();compile(packet,'original managed start collector','exec');return packet


def _run(root,admission,source_factory,guard,deadline,*,witness=None,request=None):
    _need(type(deadline)in (int,float)and math.isfinite(deadline)and deadline>time.monotonic())
    body=_admission(admission);host=body['binding']['spec']['host'];operation=body['intent']['operationId']
    def remaining():
        value=min(60,deadline-time.monotonic());_need(value>0);return value
    try:
        with transport.admitted_transport(root,host,operation,deadline=deadline)as admitted:
            with deploy.direct.Guard(root,host=host)as authority:
                guard();source=source_factory()
                if witness is not None:witness.guard_dispatch(admitted)
                argv=transport.build_ssh_argv(authority.config,host,60,command=('python3','-I','-B','-c','exec('+repr(source.decode())+')'))
                admitted.revalidate();authority.guard();guard()
                reply=transport.run_ssh(argv,input=b'',stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=remaining(),cwd=root)
                _need(reply.returncode==0 and type(reply.stdout)is bytes and len(reply.stdout)<=262144 and reply.stderr==b'')
                value=json.loads(reply.stdout,object_pairs_hook=transport._reject_duplicate_keys)
                admitted.revalidate();authority.guard();guard()
                if (type(value)is dict and set(value)=={'state','operationId','reason','errorClass','replayAllowed'}
                    and value=={'state':'blocked','operationId':operation,'reason':'instance_lifecycle_managed_tpm_owner_expired',
                                'errorClass':'ValueError','replayAllowed':False}):raise owner.WitnessExpired()
                return value
    except owner.WitnessExpired:raise
    except Exception:raise ValueError('windows_managed_start_original_unresolved')from None


@dataclass(frozen=True)
class CollectedManagedStart:
    original:OriginalManagedStart
    lineage:lifecycle.ExistingLineage
    _projection:object
    witness_receipt:object
    host_job:host.OriginalHostJob

    def projection(self):return lifecycle._plain(self._projection)


def collect(root,admission,credential_file,*,guard,deadline=None,publish=False):
    """Observe only this original; optional metadata publication grants no Ready."""
    _need(type(admission)is OriginalManagedStart and callable(guard)and type(publish)is bool)
    deadline=time.monotonic()+180 if deadline is None else deadline
    _need(type(deadline)in (int,float)and math.isfinite(deadline)and deadline>time.monotonic())
    body=_admission(admission);original_job=_host_original(admission)
    for attempt in range(3):
        try:
            request=_validate_request(admission,_run(root,admission,lambda:program(admission),guard,deadline))
            with owner.observe(root,body['binding']['spec']['host'],request['request'],credential_file,guard=guard,deadline=deadline)as witness:
                value=_run(root,admission,lambda:program(admission,request=request,witness=witness,publish=publish),guard,deadline,witness=witness,request=request['request'])
                _need(type(value)is dict and set(value)=={'original','lineage'}and _validate_projection(value['original'])==request['original'])
                lineage=lifecycle.validate_lineage(body['binding'],value['lineage']);actual=lineage.as_dict()
                _need(actual['operationId']==body['intent']['operationId']and actual['qemu']['pid']==request['request']['qemu']['pid']
                      and actual['qemu']['startTicks']==request['request']['qemu']['birth']
                      and all(actual['executables'][key]==body['lineage']['executables'][key]for key in actual['executables'])
                      and actual['firmware']['generation']==body['lineage']['firmware']['generation'])
                return CollectedManagedStart(admission,lineage,lifecycle._freeze(request['original']),lifecycle._freeze(witness.receipt()),original_job)
        except owner.WitnessExpired:
            if attempt==2 or time.monotonic()>=deadline:raise

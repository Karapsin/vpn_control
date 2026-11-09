"""Deterministic declared peers; no socket, Windows native API or guest launch."""
from __future__ import annotations
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path,PureWindowsPath
import sys
import types
import unittest
from unittest.mock import patch

B = _canonical_root / 'agent_tools/windows_system_collector'
ROOT = _canonical_root


def module(name, path):
    return _load_source(path)


C=module('_private_collector_contract_tests',B/'collector_contract.py')
W=module('_private_collector_wrapper_tests',B/'collector_wrapper.py')
K=module('_private_collector_worker_tests',B/'system_collector_worker.py')
E=module('_actual_current_collector_emitter',ROOT/'agent_tools/windows_artifact_transfer.py')
H=module('_private_hold_protocol_tests',B/'hold_protocol.py')
Q=module('_actual_current_collector_qga',ROOT/'agent_tools/windows_qga_transfer.py')
OP='12345678-1234-4234-8234-123456789abc'
ORD='abcdef01-2345-4678-9234-56789abcdef0'
SID='S-1-5-21-1-2-3-1001'
CONTRACT=(B/'collector_contract.py').read_bytes()
TEMPLATE=(B/'system_bootstrap_template.ps1').read_bytes()
TASK_DOCUMENTS={}


def pin(path,sha='a'*64,directory=False,size=10):
    i={'volumeSerial':7,'fileIndex':int.from_bytes(hashlib.sha256(path.encode()).digest()[:6],'big'),
       'attributes':16 if directory else 32}
    if not directory:i.update(sizeBytes=size,links=1,creationFileTime='133000000000000001',lastWriteFileTime='133000000000000002')
    r={'path':path,'nativeIdentity':i,'security':{'ownerSid':'S-1-5-18','sddl':'synthetic-declared-peer-only'}}
    if not directory:r['sha256']=sha
    return r


def inputs(scope='update',with_hold=False):
    with_hold=with_hold or scope=='tun'
    parent=r'C:\ProgramData\VpnControlOrdinaryTask-'+ORD;root=parent+'\\system-collector-'+OP
    modules={key:{'path':r'C:\CollectorSources'+'\\'+('hold_protocol' if key=='holdProtocol' else key)+'.py','sha256':value}
        for key,value in {**C.FIXED,'collector':C.COLLECTORS[scope],'contract':W.CONTRACT_SHA,'worker':W.WORKER_SHA}.items()}
    py=r'C:\AdmittedPython';names=sorted(C.PYTHON_REQUIRED)
    files=[pin(r['path'],r['sha256']) for r in modules.values()]+[pin(str(PureWindowsPath(py)/n)) for n in names]
    directories={root,py}
    for p in [root,root+'\\collector-request.json',*[x['path'] for x in files]]:
        directories.update(str(q) for q in PureWindowsPath(p).parents)
    context={'bootIdentifier':'11111111-2222-4333-8444-555555555555','bootFileTimeUtc':'133000000000000000',
        'machineGuid':'22222222-3333-4444-8555-666666666666','hardwareUuid':'33333333-4444-4555-8666-777777777777',
        'ordinarySid':SID,'ordinarySessionId':2,'systemSessionId':0}
    common={'schemaVersion':1,'ordinaryTaskOperationId':ORD,'sourceSha':'f'*40,
        'collectorSourceSha256':C.COLLECTORS[scope],'context':{'ordinarySid':SID,'ordinarySessionId':2,
        'approvingAdminSid':'S-1-5-21-1-2-3-1002','bootIdentifier':context['bootIdentifier']}}
    if scope=='update':
        common.update(stage='before-install',jobId=None,productOperationId=None,actors={},fileInputs={},faultBinding={},
            programData=r'C:\ProgramData',evidenceRoot=r'C:\ProgramData\update-evidence-'+ORD,
            ordinaryWorkerPid=77,ordinaryWorkerBirth='133000000000000007',expectedHelperSha256=None)
    else:
        common.update(productOperationId=OP,originRequestId=ORD,controllerId=OP,ownerActor={},guiActor=None,
            helperActor={},runtimeActor={},helperImagePath=r'C:\Installed\helper.exe',helperImageSha256='d'*64,
            runtimeImagePath=r'C:\Installed\runtime.exe',runtimeImageSha256='e'*64,configuration={})
    request={'schemaVersion':1,'operationId':OP,'ordinaryTaskOperationId':ORD,'scope':scope,'operationRoot':root,
        'requestPath':root+'\\collector-request.json','context':context,
        'pythonRuntime':{'root':py,'interpreterPath':py+'\\python.exe','version':'3.13.15','architecture':'amd64'},
        'filePins':files,'directoryPins':[pin(p,directory=True) for p in sorted(directories)],
        'treePins':[{'role':'python-runtime','root':py,'files':names}],'modules':modules,
        'collectorRequest':common,'rawStreamLimitBytes':16384,'closeHold':None}
    workspace=r'C:\OrdinaryOperation\workspace';common['context']['workspace']=workspace
    owner_source=pin(r'C:\OrdinaryTaskSources\owner.ps1',C.TASK_OWNER_SHA)
    worker_source=pin(r'C:\OrdinaryTaskSources\worker.py','b'*64)
    caller_source=pin(r'C:\CollectorSources\caller_hold.py',C.CALLER_HOLD_SHA)
    if with_hold:
        if scope=='update':common['stage']='terminal-actors'
        request['closeHold']={'schemaVersion':1,'callerSourcePin':caller_source,
            'holdReadyPath':r'C:\OrdinaryOperation\collector-hold-'+OP+'.ready.json',
            'releasePath':root+'\\close-release.json','scope':scope,'stage':'off' if scope=='tun' else 'terminal-actors','sourceSha':'f'*40}
        request['filePins'].append(caller_source)
    worker_doc={'schemaVersion':1,'operationId':ORD,'operationRoot':r'C:\OrdinaryOperation','context':context,
        'workspace':workspace,'pythonRuntime':request['pythonRuntime'],'filePins':[worker_source]}
    if with_hold:worker_doc['filePins'] += [caller_source,next(x for x in files if x['sha256']==C.FIXED['holdProtocol'])]
    worker_raw=C.encoded(worker_doc)
    worker_pin=pin(r'C:\OrdinaryOperation\worker-request.json',W.digest(worker_raw),size=len(worker_raw))
    bootstrap={'schemaVersion':1,'operationId':ORD,'operationRoot':r'C:\OrdinaryOperation','context':context,
        'filePins':[owner_source,worker_source,worker_pin],
        'bootstrap':{'mode':'python-worker','pythonPath':py+'\\python.exe','workerPath':worker_source['path'],
          'workerRequestPath':worker_pin['path'],'workerRequestSha256':worker_pin['sha256'],
          'workerRequestPinBase64':base64.b64encode(C.encoded(worker_pin)).decode()}}
    bootstrap_raw=C.encoded(bootstrap)
    bootstrap_pin=pin(r'C:\OrdinaryOperation\bootstrap-request.json',W.digest(bootstrap_raw),size=len(bootstrap_raw))
    task={'ownerActor':{'pid':71,'creationFileTime':133000000000000071,'image':E.POWERSHELL_PATH,'sha256':'c'*64,'sid':SID,'sessionId':2},
        'workerActor':{'pid':72,'creationFileTime':133000000000000072,'image':py+'\\python.exe','sha256':'a'*64,'sid':SID,'sessionId':2},
        'ownerSourcePin':owner_source,'workerSourcePin':worker_source,'bootstrapRequestPin':bootstrap_pin,'workerRequestPin':worker_pin}
    args=C.task_argv(task);task.update(ownerArgv=args['owner'],workerArgv=args['worker']);request['ordinaryTask']=task
    request['filePins'].extend([owner_source,worker_source,bootstrap_pin,worker_pin])
    present={x['path'] for x in request['directoryPins']}
    for value in (owner_source,worker_source,bootstrap_pin,worker_pin):
        for task_parent in PureWindowsPath(value['path']).parents:
            if str(task_parent) not in present:request['directoryPins'].append(pin(str(task_parent),directory=True));present.add(str(task_parent))
    security={'ownerSid':'S-1-5-18','sddl':'O:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;'+SID+')'}
    next(x for x in request['directoryPins'] if x['path']==root)['security']=security
    TASK_DOCUMENTS[bootstrap_pin['sha256']]=bootstrap_raw;TASK_DOCUMENTS[worker_pin['sha256']]=worker_raw
    guest={'deploymentId':ORD,'boot':{'lastBootUpTimeFileTimeUtc':context['bootFileTimeUtc'],
        'machineGuid':context['machineGuid'],'hardwareUuid':context['hardwareUuid']},'ordinarySid':SID,
        'powerShellPath':E.POWERSHELL_PATH,'sourceWorkspace':parent}
    rec=pin(request['requestPath'],C.request_digest(request),size=len(C.encoded(request)))
    rec['security']={'ownerSid':'S-1-5-18','sddl':'O:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;'+SID+')'}
    return request,rec,guest


class Parked(Exception):pass


class ParentPeer:
    """Declared original-holder peers; authentic current emitter handles source."""
    def __init__(self,request,guest):
        self.log=[];self.files={};self.answers=[];self.finished=False;self.fail_save=None
        self.guard_fn=lambda:self.log.append(('guard',))
        self.owner=Q.RetainedQgaOwner('/declared-no-io-collector','declared-collector',5,self.guard_fn,self.save,[],10,11)
        self.n={'QGA_OWNER':self.owner,'QGA_MODULE_SHA':W.QGA_SHA,'EMITTER_SHA256':W.EMITTER_SHA,
            'QGA_MODULE_SOURCE':(ROOT/'agent_tools/windows_qga_transfer.py').read_bytes(),
            'EMITTER_SOURCE':(ROOT/'agent_tools/windows_artifact_transfer.py').read_bytes(),'QGA_MODULE':Q,
            'QGA_GUARD':self.guard_fn,'generated_sources_closing':lambda:self.log.append(('source-close',)),
            'NATIVE_PHASE_IDS':{W.LABEL:request['operationId'],W.RELEASE_LABEL:'99999999-1111-4222-8333-444444444444'},'EMITTER_MODULE':E,'GUEST_CONTEXT':guest,
            'prefix':'declared-collector','overall_deadline':1234,'save':self.save,
            'build_native_command':self.build,'retained_call':self.call,'park_original':self.park,
            'finalize_rpc_success':self.finalize}

    def save(self,name,value):
        self.log.append(('save',name))
        if self.fail_save and self.fail_save in name:raise OSError('declared positive-write failure')
        if name in self.files:raise FileExistsError(name)
        self.files[name]=copy.deepcopy(value)

    def build(self,label,source):
        self.log.append(('build',label))
        return E.build_guest_exec(source,guest_context=self.n['GUEST_CONTEXT'],phase_id=self.n['NATIVE_PHASE_IDS'][label]),W.digest(source)

    def call(self,command,args,deadline):
        self.log.append(('rpc',command,copy.deepcopy(args)))
        answer=self.answers.pop(0)
        if isinstance(answer,BaseException):raise answer
        return answer

    def park(self,receipt,error):
        self.owner.failed=True;self.owner.parked=True;self.log.append(('park',receipt,error))
        raise Parked(str(error))

    def finalize(self):self.owner.finalized=True;self.finished=True;self.log.append(('finalize',))


def hold_observation(request, record):
    h=request['closeHold'];w=request['ordinaryTask']['workerActor']
    ready={'schemaVersion':1,'kind':'caller-collector-close-ready','ordinaryTaskOperationId':ORD,
        'collectorOperationId':OP,'sourceSha':h['sourceSha'],'scope':request['scope'],'stage':h['stage'],
        'bootIdentifier':request['context']['bootIdentifier'],'ordinaryWorker':{'pid':w['pid'],
            'birthFileTimeUtc':str(w['creationFileTime']),**{k:w[k] for k in ('image','sha256','sid','sessionId')}},
        'callerSourcePin':h['callerSourcePin'],'collectorRequestSha256':record['sha256'],
        'systemActor':{'pid':909,'birthFileTimeUtc':'133000000000000009'},
        'collectorChild':{'pid':818,'birthFileTimeUtc':'133000000000000008'},
        'driverKnownResult':0,'allOriginalChildrenTerminalAndEof':True}
    raw=H.encoded(ready);native=pin(h['holdReadyPath'],W.digest(raw),size=len(raw));native['security']['ownerSid']=SID
    return {'ready':ready,'sha256':W.digest(raw),'nativeFile':{k:v for k,v in native.items() if k!='sha256'},
        'originalHandleRetained':True}


def child_proof(request,record,pid=909):
    worker={'pid':818,'birthFileTimeUtc':'133000000000000008','image':request['pythonRuntime']['interpreterPath'],
        'sessionId':0,'exitCode':0,'bothEof':True,'originalHandleRetained':True}
    actor={'pid':818,'birthFileTimeUtc':worker['birthFileTimeUtc'],'image':worker['image'],
        'bootIdentifier':request['context']['bootIdentifier'],'token':{'sid':'S-1-5-18','sessionId':0,'elevation':1}}
    data={'schemaVersion':1,'state':'collector-completed','operationId':request['operationId'],
        'ordinaryTaskOperationId':ORD,'scope':request['scope'],'collectorSourceSha256':request['modules']['collector']['sha256'],
        'workerActor':actor,'publications':[{}]*(1 if request['scope']=='update' else 2),
        'closing':{'sourceClosing':True,'files':len(request['filePins'])+1,'completeFileDigestSha256':'b'*64},'callerHold':None}
    if request['closeHold'] is not None:data['callerHold']=hold_observation(request,record)
    captures=[]
    for name,raw in [('stdout',C.encoded(data)),('stderr',b'')]:
        captures.append({'name':name,'sizeBytes':len(raw),'sha256':W.digest(raw),'base64':base64.b64encode(raw).decode(),
            'eof':True,'nativeIdentity':pin('C:\\raw',size=len(raw))['nativeIdentity']})
    return {'schemaVersion':1,'state':'collector-closed','operationId':request['operationId'],
        'ordinaryTaskOperationId':ORD,'scope':request['scope'],'collectorSourceSha256':request['modules']['collector']['sha256'],
        'requestSha256':record['sha256'],'requestNativeIdentity':record['nativeIdentity'],'worker':worker,
        'captures':captures,'sourceClosing':True,'productMutation':False,
        'bootstrapOpening':{'pid':pid},'bootstrapClosing':{'pid':pid},'guestBootClosing':True,'bootstrapActorClosing':True}


def terminal_reply(obj,proof):
    g=obj.n['GUEST_CONTEXT'];actor={'pid':obj.ack['pid'],'birthFileTimeUtc':'133000000000000009',
        'sessionId':0,'path':g['powerShellPath'],'principalSid':'S-1-5-18','is64BitProcess':True,
        'powerShellMajor':5,'powerShellEdition':'Desktop','boot':g['boot'],'tokenElevation':1,'tokenElevationType':1}
    proof['bootstrapOpening']=actor;proof['bootstrapClosing']=actor
    proof['guestBootClosing']=True;proof['bootstrapActorClosing']=True
    source=obj.plan['savedSource']
    held={'phaseId':source['phaseId'],'path':source['path'],'identity':'00000007:000000000000002a',
        'bytes':source['bytes'],'sha256':source['sha256'],'ownerSid':'S-1-5-18',
        'sddl':'O:SYG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;'+SID+')',
        'createNew':True,'heldReadOnly':True,'writeOpenError':32,'deleteOpenError':32,'parserErrors':0,
        'bootstrapOpening':actor,'launch':'held-saved-file-scriptblock','originalOwnerSid':'S-1-5-18',
        'explicitOwnerGreen':True,'productOperation':False,'sourceClosing':True,'finalSourceSha256':source['sha256']}
    envelope={'state':'protocol-completed','protocolResult':proof,'heldSource':held,'sourceClosing':True,
        'bootstrapOpening':actor,'bootstrapClosing':actor}
    return {'exited':True,'exitcode':0,'out-data':base64.b64encode(C.encoded(envelope)).decode(),'err-data':''}


class ContractTests(unittest.TestCase):
    def test_both_exact_source_roles_validate_without_native_action(self):
        for scope in C.COLLECTORS:
            r,p,g=inputs(scope);self.assertIs(C.validate(r,{'contract':W.CONTRACT_SHA,'worker':W.WORKER_SHA},g),r)

    def test_collector_digest_cannot_be_selected_by_request(self):
        r,p,g=inputs();r['modules']['collector']['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'exact-source-collector'):C.validate(r,{'contract':W.CONTRACT_SHA,'worker':W.WORKER_SHA},g)

    def test_extra_source_executable_rejected(self):
        r,p,g=inputs();r['filePins'].append(pin(r'C:\CollectorSources\extra.exe'))
        with self.assertRaisesRegex(ValueError,'no-extra-file'):C.validate(r,{'contract':W.CONTRACT_SHA,'worker':W.WORKER_SHA},g)

    def test_alias_and_missing_runtime_member_rejected(self):
        for change in ('alias','runtime'):
            r,p,g=inputs()
            if change=='alias':r['filePins'].append(copy.deepcopy(r['filePins'][0]))
            else:r['treePins'][0]['files'].remove('python313.dll')
            with self.assertRaises(ValueError):C.validate(r,{'contract':W.CONTRACT_SHA,'worker':W.WORKER_SHA},g)

    def test_other_session_or_boot_or_ordinary_task_rejected(self):
        for key in ('session','boot','task'):
            r,p,g=inputs()
            if key=='session':r['context']['systemSessionId']=2
            elif key=='boot':g['boot']['machineGuid']=OP
            else:r['collectorRequest']['ordinaryTaskOperationId']=OP
            with self.assertRaises(ValueError):C.validate(r,{'contract':W.CONTRACT_SHA,'worker':W.WORKER_SHA},g)

    def test_outer_transport_and_arbitrary_stage_not_admitted(self):
        r,p,g=inputs();r['collectorRequest']['stage']='transport-restored'
        with self.assertRaises(ValueError):C.validate(r,{'contract':W.CONTRACT_SHA,'worker':W.WORKER_SHA},g)

    def test_ordinary_writer_root_rejected_before_any_launch(self):
        r,p,g=inputs();next(x for x in r['directoryPins'] if x['path']==r['operationRoot'])['security']={'ownerSid':SID,'sddl':'ordinary-writable-declared-peer'}
        with self.assertRaisesRegex(ValueError,'machine-writer-operation-root-policy'):
            C.validate(r,{'contract':W.CONTRACT_SHA,'worker':W.WORKER_SHA},g)

    def test_owner_dacl_projection_matches_native_security_query(self):
        # Both admitted Native.security and ScFacts.Security request flags5:
        # OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, no group.
        s='O:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;'+SID+')'
        C.root_policy({'ownerSid':'S-1-5-18','sddl':s},SID)

    def test_original_task_documents_join_actual_request_sources_and_workspace(self):
        r,p,g=inputs();t=r['ordinaryTask'];raw=[TASK_DOCUMENTS[t[k]['sha256']] for k in ('bootstrapRequestPin','workerRequestPin')]
        self.assertEqual(len(C.task_documents(r,*raw)),2)
        r['collectorRequest']['context']['workspace']=r'C:\AnotherOperation\workspace'
        with self.assertRaisesRegex(ValueError,'workspace-request-join'):C.task_documents(r,*raw)


class RenderTests(unittest.TestCase):
    def test_two_independent_operations_can_reuse_identical_held_contract_bytes(self):
        r,p,g=inputs()
        first=W.render_source(r,p,CONTRACT,TEMPLATE,E,g)
        second=W.render_source(r,p,CONTRACT,TEMPLATE,E,g)
        self.assertEqual(first,second)

    def test_real_current_builder_selects_saved_source_with_all_original_bounds(self):
        r,p,g=inputs();source=W.render_source(r,p,bytes(bytearray(CONTRACT)),TEMPLATE,E,g)
        plan=E.build_guest_exec(source,guest_context=g,phase_id=OP)
        self.assertEqual(plan['transport'],'saved-source');self.assertLessEqual(len(source),32768)
        self.assertLessEqual(plan['bounds']['serializedRequestBytes'],60000)
        self.assertLessEqual(plan['bounds']['commandUtf16UnitsIncludingNul']+1024,32767)
        self.assertEqual(base64.b64decode(plan['arguments']['input-data']),source)
        self.assertIn('function Read-ProgramBootstrap',source.decode('utf-8-sig'))

    def test_changed_template_or_request_bytes_refuse_before_launch(self):
        r,p,g=inputs()
        with self.assertRaises(ValueError):W.render_source(r,p,bytes(bytearray(CONTRACT)),TEMPLATE+b'\n',E,g)
        p['sha256']='f'*64
        with self.assertRaises(ValueError):W.render_source(r,p,bytes(bytearray(CONTRACT)),TEMPLATE,E,g)

    def test_representative_long_native_source_path_and_dacl_fit_existing_request_budget(self):
        r,p,g=inputs();old=r['modules']['nativeBridge']['path']
        new=g['sourceWorkspace']+'\\collector-sources\\system_collector_native.cs'
        r['modules']['nativeBridge']['path']=new
        for item in r['filePins']:
            if item['path']==old:item['path']=new
        present={x['path'] for x in r['directoryPins']}
        for parent in PureWindowsPath(new).parents:
            if str(parent) not in present:r['directoryPins'].append(pin(str(parent),directory=True));present.add(str(parent))
        dacl='O:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;'+SID+')'
        for item in r['filePins']:
            if item['path']==new:item['security']['sddl']=dacl
        p=pin(r['requestPath'],C.request_digest(r),size=len(C.encoded(r)));p['security']['sddl']=dacl
        source=W.render_source(r,p,bytes(bytearray(CONTRACT)),TEMPLATE,E,g)
        plan=E.build_guest_exec(source,guest_context=g,phase_id=OP)
        self.assertLessEqual(plan['bounds']['serializedRequestBytes'],60000)


class HostCustodyTests(unittest.TestCase):
    def setup_wrapper(self):
        r,p,g=inputs();peer=ParentPeer(r,g)
        obj=W.RetainedSystemCollector(peer.n,r,p,bytes(bytearray(CONTRACT)),TEMPLATE)
        return r,p,peer,obj

    def test_intent_precedes_one_start_and_only_original_pid_is_observed(self):
        r,p,peer,obj=self.setup_wrapper();peer.answers=[{'pid':909},{'exited':False}]
        self.assertEqual(obj.start(),{'pid':909})
        self.assertFalse(obj.observe()['exited'])
        with self.assertRaisesRegex(ValueError,'already-consumed'):obj.start()
        rpc=[x for x in peer.log if x[0]=='rpc'];self.assertEqual([x[1] for x in rpc],['guest-exec','guest-exec-status'])
        self.assertEqual(rpc[1][2],{'pid':909})
        intent=next(i for i,x in enumerate(peer.log) if x[:2]==('save','declared-collector.collector-start-intent.json'))
        self.assertLess(intent,next(i for i,x in enumerate(peer.log) if x[0]=='rpc'))

    def test_unknown_start_retains_original_without_second_submit(self):
        r,p,peer,obj=self.setup_wrapper();peer.answers=[OSError('uncertain original wire')]
        with self.assertRaises(Parked):obj.start()
        self.assertIn(obj,peer.owner.system_collector_wrappers);self.assertIsNotNone(obj.plan)
        with self.assertRaises(ValueError):obj.start()
        self.assertEqual(len([x for x in peer.log if x[0]=='rpc']),1)

    def test_intent_write_failure_parks_without_native_start(self):
        r,p,peer,obj=self.setup_wrapper();peer.fail_save='start-intent'
        with self.assertRaises(Parked):obj.start()
        self.assertFalse(any(x[0]=='rpc' for x in peer.log))

    def test_other_holder_or_closed_owner_cannot_observe(self):
        r,p,peer,obj=self.setup_wrapper();peer.answers=[{'pid':909}];obj.start()
        peer.n['QGA_OWNER']=types.SimpleNamespace()
        with self.assertRaises(Parked):obj.observe()
        self.assertEqual(len([x for x in peer.log if x[0]=='rpc']),1)

    def test_truncated_or_missing_exit_or_signal_never_finishes(self):
        for change in ({'out-truncated':True},{'exitcode':None},{'signal':9}):
            r,p,peer,obj=self.setup_wrapper();peer.answers=[{'pid':909}];obj.start()
            status={'exited':True,'exitcode':0,**change};peer.answers=[status]
            with self.assertRaises(Parked):obj.observe()
            self.assertFalse(peer.finished)

    def test_full_child_capture_and_generation_are_required(self):
        r,p,peer,obj=self.setup_wrapper();obj.proof=child_proof(r,p)
        obj.proof['captures'][0]['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'full-capture'):obj.validate_child()
        r,p,peer,obj=self.setup_wrapper();obj.proof=child_proof(r,p)
        child=json.loads(base64.b64decode(obj.proof['captures'][0]['base64']))
        child['workerActor']['pid']=444;raw=C.encoded(child);v=obj.proof['captures'][0]
        v.update(sizeBytes=len(raw),sha256=W.digest(raw),base64=base64.b64encode(raw).decode());v['nativeIdentity']['sizeBytes']=len(raw)
        with self.assertRaisesRegex(ValueError,'current-system-actor'):obj.validate_child()

    def test_complete_dual_raw_streams_and_child_result_retained(self):
        r,p,peer,obj=self.setup_wrapper();obj.proof=child_proof(r,p);obj.validate_child()
        self.assertEqual(peer.files['declared-collector.collector-child.stderr.raw'],b'')
        self.assertEqual(obj.worker_result['workerActor']['pid'],818)

    def test_finish_cannot_succeed_while_original_running(self):
        r,p,peer,obj=self.setup_wrapper();peer.answers=[{'pid':909}];obj.start()
        with self.assertRaisesRegex(ValueError,'not-known-closed'):obj.finish()
        self.assertFalse(peer.finished)

    def test_actual_decoder_full_terminal_finish_and_observe_do_not_reissue(self):
        r,p,peer,obj=self.setup_wrapper();peer.answers=[{'pid':909}];obj.start()
        peer.answers=[terminal_reply(obj,child_proof(r,p))]
        terminal=obj.observe();self.assertIs(obj.observe(),terminal)
        result=obj.finish();self.assertEqual(result['state'],'collector-completed');self.assertTrue(peer.finished)
        self.assertEqual([x[1] for x in peer.log if x[0]=='rpc'],['guest-exec','guest-exec-status'])
        self.assertIn('declared-collector.collector-qga.stdout.raw',peer.files)
        self.assertIn('declared-collector.collector-child.stdout.raw',peer.files)
        with self.assertRaises(ValueError):obj.finish()

    def test_actual_decoder_rejects_other_original_bootstrap_pid(self):
        r,p,peer,obj=self.setup_wrapper();peer.answers=[{'pid':909}];obj.start()
        status=terminal_reply(obj,child_proof(r,p))
        envelope=json.loads(base64.b64decode(status['out-data']))
        envelope['bootstrapOpening']['pid']=777
        status['out-data']=base64.b64encode(C.encoded(envelope)).decode();peer.answers=[status]
        with self.assertRaises(Parked):obj.observe()
        self.assertFalse(peer.finished)

    def test_failed_guest_terminal_preserves_full_diagnostics_before_parking(self):
        r,p,peer,obj=self.setup_wrapper();peer.answers=[{'pid':909}];obj.start()
        out=b'known partial observer record\n';err=b'actual declared child failure\n'
        peer.answers=[{'exited':True,'exitcode':1,'out-data':base64.b64encode(out).decode(),
            'err-data':base64.b64encode(err).decode()}]
        with self.assertRaises(Parked):obj.observe()
        self.assertEqual(obj.terminal['exitcode'],1)
        self.assertEqual(peer.files['declared-collector.collector-qga.stdout.raw'],out)
        self.assertEqual(peer.files['declared-collector.collector-qga.stderr.raw'],err)


class WorkerCustodyTests(unittest.TestCase):
    def test_dead_original_ordinary_worker_fails_current_guard(self):
        expected={'pid':71,'creationFileTime':1,'image':r'C:\actor.exe','sha256':'a'*64,'sid':SID,'sessionId':2}
        actual={'token':{'elevated':0,'elevationType':1}}
        process=types.SimpleNamespace(describe=lambda:actual,wait=lambda:0)
        owner=types.SimpleNamespace(ordinary_handles=[{'expected':expected,'process':process}],
            task_observer=types.SimpleNamespace(require_identity=lambda a,e:None))
        with self.assertRaisesRegex(ValueError,'original-ordinary-task-not-live'):K.guard_ordinary_handles(owner)

    def test_updater_calls_only_the_frozen_one_stage_and_closes_sources(self):
        r,p,g=inputs();calls=[]
        owner=types.SimpleNamespace(request=r,close_known=lambda:{'sourceClosing':True},self_actor=lambda:{'pid':5})
        collector=types.SimpleNamespace(collect_and_publish=lambda *a:calls.append(a) or {'collector':'fixed'})
        result=K.run_collection(owner,{'collector':collector,'receipts':'declared-receipts','observer':'declared-observer'})
        self.assertEqual(len(calls),1);self.assertIs(calls[0][0],r['collectorRequest']);self.assertEqual(len(result['publications']),1)

    def test_tun_retains_same_handles_across_partial_off_without_reopen_or_stop(self):
        r,p,g=inputs('tun');log=[]
        class Process:
            def __init__(self,role,states):self.role=role;self.states=iter(states)
            def times(self):return {'creationFileTime':77}
            def wait(self):log.append(('wait',self.role));return next(self.states)
        helper=Process('helper',[258,0,0]);runtime=Process('runtime',[258,258,0])
        custody=types.SimpleNamespace(handles=[('helperActor',{'creationFileTime':77},helper),('runtimeActor',{'creationFileTime':77},runtime)])
        owner=types.SimpleNamespace(request=r,guard=lambda:log.append(('guard',)),close_known=lambda:{'sourceClosing':True},self_actor=lambda:{'pid':5})
        def publish(c,stage):self.assertIs(c,custody);log.append(('publish',stage));return {'stage':stage}
        collector=types.SimpleNamespace(collect_ready=lambda *a:custody,publish=publish)
        with patch.object(K.time,'sleep',lambda _:None),patch.object(K,'wait_caller_ready',lambda *a:None):result=K.run_collection(owner,{'collector':collector,'receipts':None,'observer':None})
        self.assertEqual([x for x in log if x[0]=='publish'],[('publish','ready'),('publish','off')])
        self.assertEqual([x for x in log if x==('wait','helper')],[('wait','helper')]*3)
        self.assertEqual(len(result['publications']),2)

    def test_unknown_original_tun_wait_never_publishes_off(self):
        r,p,g=inputs('tun');stages=[]
        process=types.SimpleNamespace(times=lambda:{'creationFileTime':77},wait=lambda:0xffffffff)
        custody=types.SimpleNamespace(handles=[('helperActor',{'creationFileTime':77},process)])
        owner=types.SimpleNamespace(request=r,guard=lambda:None)
        collector=types.SimpleNamespace(collect_ready=lambda *a:custody,publish=lambda c,s:stages.append(s))
        with self.assertRaisesRegex(ValueError,'handle-unknown'):
            K.run_collection(owner,{'collector':collector,'receipts':None,'observer':None})
        self.assertEqual(stages,['ready'])


class WorkerReadyBarrierTests(unittest.TestCase):
    def peer(self,change=None,missing=False,read_error=2):
        r,record,g=inputs(with_hold=True);hold=hold_observation(r,record);log=[]
        system={'creationFileTime':133000000000000009,'image':r['ordinaryTask']['ownerActor']['image'],
            'sha256':r['ordinaryTask']['ownerActor']['sha256'],
            'token':{'sid':'S-1-5-18','elevated':1,'sessionId':0}}
        process=types.SimpleNamespace(describe=lambda:system,wait=lambda:258)
        native=types.SimpleNamespace(open_process=lambda pid,access:log.append(('open-parent',pid)) or process)
        owner=types.SimpleNamespace(request=r,task_native=native,pins=[types.SimpleNamespace(record=record)],
            guard=lambda:log.append(('ordinary-source-guard',)),self_actor=lambda:{'pid':818,'birthFileTimeUtc':'133000000000000008'})
        class Missing(OSError):winerror=read_error
        class Observation:
            attempts=0
            def __init__(self,owner,path):
                Observation.attempts+=1;self.handle=None
                if missing and Observation.attempts==1:raise Missing('declared absent READY')
                self.handle=33;self.opening=hold['nativeFile']
            def read(self,maximum):
                ready=copy.deepcopy(hold['ready'])
                if change:change(ready)
                return H.encoded(ready)
        receipts=types.SimpleNamespace(FileObservation=Observation,ctypes=__import__('ctypes'))
        return owner,{'receipts':receipts,'holdProtocol':H},log

    def test_ready_wait_retains_original_parent_and_created_file_before_close(self):
        owner,modules,log=self.peer(missing=True)
        with patch.object(K.os,'getppid',lambda:909),patch.object(K.time,'sleep',lambda _:None):
            result=K.wait_caller_ready(owner,modules)
        self.assertTrue(result['originalHandleRetained']);self.assertEqual(len(owner.caller_ready_observations),2)
        self.assertEqual([x for x in log if x[0]=='open-parent'],[('open-parent',909)])
        self.assertEqual(result['ready']['systemActor']['pid'],909)
        self.assertEqual(result['sha256'],W.digest(H.encoded(result['ready'])))

    def test_ready_writer_sharing_window_is_only_a_read_retry(self):
        owner,modules,log=self.peer(missing=True,read_error=32)
        with patch.object(K.os,'getppid',lambda:909),patch.object(K.time,'sleep',lambda _:None):
            result=K.wait_caller_ready(owner,modules)
        self.assertEqual(result['ready']['systemActor']['pid'],909)
        self.assertEqual(len(owner.caller_ready_observations),2)
        self.assertEqual([x for x in log if x[0]=='open-parent'],[('open-parent',909)])

    def test_foreign_ready_or_missing_child_eof_never_reaches_known_close(self):
        for change in (lambda v:v.update(collectorRequestSha256='0'*64),
                lambda v:v.update(allOriginalChildrenTerminalAndEof=False),
                lambda v:v['collectorChild'].update(pid=918)):
            owner,modules,log=self.peer(change=change)
            with patch.object(K.os,'getppid',lambda:909),self.assertRaises(ValueError):K.wait_caller_ready(owner,modules)
            self.assertEqual(len(owner.caller_ready_observations),1)
            self.assertIsNotNone(owner.caller_ready_observations[0].handle)

    def test_collection_publication_then_ready_then_source_close_order(self):
        r,p,g=inputs(with_hold=True);log=[]
        owner=types.SimpleNamespace(request=r,close_known=lambda:log.append('source-close') or {'sourceClosing':True},
            self_actor=lambda:{'pid':818})
        collector=types.SimpleNamespace(collect_and_publish=lambda *a:log.append('publication') or {})
        with patch.object(K,'wait_caller_ready',lambda *a:log.append('caller-ready') or {'held':True}):
            result=K.run_collection(owner,{'collector':collector,'receipts':None,'observer':None})
        self.assertEqual(log,['publication','caller-ready','source-close']);self.assertEqual(result['callerHold'],{'held':True})


class ReleaseHandshakeTests(unittest.TestCase):
    def setup_held(self):
        r,p,g=inputs(with_hold=True);peer=ParentPeer(r,g)
        obj=W.RetainedSystemCollector(peer.n,r,p,bytes(bytearray(CONTRACT)),TEMPLATE,
            (B/'release_template.ps1').read_bytes(),(B/'hold_protocol.py').read_bytes())
        peer.answers=[{'pid':909}];obj.start()
        peer.answers=[terminal_reply(obj,child_proof(r,p))];obj.observe()
        return r,p,peer,obj

    def release_reply(self,obj):
        r=obj.request;record=obj.release_record
        proof={'schemaVersion':1,'state':'collector-release-published','operationId':r['operationId'],
            'requestSha256':obj.request_pin['sha256'],'releasePath':r['closeHold']['releasePath'],
            'releaseSha256':W.digest(H.encoded(record)),
            'releaseNativeIdentity':pin('C:\\release',size=len(H.encoded(record)))['nativeIdentity'],
            'sourceClosing':True,'originalCollectorKnownClosed':True,'productMutation':False}
        proxy=types.SimpleNamespace(n=obj.n,ack=obj.release_ack,plan=obj.release_plan)
        return terminal_reply(proxy,proof)

    def test_exact_two_way_handshake_full_original_closure_before_one_ack(self):
        r,p,peer,obj=self.setup_held()
        with self.assertRaisesRegex(ValueError,'not-known-closed'):obj.finish()
        self.assertFalse(peer.finished)
        peer.answers=[{'pid':910}];self.assertEqual(obj.start_release(),{'pid':910})
        self.assertEqual(obj.release_record['closure']['qgaStdoutSha256'],W.digest(obj.raw['stdout']))
        self.assertEqual(obj.release_record['closure']['systemSourceSha256'],W.digest(obj.source))
        self.assertLessEqual(obj.release_plan['bounds']['serializedRequestBytes'],60000)
        self.assertLessEqual(obj.release_plan['bounds']['commandUtf16UnitsIncludingNul']+1024,32767)
        peer.answers=[self.release_reply(obj)];terminal=obj.observe_release()
        self.assertIs(obj.observe_release(),terminal);obj.finish();self.assertTrue(peer.finished)
        self.assertEqual([x[1] for x in peer.log if x[0]=='rpc'],
            ['guest-exec','guest-exec-status','guest-exec','guest-exec-status'])
        intents=[x for x in peer.log if x[0]=='save' and 'release-start-intent' in x[1]]
        self.assertEqual(len(intents),1)
        with self.assertRaises(ValueError):obj.start_release()

    def test_unknown_ack_start_or_terminal_parks_original_and_never_replays(self):
        for kind in ('start','terminal'):
            r,p,peer,obj=self.setup_held()
            if kind=='start':peer.answers=[OSError('declared original ACK wire unknown')]
            else:peer.answers=[{'pid':910}]
            if kind=='start':
                with self.assertRaises(Parked):obj.start_release()
            else:
                obj.start_release();peer.answers=[{'exited':True,'exitcode':1,
                    'out-data':base64.b64encode(b'declared partial ACK raw').decode(),'err-data':''}]
                with self.assertRaises(Parked):obj.observe_release()
                self.assertEqual(peer.files['declared-collector.collector-release-qga.stdout.raw'],b'declared partial ACK raw')
            self.assertFalse(peer.finished)
            with self.assertRaises(ValueError):obj.start_release()
            self.assertEqual(sum(x[0]=='rpc' and x[1]=='guest-exec' for x in peer.log),2)

    def test_other_ready_actor_cannot_authorize_ack(self):
        r,p,peer,obj=self.setup_held();obj.worker_result['callerHold']['ready']['systemActor']['pid']=711
        # The native child proof is authoritative and is re-decoded, so changing
        # only a cached Python projection cannot bypass it.
        proof=obj.proof;raw=base64.b64decode(proof['captures'][0]['base64']);result=H.decode(raw)
        result['callerHold']['ready']['systemActor']['pid']=711
        result['callerHold']['sha256']=W.digest(H.encoded(result['callerHold']['ready']))
        result['callerHold']['nativeFile']['nativeIdentity']['sizeBytes']=len(H.encoded(result['callerHold']['ready']))
        raw=H.encoded(result);v=proof['captures'][0];v.update(base64=base64.b64encode(raw).decode(),sha256=W.digest(raw),sizeBytes=len(raw))
        v['nativeIdentity']['sizeBytes']=len(raw)
        with self.assertRaises(Parked):obj.start_release()
        self.assertFalse(any(x[0]=='rpc' and x[1]=='guest-exec' and i>0 for i,x in enumerate(peer.log)
            if x[0]=='rpc' and x[1]=='guest-exec-status'))
        self.assertFalse(peer.finished)

    def test_release_without_current_root_policy_or_phase_fails_before_rpc(self):
        r,p,peer,obj=self.setup_held();peer.n['NATIVE_PHASE_IDS'][W.RELEASE_LABEL]=OP
        with self.assertRaises(Parked):obj.start_release()
        self.assertEqual(sum(x[0]=='rpc' and x[1]=='guest-exec' for x in peer.log),1)

    def test_machine_request_policy_refuses_inherited_or_ordinary_writable_file(self):
        for security in ({'ownerSid':SID,'sddl':'O:'+SID+'D:P(A;;FA;;;'+SID+')'},
                {'ownerSid':'S-1-5-18','sddl':'O:SYD:AI(A;ID;FA;;;SY)'}):
            r,p,g=inputs();p['security']=security
            with self.assertRaisesRegex(ValueError,'machine-writer-file-policy'):
                W.render_source(r,p,bytes(bytearray(CONTRACT)),TEMPLATE,E,g)

    def test_close_hold_source_must_be_actual_original_worker_input(self):
        r,p,g=inputs(with_hold=True);t=r['ordinaryTask']
        raw=[TASK_DOCUMENTS[t[k]['sha256']] for k in ('bootstrapRequestPin','workerRequestPin')]
        C.task_documents(r,*raw)
        r['closeHold']['callerSourcePin']=pin('C:\\Other\\caller.py','9'*64)
        with self.assertRaisesRegex(ValueError,'caller-hold-original-worker-inputs'):C.task_documents(r,*raw)


if __name__=='__main__':unittest.main()

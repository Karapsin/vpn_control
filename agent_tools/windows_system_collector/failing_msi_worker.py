"""Fixed SYSTEM child. Its PS parent holds all source/runtime bytes before start.

No launch, stop, credentials, token transition or arbitrary collector dispatch.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import types

NATIVE_SHA='ee28050bd0e33166956cc4f4ac68ca10cc89c30c01ae93468379895fee268a18'
CONTRACT_SHA='802303fab31a395853807ac3558144e2c163aa18bf949403844860575a57e6b4'
BOOTSTRAP_CUSTODY=[]


def require(value, reason):
    if not value:raise ValueError(reason)


def guard_ordinary_handles(owner):
    for item in owner.ordinary_handles:
        process=item['process'];expected=item['expected']
        actual=process.describe();owner.task_observer.require_identity(actual,expected)
        require(process.wait()==258 and actual['token']['elevated']==0
            and actual['token']['elevationType']==1,'system-original-ordinary-task-not-live-standard')


def expected_ready(owner, protocol):
    r=owner.request;h=r['closeHold'];w=r['ordinaryTask']['workerActor']
    system=owner.parent_process.describe()
    require(owner.parent_process.wait()==258 and system['token']['sid']=='S-1-5-18'
        and system['token']['elevated']==1 and system['token']['sessionId']==0
        and system['image']==r['ordinaryTask']['ownerActor']['image']
        and system['sha256']==r['ordinaryTask']['ownerActor']['sha256'],
        'system-caller-ready-original-parent-not-live-system')
    return {'schemaVersion':1,'kind':'caller-collector-close-ready',
        'ordinaryTaskOperationId':r['ordinaryTaskOperationId'],'collectorOperationId':r['operationId'],
        'sourceSha':h['sourceSha'],'scope':r['scope'],'stage':h['stage'],
        'bootIdentifier':r['context']['bootIdentifier'],
        'ordinaryWorker':{'pid':w['pid'],'birthFileTimeUtc':str(w['creationFileTime']),
            **{k:w[k] for k in ('image','sha256','sid','sessionId')}},
        'callerSourcePin':h['callerSourcePin'],'collectorRequestSha256':owner.pins[0].record['sha256'],
        'systemActor':{'pid':os.getppid(),'birthFileTimeUtc':str(system['creationFileTime'])},
        'collectorChild':{k:owner.self_actor()[k] for k in ('pid','birthFileTimeUtc')},
        'driverKnownResult':0,'allOriginalChildrenTerminalAndEof':True}


def wait_caller_ready(owner, modules):
    h=owner.request['closeHold']
    if h is None:return None
    receipts=modules['receipts'];protocol=modules['holdProtocol']
    protocol.validate_close_hold(h)
    owner.caller_ready_observations=[]
    # Retain exact original parent handle before inspecting it or opening READY.
    owner.parent_process=None
    owner.parent_process=owner.task_native.open_process(os.getppid(),0x101000)
    expected=expected_ready(owner,protocol)
    while True:
        owner.guard();require(len(owner.caller_ready_observations)<8192,'system-ready-observation-bound')
        value=receipts.FileObservation.__new__(receipts.FileObservation)
        owner.caller_ready_observations.append(value)
        try:
            receipts.FileObservation.__init__(value,owner,h['holdReadyPath'])
        except OSError as error:
            if getattr(error,'winerror',None) in {2,32} and getattr(value,'handle',None) in {None,receipts.ctypes.c_void_p(-1).value}:
                time.sleep(0.1);continue
            raise
        require(value.opening['security']['ownerSid']==owner.request['context']['ordinarySid'],
            'system-ready-original-ordinary-file-owner')
        raw=value.read(262144);ready=protocol.validate_ready(protocol.decode(raw,262144),expected)
        require(expected_ready(owner,protocol)==expected,'system-ready-parent-generation-changed')
        owner.guard()
        return {'ready':ready,'sha256':hashlib.sha256(raw).hexdigest(),
            'nativeFile':value.opening,'originalHandleRetained':True}


def bootstrap_module(path, expected, name):
    # The original native PS parent already holds this exact source without
    # writer/delete sharing. Native pin admission is repeated immediately below.
    raw=Path(path).read_bytes()
    require(0<len(raw)<=2*1024*1024 and hashlib.sha256(raw).hexdigest()==expected,'system-bootstrap-source-bytes')
    module=types.ModuleType(name);module.__file__=path
    require(name not in sys.modules,'system-bootstrap-module-already-registered')
    sys.modules[name]=module;BOOTSTRAP_CUSTODY.append((module,raw))
    exec(compile(raw,path,'exec'),module.__dict__)
    return module


def make_owner_class(native_module, contract):
    class SystemCollectionOwner(native_module.Owner):
        def __init__(self, request, request_pin):
            self.request=request;self.native=request_pin.native;self.pins=[request_pin]
            self.children=[];self.events=0;self.tun_custodies=[];self.by_path={str(request_pin.path).casefold():request_pin}
            self.root=native_module.absolute(request['operationRoot']);self.operation=request['operationId']
            self.raw_limit=request['rawStreamLimitBytes'];self.guard_context()
            require(sys.version_info[:3]==(3,13,15),'system-python-version')
            require(str(Path(sys.executable)).casefold()==request['pythonRuntime']['interpreterPath'].casefold(),
                    'system-admitted-interpreter')
            for r in request['directoryPins']:
                p=native_module.Pin(self.native,r,True);self.pins.append(p)
            for r in request['filePins']:
                p=native_module.Pin(self.native,r);self.pins.append(p)
                require(str(p.path).casefold() not in self.by_path,'system-duplicate-source-pin')
                self.by_path[str(p.path).casefold()]=p
            require(str(Path(__file__)).casefold() in self.by_path,'system-worker-source-pin')
            self.initial_token=self.native.token()
            self.task_observer=self.module(request['modules']['observer']['path'],
                '_system_original_task_observer_'+self.operation.replace('-',''))
            self.ordinary_handles=[];self.task_native=self.task_observer.WindowsNative()
            for role in ('ownerActor','workerActor'):
                item={'expected':request['ordinaryTask'][role],'process':None}
                self.ordinary_handles.append(item)
                item['process']=self.task_native.open_process(item['expected']['pid'],0x101000)
            parents={x['pid']:x['parentPid'] for x in self.task_native.processes()}
            require(parents.get(request['ordinaryTask']['workerActor']['pid'])==request['ordinaryTask']['ownerActor']['pid'],
                    'system-original-ordinary-worker-parent')
            docs=[self.by_path[request['ordinaryTask'][role]['path'].casefold()].digest(True,4*1024*1024)
                  for role in ('bootstrapRequestPin','workerRequestPin')]
            contract.task_documents(request,*docs)
            self.guard()
            self.event('system-collector-started',self.self_actor())

        def self_actor(self):
            return {'pid':os.getpid(),'birthFileTimeUtc':self.native.birth(self.native.k.GetCurrentProcess()),
                'image':str(Path(sys.executable)),'token':self.native.token(),
                'bootIdentifier':self.native.boot_identifier()}

        def guard_context(self):
            c=self.request['context'];t=self.native.token()
            require(t['sid']=='S-1-5-18' and t['elevation']==1 and t['sessionId']==0,
                    'system-collector-current-token-session')
            if hasattr(self,'initial_token'):require(t==self.initial_token,'system-collector-token-changed')
            require(self.native.boot_identifier()==c['bootIdentifier'],'system-collector-native-boot')
            with native_module.winreg.OpenKey(native_module.winreg.HKEY_LOCAL_MACHINE,
                    r'SOFTWARE\Microsoft\Cryptography',0,native_module.winreg.KEY_READ|native_module.winreg.KEY_WOW64_64KEY) as key:
                require(native_module.winreg.QueryValueEx(key,'MachineGuid')[0].casefold()==c['machineGuid'].casefold(),
                        'system-collector-machine-generation')
            if hasattr(self,'ordinary_handles'):guard_ordinary_handles(self)

        def close_known(self):
            require(all(x.closed and x.off is not None for x in self.tun_custodies),'system-tun-original-custody-not-closed')
            self.guard()
            records=[]
            for p in self.pins:
                p.current()
                if not p.directory:records.append({'path':str(p.path),'sha256':p.digest()})
            self.guard()
            return {'sourceClosing':True,'files':len(records),
                'completeFileDigestSha256':hashlib.sha256(contract.encoded(records)).hexdigest()}

        def guard(self):
            super().guard()
            for observation in getattr(self,'caller_ready_observations',()):
                if hasattr(observation,'opening'):
                    require(observation.describe()==observation.opening,'system-held-ready-generation-changed')
                    observation._canonical()

    return SystemCollectionOwner


def run_collection(owner, modules):
    r=owner.request;collector=modules['collector'];publications=[]
    if r['scope']=='update':
        publications.append(collector.collect_and_publish(r['collectorRequest'],owner,modules['receipts'],modules['observer']))
    else:
        custody=collector.collect_ready(r['collectorRequest'],owner,modules['receipts'],modules['observer'])
        publications.append(collector.publish(custody,'ready'))
        # This has no OFF action. It waits only on the original handles while
        # the separate public scenario performs OFF and records its own intent.
        while True:
            owner.guard();exited=[]
            for role,expected,process in custody.handles:
                if role in {'helperActor','runtimeActor'}:
                    require(process.times()['creationFileTime']==expected['creationFileTime'],
                            'system-tun-original-handle-generation')
                    state=process.wait();require(state in {0,258},'system-tun-original-handle-unknown')
                    exited.append(state==0)
                else:
                    modules['observer'].require_identity(process.describe(),expected)
                    require(process.wait()==258,'system-tun-ordinary-owner-ended-before-off-proof')
            require(len(exited)==2,'system-tun-exact-two-original-privileged-actors')
            if all(exited):break
            time.sleep(0.1)
        publications.append(collector.publish(custody,'off'))
    caller_hold=wait_caller_ready(owner,modules)
    closing=owner.close_known()
    return {'schemaVersion':1,'state':'collector-completed','operationId':r['operationId'],
        'ordinaryTaskOperationId':r['ordinaryTaskOperationId'],'scope':r['scope'],
        'collectorSourceSha256':r['modules']['collector']['sha256'],
        'workerActor':owner.self_actor(),'publications':publications,'closing':closing,'callerHold':caller_hold}


def main():
    p=argparse.ArgumentParser();p.add_argument('--request',required=True);p.add_argument('--request-sha256',required=True)
    p.add_argument('--request-pin-base64',required=True);a=p.parse_args()
    record=json.loads(base64.b64decode(a.request_pin_base64,validate=True))
    require(record['path']==a.request and record['sha256']==a.request_sha256,'system-parent-request-pin-join')
    raw=Path(a.request).read_bytes()
    require(0<len(raw)<=4*1024*1024 and hashlib.sha256(raw).hexdigest()==a.request_sha256,'system-parent-held-request')
    request=json.loads(raw)
    contract=bootstrap_module(request['modules']['contract']['path'],CONTRACT_SHA,'_fixed_system_collector_contract')
    contract.validate(request,{'contract':CONTRACT_SHA,'worker':request['modules']['worker']['sha256']})
    native_module=bootstrap_module(request['modules']['native']['path'],NATIVE_SHA,'_fixed_system_collector_native')
    request_pin=native_module.Pin(native_module.Native(),record)
    require(request_pin.digest(True,4*1024*1024)==raw,'system-request-native-repin')
    owner_class=make_owner_class(native_module,contract)
    # Store original object before initialization can acquire any native pins.
    owner=owner_class.__new__(owner_class);BOOTSTRAP_CUSTODY.append(owner)
    try:
        owner_class.__init__(owner,request,request_pin)
        modules={key:owner.module(request['modules'][key]['path'],'_fixed_system_'+key+'_'+request['operationId'].replace('-',''))
                 for key in ('receipts','collector','holdProtocol')}
        modules['observer']=owner.task_observer
        result=run_collection(owner,modules)
        data=contract.encoded(result);require(len(data)<=256*1024,'system-final-output-bound')
        sys.stdout.buffer.write(data);sys.stdout.buffer.flush()
    except BaseException as error:
        # The parent and every partly opened original object remain reachable.
        owner.park('system-collector-original-unknown',error)
    return 0


if __name__=='__main__':
    raise SystemExit(main())

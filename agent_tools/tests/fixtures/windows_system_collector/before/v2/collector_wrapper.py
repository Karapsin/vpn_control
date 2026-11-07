"""Start once / observe exact original / finish a fixed SYSTEM collector.

Called inside the existing newly admitted source-bound host holder namespace.
It neither constructs an SSH connection nor reconstructs another holder.
"""
from __future__ import annotations
import base64
import hashlib
import json
import re
import sys
import types

CONTRACT_SHA='3b7148670ff88675dfcded83786290973160607fa4d647bb6250d1c3a494005d'
WORKER_SHA='d3ab44e9a7d5cd521069f407ffbf7c6a33cae3e237b48cb5dc0750ffecc4bb9a'
TEMPLATE_SHA='f1bf692804e149c2474ec854f463f6808f6bc3061793f9fffb8e84cb6c2700ea'
EMITTER_SHA='2938a7c6c25d23adc9683ced126fe2d3c0a88614dab59a7b134a624d6f8b0ee8'
QGA_SHA='bf05c8f08c1e5210ba79ffb59186206e80dc13fef057748dab3596df8ab6f022'
LABEL='system-collector'


def require(value, reason):
    if not value:raise ValueError(reason)


def digest(raw):return hashlib.sha256(raw).hexdigest()


def contract_module(raw):
    require(type(raw) is bytes and digest(raw)==CONTRACT_SHA,'fixed-collector-contract-source')
    module=types.ModuleType('_retained_system_collector_contract')
    name=module.__name__+'_'+str(id(module))
    require(name not in sys.modules,'fixed-contract-module-preexisting')
    module.__name__=name;module.__file__='collector_contract.py@'+CONTRACT_SHA
    sys.modules[name]=module
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    return module


def render_source(request, request_pin, contract_source, template_source, emitter, guest_context):
    c=contract_module(contract_source)
    c.validate(request,{'contract':CONTRACT_SHA,'worker':WORKER_SHA},guest_context)
    c.pin(request_pin)
    require(request_pin['path']==request['requestPath'] and request_pin['sha256']==c.request_digest(request)
            and request_pin['nativeIdentity']['sizeBytes']==len(c.encoded(request)), 'fixed-parent-request-pin')
    require(type(template_source) is bytes and digest(template_source)==TEMPLATE_SHA,'fixed-system-bootstrap-template')
    template=template_source.decode('utf-8','strict')
    modules={role:record['sha256'] for role,record in request['modules'].items()}
    bridge_pin=next(p for p in request['filePins'] if p['path']==request['modules']['nativeBridge']['path'])
    replacements={'BRIDGE_PIN_BASE64':base64.b64encode(c.encoded(bridge_pin)).decode(), 'REQUEST_PIN_BASE64':base64.b64encode(c.encoded(request_pin)).decode(),
        'OPERATION':request['operationId'],'ORDINARY_OPERATION':request['ordinaryTaskOperationId'],
        'SCOPE':request['scope'],'MODULES_BASE64':"'"+base64.b64encode(c.encoded(modules)).decode()+"'"}
    require(set(re.findall(r'@@([A-Z0-9_]+)@@',template))==set(replacements),'fixed-system-bootstrap-placeholders')
    for key,value in replacements.items():
        require(template.count('@@'+key+'@@')==1,'fixed-system-bootstrap-placeholder-count')
        template=template.replace('@@'+key+'@@',value)
    source=emitter._boot_bound(template,guest_context).encode('utf-8-sig')
    require(len(source)<=32768,'fixed-system-bootstrap-saved-source-budget')
    return source


class RetainedSystemCollector:
    """The original object must stay in the original canonical QGA namespace.

    `namespace` is the already source-bound parent capsule globals, not request
    JSON. Its current guest/host gates and bf05 owner remain authoritative.
    """
    def __init__(self, namespace, request, request_pin, contract_source, template_source):
        self.n=namespace;self.request=json.loads(json.dumps(request));self.request_pin=json.loads(json.dumps(request_pin))
        self.contract_source=contract_source;self.template_source=template_source
        self.owner=namespace['QGA_OWNER'];self.state='prepared';self.consumed=False;self.ack=None
        self.plan=None;self.source=None;self.terminal=None;self.proof=None;self.raw={};self.failure=None
        # Record custody before any later preparation/journal/native effect.
        if not hasattr(self.owner,'system_collector_wrappers'):self.owner.system_collector_wrappers=[]
        self.owner.system_collector_wrappers.append(self)
        self.guard()

    def guard(self):
        n=self.n
        require(n['QGA_OWNER'] is self.owner and n['QGA_MODULE_SHA']==QGA_SHA
                and n['EMITTER_SHA256']==EMITTER_SHA,'original-canonical-collector-owner')
        require(type(n['QGA_MODULE_SOURCE']) is bytes and digest(n['QGA_MODULE_SOURCE'])==QGA_SHA
                and type(n['EMITTER_SOURCE']) is bytes and digest(n['EMITTER_SOURCE'])==EMITTER_SHA,
                'original-complete-canonical-module-bytes')
        q=n['QGA_MODULE'];e=n['EMITTER_MODULE']
        require(sys.modules.get(q.__name__) is q and sys.modules.get(e.__name__) is e
                and isinstance(self.owner,q.RetainedQgaOwner)
                and q.RetainedQgaOwner.call.__globals__ is q.__dict__
                and e.build_guest_exec.__globals__ is e.__dict__
                and e.decode_guest_result.__globals__ is e.__dict__,'original-registered-canonical-functions')
        require(not self.owner.failed and not self.owner.parked and not self.owner.finalized,
                'original-qga-owner-unavailable')
        require(n['QGA_OWNER'].guard is n['QGA_GUARD'],'original-qga-guard-custody')
        n['QGA_GUARD']();n['generated_sources_closing']()

    def park(self, reason, error):
        self.failure={'reason':reason,'error':error};self.state='unknown'
        # The actual bf05 implementation never returns or advances mutations.
        return self.n['park_original']({'kind':'fixed-system-collector','operationId':self.request.get('operationId'),
            'originalAck':self.ack,'state':'unknown','replayAllowed':False},error)

    def start(self):
        require(self.state=='prepared' and not self.consumed,'collector-start-already-consumed')
        self.consumed=True  # Before the first possible intent write or RPC.
        try:
            self.guard()
            require(self.n['NATIVE_PHASE_IDS'].get(LABEL)==self.request['operationId'],'original-collector-phase-id')
            self.source=render_source(self.request,self.request_pin,self.contract_source,self.template_source,
                self.n['EMITTER_MODULE'],self.n['GUEST_CONTEXT'])
            self.plan,source_sha=self.n['build_native_command'](LABEL,self.source)
            require(self.plan['transport']=='saved-source' and source_sha==digest(self.source),
                    'collector-real-held-saved-source-required')
            self.n['save'](self.n['prefix']+'.collector-start-intent.json',{
                'schemaVersion':1,'operationId':self.request['operationId'],
                'ordinaryTaskOperationId':self.request['ordinaryTaskOperationId'],'scope':self.request['scope'],
                'requestPin':self.request_pin,'sourceSha256':source_sha,
                'collectorSourceSha256':self.request['modules']['collector']['sha256'],
                'guestContext':self.n['GUEST_CONTEXT'],'replayAllowed':False})
            self.guard();self.state='start-pending'
            self.ack=self.n['retained_call']('guest-exec',self.plan['arguments'],self.n['overall_deadline'])
            require(type(self.ack) is dict and set(self.ack)=={'pid'} and type(self.ack['pid']) is int and self.ack['pid']>0,
                    'collector-exact-original-qga-ack')
            self.n['save'](self.n['prefix']+'.collector-original-ack.json',self.ack)
            self.state='running';self.guard()
            return dict(self.ack)
        except BaseException as error:
            return self.park('collector-start-unknown',error)

    def observe(self):
        require(self.state in {'running','terminal'},'collector-original-not-observable')
        if self.terminal is not None:return self.terminal
        try:
            self.guard()
            status=self.n['retained_call']('guest-exec-status',self.ack,self.n['overall_deadline'])
            require(type(status) is dict and type(status.get('exited')) is bool,'collector-status-schema')
            if not status['exited']:
                require(set(status)=={'exited'},'collector-pending-status-fields')
                return {'exited':False,'originalPid':self.ack['pid'],'replayAllowed':False}
            self.terminal=status
            self.n['save'](self.n['prefix']+'.collector-original-terminal.json',status)
            for name,key in (('stdout','out-data'),('stderr','err-data')):
                data=status.get(key,'');require(type(data) is str and len(data)<=12*1024*1024,'collector-qga-raw-encoded-bound')
                self.raw[name]=base64.b64decode(data,validate=True)
                require(len(self.raw[name])<=8*1024*1024,'collector-qga-raw-decoded-bound')
                self.n['save'](self.n['prefix']+'.collector-qga.'+name+'.raw',self.raw[name])
            require(set(status)<= {'exited','exitcode','signal','out-data','err-data','out-truncated','err-truncated'}
                    and type(status.get('exitcode')) is int and status['exitcode']==0 and 'signal' not in status
                    and all(type(status.get(k,False)) is bool and status.get(k,False) is False
                            for k in ('out-truncated','err-truncated')),'collector-original-terminal-or-truncation')
            require(not self.raw['stderr'],'collector-qga-unexpected-stderr')
            parsed=json.loads(self.raw['stdout'].decode('utf-8-sig','strict'))
            self.proof=self.n['EMITTER_MODULE'].decode_guest_result(self.plan,parsed,self.n['GUEST_CONTEXT'],self.ack['pid'])
            self.validate_child()
            self.guard();self.state='terminal';return status
        except BaseException as error:
            return self.park('collector-observation-unknown',error)

    def validate_child(self):
        p=self.proof;r=self.request
        expected={'schemaVersion','state','operationId','ordinaryTaskOperationId','scope','collectorSourceSha256',
            'requestSha256','requestNativeIdentity','worker','captures','sourceClosing','productMutation',
            'bootstrapOpening','bootstrapClosing','guestBootClosing','bootstrapActorClosing'}
        require(type(p) is dict and set(p)==expected and p['schemaVersion']==1 and p['state']=='collector-closed'
            and p['operationId']==r['operationId'] and p['ordinaryTaskOperationId']==r['ordinaryTaskOperationId']
            and p['scope']==r['scope'] and p['collectorSourceSha256']==r['modules']['collector']['sha256']
            and p['requestSha256']==self.request_pin['sha256'] and p['requestNativeIdentity']==self.request_pin['nativeIdentity']
            and p['sourceClosing'] is True and p['productMutation'] is False,'collector-closed-child-origin')
        w=p['worker']
        require(type(w) is dict and set(w)=={'pid','birthFileTimeUtc','image','sessionId','exitCode','bothEof','originalHandleRetained'}
            and type(w['pid']) is int and w['pid']>0 and type(w['birthFileTimeUtc']) is str
            and re.fullmatch('[1-9][0-9]{16,19}',w['birthFileTimeUtc']) and w['image']==r['pythonRuntime']['interpreterPath']
            and type(w['sessionId']) is int and w['sessionId']==0 and type(w['exitCode']) is int and w['exitCode']==0
            and w['bothEof'] is True and w['originalHandleRetained'] is True,'collector-original-child-native-generation')
        require(type(p['captures']) is list and len(p['captures'])==2,'collector-dual-full-captures')
        captures={}
        for value in p['captures']:
            require(type(value) is dict and set(value)=={'name','sizeBytes','sha256','base64','eof','nativeIdentity'}
                and value['name'] in {'stdout','stderr'} and value['name'] not in captures and value['eof'] is True
                and type(value['sizeBytes']) is int and 0<=value['sizeBytes']<=r['rawStreamLimitBytes']
                and type(value['base64']) is str and len(value['base64'])<=4*r['rawStreamLimitBytes']//3+4,
                'collector-original-child-capture-schema')
            raw=base64.b64decode(value['base64'],validate=True)
            require(len(raw)==value['sizeBytes'] and digest(raw)==value['sha256']
                    and value['nativeIdentity'].get('sizeBytes')==len(raw),'collector-original-child-full-capture-digest')
            captures[value['name']]=raw
            self.n['save'](self.n['prefix']+'.collector-child.'+value['name']+'.raw',raw)
        require(not captures['stderr'],'collector-child-unexpected-stderr')
        result=json.loads(captures['stdout'].decode('utf-8','strict'))
        require(type(result) is dict and set(result)=={'schemaVersion','state','operationId','ordinaryTaskOperationId',
            'scope','collectorSourceSha256','workerActor','publications','closing'} and result['schemaVersion']==1
            and result['state']=='collector-completed' and all(result[k]==p[k] for k in
                ('operationId','ordinaryTaskOperationId','scope','collectorSourceSha256')),'collector-child-result-join')
        actor=result['workerActor']
        require(actor['pid']==w['pid'] and actor['birthFileTimeUtc']==w['birthFileTimeUtc'] and actor['image']==w['image']
            and actor['bootIdentifier']==r['context']['bootIdentifier'] and actor['token']['sid']=='S-1-5-18'
            and actor['token']['sessionId']==0 and actor['token']['elevation']==1,'collector-child-current-system-actor')
        require(result['closing'].get('sourceClosing') is True and type(result['closing'].get('files')) is int
            and result['closing']['files']==len(r['filePins'])+1
            and re.fullmatch('[a-f0-9]{64}',result['closing'].get('completeFileDigestSha256','')),
            'collector-child-complete-source-closing')
        require(type(result['publications']) is list and len(result['publications'])==(1 if r['scope']=='update' else 2),
                'collector-finite-publication-count')
        self.worker_result=result

    def finish(self):
        require(self.state=='terminal' and self.proof is not None,'collector-original-not-known-closed')
        try:
            self.guard();self.n['finalize_rpc_success']();self.state='finished'
            # No process stop, source-pin release or new RPC occurs here.
            self.n['save'](self.n['prefix']+'.collector-complete.json',{'schemaVersion':1,
                'operationId':self.request['operationId'],'originalAck':self.ack,'sourceClosing':True,
                'bothRawCapturesComplete':True,'replayAllowed':False})
            return self.worker_result
        except BaseException as error:
            return self.park('collector-finish-unknown',error)

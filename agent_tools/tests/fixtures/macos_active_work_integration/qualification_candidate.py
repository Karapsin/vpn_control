"""Fixed read-only post-install qualification. NOT an action or CLI.

The reviewed durable host controller must start the single 90s group BEFORE
SourceSession/factory construction, hold this exact code plus pins, and install
this callback inside its private SourceSession BEFORE constructing MacCustody.
No install/GUI/credential/source publication or capability setter exists here.
"""
from contextlib import ExitStack,contextmanager
import hashlib,json,os,sys,time,types
from pathlib import Path
_CODE=sys._getframe().f_code
class Blocked(ValueError):pass
def need(ok,reason):
    if not ok:raise Blocked(reason)
def save(directory,name,value):
    raw=value if type(value)is bytes else json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    need(type(name)is str and '/'not in name and 0<len(raw)<=2097152,'qualification_record_bound')
    # The raw callback writer has only its already-held private directory FD.
    # No source/named-route gate is interposed before its immediate fsync.
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory.fd)
    try:
        offset=0
        while offset<len(raw):
            n=os.write(fd,raw[offset:]);need(n>0,'qualification_short_write');offset+=n
        os.fsync(fd)
    finally:os.close(fd)
    os.fsync(directory.fd)
def _load(held,name):
    m=types.ModuleType(name);m.__file__=str(held.path);sys.modules[name]=m
    exec(compile(held.body,str(held.path),'exec',dont_inherit=True),m.__dict__);return m

@contextmanager
def capture_before_factory(session,descriptor,output,*,deadline):
    """Private same-session hook; current actual custody authorizes each GET.
    Exact fixed source pins derive from this source-owned packet, never caller
    code/argv/path input. Raw streams survive ordinary_guest_call postguard.
    """
    mac=session.load('readiness_tart_macos_registry');protocol=session.load('readiness_qemu_jobs');J=mac.jobs;backend=session.load('readiness_tart_macos')
    descriptor=json.loads(json.dumps(descriptor))
    need(time.monotonic()<deadline<=time.monotonic()+90,'qualification_group_deadline')
    own=Path(__file__).resolve();raw=own.read_bytes();need(_CODE==compile(raw,str(own),'exec',dont_inherit=True),'qualification_loaded_source_changed')
    with ExitStack()as stack:
        proofs=[]
        def held(path,wanted):
            proof=stack.enter_context(mac.PublicProof(path,{'sha256':wanted,'generation':list(mac.private._generation(path.lstat()))}));proofs.append(proof);return proof
        selfproof=held(own,hashlib.sha256(raw).hexdigest())
        manifest_path=own.with_name('qualification-pins.json');manifest=held(manifest_path,'bf412f06eca0a46c47a70a34edc604c17574f42e899046edbb35ba6bce05e2ce').value()
        need(type(manifest)is dict and set(manifest)=={'capture','decoder','configuration','ordinary','shape'},'qualification_pins_invalid')
        bodies={}
        for role,row in manifest.items():
            proof=held(Path(row['path']),row['sha256']);need(len(proof.body)==row['bytes'],'qualification_source_size');bodies[role]=proof
        capture=_load(bodies['capture'],'_fixed_active_capture_'+session.prefix);decoder=_load(bodies['decoder'],'_fixed_active_decoder_'+session.prefix);shape=_load(bodies['shape'],'_fixed_active_shape_'+session.prefix)
        cfg=json.loads(bodies['configuration'].body);ordinary=bodies['ordinary'].body
        need(descriptor['provider']=='tart-macos'and descriptor['binding']['machine']==cfg['machine']and descriptor['binding']['ordinary_uid']==cfg['ordinaryUid']and descriptor['binding']['ordinary_account']==cfg['ordinaryPrincipal'],'qualification_selected_principal')
        run=Path(descriptor['originalRun']['path']).parent;runproof=held(Path(descriptor['originalRun']['path']),descriptor['originalRun']['pin']['sha256'])
        need(list(runproof.generation)==descriptor['originalRun']['pin']['generation'],'qualification_run_changed')
        original=runproof.value()['operationId'];state={'phase':'factory','calls':0,'callbacks':[]}
        def guard():
            need(time.monotonic()<deadline,'qualification_group_deadline');session.guard();output.guard()
            for proof in proofs:proof.guard()
        def captured(selected,argv,payload,call_deadline):
            guard();need(type(selected)is mac.MacCustody,'qualification_actual_custody_required')
            need(selected.descriptor==descriptor and selected.binding==backend.MacBinding(**descriptor['binding']) and selected.run_intent['operationId']==original and selected.lifecycle_root==run,'qualification_actual_target_changed')
            need(type(payload)is bytes and 0<len(payload)<=262144,'qualification_payload_bound')
            canonical,_=protocol.stdin_command(payload.decode('utf-8','strict'))
            need(tuple(argv)==(selected.binding.tart_binary,'exec','-i',selected.binding.vm_name,selected.binding.guest_python,*canonical[1:]),'qualification_fixed_carrier')
            probe=mac.guest_probe_source(selected.binding,prefix=selected.guest_proof['prefix'],public_files=selected.guest_proof['publicFiles']).encode()
            need(payload in(probe,ordinary),'qualification_fixed_source_only')
            need(state['calls']<16,'qualification_rpc_bound');state['calls']+=1
            label='call-'+str(state['calls'])+'-'+state['phase']
            save(output,label+'.request.stdin',payload);save(output,label+'.request.json',{'argv':list(argv),'sourceSha256':hashlib.sha256(payload).hexdigest(),'originalRun':original,'phase':state['phase']})
            with capture.PublicRpcCapture(output,label)as retained:
                try:
                    result,callback=retained.run(argv,payload,deadline=min(call_deadline,deadline),birth=J._birth,parent=lambda pid:mac._parent(pid,min(deadline,time.monotonic()+2)))
                finally:
                    # Every partial/full callback is already retained inside the
                    # actual carrier; retain its bounded joined copy before gates.
                    if retained.callback:save(output,label+'.joined-callback.jsonl',bytes(retained.callback))
            state['callbacks'].append(callback);guard();return result
        old=mac.MacCustody._native_call;mac.MacCustody._native_call=captured
        stack.callback(setattr,mac.MacCustody,'_native_call',old)
        guard();yield Qualification(session,mac,protocol,output,state,guard,ordinary,cfg,decoder,shape,descriptor,deadline);guard()

class Qualification:
    def __init__(self,session,mac,protocol,output,state,guard,ordinary,cfg,decoder,shape,descriptor,deadline):
        self.session,self.mac,self.protocol,self.output,self.state,self.guard,self.ordinary,self.cfg,self.decoder,self.shape,self.descriptor,self.deadline=session,mac,protocol,output,state,guard,ordinary,cfg,decoder,shape,descriptor,deadline
    def run(self,custody):
        need(type(custody)is self.mac.MacCustody and custody.descriptor==self.descriptor,'qualification_actual_custody_required')
        c=custody
        with c.operator(deadline=self.deadline):
            self.guard();c.guard(deadline=self.deadline)
            self.state['phase']='root-before';before=c.guest_probe(c.binding,self.deadline)
            self.state['phase']='observer';argv,payload=self.protocol.stdin_command(self.ordinary.decode('utf-8'))
            result=None;error=None
            try:result=c.ordinary_guest_call(c.binding,argv,payload,self.deadline)
            except BaseException as e:error=e
            # Raw observer reply is already durable, even when postguard above
            # failed. No further GET after a source/custody failure.
            if error is not None:raise error
            self.guard();c.guard(deadline=self.deadline)
            self.state['phase']='root-after';after=c.guest_probe(c.binding,self.deadline)
            save(self.output,'root-before.json',before);save(self.output,'root-after.json',after)
            self.guard();need(before['facts']['boot']==after['facts']['boot']and before['agent']==after['agent'],'qualification_actual_identity_changed')
            need(type(result.returncode)is int and result.stderr==b'','qualification_outer_reply_blocked')
            answer=self.decoder.decode_caller_output(result.stdout,result.returncode,self.cfg,self.shape,expected_boot=before['facts']['boot'])
            self.guard();save(self.output,'decoded-diagnostic.json',answer)
            # Diagnostic data never sets readiness or lifecycle capabilities.
            return {'schemaVersion':1,'state':'diagnostic_data_retained','nativeQualified':False,'idleAuthority':False,'inputAuthority':False,'lifecycleAuthority':False,'rpcCount':self.state['calls']}

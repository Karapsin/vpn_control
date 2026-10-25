"""Resolve an exact refused secure admission without replaying credential work.

The old claim and generated helper remain immutable. A successor is admitted only
by the original terminal read-only callback, unchanged native actors and absence
of the remote secure intent. Lost successor acknowledgement permits observation.
"""
from __future__ import annotations
import ast,hashlib,inspect,json,os,re,stat,textwrap,uuid
from pathlib import Path
from . import ssh_transport as transport
from .native_review_source_closure import _Held

MODES=('secure-resolve','secure-continue','secure-continue-status')

def _uuid(value):
    if type(value)is not str or str(uuid.UUID(value))!=value:raise ValueError('secure_recovery_identity')
    return value

def _private(held,path,limit=65536):
    from .native_review_source_closure import generation
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or not 0<info.st_size<=limit:raise ValueError('secure_recovery_metadata')
        chunks=[];size=0
        while size<=limit:
            block=os.read(descriptor,min(65536,limit+1-size))
            if not block:break
            chunks.append(block);size+=len(block)
        if size!=info.st_size or size>limit or generation(info)!=generation(os.fstat(descriptor))or generation(info)!=generation(os.stat(path,follow_symlinks=False)):raise ValueError('secure_recovery_source_changed')
        digest=hashlib.sha256(b''.join(chunks)).hexdigest()
        return held.read(str(path),digest,generation(info),max_bytes=limit)
    finally:os.close(descriptor)

def original(root,deployment_id,operation_id,held):
    """Authenticate the exact local callback barrier, not a generic UNKNOWN."""
    from . import windows_vm_deploy_remote as remote
    from .native_vm_spec import FreshWindowsVmSpec
    root=Path(root).resolve(strict=True);_uuid(deployment_id);_uuid(operation_id)
    raw=_private(held,root/'.rag_index/windows-vm-deploy-secure'/(deployment_id+'.intent.json'))
    claim=json.loads(raw,object_pairs_hook=transport._reject_duplicate_keys)
    if type(claim)is not dict or set(claim)!={'spec','setup','context','correlationId','mode','callerSha256'} or claim['mode']!='secure':raise ValueError('secure_recovery_claim')
    if not isinstance(claim['correlationId'],str) or re.fullmatch('[0-9a-f]{32}',claim['correlationId'])is None or not isinstance(claim['callerSha256'],str) or re.fullmatch('[0-9a-f]{64}',claim['callerSha256'])is None:raise ValueError('secure_recovery_source')
    spec=FreshWindowsVmSpec.parse(claim['spec'])
    if spec.deployment_id!=deployment_id:raise ValueError('secure_recovery_identity')
    directory=root/'.runtime/windows-vm-deploy'/claim['correlationId']
    source=_private(held,directory/'caller.py',8*1024**2)
    if hashlib.sha256(source).hexdigest()!=claim['callerSha256']:raise ValueError('secure_recovery_source')
    wanted={'OPERATION_ID':operation_id,'MODE':'secure','SPEC':claim['spec'],'SETUP':claim['setup'],'CONTEXT':claim['context']};bindings={}
    for node in ast.parse(source).body:
        if isinstance(node,ast.Assign)and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)and node.targets[0].id in wanted:
            if node.targets[0].id in bindings:raise ValueError('secure_recovery_bindings')
            bindings[node.targets[0].id]=ast.literal_eval(node.value)
    if bindings!=wanted:raise ValueError('secure_recovery_bindings')
    # Hashes bind retained bytes; compare the entire finite producer as well so
    # a locally invented UNKNOWN cannot assert that arbitrary code had no effect.
    # Literal set order varies with PYTHONHASHSEED and has no program semantics.
    class CanonicalSets(ast.NodeTransformer):
        def visit_Assign(self,node):
            if len(node.targets)==1 and isinstance(node.targets[0],ast.Name)and node.targets[0].id in wanted:
                if ast.literal_eval(node.value)!=wanted[node.targets[0].id]:raise ValueError('secure_recovery_bindings')
                node.value=ast.Constant(None)
            return self.generic_visit(node)
        def visit_Set(self,node):
            self.generic_visit(node);node.elts.sort(key=lambda v:ast.dump(v,include_attributes=False));return node
    canonical=lambda raw:ast.dump(CanonicalSets().visit(ast.parse(raw)),include_attributes=False)
    reviewed=remote.program(spec,'secure',setup=claim['setup'],context=claim['context'],operation_id=operation_id)
    if canonical(source)!=canonical(reviewed):raise ValueError('secure_recovery_unreviewed_source')
    native=json.loads(_private(held,directory/'native-result.json'),object_pairs_hook=transport._reject_duplicate_keys)
    closing=json.loads(_private(held,directory/'closing.json'),object_pairs_hook=transport._reject_duplicate_keys)
    if (native.get('state')!='observed' or closing!={'sourceClosing':True,'correlationId':claim['correlationId']}):raise ValueError('secure_recovery_original_unknown')
    result=remote.validate_result(spec,'secure',native['result'])
    if result.get('state')!='unknown' or result.get('failurePhase')!='secure' or result.get('failureClass')!='ValueError' or result.get('failureCheck')!='instance_secure_admission':raise ValueError('secure_recovery_not_preadmission')
    held.finish();held.final_identity_pass()
    return spec,claim

def recover(root,deployment_id,operation_id,credential_file,*,status_only=False):
    """Resolve once, then continue once; any consumed continuation is status only."""
    from . import windows_vm_deploy as deploy
    root=Path(root).resolve(strict=True);held=_Held()
    try:
        spec,claim=original(root,deployment_id,operation_id,held)
        parent=deploy._runtime_group(root,'windows-secure-recoveries')
        directory=parent/deployment_id
        try:directory.mkdir(mode=0o700)
        except FileExistsError:
            s=directory.lstat()
            if not stat.S_ISDIR(s.st_mode)or s.st_uid!=os.getuid()or stat.S_IMODE(s.st_mode)!=0o700:raise ValueError('secure_recovery_journal')
        path=directory/'identity.json'
        if not os.path.lexists(path):
            if status_only:return {'state':'unknown','reason':'secure_original_requires_resolution','operationId':operation_id,'replayAllowed':False}
            identity={'schemaVersion':1,'deploymentId':deployment_id,'originalOperationId':operation_id,'originalSourceSha256':claim['callerSha256'],'resolutionId':str(uuid.uuid4()),'operationId':str(uuid.uuid4())}
            try:deploy.stage._retain(directory,path.name,identity)
            except FileExistsError:pass
        identity=json.loads(_private(held,path),object_pairs_hook=transport._reject_duplicate_keys)
        if (set(identity)!={'schemaVersion','deploymentId','originalOperationId','originalSourceSha256','resolutionId','operationId'}or identity['schemaVersion']!=1 or identity['deploymentId']!=deployment_id or identity['originalOperationId']!=operation_id or identity['originalSourceSha256']!=claim['callerSha256']):raise ValueError('secure_recovery_journal')
        _uuid(identity['resolutionId']);_uuid(identity['operationId'])
        context={**claim['context'],'secureRecovery':identity}
        options={'credential_file':credential_file,'setup':claim['setup'],'context':context,'operation_id':identity['operationId']}
        if os.path.lexists(directory/'continuation.intent.json'):
            # The retained local fence may represent a lost acknowledgement.
            # Never replace it merely because no remote acknowledgement is seen.
            admission=json.loads(_private(held,directory/'continuation.intent.json'))
            if type(admission)is not dict or set(admission)!={'identity','callerSha256'}or admission['identity']!=identity or type(admission['callerSha256'])is not str or re.fullmatch('[0-9a-f]{64}',admission['callerSha256'])is None:raise ValueError('secure_recovery_journal')
            mode='secure-continue-status'
            payload=None
        elif status_only:
            return {'state':'unknown','reason':'secure_original_requires_resolution','operationId':operation_id,'replayAllowed':False}
        else:
            resolution=deploy._execute(root,spec,'secure-resolve',**options)
            if resolution['state']!='proven-unsubmitted':return resolution
            held.finish();held.final_identity_pass()
            try:deploy.stage._retain(directory,'resolution.json',resolution)
            except FileExistsError:
                if json.loads(_private(held,directory/'resolution.json'))!=resolution:raise ValueError('secure_recovery_resolution')
            caller=program(spec,'secure-continue',setup=claim['setup'],context=context,operation_id=identity['operationId'])
            admission={'identity':identity,'callerSha256':hashlib.sha256(caller).hexdigest()}
            try:deploy.stage._retain(directory,'continuation.intent.json',admission)
            except FileExistsError:
                mode='secure-continue-status';payload=None
            else:mode='secure-continue';payload=True
        if payload:
            from .private_credential_file import SecretFile
            with SecretFile(str(root/'.runtime/windows-vm-credentials'/deployment_id/'final-administrator.secret'))as secret:
                def closing():
                    held.finish();held.final_identity_pass()
                    current=program(spec,mode,setup=claim['setup'],context=context,operation_id=identity['operationId'])
                    if hashlib.sha256(current).hexdigest()!=admission['callerSha256']:raise ValueError('secure_recovery_source_changed')
                value=deploy._execute(root,spec,mode,payload={'password':secret.text},before_submit=closing,**options);secret.guard()
        else:value=deploy._execute(root,spec,mode,**options)
        held.finish();held.final_identity_pass()
        return {**value,'originalOperationId':operation_id,'resolutionId':identity['resolutionId'],'continuationOperationId':identity['operationId']}
    finally:held.close()

def _remote_run():
    import base64
    try:
        require(pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==CONTEXT['hostBootId'],'instance_host_epoch')
        chain()
        try:before=observed()
        except OSError:raise ValueError('instance_original_actor_unavailable')from None
        require(qmp('query-uuid')['UUID'].lower()==SPEC['deploymentId'],'instance_machine')
        old=RECOVERY['originalOperationId'];new=RECOVERY['operationId'];check=str(uuid.uuid5(uuid.UUID(old),'secure-setup-admission'))
        closure_name='secure-preadmission-closure-'+old+'.json'
        if RECOVERY_MODE=='secure-resolve':
            require(not os.path.lexists(root/'secure-intent.json'),'instance_secure_intent_exists')
            prefix='qualification-'+check;intent=read(prefix+'.intent.json');ack=read(prefix+'.ack.json');terminal=read(prefix+'.terminal.json')
            require(intent['operationId']==check and intent['readOnly']is True and intent['before']['ordinarySessionObserved']is False,'instance_original_admission')
            require(intent['before']['qemu']==before['qemu']and intent['before']['swtpm']==before['swtpm'],'instance_original_actor')
            require(ack['operationId']==check and ack['replayAllowed']is False and set(ack['ack'])=={'pid'}and type(ack['ack']['pid'])is int and ack['ack']['pid']>0,'instance_original_ack')
            require(terminal.get('exited')is True and terminal.get('exitcode')==0 and not terminal.get('err-data')and not terminal.get('out-truncated',False)and not terminal.get('err-truncated',False),'instance_original_terminal')
            raw=base64.b64decode(terminal['out-data'],validate=True);require(len(raw)<=65536,'instance_original_terminal')
            data=json.loads(raw.decode('utf-8-sig'));require(data['nonce']==check and data['fixturePrincipal']=='S-1-5-18','instance_original_terminal')
            require(not os.path.lexists(root/'secure-intent.json'),'instance_secure_intent_exists')
            process(read('qemu-started.json'));process(read('swtpm-started.json'));instance_intent();closing()
            closure={'identity':RECOVERY,'qemu':before['qemu'],'swtpm':before['swtpm'],'originalAdmission':check,'originalGuestPid':ack['ack']['pid']}
            if os.path.lexists(root/closure_name):require(read(closure_name)==closure,'instance_original_closure')
            else:save(closure_name,closure)
            result={'state':'proven-unsubmitted','operationId':old,'resolutionId':RECOVERY['resolutionId']}
        else:
            closure=read(closure_name)
            require(closure['identity']==RECOVERY and closure['qemu']==before['qemu']and closure['swtpm']==before['swtpm'],'instance_original_closure')
            name='secure-continuation-'+old+'.intent.json'
            if RECOVERY_MODE=='secure-continue':
                require(not os.path.lexists(root/'secure-intent.json'),'instance_secure_intent_exists')
                save(name,RECOVERY)
            else:require(read(name)==RECOVERY,'instance_original_continuation')
            result=secure_instance(SPEC,SETUP,new,RECOVERY_MODE=='secure-continue-status',root,read,save,process,owns,instance_intent,closing,observed,qmp)
        closing();print(json.dumps({**result,'deploymentId':SPEC['deploymentId'],'mode':RECOVERY_MODE,'replayAllowed':False}))
    except (OSError,ValueError,KeyError,TypeError)as error:
        reason=str(error)if type(error)is ValueError and re.fullmatch('instance_[a-z_]{1,64}',str(error))else 'instance_secure_recovery_unknown'
        print(json.dumps({'state':'unknown','deploymentId':SPEC['deploymentId'],'mode':RECOVERY_MODE,'operationId':RECOVERY['operationId'],'reason':reason,'replayAllowed':False}))

def program(spec,mode,*,setup,context,operation_id):
    from . import windows_vm_instance as instance,windows_vm_guest as guest,windows_vm_deploy_remote as remote
    if mode not in MODES or set(context)!={'hostBootId','pending','secureRecovery'}:raise ValueError('secure_recovery_mode')
    identity=context['secureRecovery'];_uuid(operation_id)
    if identity['deploymentId']!=spec.deployment_id or identity['operationId']!=operation_id:raise ValueError('secure_recovery_identity')
    original_context={k:v for k,v in context.items()if k!='secureRecovery'}
    source=inspect.getsource(instance._vm_main);main=ast.parse(source).body[0]
    nodes=[n for n in main.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.Assign,ast.FunctionDef))and not(isinstance(n,ast.FunctionDef)and n.name=='launch')]
    body='\n'.join(ast.get_source_segment(source,n)for n in nodes)
    prefix='import uuid,json,re\nSPEC='+repr(spec.as_dict())+'\nSETUP='+repr(setup)+'\nCONTEXT='+repr(original_context)+'\nRECOVERY='+repr(identity)+'\nRECOVERY_MODE='+repr(mode)+'\n'
    prefix+='PS_SCRIPT='+repr(guest.powershell_source(setup,operation_id))+'\nSECURE_SCRIPT='+repr(guest.secure_source(setup,operation_id))+'\nSECURE_CHECK_SCRIPT='+repr(guest.powershell_source(setup,str(uuid.uuid5(uuid.UUID(operation_id),'secure-setup-admission'))))+'\n'
    prefix+=remote.guest_rpc_definitions()+'\n'+inspect.getsource(guest.validate_setup_result)+'\n'+inspect.getsource(guest.qualify_instance)+'\n'+inspect.getsource(guest.secure_instance)+'\ndef main():\n'
    prefix+=''.join('    '+line+'\n'for line in body.splitlines())
    # The finite recovery runner shares the canonical native identity primitives.
    runner=textwrap.dedent(''.join(inspect.getsource(_remote_run).splitlines(keepends=True)[1:]))
    prefix+=''.join('    '+line+'\n'for line in runner.splitlines())+'\nmain()\n'
    compile(prefix,'saved exact original secure recovery','exec');return prefix.encode()

def validate_result(spec,mode,value):
    if(type(value)is not dict or value.get('deploymentId')!=spec.deployment_id or value.get('mode')!=mode or value.get('replayAllowed')is not False):raise ValueError('secure_recovery_response')
    _uuid(value.get('operationId'))
    state=value.get('state')
    if state=='proven-unsubmitted':
        if mode!='secure-resolve'or set(value)!={'state','operationId','resolutionId','deploymentId','mode','replayAllowed'}:raise ValueError('secure_recovery_response')
        _uuid(value['resolutionId'])
    elif state in ('secure-pending','secured-observed'):
        keys={'state','operationId','productReady','deploymentId','mode','replayAllowed'}|({'setupSecured'}if state=='secured-observed'else set())
        if mode=='secure-resolve'or set(value)!=keys or value['productReady']is not False or state=='secured-observed'and value['setupSecured']is not True:raise ValueError('secure_recovery_response')
    elif state=='unknown':
        if set(value)!={'state','deploymentId','mode','operationId','reason','replayAllowed'}or type(value['reason'])is not str or re.fullmatch('instance_[a-z_]{1,64}',value['reason'])is None:raise ValueError('secure_recovery_response')
    else:raise ValueError('secure_recovery_response')
    return value

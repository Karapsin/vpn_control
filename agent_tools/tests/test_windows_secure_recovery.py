"""Exact secure preadmission resolution, retained failures and one continuation."""
import ast,base64,contextlib,hashlib,inspect,io,json,os,tempfile,types,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools import windows_secure_recovery as recovery,windows_vm_deploy as deploy
from agent_tools.tests import test_native_vm_spec as specs
from agent_tools.native_vm_spec import FreshWindowsVmSpec

class SecureRecoveryTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory(dir=Path('/tmp').resolve());self.addCleanup(t.cleanup);self.root=Path(t.name);self.root.chmod(0o700)
        self.spec=FreshWindowsVmSpec.parse(specs.request());self.old=str(uuid.uuid4());self.setup={'imageName':'Windows 11 Pro','locale':'en-US','user':'ordinary','administrator':'fixtureAdmin'}
        self.context={'hostBootId':str(uuid.uuid4()),'pending':[]};self.calls=[]
        self.claim('start','windows-vm-deploy-intents','a'*32)
        self.secure_directory=self.claim('secure','windows-vm-deploy-secure','b'*32)
        credentials=deploy._runtime_group(self.root,'windows-vm-credentials')/self.spec.deployment_id;credentials.mkdir(mode=0o700)
        deploy.stage._retain(credentials,'final-administrator.secret',b'Final8!INERT_UNIQUE_FIXTURE_SECRET\n')
    def claim(self,mode,group,correlation):
        directory=deploy._runtime_group(self.root,'windows-vm-deploy')/correlation;directory.mkdir(mode=0o700)
        values={'SPEC':self.spec.as_dict(),'SETUP':self.setup,'CONTEXT':self.context,'MODE':mode}
        if mode=='secure':values['OPERATION_ID']=self.old
        source='\n'.join(k+'='+repr(v)for k,v in values.items()).encode()
        if mode=='secure':
            from agent_tools import windows_vm_deploy_remote as remote
            source=remote.program(self.spec,mode,setup=self.setup,context=self.context,operation_id=self.old)
        deploy.stage._retain(directory,'caller.py',source)
        parent=self.root/'.rag_index'/group;parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        claim={'spec':self.spec.as_dict(),'setup':self.setup,'context':self.context,'mode':mode,'correlationId':correlation,'callerSha256':hashlib.sha256(source).hexdigest()}
        deploy.stage._retain(parent,self.spec.deployment_id+'.intent.json',claim)
        if mode=='secure':
            failure={'schemaVersion':1,'deploymentId':self.spec.deployment_id,'mode':'secure','state':'unknown','reason':'instance_effect_or_observation_unknown','failurePhase':'secure','failureClass':'ValueError','failureCheck':'instance_secure_admission','nativeActionAllowed':False,'replayAllowed':False}
            deploy.stage._retain(directory,'native-result.json',{'state':'observed','result':failure})
            deploy.stage._retain(directory,'closing.json',{'sourceClosing':True,'correlationId':correlation})
        return directory
    def dispatch(self,root,spec,mode,**kwargs):
        self.calls.append(mode)
        if mode=='secure':raise ValueError('policy_original_exists')
        operation=kwargs['operation_id'];identity=kwargs['context']['secureRecovery']
        if mode=='secure-resolve':return {'state':'proven-unsubmitted','operationId':self.old,'resolutionId':identity['resolutionId'],'deploymentId':spec.deployment_id,'mode':mode,'replayAllowed':False}
        self.assertEqual(operation,identity['operationId'])
        if mode=='secure-continue':self.assertEqual({'password':'Final8!INERT_UNIQUE_FIXTURE_SECRET'},kwargs['payload'])
        else:self.assertNotIn('payload',kwargs)
        return {'state':'secured-observed','operationId':operation,'setupSecured':True,'productReady':False,'deploymentId':spec.deployment_id,'mode':mode,'replayAllowed':False}
    def test_public_secure_continues_proven_original_then_observes_same_successor(self):
        before={p:p.read_bytes()for p in self.secure_directory.iterdir()}
        with mock.patch.object(deploy,'_execute',side_effect=self.dispatch):
            result=deploy.secure(self.root,self.spec.deployment_id,self.old,'/INERT_CREDENTIAL_HANDLE')
            again=deploy.secure(self.root,self.spec.deployment_id,self.old,'/INERT_CREDENTIAL_HANDLE')
            status=deploy.secure(self.root,self.spec.deployment_id,self.old,'/INERT_CREDENTIAL_HANDLE',status_only=True)
        self.assertEqual(['secure-resolve','secure-continue','secure-continue-status','secure-continue-status'],self.calls)
        self.assertEqual(result['continuationOperationId'],again['operationId']);self.assertEqual(again['operationId'],status['operationId'])
        for p,raw in before.items():self.assertEqual(raw,p.read_bytes())
    def test_preserved_public_secure_refuses_same_prelaunch_claim_before_fix(self):
        folder=Path(__file__).parent/'fixtures/secure_preadmission_recovery';raw=(folder/'windows_vm_deploy.py.before.source').read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._secure_recovery_before');before.__package__='agent_tools';before.__file__=str(folder/'windows_vm_deploy.py.before.source');exec(compile(raw,before.__file__,'exec'),before.__dict__)
        with mock.patch.object(before,'_execute',side_effect=self.dispatch),self.assertRaisesRegex(ValueError,'policy_original_exists'):
            before.secure(self.root,self.spec.deployment_id,self.old,'/INERT_CREDENTIAL_HANDLE')
        self.calls.clear()
        with mock.patch.object(deploy,'_execute',side_effect=self.dispatch):self.assertEqual('secured-observed',deploy.secure(self.root,self.spec.deployment_id,self.old,'/INERT_CREDENTIAL_HANDLE')['state'])
    def test_unknown_original_is_not_absence_and_never_reaches_transport(self):
        path=self.secure_directory/'native-result.json';value=json.loads(path.read_bytes());value['state']='unknown';path.write_text(json.dumps(value));path.chmod(0o600)
        with mock.patch.object(deploy,'_execute',side_effect=AssertionError('no transport')):
            result=deploy.secure(self.root,self.spec.deployment_id,self.old,'/INERT')
        self.assertEqual('secure_recovery_original_unknown',result['reason'])
    def test_lost_continuation_ack_only_observes_original_after_restart(self):
        original=self.dispatch
        def lost(*args,**kwargs):
            if args[2]=='secure-continue':self.calls.append(args[2]);raise ValueError('ACK_LOST')
            return original(*args,**kwargs)
        with mock.patch.object(deploy,'_execute',side_effect=lost),self.assertRaisesRegex(ValueError,'ACK_LOST'):
            deploy.secure(self.root,self.spec.deployment_id,self.old,'/INERT')
        with mock.patch.object(deploy,'_execute',side_effect=original):result=deploy.secure(self.root,self.spec.deployment_id,self.old,'/INERT')
        self.assertEqual(['secure-resolve','secure-continue','secure-continue-status'],self.calls);self.assertEqual('secured-observed',result['state'])
    def test_different_original_uuid_and_modified_source_block(self):
        for change in ('identity','source'):
            with self.subTest(change=change):
                operation=str(uuid.uuid4())if change=='identity'else self.old
                if change=='source':
                    path=self.secure_directory/'caller.py';path.write_bytes(path.read_bytes()+b'\n# CHANGED\n')
                with mock.patch.object(deploy,'_execute',side_effect=AssertionError('no transport')),self.assertRaises(ValueError):deploy.secure(self.root,self.spec.deployment_id,operation,'/INERT')
    def test_preserved_recovery_principal_failure_requires_sudo_before_fixed_ordinary_route(self):
        folder=Path(__file__).parent/'fixtures/secure_recovery_principal';raw=(folder/'windows_vm_deploy.py.before.source').read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._secure_principal_before');before.__package__='agent_tools';before.__file__=str(folder/'windows_vm_deploy.py.before.source');exec(compile(raw,before.__file__,'exec'),before.__dict__)
        identity={'schemaVersion':1,'deploymentId':self.spec.deployment_id,'originalOperationId':self.old,'originalSourceSha256':'c'*64,'resolutionId':str(uuid.uuid4()),'operationId':str(uuid.uuid4())}
        options={'setup':self.setup,'context':{**self.context,'secureRecovery':identity},'operation_id':identity['operationId']}
        with self.assertRaisesRegex(ValueError,'privileged_operation_requires_credential_file'):before._execute(self.root,self.spec,'secure-resolve',**options)
        from agent_tools import ssh_transport as transport
        with mock.patch.object(transport,'admitted_transport',return_value=contextlib.nullcontext(mock.Mock())),mock.patch.object(deploy.direct,'Guard',side_effect=RuntimeError('TRUSTED_ORDINARY_ROUTE')) as route,self.assertRaisesRegex(RuntimeError,'TRUSTED_ORDINARY_ROUTE'):
            deploy._execute(self.root,self.spec,'secure-resolve',**options)
        route.assert_called_once()
    def test_generated_saved_program_contains_no_credential_and_compiles(self):
        identity={'schemaVersion':1,'deploymentId':self.spec.deployment_id,'originalOperationId':self.old,'originalSourceSha256':'c'*64,'resolutionId':str(uuid.uuid4()),'operationId':str(uuid.uuid4())}
        for mode in recovery.MODES:
            source=recovery.program(self.spec,mode,setup=self.setup,context={**self.context,'secureRecovery':identity},operation_id=identity['operationId'])
            compile(source,'actual saved caller','exec');self.assertNotIn(b'INERT_UNIQUE_FIXTURE_SECRET',source)

class NativeResolutionBodyTests(unittest.TestCase):
    def run_body(self,*,terminal=None,intent_exists=False,actor_change=False,mode='secure-resolve',lost=False):
        old=str(uuid.uuid4());new=str(uuid.uuid4());check=str(uuid.uuid5(uuid.UUID(old),'secure-setup-admission'))
        identity={'originalOperationId':old,'operationId':new,'resolutionId':str(uuid.uuid4()),'originalSourceSha256':'a'*64}
        before={'qemu':{'pid':111,'startTicks':10},'swtpm':{'pid':222,'startTicks':20}}
        state={'qualification-'+check+'.intent.json':{'operationId':check,'readOnly':True,'before':{**before,'ordinarySessionObserved':False}},'qualification-'+check+'.ack.json':{'operationId':check,'replayAllowed':False,'ack':{'pid':333}},'qualification-'+check+'.terminal.json':terminal or {'exited':True,'exitcode':0,'out-data':base64.b64encode(json.dumps({'nonce':check,'fixturePrincipal':'S-1-5-18'}).encode()).decode()},'qemu-started.json':{},'swtpm-started.json':{}}
        if actor_change:before={**before,'qemu':{'pid':112,'startTicks':11}}
        calls=[]
        def require(ok,reason):
            if not ok:raise ValueError(reason)
        def save(name,value):
            if name in state:raise FileExistsError(name)
            state[name]=value;calls.append(name)
        if mode!='secure-resolve':
            state['secure-preadmission-closure-'+old+'.json']={'identity':identity,**before}
            if mode=='secure-continue-status':state['secure-continuation-'+old+'.intent.json']=identity
        class Boot:
            @staticmethod
            def read_text():return 'BOOT'
        namespace={'CONTEXT':{'hostBootId':'BOOT'},'RECOVERY':identity,'RECOVERY_MODE':mode,'SPEC':{'deploymentId':new},'SETUP':{},'pathlib':types.SimpleNamespace(Path=lambda _:Boot()),'os':types.SimpleNamespace(path=types.SimpleNamespace(lexists=lambda _:intent_exists)),'root':Path('/INERT'),'json':json,'uuid':uuid,'re':__import__('re'),'require':require,'chain':lambda:None,'observed':lambda:before,'qmp':lambda _:{'UUID':new},'read':lambda n:state[n],'save':save,'process':lambda _:None,'instance_intent':lambda:None,'closing':lambda:None,'owns':lambda *_:None}
        def secure(*args):
            calls.append('credential-effect'if not args[3]else'original-observation')
            if lost:raise ValueError('instance_lost_ack')
            return {'state':'secured-observed','operationId':new,'setupSecured':True,'productReady':False}
        namespace['secure_instance']=secure
        exec(compile(inspect.getsource(recovery._remote_run),'actual fixed remote runner','exec'),namespace)
        output=io.StringIO()
        with mock.patch('sys.stdout',output):namespace['_remote_run']()
        return json.loads(output.getvalue()),state,calls
    def test_real_remote_body_requires_exact_terminal_actor_and_absent_intent(self):
        result,state,calls=self.run_body();self.assertEqual('proven-unsubmitted',result['state']);self.assertEqual(1,len(calls))
        for kwargs in ({'terminal':{'exited':False}}, {'intent_exists':True},{'actor_change':True}):
            result,state,calls=self.run_body(**kwargs);self.assertEqual('unknown',result['state']);self.assertEqual([],calls)
    def test_remote_successor_fence_precedes_effect_and_status_has_no_effect(self):
        result,state,calls=self.run_body(mode='secure-continue',lost=True)
        self.assertEqual('unknown',result['state']);self.assertEqual('credential-effect',calls[-1]);self.assertTrue(calls[0].startswith('secure-continuation-'))
        result,state,calls=self.run_body(mode='secure-continue-status');self.assertEqual(['original-observation'],calls)

if __name__=='__main__':unittest.main()

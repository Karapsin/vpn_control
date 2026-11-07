"""A fixture takes no unannounced update: fixed settings, applied once, verified, closed.

The real guest effect is proved natively; these cases run the actual decisions of
the packet, backend and fixture setup without a guest.
"""
import ast,hashlib,json,os,sys,tempfile,types,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools import readiness_windows as windows,readiness_windows_processes as processes,readiness_windows_remote as remote,windows_vm_unattend as unattended

FIXTURE=Path(__file__).parent/'fixtures/windows_native_tools_20261106'
MACHINE='246a3304-86f3-4e96-bf47-d53c28f83a27'
GOOD={'windowsUpdate':{'noAutoUpdate':1,'noAutoRebootWithLoggedOnUsers':1},'storeAutoDownload':2,'edgeTasksDisabled':True,'edgeServicesDisabled':True,'defenderSignaturesUnchanged':True,'boot':'b'}


def binding():
    from agent_tools.tests.test_native_vm_spec import request
    spec=request();spec['deploymentId']=MACHINE
    return {'provider':'raw-qemu-windows','spec':spec,'setup':{'imageName':'Windows 11 Pro','locale':'en-US','user':'fixtureuser','administrator':'fixtureadmin'},'context':{'hostBootId':str(uuid.uuid4()),'pending':[]},'uri':None,'domain':None,'xmlSha256':None}


class PolicyTextTests(unittest.TestCase):
    def test_settings_cover_windows_update_store_and_edge_and_leave_defender(self):
        text=unattended.UPDATE_POLICY
        for needed in ('NoAutoUpdate','NoAutoRebootWithLoggedOnUsers','WindowsStore','AutoDownload','MicrosoftEdgeUpdateTaskMachine*','OneDrive Standalone Update Task-*','Disable-ScheduledTask','edgeupdate','edgeupdatem'):self.assertIn(needed,text)
        for forbidden in ('Defender','WinDefend','Stop-Service','wuauserv','Set-LocalUser','AutoAdminLogon','Restart-Computer'):self.assertNotIn(forbidden,text)

    def test_secure_reapplies_them_because_edge_registers_its_tasks_later(self):
        from agent_tools import windows_vm_guest as guest
        source=guest.secure_source({'imageName':'Windows 11 Pro','locale':'en-US','user':'fixtureuser','administrator':'fixtureadmin'},str(uuid.uuid4()))
        self.assertEqual(1,source.count(unattended.UPDATE_POLICY));self.assertNotIn('__UPDATE_POLICY__',source)
        self.assertLess(source.index('NoAutoUpdate'),source.index('Set-LocalUser'),'a policy failure leaves no credential effect')

    def test_first_setup_never_depends_on_the_policy(self):
        self.assertIn("try {\n"+unattended.UPDATE_POLICY+"} catch {Write-Output 'FIXTURE_UPDATE_POLICY_UNAPPLIED'}\nStop-Transcript\n",unattended.INITIALIZE)

    def test_every_new_fixture_gets_them_during_first_setup(self):
        self.assertEqual(1,unattended.INITIALIZE.count(unattended.UPDATE_POLICY))
        self.assertLess(unattended.INITIALIZE.index('Register-ScheduledTask'),unattended.INITIALIZE.index(unattended.UPDATE_POLICY))
        self.assertEqual(1,unattended.INITIALIZE.count('Stop-Transcript\n'),'creator derivation keeps its one marker')
        self.assertTrue(unattended.INITIALIZE.endswith('Stop-Transcript\n'))


class PacketTests(unittest.TestCase):
    expected={'actor':{'pid':1,'startTicks':2},'hostBoot':'boot','controlConnection':'qmp:1'}
    def packet(self):return remote.program(binding(),'update-policy',str(uuid.uuid4()),expected=self.expected).decode()
    def branch(self,raw):
        return raw[raw.index("elif MODE=='update-policy':"):raw.index("elif MODE=='sleep-capability':")]
    def test_before_packet_refuses_current_builds_one_fixed_program(self):
        raw=(FIXTURE/'remote.before.source').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),json.loads((FIXTURE/'provenance.json').read_bytes())['sha256']['remote.before.source'])
        module=types.ModuleType('agent_tools._update_policy_before_'+uuid.uuid4().hex);module.__package__='agent_tools';module.__file__=str(FIXTURE/'remote.before.source')
        sys.modules[module.__name__]=module;exec(compile(raw,module.__file__,'exec'),module.__dict__)
        with self.assertRaisesRegex(ValueError,'windows_packet_action'):module.program(binding(),'update-policy',str(uuid.uuid4()),expected=self.expected)
        source=self.packet();compile(source,'update policy packet','exec')
        self.assertIn('UPDATE_POLICY_SCRIPT=',source);self.assertIn('SYSTEM_REQUIRED',source)
    def test_branch_journals_first_and_closes_only_after_verified_readback(self):
        branch=self.branch(self.packet())
        self.assertLess(branch.index("save(name+'.intent.json',intent)"),branch.index("script('update-policy',UPDATE_POLICY_SCRIPT)"))
        self.assertLess(branch.index("instance_update_policy_unverified"),branch.index("policy_closed('update-policy-applied')"))
        for forbidden in ('monitor(','send-key','guest-shutdown','qmp('):self.assertNotIn(forbidden,branch)
    def run_branch(self,outcome):
        tree=ast.parse(self.packet());branch=next(n for n in ast.walk(tree) if isinstance(n,ast.If) and isinstance(n.test,ast.Compare)
                    and getattr(n.test.left,'id','')=='MODE' and getattr(n.test.comparators[0],'value','')=='update-policy')
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);saved={}
            def require(value,reason):
                if not value:raise ValueError(reason)
            def save(name,value):(root/name).write_text(json.dumps(value));saved[name]=value
            def script(label,source):
                if isinstance(outcome,Exception):raise outcome
                return outcome
            namespace={'require':require,'state':'running','rpc':lambda *_:{},'result':{'controlConnection':'qmp:1'},'EXPECTED':self.expected,'current_actor':self.expected['actor'],'CONTEXT':{'hostBootId':'boot'},
                       'OPERATION':'op','os':os,'root':root,'read':lambda name:json.loads((root/name).read_text()),'save':save,'vm_guard':lambda:None,'script':script,'UPDATE_POLICY_SCRIPT':'fixed'}
            error=None
            try:exec(compile(ast.fix_missing_locations(ast.Module(body=branch.body,type_ignores=[])),'<update-policy>','exec'),namespace)
            except ValueError as failure:error=str(failure)
            return error,saved.get('fixture-update-policy-op.terminal.json',{}).get('state'),namespace['result'].get('updatePolicy')
    def test_verified_program_closes_applied_and_returns_the_readback(self):
        self.assertEqual((None,'update-policy-applied',GOOD),self.run_branch(GOOD))
    def test_program_that_ended_unverified_closes_its_receipt_and_still_refuses(self):
        self.assertEqual(('instance_guest_program_failed','update-policy-unverified',None),self.run_branch(ValueError('instance_guest_program_failed')))
        for bad in ({**GOOD,'edgeTasksDisabled':False},{**GOOD,'storeAutoDownload':0},{**GOOD,'windowsUpdate':{'noAutoUpdate':0,'noAutoRebootWithLoggedOnUsers':1}},{}):
            self.assertEqual(('instance_update_policy_unverified','update-policy-unverified',None),self.run_branch(bad))
    def test_unfinished_program_leaves_the_receipt_open(self):
        self.assertEqual(('instance_original_guest_pending',None,None),self.run_branch(ValueError('instance_original_guest_pending')))
    def test_readback_looks_at_the_root_task_folder(self):
        tree=ast.parse(Path(remote.__file__).read_text())
        text=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and getattr(n.targets[0],'id','')=='_UPDATE_POLICY_READBACK')
        self.assertIn("Get-ScheduledTask -TaskPath '\\' |",text);self.assertNotIn('SilentlyContinue | Where-Object {$_.TaskName',text)
    def test_binding_is_required(self):
        for expected in (None,{},{'actor':{}}):
            with self.assertRaisesRegex(ValueError,'windows_lease_host_binding'):remote.program(binding(),'update-policy',str(uuid.uuid4()),expected=expected)


class BackendTests(unittest.TestCase):
    def backend(self,value):
        calls=[]
        def run(mode,operation,deadline,**options):
            calls.append((mode,options))
            if mode=='observe':return {'state':'observed','machine':MACHINE,'guest':'running','guestAgent':True,'actor':{'pid':1},'hostBoot':'h','controlConnection':'c'},None
            return value,None
        return types.SimpleNamespace(machine=MACHINE,_guard=lambda:None,_run=run,calls=calls)
    def test_applies_with_one_bound_program_and_returns_the_readback(self):
        backend=self.backend({'state':'observed','updatePolicy':GOOD});result=windows.WindowsBackend.apply_update_policy(backend,str(uuid.uuid4()),float('inf'))
        self.assertEqual(GOOD,result);self.assertEqual(['observe','update-policy'],[row[0] for row in backend.calls])
        self.assertEqual({'actor':{'pid':1},'hostBoot':'h','controlConnection':'c'},backend.calls[1][1]['expected'])
    def test_blocked_or_unverified_guest_answer_is_an_unknown_outcome(self):
        for value in ({'state':'blocked','reason':'instance_update_policy_unverified'},{'state':'observed'}):
            with self.assertRaisesRegex(windows.providers.ProviderError,'windows_original_outcome_unknown'):
                windows.WindowsBackend.apply_update_policy(self.backend(value),str(uuid.uuid4()),float('inf'))


class IdleRoleTests(unittest.TestCase):
    def test_a_running_edge_updater_has_no_idle_role(self):
        self.assertNotIn('MicrosoftEdgeUpdate',processes._ROLES)


class SecureOrderTests(unittest.TestCase):
    def order(self,source):
        tree=ast.parse(source);secure=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and getattr(n.targets[0],'id','')=='SECURE_SETUP')
        return secure.index('__UPDATE_POLICY__')<secure.index('Set-LocalUser')
    def test_before_policy_followed_the_password_change_and_current_precedes_it(self):
        fixture=Path(__file__).parent/'fixtures/windows_native_tools_20261106';raw=(fixture/'guest-secure.before.source').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),json.loads((fixture/'provenance.json').read_bytes())['sha256']['guest-secure.before.source'])
        self.assertFalse(self.order(raw));self.assertTrue(self.order((Path(__file__).parents[1]/'windows_vm_guest.py').read_bytes()))


if __name__=='__main__':unittest.main()

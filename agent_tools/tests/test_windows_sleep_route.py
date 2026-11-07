"""The Windows sleep scenario decides from real powercfg lines and only refuses or reports.

No branch can request a power state: the guest program carries a fixed read-only
query, and a reported capability still grants nothing. The real guest answer is
native evidence; these cases run its retained lines through the actual decision.
"""
import ast,hashlib,importlib,json,sys,tempfile,types,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools import native_next_action,readiness_windows as windows,readiness_windows_remote as remote,readiness_windows_sleep as sleep,readiness_workflow as workflow,windows_sleep_capability as capability

FIXTURE=Path(__file__).parent/'fixtures/windows_native_tools_20261106'
MACHINE='246a3304-86f3-4e96-bf47-d53c28f83a27';BOOT='2026-11-06T00:30:36.5000000Z'
AVAILABLE='The following sleep states are available on this system:';UNAVAILABLE='The following sleep states are not available on this system:'


def before(name,filename):
    raw=(FIXTURE/filename).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=json.loads((FIXTURE/'provenance.json').read_bytes())['sha256'][filename]:raise AssertionError(filename+' beforeimage changed')
    module=types.ModuleType('agent_tools._sleep_route_before_'+name+uuid.uuid4().hex);module.__package__='agent_tools';module.__file__=str(FIXTURE/filename)
    sys.modules[module.__name__]=module;exec(compile(raw,module.__file__,'exec'),module.__dict__);return module


def binding():
    from agent_tools.tests.test_native_vm_spec import request
    spec=request();spec['deploymentId']=MACHINE
    return {'provider':'raw-qemu-windows','spec':spec,'setup':{'imageName':'Windows 11 Pro','locale':'en-US','user':'fixtureuser','administrator':'fixtureadmin'},'context':{'hostBootId':str(uuid.uuid4()),'pending':[]},'uri':None,'domain':None,'xmlSha256':None}


def native_lines():
    raw=(FIXTURE/'native-power-lines.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=json.loads((FIXTURE/'provenance.json').read_bytes())['sha256']['native-power-lines.json']:raise AssertionError('native lines changed')
    return json.loads(raw)['lines']


def native_facts(lines=None):
    return {'schemaVersion':1,'machine':MACHINE,'boot':BOOT,'readOnly':True,'inputAuthority':False,'powerSubmitted':False,'binaryMicrosoftSigned':True,'exitCode':0,
            'lines':native_lines() if lines is None else lines}


class CapabilityProjectionTests(unittest.TestCase):
    def test_real_clone_lines_refuse_with_the_exact_native_reasons(self):
        self.assertEqual({'schemaVersion':1,'state':'unsupported','reason':'windows_s3_unsupported','powerAllowed':False,
                          'nativeReasons':['An internal system component has disabled this standby state.','Graphics']},
                         capability.observe_s3(native_facts()['lines']))

    def test_available_row_with_a_reason_before_supported_current_refuses(self):
        lines=[AVAILABLE,'    Standby (S3)','\tThis standby state is disabled when connected standby is supported.','',UNAVAILABLE,'    Standby (S1)']
        self.assertEqual('supported',before('capability','capability.before.source').observe_s3(lines)['state'])
        with self.assertRaisesRegex(ValueError,'windows_sleep_capability_unrecognized'):capability.observe_s3(lines)


class DecisionTests(unittest.TestCase):
    def test_validate_refuses_every_unqualified_observation(self):
        self.assertEqual('unsupported',sleep.validate(native_facts(),MACHINE,BOOT)['state'])
        good=native_facts()
        for change in ({'machine':str(uuid.uuid4())},{'boot':'2020-01-01T00:00:00.0Z'},{'readOnly':False},{'inputAuthority':True},{'powerSubmitted':True},{'binaryMicrosoftSigned':False},
                       {'exitCode':1},{'exitCode':True},{'schemaVersion':2},{'extra':1},{'lines':['Andere Sprache']}):
            with self.subTest(change=change):
                with self.assertRaises(ValueError):sleep.validate({**good,**change},MACHINE,BOOT)
        with self.assertRaises(ValueError):sleep.validate(None,MACHINE,BOOT)

    def test_all_three_outcomes_never_allow_power(self):
        unsupported=sleep.decision(sleep.validate(native_facts(),MACHINE,BOOT),machine=MACHINE,boot=BOOT)
        self.assertEqual(('refused','windows_s3_unsupported',False),(unsupported['state'],unsupported['reason'],unsupported['ok']))
        self.assertEqual(['An internal system component has disabled this standby state.','Graphics'],unsupported['nativeReasons'])
        supported=sleep.decision(capability.observe_s3([AVAILABLE,'    Standby (S3)','',UNAVAILABLE,'    Standby (S1)','\tx']),machine=MACHINE,boot=BOOT)
        self.assertEqual(('supported',True,None),(supported['state'],supported['ok'],supported['reason']))
        unknown=sleep.decision(None,machine=MACHINE,boot=BOOT)
        self.assertEqual(('unknown','windows_sleep_capability_unrecognized',False),(unknown['state'],unknown['reason'],unknown['ok']))
        for result in (unsupported,supported,unknown):
            self.assertIs(False,result['powerAllowed']);self.assertIs(False,result['powerSubmitted']);self.assertIs(False,result['replayAllowed'])

    def test_probe_is_bound_read_only_and_has_one_output_line(self):
        source=sleep.powershell_source(MACHINE,BOOT)
        self.assertEqual(1,source.count('[Console]::WriteLine('));self.assertTrue(source.rstrip().splitlines()[-1].startswith('[Console]::WriteLine('))
        self.assertIn('& $path /a 2>&1',source);self.assertEqual(2,source.count('\nGuard\n'))
        for forbidden in ('SetSuspendState','rundll32','/hibernate','shutdown','Stop-Computer','Restart-Computer','guest-suspend'):self.assertNotIn(forbidden,source)
        for bad in (('not-a-uuid',BOOT),(MACHINE,'yesterday'),(MACHINE,None)):
            with self.assertRaises(ValueError):sleep.powershell_source(*bad)


class PacketTests(unittest.TestCase):
    expected={'actor':{'pid':1,'startTicks':2},'hostBoot':'boot','controlConnection':'qmp:1'}
    def test_before_packet_refuses_current_builds_one_read_only_mode(self):
        old=before('remote','remote.before.source')
        with self.assertRaisesRegex(ValueError,'windows_packet_action'):old.program(binding(),'sleep-capability',str(uuid.uuid4()),expected=self.expected)
        raw=remote.program(binding(),'sleep-capability',str(uuid.uuid4()),expected=self.expected,sleep_boot=BOOT).decode()
        compile(raw,'sleep packet','exec')
        branch=raw[raw.index("elif MODE=='sleep-capability':"):raw.index("else:raise ValueError('instance_packet_action')")]
        self.assertIn("script('sleep-capability',SLEEP_SCRIPT)",branch)
        for forbidden in ('guest-suspend','system_wakeup','system_powerdown','monitor(','qmp('):self.assertNotIn(forbidden,branch)
        self.assertNotIn('guest-suspend',raw)

    def test_packet_needs_the_exact_host_binding_and_a_bound_boot(self):
        for expected in (None,{},{'actor':{}}):
            with self.assertRaisesRegex(ValueError,'windows_lease_host_binding'):remote.program(binding(),'sleep-capability',str(uuid.uuid4()),expected=expected,sleep_boot=BOOT)
        with self.assertRaisesRegex(ValueError,'windows_sleep_boot'):remote.program(binding(),'sleep-capability',str(uuid.uuid4()),expected=self.expected)

    def test_producers_are_bound_by_registration_source_pins(self):
        names={Path(path).name for path in windows._source_pins()}
        self.assertLessEqual({'readiness_windows_sleep.py','windows_sleep_capability.py','readiness_windows_login.py','readiness_windows_login_continuation.py'},names)
        tree=ast.parse((FIXTURE/'windows.before.source').read_text())
        pins=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_source_pins')
        self.assertNotIn('sleep_module',{n.id for n in ast.walk(pins) if isinstance(n,ast.Name)})


class BackendDecisionTests(unittest.TestCase):
    def backend(self,sleep_value,*,state='observed'):
        backend=types.SimpleNamespace(machine=MACHINE,expected_sid='SID',binding={'setup':{'user':'fixtureuser'}},_guard=lambda:None,calls=[])
        def run(mode,operation,deadline,**options):
            backend.calls.append((mode,options))
            if mode=='observe':return {'state':'observed','machine':MACHINE,'guest':'running','guestAgent':True,'sessionFacts':{'boot':BOOT},'actor':{'pid':1},'hostBoot':'h','controlConnection':'c'},None
            return {'state':state,'machine':MACHINE,'sleepFacts':sleep_value},None
        backend._run=run;return backend
    def decide(self,backend):
        with mock.patch.object(windows.guest,'validate_session',return_value={'boot':BOOT}):
            return windows.WindowsBackend.sleep_capability(backend,str(uuid.uuid4()),float('inf'))
    def test_real_lines_refuse_with_one_fixed_query_and_no_recovery(self):
        backend=self.backend(native_facts());result=self.decide(backend)
        self.assertEqual(('refused','windows_s3_unsupported'),(result['state'],result['reason']))
        self.assertEqual(['observe','sleep-capability'],[row[0] for row in backend.calls])
        self.assertEqual({'actor':{'pid':1},'hostBoot':'h','controlConnection':'c'},backend.calls[1][1]['expected']);self.assertEqual(BOOT,backend.calls[1][1]['sleep_boot'])
    def test_unrecognized_or_blocked_guest_answers_stay_unknown(self):
        for backend in (self.backend(native_facts(['Andere Sprache'])),self.backend(None),self.backend(native_facts(),state='blocked')):
            result=self.decide(backend);self.assertEqual(('unknown','windows_sleep_capability_unrecognized'),(result['state'],result['reason']));self.assertIs(False,result['powerSubmitted'])
    def test_a_blocked_packet_keeps_its_fixed_reason_and_nothing_else(self):
        backend=self.backend(None,state='blocked');run=backend._run
        def blocked(mode,operation,deadline,**options):
            value,other=run(mode,operation,deadline,**options)
            if mode!='observe':value=dict(value,reason='instance_operator_busy')
            return value,other
        backend._run=blocked;self.assertEqual(('unknown','instance_operator_busy'),(lambda r:(r['state'],r['reason']))(self.decide(backend)))
        def untrusted(mode,operation,deadline,**options):
            value,other=run(mode,operation,deadline,**options)
            if mode!='observe':value=dict(value,reason='free text from a host')
            return value,other
        backend._run=untrusted;self.assertEqual('windows_sleep_capability_unrecognized',self.decide(backend)['reason'])


class RouteTests(unittest.TestCase):
    def run_route(self,module,backend):
        fixture=types.SimpleNamespace(adapter=types.SimpleNamespace(backend=backend,capabilities=frozenset()),required_readiness=frozenset({'interactive_desktop'}),context=mock.Mock(side_effect=AssertionError('no ensure context')))
        policy=types.SimpleNamespace(permitted_recoveries=frozenset())
        with mock.patch.object(module.fixtures,'registered_fixture',return_value=fixture),mock.patch.object(module.policies,'action_policy',return_value=policy):
            return module.vm_workflow(Path('.'),'readiness-sleep-capability',{'fixtureId':'windows-raw246a3304-v1','operationId':'00000000-0000-4000-8000-000000000001'})
    def test_before_route_refuses_current_answers_without_a_recovery_context(self):
        backend=types.SimpleNamespace(sleep_capability=mock.Mock(return_value={'ok':False,'state':'refused','reason':'windows_s3_unsupported','powerSubmitted':False,'replayAllowed':False}))
        with self.assertRaisesRegex(ValueError,'readiness_action_invalid'):self.run_route(before('workflow','workflow.before.source'),backend)
        result=self.run_route(workflow,backend)
        self.assertEqual(('refused','windows-raw246a3304-v1','00000000-0000-4000-8000-000000000001'),(result['state'],result['fixtureId'],result['operationId']))
        backend.sleep_capability.assert_called_once()
    def test_other_providers_refuse_by_type_without_a_power_path(self):
        result=self.run_route(workflow,types.SimpleNamespace())
        self.assertEqual(('refused','sleep_capability_provider_unsupported',False,False),(result['state'],result['reason'],result['powerAllowed'],result['powerSubmitted']))
    def test_guidance_closes_a_typed_answer_and_keeps_unknown_open(self):
        for state,kind in (('refused','complete'),('supported','complete'),('unknown','resolve_blocker')):
            self.assertEqual(kind,native_next_action.next_action('vm_workflow','readiness-sleep-capability',{'state':state,'powerSubmitted':False,'replayAllowed':False})['kind'])
        self.assertEqual('resolve_blocker',native_next_action.next_action('vm_workflow','readiness-sleep-capability',{'state':'supported','powerSubmitted':True,'replayAllowed':False})['kind'])
    def test_provider_listing_completes_before_asks_for_more_evidence(self):
        listing={'ok':True,'state':'observed','providers':[],'replayAllowed':False}
        self.assertEqual('inspect-evidence',before('next_action','next_action.before.source').next_action('vm_workflow','readiness-providers',listing)['kind'])
        self.assertEqual(('complete',False),tuple(native_next_action.next_action('vm_workflow','readiness-providers',listing)[key] for key in ('kind','requiresFreshEvidence')))
        self.assertEqual('inspect-evidence',native_next_action.next_action('vm_workflow','readiness-providers',{**listing,'ok':False})['kind'])
    def test_catalogs_classify_the_route_as_a_read_only_observation(self):
        from agent_tools import tool_action_policy as policies
        policy=policies.action_policy('vm_workflow','readiness-sleep-capability')
        self.assertEqual(('readiness_observation',frozenset()),(policy.classification,policy.permitted_recoveries))
        catalog=json.loads((Path(workflow.__file__).parent/'readiness_vm_dispatch.json').read_text())
        self.assertEqual(catalog['actions']['readiness-status'],catalog['actions']['readiness-sleep-capability'])


if __name__=='__main__':unittest.main()

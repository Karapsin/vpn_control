"""Finite Windows job source/receipt protocol, without host or guest effects."""
import base64
import copy
import contextlib
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock
from uuid import uuid4

from agent_tools import readiness_windows_jobs as jobs
from agent_tools.tests.test_readiness_windows import snapshot


class WindowsJobTests(unittest.TestCase):
    def setUp(self):
        self.binding = jobs.WindowsJobBinding('abcdef78-1234-4234-9234-123456789012',
            '2026-10-20T09:04:39.5000000Z', '12345678:0003000000000847:01dd6077063bd7e7',
            '12345678:0003000000000848:01dd6077063bd7e8')
        self.operation = str(uuid4())
        self.nonce = str(uuid4())

    def observation(self, state='running', **extra):
        config = jobs._config(self.binding, self.operation, 3, .01)
        source = (jobs._prefix() + '[NativeJob]::Own(' + jobs._literal(config) + ')\n').encode()
        return {'schemaVersion':1, 'operationId':self.operation, 'machine':self.binding.machine,
            'boot':self.binding.boot, 'rootGeneration':self.binding.root_generation,
            'admissionGeneration':self.binding.admission_generation, 'state':state,
            'reason':'original_owner_running', 'replayAllowed':False, 'admissionNonce':self.nonce,
            'programSha256':hashlib.sha256(source).hexdigest(),
            'owner':{'pid':1234,'birth':'134369629130736090','accountSid':'S-1-5-18','sessionId':0}, **extra}

    def streams(self):
        return {name:{'bytes':len(raw),'base64':base64.b64encode(raw).decode(),
                      'sha256':hashlib.sha256(raw).hexdigest()} for name,raw in {
                          'stdout':b'0\n1\n2\n','stderr':b'guest sentinel retained stderr\n',
                          'counter':b'execution\n0\n1\n2\n'}.items()}

    def test_machine_boot_and_both_independent_generations_are_mandatory(self):
        for key,value in [('machine','host'),('boot','today'),('root_generation','unbound'),('admission_generation','unbound')]:
            with self.subTest(key=key),self.assertRaises(ValueError):
                jobs.WindowsJobBinding(**{**jobs.asdict(self.binding),key:value})

    def test_source_factory_is_finite_without_credentials_commands_or_power(self):
        for action in ['shell','login','reboot','cancel']:
            with self.subTest(action=action),self.assertRaises(ValueError):jobs.program(action,self.binding,self.operation)
        for count,interval in [(True,.1),(0,.1),(1001,.1),(3,True),(3,float('nan')),(3,0),(3,2)]:
            with self.assertRaises(ValueError):jobs.program('start',self.binding,self.operation,count=count,interval_seconds=interval)
        with self.assertRaises(TypeError):jobs.program('start',self.binding,self.operation,password='PRIVATE')
        source=jobs.program('start',self.binding,self.operation,count=3,interval_seconds=.01)
        self.assertEqual(source,jobs.program('start',self.binding,self.operation,count=3,interval_seconds=.01))
        self.assertNotIn(b'SetThreadExecutionState',source)
        self.assertNotIn(b'CreateProcessAsUser',source)
        self.assertEqual(1,len([line for line in source.splitlines() if line.startswith(b'[Console]::WriteLine(')]))

    def test_enrollment_receipt_requires_original_nonce_uuid_and_two_generations(self):
        value={'schemaVersion':1,'machine':self.binding.machine,'boot':self.binding.boot,
               'rootGeneration':self.binding.root_generation,'admissionGeneration':self.binding.admission_generation,
               'enrollmentOperation':self.operation,'enrollmentNonce':self.nonce}
        self.assertEqual(self.binding,jobs.validate_enrollment(value,self.binding.machine,self.binding.boot,self.operation,self.nonce))
        for key in value:
            changed={**value,key:True if key=='schemaVersion' else 'changed'}
            with self.subTest(key=key),self.assertRaises(ValueError):
                jobs.validate_enrollment(changed,self.binding.machine,self.binding.boot,self.operation,self.nonce)

    def test_original_identity_binds_owner_generation_source_and_nonce(self):
        value=self.observation();identity=jobs.validate_observation(value,self.binding,self.operation,count=3,interval_seconds=.01)['identity']
        for change in [{'owner':{**value['owner'],'pid':2345}}, {'owner':{**value['owner'],'birth':'1'}},
                       {'admissionNonce':str(uuid4())},{'programSha256':'0'*64}]:
            with self.subTest(change=change),self.assertRaises(ValueError):
                jobs.validate_observation({**value,**change},self.binding,self.operation,count=3,interval_seconds=.01,original_identity=identity)

    def test_system_session_zero_owner_has_no_ordinary_session_dependency(self):
        result=jobs.validate_observation(self.observation(),self.binding,self.operation,count=3,interval_seconds=.01)
        self.assertEqual(0,result['identity']['owner']['sessionId'])
        for change in [{'sessionId':1},{'accountSid':'S-1-5-21-1-2-3-1000'},{'pid':True},{'birth':'PID'}]:
            value=self.observation();value['owner'].update(change)
            with self.assertRaises(ValueError):jobs.validate_observation(value,self.binding,self.operation,count=3,interval_seconds=.01)

    def test_terminal_requires_exact_once_counter_and_all_closed_binary_stream_receipts(self):
        value=self.observation('terminal',reason='original_terminal_retained',exitCode=0,streams=self.streams())
        result=jobs.validate_observation(value,self.binding,self.operation,count=3,interval_seconds=.01)
        self.assertEqual(1,result['executions']);self.assertEqual('0\n1\n2\n',result['stdout'])
        for key in ['streams','owner','exitCode']:
            bad=dict(value);del bad[key]
            with self.subTest(key=key),self.assertRaises(ValueError):jobs.validate_observation(bad,self.binding,self.operation,count=3,interval_seconds=.01)
        for name in self.streams():
            bad=copy.deepcopy(value);bad['streams'][name]['base64']=base64.b64encode(b'tampered').decode()
            with self.assertRaises(ValueError):jobs.validate_observation(bad,self.binding,self.operation,count=3,interval_seconds=.01)

    def test_unknown_owner_never_becomes_terminal_or_permission_to_replay(self):
        value=self.observation('unknown',reason='original_owner_unresolved')
        result=jobs.validate_observation(value,self.binding,self.operation,count=3,interval_seconds=.01)
        self.assertEqual('unknown',result['state']);self.assertIs(False,result['replayAllowed'])
        with self.assertRaises(ValueError):jobs.validate_observation({**value,'streams':self.streams()},self.binding,self.operation,count=3,interval_seconds=.01)

    def test_inventory_requires_complete_visibility_and_names_unknown_originals(self):
        value={'schemaVersion':1,'machine':self.binding.machine,'boot':self.binding.boot,
               'rootGeneration':self.binding.root_generation,'admissionGeneration':self.binding.admission_generation,
               'visibilityComplete':True,'terminalCount':1,'blockers':[{'operationId':self.operation,'reason':'job_original_work_not_terminal'}]}
        self.assertEqual(value,jobs.validate_inventory(value,self.binding.machine,self.binding.boot,self.binding.root_generation,self.binding.admission_generation))
        with self.assertRaises(ValueError):jobs.validate_inventory({**value,'visibilityComplete':False,'blockers':[]},self.binding.machine,self.binding.boot,self.binding.root_generation,self.binding.admission_generation)
        with self.assertRaises(ValueError):jobs.inventory_source(self.binding.machine,self.binding.boot,self.binding.root_generation)

    def test_finite_remote_packet_uses_only_guest_agent_and_expected_host_tuple(self):
        saved=snapshot();binding=jobs.WindowsJobBinding(saved['binding']['spec']['deploymentId'],self.binding.boot,self.binding.root_generation,self.binding.admission_generation)
        packet=jobs.remote_program(saved['binding'],'job-start',str(uuid4()),expected=saved['host'],job_binding=binding,job_operation=self.operation,count=3,interval_seconds=.01)
        compile(packet,'generated Windows controller','exec')
        self.assertIn(b"result['job']=script(job_label,JOB_SCRIPT)",packet)
        with self.assertRaises(ValueError):jobs.remote_program(saved['binding'],'reboot',self.operation,expected=saved['host'],job_binding=binding)

    def test_progress_is_bounded_exact_prefix_of_same_counter_owner(self):
        prefix=b'execution\n0\n1\n'
        progress={'completed':2,'bytes':len(prefix),'sha256':hashlib.sha256(prefix).hexdigest(),'base64':base64.b64encode(prefix).decode()}
        value=self.observation(progress=progress)
        result=jobs.validate_observation(value,self.binding,self.operation,count=3,interval_seconds=.01)
        self.assertEqual(2,result['progress']['completed']);self.assertNotIn('base64',result['progress'])
        for field,bad in [('completed',4),('completed',True),('bytes',32769),('sha256','0'*64),('base64','PRIVATE-CANARY')]:
            with self.subTest(field=field),self.assertRaises(ValueError):jobs.validate_observation({**value,'progress':{**progress,field:bad}},self.binding,self.operation,count=3,interval_seconds=.01)

    def test_causal_generic_evidence_failure_was_reconciled_before_and_is_blocker_now(self):
        folder=Path(__file__).parent/'fixtures/windows_jobs_blocker_classification'
        raw=(folder/'before.source').read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_text())['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._windows_jobs_blocker_before')
        before.__package__='agent_tools';before.__file__=str(folder/'before.source')
        sys.modules[before.__name__]=before;self.addCleanup(sys.modules.pop,before.__name__,None)
        exec(compile(raw,before.__file__,'exec'),before.__dict__)
        observed={'state':'unknown','reason':'original_evidence_unavailable'}
        self.assertEqual('reconcile_original',before._public('fixture',self.operation,observed,'raw-qemu-windows')['nextAction']['kind'])
        for reason in ['original_evidence_unavailable',*jobs._BLOCKERS]:
            result=jobs._public('fixture',self.operation,{**observed,'reason':reason},'raw-qemu-windows')
            self.assertEqual('resolve_blocker',result['nextAction']['kind']);self.assertNotIn('action',result['nextAction'])

    def test_pure_local_discriminator_and_missing_status_never_resolve_fixture(self):
        with tempfile.TemporaryDirectory() as directory,mock.patch.object(jobs,'_run',side_effect=AssertionError('remote')):
            from agent_tools import readiness_fixture_registry as registry
            with mock.patch.object(registry,'registered_fixture',side_effect=AssertionError('registry')):
                self.assertFalse(jobs.has_original(directory,'fixture',self.operation))
                for action in ('status','collect'):
                    with self.assertRaisesRegex(ValueError,'windows_job_original_missing'):
                        jobs.workflow(directory,action,{'fixtureId':'fixture','operationId':self.operation})
            self.assertEqual([],list(Path(directory).iterdir()))

    def test_malformed_or_echoed_receipt_raises_only_finite_errors(self):
        for change in [{'private':'PRIVATE-CANARY'}, {'reason':'PRIVATE-CANARY'}, {'owner':{'password':'PRIVATE-CANARY'}},
                       {'streams':{'stdout':{'base64':'PRIVATE-CANARY'}}}, {'schemaVersion':True}]:
            with self.assertRaises(ValueError) as caught:
                jobs.validate_observation({**self.observation(),**change},self.binding,self.operation,count=3,interval_seconds=.01)
            self.assertNotIn('PRIVATE-CANARY',str(caught.exception))

    def test_executor_lost_ack_keeps_local_consumption_and_observes_original_only(self):
        saved=snapshot()
        with tempfile.TemporaryDirectory() as directory:
            backend=types.SimpleNamespace(root=Path(directory),target='windows:trusted:'+self.binding.machine,
                machine=self.binding.machine,provider=saved['provider'],binding=saved['binding'],expected_sid=saved['expectedSid'])
            state={**saved,'guest':jobs.asdict(self.binding),'sources':{'public':'fixed'}}
            with mock.patch.object(jobs,'_source_pins',return_value={'public':'fixed'}):
                executor=jobs.WindowsJobExecutor(backend,state)
                with mock.patch.object(jobs,'_run',side_effect=TimeoutError('lost acknowledgement')) as submit:
                    with self.assertRaises(TimeoutError):executor.submit(self.operation,count=3,interval_seconds=.01)
                self.assertEqual('job-start',submit.call_args.args[1])
                with mock.patch.object(jobs,'_run',return_value=self.observation()) as observe:
                    value=executor.submit(self.operation,count=3,interval_seconds=.01)
                    self.assertEqual('job-status',observe.call_args.args[1]);self.assertEqual(self.operation,observe.call_args.args[2])
                    self.assertEqual('running',value['state'])
                    with self.assertRaisesRegex(ValueError,'windows_job_original_inputs_changed'):
                        executor.submit(self.operation,count=4,interval_seconds=.01)
                    self.assertEqual(1,observe.call_count)

    def test_causal_original_namespace_lock_call_red_then_current_full_call_green(self):
        folder=Path(__file__).parent/'fixtures/windows_jobs_namespace_lock'
        raw=(folder/'before.source').read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_text())['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._windows_jobs_namespace_before')
        before.__package__='agent_tools';before.__file__=str(folder/'before.source')
        sys.modules[before.__name__]=before
        self.addCleanup(sys.modules.pop,before.__name__,None)
        exec(compile(raw,before.__file__,'exec'),before.__dict__)
        saved=snapshot()
        for module in (before,jobs):
            with self.subTest(module=module.__name__),tempfile.TemporaryDirectory() as directory:
                backend=types.SimpleNamespace(root=Path(directory),target='windows:trusted:'+self.binding.machine,
                    machine=self.binding.machine,provider=saved['provider'],binding=saved['binding'],expected_sid=saved['expectedSid'],
                    last_facts={**saved['host'],'sessionFacts':{'boot':self.binding.boot}})
                with mock.patch.object(module,'_source_pins',return_value={'public':'fixed'}),mock.patch.object(module,'_run',side_effect=TimeoutError('controlled boundary')) as remote:
                    if module is before:
                        with self.assertRaisesRegex(TypeError,'directory'):module.ensure_namespace(backend,deadline=time.monotonic()+10)
                        self.assertEqual(0,remote.call_count)
                    else:
                        with self.assertRaisesRegex(TimeoutError,'controlled boundary'):module.ensure_namespace(backend,deadline=time.monotonic()+10)
                        self.assertEqual(2,remote.call_count)
                        self.assertEqual(['job-enroll','job-namespace-status'], [c.args[1] for c in remote.call_args_list])

    def test_only_same_root_index_absence_without_consumed_nonce_retries_first_submission(self):
        saved=snapshot()
        with tempfile.TemporaryDirectory() as directory:
            backend=types.SimpleNamespace(root=Path(directory),target='windows:trusted:'+self.binding.machine,
                machine=self.binding.machine,provider=saved['provider'],binding=saved['binding'],expected_sid=saved['expectedSid'])
            state={**saved,'guest':jobs.asdict(self.binding),'sources':{'public':'fixed'}}
            absent=self.observation('unsubmitted',reason='original_admission_absent')
            for key in ('admissionNonce','programSha256','owner'):absent.pop(key)
            with mock.patch.object(jobs,'_source_pins',return_value={'public':'fixed'}):
                executor=jobs.WindowsJobExecutor(backend,state)
                with mock.patch.object(jobs,'_run',side_effect=[absent,self.observation()]) as remote:
                    result=executor.submit(self.operation,count=3,interval_seconds=.01)
                    self.assertEqual('running',result['state']);self.assertEqual(['job-start','job-start'],[c.args[1] for c in remote.call_args_list])
                    self.assertEqual([self.operation,self.operation],[c.args[2] for c in remote.call_args_list])
                with mock.patch.object(jobs,'_run',return_value=absent) as remote:
                    with self.assertRaisesRegex(ValueError,'windows_job_original_owner_changed'):
                        executor.observe(self.operation,count=3,interval_seconds=.01)
                    self.assertEqual(1,remote.call_count)
                local=Path(directory)/'.runtime/readiness-windows-job-owners'/self.operation
                self.assertEqual(1,len(list(local.glob('unsubmitted-proof-*.json'))))
                self.assertTrue((local/'remote-admission-consumed.json').exists())

    def test_whole_controller_orders_readiness_before_generation_and_never_clamps_spent_budget(self):
        from agent_tools import ssh_transport as transport
        folder=Path(__file__).parent/'fixtures/windows_jobs_controller_ordering'
        raw=(folder/'before.source').read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_text())['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._windows_jobs_order_before')
        before.__package__='agent_tools';before.__file__=str(folder/'before.source')
        sys.modules[before.__name__]=before;self.addCleanup(sys.modules.pop,before.__name__,None)
        exec(compile(raw,before.__file__,'exec'),before.__dict__)
        for producer in (before,jobs):
            for phase in ('healthy','generation-expired','argv-expired'):
                with self.subTest(producer=producer.__name__,phase=phase),tempfile.TemporaryDirectory() as directory:
                    clock=[10.0];events=[];controller=[None]
                    expected={'actor':{'pid':123,'startTicks':456},'hostBoot':'HOST','controlConnection':'CONTROL'}
                    backend=types.SimpleNamespace(root=Path(directory).resolve(),machine=self.binding.machine,provider='raw-qemu-windows',
                        binding={'spec':{'host':'controlled'}},_guard=lambda:None)
                    @contextlib.contextmanager
                    def admitted(*args,**options):
                        events.append('ready');yield types.SimpleNamespace(revalidate=lambda:None)
                    def generate(binding,mode,operation,**options):
                        events.append('generate');controller[0]=operation
                        if phase=='generation-expired':clock[0]=30
                        return b'pass\n'
                    def argv(*args,**options):
                        if phase=='argv-expired':clock[0]=30
                        return ['controlled-no-network']
                    def child(*args,**options):
                        events.append('child')
                        return types.SimpleNamespace(returncode=0,stderr=b'',stdout=json.dumps({
                            'state':'observed','operationId':controller[0],'machine':self.binding.machine,
                            'provider':backend.provider,**expected,'job':{'schemaVersion':1}}).encode())
                    with mock.patch.object(time,'monotonic',side_effect=lambda:clock[0]),mock.patch.object(producer,'remote_program',side_effect=generate),\
                         mock.patch.object(transport,'admitted_transport',side_effect=admitted),mock.patch.object(transport,'load_config',return_value={}),\
                         mock.patch.object(transport,'build_ssh_argv',side_effect=argv),mock.patch.object(transport,'run_ssh',side_effect=child):
                        if producer is jobs and phase!='healthy':
                            with self.assertRaisesRegex(jobs._ControllerUnsubmitted,'windows_job_controller_unsubmitted'):
                                producer._run(backend,'job-status',self.operation,20,expected=expected,binding=self.binding)
                        else:producer._run(backend,'job-status',self.operation,20,expected=expected,binding=self.binding)
                    if producer is before:
                        with self.assertRaises(AssertionError):self.assertLess(events.index('ready'),events.index('generate'))
                        if phase!='healthy':
                            with self.assertRaises(AssertionError):self.assertNotIn('child',events)
                    else:
                        self.assertLess(events.index('ready'),events.index('generate'))
                        self.assertEqual(phase=='healthy','child' in events)

    def test_absence_never_retries_when_original_controller_ack_is_unresolved(self):
        saved=snapshot()
        with tempfile.TemporaryDirectory() as directory:
            backend=types.SimpleNamespace(root=Path(directory),target='windows:trusted:'+self.binding.machine,
                machine=self.binding.machine,provider=saved['provider'],binding=saved['binding'],expected_sid=saved['expectedSid'])
            state={**saved,'guest':jobs.asdict(self.binding),'sources':{'public':'fixed'}}
            absent=self.observation('unsubmitted',reason='original_admission_absent')
            for key in ('admissionNonce','programSha256','owner'):absent.pop(key)
            with mock.patch.object(jobs,'_source_pins',return_value={'public':'fixed'}):
                executor=jobs.WindowsJobExecutor(backend,state)
                with mock.patch.object(jobs,'_run',side_effect=TimeoutError('lost original ACK')):
                    with self.assertRaises(TimeoutError):executor.submit(self.operation,count=3,interval_seconds=.01)
                with mock.patch.object(jobs,'_run',return_value=absent) as remote:
                    with self.assertRaisesRegex(ValueError,'windows_job_original_controller_pending'):
                        executor.observe(self.operation,count=3,interval_seconds=.01)
                    self.assertEqual(1,remote.call_count);self.assertEqual('job-status',remote.call_args.args[1])

    def test_exact_prelaunch_no_controller_proof_allows_original_first_admission(self):
        saved=snapshot()
        with tempfile.TemporaryDirectory() as directory:
            backend=types.SimpleNamespace(root=Path(directory),target='windows:trusted:'+self.binding.machine,
                machine=self.binding.machine,provider=saved['provider'],binding=saved['binding'],expected_sid=saved['expectedSid'])
            state={**saved,'guest':jobs.asdict(self.binding),'sources':{'public':'fixed'}}
            absent=self.observation('unsubmitted',reason='original_admission_absent')
            for key in ('admissionNonce','programSha256','owner'):absent.pop(key)
            with mock.patch.object(jobs,'_source_pins',return_value={'public':'fixed'}):
                executor=jobs.WindowsJobExecutor(backend,state)
                refusal=jobs._ControllerUnsubmitted({'schemaVersion':1,'kind':'fixed-controller-unsubmitted-v1',
                    'phase':'before-controller-dispatch','operationId':self.operation,'machine':self.binding.machine})
                with mock.patch.object(jobs,'_run',side_effect=refusal):
                    with self.assertRaises(jobs._ControllerUnsubmitted):executor.submit(self.operation,count=3,interval_seconds=.01)
                with mock.patch.object(jobs,'_run',side_effect=[absent,self.observation()]) as remote:
                    self.assertEqual('running',executor.observe(self.operation,count=3,interval_seconds=.01)['state'])
                    self.assertEqual(['job-status','job-start'],[c.args[1] for c in remote.call_args_list])
                    self.assertEqual([self.operation,self.operation],[c.args[2] for c in remote.call_args_list])

    def test_namespace_lost_enrollment_reply_retains_artifact_and_accepts_current_readonly_proof(self):
        from agent_tools import readiness_windows as windows
        saved=snapshot();saved['binding']['spec']['deploymentId']=self.binding.machine
        with tempfile.TemporaryDirectory() as directory:
            backend=types.SimpleNamespace(root=Path(directory).resolve(),target='windows:trusted:'+self.binding.machine,
                machine=self.binding.machine,provider=saved['provider'],binding=saved['binding'],expected_sid=saved['expectedSid'],
                last_facts={**saved['host'],'sessionFacts':{'boot':self.binding.boot}})
            def native_boundary(*args,lost=False,**options):
                mode,original=args[1:3];controller=str(uuid4());label=mode+'-fixture'
                source=jobs.remote_program(backend.binding,mode,controller,expected=options['expected'],
                    machine=options['machine'],boot=options['boot'],enrollment_operation=options['enrollment_operation'],
                    enrollment_nonce=options['enrollment_nonce'])
                root=windows._directory(backend.root/'.runtime/readiness-windows-jobs-controllers'/original/controller)
                packet=root/(mode+'.py');windows._save(packet,source)
                prepared={'schemaVersion':1,'mode':mode,'operationId':original,'controllerId':controller,
                    'packetPath':str(packet),'packetSha256':hashlib.sha256(source).hexdigest(),'binding':backend.binding,'host':options['expected']}
                prep=root/'prepared.json';windows._save(prep,prepared)
                if lost:raise TimeoutError('lost acknowledgement')
                reply={'schemaVersion':1,'machine':self.binding.machine,'boot':self.binding.boot,
                    'rootGeneration':self.binding.root_generation,'admissionGeneration':self.binding.admission_generation,
                    'enrollmentOperation':options['enrollment_operation'],'enrollmentNonce':options['enrollment_nonce']}
                script=jobs._packet_literals(source)['JOB_SCRIPT'];digest=hashlib.sha256(script.encode()).hexdigest()
                identity={'schemaVersion':1,'operationId':controller,'label':label,'sourceSha256':digest}
                frame={**identity,'owner':{'pid':4321,'birth':'134369629130736090'},'result':reply}
                value={'state':'observed','operationId':controller,'machine':self.binding.machine,'provider':backend.provider,
                    **options['expected'],'job':reply,'jobController':{
                    'intent':{**identity,'controllerIdentity':identity,'replayAllowed':False,'actor':options['expected']['actor'],'hostBoot':options['expected']['hostBoot']},
                    'ack':{'operationId':controller,'label':label,'replayAllowed':False,'ack':{'pid':4321}},
                    'terminal':{'exited':True,'exitcode':0,'out-data':base64.b64encode(json.dumps(frame).encode()).decode()}}}
                result=root/'result.json';windows._save(result,value)
                if '_receipt' in options:
                    options['_receipt'].update({'preparedPath':str(prep),'preparedSha256':hashlib.sha256(prep.read_bytes()).hexdigest(),
                        'resultPath':str(result),'resultSha256':hashlib.sha256(result.read_bytes()).hexdigest()})
                return reply
            with mock.patch.object(jobs,'_source_pins',return_value={'public':'fixed'}):
                with mock.patch.object(jobs,'_run',side_effect=lambda *a,**k:native_boundary(*a,lost=True,**k)) as first:
                    with self.assertRaises(TimeoutError):jobs.ensure_namespace(backend,deadline=time.monotonic()+10)
                original=first.call_args.kwargs
                with self.assertRaisesRegex(ValueError,'windows_job_namespace_admission_unknown'):
                    jobs.namespace_binding(directory,backend.target,backend.machine)
                def retained(*args,**options):
                    self.assertEqual('job-namespace-status',args[1])
                    self.assertEqual(original['enrollment_operation'],options['enrollment_operation'])
                    self.assertEqual(original['enrollment_nonce'],options['enrollment_nonce'])
                    return native_boundary(*args,**options)
                with mock.patch.object(jobs,'_run',side_effect=retained):
                    self.assertEqual(self.binding,jobs.ensure_namespace(backend,deadline=time.monotonic()+10).binding)
                self.assertEqual(self.binding,jobs.namespace_binding(directory,backend.target,backend.machine,backend.binding))
            # New source cohort can create a NEW job only after authenticating
            # the accepted old artifact and current same-root readonly proof.
            with mock.patch.object(jobs,'_source_pins',return_value={'public':'new-cohort'}),mock.patch.object(jobs,'_run',side_effect=retained) as observe:
                executor=jobs.ensure_namespace(backend,deadline=time.monotonic()+10)
                self.assertEqual({'public':'new-cohort'},executor.snapshot()['sources'])
                self.assertEqual(['job-namespace-status'],[c.args[1]for c in observe.call_args_list])
            from agent_tools import readiness_fixture_registry as registry
            path=jobs._namespace_paths(directory,backend.target,backend.machine)[0]
            value=registry._json(path)[0]
            altered=copy.deepcopy(value);proof=altered['artifact']['acceptance']
            result=json.loads(Path(proof['resultPath']).read_bytes())
            result['jobController']['ack']['ack']['pid']=9999
            replacement=Path(proof['resultPath']).with_name('wrong-pid-result.json');windows._save(replacement,result)
            proof.update(resultPath=str(replacement),resultSha256=hashlib.sha256(replacement.read_bytes()).hexdigest())
            with self.assertRaisesRegex(ValueError,'windows_job_controller_terminal_changed'):
                jobs._validate_namespace_artifact(directory,altered)

    @unittest.skipUnless(os.name=='nt','actual native Windows C# compiler')
    def test_actual_native_csharp_compiles_without_creating_job_or_namespace(self):
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',
                               '$s=[Console]::In.ReadToEnd(); & ([ScriptBlock]::Create($s))'],
                              input=jobs._prefix().encode(),capture_output=True,timeout=30)
        self.assertEqual(0,result.returncode,result.stderr.decode('utf8','replace'))


if __name__=='__main__':unittest.main()

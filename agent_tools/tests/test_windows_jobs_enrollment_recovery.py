"""Whole-helper causal admission recovery without a Windows guest or connection."""
import base64
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest import mock
from uuid import uuid4

from agent_tools import readiness_windows_jobs as jobs
from agent_tools import readiness_windows as windows
from agent_tools.tests.test_readiness_windows import snapshot


class WindowsEnrollmentRecoveryTests(unittest.TestCase):
    def before(self):
        folder = Path(__file__).parent / 'fixtures/windows_jobs_enrollment_recovery'
        raw = (folder / 'before.source').read_bytes()
        self.assertEqual(json.loads((folder / 'provenance.json').read_bytes())['sourceSha256'], hashlib.sha256(raw).hexdigest())
        module = types.ModuleType('agent_tools._windows_enrollment_before')
        module.__file__ = str(folder / 'before.source')
        module.__package__ = 'agent_tools'
        sys.modules[module.__name__] = module
        self.addCleanup(sys.modules.pop, module.__name__, None)
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
        return module

    def setup_backend(self, module, directory):
        binding = module.WindowsJobBinding('abcdef78-1234-4234-9234-123456789012',
            '2026-10-20T09:04:39.5000000Z', '12345678:0003000000000847:01dd6077063bd7e7',
            '12345678:0003000000000848:01dd6077063bd7e8')
        saved = snapshot()
        saved['binding']['spec']['deploymentId'] = binding.machine
        backend = types.SimpleNamespace(root=Path(directory).resolve(), target='windows:trusted:' + binding.machine,
            machine=binding.machine, provider=saved['provider'], binding=saved['binding'], expected_sid=saved['expectedSid'],
            last_facts={**saved['host'], 'sessionFacts':{'boot':binding.boot}})
        return backend, binding, saved

    def test_complete_first_enrollment_lost_ack_red_before_original_observation_green_now(self):
        before = self.before()
        for module in (before, jobs):
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as directory:
                backend, binding, saved = self.setup_backend(module, directory)
                calls = []
                admitted = []
                def native_boundary(*args, **options):
                    mode, original = args[1:3]
                    calls.append(mode)
                    if mode == 'job-enroll':
                        self.assertEqual([], admitted)
                        admitted.append((original, options['enrollment_nonce']))
                    else:
                        self.assertEqual('job-namespace-status', mode)
                        self.assertEqual([(original, options['enrollment_nonce'])], admitted)
                    controller = str(uuid4())
                    source = module.remote_program(backend.binding, mode, controller, expected=options['expected'],
                        machine=options['machine'], boot=options['boot'], enrollment_operation=options['enrollment_operation'],
                        enrollment_nonce=options['enrollment_nonce'])
                    folder = windows._directory(backend.root / '.runtime/readiness-windows-jobs-controllers' / original / controller)
                    packet = folder / (mode + '.py')
                    windows._save(packet, source)
                    prepared = {'schemaVersion':1,'mode':mode,'operationId':original,'controllerId':controller,
                        'packetPath':str(packet),'packetSha256':hashlib.sha256(source).hexdigest(),
                        'binding':backend.binding,'host':options['expected']}
                    preparation = folder / 'prepared.json'
                    windows._save(preparation, prepared)
                    if mode == 'job-enroll':
                        raise TimeoutError('controlled lost acknowledgement after admission')
                    reply = {'schemaVersion':1,'machine':binding.machine,'boot':binding.boot,
                        'rootGeneration':binding.root_generation,'admissionGeneration':binding.admission_generation,
                        'enrollmentOperation':options['enrollment_operation'],'enrollmentNonce':options['enrollment_nonce']}
                    script = module._packet_literals(source)['JOB_SCRIPT']
                    frame_identity = {'schemaVersion':1,'operationId':controller,'label':'job-namespace-status-fixture',
                                      'sourceSha256':hashlib.sha256(script.encode()).hexdigest()}
                    frame = {**frame_identity,'owner':{'pid':4321,'birth':'134369629130736090'},'result':reply}
                    value = {'state':'observed','operationId':controller,'machine':binding.machine,
                        'provider':backend.provider,**options['expected'],'job':reply,'jobController':{
                        'intent':{**frame_identity,'controllerIdentity':frame_identity,'replayAllowed':False,
                                  'actor':options['expected']['actor'],'hostBoot':options['expected']['hostBoot']},
                        'ack':{'operationId':controller,'label':frame_identity['label'],'replayAllowed':False,'ack':{'pid':4321}},
                        'terminal':{'exited':True,'exitcode':0,'out-data':base64.b64encode(json.dumps(frame).encode()).decode()}}}
                    result = folder / 'result.json'
                    windows._save(result, value)
                    options['_receipt'].update({'preparedPath':str(preparation),
                        'preparedSha256':hashlib.sha256(preparation.read_bytes()).hexdigest(),
                        'resultPath':str(result),'resultSha256':hashlib.sha256(result.read_bytes()).hexdigest()})
                    return reply
                with mock.patch.object(module, '_source_pins', return_value={'public':'fixed'}), mock.patch.object(module, '_run', side_effect=native_boundary):
                    if module is before:
                        with self.assertRaises(TimeoutError):module.ensure_namespace(backend, deadline=time.monotonic()+10)
                        self.assertEqual(['job-enroll'], calls)  # actual original fails automatic recovery
                    else:
                        executor = module.ensure_namespace(backend, deadline=time.monotonic()+10)
                        self.assertEqual(binding, executor.binding)
                        self.assertEqual(binding, module.namespace_binding(directory, backend.target, backend.machine, backend.binding))
                        self.assertEqual(['job-enroll','job-namespace-status'], calls)
                    self.assertEqual(1, len(admitted))

    def test_discarded_command_generation_red_before_pure_spec_validation_green_now(self):
        before = self.before()
        for module in (before, jobs):
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as directory:
                backend, binding, saved = self.setup_backend(module, directory)
                state = {**saved, 'guest':module.asdict(binding), 'sources':{'public':'fixed'}}
                with mock.patch.object(module, '_source_pins', return_value={'public':'fixed'}):
                    executor = module.WindowsJobExecutor(backend, state)
                    with mock.patch.object(module, 'program', side_effect=AssertionError('generated before admission')) as generation, mock.patch.object(executor, '_dispatch_held', return_value='controlled dispatch boundary') as dispatch:
                        if module is before:
                            with self.assertRaisesRegex(AssertionError, 'generated before admission'):
                                executor.observe(str(uuid4()), count=3, interval_seconds=.01)
                            self.assertEqual(0, dispatch.call_count)
                        else:
                            self.assertEqual('controlled dispatch boundary', executor.observe(str(uuid4()), count=3, interval_seconds=.01))
                            self.assertEqual(0, generation.call_count)
                            self.assertEqual(1, dispatch.call_count)

    def test_integrity_or_exhausted_deadline_never_triggers_recovery_observation(self):
        for failure in (ValueError('windows_job_source_changed'), ValueError('windows_job_control_unknown'), TimeoutError('expired acknowledgement')):
            with self.subTest(failure=str(failure)), tempfile.TemporaryDirectory() as directory:
                backend, _, _ = self.setup_backend(jobs, directory)
                deadline = time.monotonic()-1 if isinstance(failure, TimeoutError) else time.monotonic()+10
                with mock.patch.object(jobs, '_source_pins', return_value={'public':'fixed'}), mock.patch.object(jobs, '_run', side_effect=failure) as dispatch:
                    with self.assertRaises(type(failure)):jobs.ensure_namespace(backend, deadline=deadline)
                    self.assertEqual(1, dispatch.call_count)


if __name__ == '__main__':
    unittest.main()

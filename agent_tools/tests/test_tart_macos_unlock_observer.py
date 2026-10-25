"""Fixed original observer protocol and actual detached-owner receipts.

The root/native collector remains unqualified here. Controlled public data
exercise the complete durable-owner admission, retained streams and parser.
"""
import base64
import ast
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from uuid import uuid4
import zlib

from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_tart_macos as backend_module
from agent_tools import readiness_tart_macos_unlock_observer as observer
from agent_tools import readiness_tart_macos_unlock_qualification as qualification
from agent_tools import readiness_tart_macos_registry as registry
from agent_tools.tests.test_readiness_tart_macos import binding
from agent_tools.tests.test_tart_macos_unlock_material import identity

# A macOS guest owner's darwin:<seconds>:<microseconds> birth, for an actual local
# owner whose durable birth has another host's encoding (linux:<start ticks>).
GUEST_OWNER_BIRTH = 'darwin:1700000000:0'


class ObserverBuilderTests(unittest.TestCase):
    def custody(self):
        result = object.__new__(registry.MacCustody); result.binding = binding()
        result.run_intent = {'operationId': str(uuid4())}
        result.guest_proof = {'prefix': '/usr/local/libexec/vpn-tool-recovery-cont-controlled',
                             'publicFiles': {'guest-probe.py': 'a' * 64},
                             'initialPacket': {'agent': {'rawBoot': str(uuid4()).upper()}}}
        return result

    def test_observer_is_deterministic_and_separate_from_input_operation(self):
        original = str(uuid4())
        self.assertEqual(observer.observer_id(original), observer.observer_id(original))
        self.assertNotEqual(observer.observer_id(original), original)

    def test_namespace_builder_is_pure_finite_and_does_not_accept_root_or_commands(self):
        custody = self.custody()
        enrollment = observer.enrollment_spec(custody, str(uuid4()))
        for mode in ('enroll', 'namespace-status'):
            source = observer.namespace_source(custody, mode, enrollment=enrollment)
            compile(source, 'fixed-observer-namespace', 'exec')
            self.assertIn(observer.ROOT.encode(), source)
            self.assertIn(b"'action': " + repr(mode).encode(), source)
        for invalid in ('start', 'arbitrary', {'root': '/tmp'}):
            with self.assertRaises((qualification.QualificationBlocked, TypeError)):
                observer.namespace_source(custody, invalid, enrollment=enrollment)

    def test_namespace_commitment_is_bound_to_original_enrollment_and_actual_target(self):
        custody = self.custody(); enrollment = observer.enrollment_spec(custody, str(uuid4()))
        for changed in ({**enrollment, 'hostIntentSha256': 'a' * 64},
                        {**enrollment, 'commitment': {**enrollment['commitment'], 'target': 'other'}}):
            with self.assertRaises(qualification.QualificationBlocked):
                observer.namespace_source(custody, 'enroll', enrollment=changed)
        self.assertNotEqual(enrollment, observer.enrollment_spec(custody, str(uuid4())))
        with self.assertRaises(TypeError):
            observer.namespace_source(custody, 'enroll')

    def test_historical_status_uses_current_readonly_producer_without_old_module_execution(self):
        custody = self.custody(); enrollment = observer.enrollment_spec(custody, str(uuid4()))
        enrollment['commitment']['observerProducerSha256'] = 'b' * 64
        enrollment['commitment']['rawBoot'] = str(uuid4()).upper()
        enrollment['hostIntentSha256'] = hashlib.sha256(json.dumps(enrollment['commitment'],
            sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        source = observer.namespace_source(custody, 'namespace-status', enrollment=enrollment)
        self.assertTrue(source.endswith(observer._NAMESPACE.encode()))
        with self.assertRaises(qualification.QualificationBlocked):
            observer.namespace_source(custody, 'enroll', enrollment=enrollment)

    @unittest.skipUnless(os.name == 'posix', 'complete fixed caller and private filesystem')
    def test_actual_before_adopts_untracked_namespace_current_requires_original_marker_and_no_replay(self):
        import pwd
        path = Path(__file__).parent / 'fixtures/tart_macos_unlock_observer_namespace.before.source'
        tree = ast.parse(path.read_bytes())
        before = {name: ast.literal_eval(next(node.value for node in tree.body if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)))
                  for name in ('_MACHINE',)}
        # Preserve the entire old generated caller. Only the fixed root getter
        # boundary and task-owned namespace are redirected to controlled ones.
        nodes = {node.targets[0].id: node.value for node in tree.body if isinstance(node, ast.Assign)
                 and isinstance(node.targets[0], ast.Name)}
        old_namespace = eval(compile(ast.Expression(nodes['_NAMESPACE']), '<old-namespace>', 'eval'), before)
        user = pwd.getpwuid(os.geteuid())
        parameters = {'action': 'enroll', 'target': 'controlled', 'machine': 'controlled-machine',
                      'uid': user.pw_uid, 'principal': user.pw_name, 'home': user.pw_dir,
                      'rawBoot': jobs._boot(),
                      'enrollmentId': str(uuid4()), 'hostIntentSha256': 'a' * 64}
        def call(body, target, machine_source, values):
            body = body.replace(observer.ROOT, str(target)).replace(machine_source, 'def actual_machine(p):return p["machine"]\n')
            # The whole emitted caller still performs _binding_live. Only the
            # platform-specific kernel getter uses this host's actual boot in
            # the controlled Darwin protocol fixture.
            body = body.replace('D.owner_source=lambda:OWNER', 'D.owner_source=lambda:OWNER;D._boot=lambda:' + repr(jobs._boot()))
            source = ('import sys,os\nsys.platform="darwin"\nos.getgrouplist=lambda *_:[]\n'
                      'PARAMETERS=' + repr(values) + '\nOWNER=' + repr(jobs.owner_source()) + '\n' + body)
            return subprocess.run([sys.executable, '-I', '-'], input=source.encode(), stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=5)
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve(); parent.chmod(0o700); old_root = parent / 'old'
            first = call(old_namespace, old_root, before['_MACHINE'], parameters)
            self.assertEqual(first.returncode, 0, first.stderr)
            # Different enrollment/digest is silently adopted by the unfixed
            # complete caller: neither identity was present in its marker.
            changed = {**parameters, 'enrollmentId': str(uuid4()), 'hostIntentSha256': 'b' * 64}
            red = call(old_namespace, old_root, before['_MACHINE'], changed)
            self.assertEqual(red.returncode, 0, red.stderr)
            green = call(observer._NAMESPACE, old_root, observer._MACHINE, changed)
            self.assertEqual(green.returncode, 73); self.assertEqual(green.stdout, b'')
            new_root = parent / 'new'; admitted = call(observer._NAMESPACE, new_root, observer._MACHINE, parameters)
            self.assertEqual(admitted.returncode, 0, admitted.stderr)
            marker = json.loads((new_root / 'namespace.json').read_bytes())
            self.assertEqual((marker['enrollmentId'], marker['hostIntentSha256']),
                             (parameters['enrollmentId'], parameters['hostIntentSha256']))
            repeated = call(observer._NAMESPACE, new_root, observer._MACHINE, parameters)
            self.assertEqual(repeated.returncode, 73)
            status = call(observer._NAMESPACE, new_root, observer._MACHINE, {**parameters, 'action': 'namespace-status'})
            self.assertEqual(status.returncode, 0, status.stderr)
            foreign = call(observer._NAMESPACE, new_root, observer._MACHINE, {**changed, 'action': 'namespace-status'})
            self.assertEqual(foreign.returncode, 73); self.assertEqual(foreign.stdout, b'')

    @unittest.skipUnless(os.name == 'posix', 'whole generated namespace caller and actual private paths')
    def test_whole_before_admits_stale_boot_current_stops_before_mkdir_status_stays_readonly(self):
        import pwd
        path = Path(__file__).parent / 'fixtures/tart_macos_unlock_observer_before_boot_admission.source'
        tree = ast.parse(path.read_bytes())
        nodes = {node.targets[0].id: node.value for node in tree.body if isinstance(node, ast.Assign)
                 and isinstance(node.targets[0], ast.Name)}
        machine = ast.literal_eval(nodes['_MACHINE'])
        before = eval(compile(ast.Expression(nodes['_NAMESPACE']), '<whole-before-namespace>', 'eval'), {'_MACHINE': machine})
        user = pwd.getpwuid(os.geteuid()); actual_boot = jobs._boot()
        parameters = {'action': 'enroll', 'target': 'controlled', 'machine': 'controlled-machine',
            'uid': user.pw_uid, 'principal': user.pw_name, 'home': user.pw_dir,
            'rawBoot': str(uuid4()), 'enrollmentId': str(uuid4()), 'hostIntentSha256': 'a' * 64}
        def call(body, target, values):
            body = body.replace(observer.ROOT, str(target)).replace(machine, 'def actual_machine(p):return p["machine"]\n')
            body = body.replace('D.owner_source=lambda:OWNER', 'D.owner_source=lambda:OWNER;D._boot=lambda:' + repr(actual_boot))
            source = ('import sys,os\nsys.platform="darwin"\nos.getgrouplist=lambda *_:[]\nPARAMETERS=' + repr(values)
                      + '\nOWNER=' + repr(jobs.owner_source()) + '\n' + body).encode()
            return subprocess.run([sys.executable, '-I', '-B', '-'], input=source,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); root.chmod(0o700)
            old = call(before, root / 'before', parameters)
            self.assertEqual(old.returncode, 0, old.stderr)
            fresh = root / 'current'; blocked = call(observer._NAMESPACE, fresh, parameters)
            self.assertNotEqual(blocked.returncode, 0); self.assertEqual(blocked.stdout, b'')
            self.assertFalse(fresh.exists(), 'stale boot may not perform even the initial mkdir')
            admitted = call(observer._NAMESPACE, fresh, {**parameters, 'rawBoot': actual_boot})
            self.assertEqual(admitted.returncode, 0, admitted.stderr)
            status = call(observer._NAMESPACE, fresh, {**parameters, 'action': 'namespace-status'})
            self.assertEqual(status.returncode, 0, status.stderr)
            self.assertEqual(json.loads(status.stdout)['namespace'], json.loads(admitted.stdout)['namespace'])

    @unittest.skipUnless(os.name == 'posix', 'actual fixed POSIX subprocess')
    def test_complete_native_program_wrong_account_exits_before_any_helper_or_files(self):
        source = observer._program({'uid': max(501, os.geteuid() + 1), 'principal': 'wrong', 'home': '/Users/wrong'})
        result = subprocess.run([sys.executable, '-I', '-'], input=source, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 73); self.assertEqual(result.stdout, b''); self.assertEqual(result.stderr, b'')

    def test_local_dto_cannot_construct_authenticated_observation(self):
        with self.assertRaisesRegex(qualification.QualificationBlocked, 'original_observer_required'):
            observer.NativeObservation(observation=identity(False), nativeQualified=True)


@unittest.skipUnless(os.name == 'posix', 'actual detached POSIX owner')
class OriginalObserverReceiptTests(unittest.TestCase):
    def test_complete_fixed_inventory_collects_real_owner_and_refuses_extra_work(self):
        import pwd
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); root.chmod(0o700)
            work = root / 'jobs'; work.mkdir(mode=0o700)
            admissions = root / 'admissions'; admissions.mkdir(mode=0o700)
            bound = jobs.current_binding('controlled-observer', 'controlled-machine')
            original = str(uuid4()); operation = observer.observer_id(original)
            program = jobs.Program('original-macos-unlock-observer-v1', b'print("readonly-proof")\n', 1024)
            jobs.submit(work, operation, bound, program, generation=jobs.root_generation(work))
            until = time.monotonic() + 4
            while jobs.observe(work, operation, bound, generation=jobs.root_generation(work))['state'] != 'terminal':
                self.assertLess(time.monotonic(), until); time.sleep(.01)
            packet = {'schemaVersion': 1, 'root': str(root), 'target': bound.target, 'machine': bound.machine,
                'account': bound.account, 'ownerSha256': hashlib.sha256(jobs.owner_source()).hexdigest(),
                'enrollmentId': str(uuid4()), 'hostIntentSha256': 'a' * 64,
                'rootGeneration': list(jobs.root_generation(root)), 'jobGeneration': list(jobs.root_generation(work)),
                'admissionGeneration': list(jobs.root_generation(admissions))}
            jobs._publish(root / 'namespace.json', {key: value for key, value in packet.items()
                if key not in {'rootGeneration', 'jobGeneration', 'admissionGeneration'}})
            expected = {'schemaVersion': 1, 'originalOperationId': original, 'observerOperationId': operation,
                'namespace': packet, 'binding': asdict(bound), 'programSha256': program.digest,
                'originalPins': {'controlled': 'source-admitted'}}
            jobs._publish(admissions / (operation + '.json'), {k: v for k, v in expected.items() if k != 'namespace'})
            user = pwd.getpwuid(os.geteuid())
            parameters = {'namespace': packet, 'prefix': '/not-used', 'files': {}, 'admissions': {operation: expected},
                          'uid': user.pw_uid, 'principal': user.pw_name, 'home': user.pw_dir}
            body = observer._INVENTORY.replace(observer.ROOT, str(root)).replace(observer._MACHINE,
                'def actual_machine(p):return p["namespace"]["machine"]\n')
            source = ('import sys,os\nsys.platform="darwin"\nos.getgrouplist=lambda *_:[]\nPARAMETERS=' + repr(parameters)
                      + '\nOWNER=' + repr(jobs.owner_source()) + '\n' + body).encode()
            def execute():
                return subprocess.run([sys.executable, '-I', '-B', '-'], input=source,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            first = execute(); self.assertEqual(first.returncode, 0, first.stderr)
            value = json.loads(first.stdout)
            self.assertTrue(value['visibilityComplete']); self.assertTrue(value['idle'])
            self.assertEqual(value['jobs'][0]['terminal']['programSha256'], program.digest)
            # Actual positive extra work cannot be hidden by an old host list.
            orphan = work / str(uuid4()); orphan.mkdir(mode=0o700)
            blocked = execute(); self.assertEqual((blocked.returncode, blocked.stdout), (73, b''))
            orphan.rmdir()
            extra = admissions / (str(uuid4()) + '.json'); jobs._publish(extra, {'state': 'unknown'})
            blocked = execute(); self.assertEqual((blocked.returncode, blocked.stdout), (73, b''))

    def actual_reply(self, folder):
        original = str(uuid4()); operation = observer.observer_id(original)
        current = jobs.current_binding('controlled-original-observer', 'controlled-machine')
        packet = {'root': observer.ROOT, 'rootGeneration': [1, 2], 'jobGeneration': [1, 3], 'admissionGeneration': [1, 4]}
        pins = {'original': {'generation': [1] * 9, 'sha256': 'a' * 64}}
        raw = json.dumps({'facts': {'controlled': True}, 'qualification': {'controlled': True}}).encode()
        body = {'schemaVersion': 1, 'originalOperationId': original, 'observerOperationId': operation,
                'originalPins': pins, 'executions': 1,
                'rootBefore': base64.b64encode(zlib.compress(raw)).decode(), 'rootAfter': base64.b64encode(zlib.compress(raw)).decode()}
        program_source = ("import os,pathlib,time\npath=pathlib.Path(" + repr(str(folder / operation / 'probe-executed.txt')) + ")\n"
                          "fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\n"
                          "with os.fdopen(fd,'wb')as out:out.write(b'execution\\n');out.flush();os.fsync(out.fileno())\n"
                          "time.sleep(.2)\nprint(" + repr(json.dumps(body)) + ",flush=True)\n").encode()
        program = jobs.Program('controlled-observer-packet', program_source, 8192)
        generation = jobs.root_generation(folder)
        # Actual local client dies after submission. The detached owner remains
        # the same and finishes; no replacement submit follows the death.
        child = ("import os\nfrom agent_tools import durable_remote_job as J\n"
                 "J.submit(" + repr(str(folder)) + "," + repr(operation) + ",J.MachineBinding.from_dict(" + repr(asdict(current)) + "),"
                 "J.Program(" + repr(program.purpose) + "," + repr(program.source) + ",8192),generation=" + repr(generation) + ")\nos._exit(77)\n")
        result = subprocess.run([sys.executable, '-c', child], cwd=Path(__file__).parents[2], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 77, result.stderr); self.assertEqual(result.stderr, b'')
        end = time.monotonic() + 5
        while time.monotonic() < end:
            status = jobs.observe(folder, operation, current, generation=generation)
            if status['state'] == 'terminal': break
            time.sleep(.01)
        self.assertEqual(status['state'], 'terminal', status)
        _, stdout, stderr = jobs.collect(folder, operation, current, generation=generation)
        parameters = {'namespace': packet, 'binding': asdict(current), 'originalOperationId': original,
                      'observerOperationId': operation, 'originalPins': pins}
        reply = {**parameters, 'status': status, 'stdout': base64.b64encode(stdout).decode(),
                 'stderr': base64.b64encode(stderr).decode(), 'counter': base64.b64encode((folder / operation / 'probe-executed.txt').read_bytes()).decode()}
        self.actual_owner = status.get('owner')
        if not str((self.actual_owner or {}).get('birth')).startswith('darwin:'):
            # The actual owner carries this host's durable birth (linux:<start ticks> on a
            # Linux runner); the observer admits only a macOS guest owner's
            # darwin:<seconds>:<microseconds>, so after every earlier terminal check that
            # birth itself is refused.
            try:
                observer._terminal(reply, parameters, program); refusal = None
            except Exception as error:
                refusal = (type(error), str(error))
            self.assertEqual((backend_module.MacBlocked, 'macos_actor_invalid'), refusal, 'status=%r stdout=%r stderr=%r' % (status, stdout, stderr))
            # The same actual receipt is then the one a macOS guest owner reports: one
            # macOS-encoded birth in both owner identities, every other byte actual.
            self.assertEqual(status['owner'], status['terminal']['owner'], status)
            reply['status'] = {**status, 'owner': {**status['owner'], 'birth': GUEST_OWNER_BIRTH},
                               'terminal': {**status['terminal'], 'owner': {**status['owner'], 'birth': GUEST_OWNER_BIRTH}}}
        return reply, parameters, program

    def test_original_durable_owner_after_client_death_has_one_execution_complete_streams(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary).resolve(); folder.chmod(0o700)
            reply, parameters, program = self.actual_reply(folder)
            try:
                value, terminal = observer._terminal(reply, parameters, program)
            except Exception as error:
                error.add_note('actualOwner=%r status=%r stdout=%r stderr=%r' % (self.actual_owner, reply['status'], reply['stdout'], reply['stderr']))
                raise
            self.assertEqual(value['executions'], 1, value); self.assertEqual(terminal['exitCode'], 0, terminal)
            self.assertTrue(terminal['streamsClosed'], terminal)

    def test_forged_terminal_hash_or_other_original_cannot_reuse_real_owner_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary).resolve(); folder.chmod(0o700)
            reply, parameters, program = self.actual_reply(folder)
            for field, value in (('originalOperationId', str(uuid4())), ('counter', base64.b64encode(b'execution\nexecution\n').decode()),
                                 ('stdout', base64.b64encode(b'PRIVATE-DO-NOT-ECHO').decode())):
                with self.subTest(field=field), self.assertRaises(qualification.QualificationBlocked, msg='forged %s accepted: actualOwner=%r status=%r' % (field, self.actual_owner, reply['status'])) as error:
                    try:
                        observer._terminal({**reply, field: value}, parameters, program)
                    except Exception as refused:
                        refused.add_note('forged %s: actualOwner=%r status=%r' % (field, self.actual_owner, reply['status']))
                        raise
                self.assertNotIn('PRIVATE', str(error.exception))


if __name__ == '__main__':
    unittest.main()

"""Actual private host-index files plus bounded controlled carrier responses."""
import ast
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock
from uuid import UUID, uuid4, uuid5

from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_tart_macos_registry as registry
from agent_tools import readiness_tart_macos_unlock_observer as observer
from agent_tools import readiness_tart_macos_idle as idle
from agent_tools import readiness_fixture_registry as fixtures
from agent_tools.tests.test_readiness_tart_macos import binding
from agent_tools.tests.test_tart_macos_unlock_material import identity


@unittest.skipUnless(os.name == 'posix', 'actual private source holders and operator flock')
class ObserverCustodyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.project = Path(self.temp.name).resolve(); self.project.chmod(0o700)
        self.root = self.project / '.runtime' / 'owned-run'; self.root.mkdir(mode=0o700, parents=True)
        c = self.custody = object.__new__(registry.MacCustody)
        c.root = self.project; c.lifecycle_root = self.root; c.fixture_id = 'controlled-observer'
        c.binding = binding(); c.run_intent = {'operationId': str(uuid4())}; c._registry = fixtures
        c._operator = registry.OperatorLock(self.root / 'operator.lock'); c.guard = lambda **_: None
        c.qualifications = lambda *_: None
        self.boot = str(uuid4()).upper()
        c.guest_proof = {'prefix': '/usr/local/libexec/vpn-tool-recovery-cont-controlled',
            'publicFiles': {'guest-probe.py': 'a' * 64}, 'initialPacket': {'agent': {'rawBoot': self.boot}}}
        self.calls = []; c.ordinary_guest_call = self.execute
        self.lose_first = False; self.before_send_idle_facts = None

    def execute(self, binding, argv, payload, deadline):
        c = self.custody
        self.assertTrue(c._unlock_observer_paths()[0].is_file(), 'host intent must precede first guest mkdir')
        original = c._unlock_observer_original()
        self.assertTrue(Path(original['capsule']['path']).is_file())
        parameters = ast.literal_eval(next(line.removeprefix('PARAMETERS=') for line in payload.decode().splitlines()
            if line.startswith('PARAMETERS=')))
        if self.before_send_idle_facts is not None:
            visible = c.idle_facts(self.before_send_idle_facts, deadline)
            self.assertIn('unknown_jobs', visible['blockers'])
            self.assertFalse({'running_jobs', 'unknown_jobs'} & visible['visibility'])
        self.calls.append(parameters['action'])
        if self.lose_first and len(self.calls) == 1: raise registry.MacBlocked('controlled_lost_ack')
        commitment = original['enrollment']
        packet = {'schemaVersion': 1, 'root': observer.ROOT, 'target': binding.target, 'machine': binding.machine,
            'account': str(binding.ordinary_uid), 'ownerSha256': hashlib.sha256(jobs.owner_source()).hexdigest(),
            'enrollmentId': original['operationId'], 'hostIntentSha256': commitment['hostIntentSha256'],
            'rootGeneration': [1, 2], 'jobGeneration': [1, 3], 'admissionGeneration': [1, 4]}
        return subprocess.CompletedProcess(argv, 0, json.dumps({'namespace': packet}).encode(), b'')

    def test_host_intent_precedes_once_enroll_actual_marker_readback_and_healthy_no_dispatch(self):
        c = self.custody; packet = c.prepare_unlock_observer_namespace(deadline=time.monotonic()+5)
        self.assertEqual(self.calls, ['enroll', 'namespace-status'])
        path = c._unlock_observer_paths()[0]; original = (path.read_bytes(), path.stat().st_ino)
        c.fixture_id = 'new-source-only-alias'
        self.assertEqual(c.prepare_unlock_observer_namespace(deadline=time.monotonic()+5), packet)
        self.assertEqual(self.calls, ['enroll', 'namespace-status'])
        self.assertEqual((path.read_bytes(), path.stat().st_ino), original)
        self.assertEqual(c._unlock_observer_original()['enrollment']['commitment']['rawBoot'], self.boot)

    def test_lost_first_ack_observes_original_no_second_mkdir(self):
        c = self.custody; self.lose_first = True
        with self.assertRaisesRegex(registry.MacBlocked, 'lost_ack'):
            c.prepare_unlock_observer_namespace(deadline=time.monotonic()+5)
        self.assertFalse(c._unlock_observer_paths()[1].exists())
        original = c._unlock_observer_paths()[0].read_bytes()
        c.prepare_unlock_observer_namespace(deadline=time.monotonic()+5)
        self.assertEqual(self.calls, ['enroll', 'namespace-status', 'namespace-status'])
        self.assertEqual(c._unlock_observer_paths()[0].read_bytes(), original)

    def test_actual_idle_index_blocks_before_first_guest_namespace_send(self):
        self.before_send_idle_facts = self.idle_setup()
        self.custody.prepare_unlock_observer_namespace(deadline=time.monotonic()+5)
        self.assertEqual(self.calls, ['enroll', 'namespace-status'])

    def idle_setup(self):
        c = self.custody; work = self.root / 'host-owned-jobs'; work.mkdir(mode=0o700)
        c.run_owner = SimpleNamespace(root=work)
        facts = {'processVisibilityComplete': True, 'installerVisibilityComplete': True,
            'protectedProcesses': [], 'installerBlockers': [], 'jobVisibilityComplete': True}
        return facts

    def test_whole_original_idle_method_omits_prepacket_intent_current_blocks(self):
        c = self.custody; facts = self.idle_setup()
        # No guest packet exists: the host index alone must keep UNKNOWN visible.
        jobs._publish(c._unlock_observer_paths()[0], {'state': 'unknown', 'malformed': True})
        path = Path(__file__).parent / 'fixtures/tart_macos_idle_before_unlock_observer_index.source'
        scope = {'jobs': jobs, '_uuid': registry._uuid}
        exec(compile(path.read_bytes(), str(path), 'exec'), scope)
        with c.operator(deadline=time.monotonic()+5):
            before = scope['idle_facts'](c, facts, time.monotonic()+5)
            self.assertFalse(before['blockers'])
            self.assertTrue({'running_jobs', 'unknown_jobs'} <= before['visibility'])
            after = c.idle_facts(facts, time.monotonic()+5)
            self.assertIn('unknown_jobs', after['blockers'])
            self.assertFalse({'running_jobs', 'unknown_jobs'} & after['visibility'])

    def test_orphan_observer_reservation_without_namespace_blocks_idle(self):
        c = self.custody; facts = self.idle_setup()
        directory = c._unlock_observer_paths()[2]; directory.mkdir(mode=0o700)
        jobs._publish(directory / (str(uuid4()) + '.intent.json'), {'state': 'unknown'})
        with c.operator(deadline=time.monotonic()+5):
            self.assertIn('unknown_jobs', c.idle_facts(facts, time.monotonic()+5)['blockers'])

    def test_optional_third_role_requires_opaque_custody_enrollment_and_live_generations(self):
        c = self.custody; packet = c.prepare_unlock_observer_namespace(deadline=time.monotonic()+5)
        active = idle.IdleBinding(c.binding.target, c.binding.machine, self.boot.lower(), c.binding.ordinary_uid,
                                 42, 'darwin:123456:123')
        expected = {'guest-jobs': ((2, 1), (2, 2)), 'gui-leases': ((3, 1), (3, 2)),
                    'unlock-observers': (tuple(packet['jobGeneration']), tuple(packet['admissionGeneration']))}
        with self.assertRaises(Exception): observer.ObserverIdleEnrollment(nativeQualified=True)
        with self.assertRaises(idle.MacIdleError): idle._namespaces(expected, {}, active)
        with self.assertRaises(idle.MacIdleError): idle._namespaces(expected, {}, active, {'registered': True})
        with c.operator(deadline=time.monotonic()+5), observer.idle_enrollment(c) as held:
            complete, running, unknown = idle._namespaces(expected, {}, active, held)
            self.assertFalse(complete); self.assertFalse(running); self.assertEqual(len(unknown), 3)
            original = c._unlock_observer_paths()[1]; replacement = self.root / 'new-packet'
            replacement.write_bytes(original.read_bytes()); replacement.chmod(0o600); replacement.replace(original)
            with self.assertRaises(ValueError): held.guard()

    def test_unknown_extra_host_admission_and_forged_collection_are_not_accepted(self):
        c = self.custody; c.prepare_unlock_observer_namespace(deadline=time.monotonic()+5)
        directory = c._unlock_observer_paths()[2]; directory.mkdir(mode=0o700)
        jobs._publish(directory / (str(uuid4()) + '.json'), {'state': 'terminal'})
        with self.assertRaisesRegex(registry.MacBlocked, 'inventory_changed'):
            c._unlock_observer_admissions()
        with self.assertRaisesRegex(registry.MacBlocked, 'original_observer_required'):
            c.collect_unlock_observer(str(uuid4()), {'state': 'observed_unlocked'}, deadline=time.monotonic()+5)

    def test_full_original_reservation_is_validated_before_any_program_admission(self):
        from agent_tools import readiness_tart_macos_unlock as unlock, readiness_tart_macos_unlock_material as material
        c = self.custody; c.prepare_unlock_observer_namespace(deadline=time.monotonic()+5)
        operation = str(uuid4()); recipient = identity()
        with mock.patch.object(unlock, '_snapshot', return_value=recipient):
            c.reserve_unlock_observer(operation, recipient=recipient, deadline=time.monotonic()+5)
        secret, submit = (str(uuid5(UUID(operation), phase)) for phase in ('secret', 'return'))
        with registry.private.Directory(self.root) as directory:
            unlock._record(directory, 'macos-unlock-' + operation + '.json', {'schemaVersion': 1,
                'operationId': operation, 'recipient': recipient, 'state': 'unknown_no_replay',
                'sourceSha256': next(iter(material._ORIGINAL_PRODUCERS))})
            unlock._record(directory, secret + '.json', {'schemaVersion': 1, 'operationId': secret,
                'bindingId': operation, 'action': 'secret_input', 'state': 'unknown'})
            unlock._record(directory, 'macos-unlock-password-' + secret + '.json',
                {'operationId': secret, 'state': 'transport_complete_not_unlock_receipt'})
            unlock._record(directory, 'macos-unlock-return-' + submit + '.json',
                {'operationId': submit, 'state': 'unknown_no_replay'})
            records = material._original_records(directory, operation)
        program, admission, _ = observer.admission_spec(c, operation, records, c.load_unlock_observer_namespace())
        path = c._unlock_observer_paths()[2] / (operation + '.intent.json')
        original = jobs._record(path)
        for field, changed in self.reservation_changes(original):
            with self.subTest(field=field):
                value = {**original, field: changed}
                path.write_text(json.dumps(value)); path.chmod(0o600)
                with self.assertRaisesRegex(registry.MacBlocked, 'reservation_changed'):
                    c.admit_unlock_observer(operation, admission, program, deadline=time.monotonic()+5)
                self.assertFalse(path.with_name(operation + '.program.json').exists())
                self.assertFalse(path.with_name(operation + '.json').exists())

    def reservation_changes(self, original):
        wrong_namespace = deepcopy(original['namespace']); wrong_namespace['jobGeneration'] = [7, 8]
        return [('originalRun', str(uuid4())), ('namespace', wrong_namespace),
                ('observerOperationId', str(uuid4())), ('observerProducerSha256', 'b' * 64),
                ('controller', {'pid': 0, 'birth': 'darwin:1:1'})]

    def test_preserved_full_before_method_actually_fails_same_admission_regression(self):
        path = Path(__file__).parent / 'fixtures/tart_macos_admit_before_reservation_validation.source'
        scope = dict(registry.__dict__)
        exec(compile(path.read_bytes(), str(path), 'exec'), scope)
        with mock.patch.object(registry.MacCustody, 'admit_unlock_observer', scope['admit_unlock_observer']), \
             mock.patch.object(ObserverCustodyTests, 'reservation_changes', return_value=[('originalRun', str(uuid4()))]):
            case = ObserverCustodyTests('test_full_original_reservation_is_validated_before_any_program_admission')
            result = unittest.TestResult(); case.run(result)
        self.assertEqual(result.errors, [])
        self.assertEqual(len(result.failures), 1)
        self.assertIn('MacBlocked not raised', result.failures[0][1])


if __name__ == '__main__': unittest.main()

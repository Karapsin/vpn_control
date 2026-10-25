"""Owned KVM admission exercises real reservation CAS and complete producers."""
import copy
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock
from types import SimpleNamespace
from uuid import uuid4

from agent_tools import native_environment as environments
from agent_tools import readiness_resources as resources
from agent_tools import windows_vm_deploy_remote as producer
from agent_tools.tests import test_process_census_reproducibility as census
from agent_tools.tests import test_linux_role_paths as old_census

GIB = 1024**3
BOOT = '6ddca4a6-d159-4385-a78d-0a5ce9577aef'


class ResourceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)
        self.machine = str(uuid4())
        self.operation = str(uuid4())
        self.rows = []
        self.calls = []
        guard = mock.MagicMock()
        guard.__enter__.return_value = SimpleNamespace(config=SimpleNamespace(hosts={'archlinux': object(), 'renamed': object()}), guard=lambda: None)
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(resources.deploy.direct, 'Guard', return_value=guard).start()
        mock.patch.object(resources, '_remote_observation', side_effect=self.execute).start()

    def observation(self, target):
        now = time.time_ns()//1_000_000
        sample = lambda timestamp: {'observedAtUnixMs': timestamp, 'availableMemoryBytes': 48*GIB, 'psi': 'normal', 'psiSomeAvg10': 0., 'psiFullAvg10': 0., 'vmstat': {'pswpin': 0, 'pswpout': 0, 'oomKill': 0}}
        return {'schemaVersion': 1, 'deploymentId': target.deployment_id, 'mode': 'host-resources', 'state': 'resources-observed', 'reason': None,
                'hostBootId': BOOT, 'vms': copy.deepcopy(self.rows), 'physicalMemoryBytes': 64*GIB, 'swapUsedBytes': 0,
                'samples': [sample(now-100), sample(now)], 'freeDiskBytes': 300*GIB, 'inventoryComplete': True,
                'nativeActionAllowed': False, 'replayAllowed': False}

    def execute(self, root, target, mode, credential_file=None, **kwargs):
        self.calls.append((target.as_dict(), mode, set(kwargs)))
        if mode == 'host-resources':
            self.assertIsNotNone(credential_file)
            self.assertEqual({'deadline'}, set(kwargs))
            return self.observation(target)
        self.assertEqual('peer', mode)
        return {'state': 'peer-observed', 'platform': 'linux', 'hostBootId': BOOT}

    def prepare(self, **kwargs):
        return resources.prepare_start(self.root, host='archlinux', machine_uuid=self.machine,
                operation_id=self.operation, fixture_root='/home/owner/new-owned-fixture',
                credential_file='/INERT_PRIVATE_REFERENCE', **kwargs)

    def actor(self):
        return {'pid': 17, 'startTicks': 777}

    def running(self):
        self.rows = [{**self.actor(), 'sessionId': 17, 'uid': 1000, 'commandSha256': 'a'*64,
                      'executableGeneration': [1]*9, 'configuredMemoryBytes': 2*GIB}]

    def proof(self):
        return {'machineUuid': self.machine, 'hostBootId': BOOT, 'actor': self.actor(),
                'cleanPoweroffOperationId': str(uuid4()), 'cleanPoweroff': True, 'guestJobsAbsent': True}

    def test_exact_generic_target_has_no_windows_profile_and_producer_accepts_it(self):
        target = resources.ResourceTarget(self.operation, 'archlinux', '/home/owner/new-owned-fixture')
        source = producer.program(target, 'host-resources').decode()
        self.assertEqual({'deploymentId', 'host', 'root'}, set(target.as_dict()))
        self.assertNotIn('assets', source)
        self.assertNotIn('INERT_PRIVATE_REFERENCE', source)
        admission = self.prepare()
        self.assertNotIn('INERT_PRIVATE_REFERENCE', repr(admission))
        self.assertTrue(all(set(row[0]) == {'deploymentId', 'host', 'root'} for row in self.calls))

    def test_one_submission_unknown_capacity_retained_across_fresh_handles(self):
        admission = self.prepare()
        self.assertTrue(admission.mark_submitting())
        self.assertFalse(self.prepare().mark_submitting())
        with environments._LockedState(self.root) as locked:
            row = locked.state['reservations'][0]
            self.assertEqual('unknown', row['activeJob'])
            identity = environments._identity(row)
        with self.assertRaises(environments.NativeEnvironmentError):
            environments.release_environment(self.root, identity)
        with self.assertRaisesRegex(ValueError, 'consumed'):
            admission.validate_before_dispatch()

    def retry_fixture(self, *, record_core=True, consume_resource=True):
        import hashlib
        from uuid import UUID, uuid5
        recovery_id = 'a'*64
        self.operation = str(uuid5(UUID(self.machine), recovery_id))
        admission = self.prepare()
        core_path = self.root/'.rag_index/readiness-targets'/('c'*64)
        environments._secure_directory(core_path)
        intent = {'action': 'start', 'recoveryId': recovery_id, 'target': 'owned-fixture', 'machine': self.machine,
                  'boot': None, 'account': None, 'session': None, 'originalOperationId': str(uuid4())}
        with resources.readiness.RecoveryJournal(core_path).locked(deadline=admission.deadline) as core:
            dispatch = core.next_dispatch(intent); core.consume_dispatch(dispatch)
        if consume_resource:
            self.assertTrue(admission.mark_submitting(attempt=1, recovery_id=recovery_id, dispatch_digest=dispatch['dispatchDigest']))
        proof_file = self.root/'.runtime/readiness-qemu/unsubmitted'/recovery_id/'1.json'
        environments._secure_directory(proof_file.parent)
        body = {'schemaVersion': 1, 'recoveryId': recovery_id, 'attempt': 1, 'dispatchDigest': dispatch['dispatchDigest'],
                'packetSha256': None, 'mutationExecutableStarted': False, 'popenCalled': False,
                'evidence': 'admission_before_mutation_dispatch'}
        raw = json.dumps(body).encode(); proof_file.write_bytes(raw); proof_file.chmod(0o600)
        proof = resources.readiness.RecoveryUnsubmitted(recovery_id, 1, dispatch['dispatchDigest'], hashlib.sha256(raw).hexdigest())
        if record_core:
            with resources.readiness.RecoveryJournal(core_path).locked(deadline=admission.deadline) as core:
                self.assertTrue(core.record_unsubmitted(dispatch, proof))
        return admission, core_path, proof_file, proof, intent

    def test_actual_core_and_native_unsubmitted_proofs_rearm_same_reservation(self):
        admission, core_path, proof_file, proof, intent = self.retry_fixture()
        identity = admission.reservation_identity
        with self.assertRaisesRegex(ValueError, 'previous_dispatch_unknown'):
            admission.validate_before_dispatch(attempt=2)
        self.assertTrue(admission.reconcile_unsubmitted(proof, core_journal_directory=core_path, proof_file=proof_file))
        with self.assertRaisesRegex(ValueError, 'not_submitted'):
            admission.mark_running(self.actor())
        admission.validate_before_dispatch(attempt=2)
        with resources.readiness.RecoveryJournal(core_path).locked(deadline=admission.deadline) as core:
            following = core.next_dispatch(intent); core.consume_dispatch(following)
        self.assertTrue(admission.mark_submitting(attempt=2, recovery_id=proof.recovery_id, dispatch_digest=following['dispatchDigest']))
        self.assertFalse(admission.mark_submitting(attempt=2, recovery_id=proof.recovery_id, dispatch_digest=following['dispatchDigest']))
        self.assertEqual(identity, admission.reservation_identity)
        self.assertEqual(1, len(resources._inventory(self.root)[0]))

    def remote_retry_fixture(self, *, consume_resource=True):
        import hashlib
        admission, core_path, proof_file, proof, intent = self.retry_fixture(record_core=False, consume_resource=consume_resource)
        attestation = self.root/'.runtime/readiness-qemu/unsubmitted-remote'/proof.recovery_id/'1.json'
        environments._secure_directory(attestation.parent)
        attestation.write_bytes(b'{"controlledOriginalTerminal":true}\n');attestation.chmod(0o600)
        native=json.loads(proof_file.read_bytes())
        native.update(schemaVersion=2, evidence='remote_complete_power_refusal', popenCalled=True,
                      packetSha256='f'*64, remoteAttestationSha256=hashlib.sha256(attestation.read_bytes()).hexdigest())
        raw=json.dumps(native).encode();proof_file.write_bytes(raw)
        proof=resources.readiness.RecoveryUnsubmitted(proof.recovery_id,1,proof.dispatch_digest,hashlib.sha256(raw).hexdigest())
        with resources.readiness.RecoveryJournal(core_path).locked(deadline=admission.deadline) as core:
            dispatch=core._read_named('dispatch-'+proof.recovery_id+'-1.json')
            self.assertTrue(core.record_unsubmitted(dispatch,proof))
        return admission, core_path, proof_file, proof, intent, attestation, native

    def controlled_remote_validator(self, admission, proof, attestation, native):
        """Control only the independently tested canonical-packet verifier API."""
        import hashlib
        import sys
        import types
        from contextlib import contextmanager
        snapshot=admission.submission_snapshot()
        expected={'attestation_path':attestation,'attestation_sha256':native['remoteAttestationSha256'],
          'machine_uuid':self.machine,'operation_id':self.operation,'recovery_id':proof.recovery_id,
          'attempt':1,'dispatch_digest':proof.dispatch_digest,'packet_sha256':'f'*64,
          'resource_snapshot':snapshot,'fixture_host':'archlinux','fixture_root':'/home/owner/new-owned-fixture'}
        calls=[];guards=[]
        @contextmanager
        def validated(root, **kwargs):
            self.assertEqual(self.root,root);self.assertEqual(expected,kwargs);calls.append(kwargs)
            with resources.readiness.private.Directory(attestation.parent) as directory:
                with resources.readiness.private.Snapshot(directory,attestation.name) as held:
                    self.assertEqual(hashlib.sha256(held.body).hexdigest(),native['remoteAttestationSha256'])
                    def guard():held.guard();guards.append(True)
                    yield SimpleNamespace(guard=guard)
        module=types.ModuleType('agent_tools.readiness_qemu_refusal');module.validated_remote_refusal=validated
        self.enterContext(mock.patch.dict(sys.modules,{module.__name__:module}))
        import agent_tools
        self.enterContext(mock.patch.object(agent_tools,'readiness_qemu_refusal',module,create=True))
        return calls,guards

    def test_remote_complete_refusal_whole_v1_before_red_same_consumed_claim_green(self):
        import hashlib
        import sys
        import types
        admission,core,proof_file,proof,intent,attestation,native=self.remote_retry_fixture()
        folder=Path(__file__).parent/'fixtures/resource_remote_refusal_before'
        raw=(folder/'readiness_resources.py.source').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),json.loads((folder/'provenance.json').read_bytes())['sourceSha256'])
        before=types.ModuleType('agent_tools._resource_remote_refusal_before');before.__package__='agent_tools';before.__file__=str(folder/'readiness_resources.py.source')
        with mock.patch.dict(sys.modules,{before.__name__:before}):
            exec(compile(raw,before.__file__,'exec'),before.__dict__)
            old=before.ResourceAdmission(admission.root,admission.target,admission.machine_uuid,admission.operation_id,admission.directory,admission.credential_file,admission.deadline)
            with self.assertRaisesRegex(ValueError,'resource_unsubmitted_evidence'):
                old.reconcile_unsubmitted(proof,core_journal_directory=core,proof_file=proof_file)
        identity=admission.reservation_identity
        calls,guards=self.controlled_remote_validator(admission,proof,attestation,native)
        self.assertTrue(admission.reconcile_unsubmitted(proof,core_journal_directory=core,proof_file=proof_file))
        self.assertEqual(len(calls),1);self.assertEqual(len(guards),2)
        admission.validate_before_dispatch(attempt=2)
        self.assertEqual(admission.reservation_identity,identity)
        self.assertEqual(len(resources._inventory(self.root)[0]),1)

    def test_remote_complete_refusal_validator_failure_keeps_original_unknown(self):
        admission,core,proof_file,proof,intent,attestation,native=self.remote_retry_fixture()
        self.controlled_remote_validator(admission,proof,attestation,native)
        attestation.write_bytes(b'{}')
        with self.assertRaises(AssertionError):
            admission.reconcile_unsubmitted(proof,core_journal_directory=core,proof_file=proof_file)
        with self.assertRaisesRegex(ValueError,'resource_previous_dispatch_unknown'):
            admission.validate_before_dispatch(attempt=2)
        with admission._journal().locked(deadline=admission.deadline) as journal:
            self.assertIsNone(journal.lookup('unsubmitted:1'))
        self.assertEqual(len(resources._inventory(self.root)[0]),1)

    def test_remote_controller_evidence_cannot_replace_absent_resource_admission(self):
        admission,core,proof_file,proof,intent,attestation,native=self.remote_retry_fixture(consume_resource=False)
        with self.assertRaisesRegex(ValueError,'resource_unsubmitted_remote_snapshot'):
            admission.reconcile_unsubmitted(proof,core_journal_directory=core,proof_file=proof_file)
        with self.assertRaisesRegex(ValueError,'resource_previous_dispatch_unknown'):
            admission.validate_before_dispatch(attempt=2)

    def test_remote_proof_requires_exact_version_digest_and_truthful_controller_flags(self):
        import hashlib
        admission,core,proof_file,proof,intent,attestation,native=self.remote_retry_fixture()
        for change in ({'schemaVersion':True},{'schemaVersion':1},{'popenCalled':False},
                       {'mutationExecutableStarted':True},{'packetSha256':None},
                       {'remoteAttestationSha256':None},{'evidence':'admission_before_mutation_dispatch'}):
            with self.subTest(change=change):
                body={**native,**change};raw=json.dumps(body).encode();proof_file.write_bytes(raw)
                changed=resources.readiness.RecoveryUnsubmitted(proof.recovery_id,1,proof.dispatch_digest,hashlib.sha256(raw).hexdigest())
                with self.assertRaisesRegex(ValueError,'resource_unsubmitted_evidence'):
                    admission.reconcile_unsubmitted(changed,core_journal_directory=core,proof_file=proof_file)

    def test_preserved_once_only_resource_before_red_verified_same_claim_green(self):
        import hashlib
        import sys
        import types
        admission, core_path, proof_file, proof, intent = self.retry_fixture()
        folder = Path(__file__).parent/'fixtures/resource_retry_before'
        raw = (folder/'readiness_resources.py.source').read_bytes()
        self.assertEqual(json.loads((Path(__file__).parent/'fixtures/resource_retry_before/provenance.json').read_bytes())['sourceSha256'], hashlib.sha256(raw).hexdigest())
        name = 'agent_tools._resource_retry_before'
        before = types.ModuleType(name); before.__package__ = 'agent_tools'; before.__file__ = str(folder/'readiness_resources.py.source')
        with mock.patch.dict(sys.modules, {name: before}):
            exec(compile(raw, before.__file__, 'exec'), before.__dict__)
            original = before.ResourceAdmission(admission.root, admission.target, admission.machine_uuid,
                       admission.operation_id, admission.directory, admission.credential_file, admission.deadline)
            with self.assertRaisesRegex(ValueError, 'dispatch_consumed'):
                original.validate_before_dispatch()
        identity = admission.reservation_identity
        admission.reconcile_unsubmitted(proof, core_journal_directory=core_path, proof_file=proof_file)
        admission.validate_before_dispatch(attempt=2)
        self.assertEqual(identity, admission.reservation_identity)

    def test_core_prelaunch_before_any_resource_admission_before_red_current_green(self):
        import hashlib
        import sys
        import types
        admission, core_path, proof_file, proof, intent = self.retry_fixture(consume_resource=False)
        folder = Path(__file__).parent/'fixtures/resource_no_admission_before'
        raw = (folder/'readiness_resources.py.source').read_bytes()
        provenance = Path(__file__).parent/'fixtures/resource_no_admission_before/provenance.json'
        self.assertEqual(json.loads(provenance.read_bytes())['sourceSha256'], hashlib.sha256(raw).hexdigest())
        name = 'agent_tools._resource_no_admission_before'
        before = types.ModuleType(name); before.__package__ = 'agent_tools'; before.__file__ = str(folder/'readiness_resources.py.source')
        with mock.patch.dict(sys.modules, {name: before}):
            exec(compile(raw, before.__file__, 'exec'), before.__dict__)
            original = before.ResourceAdmission(admission.root, admission.target, admission.machine_uuid,
                       admission.operation_id, admission.directory, admission.credential_file, admission.deadline)
            with self.assertRaisesRegex(ValueError, 'consumed_binding'):
                original.reconcile_unsubmitted(proof, core_journal_directory=core_path, proof_file=proof_file)
        admission.reconcile_unsubmitted(proof, core_journal_directory=core_path, proof_file=proof_file)
        admission.validate_before_dispatch(attempt=2)
        with resources.readiness.RecoveryJournal(core_path).locked(deadline=admission.deadline) as core:
            following = core.next_dispatch(intent); core.consume_dispatch(following)
        self.assertTrue(admission.mark_submitting(attempt=2, recovery_id=proof.recovery_id, dispatch_digest=following['dispatchDigest']))
        with admission._journal().locked(deadline=admission.deadline) as journal:
            self.assertIsNone(journal.lookup('submitting'))
            self.assertIs(journal.lookup('unsubmitted:1')['resourceDispatchConsumed'], False)

    def test_missing_core_proof_or_changed_native_receipt_never_rearms(self):
        admission, core_path, proof_file, proof, intent = self.retry_fixture(record_core=False)
        with self.assertRaisesRegex(ValueError, 'core_proof'):
            admission.reconcile_unsubmitted(proof, core_journal_directory=core_path, proof_file=proof_file)
        proof_file.write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError, 'evidence_changed'):
            admission.reconcile_unsubmitted(proof, core_journal_directory=core_path, proof_file=proof_file)
        with self.assertRaisesRegex(ValueError, 'previous_dispatch_unknown'):
            admission.mark_submitting(attempt=2, recovery_id=proof.recovery_id, dispatch_digest='b'*64)

    def test_concurrent_original_callers_share_capacity_and_one_submission(self):
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=2) as pool:
            admitted = list(pool.map(lambda _: self.prepare(), range(2)))
        self.assertEqual(1, len(resources._inventory(self.root)[0]))
        with ThreadPoolExecutor(max_workers=2) as pool:
            submissions = list(pool.map(lambda admission: admission.mark_submitting(), admitted))
        self.assertEqual([False, True], sorted(submissions))
        self.assertEqual(1, len(resources._inventory(self.root)[0]))

    def test_consumed_snapshot_is_original_full_census_and_local_only(self):
        admission = self.prepare(); admission.mark_submitting()
        self.calls.clear(); snapshot = admission.submission_snapshot()
        self.assertEqual([], self.calls)
        self.assertTrue(snapshot['census']['inventoryComplete'])
        self.assertEqual(BOOT, snapshot['hostBootId'])
        self.rows = [{'pid': 99}]  # A later incomplete observation is not adopted.
        self.assertEqual(snapshot, self.prepare().submission_snapshot())
        self.assertEqual([], self.calls)
        self.assertNotIn('token', repr(snapshot))

    def test_unknown_alias_capacity_counted_and_peer_route_proven(self):
        admission = self.prepare()
        admission.mark_submitting()
        with environments._LockedState(self.root) as locked:
            locked.state['reservations'][0]['resourceAliases'] = ['archlinux', 'renamed']
            locked.save()
        self.operation = str(uuid4())
        second = self.prepare()
        with second._journal().locked(deadline=second.deadline) as journal:
            plan = second._prepared(journal)['plan']
        self.assertEqual(2*GIB, plan['reservedMemoryBytes'])
        self.assertIn('peer', [item[1] for item in self.calls])

    def bookkeeping_fixture(self):
        import hashlib
        folder=Path(__file__).parent/'fixtures/resource_running_actor_before'
        raw=(folder/'public-measurement.json').read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['publicMeasurementSha256'],hashlib.sha256(raw).hexdigest())
        public=json.loads(raw);admission=self.prepare();original_operation=self.operation
        for memory in public['otherReservationMemoryBytes']:
            self.operation=str(uuid4());self.prepare(requested_memory_bytes=memory)
        self.operation=original_operation;admission.mark_submitting()
        with environments._LockedState(self.root) as locked:
            for row in locked.state['reservations']:
                if row['id']!=admission.reservation_identity['reservationId']:
                    row['allocationState']='running'
            locked.save()
        self.rows=[{**self.actor(),'sessionId':17,'uid':1000,'commandSha256':'a'*64,
                    'executableGeneration':[1]*9,'configuredMemoryBytes':public['ownActor']['configuredMemoryBytes']},
                   {'pid':18,'startTicks':888,'sessionId':18,'uid':1000,'commandSha256':'b'*64,
                    'executableGeneration':[1]*9,'configuredMemoryBytes':public['runningConfiguredMemoryBytes']-public['ownActor']['configuredMemoryBytes']}]
        original=self.observation
        def observed(target):
            value=original(target);value['physicalMemoryBytes']=public['physicalMemoryBytes']
            for index,row in enumerate(value['samples']):
                row['availableMemoryBytes']=public['minimumAvailableMemoryBytes']if index==0 else public['availableMemoryBytes']
            return value
        self.observation=observed
        return admission,public

    def test_whole_before_double_charges_actual_native_counts_RED_same_actor_once_GREEN(self):
        import hashlib,sys,types
        admission,public=self.bookkeeping_fixture();folder=Path(__file__).parent/'fixtures/resource_running_actor_before'
        raw=(folder/'readiness_resources.py.source').read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._resources_running_actor_before');before.__package__='agent_tools'
        with mock.patch.dict(sys.modules,{before.__name__:before}):
            exec(compile(raw,str(folder/'readiness_resources.py.source'),'exec'),before.__dict__)
            # Only the already-tested native observation boundary is controlled;
            # retained journal, reservation CAS and both admission algorithms run.
            before._sample=resources._sample
            old=before.ResourceAdmission(admission.root,admission.target,admission.machine_uuid,
                admission.operation_id,admission.directory,admission.credential_file,admission.deadline)
            with self.assertRaisesRegex(resources.vm_workflow.VmWorkflowError,'configured guest memory'):
                old.mark_running(self.actor())
        with admission._journal().locked(deadline=admission.deadline)as journal:self.assertIsNone(journal.lookup('running'))
        prior=copy.deepcopy(resources._inventory(self.root)[0]);identity=admission.reservation_identity
        with mock.patch.object(resources.environments,'reserve_environment',wraps=environments.reserve_environment)as reserve:
            result=admission.mark_running(self.actor())
        self.assertEqual('running',result['reservation']['allocationState']);request=reserve.call_args.args[1]
        self.assertEqual(public['runningConfiguredMemoryBytes'],request['measurement']['runningConfiguredMemoryBytes'])
        self.assertEqual(sum(public['otherReservationMemoryBytes'])+2*GIB,sum(row['memoryBytes']for row in request['runningAllocationMapping']))
        after=resources._inventory(self.root)[0]
        self.assertEqual([r for r in prior if r['id']!=identity['reservationId']],[r for r in after if r['id']!=identity['reservationId']])
        self.assertEqual(identity,admission.reservation_identity)
        self.assertEqual('running',admission.mark_running(self.actor())['reservation']['allocationState'])

    def test_running_binding_requires_both_journal_and_committed_inventory_after_client_loss(self):
        admission,public=self.bookkeeping_fixture();self.calls.clear()
        self.assertFalse(admission.running_binding(self.actor(),BOOT));self.assertEqual([],self.calls)
        with mock.patch.object(environments,'reserve_environment',side_effect=TimeoutError('controlled client loss before transition')):
            with self.assertRaises(TimeoutError):admission.mark_running(self.actor())
        with admission._journal().locked(deadline=admission.deadline)as journal:self.assertIsNotNone(journal.lookup('running'))
        self.calls.clear();self.assertFalse(admission.running_binding(self.actor(),BOOT));self.assertEqual([],self.calls)
        renewed=self.prepare();self.assertFalse(renewed.running_binding(self.actor(),BOOT))
        renewed.mark_running(self.actor());self.calls.clear()
        with mock.patch.object(resources,'_sample',side_effect=AssertionError('getter must remain local')):
            self.assertTrue(renewed.running_binding(self.actor(),BOOT))
            self.assertFalse(renewed.running_binding({'pid':self.actor()['pid'],'startTicks':self.actor()['startTicks']+1},BOOT))
            self.assertFalse(renewed.running_binding(self.actor(),str(uuid4())))
        self.assertEqual([],self.calls)

    def test_whole_getter_before_recreates_missing_metadata_RED_readonly_current_GREEN(self):
        import hashlib,sys,types
        admission,public=self.bookkeeping_fixture();admission.mark_running(self.actor())
        folder=Path(__file__).parent/'fixtures/resource_running_query_before';raw=(folder/'readiness_resources.py.source').read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._resource_running_query_before');before.__package__='agent_tools'
        with mock.patch.dict(sys.modules,{before.__name__:before}):
            exec(compile(raw,str(folder/'readiness_resources.py.source'),'exec'),before.__dict__)
            old=before.ResourceAdmission(admission.root,admission.target,admission.machine_uuid,
                admission.operation_id,admission.directory,admission.credential_file,admission.deadline)
            lock=admission.directory/'readiness.lock';lock.unlink()
            paths=lambda:set(path.relative_to(self.root)for path in self.root.rglob('*'))
            initial=paths();self.assertFalse(admission.running_binding(self.actor(),BOOT));self.assertEqual(initial,paths())
            self.assertTrue(old.running_binding(self.actor(),BOOT));self.assertTrue(lock.exists())
            directory=self.root/'.rag_index/native-environments';directory.rename(self.root/'retained-inventory')
            initial=paths();self.assertFalse(admission.running_binding(self.actor(),BOOT));self.assertEqual(initial,paths())
            self.assertFalse(old.running_binding(self.actor(),BOOT));self.assertTrue(directory.is_dir());self.assertTrue((directory/'lock').exists())

    def test_readonly_getter_retains_integrity_errors_and_deadline(self):
        from dataclasses import replace
        admission,public=self.bookkeeping_fixture();admission.mark_running(self.actor())
        with self.assertRaisesRegex(TimeoutError,'resource_deadline'):
            replace(admission,deadline=time.monotonic()-1).running_binding(self.actor(),BOOT)
        lock=admission.directory/'readiness.lock';original=lock.read_bytes();lock.write_bytes(b'UNRECOGNIZED BODY\n')
        with self.assertRaisesRegex(ValueError,'lock_integrity'):admission.running_binding(self.actor(),BOOT)
        lock.write_bytes(original)
        inventory=self.root/'.rag_index/native-environments/reservations.json';inventory.write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError,'inventory_integrity'):admission.running_binding(self.actor(),BOOT)
        inventory.unlink();initial=set(self.root.rglob('*'))
        self.assertFalse(admission.running_binding(self.actor(),BOOT));self.assertEqual(initial,set(self.root.rglob('*')))

    def test_running_binding_rejects_changed_or_unknown_original_inventory(self):
        admission,public=self.bookkeeping_fixture();admission.mark_running(self.actor())
        original=copy.deepcopy(resources._inventory(self.root)[0]);identity=admission.reservation_identity
        for key,value in [('allocationState','pending'),('activeJob','unknown'),('requestedMemoryBytes',3*GIB),('token','INERT_FOREIGN_TOKEN')]:
            with environments._LockedState(self.root)as locked:
                locked.state['reservations']=copy.deepcopy(original)
                own=next(row for row in locked.state['reservations']if row['id']==identity['reservationId']);own[key]=value;locked.save()
            with self.subTest(key=key):self.assertFalse(admission.running_binding(self.actor(),BOOT))
        with environments._LockedState(self.root)as locked:
            locked.state['reservations']=copy.deepcopy(original)
            own=next(row for row in locked.state['reservations']if row['id']==identity['reservationId']);own['activeJobEvidence']['reservationToken']='INERT_FOREIGN_TOKEN';locked.save()
        self.assertFalse(admission.running_binding(self.actor(),BOOT))
        with environments._LockedState(self.root)as locked:
            locked.state['reservations']=[row for row in original if row['id']!=identity['reservationId']];locked.save()
        self.assertFalse(admission.running_binding(self.actor(),BOOT))

    def test_running_projection_requires_exact_birth_and_configured_memory(self):
        admission,public=self.bookkeeping_fixture();original=copy.deepcopy(self.rows)
        for change in ('birth','memory','missing'):
            self.rows=copy.deepcopy(original)
            if change=='birth':self.rows[0]['startTicks']+=1
            elif change=='memory':self.rows[0]['configuredMemoryBytes']+=GIB
            else:self.rows=self.rows[1:]
            with self.subTest(change=change),self.assertRaisesRegex(ValueError,'actor_unobserved'):
                admission.mark_running(self.actor())
            with admission._journal().locked(deadline=admission.deadline)as journal:self.assertIsNone(journal.lookup('running'))
        self.rows=original
        # Pre-dispatch admission remains conservative; it never adopts an actor
        # merely because a matching VM now happens to be present.
        with admission._journal().locked(deadline=admission.deadline)as journal:prepared=admission._prepared(journal)
        with self.assertRaises(resources.vm_workflow.VmWorkflowError):admission._fresh(prepared)

    def test_running_projection_keeps_other_claims_headroom_and_pressure_limits(self):
        admission,public=self.bookkeeping_fixture();original=self.observation
        required=public['runningConfiguredMemoryBytes']+sum(public['otherReservationMemoryBytes'])+public['headroomBytes']
        for condition in ('capacity','available','pressure','boot'):
            def observed(target):
                value=original(target)
                if condition=='capacity':value['physicalMemoryBytes']=required-1
                elif condition=='available':
                    for row in value['samples']:row['availableMemoryBytes']=public['headroomBytes']-1
                elif condition=='pressure':
                    for row in value['samples']:row['psi']='critical';row['psiFullAvg10']=5.
                else:value['hostBootId']=str(uuid4())
                return value
            self.observation=observed
            with self.subTest(condition=condition),self.assertRaises((ValueError,resources.vm_workflow.VmWorkflowError)):
                admission.mark_running(self.actor())
            with admission._journal().locked(deadline=admission.deadline)as journal:self.assertIsNone(journal.lookup('running'))

    def test_original_actor_required_running_and_active_actor_blocks_release(self):
        admission = self.prepare()
        admission.mark_submitting()
        with self.assertRaisesRegex(ValueError, 'actor_unobserved'):
            admission.mark_running(self.actor())
        self.running()
        result = admission.mark_running(self.actor())
        self.assertEqual('running', result['reservation']['allocationState'])
        with self.assertRaisesRegex(ValueError, 'still_present'):
            admission.release_stopped(self.proof())
        self.rows = []
        bad = self.proof(); bad['guestJobsAbsent'] = False
        with self.assertRaisesRegex(ValueError, 'proof_required'):
            admission.release_stopped(bad)
        self.assertEqual('released', admission.release_stopped(self.proof())['state'])
        self.assertEqual([], resources._inventory(self.root)[0])
        self.assertEqual('released', admission.release_stopped(self.proof())['state'])

    def test_lost_release_ack_reconciles_original_positive_shutdown(self):
        admission = self.prepare(); admission.mark_submitting(); self.running()
        admission.mark_running(self.actor()); self.rows = []
        proof = self.proof()
        original = resources.readiness.RecoveryJournal.record
        def lost(journal, key, value):
            if key == 'released':
                raise OSError('inert lost terminal acknowledgement')
            return original(journal, key, value)
        with mock.patch.object(resources.readiness.RecoveryJournal, 'record', side_effect=lost, autospec=True):
            with self.assertRaises(OSError):
                admission.release_stopped(proof)
        self.assertEqual([], resources._inventory(self.root)[0])
        self.assertEqual('released', self.prepare().release_stopped(proof)['state'])

    def test_reboot_epoch_cannot_release_original_capacity(self):
        admission = self.prepare(); admission.mark_submitting(); self.running()
        admission.mark_running(self.actor()); self.rows = []
        original = self.observation
        def changed(target):
            value = original(target); value['hostBootId'] = str(uuid4()); return value
        self.observation = changed
        with self.assertRaisesRegex(ValueError, 'epoch_changed'):
            admission.release_stopped(self.proof())
        self.assertEqual(1, len(resources._inventory(self.root)[0]))

    def test_all_reservations_include_running_unknown_even_if_census_does_not(self):
        admission = self.prepare(); admission.mark_submitting(); self.running()
        admission.mark_running(self.actor())
        self.rows = []
        self.operation = str(uuid4())
        with self.assertRaises(environments.NativeEnvironmentError):
            self.prepare()  # Running mapping cannot be explained by live census.
        self.assertEqual(1, len(resources._inventory(self.root)[0]))

    def test_expired_deadline_and_conflicting_request_cannot_dispatch(self):
        with self.assertRaises(TimeoutError):
            self.prepare(deadline=time.monotonic()-1)
        self.prepare()
        with self.assertRaisesRegex(ValueError, 'admission_changed'):
            self.prepare(requested_memory_bytes=3*GIB)

    def test_inventory_race_refuses_reservation(self):
        native = resources.environments.reserve_environment
        def race(root, request):
            with environments._LockedState(root) as locked:
                locked.save()  # Even an empty new ledger changes its digest.
            return native(root, request)
        with mock.patch.object(resources.environments, 'reserve_environment', side_effect=race):
            with self.assertRaisesRegex(environments.NativeEnvironmentError, 'inventory changed'):
                self.prepare()
        self.assertEqual([], resources._inventory(self.root)[0])

    def test_generic_complete_saved_producer_causal_descriptor_qemu_red_green(self):
        fixture = census.ProcessCensusTests('runTest'); fixture.setUp()
        try:
            proc = fixture.proc
            (proc/'sys/kernel/random').mkdir(parents=True)
            (proc/'sys/kernel/random/boot_id').write_text(BOOT)
            (proc/'pressure').mkdir(); (proc/'pressure/memory').write_text('some avg10=0.00\nfull avg10=0.00\n')
            (proc/'vmstat').write_text('pswpin 0\npswpout 0\noom_kill 0\n')
            process = fixture.process(17, 'qemu-system-x86_64', '7', 777)
            (process/'cmdline').write_bytes(b'/proc/self/fd/7\0-m\0' + b'6144\0')
            before = old_census.RolePathTests().before('worker.before.source')
            self.assertEqual(0, before._host_capacity(proc_root=proc)['runningQemuCount'])
            target = resources.ResourceTarget(self.operation, 'archlinux', str(fixture.home/'new-owned-fixture'))
            value = fixture.run_program(producer.program(target, 'host-resources').decode())
            self.assertEqual(6*GIB, resources.facts.measurement(value)['runningConfiguredMemoryBytes'])
            self.assertEqual(17, value['vms'][0]['pid'])
            self.assertFalse((fixture.home/'new-owned-fixture').exists())
        finally:
            fixture.doCleanups()


class SecureObserverTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=Path('/tmp').resolve()); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.root.chmod(0o700)
        self.secret = 'INERT-private-test-password-9281'
        self.file = self.root/'credential.secret'; self.file.write_text(self.secret+'\n'); self.file.chmod(0o600)
        self.target = resources.ResourceTarget(str(uuid4()), 'archlinux', '/home/owner/new-fixture')
        admitted = mock.MagicMock(); self.admitted = admitted.__enter__.return_value
        guard = mock.MagicMock(); self.guard = guard.__enter__.return_value
        self.guard.config = object()
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(resources.transport, 'admitted_transport', return_value=admitted).start()
        mock.patch.object(resources.deploy.direct, 'Guard', return_value=guard).start()
        self.builder = mock.patch.object(resources.transport, 'build_ssh_argv', return_value=['FIXED-INERT-SSH']).start()
        self.runner = mock.patch.object(resources.transport, 'run_ssh').start()

    def invoke(self):
        return resources.observe(self.root, self.target, str(self.file), deadline=time.monotonic()+30)

    def test_secure_dispatch_keeps_password_out_of_command_and_source(self):
        dto = ResourceTests(); dto.rows = []
        value = dto.observation(self.target)
        self.runner.return_value = SimpleNamespace(returncode=0, stdout=json.dumps(value).encode(), stderr=b'')
        self.assertEqual(value, self.invoke())
        command = self.builder.call_args.kwargs['command']
        self.assertEqual(('sudo', '-S', '-p', '', '--', 'python3', '-I', '-B', '-c'), command[:9])
        self.assertNotIn(self.secret, repr(command))
        self.assertNotIn('\n', command[-1])
        self.assertTrue(command[-1].startswith('exec('))
        self.assertNotIn(self.secret, repr(self.builder.call_args))
        self.assertEqual((self.secret+'\n').encode(), self.runner.call_args.kwargs['input'])
        self.assertLessEqual(self.runner.call_args.kwargs['timeout'], 30)
        self.assertGreaterEqual(self.admitted.revalidate.call_count, 2)
        self.assertEqual([self.file], list(self.root.iterdir()))

    def test_echo_malformed_timeout_and_overflow_disclose_no_private_input(self):
        import subprocess
        import traceback
        failures = [SimpleNamespace(returncode=0, stdout=self.secret.encode(), stderr=b''),
                    SimpleNamespace(returncode=0, stdout=b'{malformed', stderr=b''),
                    SimpleNamespace(returncode=0, stdout=b'x'*262145, stderr=b''),
                    subprocess.TimeoutExpired(['fixed'], 1, output=self.secret.encode(), stderr=self.secret.encode())]
        for failure in failures:
            with self.subTest(kind=type(failure).__name__):
                self.runner.side_effect = failure if isinstance(failure, Exception) else None
                self.runner.return_value = failure
                try:
                    self.invoke()
                except ValueError as error:
                    self.assertEqual('resource_observation_unknown', str(error))
                    self.assertNotIn(self.secret, ''.join(traceback.format_exception(error)))
                else:
                    self.fail('unsafe reply was accepted')
        self.assertEqual([self.file], list(self.root.iterdir()))


if __name__ == '__main__':
    unittest.main()

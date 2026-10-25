"""Real private metadata admission; no native input or qualification claims."""
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
from contextlib import ExitStack
import unittest
from unittest import mock
from uuid import uuid4, UUID, uuid5

from PIL import Image

from agent_tools import private_inventory_lock as private
from agent_tools import readiness_tart_macos as backend_module
from agent_tools import readiness_tart_macos_registry as registry
from agent_tools import readiness_tart_macos_unlock as unlock
from agent_tools import readiness_tart_macos_unlock_material as material
from agent_tools import readiness_tart_macos_unlock_qualification as qualification
from agent_tools import readiness_tart_macos_unlock_observer as observer
from agent_tools.tests.test_readiness_tart_macos import binding


def identity(locked=True):
    bound = binding()
    return {'target': bound.target, 'machine': bound.machine, 'boot': '11234567-89ab-4def-8123-0123456789ab',
            'rawBoot': '11234567-89AB-4DEF-8123-0123456789AB', 'uid': bound.ordinary_uid,
            'principal': bound.ordinary_account, 'home': bound.ordinary_home,
            'agent': {'pid': 42, 'birth': 'darwin:100:50', 'uid': bound.ordinary_uid},
            'console': {'uid': bound.ordinary_uid, 'name': bound.ordinary_account, 'session': '101',
                        'onConsole': True, 'loginDone': True, 'locked': locked}, 'display': 'ready'}


@unittest.skipUnless(os.name == 'posix', 'actual private POSIX metadata')
class UnlockMaterialTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve(); self.root.chmod(0o700)
        self.directory = private.Directory(self.root); self.addCleanup(self.directory.close)
        self.operation = str(uuid4())

    def write(self, name, value):
        unlock._record(self.directory, name, value)

    def incident(self, operation=None, *, complete=True):
        operation = operation or self.operation
        original = {'schemaVersion': 1, 'operationId': operation, 'recipient': identity(),
                    'state': 'unknown_no_replay', 'sourceSha256': next(iter(material._ORIGINAL_PRODUCERS))}
        self.write('macos-unlock-' + operation + '.json', original)
        secret, submit = (str(uuid5(UUID(operation), phase)) for phase in ('secret', 'return'))
        self.write(secret + '.json', {'schemaVersion': 1, 'operationId': secret, 'bindingId': operation,
                                     'action': 'secret_input', 'state': 'unknown'})
        if complete:
            self.write('macos-unlock-password-' + secret + '.json',
                       {'operationId': secret, 'state': 'transport_complete_not_unlock_receipt'})
            self.write('macos-unlock-return-' + submit + '.json', {'operationId': submit, 'state': 'unknown_no_replay'})
        return original

    def backend(self):
        custody = object.__new__(registry.MacCustody)
        custody.binding = binding(); custody.lifecycle_root = self.root
        custody._operator = SimpleNamespace(guard=lambda: None)
        custody.guard = mock.Mock()
        backend = object.__new__(backend_module.MacTartBackend)
        backend.binding = custody.binding; backend.custody = custody
        return backend

    def live_proof(self, backend, operation, observation=None):
        """Unit-only typed native boundary; never a production qualification."""
        proof = object.__new__(observer.NativeObservation)
        proof._token = observer._TOKEN; proof._stack = ExitStack(); proof._custody = backend.custody
        proof._source = None; proof._holders = []; proof.operation = operation
        proof._observation = json.dumps(observation or identity(False)).encode()
        proof._terminal = json.dumps({'controlledNativeBoundary': True}).encode()
        proof.observer = observer.observer_id(operation); proof._closed = False; proof.raw_reply = b''
        return proof

    def test_new_uuid_cannot_ignore_original_unknown_even_with_empty_screen(self):
        self.incident()
        before = set(os.listdir(self.directory.fd))
        with self.assertRaisesRegex(qualification.QualificationBlocked, 'incident_unresolved'):
            material._new_incidents(self.directory, str(uuid4()), binding(), {'a' * 64})
        self.assertEqual(set(os.listdir(self.directory.fd)), before)

    def test_resolver_observes_same_original_append_only_then_fence_admits_new_operation(self):
        self.incident(); backend = self.backend()
        source = hashlib.sha256(Path(material.__file__).read_bytes()).hexdigest()
        with mock.patch.object(observer, 'reconcile', side_effect=lambda *a, **k: self.live_proof(backend, self.operation)) as probe:
            result = material.resolve_original(backend, self.operation, deadline=time.monotonic() + 5)
            self.assertEqual(result['state'], 'observed_unlocked'); self.assertEqual(probe.call_count, 1)
        path = self.root / ('macos-unlock-resolution-' + self.operation + '.json')
        before = (path.read_bytes(), path.stat().st_ino)
        with ExitStack() as stack:
            proof = self.live_proof(backend, self.operation); stack.callback(proof.close)
            material._new_incidents(self.directory, str(uuid4()), binding(), {self.operation: proof})
        with mock.patch.object(observer, 'reconcile', side_effect=lambda *a, **k: self.live_proof(backend, self.operation)) as repeat_probe:
            repeated = material.resolve_original(backend, self.operation, deadline=time.monotonic() + 5)
        self.assertEqual(repeat_probe.call_count, 1); self.assertEqual(repeated['state'], 'observed_unlocked')
        self.assertEqual((path.read_bytes(), path.stat().st_ino), before)

    def test_locked_or_wrong_account_never_creates_resolution(self):
        self.incident(); backend = self.backend()
        wrong = identity(False); wrong['console']['uid'] += 1
        for observation in (identity(), wrong):
            with self.subTest(observation=observation['console']['locked']):
                with mock.patch.object(observer, 'reconcile', side_effect=lambda *a, **k: self.live_proof(backend, self.operation, observation)), self.assertRaises((qualification.QualificationBlocked, unlock.UnlockBlocked)):
                    material.resolve_original(backend, self.operation, deadline=time.monotonic() + 5)
        self.assertFalse((self.root / ('macos-unlock-resolution-' + self.operation + '.json')).exists())

    def test_partial_original_cannot_be_resolved_or_hidden_by_new_uuid(self):
        self.incident(complete=False)
        with mock.patch.object(unlock, '_snapshot') as probe, self.assertRaises(qualification.QualificationBlocked):
            material.resolve_original(self.backend(), self.operation, deadline=time.monotonic() + 5)
        probe.assert_not_called()

    def test_original_replacement_during_independent_observation_blocks_resolution(self):
        self.incident(); backend = self.backend()
        def probe(*args, **kwargs):
            path = self.root / ('macos-unlock-' + self.operation + '.json')
            body = path.read_bytes(); path.unlink(); path.write_bytes(body); path.chmod(0o600)
            return self.live_proof(backend, self.operation)
        with mock.patch.object(observer, 'reconcile', side_effect=probe), self.assertRaisesRegex(qualification.QualificationBlocked, 'original_changed'):
            material.resolve_original(backend, self.operation, deadline=time.monotonic() + 5)

    def test_forged_local_unlocked_resolution_cannot_mint_native_fact_or_skip_recollection(self):
        self.incident(); backend = self.backend()
        forged = {'state': 'observed_unlocked', 'observerSourceSha256': hashlib.sha256(Path(material.__file__).read_bytes()).hexdigest(),
                  'observation': identity(False), 'operationId': self.operation}
        self.write('macos-unlock-resolution-' + self.operation + '.json', forged)
        with mock.patch.object(unlock, '_snapshot', return_value=identity(False)) as local_dto, self.assertRaisesRegex(qualification.QualificationBlocked, 'observer_unqualified'):
            material.resolve_original(backend, self.operation, deadline=time.monotonic() + 5)
        local_dto.assert_not_called()
        with self.assertRaisesRegex(qualification.QualificationBlocked, 'original_observer_required'):
            material._new_incidents(self.directory, str(uuid4()), binding(), {forged['observerSourceSha256']})

    def test_actual_unfixed_functions_accept_forged_disk_resolution_current_requires_live_remote_proof(self):
        self.incident(); source_sha = 'a' * 64
        path = Path(__file__).parent / 'fixtures/macos_unlock_resolution.before.source'
        scope = {name: getattr(material, name) for name in ('_need', '_ORIGINAL', '_original_records', '_read')}
        scope.update(unlock=unlock, deepcopy=deepcopy, os=os)
        exec(compile(path.read_bytes(), str(path), 'exec'), scope)
        records = material._original_records(self.directory, self.operation)
        fabricated = scope['_resolution'](records, self.operation, identity(False), binding(), source_sha)
        self.write('macos-unlock-resolution-' + self.operation + '.json', fabricated)
        # Actual private files and the retained complete unfixed functions.
        scope['_new_incidents'](self.directory, str(uuid4()), binding(), {source_sha})
        with self.assertRaisesRegex(qualification.QualificationBlocked, 'original_observer_required'):
            material._new_incidents(self.directory, str(uuid4()), binding(), {source_sha})

    def test_own_live_material_may_advance_partial_journal_but_not_replace_or_reuse_it(self):
        current = material._CurrentIncident(material._CURRENT_TOKEN, self.directory, self.operation, identity())
        self.incident(complete=False)
        material._new_incidents(self.directory, self.operation, binding(), set(), current)
        current.live = False
        with self.assertRaisesRegex(qualification.QualificationBlocked, 'material_closed'):
            material._new_incidents(self.directory, self.operation, binding(), set(), current)
        with self.assertRaisesRegex(qualification.QualificationBlocked, 'original_pending'):
            material._CurrentIncident(material._CURRENT_TOKEN, self.directory, self.operation, identity())

    def test_orphan_modifier_or_secret_journal_blocks_without_reading_body(self):
        for name in ('macos-unlock-modifier-unclassified.json', str(uuid4()) + '.json'):
            with self.subTest(name=name):
                path = self.root / name; path.write_bytes(b'PRIVATE-DO-NOT-PARSE'); path.chmod(0o600)
                with self.assertRaisesRegex(qualification.QualificationBlocked, 'orphan_incident_unresolved') as error:
                    material._new_incidents(self.directory, self.operation, binding(), set())
                self.assertNotIn('PRIVATE', str(error.exception)); path.unlink()

    def test_out_of_order_own_return_cannot_authorize_private_input(self):
        current = material._CurrentIncident(material._CURRENT_TOKEN, self.directory, self.operation, identity())
        original = {'schemaVersion': 1, 'operationId': self.operation, 'recipient': identity(),
                    'state': 'unknown_no_replay', 'sourceSha256': next(iter(material._ORIGINAL_PRODUCERS))}
        self.write('macos-unlock-' + self.operation + '.json', original)
        submit = str(uuid5(UUID(self.operation), 'return'))
        self.write('macos-unlock-return-' + submit + '.json', {'operationId': submit, 'state': 'unknown_no_replay'})
        with self.assertRaisesRegex(qualification.QualificationBlocked, 'original_phase_unresolved'):
            current.guard()

    def test_no_dto_or_historical_label_mints_native_material(self):
        with self.assertRaisesRegex(qualification.QualificationBlocked, 'native_case_required'):
            qualification.QualifiedUnlock(nativeQualified=True)
        with self.assertRaisesRegex(qualification.QualificationBlocked, 'custody_unqualified'):
            qualification.load({'nativeQualified': True})
        with self.assertRaisesRegex(qualification.QualificationBlocked, 'material_unqualified'):
            material._backend(SimpleNamespace(custody={'owned': True}))


class HistoricalProfileTests(unittest.TestCase):
    def records(self):
        operation, secret, submit = (str(uuid4()) for _ in range(3)); before = identity()
        before.pop('display'); after = identity(False)
        packet = {'facts': {'machine': after['machine'], 'boot': after['boot'], 'uid': after['uid'],
                           'account': after['principal'], 'home': after['home'], 'console': after['console'], 'display': 'ready'},
                  'agent': {'actor': {'pid': 42, 'birth': 'darwin:100:50'}, 'uid': after['uid'],
                            'principal': after['principal'], 'home': after['home'], 'python': binding().guest_python,
                            'rawBoot': after['rawBoot']}}
        values = {'plan': {'schemaVersion': 1, 'operationId': operation, 'fixtureId': 'controlled', 'baseline': 'public-empty.png',
                  'streamProducerSha256': qualification._HISTORICAL_STREAM, 'secretOperation': secret, 'submitOperation': submit,
                  'noCredentialBytesInPlan': True, 'actions': []},
                  'phase': {'operationId': operation, 'originalRun': 'controlled-run', 'recipient': before, 'state': 'unknown_no_replay'},
                  'password': {'operationId': secret, 'state': 'transport_complete_not_unlock_receipt'},
                  'returnIntent': {'operationId': submit, 'action': 'one_Return_existing_original_field', 'state': 'unknown'},
                  'returnComplete': {'operationId': submit, 'state': 'submitted_awaiting_independent_session'}, 'postProbe': packet,
                  'publicPreflight': {'operationId': operation, 'recipient': before, 'sourceSha256': hashlib.sha256(b'public source').hexdigest(),
                  'state': 'public_only_complete_secret_unsubmitted', 'simulatedMaximumAscii32EventGuards': 136, 'fastGuardSeconds': [.01] * 136}}
        output = io.BytesIO(); Image.new('RGB', (1024, 768)).save(output, format='PNG')
        return {**{key: json.dumps(value).encode() for key, value in values.items()}, 'source': b'public source', 'baseline': output.getvalue()}

    def test_historical_component_validation_returns_data_only_never_new_native_authority(self):
        records = self.records()
        with mock.patch.object(qualification, '_HISTORICAL_SOURCE', hashlib.sha256(records['source']).hexdigest()):
            result = qualification.historical_profile(records, binding(), 'controlled-run')
        self.assertEqual(result['authority'], 'historical_component_data_only')
        self.assertIs(result['newProducerQualified'], False)

    def test_wrong_original_account_or_missing_return_is_precise_and_private(self):
        records = self.records(); value = json.loads(records['postProbe']); value['facts']['console']['name'] = 'PRIVATE'
        records['postProbe'] = json.dumps(value).encode()
        with mock.patch.object(qualification, '_HISTORICAL_SOURCE', hashlib.sha256(records['source']).hexdigest()), self.assertRaises((qualification.QualificationBlocked, unlock.UnlockBlocked)) as error:
            qualification.historical_profile(records, binding(), 'controlled-run')
        self.assertNotIn('PRIVATE', str(error.exception))
        records = self.records(); records.pop('returnComplete')
        with self.assertRaises(qualification.QualificationBlocked):
            qualification.historical_profile(records, binding(), 'controlled-run')

    def test_duplicate_private_field_is_not_disclosed(self):
        with self.assertRaisesRegex(qualification.QualificationBlocked, '^macos_unlock_qualification_invalid$') as error:
            qualification._json(b'{"private":"NEVER","private":"ECHO"}')
        self.assertNotIn('NEVER', str(error.exception)); self.assertNotIn('ECHO', str(error.exception))


if __name__ == '__main__':
    unittest.main()

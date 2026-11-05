"""Owned causal controls, no real VM/SSH/lease/capture scenario.

All effectful primitives target owned temporary files. The retained component
schema fixture projects protected principals; source-owned policy roots and the
original-proof digest are changed ONLY in an isolated control module. This does
not seal native authority or turn failed0e75/statuse96 into a valid new boot.
"""
import ast
import base64
import copy
import hashlib
import json
import io
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).parent / 'fixtures/android_poststart_current_authority'
CORE_SHA = '2cb37a86cc2f986aa6bb03652ab3f827bba16e6b3c7061348a451a0f0912d73f'
CONTROL_SHA = '2813cb6a54ac9beb74d2016a2387f31d2323e4a80b7d2f480d5ee83870942e38'
ADAPTER_CONTROL_SHA = '51b3ed12704660b622604ffafefe9bd308c3d4ca013e873eabaee694201f769e'


def captured(path, expected, identity):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('owned_control_source_changed:' + path.name)
    value = types.ModuleType(identity)
    value.__file__ = str(path)
    exec(compile(raw, str(path), 'exec', dont_inherit=True), value.__dict__)
    return value


if os.name == 'posix':
    _fixture = captured(HERE / 'control_fixture.source', CONTROL_SHA, 'owned_current_control_fixture')
    Case, canonical, sha, pin = _fixture.Case, _fixture.canonical, _fixture.sha, _fixture.pin
else:
    Case = None


EXPECTED_SOURCE_SHAS = {'custody': 'a04c3282787e938c32a09ad3ac5a54d8499e60a766977778591ef72ef388dcae', 'retirement': 'b80edb795461815d1565148dc1eb32966c4de3aa6ad0f4bab1f53a378f537e31', 'continuity': '9e7c099de26239ac70711687a512d689e451fb0aca42627fd362e03065784589', 'bundle': 'e218c1fc862eab2a5668da970b8d642fa3254fb2ff822ab4945f23ae787f4372', 'adapter': '51b3ed12704660b622604ffafefe9bd308c3d4ca013e873eabaee694201f769e', 'renderer': '334d4b006be08bacecab845137393953462d39632e02b988608d5758e1403b3f'}
BEFORE_SLICE_SHA = '9c7336b56de1e16187336cb9e0939980b0b48dae8a3bc49235d929314b25b2ff'


def module(source_path=None, expected_sha=None):
    # Default execution authority is the actual canonical target, never the
    # frozen current fixture. Copy its verified bytes to a real owned file so
    # OUT/sources resolves only to these six held-byte test inputs. The canonical
    # template itself has SOURCE_BINDING=None and is never executed as if its
    # __file__ pointed at private/native evidence.
    if source_path is None and os.environ.get('VPN_CONTROL_DUAL_BEFORE') == 'kernel':
        source_path = HERE / 'dual_authority.before-kernel-envelope.source'
        expected_sha = '2e4e05e1986b5494865de209ebefde449bc4d65ce1b32f63bab1c39f9c8c0f9a'
    if source_path is None and os.environ.get('VPN_CONTROL_DUAL_BEFORE') == 'budget':
        source_path = HERE / 'dual_authority.before-wave-budget.source'
        expected_sha = 'af43dae1dfe34e17d624b7a3c1a51f6260eb1b005ffe5b7af088d97c6ee11710'
    if source_path is None and os.environ.get('VPN_CONTROL_DUAL_BEFORE') == 'waves':
        source_path = HERE / 'dual_authority.before-wave-absence.source'
        expected_sha = '27bbfd1b6c35f9b62e2a960aa39e6d51e54e09d3c6f6963d7028ae247050b2f8'
    if source_path is None and os.environ.get('VPN_CONTROL_DUAL_BEFORE') == 'closing':
        source_path = HERE / 'dual_authority.before-closing.source'
        expected_sha = '51766ba14145261f6321667459e55ee4f70c0aed281f64f1d0a0c8c32125f1bc'
    source_path = ROOT / 'agent_tools/android_poststart_current_authority.py' if source_path is None else source_path
    expected_sha = CORE_SHA if expected_sha is None else expected_sha
    raw = source_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        raise ValueError('owned_control_canonical_template_changed')
    temporary = tempfile.TemporaryDirectory(prefix='android-current-source-control-')
    directory = Path(temporary.name).resolve()
    directory.chmod(0o700)
    try:
        owned = directory / 'android_poststart_current_authority.py'
        with owned.open('xb') as stream:
            stream.write(raw)
        owned.chmod(0o600)
        (directory / 'sources').mkdir(mode=0o700)
        for role, expected in EXPECTED_SOURCE_SHAS.items():
            captured_raw = (HERE / 'sources' / (role + '.source')).read_bytes()
            if hashlib.sha256(captured_raw).hexdigest() != expected:
                raise ValueError('owned_control_materialized_source_changed:' + role)
            destination = directory / 'sources' / (role + '.source')
            with destination.open('xb') as stream:
                stream.write(captured_raw)
            destination.chmod(0o600)
        value = captured(owned, expected_sha, 'isolated_owned_dual_current_control')
        # Explicit fixture policy/source seam: unchanged source owns native93ff/
        # 92f hashes; the isolated owned namespace uses projected pure adapter
        # bytes and its real temporary admitted-proof checksum. No authority.
        value.SOURCE_SHAS = dict(value.SOURCE_SHAS, adapter=ADAPTER_CONTROL_SHA)
        value._owned_materialization = temporary
        value._canonical_template = source_path
        value._canonical_template_sha256 = expected_sha
        return value
    except BaseException:
        temporary.cleanup()
        raise


@unittest.skipUnless(os.name == 'posix', 'POSIX real descriptor custody and generated lease primitive')


class DualCurrentControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.core = module()
        self.addCleanup(self.core._owned_materialization.cleanup)
        self.core.POLICY_KIND = 'android-poststart-current-owned-control-policy'
        self.case = Case(self.core, self.root)
        self.core.ORIGINAL_PROOF_SHA = sha(canonical(self.case.original))
        self.core.SOURCE_BINDING = self.case.binding

    def context(self, mode='local-closing'):
        self.core.SOURCE_BINDING['mode'] = mode
        value = self.core.build_context(self.case.runtime() if mode == 'remote-live' else None)
        self.addCleanup(value.close)
        return value

    def test_captured_helper_has_truthful_file_identity_and_no_ssh_authority(self):
        canonical_path = ROOT / 'agent_tools/android_poststart_current_authority.py'
        materialized_path = Path(self.core.__file__)
        self.assertEqual(self.core._canonical_template, canonical_path)
        self.assertEqual(self.core._canonical_template_sha256, CORE_SHA)
        self.assertNotEqual(materialized_path, canonical_path)
        self.assertTrue(materialized_path.is_file())
        self.assertEqual(materialized_path.read_bytes(), canonical_path.read_bytes())
        self.assertEqual(sha(canonical_path.read_bytes()), CORE_SHA)
        canonical_tree = ast.parse(canonical_path.read_bytes())
        materialized_tree = ast.parse(materialized_path.read_bytes())
        for name in ('load_parts', 'build_context', 'CurrentContext'):
            original = next(node for node in canonical_tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name == name)
            copied = next(node for node in materialized_tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name == name)
            self.assertEqual(ast.dump(copied, include_attributes=False), ast.dump(original, include_attributes=False))
        self.assertEqual(self.core.build_context.__code__.co_filename, str(materialized_path))
        for role, expected in EXPECTED_SOURCE_SHAS.items():
            copied_path = materialized_path.parent / 'sources' / (role + '.source')
            self.assertEqual(sha(copied_path.read_bytes()), expected)
            self.assertEqual(copied_path.read_bytes(), (HERE / 'sources' / (role + '.source')).read_bytes())
        retirement = _fixture.CAPTURED_RETIREMENT
        self.assertEqual(Path(retirement.__file__), HERE / 'sources/retirement.source')
        helper_globals = _fixture.ComponentTerminalHistoryTest.release_fixture.__globals__
        self.assertIs(helper_globals['retirement'], retirement)
        self.assertEqual(Path(helper_globals['__file__']), HERE / 'component_test_helper.captured.source')
        self.assertEqual(sha(Path(retirement.__file__).read_bytes()), self.core.RETIREMENT_SHA)
        with self.assertRaisesRegex(AssertionError, 'owned_control_forbidden_ssh_dependency'):
            retirement.ssh_transport.run_ssh

    def test_actual_adapter_current_relation_new_boot_qualified_branch(self):
        context = self.context()
        current = context.attach(self.case.current)
        original = copy.deepcopy(self.case.original)
        handler = context.adapter.current_relation if os.environ.get('VPN_CONTROL_DUAL_BEFORE') == 'adapter' else context.current_relation
        result = handler(original, current)
        self.assertEqual(result[self.core.AUTHORITY_FIELD], context.identity)
        self.assertEqual(self.case.original, original)
        self.assertEqual(result['componentProducer']['result']['controllerId'], self.case.owner)
        self.assertEqual(result['componentProducer']['rows'][0]['name'], 'admission.json')
        self.assertEqual(context.adapter_audit['globalsDelta'], ['retirement'])
        self.assertTrue(context.adapter_audit['allOtherGlobalsSameObjects'])

    def test_actual_primitive_fresh_current_branch_captures_owned_original_inode(self):
        context = self.context()
        current = context.attach(self.case.current)
        before = copy.deepcopy(self.case.original)
        original_inode = self.case.lease.stat().st_ino
        handler = context.legacy.release_component_fenced if os.environ.get('VPN_CONTROL_DUAL_BEFORE') == 'primitive' else context.primitive
        def fresh():
            self.assertEqual(sha(self.case.lease.read_bytes()), self.case.lease_pin['sha256'])
            return copy.deepcopy(current)
        result = handler(self.case.lease, self.case.lease_pin, self.case.original, self.case.correlation,
                         fresh, 'local-original', self.case.remote)
        self.assertTrue(result['leaseReleased'])
        captured = Path(result['retiredEvidence']['path'])
        self.assertEqual(captured.stat().st_ino, original_inode)
        self.assertEqual(sha(captured.read_bytes()), self.case.lease_pin['sha256'])
        self.assertEqual(self.case.original, before)
        self.assertFalse(self.case.lease.exists())
        self.assertEqual(result['originalOutcome'], 'unknown')
        self.assertFalse(result['replayAllowed'])
        self.assertEqual(context.primitive_audit['globalsDelta'], ['validate_component_retained_proof'])

    def test_original_legacy_validation_and_function_globals_unchanged(self):
        context = self.context()
        original = copy.deepcopy(self.case.original)
        self.assertEqual(context.validate(original), context.original_validator(original))
        self.assertEqual(context.legacy.validate_component_retained_proof, context.original_validator)
        self.assertEqual(context.legacy.validate_component_certificate(original['componentProducer'],
                         original['componentCertificatePin'])['facts']['guestBootId'], self.core.OLD_BOOT)
        self.assertEqual(sha((HERE / 'sources/retirement.source').read_bytes()), self.core.RETIREMENT_SHA)
        current = context.attach(self.case.current)
        with self.assertRaisesRegex(ValueError, 'component_certificate_guest_invalid'):
            context.original_validator(current)
        self.assertEqual(original, self.case.original)

    def test_unsealed_source_binding_refuses_before_evidence_or_guard(self):
        core = module()
        self.addCleanup(core._owned_materialization.cleanup)
        self.assertIsNone(core.SOURCE_BINDING)
        with mock.patch.object(core, 'load_parts', side_effect=AssertionError('source loader reached')), \
             mock.patch.object(core, 'CurrentContext', side_effect=AssertionError('evidence context reached')), \
             mock.patch.object(Path, 'read_bytes', side_effect=AssertionError('source/private bytes reached')), \
             mock.patch.object(os, 'open', side_effect=AssertionError('source/private descriptor reached')):
            with self.assertRaisesRegex(ValueError, 'current_authority_source_binding_unsealed'):
                core.build_context({'ROOT': 'caller-authored'})

    def test_missing_unknown_or_changed_authority_never_returns_unchecked_dto(self):
        context = self.context()
        with self.assertRaisesRegex(ValueError, 'component_certificate_guest_invalid'):
            context.validate(self.case.current)
        current = context.attach(self.case.current)
        for field, changed in [('kind', 'caller-current-success'), ('newGuestBootId', self.core.OLD_BOOT),
                               ('releaseGranted', True), ('authoritySha256', '0' * 64)]:
            candidate = copy.deepcopy(current)
            candidate[self.core.AUTHORITY_FIELD][field] = changed
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'current_authority_missing_unknown_or_changed'):
                context.validate(candidate)
        malformed = {self.core.AUTHORITY_FIELD: context.identity, 'ok': True}
        with self.assertRaises(ValueError):
            context.validate(malformed)

    def test_real_app_recipient_change_refuses_after_full_typed_validation(self):
        context = self.context()
        current = context.attach(self.case.current)
        row = next(item for item in current['componentProducer']['rows'] if item['name'] == 'admission.json')
        certificate = json.loads(base64.b64decode(row['rawBase64']))
        certificate['appProcess']['pid'] += 1
        raw = canonical(certificate)
        row['rawBase64'] = base64.b64encode(raw).decode()
        row['bytes'] = len(raw)
        row['sha256'] = sha(raw)
        row['pin']['sha256'] = sha(raw)
        row['pin']['generation'][6] = len(raw)
        current['componentProducer']['result']['certificatePin'] = copy.deepcopy(row['pin'])
        current['componentCertificatePin'] = copy.deepcopy(row['pin'])
        current['files']['component-admission.json'].update(generation=row['pin']['generation'], sha256=sha(raw))
        with self.assertRaisesRegex(ValueError, 'current_authority_certificate_recipient_changed'):
            context.validate(current)

    def test_shared_collector_output_path_refuses(self):
        context = self.context()
        current = context.attach(self.case.current)
        current['componentProducer']['result']['certificatePath'] = self.core.BACKEND_ROOT + '/android-installer-component-baseline-foreign/current-owner-admission/admission.json'
        with self.assertRaisesRegex(ValueError, 'current_authority_certificate_output_map_changed'):
            context.validate(current)

    def test_source_owned_four_correlation_map_cannot_be_replaced(self):
        self.core.SOURCE_BINDING['outputContract']['rootDirectory'] = self.core.BACKEND_ROOT
        with self.assertRaisesRegex(ValueError, 'current_authority_output_map_unqualified'):
            self.core.build_context()

    def test_failed_start_and_frozen_failed_producers_never_authorize_new_boot(self):
        original = copy.deepcopy(self.core.SOURCE_BINDING)
        self.core.SOURCE_BINDING['startOperationId'] = self.core.FAILED_START
        with self.assertRaisesRegex(ValueError, 'current_authority_failed_or_shared_start'):
            self.core.build_context()
        self.core.SOURCE_BINDING = original
        for source in self.core.FAILED_SOURCE_SHAS:
            self.core.SOURCE_BINDING['captures']['status']['producerSourceSha256'] = source
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, 'current_authority_capture_incomplete'):
                self.core.build_context()

    def test_incomplete_capture_and_same_byte_inode_exchange_block_current(self):
        context = self.context()
        current = context.attach(self.case.current)
        path = self.root / 'closing.stdout'
        replacement = self.root / 'foreign-same-bytes'
        replacement.write_bytes(path.read_bytes())
        replacement.chmod(0o600)
        os.replace(replacement, path)
        with self.assertRaisesRegex(ValueError, 'local_capture_held_input_changed'):
            context.validate(current)

    def test_stale_current_capture_refuses_without_replay(self):
        context = self.context()
        current = context.attach(self.case.current)
        future = max(row['finishedAtNs'] for row in context.evidence.captures.values()) + self.core.MAX_AGE_NS + 1
        with mock.patch.object(self.core.time, 'time_ns', return_value=future):
            with self.assertRaisesRegex(ValueError, 'current_authority_capture_stale'):
                context.validate(current)

    def test_full_runtime_inventory_required(self):
        self.core.SOURCE_BINDING['runtimeRefs'].pop('component_release_current1e15_effect_plane_guard')
        with self.assertRaisesRegex(ValueError, 'current_authority_runtime_scope_incomplete'):
            self.core.build_context()

    def test_remote_live_checks_real_owned_guard_and_whole_source_consumers(self):
        context = self.context('remote-live')
        current = context.attach(self.case.current)
        self.assertEqual(context.validate(current), current)
        state = json.loads(self.case.control.read_bytes())
        state['complete'] = False
        self.case.control.write_bytes(canonical(state))
        with self.assertRaisesRegex(ValueError, 'owned_control_visibility_unknown'):
            context.validate(current)

    def test_runtime_body_and_global_root_or_constructor_consumer_drift_refuse(self):
        context = self.context('remote-live')
        current = context.attach(self.case.current)
        namespace = context.native
        old_root = namespace['ROOT']
        namespace['ROOT'] = Path('/caller/global-root-alias')
        with self.assertRaisesRegex(ValueError, 'current_authority_runtime_globals_changed'):
            context.validate(current)
        namespace['ROOT'] = old_root
        original = namespace['component_release_current1e15_effect_plane_guard']
        namespace['component_release_current1e15_effect_plane_guard'] = lambda: None
        with self.assertRaisesRegex(ValueError, 'current_authority_runtime_code_changed'):
            context.validate(current)
        namespace['component_release_current1e15_effect_plane_guard'] = original
        namespace['bundle'] = object()
        with self.assertRaisesRegex(ValueError, 'current_authority_routing_runtime_substituted'):
            context.validate(current)

    def test_local_closing_full_results_refuse_missing_malformed_unknown_and_physical_drift(self):
        good = copy.deepcopy(self.case.closing)
        changes = []
        def changed(name, mutate):
            value = copy.deepcopy(good);mutate(value);changes.append((name, value))
        changed('labels-only', lambda value: (value.pop('effectPlaneResults'), value.pop('physical')))
        changed('missing-plane', lambda value: value['effectPlaneResults'].pop('CURRENT1E15_EFFECT_PLANE_FIXED'))
        changed('malformed-raw', lambda value: value['effectPlaneResults']['EFFECT_PLANE_FIXED'].update(procRawRecords=None))
        changed('incomplete-pass', lambda value: value['effectPlaneResults']['EFFECT_PLANE_FIXED']['workerPasses'].pop())
        changed('unknown-visibility', lambda value: value['effectPlaneResults']['EFFECT_PLANE_FIXED']['workerPasses'][0].update(
            errors=[{'pid': 501, 'errno': 13, 'closingErrno': None, 'state': 'unknown'}], censusComplete=False))
        changed('raw-hash', lambda value: value['effectPlaneResults']['CURRENT1E15_EFFECT_PLANE_FIXED']['procRawRecords'][0].update(sha256='0' * 64))
        changed('boundary-pin', lambda value: value['effectPlaneResults']['EFFECT_PLANE_FIXED']['passes'][1][0]['generation'].__setitem__(8, 123))
        changed('host-boot', lambda value: value['effectPlaneResults']['CURRENT1E15_EFFECT_PLANE_FIXED']['workerPasses'][0].update(bootId=self.core.OLD_BOOT))
        changed('account-recipient', lambda value: value['physical']['account'].update(euid=1000))
        changed('guest-frame', lambda value: value['physical']['after']['generation']['device'].update(guestBootId=self.core.OLD_BOOT))
        changed('app-frame', lambda value: value['physical']['after']['appProcess'].update(pid=123456))
        for name, value in changes:
            with self.subTest(name=name):
                self.case.replace_closing(value)
                with self.assertRaisesRegex(ValueError, '^current_authority_'):
                    context = self.core.build_context()
                    context.close()
        self.case.replace_closing(good)
        context = self.context()
        self.assertEqual(context.validate(context.attach(self.case.current))['componentProducer']['result']['controllerId'], self.case.owner)

    def test_local_closing_guard_replays_source_raw_and_physical_relations(self):
        context = self.context()
        good = copy.deepcopy(context.closing)
        original_tables = copy.deepcopy(self.case.tables)
        for name in ('source', 'raw', 'physical'):
            with self.subTest(name=name):
                context.closing = copy.deepcopy(good)
                context.effect_fixed = copy.deepcopy(original_tables)
                if name == 'source':
                    context.effect_fixed['EFFECT_PLANE_FIXED']['validatorSource'] += '\n# source drift\n'
                elif name == 'raw':
                    context.closing['effectPlaneResults']['EFFECT_PLANE_FIXED']['procRawRecords'][0]['sha256'] = '0' * 64
                else:
                    context.closing['physical']['after']['controllerId'] = str(__import__('uuid').uuid4())
                with self.assertRaisesRegex(ValueError, '^current_authority_'):
                    context.guard()
        context.closing = good
        context.effect_fixed = original_tables
        context.guard()

    def test_unchanged_current1e15_valid_late_identity_passes_full_closing(self):
        directory = self.root / 'actual-late-processor';directory.mkdir(mode=0o700)
        tables, records = self.case.plane_module.make(directory, self.case.lease, self.core.BACKEND_ROOT,
                                                      self.case.host['bootId'], late=True)
        self.assertEqual(tables, self.case.tables)
        scan = records['CURRENT1E15_EFFECT_PLANE_FIXED']['workerPasses'][0]
        self.assertEqual(scan['newPids'], [502])
        self.assertEqual(scan['unresolvedNewPids'], [])
        self.assertEqual(scan['lateIdentities'][0]['pid'], 502)
        self.assertEqual(scan['lateClosingIdentities'][0]['pid'], 502)
        closing = copy.deepcopy(self.case.closing);closing['effectPlaneResults'] = records
        self.case.replace_closing(closing)
        context = self.context()
        self.assertEqual(context.closing_projection['planes']['CURRENT1E15_EFFECT_PLANE_FIXED']['projectedCounts'],
                         [{'python': 0, 'sudo': 0}, {'python': 0, 'sudo': 0}])

    def test_intermediate_wave_reappearance_of_positive_absence_refuses(self):
        directory = self.root / 'actual-wave-absence';directory.mkdir(mode=0o700)
        tables, records = self.case.plane_module.make(directory, self.case.lease, self.core.BACKEND_ROOT,
                                                      self.case.host['bootId'], wave_absent=True)
        self.assertEqual(tables, self.case.tables)
        record = records['EFFECT_PLANE_FIXED']
        self.assertEqual(record['workerPasses'][0]['resolved'],
                         [{'pid': 501, 'errno': 2, 'closingErrno': 2, 'state': 'rechecked-absent'}])
        self.assertEqual(len(record['censusWaves'][0]['waves']), 2)
        closing = copy.deepcopy(self.case.closing);closing['effectPlaneResults'] = records
        self.case.replace_closing(closing)
        context = self.core.build_context();context.close()
        bad = copy.deepcopy(closing)
        first = bad['effectPlaneResults']['EFFECT_PLANE_FIXED']['censusWaves'][0]['waves'][0]
        first['closingPids'] = sorted(first['closingPids'] + [501])
        self.case.replace_closing(bad)
        with self.assertRaisesRegex(ValueError, 'current_authority_plane_waves_invalid'):
            context = self.core.build_context();context.close()

    def test_current9da_cumulative_raw_budget_is_replayed_before_closing_can_admit(self):
        # This source-shaped protocol control is deliberately impossible for a
        # successfully completed actual4b1e scanner: its second pass exceeds the
        # original8MiB budget. The unchanged projector otherwise accepts every
        # hash-only nonmatching prefix, so the guard relation must reject it.
        context = self.context()
        fixed = copy.deepcopy(self.case.tables['EFFECT_PLANE_FIXED'])
        record = copy.deepcopy(self.case.plane_records['EFFECT_PLANE_FIXED'])
        fixed['binding']['expectedRootArgvBase64'] = base64.b64encode(b'python' + bytes([0]) + b'x' * 3712).decode()
        record['binding'] = copy.deepcopy(fixed['binding'])
        bootrow = copy.deepcopy(record['procRawRecords'][0])
        raw = [];scans = [];waves = [];pids = list(range(1, 1201))
        prefix_sha = sha(b'q' * 3720)
        for _ in range(2):
            raw.append(copy.deepcopy(bootrow));begin = len(raw)
            for pid in pids:
                row = copy.deepcopy(bootrow)
                row.update(pid=pid, name='cmdline', bytes=3720, sha256=prefix_sha,
                           readComplete=False, rawCaptured=False, rawBase64=None)
                raw.append(row)
            end = len(raw);raw.append(copy.deepcopy(bootrow))
            scan = {'matches': [], 'errors': [], 'resolved': [], 'enumeratedPids': pids[:],
                    'closingPids': pids[:], 'newPids': [], 'enumeratedCount': len(pids), 'readCount': len(pids),
                    'bootId': self.case.host['bootId'], 'closingBootId': self.case.host['bootId'],
                    'censusComplete': True, 'processAdopted': False}
            scans.append(scan)
            waves.append({'openingPids': pids[:], 'waves': [{'number': 0, 'pendingPids': pids[:],
                'readPids': pids[:], 'rawBegin': begin, 'rawEnd': end, 'closingPids': pids[:],
                'newPids': [], 'enumeratedPids': pids[:]}], 'matches': [], 'errors': [], 'resolved': [],
                'state': 'complete', 'bootId': self.case.host['bootId'], 'closingBootId': self.case.host['bootId'],
                'rawBytes': sum(row['bytes'] for row in raw)})
        record.update(procRawRecords=raw, workerPasses=scans, censusWaves=waves)
        scope = {'ast': ast, 'base64': base64, 'hashlib': hashlib, 'json': json,
                 're': self.core.re, 'stat': self.core.stat, 'bundle': context.adapter.bundle,
                 'PROCESS_SOURCE': fixed['processSource']}
        exec(compile(fixed['validatorSource'], '<unchanged23e-projector-budget-control>', 'exec'), scope)
        self.assertEqual(scope['validate_workers'](raw, scans, fixed['binding']),
                         [{'python': 0, 'sudo': 0}, {'python': 0, 'sudo': 0}])
        self.assertGreater(waves[-1]['rawBytes'], 8 * 1024 * 1024)
        self.assertLess(len(canonical(record)), 16 * 1024 * 1024)
        with self.assertRaisesRegex(ValueError, 'current_authority_plane_waves_invalid'):
            self.core.validate_effect_plane('EFFECT_PLANE_FIXED', fixed, record,
                                           self.case.host['bootId'], context.adapter.bundle)

    def actual_kernel_probe(self, name, drift=None):
        fixture = captured(HERE / 'kernel_fixture.source', '9bd781eba5877d4ff8e7802aeee5ab01ac99dd09ca7d02b087e3303fa737d296', 'actual_authentic_kernel_boundary_fixture')
        return fixture.Probe(self.core, self.case, self.root / name, drift=drift)

    def test_actual334_kernel_full_document_composes_with_current_generation_caller(self):
        probe = self.actual_kernel_probe('actual334-positive')
        original_function = probe.guard_function
        original_code = original_function.__code__
        probe.context.runtime_guard()
        self.assertEqual(probe.reads, 2)
        self.assertIs(probe.namespace['poststart_kernel_guard'], original_function)
        self.assertIs(probe.guard_function.__code__, original_code)
        template = (HERE / 'qualification-template.authentic.source').read_text()
        node = next(node for node in ast.parse(template).body if isinstance(node, ast.FunctionDef) and node.name == 'poststart_kernel_guard')
        self.assertEqual(probe.guard_source, (ast.get_source_segment(template, node) + '\n').encode())
        self.assertEqual(probe.guard_function.__code__.co_filename, str(probe.guard_path))

    def test_actual334_kernel_refuses_full_document_only_closing_drift(self):
        probe = self.actual_kernel_probe('actual334-closing-drift', 'closing-document')
        with self.assertRaisesRegex(ValueError, 'poststart_current_generation_changed'):
            probe.context.runtime_guard()
        self.assertEqual(probe.reads, 2)

    def test_actual334_kernel_first_generation_drift_refuses_before_plane_checks(self):
        probe = self.actual_kernel_probe('actual334-first-generation', 'first-generation')
        with self.assertRaisesRegex(ValueError, 'current_authority_current_physical_changed'):
            probe.context.runtime_guard()
        self.assertEqual(probe.reads, 1)

    def test_actual_primitive_cpython_slice_constants_have_finite_signature(self):
        core = self.core
        if os.environ.get('VPN_CONTROL_DUAL_BEFORE') == 'slice':
            core = module(HERE / 'dual_authority.before-slice.source', BEFORE_SLICE_SHA)
            self.addCleanup(core._owned_materialization.cleanup)
        primitive = core.load_parts()[2].retirement.release_component_fenced
        signature = core.code_signature(primitive.__code__)
        self.assertEqual(len(signature), 64)
        self.assertEqual(signature, core.code_signature(primitive.__code__))


class CollectionPortabilityControls(unittest.TestCase):
    def test_non_posix_collection_skips_each_test_before_captured_native_import(self):
        # Controlled collection probe, not a claim of a native Windows run. Only
        # the two literal POSIX gates are made false. pathlib/os remain native
        # to this interpreter; any forbidden source import fails immediately.
        tree = ast.parse(Path(__file__).read_bytes())
        class Gates(ast.NodeTransformer):
            count = 0
            def visit_Compare(self, node):
                self.generic_visit(node)
                if (len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq)
                        and isinstance(node.left, ast.Attribute) and node.left.attr == 'name'
                        and isinstance(node.left.value, ast.Name) and node.left.value.id == 'os'
                        and len(node.comparators) == 1 and isinstance(node.comparators[0], ast.Constant)
                        and node.comparators[0].value == 'posix'):
                    self.count += 1
                    return ast.copy_location(ast.Constant(False), node)
                return node
        gates = Gates()
        tree = ast.fix_missing_locations(gates.visit(tree))
        self.assertEqual(gates.count, 2)
        original_import = __import__
        def forbid_native(name, globals=None, locals=None, fromlist=(), level=0):
            if name in {'fcntl', 'pwd'} or name == 'agent_tools' or name.startswith('agent_tools.'):
                raise AssertionError('non_posix_collection_reached_native_source:' + name)
            return original_import(name, globals, locals, fromlist, level)
        import builtins
        scope = {'__file__': __file__, '__name__': 'owned_non_posix_collection_probe',
                 '__builtins__': dict(vars(builtins), __import__=forbid_native)}
        exec(compile(tree, __file__, 'exec', dont_inherit=True), scope)
        self.assertIsNone(scope['Case'])
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(scope['DualCurrentControls'])
        expected = suite.countTestCases()
        self.assertEqual(expected, 24)
        result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
        self.assertEqual(result.testsRun, expected)
        self.assertEqual(len(result.skipped), expected)
        self.assertTrue(result.wasSuccessful())


if __name__ == '__main__':
    unittest.main()

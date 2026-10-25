"""Source-qualified original phase endings, never historical GUI success."""
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import stat
from types import ModuleType
from unittest import mock
import unittest
from uuid import uuid4

from agent_tools import private_inventory_lock as private
from agent_tools import readiness_tart_macos_legacy_phases as subject
from agent_tools import readiness_tart_macos_unlock_qualification as qualification
from agent_tools.tests.test_tart_macos_legacy_public_resolution import LegacyPublicResolutionTests


@unittest.skipUnless(os.name == 'posix', 'actual no-follow private filesystem')
class LegacyPhaseTests(unittest.TestCase):
    write = LegacyPublicResolutionTests.write
    produce = LegacyPublicResolutionTests.produce

    def setUp(self):
        LegacyPublicResolutionTests.setUp(self)
        self.stack.enter_context(mock.patch.object(subject, '_ORIGINAL_RUN', self.run))
        self.operation, _ = self.produce()
        self.name = 'prepared-single-leftshift-' + str(uuid4())
        self.directory = self.root / self.name; self.directory.mkdir(mode=0o700)
        self.raw = self.write(self.directory / 'producer.py', b'# controlled public pre-input producer\n')
        self.spec = self.specification('inert_preparation', {'producer.py': self.raw},
                                       absent=['original-unknown.json', 'input-transport-complete.json'])
        self.cases = {self.name: self.spec}
        self.stack.enter_context(mock.patch.object(subject, '_CASES', self.cases))

    def specification(self, kind, files, *, absent=(), nested=None, phase_facts=(), root_files=None):
        return {'kind': kind, 'entries': sorted(os.listdir(self.directory)),
                'files': {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()},
                'absent': list(absent), 'nested': nested or {}, 'phaseFacts': list(phase_facts),
                'rootFiles': {name: hashlib.sha256(raw).hexdigest() for name, raw in (root_files or {}).items()}}

    def case(self):
        with ExitStack() as stack:
            return subject._case(self.custody, self.name, self.spec, stack, [], [], [])

    def journal_scaffold(self):
        info = (self.directory / 'secret-inputs').lstat()
        row = {'name': 'secret-inputs', 'device': info.st_dev, 'inode': info.st_ino,
               'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'nlink': info.st_nlink,
               'size': info.st_size, 'mtimeNs': info.st_mtime_ns, 'ctimeNs': info.st_ctime_ns}
        raw = self.write(self.root / subject._SCAFFOLD_NAME,
            {'originalRun': self.run, 'readSecretInputDirectories': False,
             'containers': [{'directory': self.name, 'entries': [row]}]})
        self.stack.enter_context(mock.patch.object(subject, '_SCAFFOLD_SHA', hashlib.sha256(raw).hexdigest()))

    def test_aggregate_actual_tcp_group_and_positive_before_phase_absence(self):
        before = {path.name: (path.read_bytes(), path.stat().st_ino)
                  for path in (self.root / 'public-transitions').iterdir()}
        with subject.observe(self.custody) as proof:
            proof.require_input_closed(); value = proof.report
            self.assertTrue(value['inputPhaseClosed'])
            self.assertFalse(value['processIdleAuthority'])
            self.assertFalse(value['historicalSemanticSuccessInferred'])
            self.assertEqual(value['publicOriginals'][0]['semanticOutcome'], 'unknown')
            self.assertEqual(value['families'][0]['inputWorkState'], 'proven_unsubmitted')
            self.assertFalse(value['newNonceQualificationAuthority'])
        first = subject.resolve(self.custody)
        path = self.root / 'legacy-input-phase-resolutions' / (self.run + '.json')
        original = (path.read_bytes(), path.stat().st_ino)
        self.assertEqual(subject.resolve(self.custody), first)
        self.assertEqual((path.read_bytes(), path.stat().st_ino), original)
        self.assertEqual({p.name: (p.read_bytes(), p.stat().st_ino)
                          for p in (self.root / 'public-transitions').iterdir()}, before)

    def test_missing_phase_is_not_assumed_absent_on_orphan_or_symlink(self):
        for kind in ('file', 'directory', 'symlink'):
            with self.subTest(kind=kind):
                path = self.directory / 'original-unknown.json'
                if kind == 'file': self.write(path, {'state': 'unknown'})
                elif kind == 'directory': path.mkdir(mode=0o700)
                else: path.symlink_to(self.directory / 'missing-target')
                with self.assertRaises(qualification.QualificationBlocked): subject.observe(self.custody)
                if kind == 'directory': path.rmdir()
                else: path.unlink()

    def test_held_source_generation_actor_and_family_changes_stop_live_proof(self):
        with subject.observe(self.custody) as proof:
            self.custody.actor = {'pid': 12, 'birth': 'other'}
            with self.assertRaisesRegex(qualification.QualificationBlocked, 'target_changed'): proof.guard()
            self.custody.actor = self.actor
            raw = (self.directory / 'producer.py').read_bytes()
            replacement = self.directory / 'replacement'; self.write(replacement, raw)
            replacement.replace(self.directory / 'producer.py')
            with self.assertRaises((qualification.QualificationBlocked, ValueError)): proof.guard()
        # A newly appeared known-family incident is never hidden by old selection.
        extra = self.root / ('prepared-single-leftshift-' + str(uuid4())); extra.mkdir(mode=0o700)
        with self.assertRaisesRegex(qualification.QualificationBlocked, 'inventory_changed'):
            subject.observe(self.custody)

    def test_forged_cache_cannot_mint_input_closure_or_hide_orphan(self):
        with self.assertRaises(qualification.QualificationBlocked): subject.LegacyInputClosure(resolved=True)
        subject.resolve(self.custody)
        path = self.root / 'legacy-input-phase-resolutions' / (self.run + '.json')
        self.write(path, {'inputPhaseClosed': True, 'resolved': True})
        with self.assertRaisesRegex(qualification.QualificationBlocked, 'resolution_conflict'):
            subject.resolve(self.custody)
        self.write(self.directory / 'original-unknown.json', {'state': 'unknown'})
        with self.assertRaises(qualification.QualificationBlocked): subject.resolve(self.custody)

    def test_secret_and_submit_transport_ids_are_exact_not_caller_labels(self):
        op = str(uuid4()); raw = self.write(self.directory / 'secret-transport-complete.json',
            {'operationId': op, 'state': 'transport_complete_not_login_receipt'})
        self.spec = self.specification('finished', {'producer.py': self.raw, 'secret-transport-complete.json': raw},
            phase_facts=[{'file': 'secret-transport-complete.json', 'operationId': op,
                          'state': 'transport_complete_not_login_receipt'}])
        self.assertEqual(self.case()['inputWorkState'], 'input_transport_finished')
        self.spec['phaseFacts'][0]['operationId'] = str(uuid4())
        with self.assertRaisesRegex(qualification.QualificationBlocked, 'original_changed'): self.case()

    def test_continuation_joins_same_secret_and_never_types_again(self):
        secret, submit = str(uuid4()), str(uuid4())
        files = {'secret-transport-complete.json': self.write(self.directory / 'secret-transport-complete.json',
                 {'operationId': secret, 'state': 'transport_complete_not_authorization_receipt'})}
        relative = 'submit-existing-filled-field-cc5ef82f-0e7e-48a9-8365-cb1bbe763887'
        child = self.directory / relative; child.mkdir(mode=0o700)
        bodies = {'submit-original-unknown.json': self.write(child / 'submit-original-unknown.json',
                    {'operationId': submit, 'originalSecretOperation': secret}),
                  'submit-transport-complete.json': self.write(child / 'submit-transport-complete.json',
                    {'operationId': submit, 'state': 'submitted'}),
                  'submit-existing-field-once.inert.py': self.write(child / 'submit-existing-field-once.inert.py',
                    b'def original_submit(view):\n view.mouse(1,1,buttons=1)\n view.mouse(1,1,buttons=0)\n')}
        nested = {relative: {'entries': sorted(os.listdir(child)), 'absent': [],
                            'files': {name: hashlib.sha256(raw).hexdigest() for name, raw in bodies.items()}}}
        self.spec = self.specification('continuation', files, nested=nested)
        self.assertEqual(self.case()['inputWorkState'], 'secret_and_final_submit_finished_prior_submits_unsubmitted')
        # Even a test-qualified source pin cannot enable a second typing call.
        source = self.write(child / 'submit-existing-field-once.inert.py', b'view.type_secret_from_fd(3)\n')
        self.spec['nested'][relative]['files']['submit-existing-field-once.inert.py'] = hashlib.sha256(source).hexdigest()
        with self.assertRaisesRegex(qualification.QualificationBlocked, 'retype_unqualified'): self.case()

    def test_expired_single_incident_approval_is_closed_not_reusable(self):
        incident = str(uuid4()); child_name = 'incidents/' + incident
        child = self.directory / child_name; child.mkdir(mode=0o700, parents=True)
        files = {'approval-window.json': self.write(self.directory / 'approval-window.json',
                  {'targetRun': self.run, 'expires': 1.0})}
        bodies = {name: self.write(child / name, {'operationId': incident}) for name in
                  ('original-unknown.json', 'input-transport-complete.json')}
        self.spec = self.specification('bounded_wake', files, nested={child_name:
            {'entries': sorted(os.listdir(child)), 'absent': [],
             'files': {name: hashlib.sha256(raw).hexdigest() for name, raw in bodies.items()}}})
        self.spec['incidentChildren'] = [incident]
        self.assertEqual(self.case()['inputWorkState'], 'one_shift_transport_finished_unused_approval_expired')
        (self.directory / 'incidents' / str(uuid4())).mkdir(mode=0o700)
        with self.assertRaisesRegex(qualification.QualificationBlocked, 'inventory_changed'): self.case()

    def test_archive_adds_no_admission_and_does_not_need_semantic_success(self):
        self.spec = self.specification('archive', {'producer.py': self.raw})
        self.spec['publicOriginal'] = self.operation
        self.assertEqual(self.case()['inputWorkState'], 'evidence_archive_no_additional_admission')
        self.assertEqual(len(list((self.root / 'public-transitions').glob('*-transport-closed.json'))), 1)

    def test_opaque_closed_proof_and_private_files_never_read(self):
        # Metadata is permitted; file contents and secret-input subtrees are not.
        self.write(self.directory / 'ordinary-pass.bin', b'DO-NOT-READ-OR-HASH')
        (self.directory / 'secret-inputs').mkdir(mode=0o700)
        self.write(self.directory / 'secret-inputs' / 'unknown.json', b'DO-NOT-READ-OR-HASH')
        self.spec['entries'] = sorted(os.listdir(self.directory))
        self.journal_scaffold()
        original_open = private.Snapshot
        def checked(directory, name):
            self.assertNotIn(name, {'ordinary-pass.bin', 'secret-inputs', 'unknown.json'})
            return original_open(directory, name)
        with mock.patch.object(private, 'Snapshot', checked):
            proof = subject.observe(self.custody)
            proof.require_input_closed(); proof.close()
            with self.assertRaisesRegex(qualification.QualificationBlocked, 'proof_closed'): proof.report

    def test_original_opaque_journal_generation_blocks_hidden_later_orphan(self):
        (self.directory / 'secret-inputs').mkdir(mode=0o700)
        self.spec['entries'] = sorted(os.listdir(self.directory)); self.journal_scaffold()
        with subject.observe(self.custody) as proof:
            # The new entry is not read. Its parent generation invalidates the
            # originally source-qualified closed phase.
            self.write(self.directory / 'secret-inputs' / 'later-unknown.json', {'state': 'unknown'})
            with self.assertRaises(qualification.QualificationBlocked): proof.guard()
        with self.assertRaisesRegex(qualification.QualificationBlocked, 'journal_generation_changed'):
            subject.observe(self.custody)

    def test_whole_before_accepts_hidden_orphan_current_refuses_without_reading_it(self):
        path = Path(__file__).parent / 'fixtures/tart_macos_legacy_phases_before_journal_generation.source'
        old = ModuleType('agent_tools._legacy_phases_before'); old.__file__ = str(path)
        old.__package__ = 'agent_tools'
        exec(compile(path.read_bytes(), str(path), 'exec'), old.__dict__)
        (self.directory / 'secret-inputs').mkdir(mode=0o700)
        self.spec['entries'] = sorted(os.listdir(self.directory)); self.journal_scaffold()
        self.write(self.directory / 'secret-inputs' / 'later-unknown.json', {'state': 'unknown'})
        # Run the archived guard against its authentic RFB epoch. Current
        # observation below retains the current live implementation.
        rfb_path = Path(__file__).parent / 'fixtures/tart_vnc_protected_fd_high/vnc.before.source'
        rfb_raw = rfb_path.read_bytes()
        self.assertEqual(hashlib.sha256(rfb_raw).hexdigest(),
                         'a5b5196c62cdfb2270d3f54faf3f8c318022d16a174447722a94f9d18d2b0a1d')
        old_rfb = ModuleType('agent_tools._legacy_journal_rfb_before')
        old_rfb.__file__, old_rfb.__package__ = str(rfb_path), 'agent_tools'
        exec(compile(rfb_raw, str(rfb_path), 'exec'), old_rfb.__dict__)
        with mock.patch.object(old, '_ORIGINAL_RUN', self.run), \
             mock.patch.object(old, '_CASES', self.cases), \
             mock.patch.object(old, 'rfb', old_rfb), mock.patch.object(old.public, 'rfb', old_rfb):
            with old.observe(self.custody) as falsely_closed:
                self.assertTrue(falsely_closed.report['inputPhaseClosed'])
        with self.assertRaisesRegex(qualification.QualificationBlocked, 'journal_generation_changed'):
            subject.observe(self.custody)


if __name__ == '__main__': unittest.main()

"""Finite historical phase closure over actual TCP RFB and private files."""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from uuid import uuid4

from agent_tools import readiness_tart_macos_legacy_public_resolution as subject
from agent_tools import readiness_tart_macos_registry as registry
from agent_tools import readiness_tart_macos_unlock_qualification as qualification
from agent_tools import readiness_tart_vnc as rfb
from agent_tools.tests.test_readiness_tart_vnc import RfbEndpoint
from agent_tools.tests.test_readiness_tart_macos import binding


@unittest.skipUnless(os.name == 'posix', 'actual private source holders and TCP RFB')
class LegacyPublicResolutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.project = Path(self.temp.name).resolve(); self.project.chmod(0o700)
        self.root = self.project / '.runtime/tool-recovery/tart/selected-run'; self.root.mkdir(mode=0o700, parents=True)
        self.run = str(uuid4()); self.actor = {'pid': 998877, 'birth': 'controlled:original'}
        self.custody = object.__new__(registry.MacCustody); self.custody.root = self.project
        self.custody.lifecycle_root = self.root; self.custody.run_intent = {'operationId': self.run}
        self.custody.actor = self.actor; self.custody.binding = binding()
        self.custody._operator = SimpleNamespace(guard=lambda: None)
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.fixture = Path(__file__).parent / 'fixtures/tart_public_mouse_signature'
        self.helper = self.project / '.runtime/tool-recovery/tart/macos-provision-ui-helper.py'
        whole = b'from pathlib import Path\nROOT=Path(' + repr(str(self.root)).encode() + b')\n' + (self.fixture / 'fixed.source').read_bytes()
        self.write(self.helper, whole)
        self.stack.enter_context(mock.patch.object(subject, '_FIXED_HELPER_SHA', hashlib.sha256(whole).hexdigest()))

    def write(self, path, value):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        body = value if type(value) is bytes else json.dumps(value, sort_keys=True).encode()
        path.write_bytes(body); path.chmod(0o600); return body

    def produce(self, *, before=False, commands=None, expected_operation=None):
        endpoint = RfbEndpoint(); self.addCleanup(endpoint.close)
        def guard(): return {'operationId': self.run}, {'child': self.actor}
        def record(path, value):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream: stream.write(json.dumps(value).encode())
        def session():
            reader, writer = os.pipe(); os.write(writer, b'controlled-public-rfb'); os.close(writer)
            return rfb.ProtectedVncSession(port=endpoint.port, credential_fd=reader, guard=guard), reader
        import uuid
        selected = SimpleNamespace(uuid4=lambda: expected_operation) if expected_operation else uuid
        scope = dict(ROOT=self.root, guard=guard, record=record, session=session, os=os, uuid=selected)
        source = (self.fixture / ('before.source' if before else 'fixed.source')).read_bytes()
        exec(compile(source, '<whole-retained-public-transition>', 'exec'), scope)
        if before:
            with self.assertRaises(TypeError): scope['public_transition']('select-English', commands)
            self.assertEqual(endpoint.events, [])
            return expected_operation, endpoint
        operation = scope['public_transition']('public-stage', commands or
            [['mouse', 1, 0, 1], ['mouse', 1, 0, 0], ['key', 'a', ['MacMeta']], ['text', 'A!']])
        return operation, endpoint

    def test_actual_complete_fixed_caller_all_releases_transport_terminal_semantics_unknown(self):
        operation, endpoint = self.produce()
        # 2 pointer events, Cmd+a pair+modifier pair, and Shifted A/! pairs.
        events = endpoint.wait_events(14); self.assertEqual(len(events), 14)
        with subject.observe(self.custody, operation) as proof:
            value = proof.report
            self.assertEqual((value['workState'], value['semanticOutcome']), ('transport_finished', 'unknown'))
            self.assertTrue(value['replayForbidden']); self.assertFalse(value['genericUnlockAuthority'])
        original = self.root / 'public-transitions' / (operation + '.json')
        before = (original.read_bytes(), original.stat().st_ino)
        result = subject.resolve(self.custody, operation)
        receipt = self.root / 'legacy-public-resolutions' / (operation + '.json')
        first = (receipt.read_bytes(), receipt.stat().st_ino)
        self.assertEqual(subject.resolve(self.custody, operation), result)
        self.assertEqual((receipt.read_bytes(), receipt.stat().st_ino), first)
        self.assertEqual((original.read_bytes(), original.stat().st_ino), before)

    def test_orphan_guard_failure_leaves_original_unknown_no_resolver_receipt(self):
        operation = str(uuid4()); self.root.joinpath('public-transitions').mkdir(mode=0o700)
        self.write(self.root / 'public-transitions' / (operation + '.json'),
                   {'operationId': operation, 'originalRun': self.run, 'child': self.actor, 'stage': 'unknown',
                    'state': 'unknown', 'commands': [['key', 'a', ['Shift']]]})
        with self.assertRaisesRegex(qualification.QualificationBlocked, 'original_unresolved'):
            subject.resolve(self.custody, operation)
        self.assertFalse((self.root / 'legacy-public-resolutions').exists())

    def test_completed_mouse_down_without_release_is_not_closed(self):
        operation, _ = self.produce(commands=[['mouse', 1, 0, 1]])
        with self.assertRaisesRegex(qualification.QualificationBlocked, 'pointer_group_unclosed'):
            subject.resolve(self.custody, operation)

    def test_forged_resolved_cache_does_not_replace_actual_transport_evidence(self):
        operation, _ = self.produce(); subject.resolve(self.custody, operation)
        path = self.root / 'legacy-public-resolutions' / (operation + '.json')
        self.write(path, {'resolved': True, 'semanticOutcome': 'success'})
        with self.assertRaisesRegex(qualification.QualificationBlocked, 'resolution_conflict'):
            subject.resolve(self.custody, operation)
        with self.assertRaises(qualification.QualificationBlocked): subject.ClosedPublicInput(resolved=True)

    def test_other_run_actor_changed_source_or_replaced_intent_blocks(self):
        operation, _ = self.produce()
        with subject.observe(self.custody, operation) as proof:
            path = self.root / 'public-transitions' / (operation + '.json'); raw = path.read_bytes()
            fresh = path.with_name('replacement'); self.write(fresh, raw); fresh.replace(path)
            with self.assertRaises((ValueError, qualification.QualificationBlocked)): proof.guard()
        self.custody.actor = {'pid': 998878, 'birth': 'controlled:other'}
        with self.assertRaisesRegex(qualification.QualificationBlocked, 'original_changed'):
            subject.observe(self.custody, operation)
        self.custody.actor = self.actor
        self.write(self.helper, b'PRIVATE-MUST-NOT-ECHO')
        with self.assertRaises(Exception) as caught: subject.observe(self.custody, operation)
        self.assertNotIn('PRIVATE', str(caught.exception))

    def test_loaded_method_change_cannot_hide_behind_qualified_disk_source(self):
        operation, _ = self.produce()
        def replaced_mouse(self, x, y, *, buttons=0):
            raise AssertionError('replaced method must never execute')
        with mock.patch.object(rfb.ProtectedVncSession, 'mouse', replaced_mouse):
            with self.assertRaisesRegex(qualification.QualificationBlocked, 'method_source_changed'):
                subject.observe(self.custody, operation)

    def test_actual_source_session_uses_same_captured_method_code_contract(self):
        from agent_tools.source_module_loader import SourceSession
        session = SourceSession(Path(__file__).parents[1], 'readiness_tart_macos_legacy_public_resolution')
        try:
            session.module._method_contract(Path(rfb.__file__).read_bytes())
            session.guard()
        finally:
            session.close()

    def test_authentic_pre_method_case_zero_events_and_no_replay(self):
        self.run = subject._PREINPUT_RUN; self.custody.run_intent = {'operationId': self.run}
        operation, endpoint = self.produce(before=True,
            commands=[['mouse', 512, 351, 1], ['mouse', 512, 351, 0]], expected_operation=subject._PREINPUT_OPERATION)
        folder = self.root / subject._PREINPUT_FOLDER
        whole = b'from pathlib import Path\nROOT=Path(' + repr(str(self.root)).encode() + b')\n' + (self.fixture / 'before.source').read_bytes()
        self.write(folder / 'macos-provision-ui-helper.py', whole)
        reference = str(Path('.runtime/tool-recovery/tart') / self.root.name / 'public-transitions' / (operation + '.json'))
        failure = self.write(folder / 'original-failure.json',
            {'originalError': 'TypeError: ProtectedVncSession.mouse() takes 3 positional arguments but 4 were given',
             'publicTransitionReceipts': [reference], 'callerResolved': False})
        with mock.patch.object(subject, '_PREINPUT_HELPER_SHA', hashlib.sha256(whole).hexdigest()), \
             mock.patch.object(subject, '_PREINPUT_FAILURE_SHA', hashlib.sha256(failure).hexdigest()):
            value = subject.resolve(self.custody, operation)
        self.assertEqual((value['workState'], value['semanticOutcome'], value['inputSubmitted']),
                         ('proven_unsubmitted', 'not_attempted', False))
        self.assertEqual(endpoint.events, [])


if __name__ == '__main__': unittest.main()

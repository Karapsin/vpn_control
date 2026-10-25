"""Actual private-filesystem legacy fences; no native input or VM actions."""
from contextlib import ExitStack
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock
from uuid import uuid4

from agent_tools import private_inventory_lock as private
from agent_tools import readiness_tart_macos_legacy_gui as legacy
from agent_tools import readiness_tart_macos_registry as registry
from agent_tools import readiness_tart_macos_unlock_qualification as qualification
from agent_tools.tests.test_readiness_tart_macos import binding


@unittest.skipUnless(os.name == 'posix', 'actual private POSIX filesystem')
class LegacyGuiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.root.chmod(0o700)
        self.run = str(uuid4()); self.operation = str(uuid4()); self.actor = {'pid': 123, 'birth': 'darwin:10:20'}
        self.public = self.root / 'public-transitions'; self.public.mkdir(mode=0o700)
        self.write(self.public / (self.operation + '.json'), {'operationId': self.operation,
            'originalRun': self.run, 'child': self.actor, 'stage': 'public-stage', 'state': 'unknown',
            'commands': [['mouse', 10, 20, 1], ['mouse', 10, 20, 0]]})
        self.containers = ['public-transitions']; self.enroll()

    def write(self, path, value):
        path.write_bytes(json.dumps(value, sort_keys=True).encode()); path.chmod(0o600)

    def enroll(self, **changes):
        self.write(self.root / 'legacy-gui-enrollment.json',
                   {'schemaVersion': 1, 'originalRun': self.run, 'containers': self.containers, **changes})

    def custody(self):
        custody = object.__new__(registry.MacCustody); custody.binding = binding()
        custody.lifecycle_root = self.root; custody.run_intent = {'operationId': self.run}; custody.actor = self.actor
        custody._operator = SimpleNamespace(guard=lambda: None)
        return custody

    def close_transport(self):
        self.write(self.public / (self.operation + '-transport-closed.json'),
            {'operationId': self.operation, 'originalRun': self.run, 'child': self.actor,
             'state': 'submitted_awaiting_independent_screen_observation'})

    def test_actual_whole_before_ignores_legacy_orphan_current_inventory_blocks(self):
        path = Path(__file__).parent / 'fixtures/tart_macos_legacy_gui_fence.before.source'
        before = ModuleType('agent_tools._preserved_legacy_gui_material_before')
        before.__file__, before.__package__ = str(path), 'agent_tools'
        exec(compile(path.read_bytes(), str(path), 'exec'), before.__dict__)
        with private.Directory(self.root) as directory:
            # Authentic whole unfixed module+actual files: a different family
            # containing unresolved input is invisible to the old root fence.
            before._new_incidents(directory, str(uuid4()), binding(), {})
        with legacy.inspect(self.custody()) as admitted:
            self.assertEqual(admitted.report['rows'][0]['transport'], 'unclosed')
            with self.assertRaisesRegex(qualification.QualificationBlocked, 'originals_unresolved'):
                admitted.require_clear()

    def test_closed_transport_does_not_mint_independent_outcome(self):
        self.close_transport()
        with legacy.inspect(self.custody()) as inventory:
            row = inventory.report['rows'][0]
            self.assertEqual((row['transport'], row['outcome']), ('closed', 'unresolved'))
            self.assertEqual(row['blocker'], 'independent_source_qualified_outcome_missing')
            self.assertEqual(row['actor'], self.actor)
            with self.assertRaises(qualification.QualificationBlocked): inventory.require_clear()

    def test_caller_resolved_flag_and_other_original_run_cannot_adopt_inventory(self):
        for changes in ({'resolved': True}, {'originalRun': str(uuid4())}, {'containers': []}):
            self.enroll(**changes)
            with self.assertRaises(qualification.QualificationBlocked): legacy.inspect(self.custody())
        with self.assertRaises(qualification.QualificationBlocked): legacy.LegacyGuiInventory(resolved=True)
        with self.assertRaises(qualification.QualificationBlocked): legacy.inspect({'root': str(self.root)})

    def test_secret_and_framebuffer_bodies_are_never_read_or_hashed(self):
        protected = self.root / ('protected-state-bound-unlock-' + str(uuid4())); protected.mkdir(mode=0o700)
        secret = protected / 'secret-inputs'; secret.mkdir(mode=0o700)
        (secret / 'private.bin').write_bytes(b'PRIVATE-NEVER-READ')
        (protected / 'ordinary-pass.bin').write_bytes(b'PRIVATE-NEVER-READ')
        (protected / 'private-filled.png').write_bytes(b'PRIVATE-NEVER-READ')
        self.containers.append(protected.name); self.enroll()
        original = private.Snapshot.__init__; opened = []
        def guarded(holder, directory, name):
            self.assertNotIn('secret', name); self.assertNotIn('pass', name); self.assertNotIn('.png', name)
            opened.append(name); return original(holder, directory, name)
        with mock.patch.object(private.Snapshot, '__init__', guarded), legacy.inspect(self.custody()) as inventory:
            self.assertEqual(len(inventory.report['rows']), 2)
            self.assertEqual(inventory.report['rows'][0]['privateBodiesRead'], False)
            self.assertFalse(inventory.report['idleAuthority'])
        self.assertEqual(set(opened), {'legacy-gui-enrollment.json', self.operation + '.json'})

    def test_changed_actor_or_transport_original_is_rejected(self):
        self.close_transport()
        path = self.public / (self.operation + '-transport-closed.json')
        value = json.loads(path.read_bytes())
        for field, replacement in (('child', {'pid': 124, 'birth': 'darwin:10:20'}),
                                   ('operationId', str(uuid4())), ('originalRun', str(uuid4()))):
            self.write(path, {**value, field: replacement})
            with self.assertRaises(qualification.QualificationBlocked): legacy.inspect(self.custody())

    def test_public_orphan_symlink_and_private_generation_change_block(self):
        orphan = self.public / (str(uuid4()) + '-transport-closed.json'); self.write(orphan, {})
        with self.assertRaisesRegex(qualification.QualificationBlocked, 'public_orphan'): legacy.inspect(self.custody())
        orphan.unlink()
        with legacy.inspect(self.custody()) as inventory:
            path = self.public / (self.operation + '.json'); raw = path.read_bytes()
            replacement = self.public / 'replacement'; replacement.write_bytes(raw); replacement.chmod(0o600); replacement.replace(path)
            with self.assertRaises(qualification.QualificationBlocked): inventory.guard()
        path.unlink(); path.symlink_to(self.root / 'legacy-gui-enrollment.json')
        with self.assertRaises((ValueError, OSError, qualification.QualificationBlocked)): legacy.inspect(self.custody())

    def test_new_historical_family_cannot_be_hidden_by_old_selection(self):
        with legacy.inspect(self.custody()) as inventory:
            extra = self.root / ('protected-standard-account-' + str(uuid4())); extra.mkdir(mode=0o700)
            with self.assertRaisesRegex(qualification.QualificationBlocked, 'family_inventory_changed'): inventory.guard()
        with self.assertRaisesRegex(qualification.QualificationBlocked, 'family_inventory_changed'): legacy.inspect(self.custody())

    def test_empty_field_or_local_unlocked_dto_never_resolves_legacy_input(self):
        self.write(self.root / 'local-resolution.json', {'locked': False, 'emptyField': True, 'resolved': True})
        with legacy.inspect(self.custody()) as inventory:
            with self.assertRaisesRegex(qualification.QualificationBlocked, 'originals_unresolved'): inventory.require_clear()
            inventory.close()
            with self.assertRaisesRegex(qualification.QualificationBlocked, 'inventory_closed'): inventory.guard()


if __name__ == '__main__': unittest.main()

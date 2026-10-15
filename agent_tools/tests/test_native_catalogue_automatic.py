"""Actual private Git catalogue closure for the finite automatic SSH helper."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import types
import unittest
from unittest.mock import patch

from agent_tools import native_execution_context as context
from agent_tools.tests import test_native_execution_context as fixture

FIXTURE = Path(__file__).with_name('fixtures')/'native_catalogue_automatic'
HELPER = 'agent_tools/ssh_automatic_program.py'


@unittest.skipUnless(os.name == 'posix' and shutil.which('git'), 'Local Git/private source custody support')
class NativeCatalogueAutomaticTest(unittest.TestCase):
    setUp = fixture.NativeExecutionContextTest.setUp
    git = fixture.NativeExecutionContextTest.git

    def checkpoint_with_helper(self):
        # Explicitly include the actual complete producer even for the preserved
        # catalogue whose finite edge omitted it. The RED then proves the map.
        shutil.copyfile(fixture.ROOT/HELPER, self.native/HELPER)
        self.git('add', HELPER, root=self.native)
        self.git('commit', '--allow-empty', '-m', 'actual automatic helper source', root=self.native)
        return self.git('rev-parse', 'HEAD', root=self.native)

    def test_actual_committed_automatic_helper_is_in_held_native_source_closure(self):
        sha = self.checkpoint_with_helper()
        reads = []
        real_read = context.closure._Held.read

        def record_read(held, path, *args, **kwargs):
            reads.append(Path(path))
            return real_read(held, path, *args, **kwargs)

        with patch.object(context.closure._Held, 'read', new=record_read):
            catalogue = context._catalogue(self.native, sha)
        self.assertIn(self.native/HELPER, reads)
        self.assertEqual(hashlib.sha256((self.native/HELPER).read_bytes()).hexdigest(), catalogue[HELPER]['sha256'])
        self.assertIn('agent_tools/native_review_source_closure.py', catalogue)

    def test_complete_preserved_catalogue_refuses_same_known_helper_before_finite_edge(self):
        proof = json.loads((FIXTURE/'provenance.json').read_text())
        raw = (FIXTURE/'before.source').read_bytes()
        self.assertEqual(proof['sourceSize'], len(raw))
        self.assertEqual(proof['sourceSha256'], hashlib.sha256(raw).hexdigest())
        before = types.ModuleType('agent_tools._native_catalogue_automatic_before')
        before.__package__ = 'agent_tools'
        before.__file__ = str(FIXTURE/'before.source')
        with patch.dict(sys.modules, {before.__name__: before}):
            exec(compile(raw, before.__file__, 'exec'), before.__dict__)
            with self.assertRaisesRegex(before.ExecutionContextError, '^native_dependency_dynamic_unknown$'):
                before._catalogue(self.native, self.checkpoint_with_helper())

    def test_literal_unknown_helper_refuses_even_when_complete_source_exists(self):
        path = self.native/'agent_tools/ssh_transport.py'
        path.write_bytes(path.read_bytes()+b'\ndef unreviewed_helper(): return importlib.import_module("agent_tools.unreviewed_helper")\n')
        (self.native/'agent_tools/unreviewed_helper.py').write_text('value = 1\n')
        self.git('add', 'agent_tools', root=self.native)
        self.git('commit', '-m', 'actual unknown literal helper', root=self.native)
        with self.assertRaisesRegex(context.ExecutionContextError, '^native_dependency_dynamic_unknown$'):
            context._catalogue(self.native, self.git('rev-parse', 'HEAD', root=self.native))

    def test_known_helper_without_committed_source_refuses(self):
        path = self.native/HELPER
        if path.exists():
            self.git('rm', HELPER, root=self.native)
            self.git('commit', '-m', 'actual missing helper source', root=self.native)
        with self.assertRaisesRegex(context.ExecutionContextError, '^native_dependency_dynamic_unknown$'):
            context._catalogue(self.native, self.git('rev-parse', 'HEAD', root=self.native))

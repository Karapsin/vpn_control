"""Complete Git catalogue regression for finite readiness dependencies."""
import ast
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

FIXTURE = Path(__file__).with_name('fixtures') / 'native_catalogue_readiness'


@unittest.skipUnless(os.name == 'posix' and shutil.which('git'), 'Local Git custody support')
class NativeCatalogueReadinessTest(unittest.TestCase):
    setUp = fixture.NativeExecutionContextTest.setUp
    git = fixture.NativeExecutionContextTest.git

    def test_complete_before_rejects_current_callers_fixed_catalogue_holds_every_dependency(self):
        raw = (FIXTURE / 'before.source').read_bytes()
        proof = json.loads((FIXTURE / 'provenance.json').read_text())
        self.assertEqual(proof['sourceSize'], len(raw))
        self.assertEqual(proof['sourceSha256'], hashlib.sha256(raw).hexdigest())
        before = types.ModuleType('agent_tools._catalogue_readiness_before')
        before.__package__ = 'agent_tools'
        before.__file__ = str(FIXTURE / 'before.source')
        with patch.dict(sys.modules, {before.__name__: before}):
            exec(compile(raw, before.__file__, 'exec'), before.__dict__)
            with self.assertRaisesRegex(before.ExecutionContextError, '^native_dependency_dynamic_unknown$'):
                before._catalogue(self.native, self.sha)
        held = context._catalogue(self.native, self.sha)
        for name in ('readiness_nested_channel', 'readiness_ssh_master',
                     'ssh_direct_nested_channel', 'readiness_transport', 'private_inventory_lock'):
            path = 'agent_tools/' + name + '.py'
            self.assertEqual(held[path]['sha256'], hashlib.sha256((self.native / path).read_bytes()).hexdigest())

    def test_unknown_literal_stdlib_is_not_an_unbounded_dynamic_import_waiver(self):
        path = self.native / 'agent_tools/ssh_direct_nested_channel.py'
        path.write_bytes(path.read_bytes() + b'\ndef unreviewed(): return __import__("subprocess")\n')
        self.git('add', str(path.relative_to(self.native)), root=self.native)
        self.git('commit', '-m', 'unreviewed dynamic edge', root=self.native)
        with self.assertRaisesRegex(context.ExecutionContextError, '^native_dependency_dynamic_unknown$'):
            context._catalogue(self.native, self.git('rev-parse', 'HEAD', root=self.native))

    def test_missing_known_readiness_source_remains_a_blocker(self):
        self.git('rm', 'agent_tools/readiness_nested_channel.py', root=self.native)
        self.git('commit', '-m', 'missing reviewed readiness edge', root=self.native)
        with self.assertRaisesRegex(context.ExecutionContextError, '^native_dependency_dynamic_unknown$'):
            context._catalogue(self.native, self.git('rev-parse', 'HEAD', root=self.native))

    def test_only_matching_package_fallback_and_unformatted_package_name_are_recognized(self):
        good = "f'{__package__}.readiness_nested_channel' if __package__ else 'agent_tools.readiness_nested_channel'"
        self.assertEqual('readiness_nested_channel', context._dynamic_name(ast.parse(good, mode='eval').body))
        for value in (
            good.replace("else 'agent_tools.readiness_nested_channel'", "else 'agent_tools.readiness_ssh_master'"),
            good.replace('if __package__', 'if unknown'),
            good.replace('{__package__}', '{__package__!r}'),
            good.replace('{__package__}', '{__package__:s}'),
            good.replace('{__package__}', '{untrusted}'),
        ):
            with self.subTest(expression=value), self.assertRaisesRegex(
                    context.ExecutionContextError, '^native_dependency_dynamic_unknown$'):
                context._dynamic_name(ast.parse(value, mode='eval').body)


if __name__ == '__main__':
    unittest.main()

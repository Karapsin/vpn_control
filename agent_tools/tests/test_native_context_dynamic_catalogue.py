"""Actual Git catalogue regressions for the two reviewed dynamic import sites."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import types
import unittest

from agent_tools import native_execution_context as current
from agent_tools.tests import test_native_execution_context as context_tests

FIXTURE = Path(__file__).with_name('fixtures')/'native_context_dynamic_catalogue'


def before_module():
    provenance = json.loads((FIXTURE/'provenance.json').read_bytes())
    for name, digest in provenance['files'].items():
        if hashlib.sha256((FIXTURE/name).read_bytes()).hexdigest() != digest:
            raise AssertionError('changed native catalogue beforeimage')
    path = FIXTURE/'native_execution_context.py.before.source'
    name = 'agent_tools._native_context_dynamic_catalogue_before'
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = 'agent_tools'
    sys.modules[name] = module
    try:
        exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    finally:
        sys.modules.pop(name, None)
    return module


@contextmanager
def actual_checkpoint():
    case = context_tests.NativeExecutionContextTest('test_native_used_tool_change_still_requires_requalification')
    try:
        case.setUp()
        yield case
    finally:
        case.doCleanups()


@unittest.skipUnless(os.name == 'posix' and shutil.which('git'), 'Local Git/private registry support')
class NativeDynamicCatalogueTests(unittest.TestCase):
    def refusal(self, module, case):
        try:
            module._catalogue(case.native, case.sha)
        except module.ExecutionContextError as error:
            self.assertEqual('native_dependency_dynamic_unknown', str(error))
            trace = error.__traceback__
            while trace:
                if trace.tb_frame.f_code.co_name == '_catalogue':
                    return trace.tb_frame.f_locals['path'], trace.tb_frame.f_locals['name']
                trace = trace.tb_next
            self.fail('catalogue refusal did not originate in actual catalogue')
        self.fail('unclassified dependency was accepted')

    def test_complete_before_refuses_both_actual_edges_current_catalogue_succeeds(self):
        old = before_module()
        with actual_checkpoint() as case:
            self.assertIn(self.refusal(old, case), {
                ('agent_tools/ssh_transport.py', 'readiness'),
                ('agent_tools/readiness_nested_channel.py', '__future__')})
            # Isolate both independent refusals without depending on set-based
            # closure traversal order. Each uses the complete old catalogue.
            old._STDLIB_DYNAMIC = {**old._STDLIB_DYNAMIC,
                                  'agent_tools/readiness_nested_channel.py': frozenset({'__future__'})}
            self.assertEqual(('agent_tools/ssh_transport.py', 'readiness'), self.refusal(old, case))
            old._STDLIB_DYNAMIC = dict(before_module()._STDLIB_DYNAMIC)
            old._DYNAMIC = {**old._DYNAMIC, 'agent_tools/ssh_transport.py':
                            old._DYNAMIC['agent_tools/ssh_transport.py'] | {'readiness'}}
            self.assertEqual(('agent_tools/readiness_nested_channel.py', '__future__'),
                             self.refusal(old, case))
            catalogue = current._catalogue(case.native, case.sha)
            self.assertIn('agent_tools/readiness.py', catalogue)
            self.assertIn('agent_tools/readiness_nested_membership.py', catalogue)
            old._STDLIB_DYNAMIC = {**old._STDLIB_DYNAMIC,
                                  'agent_tools/readiness_nested_channel.py': frozenset({'__future__'})}
            self.assertEqual(catalogue, old._catalogue(case.native, case.sha))

    def commit_source(self, case, relative, body):
        (case.native/relative).write_text(body)
        case.git('add', relative, root=case.native)
        case.git('-c', 'user.name=Local Control', '-c', 'user.email=local-control@example.invalid',
                 'commit', '-m', 'finite unclassified dependency negative', root=case.native)
        case.sha = case.git('rev-parse', 'HEAD', root=case.native)

    def test_unknown_repository_import_and_missing_reviewed_source_are_rejected(self):
        with actual_checkpoint() as case:
            path = 'agent_tools/ssh_transport.py'
            original = (case.native/path).read_text()
            self.commit_source(case, path, original.replace(
                "importlib.import_module('agent_tools.readiness')",
                "importlib.import_module('agent_tools.readiness_unclassified')"))
            self.assertEqual((path, 'readiness_unclassified'), self.refusal(current, case))
        with actual_checkpoint() as case:
            path = 'agent_tools/readiness_nested_membership.py'
            (case.native/path).unlink()
            case.git('add', path, root=case.native)
            case.git('-c', 'user.name=Local Control', '-c', 'user.email=local-control@example.invalid',
                     'commit', '-m', 'missing classified source', root=case.native)
            case.sha = case.git('rev-parse', 'HEAD', root=case.native)
            with self.assertRaisesRegex(current.ExecutionContextError, 'native_catalogue_missing_dependency'):
                current._catalogue(case.native, case.sha)

    def test_stdlib_admission_rejects_variable_expression_and_wrong_site(self):
        with actual_checkpoint() as case:
            path = 'agent_tools/readiness_nested_channel.py'
            original = (case.native/path).read_text()
            self.commit_source(case, path, original.replace("__import__('__future__')",
                               "__import__('__future__' if True else '__future__')"))
            with self.assertRaisesRegex(current.ExecutionContextError, 'native_dependency_dynamic_unknown'):
                current._catalogue(case.native, case.sha)
        with actual_checkpoint() as case:
            path = 'agent_tools/native_execution_context.py'
            original = (case.native/path).read_text()
            self.commit_source(case, path, original + "\n__import__('__future__')\n")
            self.assertEqual((path, '__future__'), self.refusal(current, case))


if __name__ == '__main__':
    unittest.main()

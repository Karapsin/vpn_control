"""TEST-001 RED halves run when their test, beforeimage or closure changed; every decision is recorded."""
import ast
import hashlib
import json
import os
import re
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from agent_tools import agent_test_runner as runner
from agent_tools import affected_agent_tests as selector
from agent_tools.tests import red_gate

SELF = 'agent_tools/tests/test_red_gate.py'
BEFORE = red_gate.ROOT / 'agent_tools/tests/fixtures/committed_source/readiness_vm_dispatch.before.source'


class RedGateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.record = self.directory / 'red-proofs.jsonl'
        environment = mock.patch.dict(os.environ, {red_gate.RECORD_ENV: str(self.record)})
        environment.start(); self.addCleanup(environment.stop)
        os.environ.pop(red_gate.CHANGED_ENV, None)
        red_gate.closure.cache_clear(); red_gate._footprints.cache_clear()
        self.addCleanup(red_gate.closure.cache_clear); self.addCleanup(red_gate._footprints.cache_clear)

    def changed(self, paths):
        target = self.directory / ('changed-%d.json' % len(list(self.directory.iterdir())))
        target.write_text(json.dumps(sorted(paths)))
        os.environ[red_gate.CHANGED_ENV] = str(target)

    def records(self):
        return [json.loads(line) for line in self.record.read_text().splitlines()]

    def test_every_red_runs_without_a_changed_set(self):
        self.assertTrue(red_gate.red_required(self, BEFORE))
        (entry,) = self.records()
        self.assertEqual((self.id(), 'ran', 'no-changed-set'), (entry['test'], entry['red'], entry['reason']))
        self.assertEqual([SELF], list(entry['testSource']))
        self.assertEqual(['agent_tools/tests/fixtures/committed_source/readiness_vm_dispatch.before.source'],
                         list(entry['beforeimages']))

    def test_unchanged_proof_is_skipped_and_recorded_with_its_digests(self):
        # readiness_windows is imported by the preserved dispatch, so it now reruns the RED (see below).
        self.changed(['agent_docs/contracts.md', 'agent_tools/native_package_release_report.py'])
        self.assertFalse(red_gate.red_required(self, BEFORE))
        (entry,) = self.records()
        self.assertEqual(('skipped', 'unchanged'), (entry['red'], entry['reason']))
        self.assertRegex(entry['testSource'][SELF], '^[0-9a-f]{64}$')
        self.assertRegex(entry['closureSha256'], '^[0-9a-f]{64}$')

    def test_a_changed_test_beforeimage_or_imported_module_reruns_red(self):
        for paths, reason in (([SELF], 'test-or-beforeimage-changed'),
                              ([BEFORE.relative_to(red_gate.ROOT).as_posix()], 'test-or-beforeimage-changed'),
                              # imported by this module, and transitively through the selector
                              (['agent_tools/tests/red_gate.py'], 'imported-module-changed'),
                              (['agent_tools/agent_test_footprints.py'], 'imported-module-changed')):
            with self.subTest(paths=paths):
                self.changed(paths)
                self.assertTrue(red_gate.red_required(self, BEFORE))
                self.assertEqual(('ran', reason), (self.records()[-1]['red'], self.records()[-1]['reason']))

    def test_recorded_footprints_extend_the_closure(self):
        self.changed(['agent_tools/tests/fixtures/lazily_read.json'])
        self.assertFalse(red_gate.red_required(self))
        red_gate.closure.cache_clear()
        with mock.patch.object(red_gate, '_footprints', return_value={SELF: frozenset({'agent_tools/tests/fixtures/lazily_read.json'})}):
            self.assertTrue(red_gate.red_required(self))
        self.assertEqual(['unchanged', 'imported-module-changed'], [entry['reason'] for entry in self.records()])

    def test_runner_passes_the_selection_changed_set_to_each_worker(self):
        plan = {'schemaVersion': 1, 'sourceFingerprint': '0' * 64, 'modules': ['agent_tools.tests.test_red_gate']}
        self.assertEqual(['a/b.py'], runner.validate_plan({**plan, 'changedPaths': ['a/b.py']})['changedPaths'])
        for bad in (['/abs'], ['../x'], [''], [1], 'a/b.py'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                runner.validate_plan({**plan, 'changedPaths': bad})
        worker = self.directory / 'worker'
        worker.mkdir()
        runner._red_gate_environment({**plan, 'changedPaths': ['b.py', 'a.py']}, worker)
        self.assertEqual(['a.py', 'b.py'], json.loads(Path(os.environ[red_gate.CHANGED_ENV]).read_text()))
        self.assertEqual(str(worker / 'red-proofs.jsonl'), os.environ[red_gate.RECORD_ENV])
        # A plan without the set (explicit audit, managed local run) reruns every RED.
        second = self.directory / 'second'
        second.mkdir()
        runner._red_gate_environment(plan, second)
        self.assertNotIn(red_gate.CHANGED_ENV, os.environ)

    def test_selector_plan_carries_the_changed_set_only_when_given(self):
        root = self.directory / 'root'
        (root / '.rag_index').mkdir(parents=True, mode=0o700)
        command = [sys.executable, '-m', 'unittest', 'agent_tools.tests.test_red_gate']
        with_set = selector.prepare_run(root, command, '0' * 64, ('b.py', 'a.py'))
        without = selector.prepare_run(root, command, '0' * 64)
        read = lambda argv: json.loads(Path(argv[argv.index('--plan-file') + 1]).read_text())
        self.assertEqual(['a.py', 'b.py'], read(with_set)['changedPaths'])
        self.assertNotIn('changedPaths', read(without))


    def test_preserved_runner_refuses_a_changed_set_RED_current_gates_red_halves_GREEN(self):
        fixture = red_gate.ROOT / 'agent_tools/tests/fixtures/red_gate'
        raw = (fixture / 'agent_test_runner.before.source').read_bytes()
        self.assertEqual(json.loads((fixture / 'provenance.json').read_bytes())['sha256'], hashlib.sha256(raw).hexdigest())
        plan = {'schemaVersion': 1, 'sourceFingerprint': '0' * 64, 'modules': ['agent_tools.tests.test_red_gate'],
                'changedPaths': ['agent_docs/contracts.md']}
        before = [node for node in ast.parse(raw).body if isinstance(node, ast.FunctionDef) and node.name == 'validate_plan']
        namespace = {'os': os, 're': re, 'HEX': runner.HEX, 'MODULE': runner.MODULE}
        exec(compile(ast.Module(body=before, type_ignores=[]), 'agent_test_runner.before.source', 'exec'), namespace)
        # RED: the preserved runner had no way to receive the changed set, so
        # every RED half reran on every push.
        with self.assertRaisesRegex(ValueError, 'Invalid unittest plan'):
            namespace['validate_plan'](plan)
        # GREEN: the same plan reaches the worker and an unchanged RED is skipped.
        worker = self.directory / 'worker'
        worker.mkdir()
        runner._red_gate_environment(runner.validate_plan(plan), worker)
        self.assertFalse(red_gate.red_required(self, BEFORE))
        self.assertEqual('skipped', json.loads((worker / 'red-proofs.jsonl').read_text().splitlines()[-1])['red'])

    def test_beforeimage_imports_and_the_mcp_environment_rerun_red_RED_before_GREEN(self):
        """Review finding 13: a RED proof also depends on what its beforeimage imports and on requirements-mcp.txt."""
        fixture = red_gate.ROOT / 'agent_tools/tests/fixtures/red_gate_beforeimage_imports'
        raw = (fixture / 'red_gate.before.source').read_bytes()
        self.assertEqual(json.loads((fixture / 'provenance.json').read_bytes())['sha256'], hashlib.sha256(raw).hexdigest())
        image = BEFORE.relative_to(red_gate.ROOT).as_posix()
        # The preserved readiness_vm_dispatch imports modules this test never imports.
        only_image = sorted(red_gate.image_closure(image) - red_gate.closure(SELF))
        self.assertIn('agent_tools/readiness_fixture_registry.py', only_image)
        before = type(sys)('red_gate_before')
        before.__file__ = red_gate.__file__
        exec(compile(raw, 'red_gate.before.source', 'exec'), before.__dict__)
        for paths, reason in ((['agent_tools/readiness_fixture_registry.py'], 'beforeimage-import-changed'),
                              (['agent_tools/requirements-mcp.txt'], 'environment-changed')):
            with self.subTest(paths=paths):
                self.changed(paths)
                if red_gate.red_required(self, fixture / 'red_gate.before.source'):
                    before._changed.cache_clear()
                    # RED: the bf8d2da2 gate skipped this proof although its result could change.
                    self.assertFalse(before.red_required(self, BEFORE))
                    self.assertEqual('unchanged', self.records()[-1]['reason'])
                self.assertTrue(red_gate.red_required(self, BEFORE))
                self.assertEqual(('ran', reason), (self.records()[-1]['red'], self.records()[-1]['reason']))
        # A non-Python beforeimage contributes only its own bytes.
        self.assertEqual(frozenset(), red_gate.image_closure('agent_tools/tests/fixtures/dispatch_source_closure/provenance.json'))
        # A beforeimage resolves relative imports against the package of the source it preserves.
        self.assertEqual('agent_tools/readiness_vm_dispatch.py', red_gate._preserved_path(image))


if __name__ == '__main__':
    unittest.main()

"""Recorded per-test footprints: real runner workers in an owned temporary repository."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from agent_tools import affected_agent_tests as selector
from agent_tools import agent_test_footprints as footprints


TOOLS = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == 'posix', 'the managed runner retains private POSIX reports')
class RunnerRecordingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='vc-footprints-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        (self.root / 'agent_tools').mkdir()
        for name in ('agent_test_runner.py', 'agent_test_session_observer.py', 'agent_test_footprints.py'):
            shutil.copy2(TOOLS / name, self.root / 'agent_tools' / name)
        files = {
            'agent_tools/__init__.py': '',
            'agent_tools/tests/__init__.py': '',
            'agent_tools/data.json': '{"value": 1}',
            'agent_tools/unread.json': '{}',
            # Reads its data while it is imported: the module owns that read.
            'agent_tools/leaf.py': "import json\nfrom pathlib import Path\nVALUE=json.loads((Path(__file__).parent/'data.json').read_text())['value']\n",
            'agent_tools/other.py': 'VALUE=2\n',
            # A lazy import inside a production function: not a static edge.
            'agent_tools/router.py': 'def route():\n    from agent_tools import other\n    return other.VALUE\n',
            'agent_tools/tests/fixtures/windows_case/before.source': 'VALUE=0\n',
            'agent_tools/tests/fixtures/windows_set/one.json': '1',
            # Computed paths and a lazy computed import: no static rule sees them.
            'agent_tools/tests/test_reader.py': (
                "import importlib, os, unittest\nfrom pathlib import Path\n"
                "FIXTURES=Path(__file__).parent/'fix'.__add__('tures')\n"
                "class Case(unittest.TestCase):\n"
                " def test_reads(self):\n"
                "  name='windows_'+'case'\n"
                "  source=(FIXTURES/name/'before.source').read_text()\n"
                "  exec(compile(source,str(FIXTURES/name/'before.source'),'exec'),{})\n"
                "  self.assertEqual(1,importlib.import_module('agent_tools.'+'leaf').VALUE)\n"
                "  self.assertEqual(['one.json'],os.listdir(FIXTURES/('windows_'+'set')))\n"
                " def test_route(self):\n"
                "  from agent_tools import router\n"
                "  self.assertEqual(2,router.route())\n"),
            'agent_tools/tests/test_other.py': (
                "import unittest\nfrom agent_tools import router\n"
                "class Case(unittest.TestCase):\n def test_value(self): self.assertEqual(2,router.route())\n"),
        }
        for relative, text in files.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        self.output = self.root / 'footprint-output'
        self.output.mkdir()

    def run_workers(self, modules):
        runs = self.root / '.rag_index' / 'agent-test-runs'
        runs.mkdir(parents=True, mode=0o700)
        (self.root / '.rag_index').chmod(0o700)
        plan = runs / 'plan.json'
        plan.write_text(json.dumps({'schemaVersion': 1, 'sourceFingerprint': 'a' * 64, 'modules': modules, 'maxWorkers': 1}))
        env = {**os.environ, 'AGENT_TEST_FOOTPRINT_DIR': str(self.output), 'GITHUB_SHA': 'b' * 40}
        result = subprocess.run([sys.executable, str(self.root / 'agent_tools/agent_test_runner.py'), '--plan-file', str(plan),
                                 '--report-dir', str(runs / 'report')], cwd=self.root, env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        values = [json.loads(path.read_text()) for path in sorted(self.output.glob('footprint-*.json'))]
        self.assertEqual(1, len(values))
        return values[0]

    def test_worker_attributes_test_and_import_time_reads(self):
        value = footprints.validate(self.run_workers(['agent_tools.tests.test_other', 'agent_tools.tests.test_reader']))
        self.assertEqual('b' * 40, value['sourceCommit'])
        reader = set(value['edges']['agent_tools/tests/test_reader.py'])
        self.assertLessEqual({'agent_tools/tests/fixtures/windows_case/before.source', 'agent_tools/leaf.py'}, reader)
        self.assertEqual(['agent_tools/data.json'], value['edges']['agent_tools/leaf.py'])
        self.assertEqual(['agent_tools/tests/fixtures/windows_set'], value['directories']['agent_tools/tests/test_reader.py'])
        self.assertNotIn('agent_tools/data.json', reader)
        self.assertNotIn('agent_tools/tests/fixtures/windows_case/before.source', value['edges'].get('agent_tools/tests/test_other.py', []))
        self.assertFalse(any(path.startswith('agent_tools/agent_test_runner') for paths in value['edges'].values() for path in paths))
        # The first exercising test and the importing function both own the lazy import.
        self.assertEqual(['agent_tools/other.py'], value['edges']['agent_tools/router.py'])
        self.assertIn('agent_tools/other.py', value['edges']['agent_tools/tests/test_other.py'])

    def test_recorded_footprints_select_what_static_edges_miss(self):
        value = self.run_workers(['agent_tools.tests.test_other', 'agent_tools.tests.test_reader'])
        merged = footprints.merge([value])
        inventory = [str(path.relative_to(self.root)) for path in self.root.rglob('*') if path.is_file()
                     and not str(path.relative_to(self.root)).startswith(('.rag_index', 'footprint-output'))]
        sources = {path: ((self.root / path).read_text() if path.endswith(('.py', '.source')) else None) for path in inventory}
        for changed in ('agent_tools/data.json', 'agent_tools/tests/fixtures/windows_case/before.source'):
            with self.subTest(changed=changed):
                self.assertEqual((), selector.select_from_sources(sources, {changed}).modules)
                self.assertEqual(('agent_tools.tests.test_reader',),
                                 selector.select_from_sources(sources, {changed}, footprints=merged).modules)
        self.assertEqual((), selector.select_from_sources(sources, {'agent_tools/unread.json'}, footprints=merged).modules)
        # The second suite finds other already cached: the router's recorded edge selects it.
        self.assertEqual((), selector.select_from_sources(sources, {'agent_tools/other.py'}).modules)
        self.assertEqual(('agent_tools.tests.test_other', 'agent_tools.tests.test_reader'),
                         selector.select_from_sources(sources, {'agent_tools/other.py'}, footprints=merged).modules)
        added = 'agent_tools/tests/fixtures/windows_set/two.json'
        sources[added] = None
        self.assertEqual(('agent_tools.tests.test_reader',),
                         selector.select_from_sources(sources, {added}, footprints=merged, structural=frozenset({added})).modules)

    def test_unset_environment_records_nothing(self):
        runs = self.root / '.rag_index' / 'agent-test-runs'
        runs.mkdir(parents=True, mode=0o700)
        (self.root / '.rag_index').chmod(0o700)
        plan = runs / 'plan.json'
        plan.write_text(json.dumps({'schemaVersion': 1, 'sourceFingerprint': 'a' * 64, 'modules': ['agent_tools.tests.test_other']}))
        env = {key: value for key, value in os.environ.items() if key != 'AGENT_TEST_FOOTPRINT_DIR'}
        result = subprocess.run([sys.executable, str(self.root / 'agent_tools/agent_test_runner.py'), '--plan-file', str(plan),
                                 '--report-dir', str(runs / 'report')], cwd=self.root, env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual([], list(self.output.iterdir()))


class TableTests(unittest.TestCase):
    def test_merge_unions_owners_and_keeps_one_commit(self):
        one = {'schemaVersion': 1, 'sourceCommit': 'c' * 40, 'edges': {'a.py': ['x']}, 'directories': {}}
        two = {'schemaVersion': 1, 'sourceCommit': 'c' * 40, 'edges': {'a.py': ['y'], 'b.py': ['x']}, 'directories': {'b.py': ['d']}}
        self.assertEqual({'schemaVersion': 1, 'sourceCommit': 'c' * 40, 'edges': {'a.py': ['x', 'y'], 'b.py': ['x']},
                          'directories': {'b.py': ['d']}}, footprints.merge([one, two]))

    def test_invalid_tables_refuse(self):
        for value in ({'schemaVersion': 2, 'edges': {}}, {'schemaVersion': 1, 'edges': {'a': ['/etc/passwd']}},
                      {'schemaVersion': 1, 'edges': {'a': ['../x']}}, {'schemaVersion': 1, 'edges': []}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                footprints.validate(value)

    def test_selector_loads_only_a_valid_cache(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertIsNone(selector.load_footprints(root))
            cache = root / selector.FOOTPRINT_CACHE
            cache.parent.mkdir(parents=True)
            cache.write_text('{')
            self.assertIsNone(selector.load_footprints(root))
            cache.write_text(json.dumps({'schemaVersion': 1, 'sourceCommit': 'd' * 40, 'edges': {}, 'directories': {}}))
            self.assertEqual('d' * 40, selector.load_footprints(root)['sourceCommit'])


if __name__ == '__main__':
    unittest.main()

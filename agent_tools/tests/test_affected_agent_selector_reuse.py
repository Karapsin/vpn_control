"""Invocation-local selector reuse controls with inert sources and real Git."""
import ast
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
from agent_tools import affected_agent_tests as selector


class SelectorReuseTests(unittest.TestCase):
    def sources(self):
        return {'agent_tools/a.py': 'from agent_tools import b',
                'agent_tools/b.py': 'from agent_tools import a',
                'agent_tools/tests/test_a.py': 'from agent_tools import a',
                'agent_tools/tests/test_b.py': 'from agent_tools import b',
                'scripts/helper.py': 'VALUE = 1',
                'agent_tools/tests/test_script.py': 'from scripts import helper'}

    def test_one_inventory_and_one_parse_per_source_version(self):
        sources = self.sources()
        sources['agent_tools/a.py'] = ('from agent_tools import b', 'VALUE = 1')
        with mock.patch.object(selector, '_inventory_indexes', wraps=selector._inventory_indexes) as inventory, mock.patch.object(ast, 'parse', wraps=ast.parse) as parse:
            result = selector.select_from_sources(sources, ['agent_tools/b.py'])
        self.assertEqual(1, inventory.call_count)
        self.assertEqual(len(sources) + 1, parse.call_count)
        self.assertEqual(('agent_tools.tests.test_a', 'agent_tools.tests.test_b'), result.modules)

    def test_script_ownership_does_not_reparse_test_sources(self):
        sources = self.sources()
        with mock.patch.object(ast, 'parse', wraps=ast.parse) as parse:
            result = selector.select_from_sources(sources, ['scripts/helper.py'])
        self.assertEqual(('agent_tools.tests.test_script',), result.modules)
        self.assertEqual(len(sources), parse.call_count)

    def test_owner_exclusion_keeps_ambiguous_other_alias(self):
        inventory = {'agent_tools/a/value.py', 'agent_tools/b/value.py'}
        self.assertEqual({'agent_tools/b/value.py'}, selector.dependencies('agent_tools/a/value.py', "FILE='value.py'", inventory))
        self.assertEqual({'agent_tools/a/value.py'}, selector.dependencies('agent_tools/b/value.py', "FILE='value.py'", inventory))

    def test_reverse_cycle_consumption_keeps_script_and_old_edges(self):
        sources = self.sources()
        sources['agent_tools/a.py'] = ('VALUE = 1', 'from agent_tools import b')
        result = selector.select_from_sources(sources, ['agent_tools/b.py', 'scripts/helper.py'])
        self.assertEqual(('agent_tools.tests.test_a', 'agent_tools.tests.test_b', 'agent_tools.tests.test_script'), result.modules)

    def test_error_order_stays_sorted_by_source(self):
        sources = self.sources() | {'agent_tools/z_bad.py': '(', 'agent_tools/c_bad.py': '('}
        with self.assertRaisesRegex(selector.SelectionError, 'Cannot analyze Python source: agent_tools/c_bad.py'):
            selector.select_from_sources(sources, ['agent_tools/b.py'])

    def test_invocations_rebuild_after_source_change(self):
        sources = self.sources()
        first = selector.select_from_sources(sources, ['agent_tools/b.py'])
        sources['agent_tools/a.py'] = 'VALUE = 1'
        second = selector.select_from_sources(sources, ['agent_tools/b.py'])
        self.assertEqual(('agent_tools.tests.test_a', 'agent_tools.tests.test_b'), first.modules)
        self.assertEqual(('agent_tools.tests.test_b',), second.modules)

    def test_reviewed_non_python_resource_preserves_syntax_bypass(self):
        path = 'agent_tools/tests/fixtures/resource.source'
        source = '('
        sources = {path: source, 'agent_tools/tests/test_resource.py': "FILE='resource.source'"}
        with mock.patch.dict(selector.REVIEWED_NON_PYTHON_RESOURCES, {path: hashlib.sha256(source.encode()).hexdigest()}):
            self.assertEqual(('agent_tools.tests.test_resource',), selector.select_from_sources(sources, [path]).modules)

    def test_real_git_removed_import_deleted_rename_and_missing_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(['git', '-C', directory, *args], stderr=subprocess.DEVNULL).decode().strip()
            git('init', '-q'); git('config', 'user.name', 'Selector test'); git('config', 'user.email', 'selector@example.invalid')
            for name, text in self.sources().items():
                target = root / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_text(text)
            git('add', '.'); git('commit', '-qm', 'baseline'); baseline = git('rev-parse', 'HEAD')
            (root / 'agent_tools/a.py').write_text('VALUE = 1')
            (root / 'agent_tools/b.py').rename(root / 'agent_tools/renamed.py')
            # The new path needs a real consumer; removed old imports still enroll.
            (root / 'agent_tools/tests/test_new.py').write_text('from agent_tools import renamed')
            result = selector.select(root, baseline)
            self.assertEqual(('agent_tools.tests.test_a', 'agent_tools.tests.test_b', 'agent_tools.tests.test_new'), result.modules)
            with self.assertRaises(selector.SelectionError):
                selector.select(root, 'missing-baseline')
            (root / 'agent_tools/renamed.py').write_bytes(b'\xff')
            with self.assertRaisesRegex(selector.SelectionError, 'not UTF-8'):
                selector.select(root, baseline)


if __name__ == '__main__':
    unittest.main()

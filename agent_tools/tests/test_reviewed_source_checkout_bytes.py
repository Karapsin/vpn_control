"""Real Windows-style Git checkout retains reviewed loader source authority."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import types
from unittest import mock
from agent_tools import affected_agent_tests as selector

ROOT = Path(__file__).resolve().parents[2]
REVIEWED_SOURCES = (
    'agent_tools/agent_test_runner.py',
    'agent_tools/android_installer_component_bundle.py',
    'agent_tools/tests/fixtures/historical_source.py',
)


# Complete original checkout caller; replayed against a real Git fixture below.
INVENTORY_TEST_BEFORE = (
    b'"""Real Windows-style Git checkout retains reviewed loader source authority."""\n'
    b'import hashlib\n'
    b'import json\n'
    b'import os\n'
    b'from pathlib import Path\n'
    b'import subprocess\n'
    b'import tempfile\n'
    b'import unittest\n'
    b'from agent_tools import affected_agent_tests as selector\n'
    b'\n'
    b'ROOT = Path(__file__).resolve().parents[2]\n'
    b'REVIEWED_SOURCES = (\n'
    b"    'agent_tools/agent_test_runner.py',\n"
    b"    'agent_tools/android_installer_component_bundle.py',\n"
    b"    'agent_tools/tests/fixtures/historical_source.py',\n"
    b')\n'
    b'\n'
    b'\n'
    b'class ReviewedSourceCheckoutBytesTests(unittest.TestCase):\n'
    b'    def test_actual_windows_checkout_preserves_bytes_and_loader_admission(self):\n'
    b"        attributes = Path(os.environ.get('REVIEWED_CHECKOUT_ATTRIBUTES', ROOT / '.gitattributes')).read_bytes()\n"
    b"        manifest = json.loads((ROOT / 'agent_tools/affected_agent_test_dependencies.json').read_bytes())\n"
    b"        inventory = set(subprocess.check_output(['git', '-C', str(ROOT), 'ls-files', '-z']).decode().split('\\0')) - {''}\n"
    b"        env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}\n"
    b"        env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)\n"
    b"        with tempfile.TemporaryDirectory(prefix='reviewed-source-checkout-') as directory:\n"
    b'            checkout = Path(directory)\n'
    b'            def git(*args):\n'
    b"                result = subprocess.run(['git', '-c', 'core.autocrlf=true', '-c', 'core.safecrlf=false', *args], cwd=checkout, env=env, capture_output=True, timeout=20)\n"
    b"                self.assertEqual(0, result.returncode, result.stderr.decode(errors='replace'))\n"
    b"            git('init', '--quiet')\n"
    b"            (checkout / '.gitattributes').write_bytes(attributes)\n"
    b'            expected = {}\n'
    b'            for name in REVIEWED_SOURCES:\n'
    b'                raw = (ROOT / name).read_bytes()\n'
    b"                self.assertIn(hashlib.sha256(raw).hexdigest(), manifest['loaders'][name]['sourceSha256'])\n"
    b'                target = checkout / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(raw)\n'
    b'                expected[name] = raw\n'
    b"            (checkout / 'unprotected.txt').write_bytes(b'LF control\\nnext line\\n')\n"
    b"            git('add', '--', '.gitattributes', 'unprotected.txt', *REVIEWED_SOURCES)\n"
    b"            for name in (*REVIEWED_SOURCES, 'unprotected.txt'):\n"
    b'                (checkout / name).unlink()\n'
    b"            git('checkout-index', '--all')\n"
    b"            self.assertEqual(b'LF control\\r\\nnext line\\r\\n', (checkout / 'unprotected.txt').read_bytes())\n"
    b'            for name in REVIEWED_SOURCES:\n'
    b"                # Actual dependency admission reproduces the Windows runner's\n"
    b'                # dynamic-import refusal before any byte comparison assertion.\n'
    b'                original_edges = selector.dependencies(name, selector.read_source(name, expected[name]), inventory)\n'
    b'                raw = (checkout / name).read_bytes()\n'
    b'                checkout_edges = selector.dependencies(name, selector.read_source(name, raw), inventory)\n'
    b'                self.assertEqual(original_edges, checkout_edges)\n'
    b'                self.assertEqual(expected[name], raw)\n'
    b"                self.assertIn(hashlib.sha256(raw).hexdigest(), manifest['loaders'][name]['sourceSha256'])\n"
    b'            name = REVIEWED_SOURCES[0]\n'
    b"            tampered = selector.read_source(name, expected[name]) + '\\n# modified loader authority\\n'\n"
    b"            with self.assertRaisesRegex(selector.SelectionError, 'Unresolved dynamic import'):\n"
    b'                selector.dependencies(name, tampered, inventory)\n'
    b'\n'
    b'    def test_attributes_changes_select_actual_source_consumers(self):\n'
    b"        sources = {'.gitattributes': None,\n"
    b'                   \'agent_tools/tests/test_checkout.py\': "from pathlib import Path\\nPath(\'.gitattributes\').read_bytes()",\n'
    b"                   'agent_tools/tests/test_other.py': 'pass'}\n"
    b"        self.assertEqual(('agent_tools.tests.test_checkout',), selector.select_from_sources(sources, {'.gitattributes'}).modules)\n"
    b'\n'
    b'\n'
    b"if __name__ == '__main__':\n"
    b'    unittest.main()\n'
)

def checkout_inventory(root):
    """Match production selection: tracked paths plus non-ignored untracked paths."""
    names = set(selector.git(root, "ls-files", "-z").decode().split("\0"))
    names.update(selector.git(root, "ls-files", "--others", "--exclude-standard", "-z").decode().split("\0"))
    return names - {""}

class ReviewedSourceCheckoutBytesTests(unittest.TestCase):
    def test_actual_windows_checkout_preserves_bytes_and_loader_admission(self):
        attributes = Path(os.environ.get('REVIEWED_CHECKOUT_ATTRIBUTES', ROOT / '.gitattributes')).read_bytes()
        manifest = json.loads((ROOT / 'agent_tools/affected_agent_test_dependencies.json').read_bytes())
        inventory = checkout_inventory(ROOT)
        env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
        with tempfile.TemporaryDirectory(prefix='reviewed-source-checkout-') as directory:
            checkout = Path(directory)
            def git(*args):
                result = subprocess.run(['git', '-c', 'core.autocrlf=true', '-c', 'core.safecrlf=false', *args], cwd=checkout, env=env, capture_output=True, timeout=20)
                self.assertEqual(0, result.returncode, result.stderr.decode(errors='replace'))
            git('init', '--quiet')
            (checkout / '.gitattributes').write_bytes(attributes)
            expected = {}
            for name in REVIEWED_SOURCES:
                raw = (ROOT / name).read_bytes()
                self.assertIn(hashlib.sha256(raw).hexdigest(), manifest['loaders'][name]['sourceSha256'])
                target = checkout / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(raw)
                expected[name] = raw
            (checkout / 'unprotected.txt').write_bytes(b'LF control\nnext line\n')
            git('add', '--', '.gitattributes', 'unprotected.txt', *REVIEWED_SOURCES)
            for name in (*REVIEWED_SOURCES, 'unprotected.txt'):
                (checkout / name).unlink()
            git('checkout-index', '--all')
            self.assertEqual(b'LF control\r\nnext line\r\n', (checkout / 'unprotected.txt').read_bytes())
            for name in REVIEWED_SOURCES:
                # Actual dependency admission reproduces the Windows runner's
                # dynamic-import refusal before any byte comparison assertion.
                original_edges = selector.dependencies(name, selector.read_source(name, expected[name]), inventory)
                raw = (checkout / name).read_bytes()
                checkout_edges = selector.dependencies(name, selector.read_source(name, raw), inventory)
                self.assertEqual(original_edges, checkout_edges)
                self.assertEqual(expected[name], raw)
                self.assertIn(hashlib.sha256(raw).hexdigest(), manifest['loaders'][name]['sourceSha256'])
            name = REVIEWED_SOURCES[0]
            tampered = selector.read_source(name, expected[name]) + '\n# modified loader authority\n'
            with self.assertRaisesRegex(selector.SelectionError, 'Unresolved dynamic import'):
                selector.dependencies(name, tampered, inventory)

    def test_attributes_changes_select_actual_source_consumers(self):
        sources = {'.gitattributes': None,
                   'agent_tools/tests/test_checkout.py': "from pathlib import Path\nPath('.gitattributes').read_bytes()",
                   'agent_tools/tests/test_other.py': 'pass'}
        self.assertEqual(('agent_tools.tests.test_checkout',), selector.select_from_sources(sources, {'.gitattributes'}).modules)

    def test_whole_before_tracked_only_red_current_untracked_module_green(self):
        self.assertEqual('33d128ac0bbd7d6b5b900d9545feb33fe8c0a8426038fee38c6d4f5af4fefebe',
                         hashlib.sha256(INVENTORY_TEST_BEFORE).hexdigest())
        before = types.ModuleType('_reviewed_inventory_before')
        before.__file__ = __file__
        exec(compile(INVENTORY_TEST_BEFORE, '<complete-original-checkout-test>', 'exec'), before.__dict__)
        inventory = checkout_inventory(ROOT)
        required = set(REVIEWED_SOURCES) | {'.gitattributes', 'agent_tools/affected_agent_test_dependencies.json'}
        for name in REVIEWED_SOURCES:
            required.update(selector.dependencies(name, selector.read_source(name, (ROOT / name).read_bytes()), inventory))
        untracked = 'agent_tools/readiness.py'
        self.assertIn(untracked, required)
        with tempfile.TemporaryDirectory(prefix='reviewed-untracked-inventory-') as directory:
            root = Path(directory)
            env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
            env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
            def git(*args, good=True):
                value = subprocess.run(['git', '-C', str(root), *args], env=env, capture_output=True, timeout=20)
                self.assertEqual(good, value.returncode == 0, value.stderr.decode(errors='replace'))
                return value.stdout
            git('init', '--quiet')
            for name in required:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((ROOT / name).read_bytes())
            ignored = 'agent_tools/ignored_fixture_module.py'
            (root / '.gitignore').write_text('/' + ignored + '\n')
            (root / ignored).write_bytes(b'raise AssertionError("must not enter inventory")\n')
            # Establish a genuine index while the new required module remains
            # untracked throughout RED, GREEN and closing checks.
            git('add', '--', '.gitignore', *sorted(required - {untracked}))
            git('ls-files', '--error-unmatch', untracked, good=False)
            before.ROOT = root
            name = 'test_actual_windows_checkout_preserves_bytes_and_loader_admission'
            red = unittest.TestResult()
            before.ReviewedSourceCheckoutBytesTests(name).run(red)
            self.assertFalse(red.failures)
            self.assertEqual(1, len(red.errors))
            self.assertIn('Declared dependency is unavailable: ' + untracked, red.errors[0][1])
            with mock.patch(__name__ + '.ROOT', root):
                green = unittest.TestResult()
                ReviewedSourceCheckoutBytesTests(name).run(green)
                self.assertTrue(green.wasSuccessful(), green.failures + green.errors)
                admitted = checkout_inventory(root)
                self.assertIn(untracked, admitted)
                self.assertNotIn(ignored, admitted)
                with self.assertRaisesRegex(selector.SelectionError, 'Declared dependency is unavailable: agent_tools/readiness.py'):
                    consumer = 'agent_tools/android_installer_component_bundle.py'
                    selector.dependencies(consumer, selector.read_source(consumer,
                                          (root / consumer).read_bytes()), admitted - {untracked})
            git('ls-files', '--error-unmatch', untracked, good=False)


if __name__ == '__main__':
    unittest.main()

"""Real Windows-style Git checkout retains reviewed loader source authority."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from agent_tools import affected_agent_tests as selector

ROOT = Path(__file__).resolve().parents[2]
REVIEWED_SOURCES = (
    'agent_tools/agent_test_runner.py',
    'agent_tools/android_installer_component_bundle.py',
    'agent_tools/tests/fixtures/historical_source.py',
)


class ReviewedSourceCheckoutBytesTests(unittest.TestCase):
    def test_actual_windows_checkout_preserves_bytes_and_loader_admission(self):
        attributes = Path(os.environ.get('REVIEWED_CHECKOUT_ATTRIBUTES', ROOT / '.gitattributes')).read_bytes()
        manifest = json.loads((ROOT / 'agent_tools/affected_agent_test_dependencies.json').read_bytes())
        inventory = set(subprocess.check_output(['git', '-C', str(ROOT), 'ls-files', '-z']).decode().split('\0')) - {''}
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


if __name__ == '__main__':
    unittest.main()

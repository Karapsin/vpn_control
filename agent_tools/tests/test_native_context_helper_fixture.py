"""Real authenticated-helper loading in old/current isolated native fixtures."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import types
import unittest

from agent_tools.tests import test_native_execution_context as current

FIXTURE = Path(__file__).with_name('fixtures')/'native_context_helper_fixture'
PROGRAM = """import sys
sys.path.insert(0,sys.argv[1])
from agent_tools import ssh_transport
helper=ssh_transport._automatic_module()._private_config()
assert callable(helper.PrivateConfigCustody)
"""


@unittest.skipUnless(os.name == 'posix', 'Local Git/private source fixture')
class NativeContextHelperFixtureTests(unittest.TestCase):
    def test_complete_before_omits_bound_helper_actual_red_current_authenticated_bytes_green(self):
        provenance = json.loads((FIXTURE/'provenance.json').read_bytes())
        for name, digest in provenance['files'].items():
            self.assertEqual(digest, hashlib.sha256((FIXTURE/name).read_bytes()).hexdigest())
        path = FIXTURE/'before.source'
        old = types.ModuleType('agent_tools.tests._native_context_helper_before')
        # The actual fixture resolves its checkout root from its source path.
        old.__file__ = current.__file__
        old.__package__ = 'agent_tools.tests'
        exec(compile(path.read_bytes(), str(path), 'exec'), old.__dict__)
        for module, red in ((old, True), (current, False)):
            case = module.NativeExecutionContextTest('test_native_used_tool_change_still_requires_requalification')
            try:
                case.setUp()
                child = subprocess.run([sys.executable, '-I', '-B', '-c', PROGRAM, str(case.native)],
                                       capture_output=True, text=True, timeout=15)
                if red:
                    self.assertNotEqual(0, child.returncode)
                    self.assertIn('FileNotFoundError', child.stderr)
                    self.assertIn('private_config_custody.py', child.stderr)
                else:
                    self.assertEqual(0, child.returncode, child.stderr)
            finally:
                case.doCleanups()


if __name__ == '__main__':
    unittest.main()

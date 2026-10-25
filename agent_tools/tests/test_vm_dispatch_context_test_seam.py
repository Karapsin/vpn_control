"""Complete old/current real SourceSession test at controlled socket boundaries."""
import hashlib
import json
import os
from pathlib import Path
import types
import unittest

from agent_tools.tests import test_readiness_vm_dispatch as current

FIXTURE = Path(__file__).with_name('fixtures')/'vm_dispatch_context_test_seam'
METHOD = 'test_real_source_request_preserves_context_manager_and_closes_capability'


@unittest.skipUnless(os.name == 'posix', 'owned SSH master and controlled provider sockets')
class VmDispatchContextTestSeamTests(unittest.TestCase):
    def test_complete_before_expects_foreign_adoption_current_refuses_and_checks_owned_capability(self):
        provenance = json.loads((FIXTURE/'provenance.json').read_bytes())
        for name, digest in provenance['files'].items():
            self.assertEqual(digest, hashlib.sha256((FIXTURE/name).read_bytes()).hexdigest())
        path = FIXTURE/'before.source'
        old = types.ModuleType('agent_tools.tests._vm_dispatch_context_test_before')
        old.__file__ = str(path)
        old.__package__ = 'agent_tools.tests'
        exec(compile(path.read_bytes(), str(path), 'exec'), old.__dict__)
        for module, red in ((old, True), (current, False)):
            case = module.VmDispatchTests(METHOD)
            try:
                case.setUp()
                if red:
                    with self.assertRaisesRegex(ValueError, 'foreign_adapter_context'):
                        getattr(case, METHOD)()
                else:
                    getattr(case, METHOD)()
                self.assertEqual([], case.children)
                self.assertEqual([], case.provider.effects)
                self.assertEqual(0, case.provider.observe_calls)
            finally:
                case.doCleanups()


if __name__ == '__main__':
    unittest.main()

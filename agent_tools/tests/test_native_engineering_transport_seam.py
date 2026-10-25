"""Complete old/current frozen engineering caller with inert transport effects."""
import hashlib
import json
import os
from pathlib import Path
import types
import unittest

from agent_tools.tests import test_native_engineering_tmux_future as current

FIXTURE = Path(__file__).with_name('fixtures')/'native_engineering_transport_seam'
METHOD = 'test_actual_loaded_frozen_resource_driver_preflight_submit_readonly_and_mutation_fences'


@unittest.skipUnless(os.name == 'posix', 'Local frozen producer private journals')
class EngineeringTransportSeamTests(unittest.TestCase):
    def test_complete_before_empty_transport_red_current_v2_record_green(self):
        provenance = json.loads((FIXTURE/'provenance.json').read_bytes())
        for name, digest in provenance['files'].items():
            self.assertEqual(digest, hashlib.sha256((FIXTURE/name).read_bytes()).hexdigest())
        path = FIXTURE/'before.source'
        old = types.ModuleType('agent_tools.tests._engineering_transport_seam_before')
        old.__file__ = str(path)
        old.__package__ = 'agent_tools.tests'
        exec(compile(path.read_bytes(), str(path), 'exec'), old.__dict__)
        for module, red in ((old, True), (current, False)):
            case = module.FutureFrozenTmuxTest(METHOD)
            try:
                case.setUp()
                if red:
                    with self.assertRaisesRegex(AssertionError, 'submission-response-lost'):
                        getattr(case, METHOD)()
                else:
                    getattr(case, METHOD)()
            finally:
                case.doCleanups()


if __name__ == '__main__':
    unittest.main()

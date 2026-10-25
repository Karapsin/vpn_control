"""Replay complete old/current target-routing tests against the real MCP gate."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

from agent_tools import mcp_server
from agent_tools import windows_credential_probe_ssh as probe
from agent_tools.tests import test_native_mcp_routes as current

FIXTURE = Path(__file__).parent / 'fixtures/native_mcp_environment_seam'
METHODS = (
    'test_windows_probe_routes_only_configured_identity_and_deadline',
    'test_credential_recovery_routes_exclude_secrets_and_unconfigured_commands',
)


class NativeMcpEnvironmentTestSeamTests(unittest.TestCase):
    def test_whole_old_missing_environment_errors_current_exact_target_and_original_status_pass(self):
        provenance = json.loads((FIXTURE / 'provenance.json').read_bytes())
        self.assertEqual(1, provenance['schemaVersion'])
        self.assertEqual({'before.source', 'actual-failure.txt', 'bypassed_admission.before.source',
                          'bypassed-admission-failure.txt'}, set(provenance['files']))
        for name, digest in provenance['files'].items():
            self.assertEqual(digest, hashlib.sha256((FIXTURE / name).read_bytes()).hexdigest())
        before = []
        for name in ('before.source', 'bypassed_admission.before.source'):
            old = types.ModuleType('agent_tools.tests._native_environment_test_' + name.split('.')[0])
            old.__file__ = current.__file__
            old.__package__ = 'agent_tools.tests'
            sys.modules[old.__name__] = old
            self.addCleanup(sys.modules.pop, old.__name__, None)
            exec(compile((FIXTURE / name).read_bytes(), str(FIXTURE / name), 'exec'), old.__dict__)
            before.append(old)
        # Frozen old setUp predates the private REPO_ROOT seam; failed or unknown
        # synthetic routes must not enter the checkout's TEST-001 failure ledger.
        root = tempfile.TemporaryDirectory(); self.addCleanup(root.cleanup)
        for method in METHODS:
            for module, red in ((before[0], 'missing_target'), (before[1], 'bypassed_admission'), (current, None)):
                with self.subTest(method=method, before=red), \
                     mock.patch.object(mcp_server, 'REPO_ROOT', Path(root.name).resolve()), \
                     mock.patch.object(probe, '_private_secret', side_effect=AssertionError('private-input boundary')) as private, \
                     mock.patch.object(probe, '_run_ssh', side_effect=AssertionError('SSH boundary')) as remote:
                    result = unittest.TestResult()
                    module.NativeRoutesTest(method).run(result)
                    if red == 'missing_target':
                        self.assertEqual([], result.failures)
                        self.assertEqual(1, len(result.errors))
                        self.assertIn("KeyError: 'state'", result.errors[0][1])
                    elif red == 'bypassed_admission':
                        self.assertEqual([], result.errors)
                        self.assertEqual(1, len(result.failures))
                        self.assertIn('AssertionError', result.failures[0][1])
                    else:
                        self.assertTrue(result.wasSuccessful(), str(result.errors) + str(result.failures))
                    private.assert_not_called()
                    remote.assert_not_called()


if __name__ == '__main__':
    unittest.main()

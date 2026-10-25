"""Finite whole-Proxy high-descriptor and drop-observation regressions; owned loopback only."""
import ast
import hashlib
import json
import os
from pathlib import Path
import sys
from types import ModuleType
import unittest

FIXTURE = Path(__file__).parent / 'fixtures/ssh_proxy_high_descriptors'
PROVENANCE_SHA = 'acd3de91861f4dc140ab05b2f7c21adabb4097dbf7092a6079b73cc550609e63'
FILES = ['controlled-high-fd.actual.json', 'controller.5011.before.source', 'controller.a088.before.source', 'controller.drop_observation_candidate.source', 'controller.selector_candidate.source', 'native-select-phase.json', 'test_proxy_high_descriptors.py']


def authenticated_fixture():
    raw = (FIXTURE / 'provenance.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROVENANCE_SHA:
        raise AssertionError('proxy fixture provenance changed: expected ' + PROVENANCE_SHA + ', actual ' + hashlib.sha256(raw).hexdigest())
    value = json.loads(raw)
    if value['schemaVersion'] != 1 or set(value['files']) != set(FILES):
        raise AssertionError('finite proxy fixture scope changed: ' + json.dumps({'schemaVersion': value['schemaVersion'], 'files': sorted(value['files']), 'expected': FILES}))
    for name in FILES:
        actual = hashlib.sha256((FIXTURE / name).read_bytes()).hexdigest()
        if actual != value['files'][name]:
            raise AssertionError('proxy fixture bytes changed: ' + name + ' expected ' + value['files'][name] + ', actual ' + actual)


authenticated_fixture()
if os.name == 'posix':
    _path = FIXTURE / 'test_proxy_high_descriptors.py'
    _module = ModuleType('_routine_proxy_high_descriptors')
    _module.__file__ = str(_path.resolve())
    _module.__package__ = None
    sys.modules[_module.__name__] = _module
    exec(compile(_path.read_bytes(), str(_path), 'exec'), _module.__dict__)
    ProxyObservationTests = _module.ProxyObservationTests
    HighDescriptorTests = _module.HighDescriptorTests
else:
    @unittest.skip('POSIX coordinator descriptor and proxy qualification')
    class ProxyObservationTests(unittest.TestCase):
        def test_supported_platform(self):
            pass


class NativePhaseEvidenceTests(unittest.TestCase):
    def test_original_diagnostic_phase_and_controlled_causal_scope_are_distinct(self):
        authenticated_fixture()
        native = json.loads((FIXTURE / 'native-select-phase.json').read_bytes())
        controlled = json.loads((FIXTURE / 'controlled-high-fd.actual.json').read_bytes())
        self.assertEqual('native-diagnostic-observation-only-not-replay-or-idle-authority', native['recordType'])
        self.assertEqual('5011866be6fb1b384f3af0ed0e0c8d053ddc0ea0aeae3478fb76436ab80b7d0f', native['nativeControllerSha256'])
        rows = native['originalPhaseMetadata']['attempts']
        self.assertEqual(3, len(rows))
        for row in rows:
            self.assertEqual(('connected', 'select', 'value-error', 0, 0),
                             (row['connectPhase'], row['forwardPhase'], row['forwardErrorClass'],
                              row['clientReadBytes'], row['upstreamReadBytes']))
        self.assertTrue(native['sourceClosing'] and native['allParentDescriptorsClosed'] and native['actorsAbsent'])
        self.assertEqual('UNKNOWN; no retroactive attribution', native['prior9e3Cause'])
        self.assertTrue(controlled['before']['valueError'])
        self.assertGreaterEqual(min(controlled['before']['inputDescriptors']), 1024)
        self.assertTrue(controlled['fixed']['bidirectional'] and controlled['fixed']['halfClosePreserved'])
        self.assertEqual(0, controlled['externalNetworkCalls'])


class DropObservationEvidenceTests(unittest.TestCase):
    def test_ci_failure_binds_whole_unfixed_candidate_and_fix_changes_only_drop_once(self):
        authenticated_fixture()
        value = json.loads((FIXTURE / 'provenance.json').read_bytes())['dropObservation']
        failure = value['originalFailure']
        self.assertIs(False, value['nativeFailureClaimed'])
        self.assertEqual((40187427911, 'cc2873b5ed0ada7b09c24e854539c85660a627c2'), (failure['run'], failure['headSha']))
        self.assertEqual(failure['traceSha256'], hashlib.sha256(('\n'.join(failure['trace']) + '\n').encode()).hexdigest())
        self.assertEqual('AssertionError: bounded controlled loopback observation timeout', failure['trace'][-1], failure['trace'])
        parts = {}
        for role in ('beforeimage', 'fixed'):
            raw = (FIXTURE / value[role]['file']).read_bytes()
            self.assertEqual(value[role]['sha256'], hashlib.sha256(raw).hexdigest(), role)
            tree = ast.parse(raw)
            proxy = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'Proxy')
            drop = next(n for n in proxy.body if isinstance(n, ast.FunctionDef) and n.name == 'drop_once')
            parts[role] = ([ast.dump(n) for n in tree.body if n is not proxy] + [ast.dump(n) for n in proxy.body if n is not drop],
                           [ast.unparse(n) for n in drop.body])
        # The complete controller is unchanged except that drop_once no longer closes the
        # forward thread's registered sockets after shutting them down.
        self.assertEqual(parts['beforeimage'][0], parts['fixed'][0])
        before, fixed = parts['beforeimage'][1], parts['fixed'][1]
        self.assertEqual((before[:-1], before[-1].replace('\n    s.close()', '')), (fixed[:-1], fixed[-1]), (before, fixed))
        self.assertIn('\n    s.close()', before[-1], before)


if __name__ == '__main__':
    unittest.main()

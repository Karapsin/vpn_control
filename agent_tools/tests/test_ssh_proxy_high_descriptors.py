"""Finite whole-Proxy high-descriptor regressions; owned loopback only."""
import hashlib
import json
import os
from pathlib import Path
import sys
from types import ModuleType
import unittest

FIXTURE = Path(__file__).parent / 'fixtures/ssh_proxy_high_descriptors'
PROVENANCE_SHA = '872453c7b71bb95b39732fb97430ceff3160f243d1cf7a0ae27dd9c37c2a96f9'
FILES = ['controlled-high-fd.actual.json', 'controller.5011.before.source', 'controller.a088.before.source', 'controller.selector_candidate.source', 'native-select-phase.json', 'test_proxy_high_descriptors.py']


def authenticated_fixture():
    raw = (FIXTURE / 'provenance.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROVENANCE_SHA:
        raise AssertionError('proxy fixture provenance changed')
    value = json.loads(raw)
    if value['schemaVersion'] != 1 or set(value['files']) != set(FILES):
        raise AssertionError('finite proxy fixture scope changed')
    for name in FILES:
        if hashlib.sha256((FIXTURE / name).read_bytes()).hexdigest() != value['files'][name]:
            raise AssertionError('proxy fixture bytes changed: ' + name)


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


if __name__ == '__main__':
    unittest.main()

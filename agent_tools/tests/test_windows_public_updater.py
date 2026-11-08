"""Finite whole-body portable controls on exact reviewed source bytes.

These tests use declared process/file/QGA peers. They do not execute Windows,
PowerShell, C#, sockets, native APIs, installers, or external network operations.
Original complete test bodies and causal beforeimages are retained as fixtures.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import os
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'windows_public_updater'
ROWS = {'agent_tools/tests/fixtures/windows_public_updater/before/v1/update_fixture_server.py': 'f9b75bdd589f838f7616b488fbbf5fb0d956e9c1d406e86e51061370088276dd', 'agent_tools/tests/fixtures/windows_public_updater/before/v1/update_receipts.py': 'e52cfa5ff0eb115e3f86e853796e38d77c230a397b224b7a0c6099e5602bd437', 'agent_tools/tests/fixtures/windows_public_updater/current_body.py': 'd25b1bb6f2e41699294740498772dab495e5ccca7c4429eae3b58488764a89cf', 'agent_tools/tests/fixtures/windows_public_updater/originals/test_private_update.py.source': '4787130ab6b953c750fea371a00980e23f80789ec77b75c236677ee658897475', 'agent_tools/windows_public_updater/native_collector.py': '246bb5e7110fe5fdad986e3cf082683934070195098730bf79ab86e0fd0296b2', 'agent_tools/windows_public_updater/update_cases.py': '17ecb2f41b42a3988f6905fe6a426935564a48e17e776efe7c3a9dbf4f668f5c', 'agent_tools/windows_public_updater/update_fixture_server.py': '507b8fe1e0c3ca8d8e327f0e49312f6040cfc6577154341dbcc3a21badc86c0e', 'agent_tools/windows_public_updater/update_receipts.py': '5e2e406b82d4a446ab971f27918b3b0f110e67e3eb8cae971b0bfe4256aa71ec'}
_held = {}
_modules = {}
CAUSAL_RESULTS = {}

def _generation(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def _guard():
    for relative, (stream, opening, expected, raw) in _held.items():
        path = ROOT / relative
        if _generation(os.fstat(stream.fileno())) != opening or _generation(path.stat()) != opening:
            raise ValueError('routine-source-generation-drift:' + relative)
        stream.seek(0)
        if hashlib.sha256(stream.read()).hexdigest() != expected:
            raise ValueError('routine-source-bytes-drift:' + relative)

def _open_sources():
    for relative, expected in ROWS.items():
        path = ROOT / relative
        stream = path.open('rb')
        opening = _generation(os.fstat(stream.fileno()))
        raw = stream.read()
        if hashlib.sha256(raw).hexdigest() != expected or _generation(path.stat()) != opening:
            stream.close()
            raise ValueError('routine-source-admission:' + relative)
        _held[relative] = (stream, opening, expected, raw)
    _guard()

def _load_source(path, expected=None):
    relative = str(path.relative_to(ROOT)).replace(os.sep, '/')
    if relative not in ROWS or (expected is not None and ROWS[relative] != expected):
        raise ValueError('undeclared-routine-source:' + relative)
    _guard()
    if relative in _modules:
        return _modules[relative]
    raw = _held[relative][3]
    name = __name__ + '._source_' + hashlib.sha256(relative.encode()).hexdigest()[:16]
    value = types.ModuleType(name)
    value.__file__ = str(path)
    value.__package__ = name.rpartition('.')[0]
    value._canonical_root = ROOT
    value._fixture_root = FIXTURES
    value._load_source = _load_source
    sys.modules[name] = value
    _modules[relative] = value
    exec(compile(raw, str(path), 'exec', dont_inherit=True), value.__dict__)
    _guard()
    return value

def _pair(case, label, before, current):
    observations = {}
    for phase, factory in (('before', before), ('current', current)):
        result = unittest.TestResult()
        factory().run(result)
        observations[phase] = {'testsRun': result.testsRun,
            'failures': [text for _, text in result.failures],
            'errors': [text for _, text in result.errors], 'skipped': result.skipped,
            'expectedFailures': len(result.expectedFailures),
            'unexpectedSuccesses': len(result.unexpectedSuccesses)}
    CAUSAL_RESULTS[label] = observations
    case.assertEqual((observations['before']['testsRun'], len(observations['before']['failures']),
        len(observations['before']['errors']), observations['before']['skipped'],
        observations['before']['expectedFailures'], observations['before']['unexpectedSuccesses']),
        (1, 1, 0, [], 0, 0), label + ': authentic before must fail the same assertion')
    case.assertEqual((observations['current']['testsRun'], len(observations['current']['failures']),
        len(observations['current']['errors']), observations['current']['skipped'],
        observations['current']['expectedFailures'], observations['current']['unexpectedSuccesses']),
        (1, 0, 0, [], 0, 0), label + ': current must pass the same oracle')

class _SourceBoundSuite(unittest.TestSuite):
    def run(self, result, debug=False):
        _guard()
        try:
            return super().run(result, debug)
        finally:
            try:
                _guard()
            finally:
                for stream, _, _, _ in _held.values():
                    stream.close()

_open_sources()

BODY = _load_source(FIXTURES / 'current_body.py')

class UpdaterCausalPairs(unittest.TestCase):
    def test_false_close_retains_original_guard_custody(self):
        original = _load_source(FIXTURES / 'before/v1/update_receipts.py')
        def oracle(module):
            class SameOracle(unittest.TestCase):
                def runTest(self):
                    with patch.object(BODY, 'r', module):
                        BODY.AppLeaseTests('test_native_false_close_never_retires_guard_custody').debug()
            return SameOracle()
        _pair(self, 'native-false-close', lambda: oracle(original), lambda: oracle(BODY.r))

    def test_fixture_unexpected_error_prevents_known_closure(self):
        original = _load_source(FIXTURES / 'before/v1/update_fixture_server.py')
        def oracle(module):
            class SameOracle(unittest.TestCase):
                def runTest(self):
                    with patch.object(BODY, 's', module):
                        BODY.AssetResponseTests('test_unexpected_fixture_error_prevents_known_closure').debug()
            return SameOracle()
        _pair(self, 'fixture-unexpected-error', lambda: oracle(original), lambda: oracle(BODY.s))

def load_tests(loader, tests, pattern):
    return _SourceBoundSuite([loader.loadTestsFromModule(BODY),
        loader.loadTestsFromTestCase(UpdaterCausalPairs)])

if __name__ == '__main__':
    unittest.main()

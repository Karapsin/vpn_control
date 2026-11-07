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
import subprocess
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'windows_system_collector'
ROWS = {'agent_tools/tests/fixtures/windows_system_collector/before/duplicate-child-raw-save/collector_wrapper.py': '41c427cc2eecb38218e219a84a82e6562daad49ff766c2bc532b5f03b95799de', 'agent_tools/tests/fixtures/windows_system_collector/before/ready-read-sharing/system_collector_worker.py': '052bf280609d72d269d855f26ddd2116d33ccedc54ce5bb077e3f80b24d801cf', 'agent_tools/tests/fixtures/windows_system_collector/before/v2/collector_body.py': 'eaeedc92d50fe51c59018c57795a29e05126aaeab567b0f9a4b9c441cd3bccc8', 'agent_tools/tests/fixtures/windows_system_collector/before/v2/collector_contract.py': '3b7148670ff88675dfcded83786290973160607fa4d647bb6250d1c3a494005d', 'agent_tools/tests/fixtures/windows_system_collector/before/v2/collector_wrapper.py': '02552ddbcf1e10c0fa1c770aa75d48aef1526e014fe41ea590cfd515af572b32', 'agent_tools/tests/fixtures/windows_system_collector/before/v2/ordinary_task_guard.ps1': '8105ad57f5140e6caef6fd21848f34d1684a00ca7c9e54ce64908211260844c1', 'agent_tools/tests/fixtures/windows_system_collector/before/v2/system_bootstrap_template.ps1': 'f1bf692804e149c2474ec854f463f6808f6bc3061793f9fffb8e84cb6c2700ea', 'agent_tools/tests/fixtures/windows_system_collector/before/v2/system_collector_native.cs': 'de48e24ca998ed30f480f130f9b8cf3cf610a86c31408d0abf144947f2264d70', 'agent_tools/tests/fixtures/windows_system_collector/before/v2/system_collector_worker.py': 'd3ab44e9a7d5cd521069f407ffbf7c6a33cae3e237b48cb5dc0750ffecc4bb9a', 'agent_tools/tests/fixtures/windows_system_collector/before/v3/collector_contract.py': '4633fcb10e815868c5d112e47a7a78053412435744242aabbfc18b8b8c10f619', 'agent_tools/tests/fixtures/windows_system_collector/before/v4/collector_contract.py': 'c500a3e3302297a8a90865b62d3f12d65cc33f68edfb386043588a2233642b1e', 'agent_tools/tests/fixtures/windows_system_collector/causal_body.py': '7a0d528d662ea4de63a691d44042cc9da02ff59eba6b99a6d74b3bad64946489', 'agent_tools/tests/fixtures/windows_system_collector/current_caller_body.py': 'cb1ad01692e792492f29e6f76c9f32074ae16f4136b5ab61659eae8b97554d5a', 'agent_tools/tests/fixtures/windows_system_collector/current_collector_body.py': 'e923c6deab7cf358dc8f4eeeea10ef9a3c1276422d0e669848b07d314ac36bc2', 'agent_tools/tests/fixtures/windows_system_collector/current_final_body.py': '8cfdb13519dfe50a7c810d6d0d2a6412cbb88beafa2fcb21944db2ef73798c23', 'agent_tools/tests/fixtures/windows_system_collector/originals/causal_controls.py.source': 'f6467ffb4c4ec3d05d1a00a3cd37a7f1bd06456339f0a2d675d35ebafad3447f', 'agent_tools/tests/fixtures/windows_system_collector/originals/test_caller_hold.py.source': 'f810787ae350221aaa9af5ad40768d9a22f54c7a4eefdb05317ebd61f2c199ea', 'agent_tools/tests/fixtures/windows_system_collector/originals/test_final_hold_guard.py.source': 'f89455652794f82febd493ba0fb8dd9a8c3b70b42ced4af0d4e0e5f204bd2fb6', 'agent_tools/tests/fixtures/windows_system_collector/originals/test_private_collector.py.source': '8ce287fc351048453eb7a16b887e08f4eb1dface72688eb7e1bb6ced7e29b5fe', 'agent_tools/tests/fixtures/windows_system_collector/originals/test_private_collector_v2.py.source': '9a24489726d579322b83f407ec82292095304c339fcb736d40b2df42a28e9568', 'agent_tools/windows_artifact_transfer.py': '2938a7c6c25d23adc9683ced126fe2d3c0a88614dab59a7b134a624d6f8b0ee8', 'agent_tools/windows_ordinary_task_owner.ps1': 'ba9afe8db7e35b18c380327534a884f3e284a11ff5f7bffb660685dc4dca86b6', 'agent_tools/windows_public_updater/native_collector.py': '246bb5e7110fe5fdad986e3cf082683934070195098730bf79ab86e0fd0296b2', 'agent_tools/windows_public_updater/update_receipts.py': '5e2e406b82d4a446ab971f27918b3b0f110e67e3eb8cae971b0bfe4256aa71ec', 'agent_tools/windows_qga_transfer.py': 'bf05c8f08c1e5210ba79ffb59186206e80dc13fef057748dab3596df8ab6f022', 'agent_tools/windows_system_collector/caller_hold.py': '0ccae3314fc03765c0568417531486ede523c7ea3aeecf22829d2d08fdd2da44', 'agent_tools/windows_system_collector/collector_contract.py': '73e085f69894421e0cf22b0eeff7770a0bbbb739144016c4a2a1be23382db317', 'agent_tools/windows_system_collector/collector_wrapper.py': 'ed27de044cbaf3aa5f77e47674b2fa3fcfb71b0385c8bfef15a4bf5d1c103d22', 'agent_tools/windows_system_collector/hold_protocol.py': 'b8dac389ad80345109d6e8678c45347224ef2c6c9da634ccbe82ab6ac3a064ad', 'agent_tools/windows_system_collector/native_primitives.py': 'ee28050bd0e33166956cc4f4ac68ca10cc89c30c01ae93468379895fee268a18', 'agent_tools/windows_system_collector/ordinary_task_guard.ps1': '8105ad57f5140e6caef6fd21848f34d1684a00ca7c9e54ce64908211260844c1', 'agent_tools/windows_system_collector/release_template.ps1': 'e80512879ca619639bddff758186eadfeca74cf738552946c3b1dc7cf77c24aa', 'agent_tools/windows_system_collector/system_bootstrap_template.ps1': '3cc5d478426f0e9e8b248580c452580559590a856209ae6737d315267af4eace', 'agent_tools/windows_system_collector/system_collector_native.cs': '88ad6bbbf8b309bb641017d035bdf6688d37ac5d6e506bcffd4122203850a955', 'agent_tools/windows_system_collector/system_collector_worker.py': '2d7abfe107eb7fe8683be6e22413126453a27c5574a5a343bdc2484d88dc720a', 'scripts/windows_broker_fixture_observer.py': '6d08edf9e57b09e98ce80d414b2ac12da4f39eb82e27cd2a3f06d9f900e04dcb', 'agent_tools/tests/fixtures/windows_system_collector/oracle_interpreter_guard.py': '1c3c4acbcf88ec35d8ee27af7c53196d85694269725e34b6a4a9946d14bc5407', 'agent_tools/tests/fixtures/windows_system_collector/oracle-cleanup.before.source': 'a7d3e8f0e8dd68f23a88f7620296d01d29c8cd626e16a7bd5b1fe6f7836d8233', 'agent_tools/tests/fixtures/windows_system_collector/oracle-cleanup.provenance.json': 'd1b9bcb284ca60c0cf02f90ad34184c50520a3ffc197eb9b5ae249d6ae0f74c2'}
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

BODY = _load_source(FIXTURES / 'current_collector_body.py')
CALLER = _load_source(FIXTURES / 'current_caller_body.py')
FINAL = _load_source(FIXTURES / 'current_final_body.py')
CAUSAL = _load_source(FIXTURES / 'causal_body.py')

class _OwnedOracleResult(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.exceptions = []
    def addFailure(self, test, error):
        super().addFailure(test, error)
        self.exceptions.append(error)
    def addError(self, test, error):
        super().addError(test, error)
        self.exceptions.append(error)
    def addSubTest(self, test, subtest, error):
        super().addSubTest(test, subtest, error)
        if error is not None:
            self.exceptions.append(error)


def _run_owned_oracle(case):
    result = _OwnedOracleResult()
    case.run(result)
    if len(result.exceptions) > 1:
        raise BaseExceptionGroup('owned oracle body/cleanup failures',
            [error.with_traceback(traceback) for _, error, traceback in result.exceptions])
    if result.exceptions:
        _, error, traceback = result.exceptions[0]
        raise error.with_traceback(traceback)
    if not result.wasSuccessful() or result.skipped or result.expectedFailures or result.unexpectedSuccesses:
        raise RuntimeError('owned-oracle-incomplete-or-unexpected-outcome')


class CollectorCausalPairs(unittest.TestCase):
    def _fixed_source_pair(self, cause):
        def oracle(source):
            class SameOracle(unittest.TestCase):
                def runTest(self):
                    with patch.object(CAUSAL, 'CAUSE', cause), patch.object(CAUSAL, 'SOURCE', source):
                        _run_owned_oracle(CAUSAL.Controls('test_known_original_close_is_not_lost_by_raw_or_policy_boundary'))
            return SameOracle()
        _pair(self, cause, lambda: oracle('before'), lambda: oracle('current'))

    def test_duplicate_child_raw_save(self):
        self._fixed_source_pair('duplicate-raw-save')

    def test_ready_read_sharing(self):
        self._fixed_source_pair('ready-read-sharing')

    def test_protected_file_policy(self):
        self._fixed_source_pair('protected-file-policy')

    def test_original_live_caller_barrier(self):
        def oracle(source):
            class SameOracle(unittest.TestCase):
                def runTest(self):
                    with patch.object(CALLER, 'BARRIER_SOURCE', source):
                        _run_owned_oracle(CALLER.BarrierCausalControl('test_original_v2_guard_sees_live_driver_through_system_closure'))
            return SameOracle()
        _pair(self, 'original-live-barrier', lambda: oracle('before'), lambda: oracle('held'))

    def test_final_update_stage_requires_caller_hold(self):
        def oracle(before):
            class SameOracle(unittest.TestCase):
                def runTest(self):
                    with patch.object(FINAL, 'BEFORE', before):
                        _run_owned_oracle(FINAL.FinalStageHoldTests('test_final_update_cleanup_refuses_missing_hold_before_effect'))
            return SameOracle()
        _pair(self, 'final-stage-hold', lambda: oracle(True), lambda: oracle(False))

_ORACLE_CHILDREN = []

class OracleInterpreterCleanupTests(unittest.TestCase):
    def test_whole_original_barrier_pair_restores_interpreter_and_real_child_launch(self):
        helper = FIXTURES / 'oracle_interpreter_guard.py'
        before = FIXTURES / 'oracle-cleanup.before.source'
        path = Path(__file__)
        with path.open('rb') as stream:
            opening = _generation(os.fstat(stream.fileno()))
            current_sha = hashlib.sha256(stream.read()).hexdigest()
            for phase, subject, expected in (('before', before, ROWS[str(before.relative_to(ROOT))]),
                                               ('current', path, current_sha)):
                _guard()
                child = subprocess.Popen([sys.executable, '-B', str(helper), str(subject), expected],
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                _ORACLE_CHILDREN.append(child)
                stdout, stderr = child.communicate(timeout=30)
                observation = json.loads(stdout)
                self.assertEqual(observation['originalBarrierPair'],
                    {'testsRun': 1, 'failures': 0, 'errors': 0, 'successful': True})
                self.assertEqual(observation['sourceSha256'], expected)
                self.assertTrue(observation['wholeSourceExecuted'])
                self.assertEqual(observation['errors'], 0)
                if phase == 'before':
                    self.assertEqual((child.returncode, observation['failures']), (1, 1))
                    self.assertIn(b'original oracle must restore actual interpreter state', stderr)
                    self.assertFalse(observation['restored']['executable'])
                    self.assertFalse(observation['restored']['getpid'])
                    self.assertFalse(observation['restored']['sleep'])
                else:
                    self.assertEqual((child.returncode, observation['failures']), (0, 0), stderr.decode())
                    self.assertEqual(observation['restored'], dict.fromkeys(observation['restored'], True))
                    self.assertTrue(observation['child']['bothEof'] and observation['child']['originalHandleWaited'])
                self.assertEqual(_generation(os.fstat(stream.fileno())), opening)
                self.assertEqual(_generation(path.stat()), opening)
                _guard()

def load_tests(loader, tests, pattern):
    return _SourceBoundSuite([loader.loadTestsFromModule(BODY),
        loader.loadTestsFromModule(CALLER), loader.loadTestsFromModule(FINAL),
        loader.loadTestsFromTestCase(CollectorCausalPairs),
        loader.loadTestsFromTestCase(OracleInterpreterCleanupTests)])

if __name__ == '__main__':
    unittest.main()

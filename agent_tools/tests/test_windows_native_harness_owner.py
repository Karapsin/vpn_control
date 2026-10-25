"""Routine promotion of the complete V3 native-test owner LOCAL regressions.

Only the ten explicitly listed SOURCE fixtures execute in an owned temporary
project. No repository runtime data, SSH, VM, inventory or credentials are read.
A terminal process is not a test pass or native qualification. The historical
``d568`` operation remains UNKNOWN and is never adopted or replayed here.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

FIXTURE = Path(__file__).parent / 'fixtures/windows_native_harness_owner'
# Fixed role inventory: source names, hashes, and ONLY owned temporary targets.
ROLES = {
    'current-adapter.source': ('ab36e6aab620b866521c031451429bee4953cf3bb19cdcb9ca264670cc714cf0', '.runtime/tool-recovery-windows/direct/durable-native-harness/native_test_owner_v3.py'),
    'whole-suite-v3.source': ('5588d488283c380c0a2fe702e25cc181524ac47caf4fed58437150d878faa00d', '.runtime/tool-recovery-windows/direct/durable-native-harness/test_native_test_owner_v3.py'),
    'foreground-6210.before.source': ('6210bb28ec3d28c9e5d259e922e62cb89c70031522b21d5af767ba7b5e34b431', '.runtime/tool-recovery-windows/direct/run_windows_bootstrap_prepared.py'),
    'adapter-7ced.before.source': ('7ced915d846f3531dbf542b51d89b30a3e860453b85c4015f4c5f56bc870c5bf', '.runtime/tool-recovery-windows/direct/durable-native-harness/review-7ced/native_test_owner.py'),
    'adapter-cafb.before.source': ('cafb012f81ef8464b27a955408cc0f66edea648ba86bb01634792295400d836a', '.runtime/tool-recovery-windows/direct/durable-native-harness/review-cafb/native_test_owner_v2.py'),
    'canonical-order.before.source': ('3642ac273b6f1a40226ef843ab4ab1db776d131eefac823d619799d8adf0f8d4', '.runtime/tool-recovery-windows/direct/durable-native-harness/v2-canonical-data-failure/native_test_owner_v2.py'),
    'constructor-source.before.source': ('14b9826dd44441812ba7c56d04913e77b9087b935c3b1318227415597cdc8fde', '.runtime/tool-recovery-windows/direct/durable-native-harness/v2-owner-read-before/native_test_owner_v2.py'),
    'canonical-owner-f3b.source': ('f3b4707528c16f176b80781dd86208c324c1e10d6eb2c14451dcf4be08d0e734', 'agent_tools/durable_remote_job.py'),
    'readiness-dependency.source': ('b218d0e477d29bd2150bf9b02bff18c0a9e0a2ff1dc02ccdb08409dbabf1e078', 'agent_tools/readiness.py'),
    'source-custody-dependency.source': ('0fac471b05e0e784913f5508a5d90b279fbc48c96751b83082d1f9c14cef95ae', 'agent_tools/native_review_source_closure.py'),
}
HARNESS = Path('.runtime/tool-recovery-windows/direct/durable-native-harness')


@unittest.skipUnless(os.name == 'posix', 'complete native harness uses disposable POSIX owner/process/FD fixtures')
class NativeHarnessOwner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = {}
        provenance = json.loads((FIXTURE / 'provenance.json').read_bytes())
        if set(provenance['sources']) != set(ROLES):
            raise ValueError('native_harness_fixture_inventory_changed')
        for name, (digest, _) in ROLES.items():
            raw = (FIXTURE / name).read_bytes()
            if hashlib.sha256(raw).hexdigest() != digest or provenance['sources'][name]['sha256'] != digest:
                raise ValueError('native_harness_fixture_source_changed')
            cls.sources[name] = raw
        spec = importlib.util.spec_from_loader('_routine_native_harness_kernel_owner', loader=None)
        cls.kernel = importlib.util.module_from_spec(spec)
        cls.kernel.__file__ = str(FIXTURE / 'canonical-owner-f3b.source')
        sys.modules[spec.name] = cls.kernel
        exec(compile(cls.sources['canonical-owner-f3b.source'], cls.kernel.__file__, 'exec', dont_inherit=True), cls.kernel.__dict__)

    def campaign(self, names=(), *, role=None):
        """Execute untouched complete suite/roles; temp layout is protocol DATA.

        Legacy source contains a .runtime protocol path. That path exists only
        inside this disposable project; there is no live repository lookup.
        """
        with tempfile.TemporaryDirectory(prefix='native-harness-', dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            root = Path(temporary)
            for name, (_, relative) in ROLES.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(self.sources[name])
            canonical = root / HARNESS / 'v2-owner-read-before/canonical-owner.source'
            canonical.write_bytes(self.sources['canonical-owner-f3b.source'])
            (root / 'agent_tools/__init__.py').write_bytes(b'')
            suite = root / HARNESS / 'test_native_test_owner_v3.py'
            env = {k: v for k, v in os.environ.items() if not k.startswith(('DYLD_', 'NATIVE_'))}
            env['PYTHONDONTWRITEBYTECODE'] = '1'
            if role is not None:
                env[role] = '1'
            # Fixed sources only: no transport process, provider or VM exists.
            process = subprocess.Popen([sys.executable, '-I', '-B', str(suite), *names], cwd=root,
                                       env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                out, err = process.communicate(timeout=180)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=10)
                self.assertIsNotNone(process.poll())
            self.assertLessEqual(len(out), 1048576)
            self.assertLessEqual(len(err), 1048576)
            ledger_name = 'review-before-actors.json' if role == 'NATIVE_REVIEW_BEFORE' else 'v3-controlled-actors.json'
            ledger = json.loads((root / HARNESS / ledger_name).read_bytes())
            self.assertEqual(ledger['activeTestPopenHandles'], 0)
            self.assertFalse(ledger['retrospectiveBirthClaims'])
            self.assertTrue(ledger['observations'])
            for actor in ledger['observations']:
                self.assertTrue(actor.get('sameBirthAbsent') is True or actor.get('reaped') is True)
                if actor.get('reaped'):
                    self.assertTrue(actor['pipeFDsClosed'])
                self.assertNotEqual(self.kernel._birth(actor['pid']), actor['birth'], 'owned original process generation still present')
            return process.returncode, out, err

    def actual_red(self, role, names, expected_failures, reason):
        code, out, err = self.campaign(names, role=role)
        self.assertEqual(out, b'')
        self.assertEqual(code, 1, err.decode(errors='replace'))
        self.assertIn(('Ran ' + str(len(names)) + ' test').encode(), err)
        self.assertIn(('FAILED (failures=' + str(expected_failures) + ')').encode(), err)
        self.assertNotIn(b'\nERROR:', err)
        self.assertIn(reason, err)

    def test_10_whole_foreground_loses_original_after_client_death_or_terminal_ack(self):
        self.actual_red('NATIVE_FOREGROUND_BEFORE', (
            'DurableNativeTests.test_client_death_recovery_actual_whole_caller',
            'DurableNativeTests.test_lost_terminal_ack_recovery_actual_whole_caller'), 2,
            b'authentic foreground lost original result')

    def test_20_whole_7ced_receipt_repin_provider_access_and_prefix_truth_fail(self):
        self.actual_red('NATIVE_REVIEW_BEFORE', (
            'DurableNativeTests.test_review_owner_and_receipt_repin_attack_rejected',
            'DurableNativeTests.test_review_remote_descriptor_coordinator_never_opens_provider_path',
            'DurableNativeTests.test_review_truncated_raw_never_complete'), 3,
            b'coordinator_must_not_open_provider_namespace')

    def test_30_whole_canonical_order_before_cannot_roundtrip_data(self):
        self.actual_red('NATIVE_ORDER_BEFORE', (
            'DurableNativeTests.test_review_remote_descriptor_coordinator_never_opens_provider_path',), 1,
            b'native_test_custody_refused')

    def test_40_whole_constructor_before_executes_changed_source(self):
        self.actual_red('NATIVE_OWNER_READ_BEFORE', (
            'DurableNativeTests.test_constructor_owner_source_change_never_launches',), 1,
            b'constructor changed producer was executed')

    def test_50_cafb_both_publication_returns_adopt_changed_generation(self):
        self.actual_red('NATIVE_PUBLICATION_BEFORE', (
            'DurableNativeTests.test_remote_publication_return_cannot_select_rewritten_receipt',
            'DurableNativeTests.test_local_publication_return_cannot_select_rewritten_admission'), 2,
            b'publication return selected attacker current receipt')

    def test_90_current_complete_29_cases_green_with_original_process_absence(self):
        code, out, err = self.campaign()
        self.assertEqual(code, 0, err.decode(errors='replace'))
        self.assertEqual(out, b'')
        self.assertRegex(err, rb'Ran 29 tests in [0-9.]+s\n\nOK\n')
        self.assertNotIn(b'skipped', err)


if __name__ == '__main__':
    unittest.main()

"""Declared local controls only. No constructor, Android, VM or private ledger.

These tests load the repository source as a module and use BaselineGuard.__new__
with explicitly synthetic physical/transport seams. Real TempFS evidence and
the authentic inline profile4 parser run; no local result is native acceptance.
"""
import argparse
import ast
import base64
import copy
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
CORRELATION = 'd475b822-e8b5-4a8d-a27e-ecf3a07a2d88'
BOOT = '28b8f9af-efbb-44da-9836-0237cb714df9'
FACTS = {'guestBootId': BOOT, 'shellUid': '2000', 'synthetic': True}
SOURCE = ROOT / 'agent_tools' / 'android_installer_component_bundle.py'
BUNDLE = None


def frozen_reply(correlation=CORRELATION, boot=BOOT, shell='/system/bin/sh'):
    """Frozen public profile4 protocol bytes; authentic parser validates them."""
    generation = '1:2:81ed:0:2000:1:128:fixed-time:fixed-ctime'
    sha = 'a' * 64
    lines = [
        'PHYSICAL-READONLY-4', 'UID 2000', 'SHELL ' + shell,
        'UTILITY /system/bin/toybox', 'NAMED-SH-GENERATION ' + generation,
        'SH-KIND regular', 'SH-TARGET NONE',
        'KSH-VERSION ' + base64.b64encode(b'@(#)MIRBSD KSH R59 Android').decode(),
        'PRINCIPAL uid=2000(shell) gid=2000(shell) groups=2000(shell)',
        'BOOT ' + boot,
        'INHERITED-LIMITS ' + base64.b64encode(b'Max file size unlimited unlimited bytes\n').decode(),
        'SHELL-GENERATION ' + generation, 'TOYBOX-GENERATION ' + generation,
        'SHELL-HASH ' + sha + '  ' + shell,
        'TOYBOX-HASH ' + sha + '  /system/bin/toybox', 'FD4 ' + sha,
        'FD5 ' + sha, 'WATCHDOG-CHILD ' + correlation + ' 123 456 2000',
        'WATCHDOG 137', 'WATCHDOG-TIME 100.00 101.00',
        'WATCHDOG-POST 1 ' + base64.b64encode(b"stat: '/proc/123': No such file or directory").decode(),
        'LIMIT-PROOF ' + base64.b64encode(b'Max file size 16384 16384 bytes').decode(),
        'EOF READONLY-4 COMPLETE',
    ]
    return '\n'.join(lines) + '\n'


def load_source(path):
    module = types.ModuleType('declared_local_component_candidate')
    module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec', dont_inherit=True), module.__dict__)
    return module


BUNDLE = load_source(SOURCE)

def parse_abi(raw, correlation=CORRELATION, boot=BOOT):
    # Retained old source exposes one argument; invoke its genuine old parser
    # on the same protocol bytes so RED is a causal ABI refusal, not TypeError.
    if BUNDLE._physical_abi_parse.__code__.co_argcount == 1:
        return BUNDLE._physical_abi_parse(raw)
    return BUNDLE._physical_abi_parse(raw, correlation, boot)


# These controls exercise the real POSIX receipt writer or actual local shell.
# Pure parser/planner and refusal-before-publication controls remain portable.
_POSIX_RECEIPT_APIS = ('getuid', 'geteuid', 'getgid', 'getegid', 'getgroups',
                       'open', 'read', 'write', 'fstat', 'stat', 'fsync', 'close', 'chmod')
_POSIX_RECEIPT_CAPABLE = (
    os.name == 'posix'
    and all(callable(getattr(os, name, None)) for name in _POSIX_RECEIPT_APIS)
    and all(hasattr(os, name) for name in ('O_DIRECTORY', 'O_NOFOLLOW'))
)
_POSIX_SHELL_CAPABLE = (
    os.name == 'posix'
    and all(callable(getattr(os, name, None)) for name in ('access', 'chmod', 'fstat', 'stat'))
    and Path('/bin/sh').is_file() and os.access('/bin/sh', os.X_OK)
    and os.access(sys.executable, os.X_OK)
    and any(path.is_dir() for path in (Path('/proc/self/fd'), Path('/dev/fd')))
    and all(shutil.which(name, path=os.defpath) is not None
            for name in ('mkdir', 'find', 'wc', 'rm', 'rmdir'))
)


class LocalCandidateControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        if os.name == 'posix' and callable(getattr(os, 'chmod', None)):
            self.root.chmod(0o700)

    def tearDown(self):
        self.tmp.cleanup()

    def synthetic(self, publish_admission=True):
        guard = BUNDLE.BaselineGuard.__new__(BUNDLE.BaselineGuard)
        guard.args = types.SimpleNamespace(output=self.root, serial='emulator-SYNTHETIC', cli=self.root / 'inert-cli')
        guard.phase = 'baseline-read-only'
        guard.request = {'correlationId': CORRELATION, 'reservation': {'synthetic': True}}
        guard.owner = 'declared-local-owner'
        guard.revision = 7
        guard.expected = copy.deepcopy(FACTS)
        guard.host = {'syntheticHost': True}
        guard.stage = {'syntheticStage': True}
        guard.sequence = 0
        guard.receipt = {'syntheticReceipt': True}
        guard.physical_calls = []
        guard.adb_calls = []
        guard.evidence_calls = []
        def physical(*unused):
            guard.physical_calls.append(id(guard))
            return copy.deepcopy(FACTS)
        def adb(words):
            guard.adb_calls.append(copy.deepcopy(words))
            # The method supplies a fresh UUID in the actual readonly probe.
            text = words[-1]
            matches = __import__('re').findall(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', text)
            corr = matches[0] if matches else CORRELATION
            return {'returncode': 0, 'stdoutRaw': frozen_reply(corr), 'stderrRaw': ''}
        def evidence(name, value):
            guard.evidence_calls.append((name, copy.deepcopy(value)))
            return BUNDLE.BaselineGuard._evidence(guard, name, value)
        guard._physical = physical
        guard._adb = adb
        guard._evidence = evidence
        guard.admission_pin = None
        if publish_admission:
            guard._evidence('current-admission', {
                'facts': guard.expected, 'stage': guard.stage, 'host': guard.host,
                'owner': guard.owner, 'revision': guard.revision,
                'installedPackageDump': 'declared inert local fixture',
            })
            guard.admission_pin = BUNDLE._read(self.root / 'component-guard-current-admission.json', True)[1]
        return guard

    def test_profile4_raw_is_distinct_abi_and_authority_flags_stay_false(self):
        raw = frozen_reply()
        abi = parse_abi(raw)
        self.assertEqual('component-physical-batch-profile4.v1', abi['protocol'])
        self.assertEqual(raw, abi['calibrationRaw'])
        self.assertEqual(CORRELATION, abi['calibrationCorrelationId'])
        self.assertEqual('/system/bin/sh', abi['shellPath'])
        self.assertEqual(137, abi['watchdogExit'])
        self.assertEqual(20, abi['stepSeconds'])
        self.assertEqual(16384, abi['frameLimit'])
        self.assertEqual(16384, abi['fileLimit'])
        self.assertEqual(32768, abi['failedPrivateStreamBytesMaximum'])
        for key in ('ownerAdmission', 'runtimeAdmission', 'batchEnabled', 'overflowWriteProven', 'nativeAcceptance'):
            self.assertIs(abi['proof'][key], False)
        dependency = ROOT / 'agent_tools' / 'android_physical_readonly_abi.py'
        self.assertEqual('0fa6510875119ca3da6a5097d484a0c3e8b384b547512ca375411a59bdd22598', hashlib.sha256(dependency.read_bytes()).hexdigest())
        authentic = load_source(dependency)
        self.assertEqual(authentic.parse(raw, CORRELATION, BOOT), abi['proof'])

    def test_corrupt_crossed_partial_and_old_abi_proofs_refuse(self):
        raw = frozen_reply()
        changed = [
            raw.rstrip(), raw + 'extra\n', raw.replace('WATCHDOG 137', 'WATCHDOG 124'),
            raw.replace('FD5 ' + 'a' * 64, 'FD5 ' + 'b' * 64),
            raw.replace(CORRELATION + ' 123 456 2000', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa 123 456 2000'),
            raw.replace('WATCHDOG-TIME 100.00 101.00', 'WATCHDOG-TIME 100.00 102.00'),
            raw.replace('UID 2000', 'UID 0'),
            'PHYSICAL-ABI-1\n' + 'a' * 64 + '  /system/bin/toybox\n' + 'b' * 64 + '  /system/bin/mksh\n' + BOOT + '\nFILE-LIMIT 16384\n',
        ]
        for value in changed:
            with self.subTest(rawSha256=hashlib.sha256(value.encode()).hexdigest()):
                with self.assertRaises(ValueError):
                    parse_abi(value)
        with self.assertRaises(ValueError):
            parse_abi(raw, CORRELATION, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')

    @unittest.skipUnless(_POSIX_RECEIPT_CAPABLE, 'actual receipt writer requires POSIX UID/GID, descriptor APIs and O_DIRECTORY/O_NOFOLLOW')
    def test_completed_synthetic_same_instance_admission_precedes_enablement(self):
        guard = self.synthetic()
        identity = id(guard)
        pin = copy.deepcopy(guard.admission_pin)
        BUNDLE.CurrentGuard.enable_physical_batch(guard)
        self.assertEqual([identity, identity], guard.physical_calls)
        self.assertEqual(pin, guard.admission_pin)
        self.assertEqual(identity, id(guard))
        self.assertEqual(1, len(guard.adb_calls))
        self.assertNotIn('PHYSICAL-1 ', guard.adb_calls[0][-1])
        self.assertTrue(hasattr(guard, 'batch_admission'))
        self.assertEqual(guard.expected, guard.batch_admission['facts'])
        self.assertEqual(137, guard.batch_admission['abi']['watchdogExit'])
        self.assertIs(guard.batch_admission['abi']['proof']['batchEnabled'], False)
        self.assertEqual(guard.batch_admission['raw'], BUNDLE._read(guard.batch_admission['path'], True)[0])

    def test_incomplete_current_admission_zero_calibration_launch(self):
        guard = self.synthetic(publish_admission=False)
        del guard.admission_pin
        with self.assertRaisesRegex(ValueError, 'batch_current_admission_required'):
            BUNDLE.CurrentGuard.enable_physical_batch(guard)
        self.assertEqual([], guard.adb_calls)
        self.assertFalse(hasattr(guard, 'batch_admission'))

    @unittest.skipUnless(_POSIX_RECEIPT_CAPABLE, 'actual receipt writer requires POSIX UID/GID, descriptor APIs and O_DIRECTORY/O_NOFOLLOW')
    def test_fresh_physical_drift_refuses_batch_admission(self):
        guard = self.synthetic()
        def physical(*unused):
            guard.physical_calls.append(id(guard))
            return {**FACTS, 'drift': len(guard.physical_calls) == 2}
        guard._physical = physical
        with self.assertRaisesRegex(ValueError, 'batch_abi_changed'):
            BUNDLE.CurrentGuard.enable_physical_batch(guard)
        self.assertEqual(2, len(guard.physical_calls))
        self.assertFalse(hasattr(guard, 'batch_admission'))

    @unittest.skipUnless(_POSIX_RECEIPT_CAPABLE, 'actual receipt writer requires POSIX UID/GID, descriptor APIs and O_DIRECTORY/O_NOFOLLOW')
    def test_real_tempfs_admission_generation_mutation_refuses(self):
        guard = self.synthetic()
        path = self.root / 'component-guard-current-admission.json'
        path.write_bytes(path.read_bytes() + b' ')
        with self.assertRaisesRegex(ValueError, 'batch_current_admission_required'):
            BUNDLE.CurrentGuard.enable_physical_batch(guard)
        self.assertEqual([], guard.adb_calls)

    @unittest.skipUnless(_POSIX_RECEIPT_CAPABLE, 'actual receipt writer requires POSIX UID/GID, descriptor APIs and O_DIRECTORY/O_NOFOLLOW')
    def test_current_admission_owner_and_revision_are_not_adopted(self):
        for field, value in (('owner', 'crossed-declared-owner'), ('revision', 8)):
            with self.subTest(field=field):
                # A distinct TempFS directory permits independent create-only evidence.
                extra = self.root / field
                extra.mkdir(mode=0o700)
                original = self.root
                self.root = extra
                try:
                    guard = self.synthetic()
                    setattr(guard, field, value)
                    with self.assertRaisesRegex(ValueError, 'batch_current_admission_required'):
                        BUNDLE.CurrentGuard.enable_physical_batch(guard)
                    self.assertEqual([], guard.adb_calls)
                finally:
                    self.root = original

    @unittest.skipUnless(_POSIX_RECEIPT_CAPABLE, 'actual receipt writer requires POSIX UID/GID, descriptor APIs and O_DIRECTORY/O_NOFOLLOW')
    def test_real_tempfs_batch_admission_generation_is_not_adopted(self):
        guard = self.synthetic()
        BUNDLE.CurrentGuard.enable_physical_batch(guard)
        path = guard.batch_admission['path']
        path.write_bytes(path.read_bytes() + b' ')
        before = copy.deepcopy(guard.adb_calls)
        with self.assertRaisesRegex(ValueError, 'batch_abi_changed'):
            BUNDLE.CurrentGuard._batch_reads(guard)
        self.assertEqual(before, guard.adb_calls)

    def test_batch_planner_fixed_utility_bindings_caps_and_named_shell_close(self):
        abi = parse_abi(frozen_reply())
        source = BUNDLE._physical_batch_source(CORRELATION, abi)
        self.assertIn('vpn-control-physical-' + CORRELATION, source)
        self.assertIn('timeout -s KILL 20', source)
        self.assertIn('ulimit -f 32', source)
        self.assertIn('test "$((os+es))" -le 16384', source)
        self.assertEqual(221208, BUNDLE._PHYSICAL_BATCH_LIMIT)
        self.assertEqual(16384, BUNDLE._PHYSICAL_FRAME_LIMIT)
        self.assertIn('run 6 /system/bin/toybox id -u', source)
        self.assertIn('run 7 /system/bin/toybox cat /proc/sys/kernel/random/boot_id', source)
        self.assertIn('package=$(/system/bin/toybox cat 9.o)', source)
        self.assertGreaterEqual(source.count('/system/bin/sh'), 3)
        self.assertIn('EOF ' + CORRELATION + ' CLEANED', source)
        for key in ('shellPath', 'shellSha256', 'toyboxSha256', 'guestBootId'):
            changed = copy.deepcopy(abi)
            changed[key] = '/caller/escape' if key == 'shellPath' else 'caller-selected'
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    BUNDLE._physical_batch_source(CORRELATION, changed)

    def test_batch_unknown_guard_precedes_abi_read_and_transport(self):
        guard = BUNDLE.BaselineGuard.__new__(BUNDLE.BaselineGuard)
        guard.batch_uncertain = True
        with self.assertRaisesRegex(ValueError, 'batch_unknown_consumed'):
            BUNDLE.CurrentGuard._batch_reads(guard)

    def adb_guard(self, failure=False, publish_admission=True):
        guard = self.synthetic(publish_admission=publish_admission)
        guard.commands = []
        guard.command_errors = []
        def command_binary(*args, **kwargs):
            guard.commands.append((args, kwargs))
            if failure:
                try:
                    os.open(self.root / 'declared-absent-local-file', os.O_RDONLY)
                except OSError as exc:
                    guard.command_errors.append(exc)
                    raise
            return {'returncode': 0, 'stdoutRaw': 'declared local reply\n', 'stderrRaw': ''}
        guard.backend = {
            'GETTER_RECORDS': {'declaredOriginal': True},
            'command_host_guard': lambda: None,
            'command_binary': command_binary,
            'LAUNCH': {'adbPath': str(self.root / 'inert-adb-name'),
                       'adbFacts': {'generation': ['synthetic']}, 'environment': {}},
        }
        return guard

    def assert_timing(self, record):
        expected = ('startedMonotonic', 'endedMonotonic', 'elapsedSeconds')
        self.assertTrue(all(key in record for key in expected), record)
        for key in expected:
            self.assertIs(type(record[key]), float)
            self.assertTrue(math.isfinite(record[key]))
            self.assertGreaterEqual(record[key], 0.0)
        self.assertGreaterEqual(record['endedMonotonic'], record['startedMonotonic'])
        self.assertAlmostEqual(record['elapsedSeconds'], record['endedMonotonic'] - record['startedMonotonic'], places=8)

    @unittest.skipUnless(_POSIX_RECEIPT_CAPABLE, 'actual receipt writer requires POSIX UID/GID, descriptor APIs and O_DIRECTORY/O_NOFOLLOW')
    def test_adb_durable_begin_failure_performs_zero_local_launches(self):
        guard = self.adb_guard()
        BUNDLE._write(self.root / 'component-guard-read-00001.json', b'declared collision\n')
        with self.assertRaises(FileExistsError):
            BUNDLE.CurrentGuard._adb(guard, ['shell', '-T', 'declared inert command'])
        self.assertEqual([], guard.commands)
        self.assertEqual(0, guard.sequence)
        self.assertEqual(b'declared collision\n', (self.root / 'component-guard-read-00001.json').read_bytes())

    def test_adb_counter_overflow_performs_zero_local_launches(self):
        guard = self.adb_guard(publish_admission=False)
        guard.read_begin_sequence = 8192
        with self.assertRaisesRegex(ValueError, 'read_begin_bound'):
            BUNDLE.CurrentGuard._adb(guard, ['shell', '-T', 'declared inert command'])
        self.assertEqual([], guard.commands)
        self.assertEqual(0, guard.sequence)
        self.assertEqual(8192, guard.read_begin_sequence)
        self.assertEqual([], list(self.root.iterdir()))

    @unittest.skipUnless(_POSIX_RECEIPT_CAPABLE, 'actual receipt writer requires POSIX UID/GID, descriptor APIs and O_DIRECTORY/O_NOFOLLOW')
    def test_adb_begin_ceiling_is_independent_of_evidence_ordinals(self):
        guard = self.adb_guard(publish_admission=False)
        guard.sequence = 16382
        guard.read_begin_sequence = 8191
        result = BUNDLE.CurrentGuard._adb(guard, ['shell', '-T', 'declared inert command'])
        self.assertEqual('declared local reply\n', result['stdoutRaw'])
        self.assertEqual(1, len(guard.commands))
        self.assertEqual(16384, guard.sequence)
        self.assertEqual(8192, guard.read_begin_sequence)
        begin = json.loads((self.root / 'component-guard-read-16383.json').read_bytes())
        self.assertEqual(8192, begin['record']['ordinal'])
        before = {path.name: BUNDLE._read(path, True) for path in self.root.iterdir()}
        with self.assertRaisesRegex(ValueError, 'read_begin_bound'):
            BUNDLE.CurrentGuard._adb(guard, ['shell', '-T', 'declared inert command'])
        self.assertEqual(1, len(guard.commands))
        self.assertEqual(before, {path.name: BUNDLE._read(path, True) for path in self.root.iterdir()})

    def test_adb_large_binding_refuses_before_begin_publication_or_launch(self):
        guard = self.adb_guard(publish_admission=False)
        guard.request['declaredOversizedBinding'] = 'x' * 4096
        with self.assertRaisesRegex(ValueError, 'read_begin_bound'):
            BUNDLE.CurrentGuard._adb(guard, ['shell', '-T', 'declared inert command'])
        self.assertEqual([], guard.commands)
        self.assertEqual(0, guard.sequence)
        self.assertFalse((self.root / 'component-guard-read-00001.json').exists())

    @unittest.skipUnless(_POSIX_RECEIPT_CAPABLE, 'actual receipt writer requires POSIX UID/GID, descriptor APIs and O_DIRECTORY/O_NOFOLLOW')
    def test_adb_actual_local_primary_survives_capture_publication_failure(self):
        guard = self.adb_guard(failure=True)
        previous = guard.backend['GETTER_RECORDS']
        BUNDLE._write(self.root / 'component-guard-read-00002.json', b'declared capture collision\n')
        with self.assertRaises(FileNotFoundError) as failure:
            BUNDLE.CurrentGuard._adb(guard, ['shell', '-T', 'declared inert command'])
        self.assertEqual(1, len(guard.commands))
        self.assertIs(guard.command_errors[0], failure.exception)
        self.assertIs(previous, guard.backend['GETTER_RECORDS'])
        begin = self.root / 'component-guard-read-00001.json'
        self.assertTrue(begin.exists())
        self.assertLessEqual(begin.stat().st_size, 4096)
        self.assertLessEqual(len(BUNDLE._raw(json.loads(begin.read_bytes())['record'])), 1024)

    @unittest.skipUnless(_POSIX_RECEIPT_CAPABLE, 'actual receipt writer requires POSIX UID/GID, descriptor APIs and O_DIRECTORY/O_NOFOLLOW')
    def test_adb_genuine_sequence_has_finite_timing_and_fixed_bounds(self):
        guard = self.adb_guard()
        previous = guard.backend['GETTER_RECORDS']
        words = ['shell', '-T', 'declared inert command']
        command = guard.backend['command_binary']
        def durable_command(*args, **kwargs):
            raw, pin = BUNDLE._read(self.root / 'component-guard-read-00001.json', True)
            envelope = json.loads(raw)
            self.assertEqual('android-installer-component-baseline-read', envelope['kind'])
            self.assertEqual(guard.request, envelope['binding'])
            self.assertEqual(guard.phase, envelope['phase'])
            self.assertEqual(guard.phase, envelope['record']['phase'])
            self.assertFalse((self.root / 'component-guard-read-00002.json').exists())
            return command(*args, **kwargs)
        guard.backend['command_binary'] = durable_command
        result = BUNDLE.CurrentGuard._adb(guard, words)
        self.assertEqual('declared local reply\n', result['stdoutRaw'])
        self.assertEqual(2, guard.sequence)
        self.assertEqual(1, len(guard.commands))
        self.assertIs(previous, guard.backend['GETTER_RECORDS'])
        args, kwargs = guard.commands[0]
        self.assertEqual(16384, kwargs['limit'])
        self.assertEqual(20, kwargs['timeout'])
        self.assertEqual(['-s', 'emulator-SYNTHETIC', *words], args[2])
        begin_path = self.root / 'component-guard-read-00001.json'
        self.assertLessEqual(begin_path.stat().st_size, 4096)
        begin_envelope = json.loads(begin_path.read_bytes())
        self.assertEqual(guard.phase, begin_envelope['phase'])
        self.assertIs(begin_envelope['installerLeaseGranted'], False)
        begin = begin_envelope['record']
        final = json.loads((self.root / 'component-guard-read-00002.json').read_bytes())['record']
        self.assert_timing(final)
        self.assertLessEqual(len(BUNDLE._raw(begin)), 1024)
        self.assertEqual(begin['startedMonotonic'], final['startedMonotonic'])
        self.assertEqual(20, begin['commandDeadlineSeconds'])
        self.assertEqual(16384, begin['carrierLimit'])
        self.assertEqual(hashlib.sha256(BUNDLE._raw(words)).hexdigest(), begin['wordsSha256'])
        self.assertIsNone(final['primaryExceptionClass'])

    @unittest.skipUnless(_POSIX_RECEIPT_CAPABLE, 'actual receipt writer requires POSIX UID/GID, descriptor APIs and O_DIRECTORY/O_NOFOLLOW')
    def test_actual_owner_subclass_virtual_capture_and_independent_timing_begin(self):
        dependency = ROOT / 'agent_tools' / 'android_api35_current_owner_admission.py'
        dependency_sha = '06daf9b5d00dccd6095b95c2a1af0d310c2519224fe6a79d428c7392592107ea'
        owner_raw = dependency.read_bytes()
        self.assertEqual(dependency_sha, hashlib.sha256(owner_raw).hexdigest())
        outer = ast.parse(owner_raw)
        assignments = [node for node in outer.body if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == '_REMOTE' for target in node.targets)]
        self.assertEqual(1, len(assignments))
        remote = ast.literal_eval(assignments[0].value)
        classes = [node for node in ast.parse(remote).body if isinstance(node, ast.ClassDef)
                   and node.name == 'OwnerAdmissionGuard']
        self.assertEqual(1, len(classes))
        canonical_class = classes[0]
        methods = [node for node in canonical_class.body if isinstance(node, ast.FunctionDef)
                   and node.name == '_evidence']
        self.assertEqual(1, len(methods))
        # Preserve the authentic subclass bases and exact _evidence AST. The
        # constructor and Android reader methods are excluded and never run.
        extracted = copy.deepcopy(canonical_class)
        extracted.body = [copy.deepcopy(methods[0])]
        tree = ast.fix_missing_locations(ast.Module(body=[extracted], type_ignores=[]))
        namespace = {'COMPONENT_BUNDLE': BUNDLE, 'copy': copy,
                     'OWNER_ADMISSION_SOURCE_SHA': dependency_sha}
        exec(compile(tree, '<canonical-owner-evidence-only>', 'exec', dont_inherit=True), namespace)
        owner_type = namespace['OwnerAdmissionGuard']
        self.assertEqual(ast.dump(methods[0], include_attributes=False),
                         ast.dump(extracted.body[0], include_attributes=False))
        guard = owner_type.__new__(owner_type)
        guard.args = types.SimpleNamespace(output=self.root, serial='emulator-SYNTHETIC', cli=self.root/'inert-cli')
        guard.request = {'correlationId': CORRELATION, 'reservation': {'synthetic': True}}
        guard.phase = 'current-owner-read-only'
        guard.sequence = 0
        guard.stage = {'syntheticStage': True}
        launches = []
        def command_binary(*args, **kwargs):
            begin_raw, begin_pin = BUNDLE._read(self.root/'read-read-00001.json', True)
            self.assertEqual(guard.request, json.loads(begin_raw)['request'])
            self.assertEqual(guard.phase, json.loads(begin_raw)['record']['phase'])
            self.assertEqual(1, guard.sequence)
            self.assertEqual(1, guard.read_begin_sequence)
            self.assertFalse((self.root/'read-read-00002.json').exists())
            launches.append((args, kwargs))
            return {'returncode': 0, 'stdoutRaw': 'declared owner local reply\n', 'stderrRaw': ''}
        previous = {'declaredOriginal': True}
        guard.backend = {'GETTER_RECORDS': previous, 'command_host_guard': lambda: None,
                         'command_binary': command_binary,
                         'LAUNCH': {'adbPath': str(self.root/'inert-adb-name'),
                                    'adbFacts': {'generation': ['synthetic']}, 'environment': {}}}
        words = ['shell', '-T', 'declared inert owner command']
        result = None
        failure = None
        try:
            result = BUNDLE.CurrentGuard._adb(guard, words)
        except BaseException as exc:
            failure = exc
        owner_packet = {
            'kind': 'canonical-owner-evidence-only-local-control',
            'sourceSha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
            'ownerDependencySha256': dependency_sha,
            'constructorCalled': False, 'nativeAcceptance': False,
            'localCommandLaunches': len(launches), 'sequence': guard.sequence,
            'exceptionClass': type(failure).__name__ if failure is not None else None,
            'result': result,
            'outputFiles': {path.name: json.loads(path.read_bytes()) for path in self.root.iterdir()},
        }
        packet_path = self.root/('owner-' + owner_packet['sourceSha256'][:12] + '-successor.json')
        with packet_path.open('x') as handle:
            handle.write(json.dumps(owner_packet, sort_keys=True, indent=2) + '\n')
        packet_path.chmod(0o600)
        if failure is not None:
            raise failure
        self.assertEqual('declared owner local reply\n', result['stdoutRaw'])
        self.assertEqual(1, len(launches))
        self.assertEqual(2, guard.sequence)
        self.assertIs(previous, guard.backend['GETTER_RECORDS'])
        begin_path = self.root/'read-read-00001.json'
        begin = json.loads(begin_path.read_bytes())
        self.assertEqual({'sourceSha256', 'request', 'record', 'guestMutationPerformed', 'replayAllowed'}, set(begin))
        self.assertEqual(dependency_sha, begin['sourceSha256'])
        self.assertEqual(guard.request, begin['request'])
        self.assertEqual(guard.phase, begin['record']['phase'])
        self.assertEqual('component-read', begin['record']['scope'])
        self.assertIs(begin['guestMutationPerformed'], False)
        self.assertIs(begin['replayAllowed'], False)
        self.assertLessEqual(begin_path.stat().st_size, 4096)
        self.assertLessEqual(len(BUNDLE._raw(begin['record'])), 1024)
        self.assertFalse((self.root/'component-guard-read-begin-00001.json').exists())
        self.assertFalse((self.root/'read-read-begin-00001.json').exists())
        capture = json.loads((self.root/'read-read-00002.json').read_bytes())
        self.assertEqual(dependency_sha, capture['sourceSha256'])
        self.assertEqual(guard.request, capture['request'])
        self.assertIs(capture['guestMutationPerformed'], False)
        self.assertIs(capture['replayAllowed'], False)
        self.assertEqual(result, capture['record']['result'])
        self.assert_timing(capture['record'])
        self.assertEqual(begin['record']['startedMonotonic'], capture['record']['startedMonotonic'])
        self.assertFalse((self.root/'component-guard-read-00001.json').exists())

    @unittest.skipUnless(_POSIX_RECEIPT_CAPABLE, 'actual receipt writer requires POSIX UID/GID, descriptor APIs and O_DIRECTORY/O_NOFOLLOW')
    def test_adb_invalid_end_clock_is_null_and_transport_primary_survives(self):
        for end, command_failure in ((float('nan'), False), (49.0, False), (float('nan'), True)):
            with self.subTest(end=end, commandFailure=command_failure):
                extra = self.root / ('clock-' + str(len(list(self.root.iterdir()))))
                extra.mkdir(mode=0o700)
                original = self.root
                self.root = extra
                try:
                    guard = self.adb_guard(failure=command_failure)
                    expected_error = FileNotFoundError if command_failure else ValueError
                    with mock.patch.object(time, 'monotonic', side_effect=[50.0, end]):
                        with self.assertRaises(expected_error) as failure:
                            BUNDLE.CurrentGuard._adb(guard, ['shell', '-T', 'declared inert command'])
                    if command_failure:
                        self.assertIs(guard.command_errors[0], failure.exception)
                        self.assertEqual(['transport', 'timing'], [row['phase'] for row in guard.read_failures])
                    else:
                        self.assertEqual(['timing'], [row['phase'] for row in guard.read_failures])
                    final_raw = (self.root / 'component-guard-read-00002.json').read_bytes()
                    self.assertNotIn(b'NaN', final_raw)
                    final = json.loads(final_raw)['record']
                    self.assertIsNone(final['endedMonotonic'])
                    self.assertIsNone(final['elapsedSeconds'])
                    self.assertEqual(expected_error.__name__, final['primaryExceptionClass'])
                finally:
                    self.root = original

    @unittest.skipUnless(_POSIX_RECEIPT_CAPABLE, 'actual receipt writer requires POSIX UID/GID, descriptor APIs and O_DIRECTORY/O_NOFOLLOW')
    def test_baseline_effect_evidence_preserves_unknown_then_observed_cleanup(self):
        guard = self.synthetic()
        cases = (
            ('batch-epoch-' + CORRELATION, {'correlationId': CORRELATION}, None, 'private acquired UID2000 spool possible'),
            ('read-00001', {'kind': 'physical-batch-transport'}, None, 'private acquired UID2000 spool possible'),
            ('read-00002', {'kind': 'physical-batch-logical-observations'}, True, 'private acquired UID2000 spool observed-cleaned'),
            ('batch-complete-' + CORRELATION, {'fixtureCleanupObserved': True}, True, 'private acquired UID2000 spool observed-cleaned'),
        )
        for name, record, mutation, effect in cases:
            with self.subTest(name=name):
                BUNDLE.BaselineGuard._evidence(guard, name, record)
                evidence = json.loads((self.root / ('component-guard-' + name + '.json')).read_bytes())
                self.assertIs(evidence['guestMutationPerformed'], mutation)
                self.assertEqual(effect, evidence['guestFixtureEffects'])
                self.assertIs(evidence['installerLeaseGranted'], False)
                self.assertIs(evidence['installedLauncherAccepted'], False)
                self.assertIs(evidence['bundledRuntimeAccepted'], False)
                self.assertIs(evidence['replayAllowed'], False)
        BUNDLE.BaselineGuard._evidence(guard, 'batch-abi', {'nativeAcceptance': False})
        calibration = json.loads((self.root / 'component-guard-batch-abi.json').read_bytes())
        self.assertIs(calibration['guestMutationPerformed'], False)

    def generated_shell(self, drift='normal'):
        """Run the actual generated source with declared Android utility seams.

        The fixtures use real local mkdir/files/fds/generations/watchdog/cleanup;
        only Android paths, utility syntax, UID/GID and fixed process reads are
        mapped. This is local causal coverage and has no Android ABI authority.
        """
        fixture = self.root / drift
        fixture.mkdir(mode=0o700)
        guest = fixture / 'guest'
        guest.mkdir(mode=0o700)
        helpers = fixture / 'helpers'
        helpers.mkdir(mode=0o700)
        apk = fixture / 'inert-base.apk'
        apk.write_bytes(b'declared actual inert local package bytes')
        boot = fixture / 'boot'
        boot.write_text(BOOT + '\n')
        shell = helpers / 'shell'
        shutil.copyfile('/bin/sh', shell)
        shell.chmod(0o755)
        toy = helpers / 'toybox'
        actor = r'''import sys,os,stat,hashlib,base64,subprocess,pathlib,shutil
a=sys.argv[1:];op=a.pop(0)
if op=='stat':
 follow=False
 if a[0]=='-L':follow=True;a.pop(0)
 assert a.pop(0)=='-c';fmt=a.pop(0);p=a.pop(0)
 s=os.fstat(int(p.rsplit('/',1)[1])) if p.startswith('/dev/fd/') else os.stat(p,follow_symlinks=follow)
 identity=p in (SHELL,TOY)
 fields={'%d':str(s.st_dev),'%i':str(s.st_ino),'%f':format(s.st_mode,'x'),'%u':'0' if identity else '2000','%g':'2000','%h':str(s.st_nlink),'%s':str(s.st_size),'%y':str(s.st_mtime_ns),'%z':str(s.st_ctime_ns),'%a':format(stat.S_IMODE(s.st_mode),'o')}
 for k,v in fields.items():fmt=fmt.replace(k,v)
 print(fmt)
elif op=='sha256sum':
 p=a[0] if a else '-';raw=sys.stdin.buffer.read() if p=='-' else pathlib.Path(APK if p=='/data/app/owned/base.apk' else p).read_bytes()
 print(hashlib.sha256(raw).hexdigest()+'  '+p)
elif op=='readlink':
 p=a[0]
 if p=='/proc/self/exe':print(TOY)
 elif p.startswith('/proc/') and p.endswith('/exe'):print(SHELL)
 else:print(os.readlink(p))
elif op=='id':print('2000' if a==['-u'] else 'uid=2000(shell) gid=2000(shell) groups=2000(shell)')
elif op=='getprop':print({'ro.build.version.sdk':'35','ro.product.cpu.abi':'x86_64','ro.kernel.qemu.avd_name':'fixture','ro.boot.qemu.avd_name':'fixture','sys.boot_completed':'1'}[a[0]])
elif op=='pm':assert a==['path','com.kardinal.vpncontrol'];print('package:/data/app/owned/base.apk')
elif op=='pidof':print({'adbd':'11','zygote':'','zygote64':'22'}[a[0]])
elif op=='cat':
 for arg in a:
  if arg.startswith('/proc/') and arg.endswith('/stat'):
   print(arg.split('/')[2]+' (fixture) '+' '.join(['S']+['0']*18+['100']))
  else:sys.stdout.buffer.write(pathlib.Path(arg).read_bytes())
elif op=='base64':
 assert a[:2]==['-w','0'];p=pathlib.Path(a[2]);sys.stdout.buffer.write(base64.b64encode(p.read_bytes()));sys.stdout.buffer.flush()
 mode=os.environ.get('DRIFT','normal')
 if p.name=='1.o' and mode=='file':p.chmod(0o644)
 if p.name=='1.o' and mode=='parent':
  cwd=pathlib.Path.cwd();cwd.rename(cwd.with_name(cwd.name+'-retained'));cwd.mkdir(mode=0o700)
 if p.name=='10.e' and mode=='shell':os.utime(SHELL,None)
 if p.name=='10.e' and mode=='utility':os.utime(TOY,None)
elif op=='timeout':
 assert a[:2]==['-s','KILL'];seconds=int(a[2]);fds=[]
 for fd in (4,5):
  try:os.fstat(fd);fds.append(fd)
  except OSError:pass
 try:r=subprocess.run(a[3:],timeout=seconds,pass_fds=fds);raise SystemExit(r.returncode)
 except subprocess.TimeoutExpired:raise SystemExit(124)
elif op in ('mkdir','find','wc','rm','rmdir'):
 resolved=shutil.which(op,path=os.defpath);assert resolved
 raise SystemExit(subprocess.run([resolved,*a]).returncode)
else:raise SystemExit(94)
'''
        prefix = '#!' + sys.executable + '\n' + '\n'.join(
            name + '=' + repr(str(path)) for name, path in (('APK', apk), ('SHELL', shell), ('TOY', toy))) + '\n'
        toy.write_text(prefix + actor)
        toy.chmod(0o755)
        for name in ('id', 'getprop', 'pm', 'pidof', 'cat'):
            path = helpers / name
            path.write_text('#!' + sys.executable + '\nimport os,sys\nos.execv(' + repr(str(toy)) + ',[' + repr(str(toy)) + ',' + repr(name) + ',*sys.argv[1:]])\n')
            path.chmod(0o755)
        def generation(path):
            value = path.stat()
            return ':'.join(str(x) for x in (value.st_dev, value.st_ino, format(value.st_mode, 'x'),
                0, 2000, value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns))
        toy_sha = hashlib.sha256(toy.read_bytes()).hexdigest()
        shell_sha = hashlib.sha256(shell.read_bytes()).hexdigest()
        if BUNDLE._physical_abi_parse.__code__.co_argcount == 1:
            raw = 'PHYSICAL-ABI-1\n' + toy_sha + '  /system/bin/toybox\n' + shell_sha + '  /system/bin/mksh\n' + BOOT + '\nFILE-LIMIT 16384\n'
        else:
            raw = frozen_reply()
            frozen_generation = '1:2:81ed:0:2000:1:128:fixed-time:fixed-ctime'
            raw = raw.replace('NAMED-SH-GENERATION ' + frozen_generation, 'NAMED-SH-GENERATION ' + generation(shell))
            raw = raw.replace('SHELL-GENERATION ' + frozen_generation, 'SHELL-GENERATION ' + generation(shell))
            raw = raw.replace('TOYBOX-GENERATION ' + frozen_generation, 'TOYBOX-GENERATION ' + generation(toy))
            raw = raw.replace('SHELL-HASH ' + 'a'*64, 'SHELL-HASH ' + shell_sha)
            raw = raw.replace('TOYBOX-HASH ' + 'a'*64, 'TOYBOX-HASH ' + toy_sha)
            raw = raw.replace('FD4 ' + 'a'*64, 'FD4 ' + toy_sha).replace('FD5 ' + 'a'*64, 'FD5 ' + toy_sha)
        abi = parse_abi(raw)
        source = BUNDLE._physical_batch_source(CORRELATION, abi)
        # Only mechanical fixture paths are substituted after production planning.
        mapped = source.replace('/system/bin/toybox', str(toy)).replace('/system/bin/mksh', str(shell)).replace('/system/bin/sh', str(shell))
        mapped = mapped.replace('/system/bin/getprop', str(helpers / 'getprop')).replace('/system/bin/pm', str(helpers / 'pm'))
        mapped = mapped.replace('/data/local/tmp', str(guest)).replace('/proc/sys/kernel/random/boot_id', str(boot))
        if not Path('/proc/self/fd').exists():
            mapped = mapped.replace('/proc/$$/fd/', '/dev/fd/')
        env = {'PATH': str(helpers) + ':' + os.defpath, 'DRIFT': drift}
        child = subprocess.run([str(shell), '-c', mapped], env=env, capture_output=True, timeout=55)
        capture = {
            'kind': 'actual-generated-shell-local-control', 'nativeAcceptance': False,
            'declaredSeams': ['Android paths', 'UID/GID', 'toybox syntax', 'fixed inert process/package reads'],
            'realLocalOperations': ['shell', 'mkdir', 'files', 'fds', 'generation checks', 'bounded child timeout', 'encoding', 'cleanup'],
            'sourceSha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
            'generatedSource': source, 'mappedSourceSha256': hashlib.sha256(mapped.encode()).hexdigest(),
            'calibrationRaw': raw, 'drift': drift, 'returncode': child.returncode,
            'stdoutRaw': child.stdout.decode(), 'stderrRaw': child.stderr.decode(),
            'remainingGuestEntries': sorted(path.name for path in guest.iterdir()),
        }
        capture_path = self.root / ('shell-' + capture['sourceSha256'][:12] + '-' + drift + '.json')
        capture_path.write_text(json.dumps(capture, sort_keys=True, indent=2) + '\n')
        capture_path.chmod(0o600)
        return child, guest

    @unittest.skipUnless(_POSIX_SHELL_CAPABLE, 'actual shell requires POSIX executable shell/Python, FD namespace and fixed host applets')
    def test_actual_generated_shell_normal_closes_and_cleans(self):
        child, guest = self.generated_shell()
        self.assertEqual(0, child.returncode, child.stderr.decode()[-4000:])
        rows = BUNDLE._physical_batch_parse(child.stdout.decode(), CORRELATION)
        self.assertEqual(10, len(rows))
        self.assertEqual('35\n', rows[0]['stdoutRaw'])
        self.assertEqual([], list(guest.iterdir()))

    @unittest.skipUnless(_POSIX_SHELL_CAPABLE, 'actual shell requires POSIX executable shell/Python, FD namespace and fixed host applets')
    def test_actual_generated_shell_file_parent_shell_utility_drift_refuse(self):
        for drift in ('file', 'parent', 'shell', 'utility'):
            with self.subTest(drift=drift):
                child, guest = self.generated_shell(drift)
                self.assertNotEqual(0, child.returncode)
                self.assertIn(b'FRAME\t1\t', child.stdout)
                self.assertNotIn(b' CLEANED\n', child.stdout)
                with self.assertRaises(ValueError):
                    BUNDLE._physical_batch_parse(child.stdout.decode(), CORRELATION)



if __name__ == '__main__':
    unittest.main()

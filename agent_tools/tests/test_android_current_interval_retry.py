import ast
import base64
import builtins
import contextlib
import io
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import time
import tempfile
import types
import unittest
import uuid

from agent_tools.tests import test_android_installer_host_preflight as host_fixture

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / 'fixtures/android_current_census'
BEFORES = Path(__file__).parent / 'fixtures/android_current_interval_retry'
PROOF_SHA = '93ff56ef99d2496aef690ea1ae44e0e7ff4136386e6718fa81e8f0ff21e2e6ed'
BOOT = '00000000-0000-4000-8000-000000000001'
PINS = {'process.before.source': '26df14113106aae8a76fed795e1d562726f1b43e9be8763c736315fac350e28e',
        'validator.original.source': '23e692586d4f82f4c6dc8a24c0200eb572292c0efc78e68497de33ca0f119670',
        'process-current1e15.before.source': '779c7bcea4e3d6b88d2d4bd508b045e834dec567a373fd9a5134d6da9b183f8f',
        'validator-current1e15.original.source': '2215ed6c0571b93c0795359fda7976a68a99e1407fd0b85195e69dba29853ed1'}


def original_text(name):
    raw = (FIXTURES / name).read_bytes()
    if hashlib.sha256(raw).hexdigest() != PINS[name]:
        raise ValueError('authentic-original-interval-source-changed')
    return raw.decode()


def capsule(before=False):
    source, proof = host_fixture.InstallerHostPreflightTests().fixture()
    tree = ast.parse(source)
    binding = {name: base64.b64encode(value).decode() for name, value in
               (('expectedRootArgvBase64', b'python\0owned-protected-worker\0'),
                ('expectedSudoArgvBase64', b'sudo\0owned-protected-worker\0'))}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            key = node.targets[0].id
            if key in ('EFFECT_PLANE_FIXED', 'CURRENT1E15_EFFECT_PLANE_FIXED'):
                current = key == 'CURRENT1E15_EFFECT_PLANE_FIXED'
                value = ast.literal_eval(node.value)
                value.update(binding=binding,
                             processSource=original_text('process-current1e15.before.source' if current else 'process.before.source'),
                             validatorSource=original_text('validator-current1e15.original.source' if current else 'validator.original.source'),
                             boundarySource='def boundary_pass(): BOUNDARY_PASSES.append([])\n', priorPass=[])
                node.value = ast.parse(repr(value), mode='eval').body
    ast.fix_missing_locations(tree)
    original = (ast.unparse(tree) + '\n').encode()
    path = BEFORES / 'successor.whole-before.source' if before else ROOT / 'agent_tools/android_component_successor.py'
    if not before and os.environ.get('VPN_CONTROL_INTERVAL_DRAFT_BEFORE') == '1':
        path = BEFORES / 'successor.draft-before.source'
        assert hashlib.sha256(path.read_bytes()).hexdigest() == '23cd89fb035d18021b7b6ba3b00deec27bc31870f2127b67c86f8afad68d230c'
    if before:
        assert hashlib.sha256(path.read_bytes()).hexdigest() == '41db35629811610f220de5ed815ba3e739966ba4b17c50b6d1cd229984f378ab'
    code = ast.parse(path.read_bytes())
    changes = 0
    for node in ast.walk(code):
        if isinstance(node, ast.Constant) and node.value == PROOF_SHA:
            node.value = proof
            changes += 1
    assert changes == 2
    ast.fix_missing_locations(code)
    namespace = {'__name__': 'held_interval_factory', '__file__': str(path)}
    exec(compile(code, str(path), 'exec'), namespace)
    factory = namespace['installer_current_host_preflight_capsule' if before else 'installer_bounded_host_preflight_capsule']
    result = factory(original, hashlib.sha256(original).hexdigest())
    module = types.ModuleType('owned_interval_' + uuid.uuid4().hex)
    exec(compile(result['source'], 'owned-full-interval-capsule', 'exec'), module.__dict__)
    return result, module


class Control:
    def __init__(self, case='gone', prefix=0, before=False, repeats=False):
        self.temp = tempfile.TemporaryDirectory(prefix='interval-unit-')
        self.base = Path(self.temp.name)
        self.fs = self.base / 'linux-root'
        self.proc = self.base / 'proc'
        self.proc.mkdir()
        (self.proc / 'sys/kernel/random').mkdir(parents=True)
        (self.proc / 'sys/kernel/random/boot_id').write_text(BOOT + '\n')
        self.operation = str(uuid.uuid4())
        self.virtual = '/var/tmp/vc-android-persisted-' + self.operation
        self.actual = self.fs / self.virtual[1:]
        self.actual.mkdir(parents=True)
        self.actual.chmod(0o700)
        self.info = self.actual.stat()
        self.result, self.module = capsule(before)
        self.case, self.prefix, self.repeats = case, prefix, repeats
        self.calls = self.lists = self.opens = 0
        self.failed = False
        self.reappearance = 0
        self.fault_fd = None
        self.partial_read = False
        self.make_process(501)
        real = os
        proxy = types.SimpleNamespace(**{name: getattr(real, name) for name in dir(real)})
        def project(info):
            values = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
            values.update(st_uid=0, st_gid=0)
            return types.SimpleNamespace(**values)
        def mapped(path):
            text = os.fspath(path)
            if text == '/': return str(self.fs)
            if text == '/var' or text == '/var/tmp' or text.startswith(self.virtual):
                return str(self.fs / text.lstrip('/'))
            return path
        def listed(path):
            if not isinstance(path, int) and Path(path) == self.proc:
                self.lists += 1
                late_at = 5 if self.case.startswith('prior_') else 2
                if self.case == 'prior_reappeared' and self.lists == 2:
                    self.make_process(501)
                if self.case == 'prior_unresolved' and self.lists == 2:
                    for pid in range(600, 633): self.make_process(pid)
                if self.lists == late_at and (not self.failed or self.repeats):
                    self.make_process(502, protected=self.case == 'protected')
            return real.listdir(path if isinstance(path, int) else mapped(path))
        def opened(path, flags, *args, **kwargs):
            text = str(path)
            if self.case == 'prior_reappeared' and not self.failed and self.lists == 1 and text == str(self.proc / '501/cmdline'):
                shutil.rmtree(self.proc / '501')
                raise FileNotFoundError(2, 'owned positively absent then reappeared')
            if text.startswith(str(self.proc / '502') + '/') and Path(text).name in ('cmdline', 'status', 'stat'):
                self.opens += 1
                if self.opens == 7 + self.prefix:
                    self.failed = True
                    if self.case == 'denied': raise PermissionError(13, 'owned explicit visibility seam')
                    if self.case == 'present': raise FileNotFoundError(2, 'owned missing-file seam')
                    if self.case == 'partial':
                        fd = real.open(path, flags, *args, **kwargs)
                        self.fault_fd = fd
                        return fd
                    fd = real.open(path, flags, *args, **kwargs)
                    shutil.rmtree(self.proc / '502')
                    if self.case == 'boot':
                        (self.proc / 'sys/kernel/random/boot_id').write_text('00000000-0000-4000-8000-000000000002\n')
                    self.fault_fd = fd
                    return fd
            return real.open(mapped(path), flags, *args, **kwargs)
        def read(fd, limit):
            if fd == self.fault_fd:
                if self.case != 'partial':
                    self.fault_fd = None
                    raise ProcessLookupError(3, 'owned disappeared process')
                if not self.partial_read:
                    self.partial_read = True
                    return real.read(fd, limit)
                shutil.rmtree(self.proc / '502')
                self.fault_fd = None
                raise ProcessLookupError(3, 'owned partial read')
            return real.read(fd, limit)
        def observed(path, *args, **kwargs):
            if self.case == 'reappear' and self.failed and Path(str(path)) == self.proc / '502':
                self.reappearance += 1
                if self.reappearance == 2: self.make_process(502)
            return project(real.stat(mapped(path), *args, **kwargs))
        proxy.open, proxy.read, proxy.listdir, proxy.stat = opened, read, listed, observed
        proxy.fstat = lambda fd: project(real.fstat(fd))
        proxy.getuid = proxy.geteuid = proxy.getgid = proxy.getegid = lambda: 0
        self.module.os = proxy
        self.module.PROC = self.proc
        self.module.ROOT = self.base
        # Only the Linux /proc surface is redirected; original scanner and
        # projector bytes, identities, protocols and error handling are intact.
        tree = ast.parse(self.result['source'])
        guard = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name == 'component_release_current1e15_effect_plane_guard')
        changed = 0
        for node in ast.walk(guard):
            if isinstance(node, ast.Constant) and node.value == '/proc':
                node.value = str(self.proc)
                changed += 1
        assert changed == 1
        ast.fix_missing_locations(guard)
        exec(compile(ast.Module(body=[guard], type_ignores=[]), 'owned-current1e15-original-guard', 'exec'), self.module.__dict__)
        self.context = {'schema': 1, 'operationId': self.operation, 'root': self.virtual,
                        'rootGeneration': [self.info.st_dev, self.info.st_ino], 'hostBootId': BOOT,
                        'machineSha256': hashlib.sha256(b'owned-machine').hexdigest(), 'account': '0'}
        self.module.CURRENT_INTERVAL_STORAGE = self.context
        if not before:
            self.module._interval_machine = lambda: self.context['machineSha256']
        def whole_host():
            self.calls += 1
            self.lists = self.opens = 0
            self.module.COMPONENT_RETIRE_OBSERVATIONS = []
            self.module.COMPONENT_RETIRE_RAW_RECORDS = []
            self.module.CLAIM_OBSERVATIONS = []
            self.module.HOST_RAW_DIGESTS = []
            value = self.module.component_release_current1e15_effect_plane_guard()
            return {'state': 'admitted', 'stableBinding': {'fixture': 'whole-host-boundary'},
                    'evidence': {'actualCurrent1e15': value}}
        # Explicit unchanged-host-fence OS boundary; every actual census and
        # strict legacy projector runs. A later real-Linux full-host control is
        # mandatory and separate from these owned-file unit cases.
        self.original_host = self.module._current_host_attempt if not before else None
        self.module._current_host_attempt = whole_host
        self.invoke = whole_host if before else self.module.installer_host_preflight

    def make_process(self, pid, protected=False):
        path = self.proc / str(pid)
        path.mkdir()
        (path / 'cmdline').write_bytes(b'python\0owned-protected-worker\0' if protected else b'ordinary\0')
        (path / 'status').write_text('Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n')
        (path / 'stat').write_text(str(pid) + ' (owned-process) S 1 ' + '0 ' * 17 + str(pid + 100) + '\n')

    def reports(self):
        directory = self.actual / 'current-intervals'
        return [json.loads(path.read_bytes()) for path in sorted(directory.glob('interval-*.json'))]

    def close(self):
        self.temp.cleanup()


@unittest.skipUnless(os.name == 'posix', 'actual proc-file/FD/flock controls require POSIX')
class IntervalTests(unittest.TestCase):
    def control(self, *args, **kwargs):
        value = Control(*args, **kwargs)
        self.addCleanup(value.close)
        return value

    def test_zero_data_late_closing_disappearance_reobserves_complete_legacy_protocol(self):
        value = self.control(before=os.environ.get('VPN_CONTROL_INTERVAL_RETRY_BEFORE') == '1')
        result = value.invoke()
        self.assertEqual(result['state'], 'admitted')
        self.assertEqual(value.calls, 2)
        reports = value.reports()
        self.assertEqual(len(reports), 1)
        self.assertTrue(reports[0]['unknownInterval'])
        self.assertTrue(reports[0]['retryable'])
        self.assertEqual(reports[0]['partialRead']['bytes'], 0)
        self.assertEqual(reports[0]['error']['type'], 'ProcessLookupError')
        self.assertEqual([row['state'] for row in reports[0]['positiveAbsence']], ['rechecked-absent', 'rechecked-absent'])
        final = result['evidence']['actualCurrent1e15']
        self.assertTrue(all(scan['censusComplete'] for scan in final['workerPasses']))
        self.assertEqual(len(result['evidence']['priorUnknownCurrentIntervals']), 1)

    def test_prior_incomplete_scan_prevents_disappearance_retry(self):
        for case in ('prior_reappeared', 'prior_unresolved'):
            with self.subTest(case=case):
                value = self.control(case)
                with self.assertRaisesRegex(value.module.CurrentIntervalRefusal, 'nonretryable'):
                    value.invoke()
                self.assertEqual(value.calls, 1)
                report = value.reports()[0]
                self.assertFalse(report['retryable'])
                self.assertFalse(report['completedCensusPasses'][0]['censusComplete'])
                self.assertEqual(report['completedCensusPasses'][0]['matches'], [])
                self.assertEqual(report['completedCensusPasses'][0]['errors'], [])

    def test_existing_store_lock_refuses_promptly_before_host_attempt(self):
        import fcntl
        value = self.control()
        directory = value.actual / 'current-intervals'
        directory.mkdir(mode=0o700)
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.addCleanup(os.close, fd)
        before = len(os.listdir('/dev/fd'))
        started = time.monotonic()
        with self.assertRaisesRegex(value.module.CurrentIntervalRefusal, 'store_busy'):
            value.invoke()
        self.assertLess(time.monotonic() - started, .5)
        self.assertEqual(value.calls, 0)
        self.assertEqual(len(os.listdir('/dev/fd')), before)

    def test_delayed_store_setup_cannot_start_host_after_deadline(self):
        value = self.control()
        clock = types.SimpleNamespace(now=0)
        value.module.time = types.SimpleNamespace(monotonic=lambda: clock.now, time_ns=time.time_ns)
        original = value.module._interval_open_store
        def delayed():
            result = original()
            clock.now = 6
            return result
        value.module._interval_open_store = delayed
        before = len(os.listdir('/dev/fd'))
        with self.assertRaisesRegex(value.module.CurrentIntervalRefusal, 'time_budget'):
            value.invoke()
        self.assertEqual(value.calls, 0)
        self.assertEqual(len(os.listdir('/dev/fd')), before)

    def test_actual_original_host_frame_retains_completed_actor_evidence(self):
        value = self.control()
        module = value.module
        real_path = Path
        module.Path = lambda name: value.proc / 'sys/kernel/random/boot_id' if str(name) == '/proc/sys/kernel/random/boot_id' else real_path(name)
        module.sys = types.SimpleNamespace(platform='linux')
        module.socket = types.SimpleNamespace(create_connection=lambda *args, **kwargs: (_ for _ in ()).throw(ConnectionRefusedError()))
        marker = base64.b64encode(b'distinctive completed original HOST actor evidence').decode()
        module.readiness_process = lambda original: {'state': 'absent', 'pid': original['pid'], 'rawBase64': marker}
        fixture = {'correlationId': module.CLAIM_ORIGINAL,
                   'pid': module.HOST_ORIGINAL_ACTORS['fixture']['pid'],
                   'startTicks': module.HOST_ORIGINAL_ACTORS['fixture']['startTicks'], 'port': 1234}
        def capture(path, limit):
            for expected in module.HOST_ADMISSION_PINS.values():
                if str(path) == expected['path']: return dict(expected, rawBase64='')
            if str(path) == str(module.ROOT / 'android-native-device-api35.lease'):
                raw = json.dumps({'owner':'android-installer','host':'archlinux','device':'api35','correlationId':module.CLAIM_ORIGINAL}, sort_keys=True, separators=(',',':')).encode()+b'\n'
                return dict(module.HOST_LEASE_PIN, state='present', parents=module.HOST_LEASE_PARENTS, rawBase64=base64.b64encode(raw).decode())
            if str(path) == module.HOST_FIXTURE_RECORD_PATH:
                return dict(module.HOST_FIXTURE_RECORD_PIN, state='present', rawBase64=base64.b64encode(json.dumps(fixture).encode()).decode())
            return {'state': 'absent', 'path': str(path)}
        module.component_retirement_capture_record = capture
        module.component_release_effect_plane_current_guard = lambda: {'kind':'owned-other-plane','binding':{},'passes':[],'workerPasses':[]}
        module._current_host_attempt = value.original_host
        value.invoke()
        report = value.reports()[0]
        self.assertEqual(report['hostAttempt']['actor_evidence']['fixture']['rawBase64'], marker)
        self.assertEqual(report['hostAttempt']['fixture_identity'], fixture)
        self.assertEqual(set(report['hostAttempt']['admissions']), set(module.HOST_ADMISSION_PINS))
        self.assertEqual(report['hostAttempt']['fixture_port'], 1234)
        self.assertTrue(report['hostAttempt']['lease'])

    def test_every_completed_closing_prefix_is_retained_and_not_retried(self):
        for prefix in range(1, 6):
            with self.subTest(prefix=prefix):
                value = self.control(prefix=prefix)
                with self.assertRaisesRegex(value.module.CurrentIntervalRefusal, 'nonretryable'):
                    value.invoke()
                self.assertEqual(value.calls, 1)
                report = value.reports()[0]
                self.assertFalse(report['retryable'])
                self.assertEqual(len(report['rawRecords']) - report['closingRawBegin'], prefix)

    def test_partial_bytes_are_retained_without_becoming_complete(self):
        value = self.control('partial')
        with self.assertRaisesRegex(value.module.CurrentIntervalRefusal, 'nonretryable'):
            value.invoke()
        report = value.reports()[0]
        self.assertGreater(report['partialRead']['bytes'], 0)
        self.assertIs(report['partialRead']['readComplete'], False)
        self.assertIs(report['retryable'], False)
        self.assertEqual(value.calls, 1)

    def test_protected_permission_present_reappearance_and_boot_never_retry(self):
        for case in ('protected', 'denied', 'present', 'reappear', 'boot'):
            with self.subTest(case=case):
                value = self.control(case)
                with self.assertRaises(value.module.CurrentIntervalRefusal):
                    value.invoke()
                self.assertEqual(value.calls, 1)
                if case != 'boot': self.assertIs(value.reports()[0]['retryable'], False)

    def test_three_failed_attempts_exhaust_without_fourth(self):
        value = self.control(repeats=True)
        with self.assertRaisesRegex(value.module.CurrentIntervalRefusal, 'samples_exhausted'):
            value.invoke()
        self.assertEqual(value.calls, 3)
        self.assertEqual(len(value.reports()), 3)

    def test_refuses_foreign_root_or_generation_before_attempt(self):
        for field, data in (('root', '/home/kardinal/.vpn-control-mcp-fixtures'), ('operationId', str(uuid.uuid4())),
                            ('rootGeneration', [1, 2]), ('account', '1000')):
            with self.subTest(field=field):
                value = self.control()
                value.context[field] = data
                with self.assertRaises(value.module.CurrentIntervalRefusal): value.invoke()
                self.assertEqual(value.calls, 0)

    def test_published_reports_are_full_private_create_only_files(self):
        value = self.control()
        result = value.invoke()
        ref = result['evidence']['priorUnknownCurrentIntervals'][0]
        path = value.actual / 'current-intervals' / Path(ref['path']).name
        raw = path.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), ref['sha256'])
        self.assertEqual(len(raw), ref['bytes'])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(path.stat().st_nlink, 1)
        self.assertFalse(list(path.parent.glob('.pending-*')))

    def test_pending_or_foreign_report_refuses_before_census_and_is_preserved(self):
        for filename in ('.pending-owned', 'foreign.json'):
            with self.subTest(filename=filename):
                value = self.control()
                directory = value.actual / 'current-intervals'
                directory.mkdir(mode=0o700)
                path = directory / filename
                path.write_bytes(b'owned unpublished evidence')
                path.chmod(0o600)
                with self.assertRaises(value.module.CurrentIntervalRefusal): value.invoke()
                self.assertEqual(value.calls, 0)
                self.assertEqual(path.read_bytes(), b'owned unpublished evidence')

    def test_operation_aggregate_reserves_space_before_new_attempt(self):
        value = self.control()
        directory = value.actual / 'current-intervals'
        directory.mkdir(mode=0o700)
        for index in range(3):
            key = uuid.uuid4().hex
            document = {'schema': 1, 'kind': 'android-current1e15-unknown-interval',
                        'operationId': value.operation, 'recordId': key,
                        'scannerSourceSha256': value.module.CURRENT_INTERVAL_SCANNER_SHA,
                        'validatorSourceSha256': value.module.CURRENT_INTERVAL_VALIDATOR_SHA,
                        'ownedPadding': 'x' * (6 * 1024 * 1024)}
            path = directory / ('interval-' + key + '.json')
            path.write_text(json.dumps(document))
            path.chmod(0o600)
        with self.assertRaisesRegex(value.module.CurrentIntervalRefusal, 'operation_budget'): value.invoke()
        self.assertEqual(value.calls, 0)

    def test_publication_failure_keeps_pending_data_and_never_retries(self):
        value = self.control()
        def fail(*args, **kwargs): raise OSError(5, 'owned publication fault')
        value.module.os.link = fail
        with self.assertRaises(OSError): value.invoke()
        self.assertEqual(value.calls, 1)
        pending = list((value.actual / 'current-intervals').glob('.pending-*'))
        self.assertEqual(len(pending), 1)
        self.assertEqual(json.loads(pending[0].read_bytes())['error']['type'], 'ProcessLookupError')
        self.assertFalse(value.reports())

    def test_unsafe_opened_parent_does_not_leak_owned_descriptors(self):
        value = self.control()
        value.actual.chmod(0o777)
        before = len(os.listdir('/dev/fd'))
        with self.assertRaises(value.module.CurrentIntervalRefusal): value.invoke()
        self.assertEqual(value.calls, 0)
        self.assertEqual(len(os.listdir('/dev/fd')), before)


class NativeControlCompositionTests(unittest.TestCase):
    def test_module_discovery_without_posix_fcntl(self):
        before = os.environ.get('VPN_CONTROL_INTERVAL_PORTABILITY_BEFORE') == '1'
        path = BEFORES / 'test.unconditional-posix.before.source' if before else Path(__file__)
        raw = path.read_bytes()
        if before: self.assertEqual(hashlib.sha256(raw).hexdigest(), '7150f450be1061a0df33d8d15b8f30c36497685afc56b2383213ca50d677702a')
        original = builtins.__import__
        def portable_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name == 'fcntl': raise ModuleNotFoundError('owned missing POSIX fcntl capability')
            return original(name, globals, locals, fromlist, level)
        isolated_builtins = dict(vars(builtins), __import__=portable_import)
        module = {'__name__':'owned_windows_discovery_probe', '__file__':str(Path(__file__)),
                  '__builtins__':isolated_builtins}
        exec(compile(raw,'held-entire-interval-test-module','exec'),module)
        discovered = unittest.TestLoader().loadTestsFromTestCase(module['NativeControlCompositionTests'])
        self.assertGreaterEqual(discovered.countTestCases(), 1)

    def test_phase_publication_failure_marks_unknown_and_stops_next_phase(self):
        before = os.environ.get('VPN_CONTROL_INTERVAL_PUBLICATION_BEFORE') == '1'
        name = 'control-body.fixed.source' if before else 'control-body.publication-fixed.source'
        raw = (BEFORES / name).read_bytes()
        expected = ('f71c2f9d2e973c0c2d991bbb0468303c48c150c53f0803e318b35ceea5456c72' if before else
                    '45e706b66884715716376bce7541cb230cae3018ee1ab7d2eaaa6aa6baede0a5')
        self.assertEqual(hashlib.sha256(raw).hexdigest(), expected)
        tree = ast.parse(raw)
        module = {'__name__':'owned_phase_publication_control','sys':sys,'json':json,'hashlib':hashlib,
                  'OPERATION_ID':'00000000-0000-4000-8000-000000000001','CONTROL_ROOT':'/owned-control',
                  'ORIGINAL_CAPSULE':b'old','ORIGINAL_CAPSULE_SHA':'old','CURRENT_CAPSULE':b'new',
                  'CURRENT_CAPSULE_SHA':'new','PHASES':[], 'control_code':lambda error:type(error).__name__,
                  'need':lambda value,reason:None if value else (_ for _ in ()).throw(ValueError(reason))}
        exec(compile(ast.Module(body=tree.body[:-1],type_ignores=[]),'held-whole-control-body','exec'),module)
        phase = next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name == 'phase')
        # The already-completed host/child boundary is an explicit inert unit
        # fixture. Execute the REAL phase publication tail and owner catch;
        # neither publication nor its failure transition is reimplemented.
        index = next(i for i,node in enumerate(phase.body) if isinstance(node,ast.Assign)
                     and any(isinstance(target,ast.Subscript) and isinstance(target.slice,ast.Constant)
                             and target.slice.value == 'reportComplete' for target in node.targets))
        phase.body = ast.parse("report={'phase':label,'state':'qualified'}\nPHASES.append(report)\n").body + phase.body[index:]
        ast.fix_missing_locations(phase)
        exec(compile(ast.Module(body=[phase],type_ignores=[]),'held-actual-phase-publication-tail','exec'),module)
        calls = []
        class Receiver:
            ROOT_FD = None
            PARENTS = []
            def canonical(self,value): return json.dumps(value).encode()
            def create(self,name,raw):
                calls.append(name)
                raise OSError(5,'owned create-only publication fault')
            def guard_root(self): pass
        receiver = Receiver()
        module['prepare_control_root'] = lambda:(receiver,{}, {'state':'owned-prepared'})
        output = io.StringIO()
        with contextlib.redirect_stdout(output): module['run_control']()
        result = json.loads(output.getvalue())
        self.assertEqual(result['state'],'unknown')
        self.assertEqual(calls,['control-before.json'])
        self.assertEqual(len(result['phases']),1)
        self.assertEqual(result['phases'][0]['state'],'unknown')
        self.assertEqual(result['phases'][0]['unexpectedFailure'],'OSError')
        self.assertTrue(result['phases'][0]['reportComplete'])
        self.assertIs(result['nativeStartRun'],False)

    def test_full_native_control_report_survives_protected_capture_stringio(self):
        before = os.environ.get('VPN_CONTROL_INTERVAL_CONTROL_BEFORE') == '1'
        name = 'control-body.before.source' if before else 'control-body.publication-fixed.source'
        raw = (BEFORES / name).read_bytes()
        expected = ('1ed08a26194ee2122a37921cc7f7fb0e52f64a03f24a4b138994efcac5ab5bba' if before else
                    '45e706b66884715716376bce7541cb230cae3018ee1ab7d2eaaa6aa6baede0a5')
        self.assertEqual(hashlib.sha256(raw).hexdigest(), expected)
        tree = ast.parse(raw)
        # Compile every actual definition unchanged. The only controlled OS
        # boundary refuses preparation before it can open or mutate anything.
        self.assertIsInstance(tree.body[-1], ast.Expr)
        self.assertEqual(ast.unparse(tree.body[-1]), 'run_control()')
        module = {'__name__':'owned_protected_stdout_control', 'sys':sys, 'json':json,
                  'OPERATION_ID':'00000000-0000-4000-8000-000000000001',
                  'PHASES':[{'phase':'previous-completed-evidence','state':'qualified'}],
                  'control_code':lambda error:error.args[0],
                  'need':lambda value,reason:None if value else (_ for _ in ()).throw(ValueError(reason))}
        exec(compile(ast.Module(body=tree.body[:-1],type_ignores=[]),'held-whole-control-body','exec'),module)
        def refuse(): raise ValueError('owned_preparation_refusal')
        module['prepare_control_root'] = refuse
        output = io.StringIO()
        with contextlib.redirect_stdout(output): module['run_control']()
        report = json.loads(output.getvalue())
        self.assertEqual(report['controlFailure'],'owned_preparation_refusal')
        self.assertEqual(report['phases'],module['PHASES'])
        self.assertEqual(report['state'],'unknown')
        self.assertIs(report['nativeStartRun'],False)


@unittest.skipUnless(os.name == 'posix', 'emitted Linux root/flock namespace requires POSIX')
class SourceTests(unittest.TestCase):
    def test_before_inspection_closes_required_time_uuid_namespace(self):
        _, parent = capsule(True)
        _, current = capsule(False)
        self.assertNotIn('uuid', parent.__dict__)
        self.assertNotIn('time', parent.__dict__)
        before = os.environ.get('VPN_CONTROL_INTERVAL_CAPTURE_BEFORE') == '1'
        path = BEFORES / ('capture-only.before.source' if before else 'capture-only.fixed.source')
        raw = path.read_bytes()
        expected = ('4859dea6f90419bb5c2b761595e73182938d1e1e7122283cf8b93ffc3e437250' if before else
                    'a412c4c3cc74fbd38ae3ffb1dd5a1ee4f1010a1d0caa08af945d71b647b73e56')
        self.assertEqual(hashlib.sha256(raw).hexdigest(), expected)
        parent._current_host_attempt = parent.installer_host_preflight
        parent.CURRENT_INTERVAL_STORAGE = {'operationId':'00000000-0000-4000-8000-000000000001'}
        for name in ('CURRENT_INTERVAL_PARENT_CAPSULE_SHA','CURRENT_INTERVAL_SCANNER_SHA',
                     'CURRENT_INTERVAL_VALIDATOR_SHA','CURRENT_INTERVAL_CLOSING_START','CURRENT_INTERVAL_CLOSING_END'):
            parent.__dict__[name] = current.__dict__[name]
        exec(compile(raw,'held-exact-before-inspection-dependencies','exec'),parent.__dict__)
        try: raise ValueError('owned_evidence_probe')
        except ValueError as error:
            report = parent._interval_capture(error,'0'*32,0,{})
        self.assertEqual(report['error']['code'],'owned_evidence_probe')
        self.assertEqual(len(report['recordId']),32)
        self.assertGreater(report['capturedAtNs'],0)
        self.assertIs(report['unknownInterval'],True)
        self.assertIs(report['retryable'],False)

    def test_both_scanners_projectors_and_current_guard_stay_exact(self):
        old, previous = capsule(True)
        new, current = capsule(False)
        for name in ('EFFECT_PLANE_FIXED', 'CURRENT1E15_EFFECT_PLANE_FIXED'):
            self.assertEqual(current.__dict__[name], previous.__dict__[name])
        a, b = ast.parse(old['source']), ast.parse(new['source'])
        for name in ('component_release_effect_plane_current_guard', 'component_release_current1e15_effect_plane_guard'):
            before = next(node for node in a.body if isinstance(node, ast.FunctionDef) and node.name == name)
            after = next(node for node in b.body if isinstance(node, ast.FunctionDef) and node.name == name)
            self.assertEqual(ast.dump(before, include_attributes=False), ast.dump(after, include_attributes=False))
        original = next(node for node in a.body if isinstance(node, ast.FunctionDef) and node.name == 'installer_host_preflight')
        renamed = next(node for node in b.body if isinstance(node, ast.FunctionDef) and node.name == '_current_host_attempt')
        renamed.name = original.name
        self.assertEqual(ast.dump(original, include_attributes=False), ast.dump(renamed, include_attributes=False))


if __name__ == '__main__': unittest.main()

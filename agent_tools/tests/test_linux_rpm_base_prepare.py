import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from agent_tools import linux_rpm_base_prepare as base


SHA = 'a' * 40
FINGERPRINT = 'b' * 64
CORRELATION = '12345678-1234-1234-1234-123456789abc'
OLD_HEADER = '1' * 40
NEW_HEADER = '2' * 40


class FakeDriver:
    def __init__(self, responses, on_call=None):
        self.responses = list(responses)
        self.calls = []
        self.on_call = on_call

    def _remote(self, config, host, program, args, payload=None, privileged=False, diagnostic=False):
        self.calls.append((host, program, args, payload, privileged))
        if self.on_call:
            self.on_call(payload)
        return self.responses.pop(0)


class LinuxRpmBasePrepareTest(unittest.TestCase):
    def test_same_version_replacement_requires_distinct_pinned_header(self):
        with tempfile.TemporaryDirectory() as temporary:
            request, _ = self.request(Path(temporary))
            request['expectedCurrentNevra'] = request['expectedBaseNevra']
            request['expectedCurrentHeaderSha1'] = OLD_HEADER
            self.assertEqual(request, base._request(request))
            for header in (None, '', 'x' * 40):
                changed = dict(request)
                if header is None:
                    del changed['expectedCurrentHeaderSha1']
                else:
                    changed['expectedCurrentHeaderSha1'] = header
                with self.assertRaises(base.LinuxRpmBasePrepareError):
                    base._request(changed)

    def test_replacement_command_decision_requires_fresh_header_mismatch(self):
        namespace = {}
        exec(base._COMMON, namespace)
        decision = namespace['base_install_command']
        same = 'vpn-control-2.1.19-1.x86_64'
        self.assertEqual(['rpm', '-Uvh', '--replacepkgs', '--', '/fixed/base.rpm'],
                         decision(same, same, OLD_HEADER, NEW_HEADER, '/fixed/base.rpm',
                                  expected_current_header=OLD_HEADER))
        self.assertIsNone(decision(same, same, OLD_HEADER, OLD_HEADER, '/fixed/base.rpm',
                                   expected_current_header=OLD_HEADER))
        self.assertIsNone(decision(same, same, OLD_HEADER, NEW_HEADER, '/fixed/base.rpm'))
        self.assertIsNone(decision(same, same, '3' * 40, NEW_HEADER, '/fixed/base.rpm',
                                   expected_current_header=OLD_HEADER))

    @staticmethod
    def protected_inventory(phase='SUCCEEDED', gate_pending=False):
        return {'state': 'observed', 'rootState': 'readable', 'truncated': False,
                'entryCount': 4, 'entries': [
                    {'kind': 'regular', 'guardName': 'gate-linux', 'guardState': 'trusted',
                     'gatePending': gate_pending, 'nameHash': '0' * 16},
                    {'kind': 'regular', 'guardName': 'reservation-linux', 'guardState': 'trusted',
                     'reservationLocked': False, 'nameHash': '1' * 16},
                    {'kind': 'directory', 'jobId': '7b7b99aa-6401-4289-9bb1-c0d74355269f',
                     'receiptState': 'terminal', 'phase': phase, 'nameHash': '2' * 16},
                    {'kind': 'directory', 'jobId': 'd1d5a85f-a334-401b-95d9-e985e08bf630',
                     'receiptState': 'terminal', 'phase': 'SUCCEEDED', 'nameHash': '3' * 16}]}

    def test_four_entry_protected_inventory_no_longer_false_blocks_preflight(self):
        namespace = {}
        exec(base._COMMON, namespace)
        namespace['protected_job_inventory'] = lambda: self.protected_inventory()
        completed = subprocess.CompletedProcess(['rpm'], 0, 'vpn-control-2.1.17-1.x86_64', '')
        guard = SimpleNamespace(name='gate-linux', is_dir=lambda follow_symlinks=False: False)
        with mock.patch('os.geteuid', return_value=0), \
             mock.patch('pwd.getpwnam', return_value=SimpleNamespace(pw_uid=1001)), \
             mock.patch('os.scandir', side_effect=lambda path: [] if path == '/proc' else [guard]), \
             mock.patch('os.path.lexists', return_value=True), \
             mock.patch('os.stat', return_value=SimpleNamespace(st_mode=0o40755, st_uid=0)), \
             mock.patch('subprocess.run', return_value=completed):
            value = namespace['inspect']('vpn-control-2.1.17-1.x86_64')
        self.assertEqual('ready', value['state'])

    def test_protected_inventory_rejects_active_unknown_or_failed_entries(self):
        namespace = {}
        exec(base._COMMON, namespace)
        admit = namespace['admit_protected_inventory']
        for change in (
            lambda value: value['entries'][2].update(phase='FAILED'),
            lambda value: value['entries'][2].update(receiptState='active'),
            lambda value: value['entries'][0].update(gatePending=True),
            lambda value: value.update(state='unknown'),
            lambda value: value['entries'][0].update(guardState='untrusted'),
            lambda value: value['entries'][1].update(gatePending=False),
            lambda value: value['entries'][1].update(jobId='12345678-1234-1234-1234-123456789abc'),
            lambda value: value['entries'][2].update(guardName='gate-linux'),
        ):
            value = self.protected_inventory()
            change(value)
            self.assertNotEqual('ready', admit(value)['state'])

    def test_held_reservation_blocks_even_when_gate_clear_and_jobs_terminal(self):
        namespace = {}
        exec(base._COMMON, namespace)
        value = self.protected_inventory()
        value['entries'][1]['reservationLocked'] = True
        decision = namespace['admit_protected_inventory'](value)
        self.assertEqual('blocked', decision['state'])
        self.assertEqual('pending-installer', decision['reason'])
        self.assertIn('hold_reservation', base._WORKER)

    def test_held_reservation_never_admits_absent_root_or_replaced_guard(self):
        namespace = {}
        exec(base._COMMON, namespace)
        self.assertNotEqual('ready', namespace['admit_protected_inventory'](
            {'state': 'observed', 'rootState': 'absent', 'entries': [],
             'entryCount': 0, 'truncated': False}, held_by_us=True)['state'])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'reservation-linux'
            path.write_bytes(b'')
            fd = os.open(path, os.O_RDONLY)
            try:
                self.assertTrue(namespace['reservation_identity'](fd, str(path)))
                path.unlink()
                path.write_bytes(b'')
                self.assertFalse(namespace['reservation_identity'](fd, str(path)))
            finally:
                os.close(fd)

    def test_worker_holds_reservation_across_final_inspect_and_rpm(self):
        worker = base._WORKER
        lock = worker.index('reservation_fd=hold_reservation()')
        inspect = worker.index('pre=inspect(', lock)
        rpm = worker.index('command=subprocess.run(argv', inspect)
        release = worker.index('os.close(reservation_fd)', rpm)
        self.assertLess(lock, inspect)
        self.assertLess(inspect, rpm)
        self.assertLess(rpm, release)

    def request(self, root):
        package = root / 'base.rpm'
        package.write_bytes(b'fake-rpm')
        digest = hashlib.sha256(package.read_bytes()).hexdigest()
        artifact = {'platform': 'linux', 'artifactKind': 'package', 'sourceSha': SHA,
                    'sourceFingerprint': FINGERPRINT, 'sha256': digest}
        verified = {'verification': 'verified', 'artifact': artifact,
                    'location': {'localPath': str(package)}}
        request = {'host': 'fedora2328', 'environment': 'fedora2328',
                   'baseArtifactId': 'sha256-' + digest, 'sourceSha': SHA,
                   'sourceFingerprint': FINGERPRINT,
                   'expectedCurrentNevra': 'vpn-control-2.1.17-1.x86_64',
                   'expectedBaseNevra': 'vpn-control-2.1.19-1.x86_64',
                   'correlationId': CORRELATION}
        return request, verified

    def test_active_runtime_blocks_before_journal_or_payload(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            request, verified = self.request(root)
            driver = FakeDriver([{'state': 'blocked', 'reason': 'active-runtime'}])
            with mock.patch.object(base, '_admitted', return_value=(Path(verified['location']['localPath']), object())), \
                 mock.patch.object(base, '_driver', return_value=driver):
                result = base.start(root, request)
            self.assertEqual('blocked', result['state'])
            self.assertEqual(1, len(driver.calls))
            self.assertFalse((root / '.rag_index/linux-rpm-base-prepare').exists())

    def test_same_version_current_header_mismatch_blocks_before_journal_or_payload(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            request, verified = self.request(root)
            request['expectedCurrentNevra'] = request['expectedBaseNevra']
            request['expectedCurrentHeaderSha1'] = OLD_HEADER
            driver = FakeDriver([{'state': 'ready', 'currentNevra': request['expectedCurrentNevra'],
                                  'currentHeaderSha1': NEW_HEADER}])
            with mock.patch.object(base, '_admitted', return_value=(Path(verified['location']['localPath']), object())), \
                 mock.patch.object(base, '_driver', return_value=driver):
                result = base.start(root, request)
            self.assertEqual('blocked', result['state'])
            self.assertEqual('current-header-mismatch', result['reason'])
            self.assertEqual(1, len(driver.calls))
            self.assertEqual((request['expectedCurrentNevra'], 'header'), driver.calls[0][2])
            self.assertFalse((root / '.rag_index/linux-rpm-base-prepare').exists())

    def test_header_preflight_returns_only_valid_current_header(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = mock.Mock(hosts={'fedora2328': mock.Mock(user='vpnfixture')})
            value = {'host': 'fedora2328', 'environment': 'fedora2328',
                     'expectedCurrentNevra': 'vpn-control-2.1.19-1.x86_64',
                     'includeCurrentHeader': True}
            driver = FakeDriver([{'state': 'ready', 'currentNevra': value['expectedCurrentNevra'],
                                  'currentHeaderSha1': OLD_HEADER},
                                 {'state': 'ready', 'currentNevra': value['expectedCurrentNevra'],
                                  'currentHeaderSha1': 'unsafe'}])
            with mock.patch.object(base.ssh_transport, 'load_config', return_value=config), \
                 mock.patch.object(base, '_driver', return_value=driver):
                first = base.preflight(root, value)
                second = base.preflight(root, value)
            self.assertEqual(OLD_HEADER, first['currentHeaderSha1'])
            self.assertEqual('unknown', second['state'])
            self.assertEqual('current-header-unavailable', second['reason'])

    def test_intent_precedes_payload_and_uncertain_submission_never_replays(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            request, verified = self.request(root)
            def check_journal(payload):
                if payload is not None:
                    journal = root / '.rag_index/linux-rpm-base-prepare' / (CORRELATION + '.json')
                    self.assertTrue(journal.is_file())
            driver = FakeDriver([{'state': 'ready', 'currentNevra': request['expectedCurrentNevra']}, None], check_journal)
            with mock.patch.object(base, '_admitted', return_value=(Path(verified['location']['localPath']), object())), \
                 mock.patch.object(base, '_driver', return_value=driver):
                result = base.start(root, request)
                replay = base.start(root, request)
            self.assertEqual('unknown', result['state'])
            self.assertEqual('unknown', replay['state'])
            self.assertFalse(replay['replayAllowed'])
            self.assertEqual(2, len(driver.calls))
            self.assertTrue((root / '.rag_index/linux-rpm-base-prepare' / (CORRELATION + '.json')).is_file())

    def test_schema_and_remote_program_restrict_operation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            request, _ = self.request(root)
            with self.assertRaises(base.LinuxRpmBasePrepareError):
                base.start(root, dict(request, command='rpm -e vpn-control'))
            self.assertIn('rpm', base._WORKER)
            self.assertIn('active-runtime', base._PREFLIGHT)
            self.assertNotIn('systemctl stop', base._WORKER)

    def test_rejects_downgrade_before_guest_or_artifact_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            request, _ = self.request(root)
            request['expectedCurrentNevra'] = 'vpn-control-2.2.0-1.x86_64'
            with self.assertRaisesRegex(base.LinuxRpmBasePrepareError, 'newer'):
                base.start(root, request)
            self.assertFalse((root / '.rag_index').exists())

    def test_fixed_remote_programs_compile_as_dispatched(self):
        for name in ('_PREFLIGHT', '_SUBMIT', '_WORKER', '_STATUS', '_OWNER_OBSERVE'):
            with self.subTest(program=name):
                compile(getattr(base, name), name, 'exec')

    def test_driver_timeout_stays_within_governed_ssh_bound(self):
        driver = base._driver(Path('/tmp'))
        self.assertGreaterEqual(driver.timeout_seconds, 1)
        self.assertLessEqual(driver.timeout_seconds, 60)

    def test_preflight_reports_guest_block_without_creating_journal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            driver = FakeDriver([{'state': 'blocked', 'reason': 'pending-installer',
                                  'currentNevra': 'vpn-control-2.1.17-1.x86_64'}])
            config = mock.Mock(hosts={'fedora2328': mock.Mock(user='vpnfixture')})
            with mock.patch.object(base.ssh_transport, 'load_config', return_value=config), \
                 mock.patch.object(base, '_driver', return_value=driver):
                result = base.preflight(root, {'host': 'fedora2328', 'environment': 'fedora2328',
                                               'expectedCurrentNevra': 'vpn-control-2.1.17-1.x86_64'})
            self.assertEqual('blocked', result['state'])
            self.assertEqual('pending-installer', result['reason'])
            self.assertFalse((root / '.rag_index').exists())

    def test_privileged_observer_ignores_own_sudo_python_command_text(self):
        namespace = {}
        exec(base._COMMON, namespace)
        process = SimpleNamespace(name='777', path='/proc/777')
        def read(path, *args, **kwargs):
            if path.endswith('/status'):
                return io.StringIO('Uid:\t0\t0\t0\t0\n')
            if path.endswith('/cmdline'):
                return io.BytesIO(b'sudo\0python3\0-c\0com.kardinal.vpncontrol\0')
            raise AssertionError(path)
        completed = subprocess.CompletedProcess(['rpm'], 0, 'vpn-control-2.1.17-1.x86_64', '')
        with mock.patch('os.geteuid', return_value=0), \
             mock.patch('os.getpid', return_value=999), \
             mock.patch('pwd.getpwnam', return_value=SimpleNamespace(pw_uid=1001)), \
             mock.patch('os.scandir', return_value=[process]), \
             mock.patch('os.path.lexists', return_value=False), \
             mock.patch('subprocess.run', return_value=completed), \
             mock.patch('builtins.open', side_effect=read):
            observed = namespace['inspect']('vpn-control-2.1.17-1.x86_64')
        self.assertEqual('ready', observed['state'])

    def test_observer_ignores_fixture_uid_ssh_sudo_wrapper_text(self):
        namespace = {}
        exec(base._COMMON, namespace)
        process = SimpleNamespace(name='778', path='/proc/778')
        def read(path, *args, **kwargs):
            if path.endswith('/status'):
                return io.StringIO('Uid:\t1001\t1001\t1001\t1001\n')
            if path.endswith('/cmdline'):
                return io.BytesIO(b'sudo\0-n\0python3\0-c\0com.kardinal.vpncontrol\0')
            raise AssertionError(path)
        completed = subprocess.CompletedProcess(['rpm'], 0, 'vpn-control-2.1.17-1.x86_64', '')
        with mock.patch('os.geteuid', return_value=0), \
             mock.patch('os.getpid', return_value=999), \
             mock.patch('pwd.getpwnam', return_value=SimpleNamespace(pw_uid=1001)), \
             mock.patch('os.scandir', return_value=[process]), \
             mock.patch('os.path.lexists', return_value=False), \
             mock.patch('subprocess.run', return_value=completed), \
             mock.patch('builtins.open', side_effect=read):
            observed = namespace['inspect']('vpn-control-2.1.17-1.x86_64')
        self.assertEqual('ready', observed['state'])

    def test_observer_reports_bounded_active_identity_without_command_line(self):
        namespace = {}
        exec(base._COMMON, namespace)
        process = SimpleNamespace(name='781', path='/proc/781')
        def read(path, *args, **kwargs):
            if path.endswith('/status'):
                return io.StringIO('Uid:\t1001\t1001\t1001\t1001\n')
            if path.endswith('/cmdline'):
                return io.BytesIO(b'java\0com.kardinal.vpncontrol.desktop.Main\0secret\0')
            if path.endswith('/stat'):
                return io.StringIO('781 (java) S ' + ' '.join(['1'] * 18) + ' 12345\n')
            raise AssertionError(path)
        completed = subprocess.CompletedProcess(['rpm'], 0, 'vpn-control-2.1.17-1.x86_64', '')
        with mock.patch('os.geteuid', return_value=0), \
             mock.patch('os.getpid', return_value=999), \
             mock.patch('pwd.getpwnam', return_value=SimpleNamespace(pw_uid=1001)), \
             mock.patch('os.scandir', return_value=[process]), \
             mock.patch('os.path.lexists', return_value=False), \
             mock.patch('subprocess.run', return_value=completed), \
             mock.patch('builtins.open', side_effect=read):
            observed = namespace['inspect']('vpn-control-2.1.17-1.x86_64')
        self.assertEqual('blocked', observed['state'])
        self.assertEqual('active-runtime', observed['reason'])
        self.assertEqual([{'pid': 781, 'startTicks': 12345, 'executable': 'java'}], observed['activeProcesses'])
        self.assertNotIn('secret', json.dumps(observed))

    def test_owner_observer_requires_exact_generation_and_returns_only_bounded_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            owner = {'state': 'observed', 'pid': 18367, 'startTicks': 2078693,
                     'controllerId': 'controller', 'runtimeRunning': False,
                     'selectedLocationId': 'selection-id', 'activeLocationId': None,
                     'configuredMode': 'PROXY_ONLY', 'activeMode': None, 'runtimeId': None,
                     'trafficInterruptionRisk': 'no-app-runtime', 'controlSessionRisk': 'unknown'}
            driver = FakeDriver([owner])
            config = mock.Mock(hosts={'fedora2328': mock.Mock(user='vpnfixture')})
            with mock.patch.object(base.ssh_transport, 'load_config', return_value=config), \
                 mock.patch.object(base, '_driver', return_value=driver):
                result = base.observe_owner(root, {'host': 'fedora2328', 'environment': 'fedora2328',
                                                   'pid': 18367, 'startTicks': 2078693})
            self.assertEqual('observed', result['state'])
            self.assertFalse(result['runtimeRunning'])
            self.assertNotIn('stateDir', result)
            self.assertFalse((root / '.rag_index').exists())


if __name__ == '__main__':
    unittest.main()

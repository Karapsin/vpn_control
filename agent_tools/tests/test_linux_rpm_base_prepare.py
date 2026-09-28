import hashlib
import io
import json
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

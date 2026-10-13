"""Existing status admission and exact private binary custody controls."""
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from unittest.mock import MagicMock

_POSIX = False
if os.name == 'posix':
    try:
        import fcntl
    except ImportError:
        pass
    else:
        from agent_tools import android_installer_dispatch as dispatch
        from agent_tools import android_original_host_status as observer
        from agent_tools import private_inventory_lock as private
        _POSIX = True


@unittest.skipUnless(_POSIX, 'POSIX native coordinator required')
class ExistingStatusAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.bundle = {'toolBundleId': observer.ORIGINAL_BUNDLE,
                       'reviewedTreeSha256': 'a' * 64, 'manifest': []}
        self.intent = {'correlationId': observer.ORIGINAL, 'host': 'archlinux',
                       'device': 'api35', 'toolBundleId': observer.ORIGINAL_BUNDLE,
                       'fixtureRoot': '/fixed-private-fixture',
                       'remote': {'toolBundle': self.bundle}}
        self.config = SimpleNamespace(hosts={'archlinux': SimpleNamespace(
            fixture_transfer_root=self.intent['fixtureRoot'])})

    def test_original_status_preserves_existing_eight_key_unknown_and_lease(self):
        with patch.object(dispatch.android_installer_tool_bundle, 'load', return_value=self.bundle) as load, \
                patch.object(dispatch.ssh_transport, 'load_config', return_value=self.config), \
                patch.object(dispatch.ssh_transport, 'connection_host', return_value=SimpleNamespace(password=None)), \
                patch.object(observer, 'observe_original', return_value={'state': 'unknown', 'reason': 'worker_or_receipt_unknown'}) as read, \
                patch.object(dispatch.ssh_transport, 'build_ssh_argv') as legacy:
            result = dispatch._result(self.intent, dispatch._remote(Path('/tmp'), self.intent, 'status'))
        load.assert_called_once_with(Path('/tmp'), observer.ORIGINAL_BUNDLE)
        read.assert_called_once_with(Path('/tmp'), self.intent)
        legacy.assert_not_called()
        self.assertEqual({'ok': False, 'state': 'unknown', 'reason': 'worker_or_receipt_unknown',
                          'correlationId': observer.ORIGINAL, 'result': None, 'identity': None,
                          'leaseReleased': False, 'replayAllowed': False}, result)

    def test_existing_bundle_mismatch_refuses_before_leaf_or_transport(self):
        with patch.object(dispatch.android_installer_tool_bundle, 'load', return_value={**self.bundle, 'manifest': ['changed']}), \
                patch.object(observer, 'observe_original') as read, \
                patch.object(dispatch.ssh_transport, 'build_ssh_argv') as transport:
            with self.assertRaisesRegex(ValueError, 'bundle binding changed'):
                dispatch._remote(Path('/tmp'), self.intent, 'status')
        read.assert_not_called()
        transport.assert_not_called()

    def test_existing_route_mismatch_refuses_before_leaf_or_transport(self):
        with patch.object(dispatch.android_installer_tool_bundle, 'load', return_value=self.bundle), \
                patch.object(dispatch.ssh_transport, 'load_config', return_value=self.config), \
                patch.object(dispatch.ssh_transport, 'connection_host', return_value=SimpleNamespace(password='wrong-route')), \
                patch.object(observer, 'observe_original') as read, \
                patch.object(dispatch.ssh_transport, 'build_ssh_argv') as transport:
            result = dispatch._remote(Path('/tmp'), self.intent, 'status')
        self.assertEqual({'state': 'unknown', 'reason': 'route_changed'}, result)
        read.assert_not_called()
        transport.assert_not_called()

    def test_other_correlations_continue_existing_adapter(self):
        self.intent['correlationId'] = '11111111-1111-4111-8111-111111111111'
        with patch.object(dispatch.android_installer_tool_bundle, 'load', return_value=self.bundle), \
                patch.object(dispatch.ssh_transport, 'load_config', return_value=self.config), \
                patch.object(dispatch.ssh_transport, 'connection_host', return_value=SimpleNamespace(password=None)), \
                patch.object(observer, 'observe_original') as read, \
                patch.object(dispatch.ssh_transport, 'build_ssh_argv', return_value=['inert']) as transport, \
                patch.object(dispatch.ssh_transfer, '_bounded_run', return_value=(0, b'{"state":"unknown","correlationId":"11111111-1111-4111-8111-111111111111"}')):
            self.assertEqual('unknown', dispatch._remote(Path('/tmp'), self.intent, 'status')['state'])
        read.assert_not_called()
        transport.assert_called_once()

    def test_leaf_refuses_other_identity_before_any_native_or_filesystem_capture(self):
        for field, wrong in [('correlationId', 'other'), ('host', 'other'), ('device', 'api29'), ('toolBundleId', 'other')]:
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'only_reviewed_original'):
                observer.observe_original('/absent-inert-root', {**self.intent, field: wrong})

    def test_original_staged_cli_is_independent_of_configured_fresh_cli(self):
        from agent_tools import ssh_direct_nested_channel as direct
        from agent_tools import android_observation, android_installer_tool_bundle, ssh_transport
        with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve()) as temporary:
            root = Path(temporary)
            parent = root / '.rag_index/android-installer-dispatch' / observer.ORIGINAL
            parent.mkdir(mode=0o700, parents=True)
            intent = {**self.intent, 'remote': {**self.intent['remote'],
                'serial': 'emulator-5682', 'avd': 'fixed-owned-avd', 'api': 35,
                'adb': '/fixed/adb', 'cli': '/immutable/original-staged-cli'}}
            profile = {'serial': 'emulator-5682', 'expectedAvd': 'fixed-owned-avd',
                       'api': 35, 'adb': '/fixed/adb', 'cli': '/configured/fresh-cli'}
            guard = MagicMock()
            guard.source_pins = {}; guard.authority_sha = 'a' * 64
            guard.config.hosts = {'archlinux': SimpleNamespace(
                fixture_transfer_root=intent['fixtureRoot'], android_devices={'api35': {}})}
            guard.held.read.side_effect = lambda path, digest: json.dumps(intent).encode() if path.endswith('/dispatch.json') else b'held'
            with patch.object(direct, 'coordinator_capable', return_value=True), \
                    patch.object(direct, 'Guard', return_value=guard), \
                    patch.object(android_observation, '_profile', return_value=profile), \
                    patch.object(android_installer_tool_bundle, 'load', return_value=self.bundle), \
                    patch.object(ssh_transport, 'build_ssh_argv', side_effect=OSError('inert transport boundary')) as transport:
                value = observer.observe_original(root, intent)
            transport.assert_called_once()
            self.assertEqual({'state': 'unknown', 'reason': 'transport_or_receipt_unknown'}, value)
            pins = [call.args[1] for call in guard.held.read.call_args_list]
            self.assertIn(observer.ORIGINAL_DISPATCH_SHA, pins)
            self.assertIn(observer.ORIGINAL_INTENT_SHA, pins)
            self.assertIn(observer.ORIGINAL_LEASE_SHA, pins)
            guard.close.assert_called_once()
            for field in ('serial', 'expectedAvd', 'api', 'adb'):
                with self.subTest(refusedField=field), \
                        patch.object(direct, 'coordinator_capable', return_value=True), \
                        patch.object(direct, 'Guard', return_value=guard), \
                        patch.object(android_observation, '_profile', return_value={**profile, field: 'changed'}), \
                        patch.object(android_installer_tool_bundle, 'load', return_value=self.bundle), \
                        patch.object(ssh_transport, 'build_ssh_argv') as transport:
                    value = observer.observe_original(root, intent)
                    transport.assert_not_called()
                    self.assertEqual('transport_or_receipt_unknown', value['reason'])
            # The staged CLI remains bound by the exact original dispatch,
            # even though the configured fresh CLI can have a different path.
            with patch.object(direct, 'coordinator_capable', return_value=True), \
                    patch.object(direct, 'Guard', return_value=guard), \
                    patch.object(ssh_transport, 'build_ssh_argv') as transport:
                value = observer.observe_original(root, {**intent, 'remote': {**intent['remote'], 'cli': '/replaced-original-cli'}})
                transport.assert_not_called()
                self.assertEqual('transport_or_receipt_unknown', value['reason'])


@unittest.skipUnless(_POSIX, 'POSIX descriptor custody required')
class PrivateBinaryCustodyTests(unittest.TestCase):
    def test_exact_binary_capture_empty_stderr_and_private_mode(self):
        with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve()) as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            binary = b'\0\xff\xfe\r\n' * 13001
            with private.Directory(root) as directory:
                observer._write(directory, 'stdout.private', binary)
                observer._write(directory, 'stderr.private', b'')
            actual = (root / 'stdout.private').read_bytes()
            self.assertEqual(binary, actual)
            self.assertEqual(hashlib.sha256(binary).digest(), hashlib.sha256(actual).digest())
            self.assertEqual(b'', (root / 'stderr.private').read_bytes())
            self.assertEqual(0o600, stat.S_IMODE((root / 'stdout.private').stat().st_mode))

    def test_existing_symlink_never_overwrites_target(self):
        with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve()) as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            target = root / 'target'; target.write_bytes(b'original')
            (root / 'stdout.private').symlink_to(target)
            with private.Directory(root) as directory, self.assertRaises(FileExistsError):
                observer._write(directory, 'stdout.private', b'replacement')
            self.assertEqual(b'original', target.read_bytes())

    def test_replaced_named_directory_refuses_capture(self):
        with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve()) as temporary:
            parent = Path(temporary)
            root = parent / 'capture'; root.mkdir(mode=0o700)
            with private.Directory(root) as directory:
                root.rename(parent / 'before')
                root.mkdir(mode=0o700)
                with self.assertRaisesRegex(ValueError, 'named parent changed'):
                    observer._write(directory, 'stdout.private', b'replacement')
            self.assertFalse((root / 'stdout.private').exists())
            self.assertFalse((parent / 'before' / 'stdout.private').exists())


if __name__ == '__main__':
    unittest.main()

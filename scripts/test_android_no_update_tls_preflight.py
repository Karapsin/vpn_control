import hashlib
import importlib.util
import json
import sys
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).with_name('android_no_update_tls_preflight.py')
spec = importlib.util.spec_from_file_location('preflight', MODULE_PATH)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


class FakeAdb:
    def __init__(self, proxy_failure=False, remove_failures=0):
        self.reverse_map = {}
        self.proxy = 'null'
        self.proxy_failure = proxy_failure
        self.remove_failures = remove_failures
        self.rooted = False
        self.pid_calls = 0
        self.calls = []
        self.records = []
    def reverse_mapping(self, port): return self.reverse_map.get(port)
    def reverse(self, device, host): self.reverse_map[device] = host
    def remove_reverse(self, device):
        if self.remove_failures:
            self.remove_failures -= 1
            raise OSError('remove reverse')
        self.reverse_map.pop(device)
    def global_proxy(self): return self.proxy
    def set_global_proxy(self, value):
        if self.proxy_failure: raise OSError('proxy')
        self.proxy = value
    def reverse_inventory(self): return dict(self.reverse_map)
    def shell_id(self): return 'uid=2000'
    def run(self, *args):
        self.calls.append(args)
        if args == ('root',): self.rooted = True
        return ''
    def wait_for_device(self): pass
    def unroot(self): self.rooted = False
    def exec_out_bytes(self, *args):
        self.calls.append(('exec-out', *args))
        return b'base'
    def shell(self, *args):
        self.calls.append(('shell', *args))
        if args == ('getprop', 'ro.kernel.qemu.avd_name'): return 'avd'
        if args == ('getprop', 'ro.build.version.sdk'): return '29'
        if args == ('dumpsys', 'package', 'com.kardinal.vpncontrol'):
            return 'versionName=2.2.19 versionCode=17180 flags=[HAS_CODE]'
        if args == ('pm', 'path', 'com.kardinal.vpncontrol'):
            return 'package:/data/app/base.apk'
        if args[:2] == ('pidof', 'zygote64'):
            self.pid_calls += 1; return '177' if self.pid_calls == 1 else '178'
        if args[:2] == ('date', '+%s'): return '100'
        return ''


class PreflightScriptTest(unittest.TestCase):
    def test_emulator_identity_accepts_legacy_or_boot_only_and_rejects_missing_or_conflict(self):
        class IdentityAdb:
            def __init__(self, kernel, boot): self.values = {"ro.kernel.qemu.avd_name": kernel, "ro.boot.qemu.avd_name": boot}
            def shell(self, *args):
                self.asserted = args
                return self.values[args[1]]
        self.assertEqual('api29', preflight.require_emulator_avd_name(IdentityAdb('api29', '')))
        self.assertEqual('api35', preflight.require_emulator_avd_name(IdentityAdb('', 'api35')))
        with self.assertRaisesRegex(RuntimeError, 'missing'):
            preflight.require_emulator_avd_name(IdentityAdb('', ''))
        with self.assertRaisesRegex(RuntimeError, 'conflicting'):
            preflight.require_emulator_avd_name(IdentityAdb('api29', 'api35'))

    def test_baseline_admits_boot_only_api35_identity_with_valid_off_package_and_hash(self):
        class BootOnlyAdb(FakeAdb):
            def shell(self, *args):
                if args == ('getprop', 'ro.kernel.qemu.avd_name'):
                    self.calls.append(('shell', *args)); return ''
                if args == ('getprop', 'ro.boot.qemu.avd_name'):
                    self.calls.append(('shell', *args)); return 'api35'
                if args == ('getprop', 'ro.build.version.sdk'):
                    self.calls.append(('shell', *args)); return '35'
                return super().shell(*args)
        adb = BootOnlyAdb()
        status = {'ok': True, 'controllerId': 'owner', 'data': {'runtimeRunning': False}}
        completed = type('Result', (), {'stdout': json.dumps(status)})()
        digest = hashlib.sha256(b'base').hexdigest()
        with patch.object(preflight.subprocess, 'run', return_value=completed):
            baseline = preflight.verify_public_baseline(adb, Path('cli.py'), 'serial', 'api35', '35', '2.2.19', '17180', digest)
        self.assertEqual('api35', baseline['avd'])
        self.assertEqual(digest, baseline['installedBaseSha256'])
        self.assertIn(('shell', 'getprop', 'ro.kernel.qemu.avd_name'), adb.calls)
        self.assertIn(('shell', 'getprop', 'ro.boot.qemu.avd_name'), adb.calls)

    def test_baseline_rejects_running_before_any_root_step(self):
        adb = FakeAdb()
        status = {'ok': True, 'data': {'runtimeRunning': True}}
        completed = type('Result', (), {'stdout': json.dumps(status)})()
        with patch.object(preflight.subprocess, 'run', return_value=completed), self.assertRaises(RuntimeError):
            preflight.verify_public_baseline(adb, Path('cli.py'), 'serial', 'avd', '29', '2.2.19', '17180', hashlib.sha256(b'base').hexdigest())
        self.assertNotIn(('root',), adb.calls)

    def test_artifact_hash_and_safe_leaf_are_enforced(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / 'base.apk'; p.write_bytes(b'base')
            preflight.require_artifact_hash(p, hashlib.sha256(b'base').hexdigest())
            with self.assertRaises(RuntimeError): preflight.require_artifact_hash(p, '0' * 64)
        with self.assertRaises(ValueError): preflight.require_task_staging('/data/local/tmp/vpn-control-a/nested')
        with self.assertRaises(ValueError): preflight.require_task_staging('/data/local/tmp/vpn-control-a;rm')

    def test_installed_base_hash_requires_exact_device_bytes(self):
        adb = FakeAdb()
        package = 'package:/data/app/base.apk\n'
        digest = hashlib.sha256(b'base').hexdigest()
        self.assertEqual(digest, preflight.require_installed_base_hash(adb, package, digest))
        with self.assertRaises(RuntimeError):
            preflight.require_installed_base_hash(adb, package, '0' * 64)
        self.assertIn(('exec-out', 'cat', '/data/app/base.apk'), adb.calls)

    def test_proxy_failure_releases_exact_reverse(self):
        adb = FakeAdb(proxy_failure=True)
        with self.assertRaises(OSError):
            preflight.establish_owned_transport(adb, 45390, 61000, 'null')
        self.assertEqual({}, adb.reverse_map)
        self.assertEqual('null', adb.proxy)

    def test_changed_zygote_cleanup_records_failure_but_restores_public_and_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); base = root / 'base.apk'; cert = root / 'ca.pem'; leaf = root / 'leaf.pem'; receipt = root / 'receipt.json'
            base.write_bytes(b'base')
            subprocess.run([
                'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', str(root / 'fixture.key'), '-out', str(cert), '-days', '1',
                '-subj', '/CN=vpn-control-preflight.test',
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            leaf.write_bytes(cert.read_bytes())
            fake = FakeAdb()
            argv = ['tool', '--adb', 'adb', '--serial', 'serial', '--cli', str(root / 'cli.py'),
                    '--certificate', str(cert), '--leaf-certificate', str(leaf), '--fixture-parent', str(root),
                    '--server-log', str(root / 'server.log'), '--probe-output', str(root / 'probe.txt'), '--device-port', '45390', '--host-port', '61000',
                    '--staging', '/data/local/tmp/vpn-control-test', '--receipt', str(receipt),
                    '--expected-avd', 'avd', '--expected-api', '29', '--expected-version', '2.2.19', '--expected-code', '17180',
                    '--base-apk', str(base), '--base-sha256', hashlib.sha256(b'base').hexdigest()]
            with patch.object(sys, 'argv', argv), patch.object(preflight, 'Adb', return_value=fake), \
                 patch.object(preflight, 'verify_public_baseline', return_value={}), \
                 patch.object(preflight, 'require_device_time_within_certificates'), \
                 patch.object(preflight, 'device_mode', return_value=0o755), \
                 patch.object(preflight, 'device_label', return_value='label'), \
                 patch.object(preflight, 'require_android_certificate_store_layout'), \
                 patch.object(preflight, 'relabel_staged_ca_store', return_value=[f"/data/local/tmp/vpn-control-test/{preflight.android_ca_store_filename(cert)}"]), \
                 patch.object(preflight, 'public_no_update_probe', return_value={}):
                with self.assertRaisesRegex(RuntimeError, 'cleanup'):
                    preflight.main()
            saved = json.loads(receipt.read_text())
            self.assertIn({'step': 'unmount', 'type': 'RuntimeError'}, saved['cleanupFailures'])
            self.assertEqual('/data/local/tmp/vpn-control-test', saved['retainedStaging'])
            self.assertFalse(fake.rooted)
            self.assertEqual({}, fake.reverse_map)
            self.assertNotIn(('shell', 'rm', '-r', '/data/local/tmp/vpn-control-test'), fake.calls)
            expected_filename = preflight.android_ca_store_filename(cert)
            self.assertIn(("push", str(cert), f"/data/local/tmp/vpn-control-test/{expected_filename}"), fake.calls)

    def test_lifecycle_target_install_metadata_defaults_false(self):
        import inspect
        signature = inspect.signature(preflight.run_fixture_lifecycle).parameters
        self.assertIs(False, signature['target_install'].default)
        self.assertEqual('/system/etc/security/cacerts', signature['ca_store_target'].default)
        self.assertEqual('null', signature['expected_proxy'].default)

    def test_lifecycle_rejects_unapproved_target_before_adb(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); base = root / 'base.apk'; base.write_bytes(b'base')
            args = SimpleNamespace(
                adb='adb', serial='serial', cli=root/'cli.py', certificate=root/'ca.pem', leaf_certificate=root/'leaf.pem',
                fixture_parent=root, server_log=root/'server.log', probe_output=root/'probe.txt',
                device_port=45390, host_port=61000, staging='/data/local/tmp/vpn-control-test', receipt=root/'receipt.json',
                expected_avd='avd', expected_api='29', expected_version='2.2.19', expected_code='17180',
                base_apk=base, base_sha256=hashlib.sha256(b'base').hexdigest(),
            )
            with patch.object(preflight, 'Adb') as adb:
                with self.assertRaisesRegex(ValueError, 'target'):
                    preflight.run_fixture_lifecycle(args, lambda *_: {}, ca_store_target='/unapproved/cacerts')
            adb.assert_not_called()

    def test_lifecycle_rejects_unapproved_proxy_before_adb(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); base = root / 'base.apk'; base.write_bytes(b'base')
            args = SimpleNamespace(
                adb='adb', serial='serial', cli=root/'cli.py', certificate=root/'ca.pem', leaf_certificate=root/'leaf.pem',
                fixture_parent=root, server_log=root/'server.log', probe_output=root/'probe.txt',
                device_port=45390, host_port=61000, staging='/data/local/tmp/vpn-control-test', receipt=root/'receipt.json',
                expected_avd='avd', expected_api='35', expected_version='2.2.19', expected_code='17180',
                base_apk=base, base_sha256=hashlib.sha256(b'base').hexdigest(),
            )
            with patch.object(preflight, 'Adb') as adb:
                with self.assertRaisesRegex(ValueError, 'proxy'):
                    preflight.run_fixture_lifecycle(args, lambda *_: {}, expected_proxy='127.0.0.1:18081')
            adb.assert_not_called()

    def test_lifecycle_rejects_proxy_mismatch_before_root_or_reverse(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); base = root / 'base.apk'; base.write_bytes(b'base')
            args = SimpleNamespace(
                adb='adb', serial='serial', cli=root/'cli.py', certificate=root/'ca.pem', leaf_certificate=root/'leaf.pem',
                fixture_parent=root, server_log=root/'server.log', probe_output=root/'probe.txt',
                device_port=45390, host_port=61000, staging='/data/local/tmp/vpn-control-test', receipt=root/'receipt.json',
                expected_avd='avd', expected_api='35', expected_version='2.2.19', expected_code='17180',
                base_apk=base, base_sha256=hashlib.sha256(b'base').hexdigest(),
            )
            fake = FakeAdb(); fake.proxy = 'null'
            with patch.object(preflight, 'Adb', return_value=fake):
                with self.assertRaisesRegex(RuntimeError, 'baseline'):
                    preflight.run_fixture_lifecycle(args, lambda *_: {}, ca_store_target='/apex/com.android.conscrypt/cacerts', expected_proxy=':0')
            self.assertNotIn(('root',), fake.calls)
            self.assertEqual({}, fake.reverse_map)

    def test_apex_target_and_colon_zero_baseline_are_used_and_restored(self):
        class StableZygoteAdb(FakeAdb):
            def shell(self, *args):
                if args[:2] == ('pidof', 'zygote64'):
                    self.calls.append(('shell', *args)); return '177'
                return super().shell(*args)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); base = root / 'base.apk'; cert = root / 'ca.pem'; leaf = root / 'leaf.pem'; receipt = root / 'receipt.json'
            base.write_bytes(b'base'); cert.write_text('ca'); leaf.write_text('leaf')
            args = SimpleNamespace(
                adb='adb', serial='serial', cli=root/'cli.py', certificate=cert, leaf_certificate=leaf,
                fixture_parent=root, server_log=root/'server.log', probe_output=root/'probe.txt',
                device_port=45390, host_port=61000, staging='/data/local/tmp/vpn-control-test', receipt=receipt,
                expected_avd='avd', expected_api='35', expected_version='2.2.19', expected_code='17180',
                base_apk=base, base_sha256=hashlib.sha256(b'base').hexdigest(),
            )
            fake = StableZygoteAdb(); fake.proxy = ':0'
            with patch.object(preflight, 'Adb', return_value=fake), \
                 patch.object(preflight, 'verify_public_baseline', return_value={}), \
                 patch.object(preflight, 'require_device_time_within_certificates'), \
                 patch.object(preflight, 'secure_private_fixture_files'), \
                 patch.object(preflight, 'device_mode', return_value=0o755), \
                 patch.object(preflight, 'device_label', return_value='u:object_r:system_security_cacerts_file:s0'), \
                 patch.object(preflight, 'require_android_certificate_store_layout'), \
                 patch.object(preflight, 'android_ca_store_filename', return_value='hash.0'), \
                 patch.object(preflight, 'relabel_staged_ca_store', return_value=['/data/local/tmp/vpn-control-test/hash.0']):
                with self.assertRaisesRegex(RuntimeError, 'ACTION_FAILED'):
                    preflight.run_fixture_lifecycle(
                        args, lambda *_: (_ for _ in ()).throw(RuntimeError('ACTION_FAILED')),
                        target_install=True, ca_store_target='/apex/com.android.conscrypt/cacerts', expected_proxy=':0',
                    )
            saved = json.loads(receipt.read_text())
            self.assertEqual('/apex/com.android.conscrypt/cacerts', saved['target'])
            self.assertEqual(':0', saved['expectedProxy'])
            self.assertEqual(':0', fake.proxy)
            self.assertEqual([], saved['cleanupFailures'])
            self.assertIn(('shell', 'cp', '-a', '/apex/com.android.conscrypt/cacerts/.', '/data/local/tmp/vpn-control-test/'), fake.calls)
            self.assertIn(('shell', 'nsenter', '-t', '177', '-m', '--', 'mount', '--bind',
                           '/data/local/tmp/vpn-control-test', '/apex/com.android.conscrypt/cacerts'), fake.calls)
            self.assertIn(('shell', 'nsenter', '-t', '177', '-m', '--', 'umount', '/apex/com.android.conscrypt/cacerts'), fake.calls)

    def test_injected_action_failure_still_reaches_terminal_fixture_cleanup(self):
        class StableZygoteAdb(FakeAdb):
            def shell(self, *args):
                if args[:2] == ('pidof', 'zygote64'):
                    self.calls.append(('shell', *args)); return '177'
                return super().shell(*args)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); base = root / 'base.apk'; cert = root / 'ca.pem'; leaf = root / 'leaf.pem'; receipt = root / 'receipt.json'
            base.write_bytes(b'base'); cert.write_text('ca'); leaf.write_text('leaf')
            args = SimpleNamespace(
                adb='adb', serial='serial', cli=root/'cli.py', certificate=cert, leaf_certificate=leaf,
                fixture_parent=root, server_log=root/'server.log', probe_output=root/'probe.txt',
                device_port=45390, host_port=61000, staging='/data/local/tmp/vpn-control-test', receipt=receipt,
                expected_avd='avd', expected_api='29', expected_version='2.2.19', expected_code='17180',
                base_apk=base, base_sha256=hashlib.sha256(b'base').hexdigest(),
            )
            fake = StableZygoteAdb(); calls = []
            def failed_action(_args, _adb, _receipt):
                calls.append('action')
                raise RuntimeError('ACTION_FAILED')
            with patch.object(preflight, 'Adb', return_value=fake), \
                 patch.object(preflight, 'verify_public_baseline', return_value={}), \
                 patch.object(preflight, 'require_device_time_within_certificates'), \
                 patch.object(preflight, 'secure_private_fixture_files'), \
                 patch.object(preflight, 'device_mode', return_value=0o755), \
                 patch.object(preflight, 'device_label', return_value='u:object_r:system_security_cacerts_file:s0'), \
                 patch.object(preflight, 'require_android_certificate_store_layout'), \
                 patch.object(preflight, 'android_ca_store_filename', return_value='hash.0'), \
                 patch.object(preflight, 'relabel_staged_ca_store', return_value=['/data/local/tmp/vpn-control-test/hash.0']):
                with self.assertRaisesRegex(RuntimeError, 'ACTION_FAILED'):
                    preflight.run_fixture_lifecycle(args, failed_action, target_install=True)
            saved = json.loads(receipt.read_text())
            self.assertEqual(['action'], calls)
            self.assertTrue(saved['targetInstall'])
            self.assertEqual('/system/etc/security/cacerts', saved['target'])
            self.assertEqual('null', saved['expectedProxy'])
            self.assertEqual('RuntimeError', saved['failure']['type'])
            self.assertEqual([], saved['cleanupFailures'])
            self.assertIn(('shell', 'cp', '-a', '/system/etc/security/cacerts/.', '/data/local/tmp/vpn-control-test/'), fake.calls)
            self.assertIn(('shell', 'nsenter', '-t', '177', '-m', '--', 'mount', '--bind',
                           '/data/local/tmp/vpn-control-test', '/system/etc/security/cacerts'), fake.calls)
            self.assertFalse(fake.rooted)
            self.assertEqual({}, fake.reverse_map)
            self.assertEqual('null', fake.proxy)

    def test_main_recovers_route_after_setup_rollback_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); base = root / 'base.apk'; cert = root / 'ca.pem'; leaf = root / 'leaf.pem'; receipt = root / 'receipt.json'
            base.write_bytes(b'base'); cert.write_text('ca'); leaf.write_text('leaf')
            fake = FakeAdb(proxy_failure=True, remove_failures=1)
            argv = ['tool', '--adb', 'adb', '--serial', 'serial', '--cli', str(root / 'cli.py'),
                    '--certificate', str(cert), '--leaf-certificate', str(leaf), '--fixture-parent', str(root),
                    '--server-log', str(root / 'server.log'), '--probe-output', str(root / 'probe.txt'), '--device-port', '45390', '--host-port', '61000',
                    '--staging', '/data/local/tmp/vpn-control-test', '--receipt', str(receipt),
                    '--expected-avd', 'avd', '--expected-api', '29', '--expected-version', '2.2.19', '--expected-code', '17180',
                    '--base-apk', str(base), '--base-sha256', hashlib.sha256(b'base').hexdigest()]
            with patch.object(sys, 'argv', argv), patch.object(preflight, 'Adb', return_value=fake), \
                 patch.object(preflight, 'verify_public_baseline', return_value={}), \
                 patch.object(preflight, 'require_device_time_within_certificates'), \
                 patch.object(preflight, 'secure_private_fixture_files'), \
                 patch.object(preflight, 'device_mode', return_value=0o755), \
                 patch.object(preflight, 'device_label', return_value='label'), \
                 patch.object(preflight, 'require_android_certificate_store_layout'), \
                 patch.object(preflight, 'android_ca_store_filename', return_value='hash.0'), \
                 patch.object(preflight, 'relabel_staged_ca_store', return_value=['/data/local/tmp/vpn-control-test/hash.0']):
                with self.assertRaises(OSError):
                    preflight.main()
            saved = json.loads(receipt.read_text())
            self.assertEqual('OSError', saved['failure']['type'])
            self.assertEqual({}, fake.reverse_map)
            self.assertFalse(fake.rooted)

    def test_main_rejects_staged_certificate_label_before_bind(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); base = root / 'base.apk'; cert = root / 'ca.pem'; leaf = root / 'leaf.pem'; receipt = root / 'receipt.json'
            base.write_bytes(b'base'); cert.write_text('ca'); leaf.write_text('leaf')
            fake = FakeAdb()
            argv = ['tool', '--adb', 'adb', '--serial', 'serial', '--cli', str(root / 'cli.py'),
                    '--certificate', str(cert), '--leaf-certificate', str(leaf), '--fixture-parent', str(root),
                    '--server-log', str(root / 'server.log'), '--probe-output', str(root / 'probe.txt'), '--device-port', '45390', '--host-port', '61000',
                    '--staging', '/data/local/tmp/vpn-control-test', '--receipt', str(receipt),
                    '--expected-avd', 'avd', '--expected-api', '29', '--expected-version', '2.2.19', '--expected-code', '17180',
                    '--base-apk', str(base), '--base-sha256', hashlib.sha256(b'base').hexdigest()]
            with patch.object(sys, 'argv', argv), patch.object(preflight, 'Adb', return_value=fake), \
                 patch.object(preflight, 'verify_public_baseline', return_value={}), \
                 patch.object(preflight, 'require_device_time_within_certificates'), \
                 patch.object(preflight, 'secure_private_fixture_files'), \
                 patch.object(preflight, 'device_mode', side_effect=[0o755, 0o755, 0o644]), \
                 patch.object(preflight, 'device_label', side_effect=['expected', 'expected', 'wrong']), \
                 patch.object(preflight, 'require_android_certificate_store_layout'), \
                 patch.object(preflight, 'android_ca_store_filename', return_value='hash.0'), \
                 patch.object(preflight, 'relabel_staged_ca_store', return_value=['/data/local/tmp/vpn-control-test/hash.0']):
                with self.assertRaisesRegex(RuntimeError, 'certificate'):
                    preflight.main()
            saved = json.loads(receipt.read_text())
            self.assertEqual('RuntimeError', saved['failure']['type'])
            self.assertNotIn(('shell', 'nsenter', '-t', '177', '-m', '--', 'mount', '--bind',
                              '/data/local/tmp/vpn-control-test', '/system/etc/security/cacerts'), fake.calls)
            self.assertFalse(fake.rooted)

    def test_probe_failure_preserves_bounded_command_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / 'server.log'; log.write_text('')
            result = type('Result', (), {'returncode': 9, 'stdout': 'x' * 2048, 'stderr': 'failure'})()
            with patch.object(preflight.subprocess, 'run', return_value=result):
                with self.assertRaises(preflight.ProbeFailure) as raised:
                    preflight.public_no_update_probe(Path('cli.py'), 'serial', log, Path(temp) / 'probe.txt')
            evidence = raised.exception.evidence['command']
            self.assertEqual(9, evidence['exit'])
            self.assertEqual(2048, evidence['stdoutBytes'])
            self.assertEqual('failure', evidence['stderr'])

    def test_copied_shell_label_fails_until_exact_staging_relabel(self):
        label = 'u:object_r:system_security_cacerts_file:s0'
        staging = '/data/local/tmp/vpn-control-safe'
        certificate = staging + '/abcd1234.0'
        unrelated = '/data/local/tmp/unrelated'
        class LabelAdb:
            def __init__(self):
                self.calls = []
                self.labels = {staging: 'u:object_r:shell_data_file:s0', certificate: 'u:object_r:shell_data_file:s0', unrelated: 'u:object_r:shell_data_file:s0'}
            def shell(self, *args):
                self.calls.append(args)
                if args[:2] == ('find', staging):
                    if '-type' not in args: return certificate
                    if args[args.index('-type') + 1] in ('l', 'd'): return ''
                    return certificate
                if args[0] == 'chcon':
                    self.labels[args[2]] = args[1]
                    return ''
                if args[:2] == ('ls', '-Zd'): return self.labels[args[-1]] + ' ' + args[-1]
                raise AssertionError(args)
        adb = LabelAdb()
        with self.assertRaisesRegex(RuntimeError, 'SELinux'):
            preflight.require_android_certificate_store_layout(0o700, 0o755, 0o644, preflight.device_label(adb, staging), label)
        preflight.relabel_staged_ca_store(adb, staging, label)
        preflight.require_android_certificate_store_layout(0o700, 0o755, 0o644, preflight.device_label(adb, staging), label)
        self.assertEqual(label, adb.labels[staging])
        self.assertEqual(label, adb.labels[certificate])
        self.assertEqual('u:object_r:shell_data_file:s0', adb.labels[unrelated])

    def test_relabel_changes_only_validated_staging_entries(self):
        class ListingAdb:
            def __init__(self): self.calls = []
            def shell(self, *args):
                self.calls.append(args)
                if args[:2] == ('find', '/data/local/tmp/vpn-control-safe'):
                    if '-type' not in args:
                        return '/data/local/tmp/vpn-control-safe/abcd1234.0\n/data/local/tmp/vpn-control-safe/other.0'
                    if args[args.index('-type') + 1] in ('l', 'd'): return ''
                    if args[args.index('-type') + 1] == 'f':
                        return '/data/local/tmp/vpn-control-safe/abcd1234.0\n/data/local/tmp/vpn-control-safe/other.0'
                if args[0] == 'chcon': return ''
                if args[:2] == ('ls', '-Zd'): return 'u:object_r:system_security_cacerts_file:s0 ' + args[-1]
                raise AssertionError(args)
        adb = ListingAdb()
        label = 'u:object_r:system_security_cacerts_file:s0'
        files = preflight.relabel_staged_ca_store(adb, '/data/local/tmp/vpn-control-safe', label)
        self.assertEqual(['/data/local/tmp/vpn-control-safe/abcd1234.0', '/data/local/tmp/vpn-control-safe/other.0'], files)
        chcon = [call for call in adb.calls if call[0] == 'chcon']
        self.assertEqual([
            ('chcon', label, '/data/local/tmp/vpn-control-safe'),
            ('chcon', label, '/data/local/tmp/vpn-control-safe/abcd1234.0'),
            ('chcon', label, '/data/local/tmp/vpn-control-safe/other.0'),
        ], chcon)
        self.assertFalse(any('/system/etc/security/cacerts' in call for call in chcon))

    def test_relabel_rejects_symlink_before_any_chcon(self):
        class SymlinkAdb:
            def __init__(self): self.calls = []
            def shell(self, *args):
                self.calls.append(args)
                if args[:2] == ('find', '/data/local/tmp/vpn-control-safe') and '-type' in args:
                    return '/data/local/tmp/vpn-control-safe/evil' if args[args.index('-type') + 1] == 'l' else ''
                raise AssertionError(args)
        adb = SymlinkAdb()
        with self.assertRaisesRegex(RuntimeError, 'forbidden'):
            preflight.relabel_staged_ca_store(adb, '/data/local/tmp/vpn-control-safe', 'u:object_r:system_security_cacerts_file:s0')
        self.assertFalse(any(call[0] == 'chcon' for call in adb.calls))

    def test_relabel_rejects_fifo_omitted_by_regular_file_listing(self):
        class SpecialEntryAdb:
            def __init__(self): self.calls = []
            def shell(self, *args):
                self.calls.append(args)
                if args[:2] == ('find', '/data/local/tmp/vpn-control-safe'):
                    if '-type' not in args:
                        return '/data/local/tmp/vpn-control-safe/abcd1234.0\n/data/local/tmp/vpn-control-safe/fifo'
                    kind = args[args.index('-type') + 1]
                    return '/data/local/tmp/vpn-control-safe/abcd1234.0' if kind == 'f' else ''
                raise AssertionError(args)
        adb = SpecialEntryAdb()
        with self.assertRaisesRegex(RuntimeError, 'nonregular'):
            preflight.relabel_staged_ca_store(adb, '/data/local/tmp/vpn-control-safe', 'u:object_r:system_security_cacerts_file:s0')
        self.assertFalse(any(call[0] == 'chcon' for call in adb.calls))

    def test_relabel_rejects_invalid_label_before_listing(self):
        class NoCallAdb:
            def shell(self, *args): raise AssertionError(args)
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            preflight.relabel_staged_ca_store(NoCallAdb(), '/data/local/tmp/vpn-control-safe', 'not;safe')

if __name__ == '__main__': unittest.main()

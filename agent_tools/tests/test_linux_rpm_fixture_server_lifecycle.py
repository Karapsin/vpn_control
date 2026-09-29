"""No-replay and bounded guest-entry tests for the Fedora fixture endpoint."""

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from agent_tools import linux_rpm_fixture_server_lifecycle as route
from agent_tools import linux_rpm_fixture_server_guest as guest


CORRELATION = "12345678-1234-1234-1234-123456789abc"
SOURCE = "a" * 40


def request():
    return {"sourceSha": SOURCE, "scenarioId": "linux-rpm-public-install-recovery",
            "host": "fedora2328", "environment": "fedora2328", "bundleHash": "b" * 64,
            "artifactIds": {"bundleManifest": "sha256-" + "b" * 64,
                            "scenarioInput": "sha256-" + "c" * 64,
                            "sourceFixture": "sha256-" + "d" * 64,
                            "targetPackage": "sha256-" + "e" * 64},
            "credentialHandle": "rpm-auth-" + "f" * 32,
            "correlationId": CORRELATION}


class LinuxRpmFixtureServerLifecycleTest(unittest.TestCase):
    def test_missing_ready_after_submitted_worker_has_bounded_phase(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job = root / "linux-rpm-fixture-server-jobs" / CORRELATION
            (job / "stage" / "fixture").mkdir(parents=True)
            (job / "worker-process.json").write_text('{"pid":123}\n')
            (job / "worker-process.json").chmod(0o600)
            self.assertEqual("worker-submitted-no-ready",
                             route._guest_phase(job, CORRELATION, os.getuid()))
            (job / "fixture-server-ready.json").write_text('{}\n')
            (job / "fixture-server-ready.json").chmod(0o600)
            self.assertEqual("server-ready-no-probe",
                             route._guest_phase(job, CORRELATION, os.getuid()))
            probe = job / "stage" / "fixture" / "probe-events"
            probe.mkdir()
            (probe / (CORRELATION + ".json")).write_text('{}\n')
            (probe / (CORRELATION + ".json")).chmod(0o600)
            self.assertEqual("probe-present-no-receipt",
                             route._guest_phase(job, CORRELATION, os.getuid()))

    def test_server_ready_without_probe_reports_only_typed_failure_event(self):
        with tempfile.TemporaryDirectory() as temporary:
            job = Path(temporary) / "linux-rpm-fixture-server-jobs" / CORRELATION
            job.mkdir(parents=True)
            log = job / "fixture-server.log"
            log.write_text('{"request":"closed-or-rejected","stage":"tls-handshake","exceptionType":"SSLError"}\n')
            log.chmod(0o600)
            self.assertEqual({"stage": "tls-handshake", "exceptionType": "SSLError"},
                             route._guest_log_signal(job, os.getuid()))
            log.write_text('{"request":"closed-or-rejected","stage":"tls-handshake","exceptionType":"SensitiveError","secret":"url"}\n')
            self.assertIsNone(route._guest_log_signal(job, os.getuid()))

    def test_server_log_activity_is_bounded_to_fixed_outcomes(self):
        with tempfile.TemporaryDirectory() as temporary:
            job = Path(temporary)
            log = job / 'fixture-server.log'
            self.assertEqual('empty', route._guest_log_activity(job, os.getuid()))
            log.write_text('{"served":"manifest","bytes":123}\n')
            log.chmod(0o600)
            self.assertEqual('manifest-served', route._guest_log_activity(job, os.getuid()))
            log.chmod(0o644)
            self.assertEqual('unsafe-manifest-served', route._guest_log_activity(job, os.getuid()))
            log.chmod(0o600)
            log.write_text('{"served":"private","bytes":123,"secret":"/path"}\n')
            self.assertEqual('unrecognized', route._guest_log_activity(job, os.getuid()))
            log.write_text('{"request":"closed-or-rejected","stage":"connect-admission",'
                           '"exceptionType":"ValueError"}\n')
            log.chmod(0o644)
            self.assertEqual('unsafe-connect-admission-ValueError',
                             route._guest_log_activity(job, os.getuid()))

    def test_server_log_is_private_even_with_default_umask(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / 'fixture-server.log'
            old_umask = os.umask(0o022)
            try:
                with guest._open_private_server_log(log) as output:
                    output.write(b'')
                self.assertEqual(0o600, log.stat().st_mode & 0o777)
            finally:
                os.umask(old_umask)

    def test_java_probe_failure_is_durably_typed_without_private_exception_text(self):
        with tempfile.TemporaryDirectory() as temporary:
            job = Path(temporary)
            def fail(_argv, **_kwargs):
                raise ValueError('private URL and trust path')
            with mock.patch.object(guest.subprocess, 'run', side_effect=fail):
                with self.assertRaisesRegex(ValueError, 'private URL'):
                    guest._java_probe(job, ['java', 'FixtureProbe.java'])
            receipt = json.loads((job / 'worker-failure.json').read_text())
            self.assertEqual({'schemaVersion': 1, 'phase': 'java-probe',
                              'exceptionType': 'ValueError'}, receipt)
            self.assertNotIn('private', json.dumps(receipt))

    def test_java_probe_tls_failure_records_bounded_causal_kind(self):
        with tempfile.TemporaryDirectory() as temporary:
            job = Path(temporary)
            failure = subprocess.CompletedProcess(['java'], 1, '',
                'javax.net.ssl.SSLHandshakeException: private path /secret')
            with mock.patch.object(guest.subprocess, 'run', return_value=failure):
                with self.assertRaises(ValueError):
                    guest._java_probe(job, ['java', 'FixtureProbe.java'])
            receipt = json.loads((job / 'worker-failure.json').read_text())
            self.assertEqual('tls-handshake', receipt['failureKind'])
            self.assertNotIn('/secret', json.dumps(receipt))

    @unittest.skipUnless(shutil.which('java') and shutil.which('openssl'),
                         'Java and OpenSSL are required for the local TLS probe regression')
    def test_actual_java_probe_keeps_certificate_available_until_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            cert, key, trust = (stage / name for name in ('cert.pem', 'key.pem', 'trust.p12'))
            made = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '2',
                '-subj', '/CN=github.com', '-addext', 'subjectAltName=DNS:github.com'],
                capture_output=True, text=True, timeout=15)
            self.assertEqual(0, made.returncode)
            make_java = stage / 'MakeTrust.java'
            make_java.write_text(guest._MAKE_TRUST_JAVA)
            made = subprocess.run(['java', str(make_java), str(cert), str(trust)],
                                  capture_output=True, text=True, timeout=15)
            self.assertEqual(0, made.returncode)
            probe_java = stage / 'FixtureProbe.java'
            probe_java.write_text(guest._PROBE_JAVA)
            body = b'{"schemaVersion":1,"assets":[]}'
            server = socket.socket()
            server.bind(('127.0.0.1', 0))
            server.listen(1)
            server.settimeout(10)
            port = server.getsockname()[1]
            def serve():
                try:
                    connection, _ = server.accept()
                    with connection:
                        data = b''
                        while not data.endswith(b'\r\n\r\n'):
                            data += connection.recv(1)
                        connection.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                        context.load_cert_chain(str(cert), str(key))
                        with context.wrap_socket(connection, server_side=True) as tunnel:
                            data = b''
                            while not data.endswith(b'\r\n\r\n'):
                                data += tunnel.recv(1)
                            tunnel.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: ' +
                                str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body)
                except (OSError, ssl.SSLError):
                    pass
                finally:
                    server.close()
            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            digest = hashlib.sha256(body).hexdigest()
            certificate_digest = hashlib.sha256(
                ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
            argv = ['java', '-Dhttps.proxyHost=127.0.0.1', f'-Dhttps.proxyPort={port}',
                    f'-Djavax.net.ssl.trustStore={trust}',
                    '-Djavax.net.ssl.trustStoreType=PKCS12',
                    *guest._probe_trust_password_property(), str(probe_java),
                    CORRELATION, digest, certificate_digest]
            result = subprocess.run(argv, capture_output=True, text=True, timeout=15)
            thread.join(timeout=10)
            self.assertEqual(0, result.returncode, result.stderr[:300])
            self.assertEqual(digest, result.stdout.strip())

    def test_unknown_server_reports_exact_live_process_generation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job = root / 'job'
            job.mkdir()
            boot = '12345678-1234-1234-1234-123456789abc'
            ready = job / 'fixture-server-ready.json'
            ready.write_text(json.dumps({'serverPid': 4567,
                'serverProcessStartIdentity': f'linux:{boot}:98765'}) + '\n')
            ready.chmod(0o600)
            proc = root / 'proc'
            (proc / 'sys/kernel/random').mkdir(parents=True)
            (proc / 'sys/kernel/random/boot_id').write_text(boot + '\n')
            process = proc / '4567'
            process.mkdir()
            (process / 'stat').write_text('4567 (python3) S ' + ' '.join(['1'] * 18) + ' 98765\n')
            user = os.getuid()
            (process / 'status').write_text(f'Uid:\t{user}\t{user}\t{user}\t{user}\n')
            self.assertEqual('live', route._guest_server_process(job, user, proc_root=proc))
            (process / 'stat').write_text('4567 (python3) S ' + ' '.join(['1'] * 18) + ' 99999\n')
            self.assertEqual('different-generation', route._guest_server_process(job, user, proc_root=proc))

    def test_worker_failure_receipt_reports_only_bounded_phase_and_type(self):
        with tempfile.TemporaryDirectory() as temporary:
            job = Path(temporary)
            receipt = job / 'worker-failure.json'
            receipt.write_text('{"schemaVersion":1,"phase":"java-probe","exceptionType":"ValueError"}\n')
            receipt.chmod(0o600)
            self.assertEqual({'phase': 'java-probe', 'exceptionType': 'ValueError'},
                             route._guest_worker_failure(job, os.getuid()))
            receipt.write_text('{"schemaVersion":1,"phase":"java-probe",'
                               '"exceptionType":"ValueError","failureKind":"tls-handshake"}\n')
            self.assertEqual({'phase': 'java-probe', 'exceptionType': 'ValueError',
                              'failureKind': 'tls-handshake'},
                             route._guest_worker_failure(job, os.getuid()))
            receipt.write_text('{"schemaVersion":1,"phase":"java-probe",'
                               '"exceptionType":"ValueError","failureKind":"secret"}\n')
            self.assertIsNone(route._guest_worker_failure(job, os.getuid()))

    def test_stop_admission_requires_exact_server_role_and_pid_generation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job = root / 'linux-rpm-fixture-server-jobs' / CORRELATION
            stage = job / 'stage'
            (stage / 'scripts').mkdir(parents=True)
            boot = '12345678-1234-1234-1234-123456789abc'
            public = '9' * 64
            for name, value in (
                ('intent.json', {'correlationId': CORRELATION, 'sourceSha': SOURCE,
                                 'publicIntentSha256': public}),
                ('fixture-server-ready.json', {'serverPid': 4567,
                    'serverProcessStartIdentity': f'linux:{boot}:98765'})):
                path = job / name
                path.write_text(json.dumps(value) + '\n')
                path.chmod(0o600)
            proc = root / 'proc'
            (proc / 'sys/kernel/random').mkdir(parents=True)
            (proc / 'sys/kernel/random/boot_id').write_text(boot + '\n')
            process = proc / '4567'
            process.mkdir()
            (process / 'stat').write_text('4567 (python3) S ' + ' '.join(['1'] * 18) + ' 98765\n')
            user = os.getuid()
            (process / 'status').write_text(f'Uid:\t{user}\t{user}\t{user}\t{user}\n')
            script = stage / 'scripts' / 'prepare_desktop_update_fixture.py'
            argv = [*guest._isolated_script_argv(script, 'serve'), '--directory', str(stage / 'fixture'),
                    '--certificate', str(stage / 'fixture-certificate.pem'),
                    '--private-key', str(stage / 'fixture-private-key.pem'),
                    '--ready-file', str(job / 'fixture-server-ready.json'),
                    '--confirm-owned-disposable-guest']
            (process / 'cmdline').write_bytes(b'\0'.join(x.encode() for x in argv) + b'\0')
            self.assertEqual(4567, route._guest_stop_identity(job, SOURCE, public, user, proc_root=proc))
            (process / 'stat').write_text('4567 (python3) S ' + ' '.join(['1'] * 18) + ' 99999\n')
            self.assertIsNone(route._guest_stop_identity(job, SOURCE, public, user, proc_root=proc))
            (process / 'stat').write_text('4567 (python3) S ' + ' '.join(['1'] * 18) + ' 98765\n')
            (process / 'cmdline').write_bytes(b'python3\0-unrelated\0')
            self.assertIsNone(route._guest_stop_identity(job, SOURCE, public, user, proc_root=proc))

    def test_stop_response_loss_does_not_dispatch_second_signal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record = {'correlationId': CORRELATION, 'sourceSha': SOURCE,
                      'publicIntentSha256': '9' * 64, 'serverGuestSha256': '2' * 64,
                      'serverGuardSha256': '3' * 64}
            route._save_journal(root, record)
            config = mock.Mock(hosts={'fedora2328': mock.Mock(user='vpnfixture',
                fixture_transfer_root=Path('/private/fedora'))})
            with mock.patch.object(route.ssh_transport, 'load_config', return_value=config), \
                 mock.patch.object(route, 'status', return_value={'state': 'unknown',
                    'serverProcess': 'live', 'workerProcess': 'absent',
                    'serverStopAdmissible': True}), \
                 mock.patch.object(route, '_remote', return_value=None) as remote:
                first = route.stop(root, {'correlationId': CORRELATION})
                second = route.stop(root, {'correlationId': CORRELATION})
            self.assertEqual('unknown', first['state'])
            self.assertEqual('unknown', second['state'])
            self.assertEqual(1, remote.call_count)

    def test_ready_server_stop_requires_terminal_failed_public_job_and_idle_guest(self):
        record = {'correlationId': CORRELATION, 'sourceSha': SOURCE,
                  'publicIntentSha256': '9' * 64, 'serverGuestSha256': '2' * 64,
                  'serverGuardSha256': '3' * 64,
                  'expectedBaseNevra': 'vpn-control-2.1.19-1.x86_64'}
        observed = {'state': 'ready', 'correlationId': CORRELATION,
                    'serverProcess': 'live', 'workerProcess': 'absent',
                    'serverStopAdmissible': True}
        config = mock.Mock(hosts={'fedora2328': mock.Mock(user='vpnfixture',
            fixture_transfer_root=Path('/private/fedora'))})
        from agent_tools import linux_rpm_base_prepare as base
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            route._save_journal(root, record)
            with mock.patch.object(route.ssh_transport, 'load_config', return_value=config), \
                 mock.patch.object(route, 'status', return_value=observed), \
                 mock.patch.object(route.rpm.RpmPublicInstallSshDriver, 'status', return_value={
                     'state': 'running', 'correlationId': CORRELATION}), \
                 mock.patch.object(base, 'preflight', return_value={
                     'state': 'ready', 'currentNevra': record['expectedBaseNevra']}), \
                 mock.patch.object(route, '_remote') as remote:
                with self.assertRaises(ValueError):
                    route.stop(root, {'correlationId': CORRELATION})
                remote.assert_not_called()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            route._save_journal(root, record)
            with mock.patch.object(route.ssh_transport, 'load_config', return_value=config), \
                 mock.patch.object(route, 'status', return_value=observed), \
                 mock.patch.object(route.rpm.RpmPublicInstallSshDriver, 'status', return_value={
                     'state': 'terminal', 'correlationId': CORRELATION, 'exitCode': 1}), \
                 mock.patch.object(base, 'preflight', return_value={
                     'state': 'ready', 'currentNevra': record['expectedBaseNevra']}), \
                 mock.patch.object(route, '_remote', return_value={
                     'state': 'terminal', 'result': 'stopped', 'correlationId': CORRELATION,
                     'pidfdExitObserved': True, 'replayAllowed': False}):
                self.assertEqual('stopped', route.stop(root, {'correlationId': CORRELATION})['result'])

    def test_recovered_target_ready_server_stops_only_after_exact_cleanup(self):
        from agent_tools import linux_rpm_workspace_recovery as recovery
        from agent_tools import linux_rpm_base_prepare as base
        corr = '944447ff-7ee3-42df-8ca8-f02dac670459'
        record = {'correlationId': corr,
                  'sourceSha': 'a876f46fa4582e6218d341ac7012fd31bc919758',
                  'publicIntentSha256': '9' * 64, 'serverGuestSha256': '2' * 64,
                  'serverGuardSha256': '3' * 64,
                  'expectedBaseNevra': 'vpn-control-2.1.19-1.x86_64',
                  'expectedTargetNevra': 'vpn-control-2.2.0-1.x86_64'}
        observed = {'state': 'ready', 'correlationId': corr, 'serverProcess': 'live',
                    'workerProcess': 'absent', 'serverStopAdmissible': True}
        config = mock.Mock(hosts={'fedora2328': mock.Mock(user='vpnfixture',
            fixture_transfer_root=Path('/private/fedora'))})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            route._save_journal(root, record)
            with mock.patch.object(route.ssh_transport, 'load_config', return_value=config), \
                 mock.patch.object(route, 'status', return_value=observed), \
                 mock.patch.object(route.rpm.RpmPublicInstallSshDriver, 'status', return_value={
                     'state': 'terminal', 'correlationId': corr, 'exitCode': 1}), \
                 mock.patch.object(base, 'preflight', return_value={
                     'state': 'ready', 'currentNevra': record['expectedTargetNevra'],
                     'currentHeaderSha1': '3ef23bc543b6302432f514edc94ba04d75a8dc3d'}), \
                 mock.patch.object(recovery, 'cleanup_status', side_effect=[
                     {'state': 'unknown'},
                     {'state': 'terminal', 'result': 'passed', 'workspaceRemoved': True,
                      'correlationId': '5eac659d-a6d4-4005-b97a-40063b10d8bf'}]) as clean, \
                 mock.patch.object(route, '_remote', return_value={
                     'state': 'terminal', 'result': 'stopped', 'correlationId': corr,
                     'pidfdExitObserved': True, 'replayAllowed': False}) as remote:
                with self.assertRaisesRegex(ValueError, 'completed workspace cleanup'):
                    route.stop(root, {'correlationId': corr})
                remote.assert_not_called()
                self.assertEqual('stopped', route.stop(root, {'correlationId': corr})['result'])
                self.assertEqual(2, clean.call_count)
                remote.assert_called_once()

    def test_host_status_admits_only_bounded_java_failure_kind(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            route._save_journal(root, {'correlationId': CORRELATION, 'sourceSha': SOURCE,
                'publicIntentSha256': '9' * 64, 'serverGuestSha256': '2' * 64,
                'serverGuardSha256': '3' * 64})
            config = mock.Mock(hosts={'fedora2328': mock.Mock(user='vpnfixture',
                fixture_transfer_root=Path('/private/fedora'))})
            failure = {'phase': 'java-probe', 'exceptionType': 'ValueError',
                       'failureKind': 'tls-handshake'}
            remote = {'state': 'unknown', 'correlationId': CORRELATION,
                      'phase': 'server-ready-no-probe', 'workerFailure': failure,
                      'serverActivity': 'manifest-served'}
            with mock.patch.object(route.ssh_transport, 'load_config', return_value=config), \
                 mock.patch.object(route, '_remote', return_value=remote):
                public = route.status(root, {'correlationId': CORRELATION})
                self.assertEqual(failure, public.get('workerFailure'))
                self.assertEqual('manifest-served', public.get('serverActivity'))
                remote['workerFailure'] = {**failure, 'secret': '/private/path'}
                self.assertNotIn('workerFailure', route.status(root, {'correlationId': CORRELATION}))
                remote['serverActivity'] = '/private/path'
                self.assertNotIn('serverActivity', route.status(root, {'correlationId': CORRELATION}))

    def test_request_accepts_only_full_fixed_fedora_public_intent(self):
        parsed, intent = route._request(request())
        self.assertEqual(SOURCE, parsed["sourceSha"])
        self.assertEqual(CORRELATION, intent.correlation_id)
        for changed in ({**request(), "host": "archlinux"},
                        {**request(), "environment": "other"},
                        {**request(), "arbitraryCommand": "true"}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                route._request(changed)

    def test_server_admission_requires_public_authorization_before_journal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parsed, intent = route._request(request())
            with mock.patch.object(route.subprocess, "run", return_value=mock.Mock(
                    returncode=0, stdout=SOURCE + "\n")), \
                 mock.patch.object(route.rpm, "admission", side_effect=ValueError("authorization absent")) as gate:
                with self.assertRaisesRegex(ValueError, "authorization absent"):
                    route._admit(root, parsed, intent)
            gate.assert_called_once_with(root, intent)
            self.assertFalse((root / route._STATE).exists())

    def test_server_intent_carries_exact_installed_jar_binding_to_public_guard(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parsed, intent = route._request(request())
            paths = {name: root / name for name in intent.artifact_ids}
            typed = {'sourceFingerprint': 'f' * 64, 'expectedBaseVersion': '2.1.19',
                     'expectedTargetVersion': '2.2.0',
                     'expectedBaseNevra': 'vpn-control-2.1.19-1.x86_64',
                     'expectedTargetNevra': 'vpn-control-2.2.0-1.x86_64',
                     'expectedDesktopJarSha256': '1' * 64,
                     'targetPackageSha256': '2' * 64}
            config = mock.Mock(hosts={'fedora2328': mock.Mock(user='vpnfixture',
                fixture_transfer_root=PurePosixPath('/private/fedora'))})
            admission = {'paths': paths, 'typed': typed, 'config': config}
            fixture_receipt = {'derivedFrom': {'scope': 'rpm-only',
                'sourceShaFromSnapshot': SOURCE, 'sourceFingerprint': typed['sourceFingerprint']}}
            with mock.patch.object(route.subprocess, 'run', return_value=mock.Mock(
                     returncode=0, stdout=SOURCE + '\n')), \
                 mock.patch.object(route.rpm, 'admission', return_value=admission), \
                 mock.patch.object(route, '_registered', side_effect=lambda _r, artifact, _s:
                     paths[next(k for k, v in intent.artifact_ids.items() if v == artifact)]), \
                 mock.patch.object(route.rpm, '_fixture', return_value=fixture_receipt), \
                 mock.patch.object(route.rpm, '_sha', return_value=typed['targetPackageSha256']):
                result = route._admit(root, parsed, intent)
            self.assertEqual(typed['expectedDesktopJarSha256'],
                             result['public']['expectedDesktopJarSha256'])

    def test_ready_for_public_requires_same_intent_and_live_server_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, intent = route._request(request())
            record = {"correlationId": CORRELATION, "sourceSha": SOURCE,
                      "sourceFingerprint": "f" * 64,
                      "publicIntentSha256": hashlib.sha256(route._canonical(intent.public_mapping())).hexdigest(),
                      "authorizationHandleSha256": hashlib.sha256(intent.credential_handle.encode()).hexdigest()}
            route._save_journal(root, record)
            ready = {"state": "ready", "correlationId": CORRELATION,
                     "sourceSha": SOURCE, "publicIntentSha256": record["publicIntentSha256"]}
            with mock.patch.object(route.subprocess, "run", return_value=mock.Mock(
                    returncode=0, stdout=SOURCE + "\n")), \
                 mock.patch.object(route, "status", return_value=ready):
                self.assertTrue(route.ready_for_public(root, intent, "f" * 64))
                self.assertFalse(route.ready_for_public(root, intent, "e" * 64))
                changed = request()
                changed["credentialHandle"] = "rpm-auth-" + "a" * 32
                _, other = route._request(changed)
                self.assertFalse(route.ready_for_public(root, other, "f" * 64))

    def test_start_journals_before_guest_effect_and_never_replays_unknown(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            public = {"correlationId": CORRELATION, "sourceSha": SOURCE,
                      "publicIntentSha256": "1" * 64}
            captured = {"public": public, "remoteRoot": "/private/fedora",
                        "config": object()}
            def payload(_root, _captured, path):
                path.write_bytes(b"fixed payload")
                return {"agent_tools/linux_rpm_fixture_server_guest.py":
                        {"size": 13, "sha256": hashlib.sha256(b"fixed payload").hexdigest()},
                        "agent_tools/linux_rpm_fixture_server.py":
                        {"size": 13, "sha256": "3" * 64}}
            def interrupted(_captured, _program, _args, _payload):
                journal = route._journal(root, CORRELATION)
                self.assertEqual(public.items() <= journal.items(), True)
                self.assertEqual(hashlib.sha256(b"fixed payload").hexdigest(), journal["payloadSha256"])
                return None
            with mock.patch.object(route, "_admit", return_value=captured), \
                    mock.patch.object(route, "_payload", side_effect=payload), \
                    mock.patch.object(route, "_remote", side_effect=interrupted) as remote:
                first = route.start(root, request())
                self.assertEqual("unknown", first["state"])
                self.assertFalse(first["replayAllowed"])
                with self.assertRaisesRegex(ValueError, "already has an intent"):
                    route.start(root, request())
                self.assertEqual(1, remote.call_count)

    def test_status_does_not_promote_unbound_or_dead_guest_server(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record = {"correlationId": CORRELATION, "sourceSha": SOURCE,
                      "publicIntentSha256": "1" * 64, "serverGuestSha256": "2" * 64,
                      "serverGuardSha256": "3" * 64}
            route._save_journal(root, record)
            config = mock.Mock(hosts={"fedora2328": mock.Mock(user="vpnfixture",
                fixture_transfer_root=Path("/private/fedora"))})
            with mock.patch.object(route.ssh_transport, "load_config", return_value=config), \
                    mock.patch.object(route, "_remote", return_value={"state": "ready",
                        "correlationId": CORRELATION, "sourceSha": "f" * 40,
                        "publicIntentSha256": "1" * 64}):
                self.assertEqual("unknown", route.status(root, {"correlationId": CORRELATION})["state"])
            with mock.patch.object(route.ssh_transport, "load_config", return_value=config), \
                    mock.patch.object(route, "_remote", return_value=None):
                self.assertEqual("unknown", route.collect(root, {"correlationId": CORRELATION})["state"])

    def test_embedded_guest_transport_programs_compile(self):
        compile(route._SUBMIT, "<rpm-fixture-server-submit>", "exec")
        compile(route._STATUS, "<rpm-fixture-server-status>", "exec")
        compile(route._STOP, "<rpm-fixture-server-stop>", "exec")
        compile(Path(guest.__file__).read_text(), "<rpm-fixture-server-guest>", "exec")

    def test_staged_fixture_server_resolves_sibling_import_in_isolated_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary) / "scripts"
            stage.mkdir()
            source = Path(__file__).resolve().parents[2] / "scripts"
            for name in ("prepare_desktop_update_fixture.py", "fixture_environment.py",
                         "macos_packaging_jdk_preflight.py"):
                candidate = source / name
                if candidate.exists():
                    shutil.copyfile(candidate, stage / name)
            script = stage / "prepare_desktop_update_fixture.py"
            old = subprocess.run(["python3", "-I", "-B", str(script), "--help"],
                                 capture_output=True, text=True, timeout=10)
            self.assertNotEqual(0, old.returncode)
            self.assertIn("fixture_environment", old.stderr)
            fixed = subprocess.run(guest._isolated_script_argv(script, "--help"),
                                   capture_output=True, text=True, timeout=10)
            self.assertEqual(0, fixed.returncode, fixed.stderr[-300:])

    def test_guest_executes_only_host_bound_guard_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            (stage / "agent_tools").mkdir()
            path = stage / "agent_tools" / "linux_rpm_fixture_server.py"
            original = b"def admit_endpoint(*_): return {'safe': True}\n"
            path.write_bytes(original)
            path.chmod(0o600)
            expected = hashlib.sha256(original).hexdigest()
            self.assertTrue(guest._verified_guard(stage, expected)["admit_endpoint"]()["safe"])
            path.write_bytes(b"def admit_endpoint(*_): return {'safe': False}\n")
            with self.assertRaisesRegex(ValueError, "guard changed"):
                guest._verified_guard(stage, expected)

    def test_guest_guard_reads_payload_member_at_its_actual_staged_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            staged = stage / "agent_tools"
            staged.mkdir()
            original = b"def admit_endpoint(*_): return {'safe': True}\n"
            path = staged / "linux_rpm_fixture_server.py"
            path.write_bytes(original)
            path.chmod(0o600)
            expected = hashlib.sha256(original).hexdigest()
            self.assertTrue(guest._verified_guard(stage, expected)["admit_endpoint"]()["safe"])

    @unittest.skipUnless(shutil.which("openssl") and shutil.which("java"),
                         "requires local OpenSSL and Java source-file mode")
    def test_jdk17_passwordless_trust_store_contains_one_certificate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cert = root / "fixture.pem"
            key = root / "fixture.key"
            trust = root / "fixture.p12"
            generated = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=github.com",
                "-addext", "subjectAltName=DNS:github.com"], capture_output=True, timeout=30)
            self.assertEqual(0, generated.returncode)
            source = root / "MakeTrust.java"
            source.write_text(guest._MAKE_TRUST_JAVA)
            result = subprocess.run(["java", str(source), str(cert), str(trust)],
                                    capture_output=True, timeout=60)
            self.assertEqual(0, result.returncode, result.stderr.decode(errors="replace")[-300:])
            self.assertGreater(trust.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()

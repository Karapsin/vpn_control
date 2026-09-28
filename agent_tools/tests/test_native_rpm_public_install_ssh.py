from __future__ import annotations

import hashlib
import errno
import io
import json
import os
from pathlib import Path
import subprocess
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import uuid
from dataclasses import replace
from types import SimpleNamespace
from pathlib import PurePosixPath

from agent_tools import native_rpm_public_install_adapter as adapter
from agent_tools import native_rpm_public_install_ssh as subject


class RpmTransportTest(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix', 'proc diagnostic requires POSIX process ownership')
    def test_proc_diagnostic_keeps_unreadable_same_uid_process_unknown(self):
        with tempfile.TemporaryDirectory() as temporary:
            proc = Path(temporary)
            process = proc / '1234'
            process.mkdir()
            (process / 'stat').write_text('1234 (fixture) S 111 222 333 ' + ' '.join(['0'] * 15 + ['4567']) + '\n')
            (process / 'cwd').symlink_to('/tmp')
            (process / 'fd').mkdir()
            (process / 'fd' / '5').symlink_to('/tmp/some-file')
            output = subject._observe_proc_tree(proc, os.geteuid())
            self.assertEqual('clear', output['procState'])
            self.assertEqual(1, output['sameUidCount'])
            (process / 'cwd').unlink()
            output = subject._observe_proc_tree(proc, os.geteuid())
            self.assertEqual('unknown', output['procState'])
            self.assertEqual([{'pid': 1234, 'startTicks': 4567, 'state': 'S',
                               'ppid': 111, 'processGroup': 222, 'session': 333, 'comm': 'fixture',
                               'errorErrno': 2,
                               'phase': 'cwd', 'reason': 'unreadable'}], output['uninspectable'])
            guest_program = subject._PROC_OBSERVE.replace("Path('/proc')", f"Path({str(proc)!r})")
            guest = subprocess.run([sys.executable, '-c', guest_program], capture_output=True, text=True,
                                   check=False)
            self.assertEqual(0, guest.returncode, guest.stderr)
            self.assertEqual(output, json.loads(guest.stdout))

    @unittest.skipUnless(os.name == 'posix', 'proc diagnostic requires POSIX process ownership')
    def test_proc_diagnostic_reports_eacces_without_exposing_cwd(self):
        with tempfile.TemporaryDirectory() as temporary:
            proc = Path(temporary)
            process = proc / '1234'
            process.mkdir()
            (process / 'stat').write_text('1234 (fixture) S 1 1234 1234 ' + ' '.join(['0'] * 15 + ['4567']) + '\n')
            (process / 'cwd').symlink_to('/private/fixture-secret')
            (process / 'fd').mkdir()
            with patch.object(subject.os, 'readlink', side_effect=PermissionError(errno.EACCES, 'denied')):
                output = subject._observe_proc_tree(proc, os.geteuid())
            self.assertEqual('unknown', output['procState'])
            self.assertEqual(13, output['uninspectable'][0]['errorErrno'])
            self.assertNotIn('/private/fixture-secret', json.dumps(output))

    def test_proc_diagnostic_rejects_unbounded_or_wrong_host_inputs_before_ssh(self):
        for request in ({'host': 'archlinux', 'environment': 'fedora2328'},
                        {'host': 'fedora2328', 'environment': 'other'},
                        {'host': 'fedora2328', 'environment': 'fedora2328', 'command': 'true'}):
            with self.subTest(request=request), self.assertRaises(subject.RpmPublicInstallSshError):
                subject.observe_proc('.', request)

    def test_proc_diagnostic_rejects_inconsistent_or_private_remote_output(self):
        config = SimpleNamespace(hosts={'fedora2328': SimpleNamespace(user='vpnfixture')})
        request = {'host': 'fedora2328', 'environment': 'fedora2328'}
        bad = [
            {'procState': 'clear', 'sameUidCount': 1, 'uninspectable': [
                {'pid': 123, 'startTicks': 44, 'state': 'S', 'phase': 'cwd', 'reason': 'unreadable'}], 'truncated': False},
            {'procState': 'unknown', 'sameUidCount': 1, 'uninspectable': [
                {'pid': 123, 'startTicks': 44, 'state': 'S', 'phase': 'cwd', 'reason': '/private/workspace'}], 'truncated': False},
        ]
        with patch.object(subject.ssh_transport, 'load_config', return_value=config):
            for value in bad:
                with self.subTest(value=value), patch.object(subject.RpmPublicInstallSshDriver, '_remote', return_value=value):
                    result = subject.observe_proc('.', request)
                    self.assertFalse(result['ok'])
                    self.assertEqual('unknown', result['procState'])
                    self.assertEqual('same-uid-proc-visibility-only', result['evidenceScope'])

    def authorize(self, root, intent):
        directory = root / '.runtime' / 'linux-rpm-public-install-authorizations'
        directory.mkdir(parents=True, mode=0o700)
        record = {'schemaVersion': 2, 'handle': intent.credential_handle, 'host': intent.host,
                  'environment': intent.environment, 'account': 'vpnfixture',
                  'purpose': adapter.SCENARIO_ID, 'passwordStatus': 'P',
                  'preservePasswordBaseline': True, 'correlationId': intent.correlation_id,
                  'bundleHash': intent.bundle_hash, 'artifactIds': dict(intent.artifact_ids),
                  'sourceFingerprint': 'f' * 64}
        path = directory / (intent.credential_handle + '.json')
        path.write_text(json.dumps(record)); path.chmod(0o600)
        return path, record

    def intent(self):
        return adapter.RpmPublicInstallIntent.from_mapping({
            'scenarioId': adapter.SCENARIO_ID, 'host': 'fedora2328', 'environment': 'owned',
            'bundleHash': 'a' * 64, 'artifactIds': {'bundleManifest': 'sha256-' + 'a' * 64,
                'scenarioInput': 'sha256-' + 'b' * 64, 'sourceFixture': 'sha256-' + 'c' * 64,
                'targetPackage': 'sha256-' + 'd' * 64},
            'credentialHandle': 'rpm-auth-' + 'e' * 32, 'correlationId': str(uuid.uuid4())})

    def typed(self, intent):
        return {'sourceFingerprint': 'f' * 64, 'expectedBaseVersion': '2.1.16',
                'expectedTargetVersion': '2.1.17', 'expectedDesktopJarSha256': '1' * 64,
                'targetPackageSha256': hashlib.sha256(b'target').hexdigest(),
                'fixtureHttpsOrigin': 'https://github.com'}

    def fixture(self, path, typed, *, extra=None, target_bytes=b'target'):
        base_bytes = b'base'
        def asset(name, raw, version):
            return {'packageType': 'rpm', 'fileName': name, 'platform': 'linux',
                    'displayVersion': version, 'sizeBytes': len(raw),
                    'sha256': hashlib.sha256(raw).hexdigest(),
                    'downloadUrl': 'https://github.com/owned/' + name}
        base = asset('base.rpm', base_bytes, '2.1.16')
        target = asset('target.rpm', target_bytes, '2.1.17')
        receipt = {'schemaVersion': 1, 'testOnly': True, 'productionTrustChanged': False,
                   'sourceFingerprint': typed['sourceFingerprint'],
                   'builds': [
                       {'label': 'base', 'version': '2.1.16', 'sourceFingerprint': typed['sourceFingerprint'],
                        'codeFingerprint': '2' * 64, 'mainJarSha256': typed['expectedDesktopJarSha256'], 'assets': [base]},
                       {'label': 'target', 'version': '2.1.17', 'sourceFingerprint': typed['sourceFingerprint'],
                        'codeFingerprint': '2' * 64, 'assets': [target]}],
                   'manifest': {'schemaVersion': 1, 'assets': [target],
                                'releaseNotesUrl': 'https://github.com/owned/release'}}
        files = {'fixture-receipt.json': json.dumps(receipt).encode(),
                 'packages/base/base.rpm': base_bytes, 'packages/target/target.rpm': target_bytes}
        if extra:
            files.update(extra)
        with tarfile.open(path, 'w') as archive:
            for name, raw in files.items():
                info = tarfile.TarInfo(name); info.size = len(raw)
                archive.addfile(info, io.BytesIO(raw))
        return receipt

    def test_built_fixture_archive_binds_every_asset_and_rejects_raw_git(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'source.tar'
            typed = self.typed(self.intent())
            receipt = self.fixture(path, typed)
            self.assertEqual(receipt, subject._fixture(path, typed))
            self.fixture(path, typed, extra={'.git/config': b'raw git'})
            with self.assertRaisesRegex(subject.RpmPublicInstallSshError, 'outside the built fixture'):
                subject._fixture(path, typed)
            self.fixture(path, typed, target_bytes=b'changed')
            with self.assertRaisesRegex(subject.RpmPublicInstallSshError, 'target artifact'):
                subject._fixture(path, typed)

    @unittest.skipUnless(os.name == 'posix', 'owner-only mode requires POSIX')
    def test_authorization_is_handle_metadata_bound_to_account_status_and_purpose(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            intent = self.intent()
            path, record = self.authorize(root, intent)
            subject._authorization(root, intent, 'f' * 64)
            record['passwordStatus'] = 'L'; path.write_text(json.dumps(record))
            with self.assertRaisesRegex(subject.RpmPublicInstallSshError, 'binding'):
                subject._authorization(root, intent, 'f' * 64)
            record['passwordStatus'] = 'P'; path.write_text(json.dumps(record)); path.chmod(0o644)
            with self.assertRaisesRegex(subject.RpmPublicInstallSshError, 'owner-only'):
                subject._authorization(root, intent, 'f' * 64)

    @unittest.skipUnless(os.name == 'posix', 'owner-only mode requires POSIX')
    def test_one_handle_rejects_new_correlation_artifact_set_or_source_pair(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); intent = self.intent()
            path, record = self.authorize(root, intent)
            subject._authorization(root, intent, 'f' * 64)
            variants = (replace(intent, correlation_id=str(uuid.uuid4())),
                        replace(intent, artifact_ids={**intent.artifact_ids,
                            'targetPackage': 'sha256-' + '9' * 64}),
                        replace(intent, bundle_hash='9' * 64, artifact_ids={**intent.artifact_ids,
                            'bundleManifest': 'sha256-' + '9' * 64}))
            for changed in variants:
                with self.subTest(changed=changed):
                    with self.assertRaisesRegex(subject.RpmPublicInstallSshError, 'binding'):
                        subject._authorization(root, changed, 'f' * 64)
            with self.assertRaisesRegex(subject.RpmPublicInstallSshError, 'binding'):
                subject._authorization(root, intent, '0' * 64)
            self.assertEqual(record, json.loads(path.read_text()))

    def test_unknown_submission_has_durable_intent_and_cannot_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            intent = self.intent(); driver = subject.RpmPublicInstallSshDriver(temporary)
            self.authorize(Path(temporary), intent)
            captured = {'paths': {}, 'typed': {'expectedBaseVersion': '2.1.16',
                'expectedTargetVersion': '2.1.17', 'expectedDesktopJarSha256': '1' * 64,
                'expectedBaseNevra': 'vpn-control-2.1.16-1.x86_64',
                'expectedTargetNevra': 'vpn-control-2.1.17-1.x86_64',
                'sourceFingerprint': 'f' * 64}, 'config': object(), 'remoteRoot': '/private'}
            def transfer(path, _captured, _intent):
                path.write_bytes(b'fixed'); return {}
            def admitted(_root, candidate):
                subject._authorization(Path(temporary), candidate, 'f' * 64)
                return captured
            with patch.object(subject, 'admission', side_effect=admitted), \
                 patch.object(driver, '_transfer', side_effect=transfer), \
                 patch.object(driver, '_remote', return_value=None) as remote:
                self.assertEqual('unknown', driver.submit(intent)['state'])
                self.assertTrue(driver._journal_path(intent.correlation_id).exists())
                with self.assertRaisesRegex(subject.RpmPublicInstallSshError, 'observe'):
                    driver.submit(intent)
                with self.assertRaisesRegex(subject.RpmPublicInstallSshError, 'binding'):
                    driver.submit(replace(intent, correlation_id=str(uuid.uuid4())))
                self.assertEqual(1, remote.call_count)

    def test_submitted_transition_and_preflight_admission_are_typed(self):
        with tempfile.TemporaryDirectory() as temporary:
            intent = self.intent(); driver = subject.RpmPublicInstallSshDriver(temporary)
            self.authorize(Path(temporary), intent)
            captured = {'paths': {}, 'typed': {'expectedBaseVersion': '2.1.16',
                'expectedTargetVersion': '2.1.17', 'expectedBaseNevra': 'vpn-control-2.1.16-1.x86_64',
                'expectedTargetNevra': 'vpn-control-2.1.17-1.x86_64',
                'expectedDesktopJarSha256': '1' * 64, 'sourceFingerprint': 'f' * 64},
                'config': object(), 'remoteRoot': '/private'}
            def transfer(path, _captured, _intent):
                path.write_bytes(b'fixed'); return {}
            request = {'scenarioId': adapter.SCENARIO_ID, 'host': intent.host, 'environment': intent.environment,
                       'bundleManifestArtifactId': intent.artifact_ids['bundleManifest'],
                       'scenarioInputArtifactId': intent.artifact_ids['scenarioInput'],
                       'sourceFixtureArtifactId': intent.artifact_ids['sourceFixture'],
                       'targetPackageArtifactId': intent.artifact_ids['targetPackage'],
                       'credentialHandle': intent.credential_handle, 'scenarioCorrelationId': intent.correlation_id}
            def admitted(_root, candidate):
                subject._authorization(Path(temporary), candidate, 'f' * 64)
                return captured
            with patch.object(subject, 'admission', side_effect=admitted), \
                 patch.object(driver, '_transfer', side_effect=transfer), \
                 patch.object(driver, '_remote', return_value={'state': 'submitted', 'correlationId': intent.correlation_id}) as remote:
                self.assertTrue(subject.preflight(temporary, request)['ready'])
                self.assertFalse(driver._journal_path(intent.correlation_id).exists())
                self.assertEqual('submitted', driver.submit(intent)['state'])
                remote_arguments = remote.call_args.args[3]
                self.assertNotIn(intent.credential_handle, repr(remote_arguments))
                self.assertNotIn('fixed', repr(remote_arguments))
            with patch.object(subject, 'admission', side_effect=subject.RpmPublicInstallSshError('changed')):
                self.assertFalse(subject.preflight(temporary, request)['ready'])

    def test_observer_never_submits_and_preserves_running_terminal_or_unknown(self):
        with tempfile.TemporaryDirectory() as temporary:
            intent = self.intent(); driver = subject.RpmPublicInstallSshDriver(temporary)
            driver._save_journal(intent)
            config = SimpleNamespace(hosts={intent.host: SimpleNamespace(user='vpnfixture', fixture_transfer_root=PurePosixPath('/private'))})
            with patch.object(subject.ssh_transport, 'load_config', return_value=config), \
                 patch.object(driver, '_remote', side_effect=[
                     {'state': 'running', 'correlationId': intent.correlation_id},
                     {'state': 'terminal', 'correlationId': intent.correlation_id, 'exitCode': 0}, None]) as remote:
                self.assertEqual('running', driver.status(intent.correlation_id)['state'])
                self.assertEqual('terminal', driver.collect(intent.correlation_id)['state'])
                self.assertEqual('unknown', driver.status(intent.correlation_id)['state'])
                self.assertEqual(3, remote.call_count)

    def test_preflight_rejects_nonstring_artifact_before_admission(self):
        intent = self.intent()
        request = {'scenarioId': adapter.SCENARIO_ID, 'host': intent.host, 'environment': intent.environment,
                   'bundleManifestArtifactId': None, 'scenarioInputArtifactId': intent.artifact_ids['scenarioInput'],
                   'sourceFixtureArtifactId': intent.artifact_ids['sourceFixture'],
                   'targetPackageArtifactId': intent.artifact_ids['targetPackage'],
                   'credentialHandle': intent.credential_handle, 'scenarioCorrelationId': intent.correlation_id}
        with patch.object(subject, 'admission') as admission:
            with self.assertRaises(ValueError):
                subject.preflight('.', request)
        admission.assert_not_called()

    def test_remote_programs_compile_and_import_in_script_mode(self):
        self.assertIn('/opt/vpn-control/bin/vpn-control', subject._LAUNCHER)
        self.assertIn("'--cleanup-synthetic-workspace'", subject._LAUNCHER)
        self.assertNotIn('credentialHandle', subject._SUBMIT)
        for name in ('_ASSESS_HARNESS', '_SUBMIT', '_STATUS', '_LAUNCHER'):
            compile(getattr(subject, name), '<' + name + '>', 'exec')
        done = subprocess.run([sys.executable, '-c', "import sys;sys.path.insert(0,'agent_tools');import native_rpm_public_install_ssh"],
                              capture_output=True, text=True, check=False)
        self.assertEqual(0, done.returncode, done.stderr)

    @unittest.skipUnless(os.name == 'posix', 'owned harness evidence requires POSIX')
    def test_multiline_harness_result_and_cleanup_require_actual_restoration(self):
        namespace = {'json': json, 'os': os, 'stat': stat, 'subprocess': subprocess}
        exec(subject._ASSESS_HARNESS, namespace)
        assess = namespace['assess_harness']
        with tempfile.TemporaryDirectory(prefix='vpn-public-install-evidence-', dir='/tmp') as evidence_raw:
            evidence = Path(evidence_raw); workspace = evidence / 'workspace'; workspace.mkdir()
            pointer = {'evidence': evidence_raw, 'workspace': str(workspace)}
            stdout = evidence / 'harness.stdout'
            intent = {'correlationId': str(uuid.uuid4()), 'sourceFingerprint': 'f' * 64,
                      'expectedTargetVersion': '2.1.17'}
            accepted = {'code': 'ACCEPTED', 'final': False, 'operationId': str(uuid.uuid4()),
                        'controllerId': 'origin', 'requestId': 'request',
                        'data': {'jobId': str(uuid.uuid4()), 'handoffReady': True}}
            result = {'accepted': accepted,
                      'protectedReceipt': {'jobId': accepted['data']['jobId'], 'phase': 'SUCCEEDED', 'code': 'OK'},
                      'replacementRecoveryObservation': {'ok': True, 'code': 'OK', 'final': True,
                          'operationId': accepted['operationId'], 'controllerId': 'next',
                          'data': {'jobId': accepted['data']['jobId'], 'originControllerId': 'origin',
                                   'originRequestId': 'request'}},
                      'sourceFingerprint': intent['sourceFingerprint'], 'targetVersion': '2.1.17',
                      'productionTrustedInstallSucceeded': True, 'sameSourceRecoveryProven': True,
                      'retainedFixtureAuth': True, 'preservesExistingFixturePassword': True}
            (evidence / 'install-result.json').write_text(json.dumps(result, indent=2))
            stdout.write_text(json.dumps(pointer) + '\n' + json.dumps(result, indent=2) + '\n')
            def run(arguments, **_kwargs):
                if arguments[0] == 'passwd':
                    return SimpleNamespace(returncode=0, stdout='vpnfixture P 2026-09-28\n', stderr='')
                return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
            summary, code = assess(stdout, intent, 0, run)
            self.assertEqual(1, code)
            self.assertTrue(summary['credentialRestored'])
            self.assertFalse(summary['cleanup']['workspaceRemoved'])
            self.assertEqual('preserved-for-recovery', summary['cleanup']['state'])
            summary, code = assess(stdout, intent, 130, run)
            self.assertEqual(130, code, 'Collection preserves the failing harness exit')
            self.assertIsNotNone(summary, 'A cleanup failure retains the correlated installation evidence')
            self.assertEqual('failed', summary['result'])
            self.assertEqual(accepted['operationId'], summary['operationId'])
            self.assertFalse(summary['cleanup']['workspaceRemoved'])
            workspace.rmdir()
            summary, code = assess(stdout, intent, 0, run)
            self.assertEqual(0, code)
            self.assertEqual('passed', summary['result'])
            auth = evidence / 'private-fixture-auth'; auth.mkdir()
            summary, code = assess(stdout, intent, 0, run)
            self.assertEqual(1, code)
            self.assertFalse(summary['credentialRestored'])
            auth.rmdir()
            def locked(arguments, **_kwargs):
                value = run(arguments)
                if arguments[0] == 'passwd': value.stdout = 'vpnfixture L 2026-09-28\n'
                return value
            summary, code = assess(stdout, intent, 0, locked)
            self.assertEqual(1, code)
            self.assertFalse(summary['credentialRestored'])
            result['retainedFixtureAuth'] = False
            (evidence / 'install-result.json').write_text(json.dumps(result, indent=2))
            summary, code = assess(stdout, intent, 0, run)
            self.assertEqual(1, code)
            self.assertFalse(summary['credentialRestored'])
            (evidence / 'install-result.json').unlink()
            summary, code = assess(stdout, intent, 1, run)
            self.assertIsNone(summary)
            self.assertEqual(1, code)

    def test_remote_submit_rejects_unlisted_transfer_before_account_or_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            run = subprocess.run([sys.executable, '-c', subject._SUBMIT, temporary,
                                  json.dumps({'fileHashes': {}, 'scenarioId': adapter.SCENARIO_ID}), '1', '0' * 64],
                                 input='x', capture_output=True, text=True, check=False)
            self.assertEqual('unknown', json.loads(run.stdout)['state'])
            self.assertFalse((Path(temporary) / 'native-scenario-jobs').exists())

    @unittest.skipUnless(os.name == 'posix', 'private remote receipt modes require POSIX')
    def test_remote_status_requires_exact_intent_receipt_and_generation(self):
        intent = self.intent()
        with tempfile.TemporaryDirectory() as temporary:
            job = Path(temporary) / 'native-scenario-jobs' / intent.environment / adapter.SCENARIO_ID / intent.correlation_id
            job.mkdir(parents=True, mode=0o700); job.chmod(0o700)
            identity = {'pid': 1234, 'startTicks': 5678}
            public = intent.public_mapping()
            receipt = {**public, **identity, 'exitCode': 0,
                       'scenarioEvidence': {'correlationId': intent.correlation_id, 'result': 'passed'}}
            def write(name, value):
                path = job / name; path.write_text(json.dumps(value)); path.chmod(0o600)
            write('intent.json', {**public, 'identity': identity})
            write('receipt.json', receipt)
            args = [temporary, intent.host, intent.environment, intent.correlation_id,
                    intent.bundle_hash, json.dumps(dict(intent.artifact_ids))]
            def observe():
                run = subprocess.run([sys.executable, '-c', subject._STATUS, *args],
                                     capture_output=True, text=True, check=False)
                self.assertEqual(0, run.returncode, run.stderr)
                return json.loads(run.stdout)
            self.assertEqual('terminal', observe()['state'])
            write('receipt.json', {**receipt, 'bundleHash': '0' * 64})
            self.assertEqual('unknown', observe()['state'])
            write('receipt.json', {**receipt, 'startTicks': 9999})
            self.assertEqual('unknown', observe()['state'])


if __name__ == '__main__':
    unittest.main()

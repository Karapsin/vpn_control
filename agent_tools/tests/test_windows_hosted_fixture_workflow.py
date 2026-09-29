from pathlib import Path
import hashlib
import json
import os
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from agent_tools import windows_update_fixture_workflow as fixture
from agent_tools import windows_msi_base_prepare as base_prepare


SHA = 'a' * 40
CORR = '12345678-1234-1234-1234-123456789abc'
ROOT = Path(__file__).resolve().parents[2]


def tracked_show(argv):
    path = argv[-1].split(':', 1)[1]
    if path == 'gradle.properties':
        return 'vpnControlVersion=2.2.0\n'
    if path in (fixture.CALLER, fixture.REUSABLE):
        return (ROOT / path).read_text()
    raise AssertionError(path)


class Runner:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, argv):
        self.calls.append(argv)
        if argv[0] == 'git' and 'show' in argv:
            return subprocess.CompletedProcess(argv, 0, tracked_show(argv), '')
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return subprocess.CompletedProcess(argv, response[0], response[1], response[2] if len(response) > 2 else '')


class WindowsFixtureWorkflowTest(unittest.TestCase):
    def setUp(self):
        observer = patch.object(base_prepare, 'readiness', return_value={
            'state': 'blocked', 'code': 'PRODUCT_VERSION',
            'installedVersion': '2.1.17', 'productCount': 1,
            'activeCount': 0, 'ownedExplorerCount': 1})
        observer.start()
        self.addCleanup(observer.stop)

    def request(self):
        return {'sourceSha': SHA, 'baseVersion': '2.1.19', 'correlationId': CORR}

    def test_equal_installed_base_is_rejected_before_hosted_dispatch_intent(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(base_prepare, 'readiness', return_value={
                 'state': 'ready', 'code': 'READY',
                 'installedVersion': '2.1.17', 'productCount': 1,
                 'activeCount': 0, 'ownedExplorerCount': 1}):
            root = Path(tmp)
            runner = Runner([])
            with self.assertRaisesRegex(ValueError, 'newer than installed'):
                fixture.dispatch(root, {**self.request(), 'baseVersion': '2.1.17'}, runner=runner)
            self.assertFalse((root / '.runtime').exists())
            self.assertEqual([], runner.calls)

    def test_newer_base_accepts_observed_product_version_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(base_prepare, 'readiness', return_value={
                 'state': 'blocked', 'code': 'PRODUCT_VERSION',
                 'installedVersion': '2.1.17', 'productCount': 1,
                 'activeCount': 0, 'ownedExplorerCount': 1}) as observe:
            root = Path(tmp)
            runner = Runner([(0, SHA + '\n'), (0, '')])
            result = fixture.dispatch(root, self.request(), runner=runner)
            self.assertEqual('submitted', result['state'])
            observe.assert_called_once_with(root, {
                'host': 'archlinux', 'expectedCurrentVersion': '2.1.19'})
            self.assertTrue((root / '.runtime/windows-msi-fixture-dispatch' /
                             (CORR + '.json')).is_file())
            self.assertEqual(1, sum(call[:3] == ['gh', 'workflow', 'run']
                                    for call in runner.calls))

    def test_unknown_or_busy_installed_version_never_dispatches(self):
        for inventory in (
            {'state': 'unknown', 'installedVersion': None},
            {'state': 'blocked', 'code': 'PRODUCT_VERSION', 'installedVersion': '2.1.17',
             'productCount': 1, 'activeCount': 1, 'ownedExplorerCount': 1},
            {'state': 'blocked', 'code': 'PRODUCT_VERSION', 'installedVersion': '2.1.17',
             'productCount': 1, 'activeCount': 0, 'ownedExplorerCount': 0},
        ):
            with self.subTest(inventory=inventory), tempfile.TemporaryDirectory() as tmp, \
                 patch.object(base_prepare, 'readiness', return_value=inventory):
                root = Path(tmp)
                runner = Runner([])
                with self.assertRaisesRegex(ValueError, 'Fresh idle CP117'):
                    fixture.dispatch(root, self.request(), runner=runner)
                self.assertFalse((root / '.runtime').exists())
                self.assertEqual([], runner.calls)

    def test_intent_is_durable_before_dispatch_and_response_loss_is_not_replayed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'gradle.properties').write_text('vpnControlVersion=2.2.0\n')
            def runner(argv):
                journal = root / '.runtime/windows-msi-fixture-dispatch' / (CORR + '.json')
                if argv[0] == 'git' and 'show' in argv:
                    return subprocess.CompletedProcess(argv, 0, tracked_show(argv), '')
                if argv[:3] == ['gh', 'workflow', 'run']:
                    self.assertTrue(journal.is_file())
                    raise TimeoutError('lost response')
                return subprocess.CompletedProcess(argv, 0, SHA + '\n', '')
            result = fixture.dispatch(root, self.request(), runner=runner)
            self.assertEqual('unknown', result['state'])
            self.assertFalse(result['replayAllowed'])
            replay = fixture.dispatch(root, self.request(), runner=Runner([]))
            self.assertEqual('unknown', replay['state'])
            self.assertFalse(replay['replayAllowed'])

    def test_exact_source_must_wire_correlation_into_run_and_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for damaged in (fixture.CALLER, fixture.REUSABLE):
                def runner(argv):
                    if argv[0] == 'git' and 'show' in argv:
                        body = tracked_show(argv)
                        if argv[-1].endswith(':' + damaged):
                            body = body.replace("inputs.correlation_id", "inputs.unbound_id")
                        return subprocess.CompletedProcess(argv, 0, body, '')
                    raise AssertionError('Dispatch reached remote before source contract')
                with self.subTest(damaged=damaged), self.assertRaisesRegex(ValueError, 'correlation'):
                    fixture.dispatch(root, self.request(), runner=runner)
                self.assertFalse((root / '.runtime').exists())

    def test_status_binds_title_sha_unique_run_and_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'gradle.properties').write_text('vpnControlVersion=2.2.0\n')
            fixture.dispatch(root, self.request(), runner=Runner([(0, SHA + '\n'), (0, '')]))
            run = {'databaseId': 71, 'headSha': SHA, 'displayTitle': 'Windows MSI fixture ' + CORR,
                   'status': 'completed', 'conclusion': 'success', 'url': 'https://github.com/x/y/actions/runs/71'}
            artifact = {'artifacts': [{'id': 81, 'name': 'vpn-control-windows-update-fixture-' + CORR,
                                       'expired': False, 'size_in_bytes': 100}]}
            result = fixture.status(root, {'correlationId': CORR}, runner=Runner([
                (0, json.dumps([run])), (0, json.dumps(artifact))]))
            self.assertEqual('complete', result['state'])
            self.assertEqual(71, result['runId'])
            self.assertEqual(81, result['artifactId'])
            self.assertEqual(SHA, result['sourceSha'])

    def test_duplicate_or_wrong_sha_run_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'gradle.properties').write_text('vpnControlVersion=2.2.0\n')
            fixture.dispatch(root, self.request(), runner=Runner([(0, SHA + '\n'), (0, '')]))
            matching = {'databaseId': 1, 'headSha': SHA, 'displayTitle': 'Windows MSI fixture ' + CORR,
                        'status': 'completed', 'conclusion': 'success'}
            duplicate = dict(matching, databaseId=2)
            wrong = dict(matching, headSha='b' * 40)
            for runs in ([matching, duplicate], [wrong]):
                result = fixture.status(root, {'correlationId': CORR}, runner=Runner([(0, json.dumps(runs))]))
                self.assertEqual('unknown', result['state'])
                self.assertFalse(result['replayAllowed'])

    def test_status_rechecks_transient_missing_run_without_dispatch_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'gradle.properties').write_text('vpnControlVersion=2.2.0\n')
            fixture.dispatch(root, self.request(), runner=Runner([(0, SHA + '\n'), (0, '')]))
            run = {'databaseId': 71, 'headSha': SHA, 'displayTitle': 'Windows MSI fixture ' + CORR,
                   'status': 'in_progress', 'conclusion': ''}
            runner = Runner([(0, '[]'), (0, json.dumps([run]))])
            result = fixture.status(root, {'correlationId': CORR}, runner=runner)
            self.assertEqual('pending', result['state'])
            self.assertEqual(71, result['runId'])
            self.assertEqual(2, len(runner.calls))
            self.assertTrue(all(call[:3] == ['gh', 'run', 'list'] for call in runner.calls))

    def test_successful_run_without_exact_artifact_remains_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'gradle.properties').write_text('vpnControlVersion=2.2.0\n')
            fixture.dispatch(root, self.request(), runner=Runner([(0, SHA + '\n'), (0, '')]))
            run = {'databaseId': 71, 'headSha': SHA, 'displayTitle': 'Windows MSI fixture ' + CORR,
                   'status': 'completed', 'conclusion': 'success'}
            for artifact_list in ({'artifacts': None}, {'artifacts': []},
                                  {'artifacts': [{'id': 81, 'name': 'unrelated', 'expired': False}]}):
                result = fixture.status(root, {'correlationId': CORR}, runner=Runner([
                    (0, json.dumps([run])), (0, json.dumps(artifact_list))]))
                self.assertEqual('unknown', result['state'])
                self.assertFalse(result['replayAllowed'])

    def test_status_does_not_create_runtime_and_rejects_unsafe_journal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = fixture.status(root, {'correlationId': CORR}, runner=Runner([]))
            self.assertEqual('unknown', missing['state'])
            self.assertFalse((root / '.runtime').exists())
            (root / 'gradle.properties').write_text('vpnControlVersion=2.2.0\n')
            fixture.dispatch(root, self.request(), runner=Runner([(0, SHA + '\n'), (0, '')]))
            journal = root / '.runtime/windows-msi-fixture-dispatch' / (CORR + '.json')
            journal.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'Unsafe fixture dispatch journal'):
                fixture.status(root, {'correlationId': CORR}, runner=Runner([]))
            journal.chmod(0o600)
            journal.write_text('{}')
            with self.assertRaisesRegex(ValueError, 'Invalid fixture dispatch journal'):
                fixture.status(root, {'correlationId': CORR}, runner=Runner([]))

    def test_failed_log_requires_one_exact_terminal_failed_run_and_redacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'gradle.properties').write_text('vpnControlVersion=2.2.0\n')
            fixture.dispatch(root, self.request(), runner=Runner([(0, SHA + '\n'), (0, '')]))
            run = {'databaseId': 71, 'headSha': SHA, 'displayTitle': 'Windows MSI fixture ' + CORR,
                   'status': 'completed', 'conclusion': 'failure'}
            raw = (b'ordinary context\nERROR: update test failed\n'
                   b'Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz123456\n'
                   b'Authorization: Basic dXNlcjpwYXNzd29yZA==\n'
                   b'ERROR: endpoint https://user:pass@example.test/subscription?access_token=privatevalue\n'
                   b'ERROR: local C:\\Users\\alice\\update-fixture and /Users/bob/private\n'
                   b'AssertionError: expected target\n')
            read_ids = []
            def reader(run_id):
                read_ids.append(run_id)
                return raw
            result = fixture.failed_log(root, {'correlationId': CORR},
                                        runner=Runner([(0, json.dumps([run]))]), log_reader=reader)
            self.assertEqual('failed-log', result['state'])
            self.assertEqual([71], read_ids)
            self.assertEqual(SHA, result['sourceSha'])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), result['logSha256'])
            self.assertIn('AssertionError: expected target', result['excerpt'])
            self.assertNotIn('ghp_abcdefghijklmnopqrstuvwxyz123456', result['excerpt'])
            self.assertNotIn('dXNlcjpwYXNzd29yZA==', result['excerpt'])
            self.assertNotIn('example.test', result['excerpt'])
            self.assertNotIn('alice', result['excerpt'])
            self.assertNotIn('bob', result['excerpt'])
            self.assertIn('[REDACTED URL]', result['excerpt'])
            self.assertIn('[REDACTED]', result['excerpt'])
            self.assertFalse(result['replayAllowed'])
            for runs in ([run, dict(run, databaseId=72)], [dict(run, headSha='b' * 40)],
                         [dict(run, status='in_progress')], [dict(run, conclusion='cancelled')]):
                result = fixture.failed_log(root, {'correlationId': CORR},
                                            runner=Runner([(0, json.dumps(runs))]), log_reader=reader)
                self.assertEqual('unknown', result['state'])
            self.assertEqual([71], read_ids)

    def test_failed_log_capture_has_child_size_cap_and_excerpt_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / 'gh'
            fake.write_text('#!/bin/sh\nprintf abcdefghijklmnop\n')
            fake.chmod(0o700)
            with patch.object(fixture, '_MAX_FAILED_LOG_BYTES', 8), \
                 patch.dict(os.environ, {'PATH': tmp + os.pathsep + os.environ.get('PATH', '')}):
                self.assertIsNone(fixture._read_failed_log(71))
            raw = (b'ERROR: repeated failure\n' * 5000)
            self.assertLessEqual(len(fixture._failed_excerpt(raw)), fixture._MAX_FAILED_EXCERPT_CHARS)

    def test_rejects_base_version_not_preceding_tracked_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'gradle.properties').write_text('vpnControlVersion=2.2.0\n')
            request = dict(self.request(), baseVersion='2.2.0')
            with self.assertRaisesRegex(ValueError, 'baseVersion'):
                fixture.dispatch(root, request, runner=Runner([]))
            self.assertFalse((root / '.runtime').exists())

    def test_collect_verifies_exact_receipt_and_msi_bytes_once(self):
        base_bytes, target_bytes = b'base MSI bytes', b'target MSI bytes'
        def asset(version, body):
            return {'fileName': 'vpn-control-' + version + '.msi', 'platform': 'windows',
                    'architecture': 'x86_64', 'displayVersion': version, 'sizeBytes': len(body),
                    'sha256': hashlib.sha256(body).hexdigest()}
        receipt = {'schemaVersion': 1, 'testOnly': True, 'productionTrustChanged': False,
                   'architecture': 'x86_64', 'nativeOs': 'Windows-11', 'sourceFingerprint': 'c' * 64,
                   'builds': [
                       {'label': 'base', 'version': '2.1.19', 'codeFingerprint': 'd' * 64,
                        'sourceFingerprint': 'c' * 64, 'assets': [asset('2.1.19', base_bytes)]},
                       {'label': 'target', 'version': '2.2.0', 'codeFingerprint': 'd' * 64,
                        'sourceFingerprint': 'c' * 64, 'assets': [asset('2.2.0', target_bytes)]}]}
        files = [{'path': 'gradle.properties', 'sha256': 'f' * 64, 'sizeBytes': 1, 'mode': 420}]
        fingerprint = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':'),
                                               ensure_ascii=False).encode()).hexdigest()
        receipt['sourceFingerprint'] = fingerprint
        for build in receipt['builds']:
            build['sourceFingerprint'] = fingerprint
        snapshot = {'schemaVersion': 1, 'sourceHead': SHA, 'canonicalVersion': '2.2.0',
                    'sourceFingerprint': fingerprint, 'files': files}
        plan = {'schemaVersion': 1, 'testOnly': True, 'productionTrustChanged': False,
                'sourceFingerprint': fingerprint, 'platform': 'windows', 'packageFamily': 'default',
                'architecture': 'x86_64', 'stages': [{'label': 'base', 'version': '2.1.19'},
                                                   {'label': 'target', 'version': '2.2.0'}]}
        complete = {'state': 'complete', 'correlationId': CORR, 'sourceSha': SHA,
                    'baseVersion': '2.1.19', 'targetVersion': '2.2.0', 'runId': 71,
                    'artifactId': 81, 'artifactName': 'vpn-control-windows-update-fixture-' + CORR}
        def download(_artifact_id, archive):
            with zipfile.ZipFile(archive, 'w') as package:
                package.writestr('fixture-receipt.json', json.dumps(receipt))
                package.writestr('snapshot.json', json.dumps(snapshot))
                package.writestr('build-plan.json', json.dumps(plan))
                package.writestr('packages/base/vpn-control-2.1.19.msi', base_bytes)
                package.writestr('packages/target/vpn-control-2.2.0.msi', target_bytes)
            return True
        with tempfile.TemporaryDirectory() as tmp, patch.object(fixture, 'status', return_value=complete):
            root = Path(tmp)
            result = fixture.collect(root, {'correlationId': CORR}, downloader=download)
            self.assertEqual('collected', result['state'])
            self.assertEqual(SHA, result['sourceSha'])
            self.assertEqual(hashlib.sha256(target_bytes).hexdigest(), result['packages'][1]['sha256'])
            self.assertEqual('unknown', fixture.collect(root, {'correlationId': CORR}, downloader=download)['state'])
            self.assertEqual(81, json.loads((root / '.runtime/windows-msi-fixture-collect' / CORR / 'intent.json').read_text())['artifactId'])
        receipt['builds'][1]['assets'][0]['sha256'] = '0' * 64
        with tempfile.TemporaryDirectory() as tmp, patch.object(fixture, 'status', return_value=complete):
            self.assertEqual('unknown', fixture.collect(tmp, {'correlationId': CORR}, downloader=download)['state'])
        receipt['builds'][1]['assets'][0]['sha256'] = hashlib.sha256(target_bytes).hexdigest()
        snapshot['sourceHead'] = 'b' * 40
        with tempfile.TemporaryDirectory() as tmp, patch.object(fixture, 'status', return_value=complete):
            self.assertEqual('unknown', fixture.collect(tmp, {'correlationId': CORR}, downloader=download)['state'])
        snapshot['sourceHead'] = SHA
        plan['sourceFingerprint'] = '0' * 64
        with tempfile.TemporaryDirectory() as tmp, patch.object(fixture, 'status', return_value=complete):
            self.assertEqual('unknown', fixture.collect(tmp, {'correlationId': CORR}, downloader=download)['state'])

    def test_collect_rejects_oversized_receipt_before_json_parse(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'fixture-receipt.json'
            path.write_bytes(b'{' + b' ' * (fixture._MAX_RECEIPT_BYTES + 1))
            with patch.object(fixture.json, 'loads', side_effect=AssertionError('parsed oversized JSON')):
                with self.assertRaisesRegex(ValueError, 'size is unsafe'):
                    fixture._bounded_json(path, fixture._MAX_RECEIPT_BYTES)

    def test_download_has_child_file_size_cap_before_writing_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / 'gh'
            fake.write_text('#!/bin/sh\nprintf abcdefghijklmnop\n')
            fake.chmod(0o700)
            archive = Path(tmp) / 'artifact.zip'
            with patch.object(fixture, '_MAX_COMPRESSED_BYTES', 8), \
                 patch.dict(os.environ, {'PATH': tmp + os.pathsep + os.environ.get('PATH', '')}):
                self.assertFalse(fixture._download_zip(81, archive))
            self.assertLessEqual(archive.stat().st_size, 8)

    def test_collect_fsyncs_stage_parent_before_download_effect(self):
        complete = {'state': 'complete', 'correlationId': CORR, 'sourceSha': SHA,
                    'baseVersion': '2.1.19', 'targetVersion': '2.2.0', 'runId': 71,
                    'artifactId': 81, 'artifactName': 'vpn-control-windows-update-fixture-' + CORR}
        real_fsync = os.fsync
        order = []
        def observed_fsync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode): order.append('directory')
            return real_fsync(fd)
        def download(_artifact_id, _archive):
            self.assertIn('directory', order)
            order.append('download')
            return False
        with tempfile.TemporaryDirectory() as tmp, patch.object(fixture, 'status', return_value=complete), \
             patch.object(fixture.os, 'fsync', side_effect=observed_fsync):
            self.assertEqual('unknown', fixture.collect(tmp, {'correlationId': CORR}, downloader=download)['state'])
            self.assertLess(order.index('directory'), order.index('download'))

    def test_collect_rejects_zip_traversal_without_writing_outside_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / 'unsafe.zip'
            with zipfile.ZipFile(archive, 'w') as package:
                package.writestr('../escape.txt', 'bad')
            with self.assertRaisesRegex(ValueError, 'archive path'):
                fixture._extract_zip(archive, Path(tmp) / 'extract')
            self.assertFalse((Path(tmp) / 'escape.txt').exists())


if __name__ == '__main__':
    unittest.main()

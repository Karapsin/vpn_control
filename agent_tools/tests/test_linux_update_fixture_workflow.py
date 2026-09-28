from pathlib import Path
import json
import subprocess
import tempfile
import unittest

from agent_tools import linux_update_fixture_workflow as fixture


SHA = 'a' * 40
CORR = '12345678-1234-1234-1234-123456789abc'


class Runner:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, argv):
        self.calls.append(argv)
        if argv[0] == 'git' and 'show' in argv:
            return subprocess.CompletedProcess(argv, 0, 'vpnControlVersion=2.2.0\n', '')
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return subprocess.CompletedProcess(argv, response[0], response[1], response[2] if len(response) > 2 else '')


class LinuxFixtureWorkflowTest(unittest.TestCase):
    def request(self):
        return {'sourceSha': SHA, 'baseVersion': '2.1.19', 'correlationId': CORR}

    def test_intent_is_durable_before_dispatch_and_response_loss_is_not_replayed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'gradle.properties').write_text('vpnControlVersion=2.2.0\n')
            def runner(argv):
                journal = root / '.runtime/linux-rpm-fixture-dispatch' / (CORR + '.json')
                if argv[0] == 'git' and 'show' in argv:
                    return subprocess.CompletedProcess(argv, 0, 'vpnControlVersion=2.2.0\n', '')
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

    def test_status_binds_title_sha_unique_run_and_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'gradle.properties').write_text('vpnControlVersion=2.2.0\n')
            fixture.dispatch(root, self.request(), runner=Runner([(0, SHA + '\n'), (0, '')]))
            run = {'databaseId': 71, 'headSha': SHA, 'displayTitle': 'Linux RPM fixture ' + CORR,
                   'status': 'completed', 'conclusion': 'success', 'url': 'https://github.com/x/y/actions/runs/71'}
            artifact = {'artifacts': [{'id': 81, 'name': 'vpn-control-linux-update-fixture-' + CORR,
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
            matching = {'databaseId': 1, 'headSha': SHA, 'displayTitle': 'Linux RPM fixture ' + CORR,
                        'status': 'completed', 'conclusion': 'success'}
            duplicate = dict(matching, databaseId=2)
            wrong = dict(matching, headSha='b' * 40)
            for runs in ([matching, duplicate], [wrong]):
                result = fixture.status(root, {'correlationId': CORR}, runner=Runner([(0, json.dumps(runs))]))
                self.assertEqual('unknown', result['state'])
                self.assertFalse(result['replayAllowed'])

    def test_successful_run_without_exact_artifact_remains_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'gradle.properties').write_text('vpnControlVersion=2.2.0\n')
            fixture.dispatch(root, self.request(), runner=Runner([(0, SHA + '\n'), (0, '')]))
            run = {'databaseId': 71, 'headSha': SHA, 'displayTitle': 'Linux RPM fixture ' + CORR,
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
            journal = root / '.runtime/linux-rpm-fixture-dispatch' / (CORR + '.json')
            journal.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'Unsafe fixture dispatch journal'):
                fixture.status(root, {'correlationId': CORR}, runner=Runner([]))
            journal.chmod(0o600)
            journal.write_text('{}')
            with self.assertRaisesRegex(ValueError, 'Invalid fixture dispatch journal'):
                fixture.status(root, {'correlationId': CORR}, runner=Runner([]))

    def test_rejects_base_version_not_preceding_tracked_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'gradle.properties').write_text('vpnControlVersion=2.2.0\n')
            request = dict(self.request(), baseVersion='2.2.0')
            with self.assertRaisesRegex(ValueError, 'baseVersion'):
                fixture.dispatch(root, request, runner=Runner([]))
            self.assertFalse((root / '.runtime').exists())


if __name__ == '__main__':
    unittest.main()

"""Inert tmux transport stand-ins; never start tmux, SSH, or package builds."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from agent_tools import ssh_tmux_session as tool

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.name == 'posix', 'private POSIX journal')
class SessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/tmp"); self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name); self.parent.chmod(0o700)
        self.req = {'purpose': tool.PURPOSE, 'host': 'archlinux', 'environment': 'owned-linux-package-build',
                    'sourceSha': 'd32f719a08db57e5d40ce2bf77e0d7c5b42de557', 'baseVersion': '2.1.19',
                    'targetVersion': '2.2.2', 'correlationId': 'ed85cff6-00d3-433c-aaed-37927df1d1b5'}
        self.job = self.parent / self.req['correlationId']; self.job.mkdir(mode=0o700)
        self.source = self.job / 'source'; (self.source / 'agent_tools').mkdir(parents=True)
        self.helper = self.source / 'agent_tools/linux_package_fixture_build.py'
        shutil.copyfile(ROOT / 'agent_tools/linux_package_fixture_build.py', self.helper)
        self.commands = []; self.sockets = []
        self.addCleanup(lambda: [s.close() for s in self.sockets])
        self.failure = False
        self.run = mock.patch.object(tool, 'run', side_effect=self.fake_run); self.run.start(); self.addCleanup(self.run.stop)
        self.proc = mock.patch.object(tool, 'proc_identity', side_effect=lambda pid: {'pid': pid, 'startTicks': pid + 100}); self.proc.start(); self.addCleanup(self.proc.stop)

    def fake_run(self, args, cwd=None):
        self.commands.append(args)
        if args[0] == 'git':
            return subprocess.CompletedProcess(args, 0, (self.req['sourceSha'] + '\n').encode() if args[-1] == 'HEAD' else b'', b'')
        if args == ['tmux', '-V']:
            return subprocess.CompletedProcess(args, 0, b'tmux 3.4\n', b'')
        if 'new-session' in args:
            sock = socket.socket(socket.AF_UNIX); sock.bind(str(self.job / 'tmux.sock')); os.chmod(self.job / 'tmux.sock', 0o600); self.sockets.append(sock)
            if self.failure:
                raise tool.SessionError('command_unavailable')
            return subprocess.CompletedProcess(args, 0, b'', b'')
        if 'display-message' in args:
            return subprocess.CompletedProcess(args, 0, b'100 200\n', b'')
        if 'list-sessions' in args:
            return subprocess.CompletedProcess(args, 0, ('vpn-build-' + self.req['correlationId'] + '\n').encode(), b'')
        raise AssertionError(args)

    def start(self):
        result = tool.start(self.job, self.source, self.req)
        tool.release(self.job, self.source, result['anchorPin'])
        return result

    def submissions(self):
        return sum('new-session' in x for x in self.commands)

    def terminal(self, content=b'fixed private tar bytes'):
        tool.write_once(self.job / 'result.tar', content)
        return tool.write_once(self.job / 'terminal.json', tool.canonical({
            'schemaVersion': 1, 'correlationId': self.req['correlationId'], 'sourceSha': self.req['sourceSha'],
            'exitCode': 0, 'resultBytes': len(content), 'resultSha256': hashlib.sha256(content).hexdigest(),
            'artifactVerification': 'required', 'replayAllowed': False}))

    def test_disconnected_caller_reattaches_same_owner_without_new_submit(self):
        result = self.start()
        for _ in range(3):
            self.assertEqual('running', tool.status(self.job, self.source, result['anchorPin'])['state'])
        self.assertEqual(1, self.submissions())
        self.assertFalse(result['replayAllowed'])

    def test_lost_submit_response_consumes_fence_never_reexecutes(self):
        self.failure = True
        with self.assertRaises(tool.SessionError): self.start()
        self.assertTrue((self.job / 'tmux-launch.json').exists())
        self.assertFalse((self.job / 'release.json').exists())
        self.failure = False
        with self.assertRaisesRegex(tool.SessionError, 'consumed_or_foreign'): self.start()
        self.assertEqual(1, self.submissions())

    def test_missing_tmux_fails_before_fence(self):
        with mock.patch.object(tool, 'run', side_effect=tool.SessionError('command_unavailable')):
            with self.assertRaises(tool.SessionError): self.start()
        self.assertFalse((self.job / 'tmux-launch.json').exists())
        self.assertEqual(0, self.submissions())

    def test_foreign_socket_never_contacts_server(self):
        (self.job / 'tmux.sock').write_bytes(b'foreign')
        with self.assertRaisesRegex(tool.SessionError, 'consumed_or_foreign'): self.start()
        self.assertEqual([], self.commands)

    def test_source_bytes_drift_rejected_before_fence(self):
        self.helper.write_bytes(self.helper.read_bytes() + b'\n# changed')
        with self.assertRaisesRegex(tool.SessionError, 'unreviewed_build_source'): self.start()
        self.assertFalse((self.job / 'tmux-launch.json').exists())

    def test_same_byte_source_replacement_rejected_after_start(self):
        result = self.start(); replacement = self.helper.with_suffix('.new'); shutil.copyfile(self.helper, replacement); replacement.replace(self.helper)
        with self.assertRaisesRegex(tool.SessionError, 'authority_changed'):
            tool.status(self.job, self.source, result['anchorPin'])
        self.assertEqual(1, self.submissions())

    def test_external_pin_required_and_coordinated_anchor_rewrite_refused(self):
        result = self.start(); anchor = self.job / 'tmux-anchor.json'
        value = json.loads(anchor.read_bytes()); value['pane']['pid'] = 999
        anchor.write_bytes(tool.canonical(value))
        with self.assertRaisesRegex(tool.SessionError, 'anchor_changed'): tool.status(self.job, self.source, result['anchorPin'])
        with self.assertRaisesRegex(tool.SessionError, 'external_pin_required'): tool.status(self.job, self.source, None)

    def test_foreign_extra_session_refused(self):
        result = self.start(); original = self.fake_run
        def foreign(args, cwd=None):
            if 'list-sessions' in args: return subprocess.CompletedProcess(args, 0, b'other\n', b'')
            return original(args, cwd)
        with mock.patch.object(tool, 'run', side_effect=foreign):
            with self.assertRaisesRegex(tool.SessionError, 'foreign_session'): tool.status(self.job, self.source, result['anchorPin'])

    def test_pid_reuse_refused(self):
        result = self.start()
        with mock.patch.object(tool, 'proc_identity', return_value={'pid': 100, 'startTicks': 999}):
            with self.assertRaisesRegex(tool.SessionError, 'owner_changed'): tool.status(self.job, self.source, result['anchorPin'])

    def test_terminal_spool_survives_server_exit_no_rebuild_and_no_promotion(self):
        result = self.start(); terminal = self.terminal(); os.unlink(self.job / 'tmux.sock')
        value = tool.status(self.job, self.source, result['anchorPin'])
        self.assertEqual('terminal', value['state']); self.assertEqual('required', value['artifactVerification'])
        chunk = tool.collect(self.job, self.source, result['anchorPin'], terminal, 0)
        self.assertEqual(b'fixed private tar bytes', base64.b64decode(chunk['chunkBase64']))
        self.assertEqual(1, self.submissions())
        self.assertNotIn('build.log', json.dumps(value)); self.assertNotIn('chunkBase64', value)

    def test_archive_drift_fails_closed(self):
        result = self.start(); pin = self.terminal()
        (self.job / 'result.tar').write_bytes(b'foreign')
        with self.assertRaises(tool.SessionError): tool.collect(self.job, self.source, result['anchorPin'], pin, 0)

    def test_strict_types_no_arbitrary_commands(self):
        for patch in ({'command': 'sh'}, {'purpose': 'shell'}, {'host': 'foreign'}, {'environment': 'vm'}, {'correlationId': True}):
            with self.assertRaises(tool.SessionError): tool.request({**self.req, **patch})
        result = self.start(); pin = self.terminal()
        with self.assertRaisesRegex(tool.SessionError, 'invalid_chunk'): tool.collect(self.job, self.source, result['anchorPin'], pin, True)
        self.assertFalse(any('kill-server' in x or 'kill-session' in x or 'attach-session' in x for x in self.commands))
        self.assertTrue(any('exec ' in x[-1] for x in self.commands if 'new-session' in x))

    def test_prepare_has_no_build_release_until_external_pin_retained(self):
        result = tool.start(self.job, self.source, self.req)
        self.assertEqual('prepared', result['state'])
        self.assertFalse((self.job / 'release.json').exists())
        self.assertEqual('prepared', tool.status(self.job, self.source, result['anchorPin'])['state'])
        tool.release(self.job, self.source, result['anchorPin'])
        with self.assertRaisesRegex(tool.SessionError, 'release_consumed'):
            tool.release(self.job, self.source, result['anchorPin'])
        self.assertEqual(1, self.submissions())

    def test_release_response_loss_resumes_with_original_external_pin(self):
        result = tool.start(self.job, self.source, self.req); original = tool.write_once
        def lost(path, raw):
            pin = original(path, raw)
            if path.name == 'release.json': raise tool.SessionError('response_lost')
            return pin
        with mock.patch.object(tool, 'write_once', side_effect=lost):
            with self.assertRaisesRegex(tool.SessionError, 'response_lost'):
                tool.release(self.job, self.source, result['anchorPin'])
        self.assertEqual('running', tool.status(self.job, self.source, result['anchorPin'])['state'])
        with self.assertRaisesRegex(tool.SessionError, 'release_consumed'):
            tool.release(self.job, self.source, result['anchorPin'])
        self.assertEqual(1, self.submissions())

    def test_long_socket_path_refused_before_fence(self):
        parent = self.parent / ('x' * 80); parent.mkdir(mode=0o700)
        job = parent / self.req['correlationId']; job.mkdir(mode=0o700)
        with self.assertRaisesRegex(tool.SessionError, 'socket_path_too_long'):
            tool.preflight(job, job / 'source', self.req)
        self.assertFalse((job / 'tmux-launch.json').exists())

    def test_only_reviewed_tool_overlay_is_allowed(self):
        self.assertEqual('874b7be8d70e917553d466ed2b8ad71419dec5f21bfd3092060f16180c284cf5',
                         tool.REVIEWED_BUILD_SHA256)
        original = self.fake_run
        def overlay(args, cwd=None):
            if args[0] == 'git' and 'status' in args:
                return subprocess.CompletedProcess(args, 0, b' M agent_tools/linux_package_fixture_build.py\n', b'')
            return original(args, cwd)
        with mock.patch.object(tool, 'run', side_effect=overlay):
            self.assertEqual(tool.REVIEWED_BUILD_SHA256, tool.preflight(self.job, self.source, self.req)['source']['helperSha256'])
        def foreign(args, cwd=None):
            if args[0] == 'git' and 'status' in args:
                return subprocess.CompletedProcess(args, 0, b' M scripts/package_linux_desktop.sh\n', b'')
            return original(args, cwd)
        with mock.patch.object(tool, 'run', side_effect=foreign):
            with self.assertRaisesRegex(tool.SessionError, 'source_changed'): self.start()
        self.assertFalse((self.job / 'tmux-launch.json').exists())

    def test_same_byte_archive_exchange_refuses_external_result_pin(self):
        result = self.start(); terminal = self.terminal()
        first = tool.collect(self.job, self.source, result['anchorPin'], terminal, 0, 5)
        result_path = self.job / 'result.tar'; replacement = self.job / 'replacement'
        replacement.write_bytes(result_path.read_bytes()); replacement.chmod(0o600); replacement.replace(result_path)
        with self.assertRaisesRegex(tool.SessionError, 'result_changed'):
            tool.collect(self.job, self.source, result['anchorPin'], terminal, 5, expected_result=first['resultPin'])

    def test_generated_worker_refuses_source_drift_before_build(self):
        self.start(); self.helper.write_bytes(self.helper.read_bytes() + b'\n# source drift')
        argv = ['worker', str(self.job), str(self.source), base64.b64encode(tool.canonical(self.req)).decode()]
        with mock.patch.object(sys, 'argv', argv), mock.patch('subprocess.run') as process, \
             mock.patch('os.getpid', return_value=200), mock.patch('resource.setrlimit'):
            with self.assertRaises(SystemExit) as result:
                exec(compile(tool._WORKER, 'fixed-tmux-worker', 'exec'), {})
        self.assertEqual(74, result.exception.code); process.assert_not_called()
        self.assertFalse((self.job / 'result.tar').exists())
        self.assertFalse((self.job / 'terminal.json').exists())

    def test_original_foreground_tar_loses_result_on_disconnect_after_build(self):
        from agent_tools import linux_package_fixture_build as original
        runtime = self.source / 'desktopApp/src/main/resources/bin/linux-amd64/sing-box'
        runtime.parent.mkdir(parents=True); runtime.write_bytes(b'inert-runtime')
        artifact = self.job / 'inert-package'; artifact.write_bytes(b'completed package')
        class BrokenStream:
            def write(self, data): raise BrokenPipeError('disconnected test transport')
        fixed = {key: self.req[key] for key in ('sourceSha', 'baseVersion', 'targetVersion', 'correlationId')}
        with mock.patch.object(original, '_run_build') as builds, \
             mock.patch.object(original, '_verify_built', return_value=[artifact]), \
             mock.patch.object(original, '_timing_inventory', return_value=[]), \
             mock.patch.object(original.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, self.req['sourceSha'])), \
             mock.patch.object(original.sys, 'stdout', mock.Mock(buffer=BrokenStream())):
            with self.assertRaises(BrokenPipeError): original._remote_run(self.job, fixed)
        self.assertEqual(5, builds.call_count)
        self.assertFalse((self.job / 'result.tar').exists())
        self.assertFalse((self.job / 'terminal.json').exists())

    def test_same_byte_release_fence_exchange_is_not_adopted(self):
        result = self.start(); fence = self.job / 'tmux-release-fence.json'
        replacement = self.job / 'replacement'; replacement.write_bytes(fence.read_bytes()); replacement.chmod(0o600); replacement.replace(fence)
        with self.assertRaisesRegex(tool.SessionError, 'release_changed'):
            tool.status(self.job, self.source, result['anchorPin'])

    def test_forged_terminal_before_release_is_not_completion(self):
        result = tool.start(self.job, self.source, self.req); self.terminal()
        with self.assertRaisesRegex(tool.SessionError, 'terminal_without_release'):
            tool.status(self.job, self.source, result['anchorPin'])

    def test_actual_generated_worker_spools_before_terminal_not_over_ssh(self):
        self.start()
        def fake_build(args, **kwargs):
            if args[0] == 'git': return self.fake_run(args)
            self.assertEqual(['-B', '-m', 'agent_tools.linux_package_fixture_build', '--remote-run'], args[1:5])
            self.assertEqual(self.source, kwargs['cwd'])
            kwargs['stdout'].write(b'durable archive'); kwargs['stderr'].write(b'private secret build stderr')
            return subprocess.CompletedProcess(args, 0)
        argv = ['worker', str(self.job), str(self.source), base64.b64encode(tool.canonical(self.req)).decode()]
        with mock.patch.object(sys, 'argv', argv), mock.patch('subprocess.run', side_effect=fake_build), \
             mock.patch('os.getpid', return_value=200), mock.patch('resource.setrlimit'):
            exec(compile(tool._WORKER, 'fixed-tmux-worker', 'exec'), {})
        terminal = json.loads((self.job / 'terminal.json').read_bytes())
        self.assertEqual(hashlib.sha256(b'durable archive').hexdigest(), terminal['resultSha256'])
        self.assertEqual(b'durable archive', (self.job / 'result.tar').read_bytes())
        self.assertNotIn('secret', json.dumps(terminal))
        self.assertEqual(0o600, (self.job / 'terminal.json').stat().st_mode & 0o777)


if __name__ == '__main__': unittest.main()

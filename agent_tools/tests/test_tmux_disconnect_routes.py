"""Fixed one-shot MCP boundary for the direct-proven inert disconnect flow."""
import unittest
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock
from agent_tools import mcp_server as server


class TmuxDisconnectRoutes(unittest.TestCase):
    identity = {'hop': 'gateway', 'correlationId': 'ec35797b-d204-4ae7-8026-20d71c4e8ac1'}

    def test_runs_same_probe_once_and_projects_only_finite_result(self):
        probe = mock.Mock()
        for method, state in [('prepare', 'prepared'), ('release', 'released'),
                              ('disconnect', 'disconnected')]:
            getattr(probe, method).return_value = {'state': state, 'replayAllowed': False}
        probe.observe.return_value = {'state': 'completed', 'sequence': 20,
                                     'replayAllowed': False, 'productAcceptance': False}
        adapter = mock.Mock(); adapter.Probe.return_value = probe
        with mock.patch.object(server, '_agent_module', return_value=adapter):
            value = server._ssh_workflow_impl('tmux-disconnect-probe', 'archlinux',
                                              identity=dict(self.identity))
        self.assertTrue(value['ok'])
        self.assertEqual('completed', value['state'])
        adapter.Probe.assert_called_once_with(server.REPO_ROOT, 'gateway', self.identity['correlationId'])
        self.assertEqual(['prepare', 'release', 'disconnect', 'observe', 'close'],
                         [call[0] for call in probe.method_calls])
        self.assertFalse(value['productAcceptance'])

    def test_invalid_inputs_never_load_or_submit(self):
        for edit in ({'host': 'foreign'}, {'identity': None}, {'identity': {}},
                     {'identity': {**self.identity, 'command': 'id'}},
                     {'identity': {**self.identity, 'hop': 'foreign'}},
                     {'identity': {**self.identity, 'correlationId': '../bad'}},
                     {'device': 'api35'}, {'transfer': {}}, {'timeout_seconds': True}):
            with self.subTest(edit=edit), mock.patch.object(server, '_agent_module') as load:
                value = server._ssh_workflow_impl('tmux-disconnect-probe',
                    **{'host': 'archlinux', 'identity': dict(self.identity), **edit})
                self.assertFalse(value['ok']); load.assert_not_called()

    def test_unknown_prepare_never_releases_or_disconnects(self):
        probe = mock.Mock(); probe.prepare.return_value = {'state': 'unknown', 'replayAllowed': False}
        adapter = mock.Mock(); adapter.Probe.return_value = probe
        with mock.patch.object(server, '_agent_module', return_value=adapter):
            value = server._ssh_workflow_impl('tmux-disconnect-probe', 'archlinux', identity=dict(self.identity))
        self.assertFalse(value['ok']); probe.release.assert_not_called()
        probe.disconnect.assert_not_called(); probe.close.assert_called_once()

    def test_rejects_extra_private_reply_before_next_effect(self):
        probe = mock.Mock(); probe.prepare.return_value = {'state': 'prepared', 'replayAllowed': False,
                                                          'private': 'secret-marker'}
        adapter = mock.Mock(); adapter.Probe.return_value = probe
        with mock.patch.object(server, '_agent_module', return_value=adapter):
            value = server._ssh_workflow_impl('tmux-disconnect-probe', 'archlinux', identity=dict(self.identity))
        self.assertFalse(value['ok']); self.assertNotIn('secret-marker', str(value))
        probe.release.assert_not_called(); probe.close.assert_called_once()

    def test_stale_helper_refuses_before_probe_construction(self):
        from agent_tools import ssh_tmux_disconnect_probe as helper
        with mock.patch.object(server, '_MCP_BOOT_TIME_NS', 0), mock.patch.object(helper, 'Probe') as call:
            value = server._ssh_workflow_impl('tmux-disconnect-probe', 'archlinux', identity=dict(self.identity))
        self.assertFalse(value['ok']); call.assert_not_called()

    def test_bad_terminal_or_deadline_never_claims_completion(self):
        valid = {'state': 'completed', 'sequence': 20, 'replayAllowed': False, 'productAcceptance': False}
        for edit in ({'sequence': True}, {'sequence': 19}, {'productAcceptance': True},
                     {'private': 'secret-marker'}, {'state': 'running', 'sequence': 1}):
            probe = mock.Mock()
            for method, state in [('prepare', 'prepared'), ('release', 'released'), ('disconnect', 'disconnected')]:
                getattr(probe, method).return_value = {'state': state, 'replayAllowed': False}
            probe.observe.return_value = {**valid, **edit}
            adapter = mock.Mock(); adapter.Probe.return_value = probe
            with self.subTest(edit=edit), mock.patch.object(server, '_agent_module', return_value=adapter), \
                    mock.patch.object(server.time, 'monotonic', side_effect=[0, 36]):
                value = server._ssh_workflow_impl('tmux-disconnect-probe', 'archlinux', identity=dict(self.identity))
            self.assertFalse(value['ok']); self.assertNotIn('secret-marker', str(value))
            probe.close.assert_called_once()

    def test_fresh_cli_accepts_only_identity_file_from_unrelated_directory(self):
        program = '''import importlib.util,json,sys
from pathlib import Path
from unittest import mock
source=Path(sys.argv[1]);sys.path.insert(0,str(source.parent))
spec=importlib.util.spec_from_file_location('disconnect_cli_server',source)
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
p=mock.Mock()
for method,state in [('prepare','prepared'),('release','released'),('disconnect','disconnected')]:
 getattr(p,method).return_value={'state':state,'replayAllowed':False}
p.observe.return_value={'state':'completed','sequence':20,'replayAllowed':False,'productAcceptance':False}
a=mock.Mock();a.Probe.return_value=p
original=s._agent_module
with mock.patch.object(s,'_agent_module',side_effect=lambda name:a if name=='ssh_tmux_disconnect_probe' else original(name)):
 code=s.main(['ssh-workflow','tmux-disconnect-probe','--host','archlinux','--identity-file',sys.argv[2]])
 assert [c[0] for c in p.method_calls]==['prepare','release','disconnect','observe','close']
 raise SystemExit(code)
'''
        with tempfile.TemporaryDirectory() as directory:
            identity = Path(directory)/'identity.json'; identity.write_text(json.dumps(self.identity))
            result = subprocess.run([sys.executable, '-I', '-c', program, str(Path(server.__file__).resolve()),
                                     str(identity)], cwd=directory, capture_output=True, text=True, timeout=30)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual('completed', json.loads(result.stdout)['state'])


if __name__ == '__main__':
    unittest.main()

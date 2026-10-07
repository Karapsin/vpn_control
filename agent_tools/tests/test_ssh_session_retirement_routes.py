"""Public retirement dispatch preserves exact receipt and bounded output."""
import unittest
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest import mock

from agent_tools import mcp_server as server
from agent_tools import ssh_connection_session_retirement as retirement
from agent_tools.native_next_action import next_action


class RetirementRoutes(unittest.TestCase):
    def test_fresh_script_context_resolves_relative_imports(self):
        source = str(Path(server.__file__).resolve())
        program = '''import importlib.util,json,sys
from pathlib import Path
from unittest import mock
source=%r
sys.path.insert(0,str(Path(source).parent))
spec=importlib.util.spec_from_file_location('retirement_cli_server',source)
server=importlib.util.module_from_spec(spec)
text=Path(source).read_text()
if sys.argv[1]=='old':
 needle='else "agent_tools.ssh_connection_session_retirement")'
 assert text.count(needle)==1
 text=text.replace(needle,'else "ssh_connection_session_retirement")',1)
exec(compile(text,source,'exec'),server.__dict__)
from agent_tools import ssh_connection_session_retirement as retirement
receipt={'state':'retired','host':'archlinux','receiptSha256':'a'*64,'replayAllowed':False}
with mock.patch.object(retirement,'status',return_value=receipt) as call:
 result=server._ssh_workflow_impl('connection-session-retirement-status','archlinux',identity={'receiptSha256':'a'*64})
 assert call.call_count==(0 if sys.argv[1]=='old' else 1)
 print(json.dumps(result))
''' % source
        with tempfile.TemporaryDirectory() as directory:
            for variant in ('old', 'fixed'):
                result = subprocess.run([sys.executable, '-I', '-c', program, variant], cwd=directory, capture_output=True, text=True, timeout=15, check=True)
                self.assertEqual(json.loads(result.stdout)['ok'], variant == 'fixed', result.stderr)

    def test_fixed_operations_use_exact_receipt(self):
        identity = {'receiptSha256': 'a' * 64}
        receipt = {'state': 'retired', 'host': 'archlinux', **identity, 'replayAllowed': False}
        for action, name in [('connection-session-retire', 'retire'),
                             ('connection-session-retirement-status', 'status')]:
            with self.subTest(action=action), mock.patch.object(retirement, name, return_value=receipt) as call:
                result = server._ssh_workflow_impl(action, 'archlinux', identity=identity)
                call.assert_called_once_with(server.REPO_ROOT, 'archlinux', 'a' * 64)
                self.assertTrue(result['ok'])
                self.assertEqual(result['receiptSha256'], identity['receiptSha256'])
                self.assertFalse(result['replayAllowed'])

    def test_invalid_authority_never_dispatches(self):
        for kwargs in [{}, {'identity': {}}, {'identity': {'receiptSha256': 'bad'}},
                       {'identity': {'receiptSha256': 'a' * 64, 'command': 'x'}},
                       {'identity': {'receiptSha256': 'a' * 64}, 'transfer': {}},
                       {'identity': {'receiptSha256': 'a' * 64}, 'device': 'api29'},
                       {'identity': {'receiptSha256': 'a' * 64}, 'timeout_seconds': True}]:
            for action in ['connection-session-retire', 'connection-session-retirement-status']:
                with self.subTest(action=action, kwargs=kwargs), mock.patch.object(retirement, 'retire') as retire, mock.patch.object(retirement, 'status') as status:
                    self.assertFalse(server._ssh_workflow_impl(action, 'archlinux', **kwargs)['ok'])
                    retire.assert_not_called(); status.assert_not_called()

    def test_untrusted_results_and_errors_are_finite_unknown(self):
        receipt = {'state': 'retired', 'host': 'archlinux', 'receiptSha256': 'a' * 64, 'replayAllowed': False}
        for value in [None, {**receipt, 'host': 'foreign'}, {**receipt, 'receiptSha256': 'b' * 64},
                      {**receipt, 'replayAllowed': True}, {**receipt, 'replayAllowed': 0}, {**receipt, 'private': 'secret'}]:
            with self.subTest(value=value), mock.patch.object(retirement, 'retire', return_value=value):
                result = server._ssh_workflow_impl('connection-session-retire', 'archlinux', identity={'receiptSha256': 'a' * 64})
                self.assertEqual(result['state'], 'unknown')
                self.assertNotIn('secret', str(result))
        with mock.patch.object(retirement, 'retire', side_effect=ValueError('private')):
            result = server._ssh_workflow_impl('connection-session-retire', 'archlinux', identity={'receiptSha256': 'a' * 64})
            self.assertNotIn('private', str(result))

    def test_cli_and_readonly_guidance(self):
        for action in ['connection-session-retire', 'connection-session-retirement-status']:
            with mock.patch.object(server, 'ssh_workflow', return_value={'ok': True}) as call:
                self.assertEqual(server.main(['ssh-workflow', action, '--host', 'archlinux']), 0)
                self.assertEqual(call.call_args.args[0], action)
            result = {'ok': True, 'state': 'retired', 'host': 'archlinux', 'receiptSha256': 'a' * 64, 'replayAllowed': False}
            guidance = next_action('ssh_workflow', action, result)
            self.assertEqual(guidance['action']['action'], 'connection-session-prepare')
            self.assertNotIn('action', next_action('ssh_workflow', action, {**result, 'state': 'unknown'}))

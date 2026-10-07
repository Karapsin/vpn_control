"""Fixed gateway tmux routing exposes no command or credential overrides."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from agent_tools import mcp_server as server
from agent_tools import ssh_gateway_tmux_master_ssh as adapter


class GatewayTmuxRoutes(unittest.TestCase):
    corr = '691bd32a-4ea6-42a6-a3a2-e28b8d3498ec'

    def setUp(self):
        patch = mock.patch.object(server, '_MCP_BOOT_TIME_NS', 2**63-1)
        patch.start(); self.addCleanup(patch.stop)

    def test_fixed_dispatch_and_finite_projection(self):
        for action, method, result in (
            ('gateway-tmux-availability', 'availability', {'available': True, 'reason': 'available', 'nativeActionAllowed': False}),
            ('gateway-tmux-prepare', 'prepare', {'state': 'prepared', 'correlationId': self.corr, 'replayAllowed': False, 'anchorPin': {'generation': [1]*9, 'sha256': 'a'*64}}),
            ('gateway-tmux-release', 'release', {'state': 'released', 'correlationId': self.corr, 'replayAllowed': False}),
            ('gateway-tmux-status', 'status', {'state': 'ready', 'correlationId': self.corr, 'replayAllowed': False, 'readyPin': {'generation': [1]*9, 'sha256': 'a'*64}, 'controlPath': '/private/marker', 'recoveryCorrelationId': self.corr.replace('-', ''), 'adoptionAllowed': False}),
        ):
            identity = None if method == 'availability' else {'correlationId': self.corr}
            with self.subTest(action=action), mock.patch.object(adapter, 'operate', return_value=result) as call:
                value = server._ssh_workflow_impl(action, 'archlinux', identity=identity)
                call.assert_called_once_with(server.REPO_ROOT, method, {} if identity is None else identity)
                self.assertTrue(value['ok'])
                self.assertNotIn('/private/marker', str(value))

    def test_reconciliation_status_fixed_dispatch(self):
        result = {'state': 'adopted', 'replayAllowed': False,
                  'launchAllowed': False, 'adoptionAllowed': False}
        helper = mock.Mock()
        helper.observe.return_value = result
        with mock.patch.object(server, '_agent_module', return_value=helper) as load:
            value = server._ssh_workflow_impl('gateway-tmux-reconciliation-status', 'archlinux')
        load.assert_called_once_with('ssh_gateway_tmux_reconciliation_status')
        helper.observe.assert_called_once_with(server.REPO_ROOT)
        self.assertTrue(value['ok'])
        self.assertEqual('adopted', value['state'])

    def test_reconciliation_status_rejects_overrides_before_load(self):
        for edit in ({'host':'foreign'}, {'identity':{}}, {'transfer':{}},
                     {'device':'api35'}, {'timeout_seconds':True}):
            with self.subTest(edit=edit), mock.patch.object(server, '_agent_module') as load:
                value = server._ssh_workflow_impl('gateway-tmux-reconciliation-status',
                                                  **{'host':'archlinux', **edit})
                self.assertFalse(value['ok'])
                load.assert_not_called()

    def test_reconciliation_status_rejects_private_or_capability_fields(self):
        valid = {'state':'adopted', 'replayAllowed':False,
                 'launchAllowed':False, 'adoptionAllowed':False}
        for edit in ({'private':'secret-marker'}, {'launchAllowed':True},
                     {'adoptionAllowed':0}, {'state':'foreign'}):
            helper = mock.Mock(); helper.observe.return_value = {**valid, **edit}
            with self.subTest(edit=edit), mock.patch.object(server, '_agent_module', return_value=helper):
                value = server._ssh_workflow_impl('gateway-tmux-reconciliation-status', 'archlinux')
                self.assertFalse(value['ok'])
                self.assertNotIn('secret-marker', str(value))

    def test_invalid_inputs_do_not_dispatch(self):
        for edit in ({'host': 'foreign'}, {'identity': {'correlationId': '../foreign'}},
                     {'identity': {'correlationId': self.corr, 'command': 'foreign'}},
                     {'transfer': {}}, {'device': 'api29'}, {'timeout_seconds': True}):
            with self.subTest(edit=edit), mock.patch.object(adapter, 'operate') as call:
                value = server._ssh_workflow_impl('gateway-tmux-prepare', **{'host':'archlinux', 'identity':{'correlationId':self.corr}, **edit})
                self.assertFalse(value['ok']); call.assert_not_called()

    def test_private_or_foreign_output_remains_unknown(self):
        for result in ({'state':'released', 'correlationId':self.corr, 'replayAllowed':False, 'private':'secret-marker'},
                       {'state':'released', 'correlationId':self.corr, 'replayAllowed':0},
                       {'state':'released', 'correlationId':'foreign', 'replayAllowed':False}):
            with mock.patch.object(adapter, 'operate', return_value=result):
                value=server._ssh_workflow_impl('gateway-tmux-release', 'archlinux', identity={'correlationId':self.corr})
                self.assertFalse(value['ok']); self.assertEqual('unknown',value['state'])
                self.assertNotIn('secret-marker',str(value))

    def test_stale_source_rejects_before_operation(self):
        with mock.patch.object(server, '_MCP_BOOT_TIME_NS', 0), mock.patch.object(adapter, 'operate') as call:
            result=server._ssh_workflow_impl('gateway-tmux-prepare','archlinux',identity={'correlationId':self.corr})
            self.assertFalse(result['ok']);call.assert_not_called()

    def test_reconciliation_stale_source_before_observation(self):
        from agent_tools import ssh_gateway_tmux_reconciliation_status as helper
        with mock.patch.object(server, '_MCP_BOOT_TIME_NS', 0), \
                mock.patch.object(helper, 'observe') as call:
            result = server._ssh_workflow_impl('gateway-tmux-reconciliation-status', 'archlinux')
        self.assertFalse(result['ok']); call.assert_not_called()

    def test_reconciliation_cli_from_unrelated_directory(self):
        program = """import importlib.util,json,sys
from pathlib import Path
from unittest import mock
source=Path(sys.argv[1]);sys.path.insert(0,str(source.parent))
spec=importlib.util.spec_from_file_location('reconciliation_cli_server',source)
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
helper=mock.Mock();helper.observe.return_value={'state':'adopted','replayAllowed':False,'launchAllowed':False,'adoptionAllowed':False}
original=s._agent_module
def fixed(name):
 return helper if name=='ssh_gateway_tmux_reconciliation_status' else original(name)
with mock.patch.object(s,'_agent_module',side_effect=fixed) as load:
 code=s.main(['ssh-workflow','gateway-tmux-reconciliation-status','--host','archlinux'])
 assert sum(call.args==('ssh_gateway_tmux_reconciliation_status',) for call in load.call_args_list)==1
 helper.observe.assert_called_once_with(s.REPO_ROOT)
 raise SystemExit(code)
"""
        with tempfile.TemporaryDirectory() as directory:
            p = subprocess.run([sys.executable, '-I', '-c', program,
                                str(Path(server.__file__).resolve())],
                               cwd=directory, capture_output=True, text=True, timeout=30)
        self.assertEqual(0, p.returncode, p.stderr)
        value = json.loads(p.stdout)
        self.assertTrue(value['ok']); self.assertEqual('adopted', value['state'])

    def test_fresh_cli_from_unrelated_directory(self):
        program="""import importlib.util,json,sys
from pathlib import Path
from unittest import mock
source=Path(sys.argv[1]);sys.path.insert(0,str(source.parent))
spec=importlib.util.spec_from_file_location('gateway_cli_server',source)
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
from agent_tools import ssh_gateway_tmux_master_ssh as a
with mock.patch.object(a,'operate',return_value={'available':True,'reason':'available','nativeActionAllowed':False}) as call:
 code=s.main(['ssh-workflow','gateway-tmux-availability','--host','archlinux'])
 assert call.call_count==1
 raise SystemExit(code)
"""
        with tempfile.TemporaryDirectory() as directory:
            p=subprocess.run([sys.executable,'-I','-c',program,str(Path(server.__file__).resolve())],cwd=directory,capture_output=True,text=True,timeout=30)
        self.assertEqual(0,p.returncode,p.stderr);self.assertTrue(json.loads(p.stdout)['ok'])

"""Fresh MCP CLI and package dispatch retain the reviewed finite routes."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from agent_tools import mcp_server as server
from agent_tools import ssh_acceptance_observation_routes as routes


class AcceptanceRouteIntegration(unittest.TestCase):
    def test_public_cli_accepts_fixed_actions(self):
        for action in routes.ACTIONS:
            with self.subTest(action=action), mock.patch.object(server, 'ssh_workflow', return_value={'ok': True}) as call:
                self.assertEqual(server.main(['ssh-workflow', action, '--host', 'archlinux']), 0)
                self.assertEqual(call.call_args.args[0], action)

    def test_package_dispatch_keeps_identity_and_device(self):
        for action in routes.ACTIONS:
            identity = routes.ARCHIVE_IDENTITY if action != 'android-availability' else None
            device = 'api29' if action == 'android-availability' else None
            with self.subTest(action=action), mock.patch.object(routes, 'dispatch', return_value={'ok': False, 'replayAllowed': False}) as call:
                result = server._ssh_workflow_impl(action, 'archlinux', 10, identity, None, device)
                call.assert_called_once_with(server.REPO_ROOT, action, 'archlinux', 10, identity, None, device)
                self.assertFalse(result['replayAllowed'])

    def test_fresh_direct_server_import_dispatches_package_helper(self):
        source = str(Path(server.__file__).resolve())
        program = '''import importlib.util,json,sys
from pathlib import Path
from unittest import mock
source=%r
sys.path.insert(0,str(Path(source).parent))
spec=importlib.util.spec_from_file_location('fresh_acceptance_server',source)
server=importlib.util.module_from_spec(spec);spec.loader.exec_module(server)
from agent_tools import ssh_acceptance_observation_routes as routes
with mock.patch.object(routes,'dispatch',return_value={'ok':True,'replayAllowed':False}) as call:
 result=server._ssh_workflow_impl('android-availability','archlinux',device='api35')
 assert call.call_count==1
 print(json.dumps(result))
''' % source
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, '-I', '-c', program], cwd=directory, capture_output=True, text=True, timeout=15, check=True)
            self.assertEqual(json.loads(result.stdout), {'ok': True, 'replayAllowed': False})

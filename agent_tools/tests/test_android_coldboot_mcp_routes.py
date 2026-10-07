"""Actual MCP/CLI registration for the fixed read-only Android getter."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from agent_tools import mcp_server as server
from agent_tools import android_coldboot_product_routes as routes
from agent_tools import android_api35_large_routing_routes as large_routes

class RegistrationTests(unittest.TestCase):
    def test_registered_api35_route_dispatches_once(self):
        response = {'tool': 'vm_workflow', 'ok': True, 'currentRoutingVerified': True,
                    'productAdmitted': False, 'acceptanceComplete': False}
        with mock.patch.object(large_routes, 'dispatch', return_value=response) as call:
            self.assertEqual(response, server._vm_workflow_impl(large_routes.ACTION, {}))
            call.assert_called_once_with(server.REPO_ROOT, large_routes.ACTION, {})

    def test_registered_route_dispatches_once_without_native_replay(self):
        response = {'tool': 'vm_workflow', 'ok': True, 'state': 'current-product-getters-admitted', 'replayAllowed': False, 'acceptanceComplete': False}
        with mock.patch.object(routes, 'dispatch', return_value=response) as call:
            self.assertEqual(response, server._vm_workflow_impl(routes.ACTION, {}))
            call.assert_called_once_with(server.REPO_ROOT, routes.ACTION, {})

    def test_cli_exposes_the_fixed_action(self):
        with tempfile.TemporaryDirectory() as tmp:
            request = Path(tmp) / 'request.json'
            request.write_text(json.dumps({}))
            for action in (routes.ACTION, large_routes.ACTION):
                with self.subTest(action=action), mock.patch.object(server, 'vm_workflow', return_value={'ok': True}) as call:
                    self.assertEqual(0, server.main(['vm-workflow', action, '--inputs-file', str(request)]))
                    call.assert_called_once_with(action, {})

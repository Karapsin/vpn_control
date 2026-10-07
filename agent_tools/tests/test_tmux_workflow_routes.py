"""MCP registration and strict inputs for the fixed tmux workflows."""
import unittest
import tempfile
from pathlib import Path
from unittest import mock
from agent_tools import mcp_server as server
from agent_tools import tmux_workflow_routes as routes


class TmuxRoutes(unittest.TestCase):
    def test_registered_mcp_adapter_dispatches_availability(self):
        with mock.patch.object(routes.adapter, 'operate', return_value={'available': True, 'reason': 'available', 'nativeActionAllowed': False}) as call:
            result = server._vm_workflow_impl('linux-package-tmux-availability', {})
            self.assertTrue(result['ok'], result)
            call.assert_called_once_with(server.REPO_ROOT, 'availability', {}, source_root=None)

    def test_cli_recognises_only_fixed_tmux_actions(self):
        with tempfile.TemporaryDirectory() as directory:
            request = Path(directory) / 'request.json'
            request.write_text('{}')
            for action in routes.ACTIONS:
                with self.subTest(action=action), mock.patch.object(server, 'vm_workflow', return_value={'ok': True}) as call:
                    self.assertEqual(server.main(['vm-workflow', action, '--inputs-file', str(request)]), 0)
                    self.assertEqual(call.call_args.args[0], action)

    def test_invalid_installer_inputs_do_not_read_credentials_or_dispatch(self):
        request = {'host': 'archlinux', 'correlationId': '209dd37d-1a74-404e-bab2-d0ecc597782e', 'sourceSha': 'd32f719a08db57e5d40ce2bf77e0d7c5b42de557'}
        for request in [{}, {**request, 'host': 'foreign'}, {**request, 'package': 'anything'}, {**request, 'timeoutSeconds': True}]:
            with self.subTest(request=request), mock.patch.object(routes.installer, 'start') as call:
                self.assertFalse(routes.dispatch(server.REPO_ROOT, 'arch-tmux-install-start', request)['ok'])
                call.assert_not_called()

    def test_observation_cannot_supply_a_source_path(self):
        for action in ('availability', 'status', 'collect'):
            with self.subTest(action=action), mock.patch.object(routes.adapter, 'operate') as call:
                self.assertFalse(routes.dispatch(server.REPO_ROOT, 'linux-package-tmux-' + action, {'sourceRoot': None})['ok'])
                call.assert_not_called()

    def test_unknown_start_does_not_retry_or_expose_private_exception(self):
        with mock.patch.object(routes.adapter, 'operate', side_effect=ValueError('private credential')) as call:
            result = routes.dispatch(server.REPO_ROOT, 'linux-package-tmux-availability', {})
            self.assertFalse(result['replayAllowed']); self.assertFalse(result['ok'])
            self.assertNotIn('credential', str(result)); self.assertEqual(call.call_count, 1)

    def test_forged_available_reply_never_exposes_private_data(self):
        with mock.patch.object(routes.adapter, 'operate', return_value={'available': True, 'private': 'secret-fixture-marker', 'command': 'unexpected'}):
            result = routes.dispatch(server.REPO_ROOT, 'linux-package-tmux-availability', {})
            self.assertFalse(result['ok'])
            self.assertNotIn('secret-fixture-marker', str(result))
            self.assertNotIn('command', result)

    def test_registered_status_dispatches_original_job_once(self):
        request = {'correlationId': '86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0'}
        reply = {'state': 'ready', **request, 'sourceSha': 'd32f719a08db57e5d40ce2bf77e0d7c5b42de557', 'replayAllowed': False}
        with mock.patch.object(routes.adapter, 'operate', return_value=reply) as call:
            result = server._vm_workflow_impl('linux-package-tmux-status', request)
            self.assertTrue(result['ok'], result)
            call.assert_called_once_with(server.REPO_ROOT, 'status', request, source_root=None)

    def test_invalid_build_request_never_reaches_native_adapter(self):
        requests = [('start', {}), ('start', {'command': 'anything'}),
                    ('status', {'correlationId': True}), ('collect', {'correlationId': 'invalid'}),
                    ('availability', {'correlationId': '86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0'})]
        for operation, request in requests:
            with self.subTest(operation=operation, request=request), mock.patch.object(routes.adapter, 'operate') as call:
                self.assertFalse(routes.dispatch(server.REPO_ROOT, 'linux-package-tmux-' + operation, request)['ok'])
                call.assert_not_called()

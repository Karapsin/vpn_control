import contextlib
import copy
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from agent_tools import mcp_server as server
from agent_tools import android_api35_remaining_proxy_status_routes as route


class RemainingProxyStatusMcpTests(unittest.TestCase):
    def setUp(self):
        patch = mock.patch.object(server, '_MCP_BOOT_TIME_NS', 2**63-1)
        patch.start()
        self.addCleanup(patch.stop)

    def output(self):
        return {'tool': 'vm_workflow', 'ok': True, 'state': 'remaining-proxy-restored',
                'reason': 'observed', 'productAdmitted': False, 'acceptanceComplete': False,
                'replayAllowed': False, 'receiptSha256': 'a'*64, 'receiptBytes': 191979,
                'controllerId': '58d546ea-8208-40a3-bba4-e8759768284e',
                'configurationRevision': 0, 'runtimeOff': True, 'fourProxyRowsAbsent': True,
                'exclusionEmpty': True, 'binderProxyClear': True,
                'originalOperationOutcome': 'unknown', 'historicalUnknownsPreserved': True,
                'recordCount': 4}

    def test_registered_actual_dispatch(self):
        with mock.patch.object(route, 'dispatch', return_value=self.output()) as dispatch:
            result = server._vm_workflow_impl(route.ACTION, {})
        self.assertTrue(result['ok'])
        dispatch.assert_called_once_with(server.REPO_ROOT, route.ACTION, {})
        self.assertFalse(result['productAction'])

    def test_nonempty_request_has_no_dispatch(self):
        with mock.patch.object(route, 'dispatch') as dispatch:
            result = server._vm_workflow_impl(route.ACTION, {'correlationId': 'foreign'})
        self.assertFalse(result['ok'])
        dispatch.assert_not_called()

    def test_forged_projection_never_grants_authority(self):
        cases = [{'privateKey': 'private-marker'}, {'receiptBytes': True},
                 {'configurationRevision': True}, {'recordCount': 3},
                 {'receiptSha256': 'bad'}, {'controllerId': 'bad'},
                 {'runtimeOff': False}, {'acceptanceComplete': True}, {'replayAllowed': True}]
        for change in cases:
            with self.subTest(change=change), mock.patch.object(route, 'dispatch', return_value={**self.output(), **change}):
                result = server._vm_workflow_impl(route.ACTION, {})
                self.assertFalse(result['ok'])
                self.assertNotIn('private-marker', str(result))

    def test_failure_does_not_forward_private_exception(self):
        with mock.patch.object(route, 'dispatch', side_effect=ValueError('private-marker')):
            result = server._vm_workflow_impl(route.ACTION, {})
        self.assertFalse(result['ok'])
        self.assertNotIn('private-marker', str(result))

    def test_actual_cli_catalogue(self):
        with tempfile.TemporaryDirectory() as directory:
            request = Path(directory)/'request.json'
            request.write_text('{}')
            with mock.patch.object(server, 'vm_workflow', return_value={'ok': True}) as dispatch, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, server.main(['vm-workflow', route.ACTION, '--inputs-file', str(request)]))
        dispatch.assert_called_once_with(route.ACTION, {})

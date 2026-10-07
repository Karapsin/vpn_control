"""MCP integration preserves the actual fixed source-campaign action semantics."""
import unittest
from unittest import mock
from agent_tools import mcp_server as server

LEASE = 'f18df6cb-2c43-4265-b1ba-4bbadf9b708a'

class SourceCampaignRouteTests(unittest.TestCase):
    def test_submitted_install_is_successful_and_remains_a_product_action(self):
        module = mock.Mock()
        module.workflow.return_value = {'state':'submitted','correlationId':LEASE,
            'replayAllowed':False,'nativeActionAllowed':False,'productAction':True}
        with mock.patch.object(server, '_agent_module', return_value=module):
            result=server._vm_workflow_impl('windows-cp117-source-campaign-start', {'host':'archlinux','leaseId':LEASE})
        self.assertTrue(result['ok'])
        self.assertTrue(result['productAction'])
        self.assertFalse(result['replayAllowed'])
        module.workflow.assert_called_once_with(server.REPO_ROOT,'start',{'host':'archlinux','leaseId':LEASE})

    def test_finish_projects_actual_active_lease_result(self):
        module=mock.Mock()
        module.workflow.return_value={'state':'active','leaseId':LEASE,'replayAllowed':False}
        with mock.patch.object(server,'_agent_module',return_value=module):
            result=server._vm_workflow_impl('windows-cp117-source-campaign-finish', {'host':'archlinux','leaseId':LEASE})
        self.assertTrue(result['ok'])
        self.assertFalse(result['productAction'])

    def test_unexpected_private_output_is_rejected(self):
        module=mock.Mock()
        module.workflow.return_value={'state':'submitted','correlationId':LEASE,
            'replayAllowed':False,'nativeActionAllowed':False,'productAction':True,'privatePath':'secret'}
        with mock.patch.object(server,'_agent_module',return_value=module):
            result=server._vm_workflow_impl('windows-cp117-source-campaign-start', {'host':'archlinux','leaseId':LEASE})
        self.assertFalse(result['ok'])
        self.assertNotIn('privatePath',result)

class RecoverySuccessorRouteTests(unittest.TestCase):
    def test_fixed_successor_route_preserves_no_replay_and_rejects_private_data(self):
        for private in ({}, {'privatePath':'secret'}):
            module=mock.Mock();module._RECOVERY='c2c0e5c9-77aa-4bd2-91a1-fb7540aa9f58'
            module.workflow.return_value={'state':'submitted','recoveryCorrelationId':module._RECOVERY,
                'replayAllowed':False,'nativeActionAllowed':False,'productAction':False,**private}
            with mock.patch.object(server,'_agent_module',return_value=module):
                result=server._vm_workflow_impl('windows-cp117-guest-agent-recovery-successor-start',{})
            self.assertEqual(not bool(private),result['ok'])
            self.assertFalse(result['replayAllowed'])
            self.assertNotIn('privatePath',result)
            module.workflow.assert_called_once_with(server.REPO_ROOT,'start',{})

    def test_successor_rejects_inputs_before_dispatch(self):
        with mock.patch.object(server,'_agent_module') as loader:
            result=server._vm_workflow_impl('windows-cp117-guest-agent-recovery-successor-start',{'retry':True})
        self.assertFalse(result['ok']);loader.assert_not_called()

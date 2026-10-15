"""Current retirement and retained source-campaign projection boundaries."""
import unittest
from pathlib import Path
from unittest import mock
from agent_tools import mcp_server as server
from agent_tools import windows_cp117_source_projection as projection

LEASE = 'f18df6cb-2c43-4265-b1ba-4bbadf9b708a'

class HistoricalSourceReadSeamTests(unittest.TestCase):
    def test_only_two_exact_public_labels_map_to_checkout_sources(self):
        from agent_tools import windows_cp117_bound_absence_completion as binding
        from agent_tools import windows_fixture_credentials, windows_update_fixture_server
        from agent_tools.tests.fixtures.windows_cp117_historical_factory.context import inert_repository_source_reads
        historical=Path('/Users/karapsin_de/Nextcloud/projects/vpn_control/agent_tools')
        with mock.patch.object(binding,'_read_bound_file',return_value='PUBLIC_PIN') as reader:
            with inert_repository_source_reads():
                for module in (windows_fixture_credentials,windows_update_fixture_server):
                    actual=Path(module.__file__).resolve();label=historical/actual.name
                    for path,private,expected in ((label,False,actual),(label,True,label),
                            (Path('/unrelated/agent_tools')/actual.name,False,Path('/unrelated/agent_tools')/actual.name)):
                        with self.subTest(path=path,private=private):
                            self.assertEqual(binding._read_bound_file(path,private=private,retain_bytes=True),'PUBLIC_PIN')
                            reader.assert_called_with(expected,private=private,retain_bytes=True)

class SourceCampaignRouteTests(unittest.TestCase):
    def test_retired_start_is_refused_before_dispatch(self):
        with mock.patch.object(server, '_vm_workflow_impl') as dispatch:
            result=server.vm_workflow('windows-cp117-source-campaign-start',
                                      {'host':'archlinux','leaseId':LEASE})
        self.assertFalse(result['ok'])
        self.assertEqual(result['reason'],'historical_windows_profile_retired')
        self.assertFalse(result['productAction'])
        self.assertFalse(result['replayAllowed'])
        dispatch.assert_not_called()

    def test_historical_submitted_projection_remains_a_product_action(self):
        # Projection of a retained response does not authorize a new submission.
        result=projection.project('start',{'state':'submitted','correlationId':LEASE,
            'replayAllowed':False,'nativeActionAllowed':False,'productAction':True}
        )
        self.assertTrue(result['ok'])
        self.assertTrue(result['productAction'])
        self.assertFalse(result['replayAllowed'])

    def test_finish_projects_actual_active_lease_result(self):
        module=mock.Mock()
        module._LEASE_ID=LEASE
        module.workflow.return_value={'state':'active','leaseId':LEASE,'replayAllowed':False}
        adapters={'windows_cp117_source_campaign':module,
                  'windows_cp117_source_projection':projection}
        with mock.patch.object(server,'_agent_module',side_effect=adapters.__getitem__):
            result=server._vm_workflow_impl('windows-cp117-source-campaign-finish', {'host':'archlinux','leaseId':LEASE})
        self.assertTrue(result['ok'])
        self.assertFalse(result['productAction'])
        self.assertFalse(result['replayAllowed'])
        module.workflow.assert_called_once_with(server.REPO_ROOT,'finish',{'host':'archlinux','leaseId':LEASE})

    def test_unexpected_private_output_is_rejected(self):
        result=projection.project('start',{'state':'submitted','correlationId':LEASE,
            'replayAllowed':False,'nativeActionAllowed':False,'productAction':True,'privatePath':'secret'}
        )
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

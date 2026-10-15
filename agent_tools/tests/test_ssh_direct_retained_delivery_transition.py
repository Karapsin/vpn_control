"""Exact reviewed MCP delivery edge; actual provider/journals, inert transport.

Original native badc terminal/READY evidence is retained separately. These local
controls prove admission/refusal decisions, not new native connection acceptance.
"""
import hashlib,os,subprocess,unittest
from unittest import mock
from agent_tools import ssh_direct_nested_channel as direct
from agent_tools.tests import test_ssh_direct_retained_wrapper_transition as prior
from agent_tools.tests import test_ssh_direct_ended_source_transition as history

PROVIDER_BEFORE=history.historical('ssh_fresh_nested_channel.delivery-before.py.gz','acdccf42ac5794d6809664fa933bb50377549a4c000ecebc457bb3528eb83c2a')
MCP_DELIVERY=history.historical('mcp_server.delivery-reviewed.py.gz','f2270ebb2cfd63066d84807b67b1d577b0acd1e90852ac397cf4f05d53c06f9c')

class RetainedDeliveryTransitionTests(prior.RetainedWrapperTransitionTests):
    def setUp(self):
        self.f=history.ProviderEndedHistoryTests('runTest');self.f.setUp();self.addCleanup(self.f.doCleanups)
        f=self.f;f.provider_path.write_bytes(PROVIDER_BEFORE);(f.source/'mcp_server.py').write_bytes(prior.MCP_WRAPPER)
        f.module=f.load();f.seed();f.transition(mcp_body=MCP_DELIVERY)
    def test_unobserved_predecessor_mcp_combination_refuses(self):
        self.f.mutate_intent(lambda v:v['directSourcePins'].__setitem__('mcp_server.py',hashlib.sha256(history.MCP_CHECKPOINT74).hexdigest()));self.refuse()
        # The current unreviewed provider cannot declare itself a predecessor
        # for a changed MCP merely because its selfhash is currently loaded.
        g=history.ProviderEndedHistoryTests('runTest');g.setUp();self.addCleanup(g.doCleanups)
        g.provider_path.write_bytes(history.CURRENT_PROVIDER_SOURCE.read_bytes());(g.source/'mcp_server.py').write_bytes(prior.MCP_WRAPPER)
        g.module=g.load();g.seed();g.transition(mcp_body=MCP_DELIVERY);g.refuse()
    def test_current_delivery_mcp_other_byte_refuses(self):
        p=self.f.source/'mcp_server.py';p.write_bytes(MCP_DELIVERY+b'\n# unreviewed next delivery\n');self.refuse()
    def test_new_connection_has_actual_working_direct_route_only(self):
        f=self.f;value=f.invoke(corr=f.new);self.assertEqual('ready',value['state'])
        before=len(f.calls);fds=len(os.listdir('/dev/fd'))
        with mock.patch.object(f.owner,'expected_remote',f.module._REMOTE),mock.patch.object(subprocess,'Popen',side_effect=f.owner.consumer):
            route=direct.route_options(f.root,'archlinux',f.new,value['receiptSha256'])
        self.assertEqual(f.new,route['correlationId']);self.assertEqual(value['receiptSha256'],route['receiptSha256'])
        self.assertEqual(('-S','/tmp/vpn-channel-'+f.new+'/m','-o','ControlMaster=no','-o','ControlPersist=no','-o','ProxyCommand=false'),route['innerOptions'])
        self.assertEqual(before+1,len(f.calls));self.assertEqual(['prepare','status','prepare','status'],[c[6]for c in f.calls])
        self.assertEqual(fds,len(os.listdir('/dev/fd')));self.unchanged()
    def test_original_provider_same_delivery_mcp_ended_history_remains_admitted(self):
        f=self.f
        # A separate owned fixture seeds the actual predecessor under the exact
        # delivery image, then transitions only its provider self-source.
        g=history.ProviderEndedHistoryTests('runTest');g.setUp();self.addCleanup(g.doCleanups)
        g.provider_path.write_bytes(PROVIDER_BEFORE);(g.source/'mcp_server.py').write_bytes(MCP_DELIVERY)
        g.module=g.load();g.seed();g.transition(mcp_body=MCP_DELIVERY)
        self.assertEqual('ready',g.invoke(corr=g.new)['state'])
        self.assertEqual(g.before,{name:(g.journal/(g.corr+'.'+name+'.json')).read_bytes()for name in g.before})

class ReviewedDeliveryHistoryPopulationTests(prior.ReviewedWrapperHistoryPopulationTests):
    def admit(self,kind):
        f=history.Checkpoint74EndedPopulationTests('runTest');f.setUp();self.addCleanup(f.doCleanups)
        f.seed_original(kind);f.transition(mcp=MCP_DELIVERY)
        self.assertEqual('ready',f.f.invoke(corr=f.f.new)['state'])
        self.assertEqual(f.f.before,{name:(f.f.journal/(f.f.corr+'.'+name+'.json')).read_bytes()for name in f.f.before})
        self.assertEqual(['prepare','status','prepare'],[c[6]for c in f.f.calls]);f.f.assert_legacy_unchanged()
    def test_dcb_reviewed_wrapper_to_delivery_preserves_original_history(self):
        f=prior.RetainedWrapperTransitionTests('runTest');f.setUp();self.addCleanup(f.doCleanups)
        f.f.transition(mcp_body=MCP_DELIVERY);before=len(f.f.calls)
        self.assertEqual('ended',f.observe()['state']);self.assertEqual(before,len(f.f.calls));f.unchanged()
        self.assertEqual('ready',f.f.invoke(corr=f.f.new)['state']);f.unchanged()
        self.assertEqual(['prepare','status','prepare'],[c[6]for c in f.f.calls])

"""Actual provider/route refusal conversion; no native SSH or real inventory.

TempFS provider seeding uses the existing inert remote-reply seam. Source
reproduction proves the constructor defect; the original Android exception
text was not retained and its masked cause remains unproved.
"""
import json,subprocess,unittest,uuid
from unittest import mock
from agent_tools import ssh_direct_nested_channel as direct
from agent_tools.tests import test_ssh_direct_nested_channel as fixtures
if fixtures.COORDINATOR_CAPABLE:
    from agent_tools import ssh_fresh_nested_channel as channel,mcp_server

REASONS=('outer_prompt_unavailable','credential_unavailable','intent_absent','intent_binding_changed')

@unittest.skipUnless(fixtures.COORDINATOR_CAPABLE,'POSIX protected local provider required')
class ActualDirectRouteLocalReasonTests(unittest.TestCase):
    def setUp(self):
        from agent_tools.tests.route_adapter import bind_cached_routes
        from agent_tools import mcp_server as _route_server
        bind_cached_routes(self,_route_server,
            'ssh_direct_nested_channel',
            'ssh_fresh_nested_channel',
        )
        self.f=fixtures.DirectChannelTests('runTest');self.f.setUp();self.addCleanup(self.f.doCleanups)
    def route(self,receipt='a'*64):
        f=self.f
        with mock.patch.object(subprocess,'Popen',side_effect=f.consumer):
            return direct.route_options(f.root,'archlinux',f.corr,receipt)
    def refusal(self,reason,receipt='a'*64):
        f=self.f;before=len(f.calls)
        with self.assertRaises(ValueError) as caught:self.route(receipt)
        self.assertIsInstance(caught.exception,channel.ChannelUnknown)
        value=caught.exception.result
        self.assertEqual({'state':'unknown','nativeActionAllowed':False,'replayAllowed':False,'correlationId':f.corr,'reason':reason},value)
        self.assertEqual(before,len(f.calls));f.assert_legacy_unchanged()
        self.assertEqual('channel_unknown',str(caught.exception));return value
    def test_actual_inventory_drift_preserves_provider_reason_through_route_and_mcp(self):
        f=self.f;ready=f.invoke();self.assertEqual('ready',ready['state'])
        before=(f.root/'.rag_index/ssh-direct-nested-channel/hosts/archlinux'/(f.corr+'.intent.json')).read_bytes()
        f.f.f.config['hosts']['archlinux']['password']='inert changed credential';f.f.f.write_config()
        self.refusal('intent_binding_changed',ready['receiptSha256'])
        self.assertEqual(before,(f.root/'.rag_index/ssh-direct-nested-channel/hosts/archlinux'/(f.corr+'.intent.json')).read_bytes())
        count=len(f.calls)
        with mock.patch.object(mcp_server,'REPO_ROOT',f.root),mock.patch.object(subprocess,'Popen',side_effect=f.consumer):
            value=mcp_server._ssh_workflow_impl('connection-direct-channel-status','archlinux',identity={'correlationId':str(uuid.UUID(f.corr))})
        self.assertFalse(value['ok']);self.assertEqual('intent_binding_changed',value['reason']);self.assertEqual('unknown',value['state'])
        self.assertFalse(value['nativeActionAllowed']);self.assertFalse(value['replayAllowed']);self.assertEqual(count,len(f.calls))
    def test_actual_absent_intent_preserves_local_reason_without_child(self):
        f=self.f;j=channel._journal(f.root,True,direct=True,host='archlinux')
        self.refusal('intent_absent')
        self.assertEqual([],list(j.iterdir()))
    def test_actual_gateway_prompt_refusal_preserves_local_reason_without_child(self):
        f=self.f;gateway=f.f.f.config['hosts']['archlinux']['gateway'];f.f.f.config['hosts'][gateway]['password']='inert gateway credential';f.f.f.write_config()
        self.refusal('outer_prompt_unavailable')
    def test_actual_ready_route_retains_exact_options_and_no_new_prepare(self):
        f=self.f;ready=f.invoke();route=self.route(ready['receiptSha256'])
        self.assertEqual('direct',route['transportMode']);self.assertEqual(f.corr,route['correlationId']);self.assertEqual(ready['receiptSha256'],route['receiptSha256'])
        self.assertEqual(direct.OUTER_OPTIONS,route['outerOptions'])
        self.assertEqual(('-S','/tmp/vpn-channel-'+f.corr+'/m','-o','ControlMaster=no','-o','ControlPersist=no','-o','ProxyCommand=false'),route['innerOptions'])
        self.assertEqual(['prepare','status'],[c[6]for c in f.calls]);f.assert_legacy_unchanged()

    def test_preserved_missing_terminal_beforeimage_and_fixed_refusal_keep_original_unknown(self):
        import hashlib
        from pathlib import Path
        folder=Path(__file__).parent/'fixtures/channel_terminal_absence'
        raw=(folder/'before.source').read_bytes()
        provenance=json.loads((folder/'provenance.json').read_bytes())
        self.assertEqual(provenance['fragmentSha256'],hashlib.sha256(raw).hexdigest())
        namespace=dict(channel.__dict__)
        exec(compile(raw,str(folder/'before.source'),'exec'),namespace)
        before=namespace['_retained_v2_terminal']
        for implementation,fixed in ((before,False),(channel._retained_v2_terminal,True)):
            with self.subTest(fixed=fixed):
                f=fixtures.DirectChannelTests('runTest');f.setUp()
                try:
                    with mock.patch.object(channel,'_retained_v2_terminal',implementation):
                        self.assertEqual('ready',f.invoke()['state'])
                        original=f.root/'.rag_index/ssh-direct-nested-channel/hosts/archlinux'/(f.corr+'.intent.json')
                        retained=original.read_bytes();count=len(f.calls)
                        f.f.f.config['hosts']['archlinux']['password']='inert changed credential';f.f.f.write_config()
                        value=f.invoke('status')
                    self.assertEqual('unknown',value['state'])
                    self.assertEqual('intent_binding_changed' if fixed else None,value.get('reason'))
                    self.assertEqual(count,len(f.calls));self.assertEqual(retained,original.read_bytes())
                    self.assertFalse((original.parent/(f.corr+'.terminal.json')).exists())
                finally:f.doCleanups()

@unittest.skipUnless(fixtures.COORDINATOR_CAPABLE,'POSIX direct route dependencies required')
class ClosedReasonDtoControls(unittest.TestCase):
    def base(self):return {'state':'unknown','nativeActionAllowed':False,'replayAllowed':False,'correlationId':'a'*32}
    def route(self,value):
        with mock.patch.object(direct,'status',return_value=value):
            return direct.route_options('/unopened-fixture-root','archlinux','a'*32,'b'*64)
    def admit(self,reason):
        value={**self.base(),'reason':reason}
        with self.assertRaises(ValueError)as caught:self.route(value)
        self.assertIsInstance(caught.exception,channel.ChannelUnknown)
        self.assertEqual(value,caught.exception.result)
        result=caught.exception.result;result['reason']='inert mutation';self.assertEqual(reason,caught.exception.result['reason'])
    def refuse(self,changes):
        with self.assertRaisesRegex(ValueError,'^receipt$' if changes.get('state')=='ready' else '^unknown_dto$')as caught:self.route({**self.base(),'reason':'intent_absent',**changes})
        self.assertNotIsInstance(caught.exception,channel.ChannelUnknown)
    def test_ordinary_unknown_without_local_reason_retains_route_exception(self):
        value=self.base()
        with self.assertRaises(channel.ChannelUnknown)as caught:self.route(value)
        self.assertEqual(value,caught.exception.result)
    def test_ordinary_remote_diagnostic_without_reason_retains_route_exception(self):
        value={**self.base(),'failurePhase':'master_snapshot','failureReason':'socket','exceptionClass':'ValueError','errno':None}
        with self.assertRaises(channel.ChannelUnknown)as caught:self.route(value)
        self.assertEqual(value,caught.exception.result)

for reason in REASONS:
    def test(self,reason=reason):self.admit(reason)
    setattr(ClosedReasonDtoControls,'test_admits_only_bounded_'+reason,test)

INVALID={
 'private_text':{'reason':'inert private credential/path sentinel'},
 'unknown_text':{'reason':'unreviewed_local_reason'},
 'empty_text':{'reason':''},
 'null':{'reason':None},
 'boolean':{'reason':True},
 'list':{'reason':['intent_absent']},
 'mapping':{'reason':{'intent_absent':True}},
 'unexpected_field':{'privateRoute':'inert private route sentinel'},
 'wrong_state':{'state':'ready'},
 'native_action':{'nativeActionAllowed':True},
 'application_replay':{'replayAllowed':True},
 'malformed_remote_tuple':{'failurePhase':'master_snapshot','failureReason':'socket'},
}
for name,changes in INVALID.items():
    def test(self,changes=changes):self.refuse(changes)
    setattr(ClosedReasonDtoControls,'test_refuses_'+name,test)

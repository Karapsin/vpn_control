"""Fixed session routes expose no arbitrary remote operation."""
import unittest
from unittest import mock
from agent_tools import mcp_server as server, ssh_transport as transport
from agent_tools import ssh_connection_session as session


class SessionRoutes(unittest.TestCase):
    def test_prepare_dispatches_fixed_helper(self):
        receipt = {'state':'ready','host':'archlinux','receiptSha256':'a'*64,'created':False}
        with mock.patch.object(transport,'_session_module',return_value=session), mock.patch.object(session,'prepare',return_value=receipt) as call:
            result=server._ssh_workflow_impl('connection-session-prepare','archlinux')
        call.assert_called_once_with(server.REPO_ROOT,'archlinux')
        self.assertTrue(result['ok'])
        self.assertIs(result['replayAllowed'],False)

    def test_status_uses_only_existing_receipt(self):
        receipt={'state':'ready','host':'archlinux','receiptSha256':'a'*64}
        with mock.patch.object(transport,'_session_module',return_value=session), mock.patch.object(session,'admission',return_value=receipt) as call:
            result=server._ssh_workflow_impl('connection-session-status','archlinux',identity={'receiptSha256':'a'*64})
        call.assert_called_once_with(server.REPO_ROOT,'archlinux','a'*64)
        self.assertTrue(result['ok'])

    def test_invalid_inputs_never_dispatch(self):
        cases=[('connection-session-prepare',{'identity':{}}),
               ('connection-session-status',{}),
               ('connection-session-status',{'identity':{'receiptSha256':'bad'}}),
               ('connection-session-status',{'identity':{'receiptSha256':'a'*64,'command':'bad'}}),
               ('connection-session-prepare',{'timeout_seconds':True}),
               ('connection-session-prepare',{'transfer':{}}),
               ('connection-session-prepare',{'device':'api29'})]
        for action,kwargs in cases:
            with self.subTest(action=action,kwargs=kwargs), mock.patch.object(transport,'_session_module') as call:
                self.assertFalse(server._ssh_workflow_impl(action,'archlinux',**kwargs)['ok'])
                call.assert_not_called()

    def test_untrusted_receipts_and_exception_stay_finite_unknown(self):
        for value in (None, {'state':'ready','host':'foreign','receiptSha256':'a'*64,'created':True},
                      {'state':'ready','host':'archlinux','receiptSha256':'a'*64,'created':0},
                      {'state':'ready','host':'archlinux','receiptSha256':'a'*64,'created':True,'raw':'private'}):
            with self.subTest(value=value), mock.patch.object(transport,'_session_module',return_value=session), mock.patch.object(session,'prepare',return_value=value):
                result=server._ssh_workflow_impl('connection-session-prepare','archlinux')
                self.assertEqual(result['state'],'unknown')
                self.assertNotIn('raw',result)
        with mock.patch.object(transport,'_session_module',side_effect=ValueError('private')):
            result=server._ssh_workflow_impl('connection-session-prepare','archlinux')
        self.assertNotIn('private',str(result))

    def test_cli_exposes_fixed_routes(self):
        for action in ('connection-session-prepare','connection-session-status'):
            with self.subTest(action=action), mock.patch.object(server,'ssh_workflow',return_value={'ok':True}) as call:
                self.assertEqual(server.main(['ssh-workflow',action,'--host','archlinux']),0)
                self.assertEqual(call.call_args.args[0],action)

    def test_guidance_only_offers_readonly_receipt_status_then_probe(self):
        from agent_tools.native_next_action import next_action
        receipt={'ok':True,'state':'ready','host':'archlinux','receiptSha256':'a'*64,'replayAllowed':False}
        guidance=next_action('ssh_workflow','connection-session-prepare',receipt)
        self.assertEqual(guidance['action'],{'tool':'ssh_workflow','action':'connection-session-status',
                                           'args':{'host':'archlinux','identity':{'receiptSha256':'a'*64}}})
        self.assertEqual(next_action('ssh_workflow','connection-session-status',receipt)['action']['action'],'probe')
        for changes in ({'ok':False},{'state':'unknown'},{'receiptSha256':'bad'},{'replayAllowed':True}):
            self.assertNotIn('action',next_action('ssh_workflow','connection-session-prepare',{**receipt,**changes}))

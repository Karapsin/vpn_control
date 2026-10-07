import unittest
import os
from unittest import mock
from pathlib import Path
from agent_tools import tmux_workflow_routes as routes
from agent_tools import ssh_tmux_resource_admission as resource
from agent_tools import mcp_server as server
REQUEST={'sourceSha':'d32f719a08db57e5d40ce2bf77e0d7c5b42de557','baseVersion':'2.1.19','targetVersion':'2.2.2','correlationId':'d93cd8dd-a62f-480a-abd8-478be5cc1d21'}
class ResourceRoutes(unittest.TestCase):
 def test_registered_start_must_use_resource_bridge(self):
  with mock.patch.object(resource,'operate',side_effect=ValueError('missing binding')) as gated,mock.patch.object(routes.adapter,'operate') as old:
   result=server._vm_workflow_impl('linux-package-tmux-start',REQUEST)
   self.assertFalse(result['ok']);gated.assert_called_once();old.assert_not_called()
 def test_resource_prepare_registration_required(self):
  self.assertIn('linux-package-tmux-resource-prepare',routes.ACTIONS)
 def test_registered_preflight_uses_resource_bridge(self):
  with mock.patch.object(resource,'operate',side_effect=ValueError('missing binding')) as gated,mock.patch.object(routes.adapter,'operate') as old:
   result=server._vm_workflow_impl('linux-package-tmux-preflight',REQUEST)
   self.assertFalse(result['ok']);gated.assert_called_once();old.assert_not_called()
 def test_invalid_inputs_reject_before_private_lookup_or_native_prepare(self):
  full={**REQUEST,'sourceRoot':str(Path.cwd())}
  for request in ({},REQUEST,{**full,'token':'private-token'},{**full,'reservationId':'env-any'},{**full,'host':'foreign'},{**full,'sourceRoot':'relative'},{**full,'correlationId':False}):
   with self.subTest(request=request),mock.patch.object(routes,'_protected_identity') as lookup,mock.patch.object(resource,'prepare') as native,mock.patch.object(resource.build,'preflight') as check:
    self.assertFalse(routes.dispatch(Path.cwd(),'linux-package-tmux-resource-prepare',request)['ok']);lookup.assert_not_called();native.assert_not_called();check.assert_not_called()
 def test_prepare_finite_output_and_no_token_projection(self):
  request={**REQUEST,'sourceRoot':str(Path.cwd())};identity={'token':'secret-token'}
  with mock.patch.object(resource.build,'preflight'),mock.patch.object(routes,'_protected_identity',return_value=identity),mock.patch.object(resource,'prepare',return_value={'state':'ready','correlationId':REQUEST['correlationId'],'resourceBound':True,'nativeActionAllowed':False}) as call:
   result=routes.dispatch(Path.cwd(),'linux-package-tmux-resource-prepare',request);self.assertTrue(result['ok']);self.assertNotIn('secret-token',str(result));call.assert_called_once_with(Path.cwd(),REQUEST,identity,source_root=str(Path.cwd()))
 def test_forged_prepare_reply_rejects_private_and_untyped_booleans(self):
  reply={'state':'ready','correlationId':REQUEST['correlationId'],'resourceBound':True,'nativeActionAllowed':False}
  for extra in ({'token':'secret-token'},{'resourceBound':1},{'nativeActionAllowed':0},{'correlationId':'foreign'}):
   with mock.patch.object(resource.build,'preflight'),mock.patch.object(routes,'_protected_identity',return_value={}),mock.patch.object(resource,'prepare',return_value={**reply,**extra}):
    result=routes.dispatch(Path.cwd(),'linux-package-tmux-resource-prepare',{**REQUEST,'sourceRoot':str(Path.cwd())});self.assertFalse(result['ok']);self.assertNotIn('secret-token',str(result))
 def test_source_failure_precedes_private_registry_read(self):
  with mock.patch.object(resource.build,'preflight',side_effect=ValueError('dirty source')),mock.patch.object(routes,'_protected_identity') as lookup:
   self.assertFalse(routes.dispatch(Path.cwd(),'linux-package-tmux-resource-prepare',{**REQUEST,'sourceRoot':str(Path.cwd())})['ok']);lookup.assert_not_called()
 def test_legacy_status_collect_still_use_immutable_adapter(self):
  request={'correlationId':'86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0'}
  with mock.patch.object(routes.adapter,'operate',return_value={'state':'ready',**request,'sourceSha':REQUEST['sourceSha'],'replayAllowed':False}) as old:
   self.assertTrue(routes.dispatch(Path.cwd(),'linux-package-tmux-status',request)['ok']);old.assert_called_once_with(Path.cwd(),'status',request,source_root=None)
 @unittest.skipUnless(os.name=='posix','private reservation reader requires POSIX coordinator')
 def test_private_registry_unique_exact_row_and_pin_checked(self):
  import json
  identity={'reservationId':'env-new','token':'secret-token','hostAlias':'archlinux','environment':'owned-linux-package-build-'+REQUEST['correlationId'],'operator':'root-tmux-build'}
  row={'id':identity['reservationId'],**{k:v for k,v in identity.items() if k!='reservationId'}};pin={'sha256':'a'*64,'generation':[0]*9}
  for rows,expected in (([row],True),([row,row],False),([],False)):
   with mock.patch.object(routes.closure.pipe,'_read',return_value=(json.dumps({'version':1,'reservations':rows}).encode(),pin)),mock.patch.object(resource,'inventory',return_value=(pin,[])):
    if expected:self.assertEqual(identity,routes._protected_identity(Path.cwd(),REQUEST))
    else:
     with self.assertRaises(ValueError):routes._protected_identity(Path.cwd(),REQUEST)
  with mock.patch.object(routes.closure.pipe,'_read',return_value=(json.dumps({'version':1,'reservations':[row]}).encode(),pin)),mock.patch.object(resource,'inventory',return_value=({'changed':True},[])):
   with self.assertRaises(ValueError):routes._protected_identity(Path.cwd(),REQUEST)

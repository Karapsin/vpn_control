import contextlib,copy,io,tempfile,unittest
from pathlib import Path
from unittest import mock
from agent_tools import mcp_server as server
from agent_tools import android_fixture_tls_routes as route

class TlsMcpRouteTests(unittest.TestCase):
    request={'campaignId':'21111111-1111-4111-8111-111111111111','sourceSha':'a'*40,
             'baseArtifactId':'sha256-'+'b'*64,'targetArtifactId':'sha256-'+'c'*64,
             'sourceRoot':'/private/clean-source'}
    def setUp(self):
        patch=mock.patch.object(server,'_MCP_BOOT_TIME_NS',2**63-1)
        patch.start();self.addCleanup(patch.stop)
    def output(self):
        pin={'sha256':'d'*64,'bytes':10,'generation':[1,2,10,4,5,384,6,1]}
        receipt={'schema':1,'campaignId':self.request['campaignId'],'tlsReceipt':pin,
                 'nestedBinding':{'nestedName':'android-fixture-tls-31111111-1111-4111-8111-111111111111',
                                  'nestedGeneration':[1,2,100,4,5,448,6,2],
                                  'materialPins':{name:copy.deepcopy(pin) for name in ('ca-key.pem','ca.pem','leaf-key.pem','leaf.pem','receipt.json')}},
                 'verifiedPlanSha256':'e'*64,'deviceMutationAllowed':False}
        return {'ok':True,'campaignId':self.request['campaignId'],'receipt':receipt,
                'deviceMutationPerformed':False,
                'evidenceDirectory':str(server.REPO_ROOT.resolve()/'.runtime/parity-evidence'/('android-fixture-tls-route-'+self.request['campaignId']))}
    def test_registered_dispatch_preserves_request_and_has_no_device_authority(self):
        output=self.output()
        with mock.patch.object(route,'run',return_value=output) as run:
            result=server._vm_workflow_impl('android-fixture-tls-mint',dict(self.request))
        self.assertTrue(result['ok']);run.assert_called_once_with(server.REPO_ROOT,self.request)
        self.assertFalse(result['productAction']);self.assertFalse(result['deviceMutationAllowed'])
    def test_nested_private_fields_and_invalid_metadata_are_rejected(self):
        for kind in ('private','bool','path','leaf','pin'):
            output=self.output()
            if kind=='private':output['receipt']['privateKey']='private-marker'
            if kind=='bool':output['receipt']['nestedBinding']['nestedGeneration'][0]=True
            if kind=='path':output['evidenceDirectory']='/private/foreign'
            if kind=='leaf':output['receipt']['nestedBinding']['nestedName']='../../foreign'
            if kind=='pin':output['receipt']['nestedBinding']['materialPins']['leaf.pem']['sha256']='foreign'
            with self.subTest(kind=kind),mock.patch.object(route,'run',return_value=output):
                result=server._vm_workflow_impl('android-fixture-tls-mint',dict(self.request))
                self.assertFalse(result['ok']);self.assertNotIn('private-marker',str(result))
    def test_invalid_requests_do_not_dispatch(self):
        for extra in ({'host':'archlinux'},{'sourceRoot':'relative'},{'campaignId':'bad'},
                      {'sourceSha':'bad'},{'baseArtifactId':'bad'}):
            with self.subTest(extra=extra),mock.patch.object(route,'run') as run:
                self.assertFalse(server._vm_workflow_impl('android-fixture-tls-mint',{**self.request,**extra})['ok'])
                run.assert_not_called()
    def test_route_failure_is_truthful_without_raw_error_details(self):
        with mock.patch.object(route,'run',side_effect=ValueError('private-marker')):
            out=server._vm_workflow_impl('android-fixture-tls-mint',self.request)
        self.assertFalse(out['ok']);self.assertNotIn('private-marker',str(out))
    def test_cli_accepts_route(self):
        with tempfile.TemporaryDirectory() as directory:
            request=Path(directory)/'request.json';request.write_text('{}')
            with mock.patch.object(server,'vm_workflow',return_value={'ok':True}) as dispatch,contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0,server.main(['vm-workflow','android-fixture-tls-mint','--inputs-file',str(request)]))
        dispatch.assert_called_once_with('android-fixture-tls-mint',{})

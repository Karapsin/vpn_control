"""Typed route boundaries; all operation calls mocked, no SSH/native tests."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from agent_tools import ssh_acceptance_observation_routes as routes
from agent_tools import android_device_availability as availability, ssh_nested_socket_orphan_archive as archive, ssh_transport as transport

BOOT='11111111-1111-1111-1111-111111111111'
GEN=[1,2,stat.S_IFREG|0o755,0,100,1,2,1]
PROFILE={'adb':'/private/adb','cli':'/private/cli','serial':'emulator-5554','expectedAvd':'fixture','api':35}


def visible():
    return {'available':True,'outcome':'available','reason':'adb_transport_visible','bootId':BOOT,'bootContinuity':'unknown','adbGeneration':GEN,'productAdmitted':False,'lifecycleActionAllowed':False}


class ObservationRoutes(unittest.TestCase):
    def test_fixed_archive_and_status_dispatch_exact_identity(self):
        value={'ok':True,'state':'archived','replayAllowed':False,'historicalStatus':True,'remoteRevalidated':False,'archivePerformed':True}
        for action,name in [('connection-nested-orphan-archive','archive'),('connection-nested-orphan-archive-status','status')]:
            with self.subTest(action=action),mock.patch.object(archive,name,return_value=value) as operation:
                result=routes.dispatch(Path.cwd(),action,'archlinux',identity=dict(routes.ARCHIVE_IDENTITY))
                operation.assert_called_once_with(Path.cwd(),'archlinux');self.assertEqual({'tool':'ssh_workflow',**value},result)

    def test_unknown_archive_history_does_not_call_recovery_or_archive_from_status(self):
        value={'ok':False,'state':'consumed-unknown','replayAllowed':False,'historicalStatus':True}
        with mock.patch.object(archive,'status',return_value=value) as status,mock.patch.object(archive,'archive') as mutation,mock.patch.object(transport,'load_config',side_effect=AssertionError('historical status must not need live config')):
            result=routes.dispatch(Path.cwd(),'connection-nested-orphan-archive-status','archlinux',identity=dict(routes.ARCHIVE_IDENTITY))
            self.assertFalse(result['ok']);self.assertFalse(result['replayAllowed']);self.assertFalse(result['archivePerformed']);mutation.assert_not_called();status.assert_called_once()

    def test_bad_public_archive_authority_never_calls_helpers(self):
        cases=[{}, {'host':'foreign'}, {'host':'archlinux','identity':{}}, {'host':'archlinux','identity':{**routes.ARCHIVE_IDENTITY,'command':'secret'}}, {'host':'archlinux','identity':{**routes.ARCHIVE_IDENTITY,'observationSha256':'a'*64}}, {'host':'archlinux','identity':dict(routes.ARCHIVE_IDENTITY),'transfer':{}}, {'host':'archlinux','identity':dict(routes.ARCHIVE_IDENTITY),'device':'api35'}, {'host':'archlinux','identity':dict(routes.ARCHIVE_IDENTITY),'timeout_seconds':True}, {'host':'archlinux','identity':dict(routes.ARCHIVE_IDENTITY),'timeout_seconds':61}]
        for action in ('connection-nested-orphan-archive','connection-nested-orphan-archive-status'):
            for case in cases:
                with self.subTest(action=action,case=case),mock.patch.object(archive,'archive') as mutation,mock.patch.object(archive,'status') as status:
                    self.assertFalse(routes.dispatch(Path.cwd(),action,**case)['ok']);mutation.assert_not_called();status.assert_not_called()

    def test_forged_private_archive_outputs_and_exceptions_never_escape(self):
        good={'ok':True,'state':'archived','replayAllowed':False,'historicalStatus':True,'remoteRevalidated':False,'archivePerformed':True}
        values=[None,{'state':'archived'},{**good,'private':'secret'},{**good,'ok':1},{**good,'replayAllowed':0},{**good,'remoteRevalidated':True},{**good,'archivePerformed':False}]
        for value in values:
            with self.subTest(value=value),mock.patch.object(archive,'archive',return_value=value):
                result=routes.dispatch(Path.cwd(),'connection-nested-orphan-archive','archlinux',identity=dict(routes.ARCHIVE_IDENTITY));self.assertFalse(result['ok']);self.assertNotIn('secret',json.dumps(result))
        with mock.patch.object(archive,'archive',side_effect=RuntimeError('private password secret')):
            self.assertNotIn('secret',json.dumps(routes.dispatch(Path.cwd(),'connection-nested-orphan-archive','archlinux',identity=dict(routes.ARCHIVE_IDENTITY))))

    def fixture(self,tmp,api=35):
        root=Path(tmp);path=root/transport.CONFIG_FILENAME;path.write_text('{}');path.chmod(0o600)
        profile={**PROFILE,'api':api};target=SimpleNamespace(android_devices={'api'+str(api):profile},password=None)
        return root,profile,SimpleNamespace(hosts={'archlinux':target}),target

    def test_available_and_unavailable_are_reads_never_product_or_lifecycle_admission(self):
        for api in (29,35):
            with self.subTest(api=api),tempfile.TemporaryDirectory() as tmp:
                root,profile,config,target=self.fixture(tmp,api)
                for value in (visible(),{**visible(),'available':False,'outcome':'unavailable','reason':'configured_device_not_found'}):
                    with mock.patch.object(transport,'load_config',return_value=config),mock.patch.object(transport,'connection_host',return_value=target),mock.patch.object(availability,'observe',return_value=value) as observe:
                        result=routes.dispatch(root,'android-availability','archlinux',device='api'+str(api),timeout_seconds=10)
                        self.assertTrue(result['ok']);self.assertFalse(result['productAdmitted']);self.assertFalse(result['lifecycleActionAllowed']);self.assertFalse(result['replayAllowed']);observe.assert_called_once_with(root,'archlinux',profile,10,None)

    def test_expected_boot_and_changed_continuity_are_typed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root,profile,config,target=self.fixture(tmp)
            for expected,continuity in ((BOOT,'same'),('22222222-2222-2222-2222-222222222222','changed')):
                with mock.patch.object(transport,'load_config',return_value=config),mock.patch.object(transport,'connection_host',return_value=target),mock.patch.object(availability,'observe',return_value={**visible(),'bootContinuity':continuity}) as observe:
                    result=routes.dispatch(root,'android-availability','archlinux',device='api35',identity={'expectedBootId':expected})
                    self.assertTrue(result['ok']);self.assertEqual(continuity,result['bootContinuity']);self.assertEqual(expected,observe.call_args.args[-1])

    def test_bad_availability_inputs_reject_before_any_operation(self):
        for changes in ({'device':'api36'},{'device':'api35;echo'},{'host':'../private'},{'timeout_seconds':True},{'timeout_seconds':31},{'timeout_seconds':0},{'identity':{}},{'identity':{'expectedBootId':BOOT,'command':'secret'}},{'identity':{'expectedBootId':'bad'}},{'transfer':{}},{'device':None}):
            with self.subTest(changes=changes),mock.patch.object(availability,'observe') as observe,mock.patch.object(transport,'load_config') as config:
                kwargs={'host':'archlinux','device':'api35'};kwargs.update(changes)
                self.assertFalse(routes.dispatch(Path.cwd(),'android-availability',**kwargs)['ok']);observe.assert_not_called();config.assert_not_called()

    def test_configured_alias_crossed_api_password_and_config_drift_fail_closed(self):
        for attack in ('missing-device','crossed-api','password','config-drift'):
            with self.subTest(attack=attack),tempfile.TemporaryDirectory() as tmp:
                root,profile,config,target=self.fixture(tmp)
                if attack=='missing-device':target.android_devices={}
                elif attack=='crossed-api':profile['api']=29
                elif attack=='password':target.password='secret'
                def observe(*args):
                    (root/transport.CONFIG_FILENAME).write_text('{}');return visible()
                with mock.patch.object(transport,'load_config',return_value=config),mock.patch.object(transport,'connection_host',return_value=target),mock.patch.object(availability,'observe',side_effect=observe) as operation:
                    result=routes.dispatch(root,'android-availability','archlinux',device='api35');self.assertFalse(result['ok']);self.assertNotIn('secret',json.dumps(result))
                    self.assertEqual(int(attack=='config-drift'),operation.call_count)

    def test_forged_availability_output_is_finite_unknown(self):
        values=[None,{**visible(),'private':'secret'},{**visible(),'productAdmitted':True},{**visible(),'available':1},{**visible(),'adbGeneration':[1]*8},{**visible(),'bootContinuity':'same'},{**visible(),'reason':'secret'},{**visible(),'outcome':[]},{**visible(),'lifecycleActionAllowed':0}]
        with tempfile.TemporaryDirectory() as tmp:
            root,profile,config,target=self.fixture(tmp)
            for value in values:
                with self.subTest(value=value),mock.patch.object(transport,'load_config',return_value=config),mock.patch.object(transport,'connection_host',return_value=target),mock.patch.object(availability,'observe',return_value=value):
                    result=routes.dispatch(root,'android-availability','archlinux',device='api35');self.assertFalse(result['ok']);self.assertEqual('unknown',result['outcome']);self.assertNotIn('secret',json.dumps(result))

    def test_source_drift_and_unhandled_routes_never_dispatch(self):
        with mock.patch.object(routes,'_source_pin',side_effect=ValueError('private secret')),mock.patch.object(archive,'archive') as operation:
            self.assertFalse(routes.dispatch(Path.cwd(),'connection-nested-orphan-archive','archlinux',identity=dict(routes.ARCHIVE_IDENTITY))['ok']);operation.assert_not_called()
        with mock.patch.object(routes,'_module') as operation:self.assertIsNone(routes.dispatch(Path.cwd(),'foreign'));operation.assert_not_called()

    def test_fresh_cli_module_context_imports_package_helpers_outside_repository(self):
        program='''import importlib.util,json,sys
from pathlib import Path
from unittest import mock
source=Path(sys.argv[1]);spec=importlib.util.spec_from_file_location('script_routes',source)
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
a=r._module('ssh_nested_socket_orphan_archive')
with mock.patch.object(a,'status',return_value={'ok':False,'state':'consumed-unknown','replayAllowed':False,'historicalStatus':True}) as call:
 value=r.dispatch(source.parent.parent,'connection-nested-orphan-archive-status','archlinux',identity=r.ARCHIVE_IDENTITY)
 assert call.call_count==1
 assert value['state']=='consumed-unknown' and value['replayAllowed']is False
 print(json.dumps(value))
'''
        with tempfile.TemporaryDirectory() as tmp:
            value=subprocess.run([sys.executable,'-I','-c',program,str(Path(routes.__file__).resolve())],cwd=tmp,capture_output=True,text=True,timeout=15,check=True)
            self.assertFalse(json.loads(value.stdout)['ok'])

    def test_unknown_availability_exact_source_variants_stay_unknown(self):
        for reason in ('transport_failed','malformed_availability','availability_changed','availability_transport_unknown'):
            value={'available':False,'outcome':'unknown','reason':reason,'bootContinuity':'unknown','productAdmitted':False,'lifecycleActionAllowed':False}
            self.assertEqual(value,routes._availability_projection(value,None))
            with self.assertRaises(ValueError):routes._availability_projection({**value,'bootId':BOOT,'adbGeneration':GEN},None)
        value={**visible(),'available':False,'outcome':'unknown','reason':'adb_read_unclassified'}
        self.assertEqual(value,routes._availability_projection(value,None))
        value.pop('bootId');value.pop('adbGeneration')
        with self.assertRaises(ValueError):routes._availability_projection(value,None)

    def test_post_helper_source_drift_rejects_success_and_never_retries(self):
        value={'ok':True,'state':'archived','replayAllowed':False,'historicalStatus':True,'remoteRevalidated':False,'archivePerformed':True}
        with mock.patch.object(routes,'_source_pin',side_effect=[('same',),('same',),('changed',)]),mock.patch.object(archive,'archive',return_value=value) as operation:
            result=routes.dispatch(Path.cwd(),'connection-nested-orphan-archive','archlinux',identity=dict(routes.ARCHIVE_IDENTITY))
            self.assertFalse(result['ok']);self.assertFalse(result['replayAllowed']);operation.assert_called_once()
        for action in ([],{},None):self.assertIsNone(routes.dispatch(Path.cwd(),action))

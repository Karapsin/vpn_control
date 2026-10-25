"""Inert installer/channel refusal tests; native root qualification remains off."""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agent_tools import tart_macos_idle_helper as helper


def value():
    return {'machine':'11111111-1111-4111-8111-111111111111','qualificationOriginBoot':'22222222-2222-4222-8222-222222222222',
        'ordinaryUid':502,'ordinaryPrincipal':'ownedfixture','python':'/usr/local/libexec/vpn-tool-recovery-cont-abcdef12/python/bin/python3.12',
        'pythonSha256':'1'*64,'agentSha256':'2'*64,'agentPlistSha256':'3'*64,'helper':'/usr/local/libexec/vpn-tool-recovery-idle-12345678-1234-4234-8234-123456789abc/main.py'}


class IdleHelperTests(unittest.TestCase):
    def test_config_has_explicit_target_account_source_and_versioned_helper_no_command_api(self):
        self.assertEqual(value(),helper.config(value()))
        for fields in ({'machine':None},{'qualificationOriginBoot':'not-boot'},{'ordinaryUid':True},{'python':'/usr/bin/python3'},
                       {'helper':'/tmp/arbitrary.py'},{'pythonSha256':'private'}):
            with self.subTest(fields=fields),self.assertRaises((ValueError,TypeError)):
                helper.config({**value(),**fields})
        with self.assertRaises(helper.HelperUnavailable):helper.config({**value(),'command':'PRIVATE'})
    def test_complete_generated_helper_extra_argument_refuses_before_native_getter_or_child(self):
        if os.name!='posix' or not hasattr(os,'O_NOFOLLOW'):self.skipTest('POSIX fixed helper source builder')
        source=helper.helper_source(value());self.assertLess(len(source),524288)
        self.assertTrue(source.startswith(('#!'+value()['python']+' -IB\n').encode()))
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'main.py';path.write_bytes(source)
            result=subprocess.run([sys.executable,str(path),'forbidden'],capture_output=True,timeout=10)
        self.assertEqual(3,result.returncode);self.assertEqual(b'',result.stderr)
        if result.stdout:self.assertEqual({'state':'blocked','reason':'macos_idle_helper_unavailable'},json.loads(result.stdout))
        self.assertNotIn(b'PRIVATE',result.stdout)
    def test_nonroot_user_domain_cannot_start_any_process(self):
        with patch.object(helper.os,'geteuid',return_value=502),patch.object(helper.subprocess,'Popen',side_effect=AssertionError('must not spawn')):
            with self.assertRaises(helper.HelperUnavailable):helper.user_domain(502,value())
    def test_direct_ordinary_child_without_root_owned_pipe_cannot_read_native_domain(self):
        native=SimpleNamespace(domain=lambda kind:(_ for _ in ()).throw(AssertionError('nativegetter must not run')))
        processes=SimpleNamespace(process=lambda pid:(_ for _ in ()).throw(AssertionError('parentgetter must not run')))
        with tempfile.TemporaryFile()as stream,patch.object(helper.os,'geteuid',return_value=502),patch.object(helper.os,'fstat',return_value=os.fstat(stream.fileno())):
            with self.assertRaises(helper.HelperUnavailable):
                helper.child_domain(None,processes,native,value(),Path('/qualified-python'))
    def test_captured_source_guard_rejects_changed_loaded_code_before_install_packet(self):
        with patch.object(helper,'_EXECUTING_CODE',compile('PRIVATE=1','<other>','exec')):
            with self.assertRaises(helper.HelperUnavailable):helper.helper_source(value())
    def test_current_ordinary_frame_is_exact_existing_verified_stdin_protocol(self):
        from agent_tools import readiness_qemu_jobs as protocol
        expected,payload=protocol.stdin_command(helper.ordinary_source(value()).decode())
        actual=helper._ordinary_arguments({**value(),'invocationBoot':'fresh'})
        self.assertEqual((value()['python'].encode(),*(part.encode()for part in expected[1:])),actual)
        self.assertNotIn(payload.decode(),str(actual))
        compile(helper.caller_source(value()),'<fixed-ordinary-helper-caller>','exec')
    def test_wrong_control_chain_account_or_launchd_parent_blocks_before_file_or_code_getters(self):
        own=(100,0,101,1000,1);sudo=(101,0,102,1000,2);caller=(102,502,103,1000,3);agent=(103,502,1,1000,4)
        for changed in ((103,503,1,1000,4),(103,502,2,1000,4)):
            records={100:own,101:sudo,102:caller,103:changed}
            processes=SimpleNamespace(process=lambda pid:records[pid])
            with patch.object(helper.os,'getpid',return_value=100):
                with self.assertRaises(helper.HelperUnavailable):
                    helper.source_owned_chain(None,processes,None,[],{**value(),'invocationBoot':'fresh'},Path('/python'))
    def test_missing_posix_builder_capability_is_finite_before_any_open(self):
        with patch.object(helper.os,'name','nt'),patch.object(helper.os,'open',side_effect=AssertionError('must not open')):
            with self.assertRaises(helper.HelperUnavailable):helper.helper_source(value())

    def test_actual_invocation_boot_replaces_origin_without_public_override(self):
        try:import pwd
        except ImportError:self.skipTest('POSIX guest account context')
        fresh='33333333-3333-4333-8333-333333333333'
        context={**value(),'invocationBoot':fresh}
        base=SimpleNamespace(machine=lambda:context['machine'],boot=lambda:(fresh,1))
        with patch('pwd.getpwuid',return_value=SimpleNamespace(pw_name='ownedfixture')):
            helper._target(base,context)
            base.boot=lambda:(value()['qualificationOriginBoot'],1)
            with self.assertRaises(helper.HelperUnavailable):helper._target(base,context)
        with self.assertRaises(helper.HelperUnavailable):helper.config(context)

    def test_protected_file_actual_contents_and_owner_are_not_dto_approval(self):
        if os.name!='posix' or not hasattr(os,'O_NOFOLLOW'):self.skipTest('POSIX protected source file')
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'public.py';path.write_bytes(b'fixed-public-source\n');path.chmod(0o644)
            if os.geteuid()!=0:
                with self.assertRaises(helper.HelperUnavailable):helper.protected_file(path,maximum=1024)
            else:
                raw,_=helper.protected_file(path,maximum=1024,expected_sha=hashlib.sha256(path.read_bytes()).hexdigest())
                self.assertEqual(path.read_bytes(),raw)
                with self.assertRaises(helper.HelperUnavailable):helper.protected_file(path,maximum=1024,expected_sha='0'*64)
                path.chmod(0o666)
                with self.assertRaises(helper.HelperUnavailable):helper.protected_file(path,maximum=1024)

    def test_network_and_source_views_remain_separate_and_never_grant_idle_authority(self):
        from agent_tools import tart_macos_network_census as network
        observer=(100,0,101,1000,1);agent=(103,502,1,1000,4)
        records={100:(observer,'unmanaged'),103:(agent,'unmanaged')}
        processes=SimpleNamespace(snapshot=lambda:records,process=lambda pid:records[pid][0])
        volume=SimpleNamespace(public=lambda:{'rootMount':'readonly_apfs_snapshot'})
        service=SimpleNamespace(Domain=lambda kind,uid,rows:SimpleNamespace(kind=kind,uid=uid,rows=rows),
            Catalog=lambda volume,uid:object(),review=lambda *args,**kwargs:{'visibilityComplete':True})
        native=SimpleNamespace(image=lambda actor:b'private-mapped-image',
            domain=lambda kind:service.Domain(kind,0,[]),volume=lambda:volume)
        snapshot=(((b'PRIVATE-if',0x51,1,(18,)),),())
        network_native=SimpleNamespace(snapshot=lambda:snapshot)
        context={**value(),'invocationBoot':'33333333-3333-4333-8333-333333333333'}
        with patch.object(helper.os,'geteuid',return_value=0),patch.object(helper.os,'getpid',return_value=100),\
                patch.object(helper,'_target'),patch.object(helper,'user_domain',return_value=[]),\
                patch.object(helper,'source_owned_chain',return_value=(agent,)),\
                patch.object(network,'NativeNetwork',return_value=network_native):
            result=helper.collect(None,processes,native,service,network,context,Path('/qualified-python'))
        self.assertTrue(result['serviceEvidence']['visibilityComplete'])
        self.assertFalse(result['networkEvidence']['activityClear'])
        self.assertEqual(['kernel_tunnel_activity_unqualified'],result['networkEvidence']['blockers'])
        self.assertFalse(result['idleAuthority']);self.assertFalse(result['nativeQualified'])
        self.assertIn('protected_network_provider_source_join',result['missingEvidence'])
        self.assertNotIn('PRIVATE',json.dumps(result))


if __name__=='__main__':unittest.main()

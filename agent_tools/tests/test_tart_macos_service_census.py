"""Service decision/call boundary tests; guest native qualification separate."""
import ctypes as C
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from types import ModuleType
import unittest
from unittest.mock import patch

from agent_tools import tart_macos_service_census as svc


class ServiceReviewTests(unittest.TestCase):
    def setUp(self):
        self.observer=(10,0,1,100,1);self.actor=(11,0,1,101,2)
        self.processes={10:(self.observer,'unmanaged'),11:(self.actor,'unmanaged')}
        self.rows=[{'Label':'private-unexported-label','PID':11}]
        self.domains=[svc.Domain('system',0,self.rows)]
        self.source=SimpleNamespace(transactions=True)
        self.catalog=SimpleNamespace(match=lambda row,actor,native,**kwargs:self.source,stable=lambda:True)
        self.code='apple_valid';self.activity='tracked_clean_idle_exit';self.image=b'private-memory-only'
        self.native=SimpleNamespace(image=lambda actor:self.image,
            processes=SimpleNamespace(code=lambda actor:self.code,activity=lambda actor:self.activity))
    def review(self):
        return svc.review(self.processes,self.domains,self.catalog,self.native,ordinary_uid=502,observer=self.observer)
    def test_positive_is_computed_from_source_code_kernel_activity_not_constant_false(self):
        result=self.review()
        self.assertTrue(result['visibilityComplete']);self.assertEqual([],result['runningJobs'])
        self.assertEqual('idle_system_service',result['processes'][1]['role'])
        self.assertNotIn('private',str(result))
    def test_apple_signature_or_launchd_parent_without_tracked_clean_is_unknown(self):
        for state in ('untracked','tracked_dirty','tracked_clean','launch_in_progress','unavailable','identity_changed'):
            self.activity=state;result=self.review()
            self.assertFalse(result['visibilityComplete']);self.assertTrue(result['runningJobs'])
            self.assertIn('macos_service_activity_unqualified',result['reasons'])
    def test_protected_overrides_even_observer_identity_or_clean_apple_source(self):
        for pid in (10,11):
            before=self.processes[pid];self.processes[pid]=(before[0],'protected_runtime')
            result=self.review();self.assertFalse(result['visibilityComplete'])
            self.assertIn(pid,result['protectedProcesses'])
            self.processes[pid]=before
    def test_installer_requires_both_declared_transactions_and_actual_clean_kernel_state(self):
        self.processes[11]=(self.actor,'installer')
        result=self.review();self.assertTrue(result['visibilityComplete'])
        self.assertEqual('idle_installer_service',result['processes'][1]['role'])
        self.source.transactions=False
        result=self.review();self.assertFalse(result['visibilityComplete']);self.assertEqual([11],result['installerBlockers'])
        self.source.transactions=True;self.activity='tracked_dirty'
        self.assertEqual([11],self.review()['installerBlockers'])
    def test_missing_user_domain_does_not_infer_no_competing_work(self):
        actor=(11,502,1,101,2);self.processes[11]=(actor,'unmanaged')
        self.assertIn('user_service_domain_unobserved',self.review()['reasons'])
        self.domains.append(svc.Domain('caller_user',502,[]))
        self.assertTrue(self.review()['visibilityComplete'])
    def test_missing_source_pid_or_source_change_blocks(self):
        self.rows[0]['PID']=12
        result=self.review();self.assertFalse(result['visibilityComplete'])
        self.assertIn('loaded_service_process_changed',result['reasons'])
        self.rows[0]['PID']=11;self.catalog.stable=lambda:False
        self.assertIn('macos_service_source_changed',self.review()['reasons'])
    def test_code_and_mapped_image_change_are_separate_blockers(self):
        self.code='not_apple_valid'
        self.assertIn('macos_service_code_unqualified',self.review()['reasons'])
        self.code='apple_valid';counter=iter((b'before',b'after'));self.native.image=lambda actor:next(counter)
        self.assertIn('macos_service_executable_changed',self.review()['reasons'])
    def test_native_error_never_echoes_unknown_argv_path_label_or_digest(self):
        def fail(*args):raise OSError('PRIVATE-ARGV-PATH-HASH')
        self.catalog.match=fail;result=self.review()
        self.assertIn('macos_service_evidence_unavailable',result['reasons'])
        self.assertNotIn('PRIVATE',str(result));self.assertNotIn('unexported',str(result))
    def test_readonly_root_is_not_authenticated_policy(self):
        self.assertFalse(svc.Volume((1,2),True,False,1,True).source_eligible)
        self.assertFalse(svc.Volume((1,2),False,True,1,True).source_eligible)
        self.assertTrue(svc.Volume((1,2),True,True,1,True).source_eligible)
        self.assertFalse(svc.Volume((1,2),True,True,1,False).source_eligible)
        self.assertNotIn('sealed',svc.Volume((1,2),True,True,1,True).public())
    def test_statfs_layout_matches_installed_apple_primary_header_without_native_getter(self):
        if sys.platform!='darwin':self.skipTest('Apple SDK structure check requires Darwin compiler headers')
        compiler=shutil.which('cc')
        if compiler is None:self.skipTest('Apple SDK structure check requires C compiler')
        source='#include <sys/mount.h>\n#include <stddef.h>\n#include <stdio.h>\nint main(void){printf("%zu %zu %zu %zu",sizeof(struct statfs),offsetof(struct statfs,f_flags),offsetof(struct statfs,f_fstypename),offsetof(struct statfs,f_mntonname));return 0;}\n'
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);(root/'layout.c').write_text(source)
            result=subprocess.run([compiler,str(root/'layout.c'),'-o',str(root/'layout')],capture_output=True,timeout=20)
            self.assertEqual(0,result.returncode,'controlled layout compile failed')
            actual=subprocess.run([str(root/'layout')],capture_output=True,timeout=5,check=True)
        self.assertEqual([C.sizeof(svc._Statfs),svc._Statfs.flags.offset,svc._Statfs.typename.offset,svc._Statfs.mounted.offset],
                         [int(item)for item in actual.stdout.split()])

    def test_actual_ctypes_mapped_image_getter_uses_get_only_and_generation_guard(self):
        calls=[]
        @C.CFUNCTYPE(C.c_int,C.c_int,C.c_uint32,C.c_void_p,C.c_size_t)
        def csops(pid,operation,buffer,size):
            calls.append((pid,operation,size));C.memset(buffer,7,size);return 0
        native=svc.NativeServices.__new__(svc.NativeServices)
        native.base=SimpleNamespace(lib=SimpleNamespace(csops=csops))
        native.processes=SimpleNamespace(process=lambda pid:self.actor)
        image=native.image(self.actor)
        self.assertEqual(bytes([7])*20,image);self.assertEqual([(11,5,20)],calls)
        identities=iter((self.actor,(11,0,1,102,2)));native.processes.process=lambda pid:next(identities)
        with self.assertRaisesRegex(svc.ServiceUnavailable,'macos_service_process_changed'):native.image(self.actor)


class ServiceUserDomainCausalTests(unittest.TestCase):
    def test_authentic_before_rejects_actual_other_user_domain_current_joins_exact_uid(self):
        executable=Path('/usr/bin/true')
        if not executable.is_file()or executable.stat().st_uid!=0:
            self.skipTest('controlled service source match requires existing root-owned public executable metadata')
        fixture=Path(__file__).parent/'fixtures/macos_service_user_domain_before.source';raw=fixture.read_bytes()
        self.assertEqual('7846758ef3cc1e9620fb9d0f68fef4607897fb8609828ffaacfc9d00f2b68e1b',hashlib.sha256(raw).hexdigest())
        before=ModuleType('_service_user_domain_before');before.__file__=str(fixture)
        sys.modules[before.__name__]=before
        try:exec(compile(raw,str(fixture),'exec'),before.__dict__)
        finally:sys.modules.pop(before.__name__,None)
        observer=(10,0,1,1000,1);actor=(11,501,1,1000,2)
        processes={10:(observer,'unmanaged'),11:(actor,'unmanaged')}
        def review(module,domain_uid=501,explicit_source_uid=None,kind='caller_user'):
            identity=(1,2,3)
            source=SimpleNamespace(path=Path('/public-source-fixture.plist'),identity=identity,
                uid=explicit_source_uid,origin='system_agent',executable=executable,
                arguments=(str(executable).encode(),),transactions=True)
            catalog=module.Catalog.__new__(module.Catalog)
            catalog.ordinary_uid=502;catalog.volume=SimpleNamespace(device=executable.stat().st_dev)
            catalog.sources={'PRIVATE-service':source};catalog.directories=[]
            catalog._read=lambda path:(b'public-controlled-source',identity)
            native=SimpleNamespace(image=lambda actor:b'private-image',
                argv=lambda actor:(str(executable).encode(),(str(executable).encode(),)),
                processes=SimpleNamespace(code=lambda actor:'apple_valid',activity=lambda actor:'tracked_clean_idle_exit'))
            domains=([module.Domain('system',0,[])]if(kind,domain_uid)!=('system',0)else[])
            domains.append(module.Domain(kind,domain_uid,[{'Label':'PRIVATE-service','PID':11}]))
            return module.review(processes,domains,catalog,native,ordinary_uid=502,observer=observer)
        old=review(before);current=review(svc)
        self.assertFalse(old['visibilityComplete'])
        self.assertIn('macos_service_account_or_parent_unqualified',old['reasons'])
        self.assertTrue(current['visibilityComplete']);self.assertEqual([],current['runningJobs'])
        for result in (review(svc,domain_uid=502),review(svc,explicit_source_uid=502),
                       review(svc,domain_uid=0,kind='system')):
            self.assertFalse(result['visibilityComplete'])
            self.assertTrue(result['runningJobs']);self.assertNotIn('PRIVATE',str(result))


class CapabilityGetterTests(unittest.TestCase):
    def setUp(self):
        self.machine='11111111-1111-4111-8111-111111111111'
        self.boot='22222222-2222-4222-8222-222222222222'
        self.base=SimpleNamespace(machine=lambda:self.machine,boot=lambda:(self.boot,1))
        self.calls=[]
        def domain(kind):
            self.calls.append(kind)
            return svc.Domain(kind,502,[{'Label':'PRIVATE-label','PID':17,
                    'EnvironmentVariables':{'PRIVATE':'PRIVATE-secret'},'ProgramArguments':['PRIVATE-argv']}])
        self.native=SimpleNamespace(domain=domain,volume=lambda:svc.Volume((1,2),True,True,1,True))
    def facts(self,**overrides):
        inputs=dict(machine=self.machine,boot=self.boot,uid=502,principal='ownedfixture')
        inputs.update(overrides)
        local_os=SimpleNamespace(name='posix',geteuid=lambda:502)
        accounts=SimpleNamespace(getpwuid=lambda uid:SimpleNamespace(pw_name='ownedfixture'))
        with patch.object(svc,'os',local_os),patch.object(svc,'pwd',accounts):
            return svc.capability_facts(self.base,self.native,**inputs)
    def test_finite_getter_counts_do_not_export_native_dictionaries_or_claim_idle(self):
        result=self.facts()
        self.assertFalse(result['nativeQualified']);self.assertFalse(result['idleAuthority'])
        self.assertEqual(['system','caller_user'],self.calls)
        self.assertEqual(1,result['domains'][0]['activePids'])
        self.assertNotIn('PRIVATE',json.dumps(result))
    def test_target_account_and_boot_fail_before_any_service_getter(self):
        for change in ({'machine':self.boot},{'boot':self.machine},{'uid':503},{'principal':'another'}):
            with self.subTest(change=change):
                self.calls.clear()
                with self.assertRaises(svc.ServiceUnavailable):self.facts(**change)
                self.assertEqual([],self.calls)
    def test_api_failure_is_finite_and_never_healthy(self):
        def fail(kind):raise OSError('PRIVATE-argv-path-environment')
        self.native.domain=fail;self.native.volume=lambda:(_ for _ in ()).throw(OSError('PRIVATE'))
        result=self.facts()
        self.assertEqual([{'domain':'system','state':'unavailable'},{'domain':'caller_user','state':'unavailable'}],result['domains'])
        self.assertEqual({'state':'unavailable'},result['volume']);self.assertNotIn('PRIVATE',str(result))
    def test_complete_generated_caller_refuses_argument_without_opening_native_frameworks(self):
        if svc.os.name!='posix' or not hasattr(svc.os,'O_NOFOLLOW'):
            with self.assertRaisesRegex(svc.ServiceUnavailable,'macos_service_source_unavailable'):
                svc.capability_source(machine=self.machine,boot=self.boot,uid=502,principal='ownedfixture')
            return
        source=svc.capability_source(machine=self.machine,boot=self.boot,uid=502,principal='ownedfixture')
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'getter.py';path.write_bytes(source)
            result=subprocess.run([sys.executable,str(path),'forbidden'],capture_output=True,timeout=10)
        self.assertEqual(3,result.returncode)
        self.assertEqual({'state':'blocked','reason':'macos_service_getter_unavailable'},json.loads(result.stdout))
        self.assertEqual(b'',result.stderr)

    def test_unsupported_source_capture_blocks_before_open(self):
        opened=unittest.mock.Mock(side_effect=AssertionError('unsupported source open'))
        with patch.object(svc,'os',SimpleNamespace(name='nt',open=opened)):
            with self.assertRaisesRegex(svc.ServiceUnavailable,'macos_service_source_unavailable'):
                svc.capability_source(machine=self.machine,boot=self.boot,uid=502,principal='ownedfixture')
        opened.assert_not_called()


if __name__=='__main__':unittest.main()

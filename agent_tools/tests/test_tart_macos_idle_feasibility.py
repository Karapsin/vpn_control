"""Finite ordinary GET facts cannot become service-purpose or idle authority."""
from pathlib import Path
import hashlib
import json
import ctypes as C
import os
import signal
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agent_tools import tart_macos_idle_feasibility as getter
from agent_tools import tart_macos_service_census as service


class IdleFeasibilityTests(unittest.TestCase):
    def setUp(self):
        self.inputs=dict(machine='11111111-1111-4111-8111-111111111111',
            boot='22222222-2222-4222-8222-222222222222',uid=502,principal='toolrecovery',
            agent=(5,502,1,1000,1))
        self.observer=(10,502,5,1000,2);self.root=(20,0,1,1000,3)
        self.records={5:(self.inputs['agent'],'unmanaged'),10:(self.observer,'unmanaged'),20:(self.root,'installer')}
        self.inputs['actors']=tuple((actor[0],actor[1],actor[3],actor[4],role)for actor,role in self.records.values())
        self.calls=[]
        self.base=SimpleNamespace(machine=lambda:self.inputs['machine'],boot=lambda:(self.inputs['boot'],1))
        self.processes=SimpleNamespace(process=lambda pid:self.records[pid][0],snapshot=self.snapshot,
            code=lambda actor:'apple_valid',activity=lambda actor:'untracked')
        self.catalog=SimpleNamespace(stable=lambda:True,match=lambda row,actor,native,**kwargs:
            SimpleNamespace(origin='system_daemon',transactions=True))
        self.native=SimpleNamespace(image=lambda actor:b'private-mapped-image',
            domain=lambda kind:service.Domain(kind,502,[{'Label':'PRIVATE-service','PID':20}]if kind=='system'else[]),
            volume=lambda:SimpleNamespace(public=lambda:{'rootMount':'readonly_apfs_snapshot'}))
        self.raw_pids=lambda base:tuple(sorted(self.records))

    def snapshot(self):
        self.calls.append('snapshot');return dict(self.records)

    def collect(self,**changes):
        with patch.object(getter.os,'geteuid',return_value=502),patch.object(getter.os,'getpid',return_value=10),\
                patch.object(getter.os,'getppid',return_value=5),patch.object(getter,'pwd',
                    SimpleNamespace(getpwuid=lambda uid:SimpleNamespace(pw_name='toolrecovery'))),\
                patch.object(service,'Catalog',return_value=self.catalog),\
                patch.object(getter,'_raw_pids',side_effect=lambda base:self.raw_pids(base)),\
                patch.object(getter,'_path_access',return_value='available'):
            return getter.collect(self.base,self.processes,self.native,service,**{**self.inputs,**changes})

    def test_successful_getters_preserve_actual_untracked_installer_and_no_idle_authority(self):
        result=self.collect()
        self.assertFalse(result['nativeQualified']);self.assertFalse(result['idleAuthority'])
        self.assertTrue(result['processSnapshotStable']);self.assertTrue(result['sourceCatalogStable'])
        root=next(row for row in result['processes']if row['pid']==20)
        self.assertEqual('installer',root['role']);self.assertEqual('untracked',root['activity'])
        self.assertEqual('observed',root['mappedCode']);self.assertEqual('matched',root['loadedSource'])
        self.assertIn('known_service_purpose_and_activity_applicability',result['missingAuthority'])
        self.assertNotIn('PRIVATE',str(result));self.assertNotIn('private-mapped-image',str(result))

    def test_permission_failures_and_unrecognized_replies_are_finite_missing_visibility(self):
        def failure(*args):raise PermissionError('PRIVATE-PATH-ENV')
        self.processes.code=failure;self.processes.activity=lambda actor:'PRIVATE-ACTIVITY';self.native.image=failure
        self.native.domain=failure
        result=self.collect()
        self.assertIn('code_visibility_incomplete',result['missingVisibility'])
        self.assertIn('dirty_visibility_incomplete',result['missingVisibility'])
        self.assertIn('mapped_visibility_incomplete',result['missingVisibility'])
        self.assertIn('system_domain_unavailable',result['missingVisibility'])
        self.assertNotIn('PRIVATE',str(result));self.assertFalse(result['idleAuthority'])

    def test_mapped_getter_success_does_not_hide_source_custody_failure(self):
        self.catalog.match=lambda *args:(_ for _ in ()).throw(PermissionError('PRIVATE-PATH'))
        result=self.collect();root=next(row for row in result['processes']if row['pid']==20)
        self.assertEqual('observed',root['mappedCode']);self.assertEqual('unavailable',root['loadedSource'])
        self.assertIn('loaded_source_visibility_incomplete',result['missingVisibility'])
        self.assertNotIn('PRIVATE',str(result))

    def test_other_user_domain_and_process_churn_are_not_suppressed(self):
        self.records[21]=((21,501,1,1000,4),'unmanaged')
        self.inputs['actors']+=((21,501,1000,4,'unmanaged'),)
        result=self.collect();self.assertIn('other_user_service_domain_unobserved',result['missingVisibility'])
        first=dict(self.records);second={**first,22:((22,0,1,1000,5),'unmanaged')}
        samples=iter((tuple(first),tuple(second)));self.raw_pids=lambda base:next(samples)
        result=self.collect();self.assertFalse(result['processSnapshotStable'])
        self.assertIn('process_snapshot_changed',result['missingVisibility'])

    def test_wrong_explicit_machine_boot_account_and_agent_stop_before_snapshot(self):
        for change in ({'machine':'33333333-3333-4333-8333-333333333333'},
                       {'boot':'33333333-3333-4333-8333-333333333333'},{'uid':503},
                       {'principal':'different'},{'agent':(6,502,1,1000,1)},{'machine':'PRIVATE-invalid'}):
            with self.subTest(change=change):
                self.calls.clear()
                with self.assertRaises(getter.FeasibilityUnavailable):self.collect(**change)
                self.assertEqual([],self.calls)

    def test_complete_generated_caller_extra_argument_refuses_before_framework_or_getters(self):
        if getter.os.name!='posix':self.skipTest('fixed Mac source requires POSIX nofollow')
        source=getter.source(**self.inputs)
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'getter.py';path.write_bytes(source)
            result=subprocess.run([sys.executable,str(path),'forbidden'],capture_output=True,timeout=10)
        self.assertEqual(3,result.returncode);self.assertEqual(b'',result.stderr)
        self.assertEqual({'reason':'macos_idle_guest_required','stage':'guest_guard','state':'blocked'},json.loads(result.stdout))
        with patch.object(getter,'_EXECUTING_CODE',None):
            with self.assertRaisesRegex(getter.FeasibilityUnavailable,'macos_idle_source_changed'):
                getter.source(**self.inputs)

    def test_authentic_whole_before_generated_receiver_hid_finite_stage_current_receiver_preserves_it(self):
        if getter.os.name!='posix':self.skipTest('fixed Mac source requires POSIX nofollow')
        fixture=Path(__file__).parent/'fixtures/macos_idle_feasibility_before.source';raw=fixture.read_bytes()
        self.assertEqual('e40ea900788c30817f74282b1bf091d30ab1b97f8ee06dbc6dc1e2f7665dfdff',hashlib.sha256(raw).hexdigest())
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory)
            for name in getter._FILES:
                body=raw if name=='tart_macos_idle_feasibility.py'else Path(getter.__file__).with_name(name).read_bytes()
                (root/name).write_bytes(body)
            owner=root/'tart_macos_idle_feasibility.py';before={'__name__':'_authentic_idle_before','__file__':str(owner)}
            exec(compile(raw,str(owner),'exec'),before)
            replies=[]
            for source in (before['source'](**{key:value for key,value in self.inputs.items()if key!='actors'}),getter.source(**self.inputs)):
                packet=root/'packet.py';packet.write_bytes(source)
                result=subprocess.run([sys.executable,str(packet),'forbidden'],capture_output=True,timeout=10)
                self.assertEqual(3,result.returncode);self.assertEqual(b'',result.stderr)
                replies.append(json.loads(result.stdout))
        def require_finite_stage(reply):self.assertEqual('guest_guard',reply['stage'])
        with self.assertRaises((AssertionError,KeyError)):require_finite_stage(replies[0])
        require_finite_stage(replies[1])

    def test_untrusted_native_exception_text_and_fake_stage_cannot_escape(self):
        for error in (OSError('PRIVATE-PATH-ARGV'),getter.FeasibilityUnavailable('PRIVATE'),
                      getter.StageUnavailable('PRIVATE')):
            result=getter.failure(error,'PRIVATE-stage')
            self.assertEqual({'state':'blocked','reason':'macos_idle_getters_unavailable','stage':'collection'},result)
            self.assertNotIn('PRIVATE',str(result))
        self.raw_pids=lambda base:(_ for _ in ()).throw(PermissionError('PRIVATE-process'))
        with self.assertRaises(getter.StageUnavailable)as error:self.collect()
        self.assertEqual('process_snapshot_before',getter.failure(error.exception,'collection')['stage'])

    def test_root_projection_has_explicit_identity_no_paths_and_no_idle_authority(self):
        facts={'machine':self.inputs['machine'],'boot':self.inputs['boot'],'uid':502,'account':'toolrecovery',
            'observerUid':0,'processVisibilityComplete':True,'processes':[
                {'pid':20,'uid':0,'birth':'darwin:1000:3','executableRole':'installer'}]}
        bound={key:self.inputs[key]for key in ('machine','boot','uid','principal')}
        packet={'facts':facts,'agent':{}}
        self.assertEqual(((20,0,1000,3,'installer'),),getter.root_candidates(packet,**bound))
        for change in ({'machine':'other'},{'boot':'other'},{'observerUid':502},{'processVisibilityComplete':False},
                       {'processes':facts['processes']*2}):
            with self.subTest(change=change),self.assertRaises(getter.FeasibilityUnavailable):
                getter.root_candidates({'facts':{**facts,**change},'agent':{}},**bound)

    def test_exited_or_reused_candidate_never_gets_code_of_replacement(self):
        original=self.processes.process
        self.processes.process=lambda pid:(20,0,1,1001,3)if pid==20 else original(pid)
        calls=[];self.processes.code=lambda actor:calls.append(actor[0])or'apple_valid'
        result=self.collect()
        self.assertNotIn(20,calls)
        self.assertEqual([{'pid':20,'uid':0,'birth':'darwin:1000:3','identity':'identity_changed'}],result['unavailableCandidateActors'])
        self.assertIn('candidate_actor_identity_unavailable',result['missingVisibility'])
        self.assertFalse(result['idleAuthority'])

    def test_actual_new_child_kernel_alarm_bounds_hanging_getters_without_signalling_any_owner(self):
        if os.name!='posix' or not hasattr(signal,'SIGALRM'):self.skipTest('Mac synchronous GET uses POSIX alarm')
        program=('import signal,time\nfrom agent_tools.tart_macos_idle_feasibility import arm_budget\n'
            'arm_budget()\nassert signal.getsignal(signal.SIGALRM)==signal.SIG_DFL\n'
            'remaining=signal.alarm(0)\nassert 59<=remaining<=60\n'
            'signal.alarm(1)\ntime.sleep(10)\n')
        result=subprocess.run([sys.executable,'-c',program],capture_output=True,timeout=5)
        self.assertEqual(-signal.SIGALRM,result.returncode)
        self.assertEqual(b'',result.stdout);self.assertEqual(b'',result.stderr)


_DENIED_PATH_C=r'''
#include <stdint.h>
#include <string.h>
#include <errno.h>
int proc_listallpids(void *output,int length){
 int pids[]={5,10,20};if(!output)return 3;if(length<12)return 0;memcpy(output,pids,12);return 3;
}
int proc_pidinfo(int pid,int flavor,uint64_t arg,void *output,int length){
 if(flavor!=3||arg||length!=136)return 0;unsigned char *raw=output;memset(raw,0,136);
 uint32_t ppid=pid==10?5:1,uid=pid==20?0:502;uint64_t seconds=1000,micro=pid==5?1:pid==10?2:3;
 memcpy(raw+12,&pid,4);memcpy(raw+16,&ppid,4);memcpy(raw+20,&uid,4);
 memcpy(raw+120,&seconds,8);memcpy(raw+128,&micro,8);return 136;
}
int proc_pidpath(int pid,void *output,uint32_t length){
 if(pid==20){errno=13;return 0;}char *path="/PRIVATE-UNEXPECTED-PATH";
 if(length<=strlen(path))return 0;strcpy(output,path);return (int)strlen(path)+1;
}
'''


class CandidateCensusCausalTests(unittest.TestCase):
    def test_authentic_before_full_census_path_denied_red_current_candidate_gets_finite_permission_green(self):
        if sys.platform=='win32' or shutil.which('cc')is None:self.skipTest('controlled ordinary GET requires POSIX C compiler')
        from agent_tools import tart_macos_idle_collector as census
        fixture=Path(__file__).parent/'fixtures/macos_idle_candidate_census_before.source';raw=fixture.read_bytes()
        self.assertEqual('04459d2637f4e49cb24b19a42a11bd9466f52991e896dae2808518d16fa1945c',hashlib.sha256(raw).hexdigest())
        before={'__name__':'_candidate_census_before','__file__':str(fixture)};exec(compile(raw,str(fixture),'exec'),before)
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);(root/'denied.c').write_text(_DENIED_PATH_C)
            subprocess.run([shutil.which('cc'),'-shared','-fPIC',str(root/'denied.c'),'-o',str(root/'denied.dylib')],
                           capture_output=True,timeout=20,check=True)
            lib=C.CDLL(str(root/'denied.dylib'),use_errno=True)
            for name,result,args in (
                ('proc_listallpids',C.c_int,[C.c_void_p,C.c_int]),
                ('proc_pidinfo',C.c_int,[C.c_int,C.c_int,C.c_uint64,C.c_void_p,C.c_int]),
                ('proc_pidpath',C.c_int,[C.c_int,C.c_void_p,C.c_uint32])):
                value=getattr(lib,name);value.restype=result;value.argtypes=args
            inputs=dict(machine='11111111-1111-4111-8111-111111111111',boot='22222222-2222-4222-8222-222222222222',
                uid=502,principal='toolrecovery',agent=(5,502,1,1000,1))
            base=SimpleNamespace(proc=lib,machine=lambda:inputs['machine'],boot=lambda:(inputs['boot'],1))
            processes=census.Native.__new__(census.Native);processes.base=base
            processes.code=lambda actor:'apple_valid';processes.activity=lambda actor:'untracked'
            native=SimpleNamespace(image=lambda actor:b'private-mapped-image',
                domain=lambda kind:service.Domain(kind,502,[]),
                volume=lambda:SimpleNamespace(public=lambda:{'rootMount':'readonly_apfs_snapshot'}))
            catalog=SimpleNamespace(stable=lambda:True)
            with patch.object(getter.os,'geteuid',return_value=502),patch.object(getter.os,'getpid',return_value=10),\
                    patch.object(getter.os,'getppid',return_value=5),patch.object(getter,'pwd',
                        SimpleNamespace(getpwuid=lambda uid:SimpleNamespace(pw_name='toolrecovery'))),\
                    patch.dict(before,pwd=SimpleNamespace(getpwuid=lambda uid:SimpleNamespace(pw_name='toolrecovery'))),\
                    patch.object(service,'Catalog',return_value=catalog):
                # Real collector Native.snapshot reads the controlled C PID
                # info/path ABI. One ordinary EACCES aborts the whole old call.
                with self.assertRaisesRegex(before['StageUnavailable'],'process_snapshot_before'):
                    before['collect'](base,processes,native,service,**inputs)
                result=getter.collect(base,processes,native,service,**inputs,actors=((20,0,1000,3,'installer'),))
        self.assertEqual('diagnostic',result['state'])
        self.assertEqual('permission_denied',result['processes'][0]['pathAccess'])
        self.assertEqual('untracked',result['processes'][0]['activity'])
        self.assertIn('path_visibility_incomplete',result['missingVisibility'])
        self.assertFalse(result['idleAuthority']);self.assertFalse(result['nativeQualified'])
        self.assertNotIn('PRIVATE',str(result))


if __name__=='__main__':unittest.main()

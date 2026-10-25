"""Controlled getter/complete helper protocol; never opens native frameworks."""
import copy
import ctypes as C
import json
import os
from pathlib import Path
import subprocess
import shutil
from unittest.mock import patch
import sys
import tempfile
import unittest
from uuid import uuid4

from agent_tools import tart_macos_idle_collector as census


class Base:
    def __init__(self):
        self.machine_id = str(uuid4()); self.boot_id = str(uuid4()); self.calls = []
    def machine(self):
        self.calls.append('machine'); return self.machine_id
    def boot(self):
        self.calls.append('boot'); return self.boot_id, {'seconds': 100, 'microseconds': 2}


class Getters:
    def __init__(self):
        self.rows = {10: ((10, 0, 1, 100, 1), 'unmanaged'),
                     11: ((11, 502, 1, 101, 2), 'unmanaged')}
        self.code_value = 'apple_valid'; self.reads = 0
    def snapshot(self):
        self.reads += 1; return copy.deepcopy(self.rows)
    def code(self, actor):
        return self.code_value
    def activity(self, actor):
        return 'tracked_clean_idle_exit'


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.base = Base(); self.getters = Getters()
    def collect(self):
        return census._collect(self.base, self.getters, self.base.machine_id, 502, 10)

    def test_full_getter_census_retains_only_kernel_identity_and_finite_posture(self):
        value = self.collect()
        self.assertTrue(value['processIdentityComplete'])
        self.assertEqual(2, self.getters.reads)
        self.assertEqual({'pid', 'uid', 'ppid', 'birth', 'code', 'role', 'activity'}, set(value['first'][0]))
        self.assertEqual('verified_probe', value['first'][0]['role'])
        self.assertIs(value['nativeIdle'], False); self.assertIs(value['nativeQualified'], False)
        self.assertNotIn('visibility', value)
        self.assertIn('loaded_service_custody', value['missingEvidence'])

    def test_apple_signature_and_launchd_parent_do_not_make_service_idle(self):
        value = self.collect()
        self.assertEqual('apple_valid', value['first'][1]['code'])
        self.assertEqual(1, value['first'][1]['ppid'])
        self.assertEqual('unmanaged', value['first'][1]['role'])
        self.assertFalse(value['nativeIdle'])

    def test_protected_installer_overrides_apple_provenance(self):
        for role in ('protected_runtime', 'installer'):
            self.getters.rows[11] = (self.getters.rows[11][0], role)
            value = self.collect()
            self.assertEqual(role, value['first'][1]['role'])
            self.assertFalse(value['nativeIdle'])

    def test_exec_or_process_identity_unavailable_never_upgrades_to_complete(self):
        self.getters.code_value = 'identity_changed'
        self.assertFalse(self.collect()['processIdentityComplete'])
        original = self.getters.snapshot
        def changing():
            value = original()
            if self.getters.reads % 2 == 0:
                value[11] = ((11, 502, 1, 102, 2), 'unmanaged')
            return value
        self.getters.snapshot = changing
        self.getters.code_value = 'apple_valid'
        self.assertFalse(self.collect()['processIdentityComplete'])

    def test_invalid_getter_reply_does_not_echo_private_input(self):
        secret = 'PRIVATE-ACTUAL-PATH-AND-ARGV'
        self.getters.code_value = secret
        with self.assertRaisesRegex(census.CensusUnavailable, '^macos_census_code_unavailable$') as caught:
            self.collect()
        self.assertNotIn(secret, str(caught.exception))
        self.getters.code_value = 'apple_valid'
        self.getters.rows[11] = ((11, 502, 1, 100, 2), secret)
        with self.assertRaisesRegex(census.CensusUnavailable, '^macos_census_process_unavailable$'):
            self.collect()

    def test_wrong_selected_machine_stops_before_any_process_getter(self):
        with self.assertRaisesRegex(census.CensusUnavailable, '^macos_census_target_changed$'):
            census._collect(self.base, self.getters, str(uuid4()), 502, 10)
        self.assertEqual(0, self.getters.reads)

    def test_root_observer_uid_and_generation_are_not_inferred(self):
        self.getters.rows[10] = ((10, 502, 1, 100, 1), 'unmanaged')
        with self.assertRaisesRegex(census.CensusUnavailable, '^macos_census_observer_changed$'):
            self.collect()

    def test_complete_captured_zeroarg_helper_fails_closed_before_native_access(self):
        program = census.diagnostic_source(self.base.machine_id, 502)
        # Extra args are rejected before any root, platform or framework getter.
        # This real child executes both captured modules and the fixed entrypoint.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixed-helper.py'; path.write_bytes(program)
            result = subprocess.run([sys.executable, str(path), 'PRIVATE-ARGV'], input=b'PRIVATE-STDIN',
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(3, result.returncode)
        self.assertEqual(b'', result.stderr)
        self.assertEqual({'state': 'blocked', 'reason': 'macos_census_unavailable'}, json.loads(result.stdout))
        self.assertNotIn(b'PRIVATE', result.stdout)

    def test_dirty_get_flags_distinguish_untracked_clean_dirty_launch_and_future_bits(self):
        cases = {0:'untracked', 1:'tracked_clean', 3:'tracked_clean_idle_exit', 5:'tracked_dirty',
                 7:'tracked_dirty', 9:'launch_in_progress', 11:'launch_in_progress',
                 15:'launch_in_progress', 2:'unavailable', 4:'unavailable',
                 8:'unavailable', 16:'unavailable', -1:'unavailable'}
        for flags, expected in cases.items():
            with self.subTest(flags=flags): self.assertEqual(expected, census.dirty_posture(flags))
        self.assertEqual('unavailable', census.dirty_posture(True))

    def test_actual_ctypes_getter_reads_uint32_without_any_tracking_setter(self):
        actor = (11, 502, 1, 100, 2)
        @C.CFUNCTYPE(C.c_int, C.c_int, C.POINTER(C.c_uint32))
        def get_dirty(pid, flags):
            self.assertEqual(11, pid); flags[0] = 3; return 0
        proc = type('GetOnlyProc', (), {})(); proc.proc_get_dirty = get_dirty
        native = census.Native.__new__(census.Native)
        native.base = type('BoundBase', (), {'proc':proc})(); native.process = lambda pid: actor
        self.assertEqual('tracked_clean_idle_exit', native.activity(actor))
        identities = iter((actor, (11, 502, 1, 101, 2)))
        native.process = lambda pid: next(identities)
        self.assertEqual('identity_changed', native.activity(actor))

    def test_security_pointer_abi_and_all_architecture_validation_release_owned_refs(self):
        compiler = shutil.which('cc')
        if compiler is None: self.skipTest('controlled C ABI fixture requires C compiler')
        # A controlled native library only: no Apple/system native API is called.
        source = r"""
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
static int mode=0, allocated=0, released=0, flags_seen=-1, anchor_seen=0;
char kCFTypeDictionaryKeyCallBacks[32], kCFTypeDictionaryValueCallBacks[32];
static char pidkey;
void *kSecGuestAttributePid=&pidkey;
static void *owned(void) { allocated++; return malloc(8); }
void configure(int value) { mode=value; allocated=released=anchor_seen=0; flags_seen=-1; }
int outstanding(void) { return allocated-released; }
int all_architectures(void) { return flags_seen; }
int apple_requirement(void) { return anchor_seen; }
void CFRelease(void *ref) { if(ref) {released++; free(ref);} }
void *CFNumberCreate(void *a,long type,void *number) {
  if(type!=3 || *(int32_t*)number!=11) return NULL;
  return owned();
}
void *CFDictionaryCreate(void *a,void **keys,void **values,long n,void *kc,void *vc) {
  return (n==1 && keys[0]==kSecGuestAttributePid && values[0] && kc && vc)?owned():NULL;
}
void *CFStringCreateWithCString(void *a,const char *s,uint32_t encoding) {
  anchor_seen=strcmp(s,"anchor apple")==0 && encoding==0x08000100;
  return owned();
}
int32_t SecRequirementCreateWithString(void *s,uint32_t flags,void **out) {
  if(mode==4) return -1; *out=owned(); return 0;
}
int32_t SecCodeCopyGuestWithAttributes(void *host,void *dict,uint32_t flags,void **out) {
  if(mode==3 || host || flags) return -1; *out=owned(); return 0;
}
int32_t SecCodeCheckValidity(void *ref,uint32_t flags,void *req) { return mode==1?-1:0; }
int32_t SecCodeCopyStaticCode(void *ref,uint32_t flags,void **out) {
  if(mode==5) return -1; *out=owned(); return 0;
}
int32_t SecStaticCodeCheckValidity(void *ref,uint32_t flags,void *req) {
  flags_seen=flags; return mode==2?-1:0;
}
int proc_get_dirty(int pid,uint32_t *out) { *out=3; return 0; }
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); c = root/'controlled.c'; library = root/'controlled.so'
            c.write_text(source)
            flags = ['-dynamiclib'] if sys.platform == 'darwin' else ['-shared', '-fPIC']
            built = subprocess.run([compiler, *flags, '-o', str(library), str(c)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            self.assertEqual(0, built.returncode, 'controlled ABI library did not compile')
            lib = C.CDLL(str(library))
            def fn(lib, name, result, args):
                getter = getattr(lib, name); getter.restype=result; getter.argtypes=args
            fn(lib,'CFRelease',None,[C.c_void_p])
            fn(lib,'CFStringCreateWithCString',C.c_void_p,[C.c_void_p,C.c_char_p,C.c_uint32])
            fn(lib,'configure',None,[C.c_int])
            probe = type('ControlledProbe', (), {'cf':lib,'proc':lib,'_fn':staticmethod(fn)})()
            # Only constructor's fixed library lookup is replaced by this actual
            # controlled shared library; code() traverses complete ctypes ABI.
            with patch.object(census.C, 'CDLL', return_value=lib): native=census.Native(probe)
            actor=(11,502,1,100,2); native.process=lambda pid:actor
            for mode, expected in ((0,'apple_valid'),(1,'not_apple_valid'),(2,'not_apple_valid'),
                                   (3,'unavailable'),(4,'unavailable'),(5,'unavailable')):
                with self.subTest(mode=mode):
                    lib.configure(mode)
                    self.assertEqual(expected,native.code(actor))
                    self.assertEqual(0,lib.outstanding())
                    self.assertEqual(1,lib.apple_requirement())
                    if mode in (0,2): self.assertEqual(1,lib.all_architectures())

    def test_actual_read_only_atime_advancement_before_red_current_green(self):
        # Whole original implementation, real files and real os.read/fstat:
        # old stat_result equality mistakes source reads for source mutations.
        tools = Path(census.__file__).parent
        before = Path(__file__).parent/'fixtures'/'macos_idle_collector_atime_before.py'
        source_cases = (('before',before.read_bytes()), ('current',Path(census.__file__).read_bytes()))
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            check=root/'atime-check'; check.write_bytes(b'read only')
            old=check.stat(); os.utime(check,ns=(1,old.st_mtime_ns)); check.read_bytes()
            if check.stat().st_atime_ns==1: self.skipTest('fixture volume does not advance read access time')
            for kind, raw in source_cases:
                case=root/kind; case.mkdir()
                own=case/'tart_macos_idle_collector.py'; own.write_bytes(raw)
                probe=case/'tart_macos_probe.py'; probe.write_bytes((tools/'tart_macos_probe.py').read_bytes())
                namespace={'__name__':'_controlled_captured_source','__file__':str(own)}
                exec(compile(raw,str(own),'exec',dont_inherit=True),namespace)
                for path in (own,probe):
                    current=path.stat(); os.utime(path,ns=(1,current.st_mtime_ns))
                if kind=='before':
                    with self.assertRaisesRegex(namespace['CensusUnavailable'],'^macos_census_source_changed$'):
                        namespace['diagnostic_source'](self.base.machine_id,502)
                else:
                    captured=namespace['diagnostic_source'](self.base.machine_id,502)
                    self.assertGreater(len(captured),0)
                    self.assertNotEqual(1,probe.stat().st_atime_ns)
                    self.assertNotEqual(1,own.stat().st_atime_ns)

    def test_missing_target_no_default_and_no_native_calls(self):
        for machine, uid in ((None, 502), (self.base.machine_id, True), (self.base.machine_id, 0)):
            with self.assertRaises(census.CensusUnavailable): census.diagnostic_source(machine, uid)


if __name__ == '__main__': unittest.main()

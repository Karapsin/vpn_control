"""Native API decision causal test with actual controlled C ABI, not IOKit."""
import ast
import ctypes as C
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_tart_macos_leases as leases


_C = r'''
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
static int active,refs,creates,releases,present,inventory_error,inventory_live;
static uint32_t release_rc;
static int64_t key;
static char array;
static void *owned(void){refs++;return malloc(8);}
void Configure(uint32_t rc,int p,int error,int live){active=refs=creates=releases=0;present=p;inventory_error=error;inventory_live=live;release_rc=rc;}
void Expire(void){active=0;}
int References(void){return refs;} int Creates(void){return creates;} int Releases(void){return releases;}
void *CFStringCreateWithCString(void*a,const char*s,uint32_t e){return owned();}
void CFRelease(void*p){if(p){refs--;free(p);}}
int IOPMAssertionCreateWithDescription(void*k,void*n,void*d,void*r,void*b,double t,void*a,uint32_t*out){active=1;creates++;*out=123;return 0;}
int IOPMAssertionRelease(uint32_t id){releases++;if(id!=123)return 7;if(!release_rc)active=0;return (int32_t)release_rc;}
void *IOPMAssertionCopyProperties(uint32_t id){return (active||present)&&id==123?owned():0;}
int IOPMCopyAssertionsByProcess(void **out){if(inventory_error){*out=0;return 7;}*out=owned();return 0;}
long CFDictionaryGetCount(void*d){return inventory_live?1:0;}
void CFDictionaryGetKeysAndValues(void*d,void**keys,void**values){key=getpid();keys[0]=&key;values[0]=&array;}
unsigned long CFGetTypeID(void*p){return p==&key?1:2;}
unsigned long CFNumberGetTypeID(void){return 1;}
unsigned long CFArrayGetTypeID(void){return 2;}
int CFNumberGetValue(void*p,int type,void*out){*(int64_t*)out=key;return 1;}
long CFArrayGetCount(void*p){return inventory_live?1:0;}
'''


class ExpiredReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cc=shutil.which('cc')
        if cc is None:raise unittest.SkipTest('controlled C ABI fixture requires compiler')
        cls.temporary=tempfile.TemporaryDirectory();root=Path(cls.temporary.name)
        library=root/'controlled-lease.so'
        result=subprocess.run([cc,'-dynamiclib'if sys.platform=='darwin'else'-shared','-fPIC','-x','c','-',
                               '-o',str(library)],input=_C.encode(),capture_output=True,timeout=20)
        if result.returncode:raise AssertionError('controlled C ABI compile failed')
        cls.lib=C.CDLL(str(library))
        cls.lib.Configure.argtypes=[C.c_uint32,C.c_int,C.c_int,C.c_int];cls.lib.Configure.restype=None
        cls.lib.Expire.argtypes=[];cls.lib.Expire.restype=None
        archive=Path(__file__).parent/'fixtures/macos_lease_expiry_before.source'
        raw=archive.read_bytes()
        if hashlib.sha256(raw).hexdigest()!='fc20f5fcf1cb6ff1c715c574345e1a32cdc9d271c70881cf0e14f409725d8270':
            raise AssertionError('preserved native failure source changed')
        cls.before=next(node.value.value for node in ast.parse(raw).body if isinstance(node,ast.Assign)
                        and any(isinstance(target,ast.Name)and target.id=='_ASSERTIONS'for target in node.targets))
    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()
    def api(self,source,rc=0xe00002c2,present=0,error=0,live=0):
        lib=self.lib;lib.Configure(rc,present,error,live)
        scope={'D':vars(jobs),'P':{}};exec(source,scope)
        class Fixture:
            cf=io=lib
            def __init__(self):
                self._fn(lib,'CFStringCreateWithCString',C.c_void_p,[C.c_void_p,C.c_char_p,C.c_uint32])
                self._fn(lib,'CFRelease',None,[C.c_void_p])
            @staticmethod
            def _fn(lib,name,result,args):
                fn=getattr(lib,name);fn.restype=result;fn.argtypes=args
        scope['P']['Native']=Fixture
        class Api(scope['MacAssertions']):
            def validate_identity(self):pass
            def admit(self):pass
        value=Api({});identity=value.create('PreventUserIdleDisplaySleep',3)
        self.assertEqual(123,identity);lib.Expire()
        return value,identity
    def test_original_c_api_expired_bad_argument_before_red_fixed_green_with_os_absence(self):
        old,identity=self.api(self.before)
        with self.assertRaisesRegex(jobs.DurableJobError,'macos_assertion_release_failed'):old.release(identity,True)
        self.assertEqual((1,1,0),(self.lib.Creates(),self.lib.Releases(),self.lib.References()))
        fixed,identity=self.api(leases._ASSERTIONS);fixed.release(identity,True)
        self.assertEqual((1,1,0),(self.lib.Creates(),self.lib.Releases(),self.lib.References()))
    def test_bad_argument_alone_or_missing_ownership_expiry_or_inventory_never_succeeds(self):
        for variant in ('not_expired','unconfirmed','properties_present','inventory_error','inventory_live','other_error'):
            with self.subTest(variant=variant):
                api,identity=self.api(leases._ASSERTIONS,rc=7 if variant=='other_error' else 0xe00002c2,
                    present=int(variant=='properties_present'),error=int(variant=='inventory_error'),live=int(variant=='inventory_live'))
                if variant=='unconfirmed':api.confirmed.clear()
                with self.assertRaises(jobs.DurableJobError):api.release(identity,variant!='not_expired')
                self.assertEqual((1,1,0),(self.lib.Creates(),self.lib.Releases(),self.lib.References()))
    def test_regular_release_and_expired_not_found_still_require_properties_absence(self):
        for rc in (0,0xe00002f0):
            api,identity=self.api(leases._ASSERTIONS,rc=rc);api.release(identity,rc!=0)
            self.assertEqual((1,1,0),(self.lib.Creates(),self.lib.Releases(),self.lib.References()))


if __name__=='__main__':unittest.main()

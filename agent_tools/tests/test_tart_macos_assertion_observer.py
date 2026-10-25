"""Actual controlled C ABI + complete preserved private caller RED/GREEN."""
import ast
import contextlib
import ctypes as C
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

from agent_tools import tart_macos_assertion_observer as observer

_C=r'''
#include <stdint.h>
#include <stdlib.h>
static int64_t pid=71; static char array,row1,row2;
static int refs,foreigncalls;
int References(void){return refs;} int ForeignCalls(void){return foreigncalls;}
void Configure(void){refs=foreigncalls=0;}
int IOPMCopyAssertionsByProcess(void **out){refs++;*out=malloc(8);return 0;}
void *IOPMAssertionCopyProperties(uint32_t id){foreigncalls++;return 0;}
void CFRelease(void *p){refs--;if(p!=&row1&&p!=&row2)free(p);}
void *CFRetain(void*p){refs++;return p;}
long CFDictionaryGetCount(void*p){return 1;}
void CFDictionaryGetKeysAndValues(void*p,void**keys,void**values){keys[0]=&pid;values[0]=&array;}
unsigned long CFGetTypeID(void*p){return p==&pid?1:p==&array?2:4;}
unsigned long CFNumberGetTypeID(void){return 1;}
unsigned long CFArrayGetTypeID(void){return 2;}
unsigned long CFDictionaryGetTypeID(void){return 4;}
int CFNumberGetValue(void*p,int type,void*out){*(int64_t*)out=pid;return 1;}
long CFArrayGetCount(void*p){return 2;}
void *CFArrayGetValueAtIndex(void*p,long index){return index?&row2:&row1;}
long Row(void*p){return p==&row1?0:1;}
'''


class OriginalObserverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler=shutil.which('cc')
        if compiler is None:raise unittest.SkipTest('controlled C ABI requires compiler')
        cls.temporary=tempfile.TemporaryDirectory();root=Path(cls.temporary.name);library=root/'observer.so'
        result=subprocess.run([compiler,'-dynamiclib'if sys.platform=='darwin'else'-shared','-fPIC','-x','c','-','-o',str(library)],
                              input=_C.encode(),capture_output=True,timeout=20)
        if result.returncode:raise AssertionError('controlled observer ABI compile failed')
        cls.lib=C.CDLL(str(library))
        declarations={'IOPMCopyAssertionsByProcess':(C.c_int,[C.POINTER(C.c_void_p)]),
            'IOPMAssertionCopyProperties':(C.c_void_p,[C.c_uint32]),'CFRelease':(None,[C.c_void_p]),
            'CFDictionaryGetCount':(C.c_long,[C.c_void_p]),
            'CFDictionaryGetKeysAndValues':(None,[C.c_void_p,C.POINTER(C.c_void_p),C.POINTER(C.c_void_p)]),
            'CFGetTypeID':(C.c_ulong,[C.c_void_p]),'CFNumberGetTypeID':(C.c_ulong,[]),
            'CFArrayGetTypeID':(C.c_ulong,[]),'CFNumberGetValue':(C.c_int,[C.c_void_p,C.c_int,C.c_void_p]),
            'CFArrayGetCount':(C.c_long,[C.c_void_p]),'Row':(C.c_long,[C.c_void_p])}
        for name,(result,args)in declarations.items():
            fn=getattr(cls.lib,name);fn.restype=result;fn.argtypes=args
        raw=(Path(__file__).parent/'fixtures/macos_foreign_assertion_observer_before.source').read_bytes()
        if hashlib.sha256(raw).hexdigest()!='008546167008f221b11af94de1f9ad15f85423863c7ae4efb72cb84b6f1eeaa4':
            raise AssertionError('original native caller beforeimage changed')
        tree=ast.parse(raw)
        cls.read_original=next(node.value.value for node in tree.body if isinstance(node,ast.Assign)
            and any(isinstance(t,ast.Name)and t.id=='READ_ORIGINAL'for t in node.targets))
        cls.cancel_ast=next(node for node in tree.body if isinstance(node,ast.FunctionDef)and node.name=='cancel_case')
    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()
    def setUp(self):
        self.lib.Configure();self.owner={'pid':71,'birth':'darwin:100:1'}
        self.expected={35252:'PreventUserIdleSystemSleep',353:'PreventUserIdleDisplaySleep'}
        self.properties=[{'AssertionId':key,'AssertType':kind,'AssertPID':71,'AssertLevel':255,
            'AssertName':'VPNControlTemporaryGUILease','TimeoutAction':'TimeoutActionRelease','TimeoutSeconds':90}
            for key,kind in self.expected.items()]
        def value(pointer):
            try:return self.properties[self.lib.Row(pointer)]
            finally:self.lib.CFRelease(pointer)
        self.api=SimpleNamespace(cf=self.lib,io=self.lib,validate_identity=lambda:None,
            native=SimpleNamespace(value=value),owner_absent=lambda owner:False)
        self.birth=lambda pid:'darwin:100:1'
    def check(self):return observer.verify_owned_assertions(self.api,self.owner,self.expected,self.birth)
    def test_whole_original_native_caller_foreign_properties_before_red_fixed_pid_array_green(self):
        def evidence(case,op,fixed):
            acquired={'leaseOwner':self.owner,'assertions':list(self.expected)}
            j=SimpleNamespace(observe=lambda *a,**k:{'state':'running'},_record=lambda *a:acquired,_birth=self.birth)
            scope={'binding':lambda:None,'namespace':lambda b:(Path('/unused'),{'jobGeneration':[1,2]}),
                'CONFIG':{'operation':op},'original':lambda *a:None,'J':j,'P':SimpleNamespace(api=self.api),
                'L':SimpleNamespace(_ASSERTIONS="MacAssertions=lambda binding:P['api']",asdict=lambda b:{}),
                'vars':lambda item:item if isinstance(item,dict)else item.__dict__,'json':json}
            scope['P']={'api':self.api}
            j.job_binding=lambda:None
            # Original binding object API is used exactly by complete READ_ORIGINAL.
            scope['binding']=lambda:SimpleNamespace(job_binding=lambda:None)
            body=self.read_original
            if fixed:
                start=body.index('properties=[]\n');end=body.index('value={',start)
                body=body[:start]+'''proof=verify_owned_assertions(api,owner,expected,J._birth)
properties=[{'id':key,'present':proof['active']}for key in proof['assertions']]
'''+body[end:]
                scope.update(verify_owned_assertions=observer.verify_owned_assertions,expected=self.expected)
            output=io.StringIO()
            with contextlib.redirect_stdout(output):exec(body,scope)
            return json.loads(output.getvalue())
        for fixed in (False,True):
            calls=[]
            base={'admit_case':lambda *a:(Path('/unused'),'original-uuid'),
                  'request':lambda case,action,*args:calls.append(action),
                  'helper':lambda:{'record':lambda *a:None}}
            scope={'BASE':base,'evidence':lambda case,op:evidence(case,op,fixed),
                   'finish':lambda *a:'same_original_cancelled'}
            exec(compile(ast.Module(body=[self.cancel_ast],type_ignores=[]),'<whole-original-cancel-caller>','exec'),scope)
            if not fixed:
                with self.assertRaisesRegex(AssertionError,'native_assertions_not_active'):scope['cancel_case']()
                self.assertEqual(['acquire'],calls)
            else:
                self.assertEqual('same_original_cancelled',scope['cancel_case']());self.assertEqual(['acquire','cancel'],calls)
            self.assertEqual(0,self.lib.References())
        self.assertGreater(self.lib.ForeignCalls(),0)
    def test_fixed_getter_does_not_use_foreign_copyproperties(self):
        self.assertTrue(self.check()['active']);self.assertEqual(0,self.lib.ForeignCalls());self.assertEqual(0,self.lib.References())
    def test_missing_duplicate_wrongpid_kind_level_or_timeout_never_counts_active(self):
        originals=[dict(value)for value in self.properties]
        for change in ({'AssertionId':353},{'AssertionId':999},{'AssertPID':72},{'AssertType':'PRIVATE'},
                       {'AssertLevel':0},{'TimeoutSeconds':True},{'TimeoutAction':'PRIVATE'}):
            with self.subTest(change=change):
                self.properties=[dict(value)for value in originals];self.properties[0].update(change)
                with self.assertRaisesRegex(ValueError,'original_assertion_inventory_unverified'):self.check()
                self.assertEqual(0,self.lib.References())
    def test_owner_generation_change_before_or_after_native_snapshot_blocks(self):
        self.birth=lambda pid:'darwin:changed'
        with self.assertRaises(ValueError):self.check()
        births=iter(('darwin:100:1','darwin:changed'));self.birth=lambda pid:next(births)
        with self.assertRaises(ValueError):self.check()
        self.assertEqual(0,self.lib.References())


if __name__=='__main__':unittest.main()

"""Controlled real C ABI network getters; no coordinator network observation."""
import ctypes as C
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agent_tools import tart_macos_network_census as network


_C = r'''
#include <stdint.h>
#include <stddef.h>
#include <string.h>
struct address { uint8_t length,family;uint16_t index;uint8_t kind,nlen,alen,slen;char name[16]; };
struct node {struct node *next;char *name;unsigned flags;struct address *address;void *mask,*dest,*data;};
struct object {unsigned long type;const char *text;};
static struct object name={2,"name"},preferences={7,"preferences"},array={3,"array"},
 service={4,"service"},identity={2,"PRIVATE-service"},ether={5,"ether"},ppp={5,"ppp"},
 provider={5,"provider"},etherkind={2,"Ethernet"},pppkind={2,"PPP"},
 providerkind={2,"PRIVATE-provider"},bsd={2,"en0"},connection={8,"connection"};
static struct address link;
static struct node row;
static int mode,refs,frees,creates,statuscalls,badargs;
void set_mode(int value){mode=value;refs=frees=creates=statuscalls=badargs=0;}
int outstanding(void){return refs;}int free_count(void){return frees;}
int connection_count(void){return creates;}int status_count(void){return statuscalls;}
int bad_arguments(void){return badargs;}
int getifaddrs(struct node **head){
 memset(&link,0,sizeof(link));memset(&row,0,sizeof(row));
 link.length=20;link.family=18;link.index=1;link.kind=6;link.nlen=3;memcpy(link.name,"en0",3);
 row.name="en0";row.flags=0x43;row.address=&link;
 if(mode==4){row.name="utun0";row.flags=0x51;link.nlen=5;memcpy(link.name,"utun0",5);link.kind=1;}
 if(mode==5){row.next=&row;}if(mode==6){link.length=4;}
 if(mode==7){link.family=2;}*head=&row;return mode==8?-1:0;
}
void freeifaddrs(struct node *head){if(head!=&row)badargs++;frees++;}
void *CFRetain(void *object){refs++;return object;}
void CFRelease(void *object){if(!object)badargs++;refs--;}
void *CFStringCreateWithCString(void *allocator,const char *text,uint32_t encoding){
 if(allocator||encoding!=0x08000100||strcmp(text,"vpn-control-readonly-network-census"))badargs++;
 refs++;return &name;
}
unsigned long CFGetTypeID(struct object *object){return object->type;}
unsigned long CFArrayGetTypeID(void){return 3;}
long CFArrayGetCount(void *object){if(object!=&array)badargs++;return mode==9?-1:1;}
void *CFArrayGetValueAtIndex(void *object,long index){if(object!=&array||index)badargs++;return &service;}
const char *text_value(struct object *object){return object->text;}
void *SCPreferencesCreate(void *allocator,void *label,void *prefsID){
 if(allocator||label!=&name||prefsID)badargs++;refs++;return &preferences;
}
void *SCNetworkServiceCopyAll(void *prefs){if(prefs!=&preferences)badargs++;refs++;return &array;}
unsigned long SCNetworkServiceGetTypeID(void){return 4;}
void *SCNetworkServiceGetServiceID(void *value){if(value!=&service)badargs++;return &identity;}
void *SCNetworkServiceGetInterface(void *value){if(value!=&service)badargs++;
 return mode==1||mode==2||mode==10?&ppp:mode==3?&provider:&ether;}
unsigned char SCNetworkServiceGetEnabled(void *value){if(value!=&service)badargs++;return 1;}
unsigned long SCNetworkInterfaceGetTypeID(void){return 5;}
void *SCNetworkInterfaceGetInterfaceType(void *value){return value==&ppp?&pppkind:value==&provider?&providerkind:&etherkind;}
void *SCNetworkInterfaceGetBSDName(void *value){return value==&ether?&bsd:NULL;}
void *SCNetworkInterfaceGetInterface(void *value){return value==&ppp?&ether:NULL;}
void *SCNetworkConnectionCreateWithServiceID(void *allocator,void *sid,void *callback,void *context){
 if(allocator||sid!=&identity||callback||context)badargs++;creates++;refs++;return &connection;
}
int32_t SCNetworkConnectionGetStatus(void *value){if(value!=&connection)badargs++;statuscalls++;return mode==2?2:mode==10?-1:0;}
'''


class NetworkCAbiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler=shutil.which('cc')
        if compiler is None or sys.platform=='win32':raise unittest.SkipTest('controlled C ABI requires POSIX C compiler')
        cls.directory=tempfile.TemporaryDirectory();root=Path(cls.directory.name)
        source=root/'network.c';source.write_text(_C);library=root/'network.dylib'
        build=subprocess.run([compiler,'-shared','-fPIC',str(source),'-o',str(library)],capture_output=True,timeout=20)
        if build.returncode:raise AssertionError('controlled network ABI compile failed')
        cls.lib=C.CDLL(str(library))
        for name in ('outstanding','free_count','connection_count','status_count','bad_arguments'):
            getattr(cls.lib,name).restype=C.c_int;getattr(cls.lib,name).argtypes=[]
        cls.lib.set_mode.argtypes=[C.c_int];cls.lib.text_value.argtypes=[C.c_void_p];cls.lib.text_value.restype=C.c_char_p

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def setUp(self):
        self.lib.set_mode(0)
        def fn(lib,name,result,args):
            value=getattr(lib,name);value.restype=result;value.argtypes=args
        def value(owned):
            try:return self.lib.text_value(owned).decode('utf-8')
            finally:self.lib.CFRelease(owned)
        self.base=SimpleNamespace(lib=self.lib,cf=self.lib,sc=self.lib,_fn=fn,value=value)
        fn(self.lib,'CFRelease',None,[C.c_void_p])
        fn(self.lib,'CFStringCreateWithCString',C.c_void_p,[C.c_void_p,C.c_char_p,C.c_uint32])
        with patch.object(network.sys,'platform','darwin'):self.native=network.NativeNetwork(self.base)

    def tearDown(self):
        self.assertEqual(0,self.lib.outstanding(),'every copied/retained CF object is released')
        self.assertEqual(0,self.lib.bad_arguments(),'only fixed GET signatures and null callbacks')

    def facts(self,mode):
        self.lib.set_mode(mode);one=self.native.snapshot();two=self.native.snapshot()
        return network.review(one,two)

    def test_actual_interface_and_service_getters_keep_private_values_inside(self):
        result=self.facts(0)
        self.assertTrue(result['visibilityComplete']);self.assertTrue(result['activityClear'])
        self.assertEqual(1,result['interfaceCount']);self.assertEqual(1,result['serviceCount'])
        self.assertEqual(0,self.lib.connection_count());self.assertEqual(2,self.lib.free_count())
        self.assertNotIn('PRIVATE',json.dumps(result));self.assertNotIn('en0',json.dumps(result))

    def test_ppp_status_is_applied_only_to_supported_services(self):
        self.assertTrue(self.facts(1)['activityClear'])
        self.assertEqual(2,self.lib.connection_count());self.assertEqual(2,self.lib.status_count())
        active=self.facts(2)
        self.assertFalse(active['activityClear']);self.assertEqual(1,active['activeConnectionCount'])
        self.assertEqual(['sc_connection_active'],active['blockers'])
        invalid=self.facts(10)
        self.assertFalse(invalid['activityClear']);self.assertIn('sc_connection_status_unavailable',invalid['blockers'])

    def test_unknown_network_extension_provider_cannot_borrow_ppp_status(self):
        result=self.facts(3)
        self.assertFalse(result['activityClear']);self.assertEqual(1,result['unsupportedProviderCount'])
        self.assertEqual(0,self.lib.connection_count());self.assertNotIn('PRIVATE',str(result))

    def test_kernel_tunnel_blocks_even_without_registered_service(self):
        result=self.facts(4)
        self.assertEqual(1,result['tunnelCount']);self.assertFalse(result['activityClear'])
        self.assertEqual(1,result['activeKernelTunnelCount'])
        self.assertEqual(0,result['downUnaddressedKernelTunnelCount'])
        self.assertEqual(['kernel_tunnel_activity_unqualified'],result['blockers'])
        self.assertNotIn('utun',str(result))

    def test_cycle_bad_link_missing_link_and_native_failure_free_exact_original_list(self):
        for mode in (5,6,7,8):
            with self.subTest(mode=mode):
                self.lib.set_mode(mode)
                with self.assertRaises(network.NetworkUnavailable):self.native.interfaces()
                self.assertEqual(1,self.lib.free_count())
        self.lib.set_mode(9)
        with self.assertRaisesRegex(network.NetworkUnavailable,'macos_network_services_invalid'):self.native.services()

    def test_real_darwin_header_layout_matches_without_any_network_getter(self):
        if sys.platform!='darwin':self.skipTest('Darwin struct layout requires Apple headers')
        root=Path(self.directory.name);path=root/'layout.c';program=root/'layout'
        path.write_text('#include <ifaddrs.h>\n#include <stddef.h>\n#include <stdio.h>\nint main(void){printf("%zu %zu %zu %zu",sizeof(struct ifaddrs),offsetof(struct ifaddrs,ifa_name),offsetof(struct ifaddrs,ifa_flags),offsetof(struct ifaddrs,ifa_addr));}\n')
        subprocess.run([shutil.which('cc'),str(path),'-o',str(program)],capture_output=True,timeout=20,check=True)
        result=subprocess.run([str(program)],capture_output=True,timeout=5,check=True)
        self.assertEqual([C.sizeof(network._Ifaddrs),network._Ifaddrs.name.offset,network._Ifaddrs.flags.offset,
                          network._Ifaddrs.address.offset],[int(item)for item in result.stdout.split()])


class NetworkTargetAndSourceTests(unittest.TestCase):
    def setUp(self):
        self.machine='11111111-1111-4111-8111-111111111111';self.boot='22222222-2222-4222-8222-222222222222'
        self.snapshot=(((b'PRIVATE-if',0x43,6,(18,)),),(('PRIVATE-service',True,(('Ethernet','PRIVATE-if'),),None),))
        self.base=SimpleNamespace(machine=lambda:self.machine,boot=lambda:(self.boot,1))
        self.calls=[]
        self.native=SimpleNamespace(snapshot=lambda:self.calls.append(1)or self.snapshot)

    def collect(self,**changes):
        inputs=dict(machine=self.machine,boot=self.boot,uid=502,principal='toolrecovery');inputs.update(changes)
        with patch.object(network.os,'geteuid',return_value=502),patch.object(network,'pwd',
                SimpleNamespace(getpwuid=lambda uid:SimpleNamespace(pw_name='toolrecovery'))):
            return network.collect(self.base,self.native,**inputs)

    def test_explicit_target_before_and_after_read_only_getters(self):
        for change in ({'machine':'33333333-3333-4333-8333-333333333333'},{'boot':'33333333-3333-4333-8333-333333333333'},
                       {'uid':503},{'principal':'different'}):
            with self.subTest(change=change):
                self.calls.clear()
                with self.assertRaises(network.NetworkUnavailable):self.collect(**change)
                self.assertEqual([],self.calls)
        result=self.collect()
        self.assertEqual(2,len(self.calls));self.assertFalse(result['idleAuthority']);self.assertFalse(result['nativeQualified'])
        self.assertNotIn('PRIVATE',json.dumps(result))
        sequence=iter(((self.boot,1),('33333333-3333-4333-8333-333333333333',1)))
        self.base.boot=lambda:next(sequence)
        with self.assertRaisesRegex(network.NetworkUnavailable,'macos_network_target_changed'):self.collect()

    def test_changing_snapshot_and_unknown_or_duplicate_shapes_cannot_prove_clear(self):
        with self.assertRaisesRegex(network.NetworkUnavailable,'macos_network_snapshot_changed'):
            network.review(self.snapshot,(self.snapshot[0],()))
        for snapshot in ((self.snapshot[0]*2,self.snapshot[1]),((),self.snapshot[1]),
                         (self.snapshot[0],self.snapshot[1]*2),(((b'PRIVATE',),),self.snapshot[1])):
            with self.subTest(snapshot=snapshot):
                with self.assertRaises(network.NetworkUnavailable):network.review(snapshot,snapshot)
        unknown=(((b'PRIVATE-if',0x43,1,(18,)),),())
        result=network.review(unknown,unknown)
        self.assertFalse(result['activityClear'])
        self.assertEqual(['kernel_interface_role_unqualified'],result['blockers'])
        self.assertNotIn('PRIVATE',str(result))
        down=(((b'PRIVATE-if',0x10,0x37,(18,)),),())
        result=network.review(down,down)
        self.assertEqual(1,result['downUnaddressedKernelTunnelCount'])
        self.assertEqual(0,result['activeKernelTunnelCount'])
        self.assertEqual(0,result['addressedKernelTunnelCount'])
        self.assertFalse(result['activityClear'])
        self.assertEqual(['kernel_tunnel_activity_unqualified'],result['blockers'])

    def test_fixed_source_captures_only_two_modules_and_refuses_loaded_disk_drift(self):
        if network.os.name!='posix':self.skipTest('fixed Mac source builder requires POSIX nofollow')
        inputs=dict(machine=self.machine,boot=self.boot,uid=502,principal='toolrecovery')
        source=network.diagnostic_source(**inputs)
        compile(source,'<network-generated>','exec')
        self.assertIn(b'idleAuthority',source);self.assertNotIn(b'NEVPNManager',source)
        with patch.object(network,'_EXECUTING_CODE',None):
            with self.assertRaisesRegex(network.NetworkUnavailable,'macos_network_source_changed'):
                network.diagnostic_source(**inputs)


if __name__=='__main__':unittest.main()

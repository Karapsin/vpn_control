"""Real fixed ABI parser/getter tests without observing any host socket."""
import ctypes as C
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agent_tools import tart_macos_tunnel_owners as owners


def record(*,unit=1,socket=100,pcb=200,name=b'com.apple.net.utun_control',state=2,kind=6,family=32):
    raw=bytearray(792)
    for offset,value,fmt in ((160,socket,'Q'),(168,pcb,'Q'),(184,family,'i'),(192,state,'H'),
                             (256,kind,'i'),(264,17,'I'),(284,unit,'I')):
        struct.pack_into('<'+fmt,raw,offset,value)
    raw[288:288+len(name)]=name
    return bytes(raw)


class TunnelParserTests(unittest.TestCase):
    def setUp(self):
        self.actor=(20,0,1,1000,1);self.value=owners.parse_socket(record())
        self.interfaces=((b'utun0',0x51,1,(18,30)),)

    def test_exact_primary_unit_minus_one_join_emits_only_kernel_actor(self):
        result=owners.join(self.interfaces,[(self.actor,{7:self.value})])
        self.assertTrue(result['currentHolderVisibilityComplete'])
        self.assertEqual([{'pid':20,'uid':0,'ppid':1,'birth':'darwin:1000:1','matchedTunnelCount':1}],result['holders'])
        self.assertFalse(result['providerActivityQualified'])
        self.assertEqual('unavailable',result['creatorAndTransferVisibility'])
        self.assertNotIn('utun',json.dumps(result));self.assertNotIn('control',json.dumps(result))
        wrong=owners.parse_socket(record(unit=2))
        result=owners.join(self.interfaces,[(self.actor,{7:wrong})])
        self.assertFalse(result['currentHolderVisibilityComplete'])
        self.assertIn('active_tunnel_holder_unresolved',result['blockers'])

    def test_duplicate_shared_transferred_or_reused_unit_cannot_prove_original_ownership(self):
        other=(21,502,1,1000,2)
        cases=([(self.actor,{7:self.value,8:self.value})],
               [(self.actor,{7:self.value}),(other,{8:self.value})],
               [(self.actor,{7:self.value}),(other,{8:owners.parse_socket(record(socket=101,pcb=201))})])
        for holders in cases:
            result=owners.join(self.interfaces,holders)
            self.assertFalse(result['currentHolderVisibilityComplete'])
            self.assertIn('duplicate_or_shared_tunnel_holder',result['blockers'])
        # Even one current holder cannot authenticate the original creator or
        # historical transfer: no such kernel field exists in this GET record.
        transferred=owners.join(self.interfaces,[(other,{8:self.value})])
        self.assertEqual('current_fd_holders_only',transferred['ownershipScope'])
        self.assertFalse(transferred['providerActivityQualified'])

    def test_abi_truncation_unterminated_name_unit_and_transition_flags_refuse(self):
        for raw in (record()[:-1],record(unit=0),record(unit=65537),record(state=4),record(state=10),
                    record(socket=0),record(family=2),record(name=b'X'*96)):
            with self.subTest(rawlen=len(raw)),self.assertRaises(owners.OwnershipUnavailable):owners.parse_socket(raw)
        private=owners.parse_socket(record(name=b'PRIVATE-control'))
        self.assertEqual([],owners.join(self.interfaces,[(self.actor,{7:private})])['holders'])

    def test_actual_darwin_primary_header_layout_matches_all_parser_offsets(self):
        if sys.platform!='darwin' or shutil.which('cc')is None:self.skipTest('Darwin primary header layout needs Apple compiler')
        source='#include <stdio.h>\n#include <stddef.h>\n#include <sys/proc_info.h>\nint main(void){printf("%zu %zu %zu %zu %zu %zu %zu %zu %zu %zu %u %u %u",sizeof(struct socket_fdinfo),offsetof(struct socket_fdinfo,psi.soi_kind),offsetof(struct socket_fdinfo,psi.soi_family),offsetof(struct socket_fdinfo,psi.soi_so),offsetof(struct socket_fdinfo,psi.soi_pcb),offsetof(struct socket_fdinfo,psi.soi_proto.pri_kern_ctl.kcsi_unit),offsetof(struct socket_fdinfo,psi.soi_proto.pri_kern_ctl.kcsi_name),sizeof(((struct kern_ctl_info*)0)->kcsi_name),sizeof(struct proc_fdinfo),offsetof(struct proc_fdinfo,proc_fdtype),PROC_PIDLISTFDS,PROC_PIDFDSOCKETINFO,PROX_FDTYPE_SOCKET);}\n'
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);(root/'layout.c').write_text(source)
            subprocess.run([shutil.which('cc'),str(root/'layout.c'),'-o',str(root/'layout')],capture_output=True,timeout=20,check=True)
            result=subprocess.run([str(root/'layout')],capture_output=True,timeout=5,check=True)
        self.assertEqual([792,256,184,160,168,284,288,96,8,4,1,3,2],[int(value)for value in result.stdout.split()])


_C=r'''
#include <stdint.h>
#include <string.h>
#include <errno.h>
struct fd {int32_t number;uint32_t kind;};
static int mode,calls,bad;
void reset(int value){mode=value;calls=bad=0;}int badargs(void){return bad;}
int proc_pidinfo(int pid,int flavor,uint64_t arg,void *buffer,int length){
 if(pid!=20||flavor!=1||arg)bad++;
 if(mode==1){errno=13;return 0;}if(!buffer)return 8;
 if(length<8){bad++;return 0;}struct fd value={7,2};memcpy(buffer,&value,8);return 8;
}
int proc_pidfdinfo(int pid,int fd,int flavor,unsigned char *buffer,int length){
 if(pid!=20||fd!=7||flavor!=3||length!=792)bad++;
 if(mode==2)return 0;memset(buffer,0,length);
 uint64_t socket=(mode==3&&calls++?101:100),pcb=200;
 int32_t family=32,kind=6;uint32_t control=17,unit=1;uint16_t state=2;
 memcpy(buffer+160,&socket,8);memcpy(buffer+168,&pcb,8);memcpy(buffer+184,&family,4);
 memcpy(buffer+192,&state,2);memcpy(buffer+256,&kind,4);memcpy(buffer+264,&control,4);
 memcpy(buffer+284,&unit,4);strcpy((char*)buffer+288,"com.apple.net.utun_control");return 792;
}
'''


class TunnelNativeCAbiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sys.platform=='win32' or shutil.which('cc')is None:raise unittest.SkipTest('controlled getter C ABI requires POSIX compiler')
        cls.directory=tempfile.TemporaryDirectory();root=Path(cls.directory.name)
        (root/'native.c').write_text(_C)
        subprocess.run([shutil.which('cc'),'-shared','-fPIC',str(root/'native.c'),'-o',str(root/'native.dylib')],
                       capture_output=True,timeout=20,check=True)
        cls.lib=C.CDLL(str(root/'native.dylib'),use_errno=True)
        cls.lib.reset.argtypes=[C.c_int];cls.lib.badargs.restype=C.c_int
    @classmethod
    def tearDownClass(cls):cls.directory.cleanup()
    def setUp(self):
        self.lib.reset(0);self.actor=(20,0,1,1000,1)
        def fn(lib,name,result,args):value=getattr(lib,name);value.restype=result;value.argtypes=args
        fn(self.lib,'proc_pidinfo',C.c_int,[C.c_int,C.c_int,C.c_uint64,C.c_void_p,C.c_int])
        self.processes=SimpleNamespace(process=lambda pid:self.actor)
        with patch.object(owners.sys,'platform','darwin'):
            self.native=owners.NativeHolders(SimpleNamespace(proc=self.lib,_fn=fn),self.processes)
    def tearDown(self):self.assertEqual(0,self.lib.badargs())
    def test_complete_fixed_getters_and_two_socket_generations(self):
        count,sockets=self.native.actor(self.actor)
        self.assertEqual(1,count);self.assertEqual({7:owners.parse_socket(record())},sockets)
    def test_permission_short_reply_and_reused_descriptor_fail_closed(self):
        for mode,reason in ((1,'macos_fd_visibility_unavailable'),(2,'macos_socket_visibility_unavailable'),(3,'macos_socket_generation_changed')):
            self.lib.reset(mode)
            with self.subTest(mode=mode),self.assertRaisesRegex(owners.OwnershipUnavailable,reason):self.native.actor(self.actor)
    def test_pid_birth_change_refuses_before_reading_an_unrelated_reused_pid(self):
        self.processes.process=lambda pid:(20,0,1,1001,1)
        with self.assertRaisesRegex(owners.OwnershipUnavailable,'macos_fd_owner_changed'):self.native.actor(self.actor)


class TunnelTargetAndSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.inputs=dict(machine='11111111-1111-4111-8111-111111111111',
            boot='22222222-2222-4222-8222-222222222222',uid=502,principal='toolrecovery',agent=(5,502,1,1000,1))
        self.actor=(20,0,1,1000,2);self.records={20:(self.actor,'unmanaged')}
        self.interfaces=((b'utun0',0x51,1,(18,30)),)
        self.base=SimpleNamespace(machine=lambda:self.inputs['machine'],boot=lambda:(self.inputs['boot'],1))
        self.processes=SimpleNamespace(process=lambda pid:self.inputs['agent'],snapshot=lambda:self.records)
        self.network=SimpleNamespace(interfaces=lambda:self.interfaces)
        self.calls=[]
        self.native=SimpleNamespace(platform=lambda:self.calls.append('platform'),
            actor=lambda actor:(1,{7:owners.parse_socket(record())}))
    def collect(self,**changes):
        with patch.object(owners.os,'geteuid',return_value=502),patch.object(owners.os,'getppid',return_value=5),\
                patch.object(owners,'pwd',SimpleNamespace(getpwuid=lambda uid:SimpleNamespace(pw_name='toolrecovery'))):
            return owners.collect(self.base,self.processes,self.network,self.native,**{**self.inputs,**changes})
    def test_wrong_selected_machine_boot_account_or_agent_refuses_before_any_fd_work(self):
        for change in ({'machine':'33333333-3333-4333-8333-333333333333'},
                       {'boot':'33333333-3333-4333-8333-333333333333'},{'principal':'different'},{'uid':503},
                       {'agent':(6,502,1,1000,1)}):
            self.calls.clear()
            with self.subTest(change=change),self.assertRaises(owners.OwnershipUnavailable):self.collect(**change)
            self.assertEqual([],self.calls)
    def test_current_holder_proof_is_not_provider_or_idle_authority(self):
        result=self.collect()
        self.assertTrue(result['tunnelOwners']['currentHolderVisibilityComplete'])
        self.assertFalse(result['tunnelOwners']['providerActivityQualified'])
        self.assertFalse(result['idleAuthority']);self.assertFalse(result['nativeQualified'])
    def test_interface_change_owner_visibility_failure_and_process_exit_remain_blockers(self):
        snapshots=iter((self.interfaces,((b'utun1',0x51,1,(18,30)),)))
        self.network.interfaces=lambda:next(snapshots)
        with self.assertRaisesRegex(owners.OwnershipUnavailable,'macos_tunnel_snapshot_changed'):self.collect()
        self.network.interfaces=lambda:self.interfaces
        snapshots=iter((self.records,{}));self.processes.snapshot=lambda:next(snapshots)
        with self.assertRaisesRegex(owners.OwnershipUnavailable,'macos_tunnel_snapshot_changed'):self.collect()
        self.processes.snapshot=lambda:self.records
        self.native.actor=lambda actor:(_ for _ in ()).throw(owners.OwnershipUnavailable('macos_fd_visibility_unavailable'))
        result=self.collect()
        self.assertFalse(result['tunnelOwners']['currentHolderVisibilityComplete'])
        self.assertEqual('macos_fd_visibility_unavailable',result['tunnelOwners']['unavailableActors'][0]['reason'])
    def test_complete_generated_receiver_extra_argument_stops_before_any_framework(self):
        if owners.os.name!='posix':self.skipTest('Mac source renderer requires POSIX nofollow')
        source=owners.source(**self.inputs)
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'receiver.py';path.write_bytes(source)
            result=subprocess.run([sys.executable,str(path),'forbidden'],capture_output=True,timeout=10)
        self.assertEqual(3,result.returncode);self.assertEqual(b'',result.stderr)
        self.assertEqual({'state':'blocked','reason':'macos_tunnel_owners_unavailable'},json.loads(result.stdout))
        with patch.object(owners,'_EXECUTING_CODE',None):
            with self.assertRaisesRegex(owners.OwnershipUnavailable,'macos_tunnel_source_changed'):owners.source(**self.inputs)


if __name__=='__main__':unittest.main()

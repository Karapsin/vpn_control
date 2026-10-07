"""Bounded actual virtual-boot bytes and harmless QEMU reader; no guest boot."""
import binascii
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import patch

def source_recipe():
    return json.dumps(['qemu-system-x86_64','-machine','q35,accel=kvm,smm=on',
        '-drive','file=/home/kardinal/vpn-control-windows-native-20260907/task.qcow2,if=none,id=disk,format=qcow2',
        '-device','ide-hd,drive=disk,bus=ide.0','-device','e1000e,netdev=net',
        '-device','virtio-serial-pci','-device','virtserialport,chardev=qga0,name=org.qemu.guest_agent.0']).encode()


def controller_boot():
    return {'bootMode':'uefi','diskController':launch.source_disk_controller(source_recipe())}


from agent_tools import windows_parallel_vm_launch as launch


def gpt(virtual=8 * 1024 ** 2, duplicate_esp=False):
    raw = bytearray(launch.PREFIX_BYTES)
    raw[510:512] = b'\x55\xaa'
    raw[450] = 0xee
    struct.pack_into('<II', raw, 454, 1, virtual // 512 - 1)
    raw[512:520] = b'EFI PART'
    struct.pack_into('<IIII', raw, 520, 0x10000, 92, 0, 0)
    struct.pack_into('<QQQQ', raw, 536, 1, virtual // 512 - 1, 34, virtual // 512 - 34)
    raw[568:584] = uuid.UUID('cf2b9424-d28e-435c-bfe4-ddd42a6bd1e6').bytes_le
    struct.pack_into('<QIII', raw, 584, 2, 128, 128, 0)
    for index in range(2 if duplicate_esp else 1):
        offset = 1024 + index * 128
        raw[offset:offset+16] = launch.ESP_GUID.bytes_le
        raw[offset+16:offset+32] = uuid.UUID(int=index+1).bytes_le
        struct.pack_into('<QQ', raw, offset+32, 2048 + index*1024, 3071 + index*1024)
    repair_crc(raw)
    return bytes(raw)


def repair_crc(raw):
    struct.pack_into('<I', raw, 600, binascii.crc32(raw[1024:1024+128*128]) & 0xffffffff)
    raw[528:532] = b'\0' * 4
    struct.pack_into('<I', raw, 528, binascii.crc32(raw[512:604]) & 0xffffffff)


def native_prepared_fixture():
    from agent_tools import windows_parallel_vm_prepare as prepare
    return {'state':'prepared','correlationId':str(uuid.uuid4()),
          'template':str(prepare.TEMPLATE_ROOT/'template.qcow2'),'templateSha256':'a'*64,
          'templateGeneration':[1,2,stat.S_IFREG|0o440,0,1000,1,1024,7,8],
          'ordinaryQemuReadAccessConfigured':True,'nativeGuestStarted':False,
          'launchAdmitted':False,'productAcceptance':False,
          'overlays':[{'path':str(Path(p)/'disk.qcow2'),
               'generation':[1,3+i,stat.S_IFREG|0o600,1000,1000,1,198144,7,8],
               'guestGeneration':[1,5+i,stat.S_IFDIR|0o700,1000,1000]}
               for i,p in enumerate(launch.inventory.DESTINATIONS)]}


class BootBytesTest(unittest.TestCase):
    def test_repair_factories_survive_actual_saved_request_json_roundtrip(self):
        request={'prepared':native_prepared_fixture(),'observed':{
            'state':'boot-observed','nativeGuestStarted':False,'productAcceptance':False,
            'boot':controller_boot()},'proof':{'unknownBase64':'','supervisor':{
            'programSha256':'a'*64,'pid':1,'startTicks':2}},'correlation':str(uuid.uuid4())}
        reloaded=json.loads(json.dumps(request,sort_keys=True))
        for factory in (launch.ordinary_secondary_shutdown_program,launch.secondary_repair_program):
            with self.subTest(factory=factory.__name__):
                self.assertEqual(factory(request['prepared'],request['observed'],request['proof'],request['correlation']),
                    factory(reloaded['prepared'],reloaded['observed'],reloaded['proof'],reloaded['correlation']))

    def test_generated_shutdown_reader_keeps_coalesced_qmp_event_and_ack(self):
        import ast
        observation={'state':'boot-observed','nativeGuestStarted':False,'productAcceptance':False,'boot':controller_boot()}
        program=launch.ordinary_secondary_shutdown_program(native_prepared_fixture(),observation,
            {'unknownBase64':'','supervisor':{}},str(uuid.uuid4()))
        ns={};exec(compile(program.split('\nPROOF=',1)[0],'actual generated QMP dependencies','exec'),ns)
        receiver=next(n for n in ast.walk(ast.parse(program)) if isinstance(n,ast.FunctionDef) and n.name=='receive')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            reader,writer=socket.socketpair()
            event=b'{"event":"POWERDOWN"}\r\n'
            ack=b'{"return":{},"id":"original-system_powerdown"}\r\n'
            try:
                ns.update(connection=reader,framer=ns['AccessClient']('unused',max_response_bytes=4096).bind(
                    {'rootFd':fd},launch.fixed_guest('secondary'),{}))
                exec(compile(ast.Module([receiver],type_ignores=[]),'actual generated QMP receive','exec'),ns)
                writer.sendall(event+ack)
                self.assertEqual(ns['receive'](),{'event':'POWERDOWN'})
                self.assertEqual(ns['receive'](),{'return':{},'id':'original-system_powerdown'})
                self.assertEqual((root/'qga-secondary-1.private').read_bytes(),event)
                self.assertEqual((root/'qga-secondary-2.private').read_bytes(),ack)
            finally:reader.close();writer.close();os.close(fd)

    def test_actual_valid_gpt_crcs_esp_and_disk_guid_choose_uefi(self):
        result = launch.boot_layout(gpt(), 8 * 1024 ** 2)
        self.assertEqual(result['bootMode'], 'uefi')
        self.assertEqual(result['esp']['firstLba'], 2048)
        self.assertEqual(result['diskGuid'], 'cf2b9424-d28e-435c-bfe4-ddd42a6bd1e6')
        self.assertEqual(result['tpmDependency'], 'unverified')
        self.assertFalse(result['guestOperatingSystemVerified'])

    def test_actual_legacy_active_mbr_choose_bios(self):
        raw = bytearray(launch.PREFIX_BYTES)
        raw[0] = 0xfa;raw[510:512] = b'\x55\xaa';raw[446] = 0x80;raw[450] = 7
        struct.pack_into('<II', raw, 454, 2048, 4096)
        value = launch.boot_layout(bytes(raw), 8 * 1024 ** 2)
        self.assertEqual(value['bootMode'], 'bios')
        self.assertEqual(value['activePartition']['partitionType'], 7)

    def test_bad_crc_truncation_bool_size_duplicate_esp_and_hybrid_refuse(self):
        corrupt_header = bytearray(gpt());corrupt_header[568] ^= 1
        corrupt_table = bytearray(gpt());corrupt_table[1030] ^= 1
        hybrid = bytearray(gpt());hybrid[466] = 7
        for raw, size, code in ((bytes(corrupt_header), 8 * 1024**2, 'boot-gpt-header-crc'),
                                (bytes(corrupt_table), 8 * 1024**2, 'boot-gpt-table-crc'),
                                (gpt()[:-1], 8 * 1024**2, 'boot-prefix-size'),
                                (gpt(), True, 'boot-prefix-size'),
                                (gpt(duplicate_esp=True), 8 * 1024**2, 'boot-esp-ambiguous'),
                                (bytes(hybrid), 8 * 1024**2, 'boot-hybrid-mbr')):
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, code):
                launch.boot_layout(raw, size)

    def test_valid_crcs_cannot_hide_overlapping_partitions(self):
        raw = bytearray(gpt(duplicate_esp=True))
        struct.pack_into('<QQ', raw, 1024+128+32, 2048, 4095);repair_crc(raw)
        with self.assertRaisesRegex(ValueError, 'boot-gpt-overlap'):
            launch.boot_layout(bytes(raw), 8 * 1024 ** 2)

    def test_measured_source_ide_controller_is_not_replaced_by_nvme(self):
        # Measured native recipe30a5 used q35's IDE/AHCI disk; NVMe boot
        # returned INACCESSIBLE_BOOT_DEVICE0x7B on the unchanged source image.
        raw=source_recipe()
        controller=launch.source_disk_controller(raw)
        argv=launch.fixed_argv(launch.fixed_guest('secondary'),{'bootMode':'uefi','diskController':controller},
            overlay_fd=5,template_fd=6,code_fd=7,vars_fd=8)
        self.assertIn('ide-hd,drive=owned-disk,bus=ide.0,bootindex=0',argv)
        self.assertFalse(any(v.startswith('nvme,') for v in argv))

    def test_actual_source_recipe_refuses_missing_conflicting_and_wrong_source_devices(self):
        original=json.loads(source_recipe())
        for old,new in [('ide-hd,drive=disk,bus=ide.0','nvme,drive=disk'),
                        ('e1000e,netdev=net','virtio-net-pci,netdev=net'),
                        ('file=/home/kardinal/vpn-control-windows-native-20260907/task.qcow2,if=none,id=disk,format=qcow2',
                         'file=/foreign/task.qcow2,if=none,id=disk,format=qcow2')]:
            with self.subTest(new=new),self.assertRaises(ValueError):
                launch.source_disk_controller(json.dumps([new if v==old else v for v in original]).encode())
        with self.assertRaisesRegex(ValueError,'launch-source-controller'):
            launch.source_disk_controller(json.dumps(original+['-device','nvme,drive=disk']).encode())
        for bad in (None,True,{},dict(controller_boot()['diskController'],kind='nvme')):
            with self.subTest(bad=bad),self.assertRaisesRegex(ValueError,'launch-disk-controller'):
                launch.fixed_argv(launch.fixed_guest('secondary'),{'bootMode':'uefi','diskController':bad},
                    overlay_fd=5,template_fd=6,code_fd=7,vars_fd=8)

    def test_missing_controller_descriptor_does_not_admit_guessed_device(self):
        with self.assertRaisesRegex(ValueError,'launch-disk-controller'):
            launch.fixed_argv(launch.fixed_guest('secondary'),{'bootMode':'uefi'},
                overlay_fd=5,template_fd=6,code_fd=7,vars_fd=8)

    def test_fixed_recipes_only_owned_fd_drives_ports_macs_and_fresh_firmware(self):
        for slot in ('secondary', 'tertiary'):
            guest = launch.fixed_guest(slot)
            argv = launch.fixed_argv(guest, dict(launch.boot_layout(gpt(), 8*1024**2),diskController=launch.source_disk_controller(source_recipe())),
                                     overlay_fd=5, template_fd=6, code_fd=7, vars_fd=8)
            self.assertEqual(argv[0], '/usr/bin/qemu-system-x86_64')
            self.assertIn('4096', argv)
            self.assertIn('2', argv)
            self.assertIn('user,id=owned-net,hostfwd=tcp:127.0.0.1:' + str(guest.ssh_port) + '-:22', argv)
            self.assertIn('e1000e,netdev=owned-net,mac=' + guest.mac, argv)
            blocks = [json.loads(argv[i+1]) for i,x in enumerate(argv) if x=='-blockdev']
            self.assertEqual(blocks[2]['filename'], '/proc/self/fd/5')
            self.assertEqual(blocks[0]['filename'], '/proc/self/fd/6')
            self.assertTrue(blocks[0]['read-only'])
            self.assertEqual(blocks[3]['backing'], 'template')
            self.assertNotIn('-tpmdev', argv)
        with self.assertRaisesRegex(ValueError, 'launch-firmware-fds'):
            launch.fixed_argv(launch.fixed_guest('secondary'), controller_boot(), overlay_fd=5, template_fd=6)
        with self.assertRaisesRegex(ValueError, 'guest-slot'):
            launch.fixed_guest('windows-cp117')

    def test_generated_prefix_real_socket_overflow_retains_known_protocol_error(self):
        import socket,time
        source=launch.launch_program(native_prepared_fixture(),{'state':'boot-observed','nativeGuestStarted':False,
            'productAcceptance':False,'boot':controller_boot()},str(uuid.uuid4()))
        ns={};exec(compile(source.split('\nrun=None\n',1)[0],'actual generated capture','exec'),ns)
        with tempfile.TemporaryDirectory() as d:
            fd=os.open(d,os.O_RDONLY|os.O_DIRECTORY)
            a,b=socket.socketpair()
            try:
                client=ns['AccessClient']('/inert',max_response_bytes=32).bind({'rootFd':fd},ns['SimpleNamespace'](slot='secondary'),{})
                b.sendall(b'PUBLIC_PREFIX'+b'x'*21)
                with self.assertRaises(ns['QgaProtocolError']):client._read_response(a,time.monotonic()+1)
                self.assertEqual(Path(d,'qga-secondary-1.private').read_bytes(),(b'PUBLIC_PREFIX'+b'x'*21)[:33])
            finally:a.close();b.close();os.close(fd)

    def test_actual_native_program_builder_rejects_incomplete_or_boolean_pins(self):
        prepared=native_prepared_fixture()
        source=launch.boot_program(prepared,str(uuid.uuid4()));compile(source,'fixed boot source','exec')
        self.assertNotIn('subprocess.Popen',source)
        for field,value in (('templateGeneration',[True,2,stat.S_IFREG|0o440,0,1000,1,1024,7,8]),
                            ('templateSha256','bad'),('productAcceptance',True),('correlationId','arbitrary'),
                            ('ordinaryQemuReadAccessConfigured',1)):
            changed={**prepared,field:value}
            with self.subTest(field=field),self.assertRaises(ValueError):
                launch.boot_program(changed,str(uuid.uuid4()))


@unittest.skipUnless(os.name == 'posix' and shutil.which('qemu-img'), 'Actual harmless QEMU reader required')
class OriginalProcessObservationTest(unittest.TestCase):
    def test_real_file_holder_roles_refuse_foreign_pid_fd_and_write_access(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);path=root/'template.qcow2';path.write_bytes(b'PRIVATE_TEMPLATE')
            proc=root/'proc';parent=proc/'123';(parent/'fd').mkdir(parents=True);(parent/'fdinfo').mkdir()
            (parent/'fd/4').symlink_to(path);(parent/'fdinfo/4').write_text('flags: 0100000\n')
            row={'pid':123,'startTicks':99,'programSha256':'a'*64,'imageFiles':[{'fd':'4','path':str(path),
                'generation':launch.inventory.generation(path.stat()),'accessMode':os.O_RDONLY}]}
            authority={'parent':row,'tertiary':{'pid':456,'startTicks':100}}
            census={'complete':True,'argvUsers':[],'holders':[{'pid':123,'startTicks':99,'fd':'4'}]}
            # The kernel process verifier is the sole portability projection;
            # full inode/path/access-role checks use real files and fdinfo.
            with patch.object(launch,'observed_process'):
                launch.repair_census(proc,path,census,authority)
                (parent/'fdinfo/4').write_text('flags: 0100002\n')
                with self.assertRaisesRegex(ValueError,'repair-inert-holder-role'):launch.repair_census(proc,path,census,authority)
                (parent/'fdinfo/4').write_text('flags: 0100000\n')
                row['imageFiles'][0]['fd']='5'
                with self.assertRaisesRegex(ValueError,'repair-inert-holder-role'):launch.repair_census(proc,path,census,authority)
                row['imageFiles'][0]['fd']='4';authority['parent']=dict(row,pid=124)
                with self.assertRaisesRegex(ValueError,'repair-foreign-image-holder'):launch.repair_census(proc,path,census,authority)


    def test_real_hash_and_proc_file_projection_refuse_changed_original_program(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(.2)'])
            try:
                proc=root/'proc';entry=proc/str(child.pid);entry.mkdir(parents=True)
                program=b'PUBLIC_ORIGINAL_PROGRAM';argv=b'/usr/bin/python3\0-c\0'+program+b'\0'
                (entry/'cmdline').write_bytes(argv);(entry/'stat').write_text(str(child.pid)+' (fixture) R'+' 0'*18+' 99')
                (entry/'status').write_text('Uid: '+str(os.getuid())+' '+str(os.getuid())+'\n')
                (entry/'exe').symlink_to(Path(sys.executable).resolve())
                row={'pid':child.pid,'startTicks':99,'uid':os.getuid(),'binary':launch.inventory.generation((entry/'exe').stat())}
                expected=__import__('hashlib').sha256(program).hexdigest()
                launch.observed_process(proc,row,expected)
                (entry/'cmdline').write_bytes(argv.replace(program,b'FOREIGN_PROGRAM'))
                with self.assertRaisesRegex(ValueError,'repair-original-program'):launch.observed_process(proc,row,expected)
            finally:child.wait(timeout=2)


class ActualHeldReaderTest(unittest.TestCase):
    def test_actual_qcow_prefix_from_inherited_fds_no_source_write_private_raw(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'source.raw';image=root/'sealed.qcow2';prefix=root/'boot-prefix.private'
            source.write_bytes(gpt())
            with source.open('r+b') as file:file.truncate(8*1024**2)
            subprocess.run([shutil.which('qemu-img'),'convert','-f','raw','-O','qcow2',str(source),str(image)],
                           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=10)
            image.chmod(0o440)
            reader=os.open(image,os.O_RDONLY|os.O_NOFOLLOW)
            output=os.open(prefix,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
            before=launch.inventory.generation(os.fstat(reader))
            try:
                # Only inherited-fd alias spelling is projected on Darwin.
                alias='/proc/self/fd/' if Path('/proc/self/fd').exists() else '/dev/fd/'
                with patch.object(launch,'fd_alias',side_effect=lambda fd:alias+str(fd)):
                    raw=launch.held_virtual_prefix(reader,output,shutil.which('qemu-img'))
                self.assertEqual(raw,gpt())
                self.assertEqual(prefix.read_bytes(),gpt())
                self.assertEqual(stat.S_IMODE(prefix.stat().st_mode),0o600)
                self.assertEqual(launch.inventory.generation(os.fstat(reader)),before)
            finally:
                os.close(reader);os.close(output)


@unittest.skipUnless(os.name == 'posix' and shutil.which('qemu-img'), 'Actual harmless QEMU reader required')
class WholeObserverTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve();self.root.chmod(0o700)
        parent=self.root/'template';parent.mkdir(mode=0o750)
        self.image=parent/'template.qcow2';raw=self.root/'source.raw';raw.write_bytes(gpt(96*1024**3))
        with raw.open('r+b') as file:file.truncate(96*1024**3)
        self.binary=Path(shutil.which('qemu-img')).resolve()
        subprocess.run([str(self.binary),'convert','-f','raw','-O','qcow2',str(raw),str(self.image)],
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=10)
        self.image.chmod(0o440)
        self.guests=tuple(self.root/name for name in ('secondary','tertiary'))
        for guest in self.guests:
            guest.mkdir(mode=0o700);overlay=guest/'disk.qcow2';overlay.write_bytes(b'OWNED_OVERLAY');overlay.chmod(0o600)
        self.proc=self.root/'proc';self.proc.mkdir();(self.proc/'net').mkdir()
        for name in ('tcp','tcp6'):(self.proc/'net'/name).write_text('header\n')
        self.expected={'state':'prepared','correlationId':str(uuid.uuid4()),'template':str(self.image),
            'templateGeneration':launch.inventory.generation(self.image.lstat()),
            'templateSha256':__import__('hashlib').sha256(self.image.read_bytes()).hexdigest(),
            'overlays':[{'path':str(g/'disk.qcow2'),'generation':launch.inventory.generation((g/'disk.qcow2').lstat()),
                         'guestGeneration':launch.inventory.parent_identity(g.lstat())} for g in self.guests],
            'nativeGuestStarted':False,'launchAdmitted':False,'productAcceptance':False}
        self.correlation=str(uuid.uuid4())
        self.scope=(self.image,self.guests,self.proc,self.binary,self.root,os.getuid())
        self.evidence=parent/('boot-read-'+self.correlation)
        alias='/proc/self/fd/' if Path('/proc/self/fd').exists() else '/dev/fd/'
        self.alias=patch.object(launch,'fd_alias',side_effect=lambda fd:alias+str(fd));self.alias.start();self.addCleanup(self.alias.stop)
        # Darwin forbids executing /dev/fd. Only this Linux exec boundary is
        # projected; actual qemu-img reads, inherited image FDs and guards run.
        self.exec_alias=None
        if not Path('/proc/self/fd').exists():
            self.exec_alias=patch.object(launch,'binary_alias',side_effect=lambda fd:str(self.binary))
            self.exec_alias.start();self.addCleanup(self.exec_alias.stop)

    def test_actual_whole_observer_retains_prefix_and_false_launch_flags(self):
        value=launch.observed_boot(self.scope,self.expected,self.correlation)
        self.assertEqual(value['state'],'boot-observed');self.assertEqual(value['boot']['bootMode'],'uefi')
        self.assertEqual((self.evidence/'boot-prefix.private').read_bytes(),gpt(96*1024**3))
        self.assertEqual(json.loads((self.evidence/'result.json').read_bytes()),value)
        self.assertFalse(value['nativeGuestStarted']);self.assertFalse(value['launchAdmitted'])
        self.assertFalse(value['productAcceptance']);self.assertEqual(self.expected['templateGeneration'],launch.inventory.generation(self.image.lstat()))

    def test_generated_actual_observer_body_reads_same_qcow_and_keeps_provenance(self):
        native=native_prepared_fixture()
        self.alias.stop()
        if self.exec_alias:self.exec_alias.stop()
        try:
            program=launch.boot_program(native,self.correlation)
        finally:
            self.alias.start()
            if self.exec_alias:self.exec_alias.start()
        namespace={};exec(compile(program.rsplit('\ntry:\n',1)[0],'actual generated observer definitions','exec'),namespace)
        alias='/proc/self/fd/' if Path('/proc/self/fd').exists() else '/dev/fd/'
        namespace['fd_alias']=lambda fd:alias+str(fd)
        if not Path('/proc/self/fd').exists():namespace['binary_alias']=lambda fd:str(self.binary)
        value=namespace['observed_boot'](self.scope,self.expected,self.correlation)
        self.assertEqual(value['state'],'boot-observed')
        self.assertEqual(value['boot']['prefixSha256'],__import__('hashlib').sha256(gpt(96*1024**3)).hexdigest())
        self.assertEqual(value['prefixGeneration'],launch.inventory.generation((self.evidence/'boot-prefix.private').lstat()))

    def test_actual_whole_observer_named_namespace_swap_preserves_original_unknown(self):
        parser=launch.boot_layout;detached=self.evidence.with_name(self.evidence.name+'-detached')
        def changed(raw,size):
            value=parser(raw,size);self.evidence.rename(detached);self.evidence.mkdir(mode=0o700);return value
        with patch.object(launch,'boot_layout',side_effect=changed),self.assertRaisesRegex(ValueError,'boot-closing-evidence'):
            launch.observed_boot(self.scope,self.expected,self.correlation)
        self.assertFalse((self.evidence/'result.json').exists())
        self.assertFalse((detached/'result.json').exists())
        self.assertEqual((detached/'boot-prefix.private').read_bytes(),gpt(96*1024**3))
        self.assertEqual(json.loads((detached/'unknown.json').read_bytes())['state'],'unknown')

    def test_actual_whole_observer_binary_changed_during_intent_never_executes(self):
        binary=self.root/'qemu-img';shutil.copyfile(self.binary,binary);binary.chmod(0o755)
        marker=self.root/'foreign-executed';scope=(*self.scope[:3],binary,*self.scope[4:])
        writer=launch.prepare.record_at
        def changed(fd,name,value):
            writer(fd,name,value)
            if name=='intent.json':binary.write_bytes(('#!/bin/sh\necho FOREIGN > '+str(marker)+'\nexit 1\n').encode())
        with patch.object(launch.prepare,'record_at',side_effect=changed),self.assertRaisesRegex(ValueError,'boot-preexec-binary'):
            launch.observed_boot(scope,self.expected,self.correlation)
        self.assertFalse(marker.exists())
        self.assertFalse((self.evidence/'result.json').exists())
        self.assertEqual(json.loads((self.evidence/'unknown.json').read_bytes())['state'],'unknown')

    @unittest.skipUnless(Path('/proc/self/fd').exists(), 'Linux inherited executable FD; Darwin exec is not equivalent')
    def test_actual_linux_binary_name_swap_at_exec_runs_original_fd_no_foreign_code(self):
        binary=self.root/'qemu-img';shutil.copyfile(self.binary,binary);binary.chmod(0o755)
        marker=self.root/'foreign-executed';scope=(*self.scope[:3],binary,*self.scope[4:]);runner=launch.subprocess.run
        def swapped(argv,**kwargs):
            binary.rename(self.root/'original-qemu-img')
            binary.write_bytes(('#!/bin/sh\necho FOREIGN > '+str(marker)+'\nexit 1\n').encode());binary.chmod(0o755)
            self.assertTrue(argv[0].startswith('/proc/self/fd/'))
            return runner(argv,**kwargs)
        with patch.object(launch.subprocess,'run',side_effect=swapped),self.assertRaisesRegex(ValueError,'boot-closing-binary'):
            launch.observed_boot(scope,self.expected,self.correlation)
        self.assertFalse(marker.exists())
        self.assertEqual((self.evidence/'boot-prefix.private').read_bytes(),gpt(96*1024**3))
        self.assertFalse((self.evidence/'result.json').exists())

    def test_actual_whole_observer_prefix_changed_after_parse_refuses(self):
        parser=launch.boot_layout
        def changed(raw,size):
            value=parser(raw,size)
            with (self.evidence/'boot-prefix.private').open('r+b') as file:file.write(b'ALTERED')
            return value
        with patch.object(launch,'boot_layout',side_effect=changed),self.assertRaisesRegex(ValueError,'boot-closing-prefix'):
            launch.observed_boot(self.scope,self.expected,self.correlation)
        self.assertFalse((self.evidence/'result.json').exists())
        self.assertEqual(json.loads((self.evidence/'unknown.json').read_bytes())['state'],'unknown')

    def test_actual_whole_observer_overlay_changed_after_read_refuses(self):
        parser=launch.boot_layout
        def changed(raw,size):
            value=parser(raw,size);(self.guests[0]/'disk.qcow2').chmod(0o666);return value
        with patch.object(launch,'boot_layout',side_effect=changed),self.assertRaisesRegex(ValueError,'boot-closing-image'):
            launch.observed_boot(self.scope,self.expected,self.correlation)
        self.assertFalse((self.evidence/'result.json').exists())
        self.assertTrue((self.evidence/'unknown.json').exists())


class PairProducerTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve();self.root.chmod(0o700)
        parent=self.root/'template';parent.mkdir(mode=0o750)
        self.template=parent/'template.qcow2';self.template.write_bytes(b'SEALED');self.template.chmod(0o440)
        self.guests=tuple(launch.Guest(slot,self.root/slot,port,vnc,mac) for slot,port,vnc,mac in
            zip(('secondary','tertiary'),(2339,2338),(5939,5938),launch.inventory.MACS))
        for guest in self.guests:
            guest.root.mkdir(mode=0o700);image=guest.root/'disk.qcow2';image.write_bytes(b'OVERLAY');image.chmod(0o600)
        self.binary=Path(sys.executable).resolve()
        self.code=self.root/'code.fd';self.seed=self.root/'seed.fd'
        for path in (self.code,self.seed):path.write_bytes(b'FIRMWARE_SEED');path.chmod(0o644)
        self.proc=self.root/'proc';self.proc.mkdir();(self.proc/'net').mkdir();(self.proc/'pressure').mkdir()
        for name in ('tcp','tcp6'):(self.proc/'net'/name).write_text('header\n')
        (self.proc/'meminfo').write_text('MemAvailable: 33554432 kB\n')
        (self.proc/'pressure/memory').write_text('some avg10=0.00 avg60=0.00\nfull avg10=0.00 avg60=0.00\n')
        self.prepared={'template':str(self.template),'templateGeneration':launch.inventory.generation(self.template.lstat()),
            'templateSha256':__import__('hashlib').sha256(self.template.read_bytes()).hexdigest(),
            'overlays':[{'path':str(g.root/'disk.qcow2'),'generation':launch.inventory.generation((g.root/'disk.qcow2').lstat()),
                        'guestGeneration':launch.inventory.parent_identity(g.root.lstat())} for g in self.guests]}
        self.sourceRoot=self.root/'vpn-control-windows-native-20260907';self.sourceRoot.mkdir()
        self.source=self.sourceRoot/'task.qcow2';self.source.write_bytes(self.template.read_bytes())
        self.sourceRecipe=self.sourceRoot/'qemu-command.json';self.sourceRecipe.write_bytes(source_recipe())
        self.observed={'state':'boot-observed','boot':controller_boot(),'sourceDiskRecipe':{
            'generation':launch.inventory.generation(self.sourceRecipe.lstat()),'sha256':__import__('hashlib').sha256(self.sourceRecipe.read_bytes()).hexdigest(),
            'sourceGeneration':launch.inventory.generation(self.source.lstat())},'templateGeneration':self.prepared['templateGeneration'],
            'overlays':self.prepared['overlays'],'firmwareCandidates':[{'path':str(p),'available':True,
             'generation':launch.inventory.generation(p.lstat()),'sha256':__import__('hashlib').sha256(p.read_bytes()).hexdigest()}
             for p in (self.code,self.seed)]}
        self.scope=(self.template,self.guests,self.proc,self.binary,self.code,self.seed,self.root,
                    os.getuid(),os.getgid(),os.getgid(),os.getuid())
        self.correlation=str(uuid.uuid4());self.children=[];self.runs=[]
        self.addCleanup(self.close_originals)
        # Host free space can fall below the native VM admission threshold during
        # packaging. Project only this hardware observation: all actual resource
        # decisions, files, held descriptors and harmless children still run.
        self.free_disk_bytes=16*1024**3
        native_statvfs=os.statvfs
        def fixture_statvfs(path):
            if Path(path)==self.root:
                return SimpleNamespace(f_bavail=self.free_disk_bytes//4096,f_frsize=4096)
            return native_statvfs(path)
        self.disk_capacity=patch.object(launch.os,'statvfs',side_effect=fixture_statvfs)
        self.disk_capacity.start();self.addCleanup(self.disk_capacity.stop)
        real_popen=subprocess.Popen
        def harmless(argv,**kwargs):
            # Only QEMU/privilege OS boundary is projected. Original real
            # Popen, inherited image/log FDs and all filesystem guards run.
            for key in ('user','group','extra_groups'):kwargs.pop(key,None)
            child=real_popen([sys.executable,'-u','-c',"import os,time;os.write(1,b'ORIGINAL_PREFIX');time.sleep(.5)"],**kwargs)
            self.children.append(child);return child
        self.popen=patch.object(launch.subprocess,'Popen',side_effect=harmless);self.popen.start();self.addCleanup(self.popen.stop)
        self.slots=patch.object(launch,'fixed_guest',side_effect=lambda s:next(g for g in self.guests if g.slot==s));self.slots.start();self.addCleanup(self.slots.stop)
        def identity(proc,child,argv,pin,uid):
            self.assertIsNone(child.poll())
            return {'pid':child.pid,'startTicks':1,'uid':uid,'binary':pin,'argv':argv}
        self.identity=patch.object(launch,'native_identity',side_effect=identity);self.identity.start();self.addCleanup(self.identity.stop)

    def close_originals(self):
        for child in self.children:child.wait(timeout=3)
        run=launch.LIVE_LAUNCHES.pop(self.correlation,None)
        if run:
            for _,fd,_ in run['files']:
                try:os.close(fd)
                except OSError:pass
            for _,fd,_ in run['directories']:
                try:os.close(fd)
                except OSError:pass
            for _,fd,_ in run.get('logs',[]):os.close(fd)
            if run['rootFd'] is not None:os.close(run['rootFd'])

    def test_actual_generated_secondary_prefix_executes_owned_single_guest_pipeline(self):
        prepared=native_prepared_fixture();observation={'state':'boot-observed','nativeGuestStarted':False,
            'productAcceptance':False,'boot':controller_boot()}
        with patch.object(launch,'fixed_guest',self.slots.temp_original),patch.object(launch,'native_identity',self.identity.temp_original):
            source=launch.secondary_repair_program(prepared,observation,{'unknownBase64':'','supervisor':{}},self.correlation)
        ns={};exec(compile(source.split('\nrun=None\n',1)[0],'actual generated repair dependencies','exec'),ns)
        ns['LIVE_LAUNCHES']=launch.LIVE_LAUNCHES
        ns['fixed_guest']=lambda slot:next(g for g in self.guests if g.slot==slot)
        ns['native_identity']=launch.native_identity
        guest=self.guests[0];state=guest.root/'vm-state';state.mkdir()
        variables=state/'vars.fd';variables.write_bytes(b'ORIGINAL_PRIVATE_VARS');variables.chmod(0o600)
        ns['repair_phase']=lambda proc,proof:{'parent':{'imageFiles':[{'path':str(variables),
            'generation':launch.inventory.generation(variables.lstat()),'accessMode':2}]},'tertiary':{}}
        one=(self.scope[0],(guest,),*self.scope[2:])
        current,binding=ns['fresh_secondary_repair'](one,self.prepared,self.observed,{})
        value,run=ns['launch_pair'](one,current,binding,self.correlation)
        self.assertEqual(value['state'],'pair-started');self.assertEqual(len(run['handles']),1)
        self.assertEqual(variables.read_bytes(),b'ORIGINAL_PRIVATE_VARS')
        self.assertFalse((self.guests[1].root/'vm-state').exists())

    def test_actual_single_secondary_repair_reuses_owned_vars_and_new_sockets(self):
        guest=self.guests[0];state=guest.root/'vm-state';state.mkdir()
        variables=state/'vars.fd';variables.write_bytes(b'OWNED_EXISTING_VARS');variables.chmod(0o600)
        original=launch.inventory.generation(variables.lstat())
        authority={'parent':{'imageFiles':[{'path':str(variables),'generation':original,'accessMode':2}]},'tertiary':{}}
        one=(self.scope[0],(guest,),*self.scope[2:])
        with patch.object(launch,'repair_phase',return_value=authority):
            current,binding=launch.fresh_secondary_repair(one,self.prepared,self.observed,{'kernelProjection':'original'})
            value,run=launch.launch_pair(one,current,binding,self.correlation)
        self.assertEqual(len(self.children),1);self.assertEqual(value['state'],'pair-started')
        self.assertEqual(variables.read_bytes(),b'OWNED_EXISTING_VARS')
        self.assertEqual(launch.inventory.generation(variables.lstat()),original)
        argv=run['identities'][0]['argv']
        self.assertIn('ide-hd,drive=owned-disk,bus=ide.0,bootindex=0',argv)
        self.assertIn('e1000e,netdev=owned-net,mac='+guest.mac,argv)
        self.assertIn('unix:'+str(guest.root/('vm-r-'+self.correlation[:8])/'qmp.sock')+',server=on,wait=off',argv)
        self.assertFalse((self.guests[1].root/'vm-state').exists())

    def test_actual_unproved_repair_phase_never_submits_new_vm(self):
        one=(self.scope[0],(self.guests[0],),*self.scope[2:])
        observed=dict(self.observed,overlays=self.prepared['overlays'][:1],repair={'proof':{'unknownBase64':'','supervisor':{}},'varsGeneration':[]})
        with self.assertRaises(launch.PairUnknown) as error:
            launch.launch_pair(one,dict(self.prepared,overlays=self.prepared['overlays'][:1]),observed,self.correlation)
        self.assertEqual(error.exception.run['handles'],[]);self.assertEqual(self.children,[])

    def test_repair_recipe_cannot_expand_into_tertiary_or_foreign_state(self):
        with self.assertRaisesRegex(ValueError,'repair-recipe-scope'):
            launch.fixed_argv(self.guests[1],controller_boot(),overlay_fd=5,template_fd=6,
                code_fd=7,vars_fd=8,repair_correlation=self.correlation)

    def test_actual_source_recipe_identity_and_descriptor_close_before_submission(self):
        writer=launch.prepare.record_at
        def drift(fd,name,value):
            writer(fd,name,value)
            if name=='intent.json':self.sourceRecipe.write_bytes(self.sourceRecipe.read_bytes()+b' ')
        with patch.object(launch.prepare,'record_at',side_effect=drift),self.assertRaises(launch.PairUnknown) as error:
            launch.launch_pair(self.scope,self.prepared,self.observed,self.correlation)
        self.assertEqual(error.exception.run['handles'],[])
        self.assertEqual(self.children,[])
        self.assertFalse((error.exception.run['root']/'result.json').exists())

    def test_actual_mismatched_source_recipe_descriptor_refuses_before_submission(self):
        self.observed['boot']['diskController']['recipeSha256']='a'*64
        with self.assertRaises(launch.PairUnknown) as error:
            launch.launch_pair(self.scope,self.prepared,self.observed,self.correlation)
        self.assertEqual(error.exception.run['handles'],[]);self.assertEqual(self.children,[])

    def test_actual_pair_guard_staging_original_processes_and_private_vars(self):
        value,run=launch.launch_pair(self.scope,self.prepared,self.observed,self.correlation)
        self.assertEqual(value['state'],'pair-started');self.assertEqual(len(self.children),2)
        self.assertEqual(run['handles'],self.children)
        self.assertFalse(value['guestAccessVerified']);self.assertFalse(value['productAcceptance'])
        for guest in self.guests:
            self.assertEqual((guest.root/'vm-state/vars.fd').read_bytes(),self.seed.read_bytes())
            self.assertEqual(stat.S_IMODE((guest.root/'vm-state/vars.fd').stat().st_mode),0o600)
        self.assertEqual(self.prepared['templateGeneration'],launch.inventory.generation(self.template.lstat()))

    def test_actual_second_started_hook_cannot_publish_changed_first_overlay_mode(self):
        writer=launch.prepare.record_at
        def changed(fd,name,value):
            writer(fd,name,value)
            if name=='tertiary-started.json':(self.guests[0].root/'disk.qcow2').chmod(0o666)
        with patch.object(launch.prepare,'record_at',side_effect=changed),self.assertRaises(launch.PairUnknown) as error:
            launch.launch_pair(self.scope,self.prepared,self.observed,self.correlation)
        self.assertEqual(error.exception.run['handles'],self.children)
        self.assertEqual(len(self.children),2)
        self.assertFalse((error.exception.run['root']/'result.json').exists())

    def test_actual_postspawn_journal_error_preserves_same_child_raw_and_unknown(self):
        writer=launch.prepare.record_at
        def failed(fd,name,value):
            if name=='secondary-started.json':raise OSError('owned-journal-fixture')
            return writer(fd,name,value)
        with patch.object(launch.prepare,'record_at',side_effect=failed),self.assertRaises(launch.PairUnknown) as error:
            launch.launch_pair(self.scope,self.prepared,self.observed,self.correlation)
        run=error.exception.run
        self.assertEqual(run['handles'],self.children);self.assertEqual(len(self.children),1)
        self.assertIsNone(self.children[0].poll())
        self.children[0].wait(timeout=3)
        self.assertEqual((run['root']/'secondary-qemu.private').read_bytes(),b'ORIGINAL_PREFIX')
        self.assertFalse((run['root']/'result.json').exists())
        self.assertEqual(json.loads((run['root']/'unknown.json').read_bytes())['originalPids'],[self.children[0].pid])

    def test_resource_shortfall_and_changed_source_refuse_before_process(self):
        for cause in ('memory','disk','source'):
            with self.subTest(cause=cause):
                self.close_originals()
                self.free_disk_bytes=1024 if cause=='disk' else 16*1024**3
                if cause=='memory':(self.proc/'meminfo').write_text('MemAvailable: 1024 kB\n')
                else:
                    (self.proc/'meminfo').write_text('MemAvailable: 33554432 kB\n')
                    if cause=='source':self.template.chmod(0o666)
                with self.assertRaises(launch.PairUnknown) as error:
                    launch.launch_pair(self.scope,self.prepared,self.observed,self.correlation)
                if cause in ('memory','disk'):
                    self.assertEqual(str(error.exception.__cause__),'launch-resource-headroom')
                self.assertEqual(len(self.children),0)

    def test_fixed_native_builder_compiles_full_reused_qga_and_no_credentials(self):
        native=native_prepared_fixture()
        observed={'state':'boot-observed','nativeGuestStarted':False,'productAcceptance':False,'boot':{'bootMode':'uefi'}}
        # Restore original function source after the fixture boundary projection.
        self.slots.stop();self.identity.stop()
        try:program=launch.launch_program(native,observed,str(uuid.uuid4()))
        finally:self.slots.start();self.identity.start()
        compile(program,'fixed pair generated source','exec')
        self.assertIn('kvm_gid=grp.getgrnam',program)
        self.assertIn('guest_exec_status(created',program)
        self.assertNotIn('CP117',program)
        self.assertNotIn('kill(',program)

    def serve_qga(self, guest, *, bad_pid=False):
        import base64
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        listener.bind(str(guest.root/'vm-state/qga.sock'));listener.listen(8);listener.settimeout(2)
        requests=[];errors=[]
        def server():
            try:
                for _ in range(3 if bad_pid else 4):
                    connection,_=listener.accept()
                    with connection:
                        reader=connection.makefile('rb')
                        sync=json.loads(reader.readline()[1:])
                        connection.sendall(b'\xff'+json.dumps({'return':sync['arguments']['id']}).encode()+b'\n')
                        request=json.loads(reader.readline());requests.append(request)
                        command=request['execute']
                        if command=='guest-ping':value={}
                        elif command=='guest-get-osinfo':value={'id':'mswindows','machine':'x86_64'}
                        elif command=='guest-exec':
                            value={'pid':True if bad_pid else 123}
                            self.assertEqual(request['arguments']['arg'][-1],launch.CONTEXT_SCRIPT)
                        else:
                            self.assertEqual(command,'guest-exec-status');self.assertEqual(request['arguments']['pid'],123)
                            data=json.dumps({'interactiveUser':'FIXTURE\\kardinal','interactiveSid':'S-1-5-21-1-2-3-1000',
                                             'sessionIds':[1],'architecture':'AMD64','windowsVersion':'fixture'}).encode()
                            value={'exited':True,'exitcode':0,'out-data':base64.b64encode(data).decode()}
                        response=json.dumps({'return':value}).encode()+b'\n'
                        connection.sendall(response[:7]);connection.sendall(response[7:]);reader.close()
            except BaseException as error:errors.append(error)
            finally:listener.close()
        thread=threading.Thread(target=server,daemon=True);thread.start()
        return requests,errors,thread

    def test_actual_qga_protocol_frames_context_and_original_pid_poll_without_replay(self):
        _,run=launch.launch_pair(self.scope,self.prepared,self.observed,self.correlation)
        servers=[self.serve_qga(g) for g in self.guests]
        # Project only Linux SO_PEERCRED (fixture server is a test thread).
        synchronize=launch.qga.QgaReadOnlyClient._synchronize
        with patch.object(launch.AccessClient,'_synchronize',synchronize):
            value=launch.guest_access(run,self.guests,self.proc,deadline_seconds=2)
        self.assertEqual(value['state'],'access-ready');self.assertFalse(value['productAcceptance'])
        self.assertEqual(len(value['guests']),2)
        for requests,errors,thread in servers:
            thread.join(2);self.assertFalse(errors);self.assertFalse(thread.is_alive())
            self.assertEqual([r['execute'] for r in requests],['guest-ping','guest-get-osinfo','guest-exec','guest-exec-status'])
        frames=tuple(run['root'].glob('qga-*.private'))
        self.assertEqual(len(frames),16)
        self.assertTrue(all(stat.S_IMODE(p.stat().st_mode)==0o600 for p in frames))

    def test_actual_qga_boolean_context_pid_refuses_no_status_or_second_exec(self):
        _,run=launch.launch_pair(self.scope,self.prepared,self.observed,self.correlation)
        requests,errors,thread=self.serve_qga(self.guests[0],bad_pid=True)
        with patch.object(launch.AccessClient,'_synchronize',launch.qga.QgaReadOnlyClient._synchronize),self.assertRaisesRegex(ValueError,'access-context-pid'):
            launch.guest_access(run,self.guests,self.proc,deadline_seconds=2)
        thread.join(2);self.assertFalse(errors)
        self.assertEqual([r['execute'] for r in requests],['guest-ping','guest-get-osinfo','guest-exec'])
        self.assertFalse((run['root']/'access-result.json').exists())
        self.assertEqual(run['handles'],self.children)

    def test_actual_socket_partial_eof_deadline_overflow_preserves_bounded_raw(self):
        import time
        _,run=launch.launch_pair(self.scope,self.prepared,self.observed,self.correlation)
        client=launch.AccessClient('unused',max_response_bytes=32).bind(run,self.guests[0],run['identities'][0])
        for index,cause in enumerate(('eof','deadline','overflow'),1):
            with self.subTest(cause=cause):
                reader,writer=socket.socketpair()
                prefix=b'PUBLIC_PARTIAL_QGA_RESPONSE' if cause!='overflow' else b'X'*64
                try:
                    writer.sendall(prefix)
                    if cause=='eof':writer.shutdown(socket.SHUT_WR)
                    with self.assertRaises((EOFError,TimeoutError,launch.qga.QgaObservationError)):
                        client._read_response(reader,time.monotonic()+.03)
                    path=run['root']/('qga-secondary-'+str(index)+'.private')
                    self.assertTrue(path.exists(),'actual received prefix must survive classification')
                    self.assertEqual(path.read_bytes(),prefix[:33])
                    meta=json.loads((run['root']/('qga-secondary-'+str(index)+'.json')).read_bytes())
                    self.assertIs(meta['complete'],False);self.assertEqual(meta['reason'],cause)
                    self.assertEqual(meta['retainedBytes'],len(prefix[:33]));self.assertIs(meta['replayAllowed'],False)
                    self.assertEqual(run['handles'],self.children)
                    self.assertFalse((run['root']/'access-result.json').exists())
                finally:reader.close();writer.close()


if __name__=='__main__':unittest.main()

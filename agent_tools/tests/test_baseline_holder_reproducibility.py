"""Real temporary FD/inode boundaries; mutable names cannot certify a stopped source."""
import os,sys,tempfile,unittest
from pathlib import Path
from unittest import mock
from agent_tools import native_vm_baseline_config as subject

@unittest.skipUnless(os.name=='posix','POSIX source-holder boundary')
class BaselineHolderReproducibilityTests(unittest.TestCase):
    def linux_observe(self,comm,held=True):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();source=root/'source.qcow2';source.write_bytes(b'QFI\xfbPUBLIC')
            other=root/'other.qcow2';other.write_bytes(b'PUBLIC_OTHER')
            proc=root/'proc';pid=proc/'77';(pid/'fd').mkdir(parents=True)
            (pid/'comm').write_text(comm+'\n')
            (pid/'stat').write_text('77 ('+comm+') '+' '.join(['S']+['0']*18+['19']))
            (pid/'exe').symlink_to('/usr/bin/qemu-system-x86_64' if comm=='7' else '/usr/bin/python3')
            (pid/'fd'/'9').symlink_to(source if held else other)
            real_path=Path;real_listdir=os.listdir
            def path(value,*parts):return (proc if value=='/proc' else real_path(value)).joinpath(*parts)
            def listdir(value):return ['77'] if value=='/proc' else real_listdir(value)
            with mock.patch.object(subject.sys,'platform','linux'),mock.patch.object(subject,'Path',side_effect=path),mock.patch.object(subject.os,'listdir',side_effect=listdir):
                return subject._fixed_qemu_stopped(source)
    def test_descriptor_named_qemu_with_exact_source_inode_blocks(self):
        self.assertFalse(self.linux_observe('7'))
    def test_unrelated_process_name_cannot_hide_a_source_capture_holder(self):
        self.assertFalse(self.linux_observe('python'))
    def test_unrelated_open_inode_does_not_block(self):
        self.assertTrue(self.linux_observe('7',held=False))
    def test_macos_descriptor_name_cannot_skip_source_holder(self):
        with tempfile.TemporaryDirectory() as temporary:
            source=Path(temporary)/'source.qcow2';source.write_bytes(b'QFI\xfbPUBLIC')
            def run(argv,**kwargs):
                if argv==('ps','-axo','pid=,comm='):out=b'77 /dev/fd/7\n'
                elif argv==('ps','-p','77','-o','lstart='):out=b'Wed Oct 14 10:00:00 2026\n'
                elif argv==('lsof','-Fpn','-p','77'):out=('p77\nn'+str(source)+'\n').encode()
                else:raise AssertionError(argv)
                return __import__('subprocess').CompletedProcess(argv,0,out,b'')
            with mock.patch.object(subject.sys,'platform','darwin'),mock.patch.object(subject.subprocess,'run',side_effect=run):
                self.assertFalse(subject._fixed_qemu_stopped(source))

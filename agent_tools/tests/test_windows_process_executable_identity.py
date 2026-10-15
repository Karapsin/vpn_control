"""Complete VM observer controls for descriptor-executed QEMU (comm is '7')."""
import contextlib,io,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest import mock
from agent_tools import windows_vm_baseline_inventory as baseline,windows_parallel_vm_source_inventory as inventory
from agent_tools.tests.test_windows_parallel_vm_source_inventory import SourceInventoryTest

@unittest.skipUnless(os.name=='posix','Arch process filesystem semantics')
class BaselineExecutableIdentityTest(unittest.TestCase):
    def test_complete_native_observer_finds_qemu_independently_of_comm(self):
        with tempfile.TemporaryDirectory() as temporary:
            home=Path(temporary).resolve();directory=home/'windows-owned';directory.mkdir()
            disk=directory/'task.qcow2';disk.write_bytes(b'QFI\xfbPUBLIC')
            proc=home/'proc';pid=proc/'7';(pid/'fd').mkdir(parents=True)
            (pid/'stat').write_text('7 (7) '+' '.join(['S']+['0']*18+['17']))
            (pid/'comm').write_text('7\n')
            (pid/'exe').symlink_to('/usr/bin/qemu-system-x86_64')
            (pid/'fd'/'8').symlink_to(disk)
            (pid/'cmdline').write_bytes(b'/proc/self/fd/7\0-drive\0'+('file='+str(disk)+',format=qcow2').encode()+b'\0')
            # Only the consumed physical host paths are projected; the complete
            # native entry, imports, parsers and output writer remain in use.
            source=baseline._REMOTE.replace("ROOT='/home/kardinal'","ROOT="+repr(str(home))).replace('/proc',str(proc))
            image=subprocess.CompletedProcess(['qemu-img'],0,json.dumps({'format':'qcow2','virtual-size':1024}).encode(),b'')
            stream=io.StringIO()
            with mock.patch.object(sys,'platform','linux'),mock.patch.object(subprocess,'run',return_value=image),contextlib.redirect_stdout(stream):
                exec(compile(source,'complete native baseline observer','exec'),{'__name__':'__main__'})
            native=json.loads(stream.getvalue());self.assertTrue(native['processesComplete'])
            self.assertEqual([{'pid':7,'startTicks':17}],native['candidates'][0]['holders'])
            self.assertFalse(native['candidates'][0]['noQemuObserved'])
            self.assertFalse(baseline.classify(native)['nativeActionAllowed'])

@unittest.skipUnless(os.name=='posix','Arch process filesystem semantics')
class SourceExecutableIdentityTest(unittest.TestCase):
    setUp=SourceInventoryTest.setUp
    pid=SourceInventoryTest.pid
    observe=SourceInventoryTest.observe
    def test_full_source_observer_refuses_descriptor_qemu_mac_conflict(self):
        pid=self.pid(42,comm='7')
        (pid/'exe').unlink()
        (pid/'exe').symlink_to('/usr/bin/qemu-system-x86_64')
        (pid/'cmdline').write_bytes(b'/proc/self/fd/7\0-net\0nic,macaddr='+inventory.MACS[0].encode()+b'\0')
        with self.assertRaisesRegex(ValueError,'mac-conflict'):self.observe()
        self.assertEqual([],self.hash_calls)

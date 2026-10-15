"""Whole proc observers use physical executable identities, never comm names."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from agent_tools import linux_deb_arch_guest_prepare_remote as worker
from agent_tools import windows_vm_swtpm_repair as tpm
from agent_tools.tests.linux_role_fixture import program
from agent_tools.tests import test_linux_role_paths as role_fixture


@unittest.skipUnless(os.name=='posix','Linux proc fixture boundary')
class ProcessCensusTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(dir=Path('/tmp').resolve());self.addCleanup(temporary.cleanup)
        self.home=Path(temporary.name);self.proc=self.home/'proc';self.proc.mkdir()
        for name in ('1/ns','self/ns'):(self.proc/name).mkdir(parents=True)
        for name in ('1/ns/pid','self/ns/pid'):(self.proc/name).symlink_to('pid:[17]')
        (self.proc/'self/mountinfo').write_text('1 0 0:1 / /proc rw - proc proc rw\n')
        self.process(1,'python3','systemd',11)
        (self.proc/'net').mkdir();(self.proc/'net/unix').write_text('header\n')
        (self.proc/'meminfo').write_text('MemTotal: 67108864 kB\nMemAvailable: 50331648 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n')
    def process(self,pid,executable,comm,start):
        directory=self.proc/str(pid);directory.mkdir(exist_ok=True)
        (directory/'comm').write_text(comm+'\n')
        fields=['S']+['0']*20;fields[3]=str(pid);fields[19]=str(start)
        (directory/'stat').write_text(str(pid)+' ('+comm+') '+' '.join(fields)+'\n')
        binary=self.home/executable
        if not binary.exists():binary.write_bytes(b'inert physical executable')
        (directory/'exe').symlink_to(binary)
        return directory
    def run_program(self,source):
        result=subprocess.run([sys.executable,'-I','-B','-c',program(source,self.home,self.proc,self.home/'root-owned')],
                              capture_output=True,timeout=5)
        self.assertEqual(0,result.returncode,result.stderr.decode());return json.loads(result.stdout)
    def test_original_capacity_misses_descriptor_qemu_and_fixed_counts_it(self):
        process=self.process(17,'qemu-system-x86_64','7',777)
        (process/'cmdline').write_bytes(b'/proc/self/fd/7\0-m\0'+b'6144\0')
        before=role_fixture.RolePathTests().before('worker.before.source')
        self.assertEqual(0,before._host_capacity(proc_root=self.proc)['runningQemuCount'])
        current=worker._host_capacity(proc_root=self.proc)
        self.assertEqual(1,current['runningQemuCount']);self.assertEqual(6144,current['runningQemuMiB'])
    def test_whole_original_tpm_owner_misses_descriptor_process_and_fixed_detects_it(self):
        process=self.process(17,'swtpm','7',777);(process/'fd').mkdir()
        before=(Path(__file__).parent/'fixtures/source_loader_lifetime/tpm_owner.before.source').read_text()
        def rendered(source):return source.replace('__TPM_SOCKET__',repr(str(self.home/'socket'))).replace('__GUEST__',repr(str(self.home/'guest')))
        old=self.run_program(rendered(before));current=self.run_program(rendered(tpm._OWNER_OBSERVE_REMOTE))
        self.assertEqual([],old['processes'])
        self.assertEqual([17],[r['pid'] for r in current['processes']])
    def test_closed_tpm_census_rejects_hidden_or_unreadable_live_process(self):
        source=tpm._PROCESS_CENSUS+'\nimport json\nprint(json.dumps(swtpm_processes()))\n'
        self.assertEqual([],self.run_program(source))
        self.process(17,'swtpm','7',777)
        self.assertEqual([[17,777]],self.run_program(source))
        (self.proc/'self/mountinfo').write_text('1 0 0:1 / /proc rw - proc proc rw,hidepid=2\n')
        result=subprocess.run([sys.executable,'-I','-B','-c',program(tpm._CENSUS_COMMAND,self.home,self.proc,self.home/'root-owned')],capture_output=True,timeout=5)
        self.assertEqual(2,result.returncode)


if __name__=='__main__':unittest.main()

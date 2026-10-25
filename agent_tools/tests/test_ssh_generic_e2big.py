"""Actual kernel prelaunch refusal through synchronous generated SSH callers."""
import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock

from agent_tools import ssh_transport as transport
from agent_tools.tests.test_ssh_automatic_program import PeerFixture


@unittest.skipUnless(os.name == 'posix', 'saved-program coordinator requires POSIX')
class GenericE2BigTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.root.chmod(0o700)
        self.peer=PeerFixture(self.root);self.config=transport.load_config(self.root)

    def argv(self, code):
        return transport.build_ssh_argv(self.config,'explicit-peer',5,
            command=('python3','-I','-B','-c',code,'a space'),
            ssh_binary=str(self.peer.binary),nested_ssh_binary=str(self.peer.binary))

    def test_actual_kernel_refusal_original_red_and_same_command_saved_once_green(self):
        argmax=os.sysconf('SC_ARG_MAX')
        if not 65536<=argmax<=8*1024*1024:self.skipTest('finite native ARG_MAX unavailable')
        remaining=argmax-20000-sum(len(os.fsencode(k))+len(os.fsencode(v))+2 for k,v in os.environ.items())
        padding={};index=0
        while remaining>128:
            name='VC_GENERIC_KERNEL_BUDGET_'+str(index)
            value='E'*min(60000,remaining-len(name)-2)
            padding[name]=value;remaining-=len(name)+len(value)+2;index+=1
        marker=self.root/'once'
        code='PADDING='+repr('X'*32000)+'\nfrom pathlib import Path\nimport sys\np=Path('+repr(str(marker))+')\np.open("a").write("once\\n")\nprint(sys.argv[1]);print(sys.stdin.read());raise SystemExit(7)\n'
        code='exec('+repr(code)+')'
        argv=self.argv(code)
        self.assertIsInstance(argv,transport.BoundInlineArgv)
        self.assertLessEqual(sum(transport.argv_byte_sizes(argv))+len(argv),60000)
        fixture=Path(__file__).parent/'fixtures/ssh_generic_e2big'
        raw=(fixture/'ssh_transport.py.before.source').read_bytes()
        self.assertEqual(json.loads((fixture/'provenance.json').read_bytes())['beforeSha256'],hashlib.sha256(raw).hexdigest())
        old=types.ModuleType('agent_tools._generic_e2big_before');old.__package__='agent_tools';old.__file__=str(fixture/'ssh_transport.py.before.source')
        with mock.patch.dict(sys.modules,{old.__name__:old}):exec(compile(raw,old.__file__,'exec'),old.__dict__)
        with self.peer.environment(),mock.patch.dict(os.environ,padding):
            short=subprocess.run([sys.executable,'-c','pass'],capture_output=True,timeout=5)
            self.assertEqual(0,short.returncode)
            with self.assertRaises(OSError)as error:old.run_ssh(argv,input='payload',text=True,capture_output=True,timeout=10)
            self.assertEqual(errno.E2BIG,error.exception.errno)
            self.assertFalse(marker.exists());self.assertEqual([],self.peer.events())
            result=transport.run_ssh(argv,input='payload',text=True,capture_output=True,timeout=10)
        self.assertEqual(7,result.returncode);self.assertEqual('a space\npayload\n',result.stdout)
        self.assertEqual('',result.stderr);self.assertEqual('once\n',marker.read_text())
        self.assertEqual(2,len(self.peer.events()))
        self.assertTrue(all(x['commandBytes']<=60000 and x['maxArgumentBytes']<=60000 for x in self.peer.events()))
        journal=self.root/'.rag_index/ssh-automatic-program'/argv.saved_plan.correlation
        self.assertEqual(code.encode(),(journal/'program.source').read_bytes())
        self.assertTrue((journal/'submission-returned.json').exists())
        proof=json.loads((journal/'prelaunch-refusal.json').read_bytes())
        intent=json.loads((journal/'file-fallback-intent.json').read_bytes())
        self.assertEqual(errno.E2BIG,proof['errno']);self.assertIs(False,proof['childCreated'])
        self.assertEqual(hashlib.sha256(code.encode()).hexdigest(),intent['programSha256'])
        self.assertEqual(transport.argv_byte_sizes(argv),intent['originalArgumentBytes'])

    def test_healthy_bound_command_has_no_automatic_state(self):
        argv=self.argv('import sys;print(sys.stdin.read());raise SystemExit(4)')
        self.assertEqual(tuple(argv),argv.original_argv)
        with self.peer.environment():
            result=transport.run_ssh(argv,input=b'healthy',capture_output=True,timeout=5)
        self.assertEqual((4,b'healthy\n',b''),(result.returncode,result.stdout,result.stderr))
        self.assertEqual(1,len(self.peer.events()))
        self.assertFalse((self.root/'.rag_index/ssh-automatic-program').exists())

    def test_mutation_cannot_change_fallback_or_original(self):
        argv=self.argv('print("healthy")')
        with self.assertRaises(transport.SshConfigError):argv.append('changed')
        with self.assertRaises(transport.SshConfigError):argv._saved_plan=None
        list.__setitem__(argv,-1,'changed')
        with self.assertRaises(transport.SshConfigError):transport.run_ssh(argv,capture_output=True)
        self.assertEqual([],self.peer.events())

    def test_custom_raw_error_or_ssh_terminal_failure_never_retries(self):
        argv=self.argv('print("healthy")')
        error=OSError(errno.E2BIG,'custom result does not prove prelaunch')
        runner=mock.Mock(side_effect=error)
        with self.assertRaises(OSError)as caught:transport.run_ssh(argv,runner=runner)
        self.assertIs(error,caught.exception);self.assertEqual(1,runner.call_count)
        self.peer.mode.write_text('reject')
        with self.peer.environment(),self.assertRaises(subprocess.CalledProcessError)as caught:
            transport.run_ssh(argv,capture_output=True,check=True,timeout=5)
        self.assertEqual(255,caught.exception.returncode);self.assertEqual(1,len(self.peer.events()))
        self.assertFalse((self.root/'.rag_index/ssh-automatic-program').exists())

    def test_preserved_list_subclass_source_escape_red_and_closed_guard_green(self):
        from agent_tools import source_module_loader as loader
        sources=self.root/'agent_tools';sources.mkdir(mode=0o700)
        for name in ('ssh_transport.py','ssh_automatic_program.py','private_config_custody.py','native_review_source_closure.py','readiness.py','private_inventory_lock.py'):
            shutil.copyfile(Path(transport.__file__).parent/name,sources/name)
        (sources/'entry.py').write_text('from pathlib import Path\nfrom . import ssh_transport as t\ndef carrier(root,binary):\n c=t.load_config(Path(root))\n return t.build_ssh_argv(c,"explicit-peer",5,command=("python3","-c","print(1)"),ssh_binary=binary,nested_ssh_binary=binary)\n')
        fixture=Path(__file__).parent/'fixtures/ssh_generic_e2big'
        raw=(fixture/'source_module_loader.py.before.source').read_bytes()
        self.assertEqual(json.loads((fixture/'provenance.json').read_bytes())['loaderBeforeSha256'],hashlib.sha256(raw).hexdigest())
        old=types.ModuleType('_generic_loader_before');old.__file__=str(fixture/'source_module_loader.py.before.source')
        with mock.patch.dict(sys.modules,{old.__name__:old}):exec(compile(raw,old.__file__,'exec'),old.__dict__)
        for implementation,blocked in ((old,False),(loader,True)):
            proxy=implementation.Adapter(sources,'entry')
            carrier=proxy.carrier(str(self.root),str(self.peer.binary));proxy.close()
            if blocked:
                with self.assertRaisesRegex(ValueError,'closed_adapter_source'):carrier.validate_original()
            else:
                carrier.validate_original()  # causal RED: old list path loses plan custody
        self.assertEqual([],self.peer.events())

    def test_unbound_prelaunch_refusal_has_no_reconstruction_authority(self):
        error=OSError(errno.E2BIG,'actual boundary')
        with mock.patch.object(transport.subprocess,'Popen',side_effect=error)as child:
            with self.assertRaises(transport.PrelaunchE2Big):transport.run_ssh(['fixture','host','true'])
        self.assertEqual(1,child.call_count);self.assertEqual([],self.peer.events())


if __name__=='__main__':unittest.main()

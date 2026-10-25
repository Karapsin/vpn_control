"""Complete existing pipe collectors with real kernel refusal and local SSH peer."""
import errno,hashlib,importlib,json,os,subprocess,sys,tempfile,types,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools import ssh_transport as transport
from agent_tools.tests.test_ssh_automatic_program import PeerFixture


@unittest.skipUnless(os.name=='posix','POSIX saved-program coordinator')
class CollectorE2BigTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.root.chmod(0o700)
        self.peer=PeerFixture(self.root)
        for host in ('archlinux','fedora2328'):
            self.peer.hosts[host]=dict(self.peer.hosts['explicit-peer'])
        self.peer.write_config();self.config=transport.load_config(self.root)

    def before(self,name):
        folder=Path(__file__).parent/'fixtures/ssh_collector_e2big';path=folder/(name+'.py.before.source')
        raw=path.read_bytes();self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['beforeimages'][name+'.py'],hashlib.sha256(raw).hexdigest())
        module=types.ModuleType('agent_tools._collector_before_'+name+'_'+uuid.uuid4().hex)
        module.__package__='agent_tools';module.__file__=str(path)
        with mock.patch.dict(sys.modules,{module.__name__:module}):exec(compile(raw,str(path),'exec'),module.__dict__)
        return module

    def padding(self):
        argmax=os.sysconf('SC_ARG_MAX')
        if not 65536<=argmax<=8*1024*1024:self.skipTest('finite ARG_MAX unavailable')
        remaining=argmax-20000-sum(len(os.fsencode(k))+len(os.fsencode(v))+2 for k,v in os.environ.items());result={};index=0
        while remaining>128:
            name='VC_COLLECTOR_BUDGET_'+str(index);value='E'*min(60000,remaining-len(name)-2)
            result[name]=value;remaining-=len(name)+len(value)+2;index+=1
        return result

    def invoke(self,module,kind,argv,source):
        if kind=='tuple':return module._run_probe(argv,5)
        if kind=='bytes':return module._run(argv,5)
        if kind=='transfer':return module._bounded_run(argv,b'public payload',5)
        if kind=='census':return module._privileged_capture(argv,b'{}',5)
        if kind=='rpm':return module.RpmPublicInstallSshDriver(self.root,timeout_seconds=5,ssh_binary=str(self.peer.binary))._remote(self.config,'explicit-peer',source,())
        if kind=='server':
            builder=transport.build_ssh_argv
            def fixture_binary(*args,**kwargs):
                if len(args)<5:kwargs.update(ssh_binary=str(self.peer.binary),nested_ssh_binary=str(self.peer.binary))
                return builder(*args,**kwargs)
            with mock.patch.object(transport,'build_ssh_argv',side_effect=fixture_binary):return module._remote({'config':self.config},source,())
        raise AssertionError(kind)

    def test_all_contextmanager_collector_owners_actual_red_and_green(self):
        cases=[('arch_ai_loop_observe','tuple'),('android_observation','tuple'),('ssh_jobs','tuple'),('native_host_observation','bytes'),('ssh_transfer','transfer'),('arch_qemu_holder_census','census'),('native_rpm_public_install_ssh','rpm'),('linux_rpm_fixture_server_lifecycle','server')]
        for name,kind in cases:
            with self.subTest(owner=name):
                marker=self.root/('once-'+name)
                source='PADDING='+repr('X'*32000)+'\nfrom pathlib import Path\nimport json,sys\np=Path('+repr(str(marker))+')\np.open("a").write("once\\n")\nprint(json.dumps({"sentinel":1}))\n'
                argv=transport.build_ssh_argv(self.config,'explicit-peer',5,command=('python3','-I','-B','-c','exec('+repr(source)+')'),ssh_binary=str(self.peer.binary),nested_ssh_binary=str(self.peer.binary))
                old=self.before(name);current=importlib.import_module('agent_tools.'+name);count=len(self.peer.events())
                with self.peer.environment(),mock.patch.dict(os.environ,self.padding()):
                    with self.assertRaises(OSError) as native:
                        subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                    self.assertEqual(errno.E2BIG,native.exception.errno)
                    try:self.invoke(old,kind,argv,source)
                    except Exception:pass
                    self.assertFalse(marker.exists());self.assertEqual(count,len(self.peer.events()))
                    result=self.invoke(current,kind,argv,source)
                self.assertEqual('once\n',marker.read_text());self.assertEqual(count+2,len(self.peer.events()))
                if kind=='tuple' or kind=='transfer':self.assertEqual((0,b'{"sentinel": 1}\n'),result)
                elif kind=='bytes':self.assertEqual(b'{"sentinel": 1}\n',result)
                elif kind=='census':self.assertTrue(result['complete']);self.assertEqual(b'{"sentinel": 1}\n',result['stdout'])
                else:self.assertEqual({'sentinel':1},result)
                self.assertTrue(all(x['commandBytes']<=60000 and x['maxArgumentBytes']<=60000 for x in self.peer.events()[count:]))

    def test_popen_existing_collector_contract_retains_stream_custody(self):
        # The same shared boundary also covers the existing tmux/android/package
        # owners that already call popen_ssh and finish_ssh (directly or via _capture).
        marker=self.root/'low-level-once'
        code='exec('+repr('PADDING='+repr('X'*32000)+'\nfrom pathlib import Path\nimport sys\nPath('+repr(str(marker))+').write_text("once")\nprint(sys.stdin.read())\n')+')'
        argv=transport.build_ssh_argv(self.config,'explicit-peer',5,command=('python3','-c',code),ssh_binary=str(self.peer.binary),nested_ssh_binary=str(self.peer.binary))
        fixture=Path(__file__).parent/'fixtures/ssh_generic_e2big'
        raw=(fixture/'ssh_transport.py.before-popen.source').read_bytes()
        self.assertEqual(json.loads((fixture/'provenance.json').read_bytes())['popenBeforeSha256'],hashlib.sha256(raw).hexdigest())
        old=types.ModuleType('agent_tools._popen_before');old.__package__='agent_tools';old.__file__=str(fixture/'ssh_transport.py.before-popen.source')
        with mock.patch.dict(sys.modules,{old.__name__:old}):exec(compile(raw,old.__file__,'exec'),old.__dict__)
        with self.peer.environment(),mock.patch.dict(os.environ,self.padding()):
            with self.assertRaises(OSError)as refusal:
                old.popen_ssh(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            self.assertEqual(errno.E2BIG,refusal.exception.errno)
            self.assertFalse(marker.exists());self.assertEqual([],self.peer.events())
            process=transport.popen_ssh(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            self.assertEqual('SubmittedProcess',type(process).__name__)
            out,err=process.communicate(b'payload',timeout=10);transport.finish_ssh(process)
        self.assertEqual((b'payload\n',b''),(out,err));self.assertEqual('once',marker.read_text());self.assertEqual(2,len(self.peer.events()))
        journal=self.root/'.rag_index/ssh-automatic-program'/argv.saved_plan.correlation
        self.assertTrue((journal/'prelaunch-refusal.json').exists());self.assertTrue((journal/'submission-returned.json').exists())


if __name__=='__main__':unittest.main()

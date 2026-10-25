"""Fresh explicit routes retain source custody and intentional phase ownership."""
import dataclasses,hashlib,json,os,shlex,subprocess,sys,tempfile,time,types,unittest,uuid
from pathlib import Path,PurePosixPath
from unittest import mock
if os.name=='posix':
    from agent_tools import ssh_transport as transport,ssh_forward as forward,ssh_tmux_disconnect_probe as probe

@unittest.skipUnless(os.name=='posix','POSIX controlled SSH endpoints')
class FreshDispatchTests(unittest.TestCase):
    def before(self,name):
        folder=Path(__file__).parent/'fixtures/ssh_fresh_dispatch';path=folder/(name+'.py.before.source');raw=path.read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['beforeimages'][name+'.py'],hashlib.sha256(raw).hexdigest())
        module=types.ModuleType('agent_tools._fresh_before_'+name+'_'+uuid.uuid4().hex);module.__file__=str(path);module.__package__='agent_tools'
        with mock.patch.dict(sys.modules,{module.__name__:module}):exec(compile(raw,str(path),'exec'),module.__dict__)
        sys.modules[module.__name__]=module;self.addCleanup(sys.modules.pop,module.__name__,None)
        return module

    def test_fresh_inline_kernel_refusal_retains_same_route_and_transfer(self):
        from agent_tools.tests.test_ssh_collector_e2big import CollectorE2BigTests
        fixture=CollectorE2BigTests('runTest');fixture.setUp();self.addCleanup(fixture.doCleanups)
        root=fixture.root;peer=fixture.peer
        # Deliberately unavailable current pointer is not recovered or changed
        # during the explicit intentional fresh-outer test phase.
        journal=root/'.rag_index/readiness-ssh-master/explicit-peer'
        for directory in (root/'.rag_index',root/'.rag_index/readiness-ssh-master',journal):directory.mkdir(mode=0o700)
        pointer=journal/'current.json';pointer.write_text('{}');pointer.chmod(0o600)
        marker=root/'fresh-once';code='exec('+repr('PADDING='+repr('X'*32000)+'\nfrom pathlib import Path\nimport sys\nPath('+repr(str(marker))+').write_text("once")\nprint(sys.stdin.read())\n')+')'
        argv=transport.build_ssh_argv(fixture.config,'explicit-peer',5,command=('python3','-I','-B','-c',code),ssh_binary=str(peer.binary),fresh_direct=True)
        self.assertTrue(argv.saved_plan.fresh_direct);self.assertNotIn('ProxyCommand=false',argv)
        self.assertEqual('none',argv[argv.index('-S')+1])
        with peer.environment(),mock.patch.dict(os.environ,fixture.padding()):result=transport.run_ssh(argv,input=b'payload',capture_output=True,timeout=10)
        self.assertEqual((0,b'payload\n',b''),(result.returncode,result.stdout,result.stderr));self.assertEqual('once',marker.read_text());self.assertEqual(2,len(peer.events()));self.assertEqual('{}',pointer.read_text())
        self.assertTrue(all(row['commandBytes']<=60000 and row['maxArgumentBytes']<=60000 for row in peer.events()))

    def test_original_forward_inherits_reuse_only_proxy_current_fresh_master_green(self):
        from agent_tools.tests.test_readiness_transport import ReadinessTransportTests
        fixture=ReadinessTransportTests('runTest');fixture.setUp();self.addCleanup(fixture.doCleanups);fixture.ensure()
        config=transport.load_config(fixture.root)
        target=dataclasses.replace(config.hosts['explicit-peer'],alias='archlinux',transport='nested',gateway='explicit-peer',remote_host_alias='arch',remote_control_path=PurePosixPath('/fixture/existing'))
        config.hosts['archlinux']=target;path=str(fixture.root/'owned-forward.sock');old=self.before('ssh_forward')
        refused=subprocess.run(old._local_argv(config,target,path,'open'),capture_output=True,timeout=3)
        self.assertEqual(255,refused.returncode);self.assertFalse(Path(path).exists())
        argv=forward._local_argv(config,target,path,'open');self.assertNotIn('ProxyCommand=false',argv)
        child=transport.popen_ssh(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        def cleanup():
            if child.poll()is None:child.terminate()
            child.communicate(timeout=3)
        self.addCleanup(cleanup)
        deadline=time.monotonic()+3
        while not Path(path).exists()and time.monotonic()<deadline:time.sleep(.01)
        self.assertTrue(Path(path).exists());self.assertIsNone(child.poll());self.assertEqual(1,len(fixture.children))

    def test_original_disconnect_builder_mutates_bound_carrier_current_keeps_plan(self):
        from agent_tools.tests.test_ssh_tmux_disconnect_probe import DisconnectProbeTests
        fixture=DisconnectProbeTests('runTest');fixture.setUp();self.addCleanup(fixture.doCleanups)
        old=self.before('ssh_tmux_disconnect_probe');old.OWNER_SHA=probe.OWNER_SHA
        previous=old.Probe(fixture.home,'gateway',str(uuid.uuid4()));fixture.instances.append(previous)
        with self.assertRaises(ValueError):previous._argv()
        current=fixture.make('gateway');argv=current._argv()
        self.assertTrue(isinstance(argv,list)or hasattr(argv,'original_argv'))
        raw=tuple(argv)if isinstance(argv,list)else argv.original_argv
        self.assertEqual('/usr/bin/ssh',raw[0]);self.assertNotIn(probe.EXEC,raw);self.assertIn('ControlPath=none',raw)
        self.assertEqual('prepared',current.prepare()['state'])

if __name__=='__main__':unittest.main()

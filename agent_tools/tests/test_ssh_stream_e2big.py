"""Complete retained SSH stream owners: real native E2BIG, one harmless mutation."""
import hashlib,importlib,json,os,subprocess,sys,tempfile,types,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools import ssh_transport as transport


@unittest.skipUnless(os.name=='posix','POSIX stream/source custody')
class StreamE2BigTests(unittest.TestCase):
    def setUp(self):
        from agent_tools.tests.test_ssh_collector_e2big import CollectorE2BigTests
        self.fixture=CollectorE2BigTests('runTest');self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.root=self.fixture.root;self.peer=self.fixture.peer;self.config=self.fixture.config

    def before(self,name,cohort='ssh_stream_e2big'):
        folder=Path(__file__).parent/'fixtures'/cohort;path=folder/(name+'.py.before.source');raw=path.read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['beforeimages'][name+'.py'],hashlib.sha256(raw).hexdigest())
        module=types.ModuleType('agent_tools._stream_before_'+name+'_'+uuid.uuid4().hex);module.__package__='agent_tools';module.__file__=str(path)
        with mock.patch.dict(sys.modules,{module.__name__:module}):exec(compile(raw,str(path),'exec'),module.__dict__)
        return module

    def capture(self):
        from agent_tools.windows_diagnostic_authority_capture import AuthorityCapture
        leaf='stream-'+uuid.uuid4().hex;path=self.root/'.runtime/parity-evidence'/leaf
        path.mkdir(parents=True,mode=0o700);path.chmod(0o700)
        capture=AuthorityCapture(self.root,leaf);self.addCleanup(capture.close);return capture

    def invoke(self,module,name,argv,source):
        capture=self.capture()
        if name=='android_admission_readback':return module._run_stream_probe(argv,5)
        if name=='android_installer_direct_transport':
            capsule=self.root/('capsule-'+uuid.uuid4().hex);capsule.mkdir(mode=0o700)
            return module._transport_capture(capsule,argv,b'public frame','status',self.root,{},hashlib.sha256(source.encode()).hexdigest())
        if name=='windows_cp117_base_source_refresh':
            with tempfile.TemporaryFile()as stream:return module._upload(argv,stream,capture,lambda:None)
        if name=='windows_cp117_bound_absence_completion':return module._stream(argv,lambda _:None)
        if name in ('windows_cp117_fixture_recovery','windows_cp117_fixture_recovery_short_socket'):return module._stream(argv,b'public secret',capture,{})
        if name in ('windows_cp117_recovered_guest_observe','windows_cp117_recovered_login'):
            callback=module._probe_stream if name.endswith('recovered_login')else module._stream
            return (callback(argv,capture,'diagnostic','nonce','a'*64,b'public secret')
                    if name.endswith('recovered_login') else callback(argv,capture,'diagnostic','nonce','a'*64,{}))
        if name in ('windows_cp117_recovered_gui_login','windows_cp117_windowless_gui_login','windows_cp117_windowless_provider_login'):
            return module._stream(argv,capture,'diagnostic','nonce','a'*64,{},b'public secret')
        if name=='windows_parallel_vm_prepare_transport':
            client=module.RetainedClient(argv,b'public secret',capture)
            value=client.observe(5);client.close_terminal();return value
        if name=='windows_parallel_vm_source_inventory':return module.bounded_collect(argv,b'public secret',5)
        if name=='windows_vm_optical_post_collect':
            builder=transport.build_ssh_argv
            def fixture_binary(*args,**kwargs):
                if len(args)<5:kwargs.update(ssh_binary=str(self.peer.binary),nested_ssh_binary=str(self.peer.binary))
                return builder(*args,**kwargs)
            with mock.patch.object(transport,'build_ssh_argv',side_effect=fixture_binary):return module._bounded_ssh(self.root,source,5)
        if name=='native_owner_gui_lifecycle_ssh':
            held=types.SimpleNamespace(finish=lambda:None)
            driver=module.NativeOwnerGuiLifecycleSshDriver(self.root,lambda _:self.root,lambda _:self.root,5,str(self.peer.binary))
            return driver._run_closed(self.config,'explicit-peer',('python3','-I','-B','-c','exec('+repr(source)+')'),b'public payload',held)
        raise AssertionError(name)

    def test_every_migrated_complete_stream_owner_causal_red_green(self):
        names=['android_admission_readback','android_installer_direct_transport','windows_cp117_base_source_refresh','windows_cp117_bound_absence_completion','windows_cp117_fixture_recovery','windows_cp117_fixture_recovery_short_socket','windows_cp117_recovered_guest_observe','windows_cp117_recovered_gui_login','windows_cp117_recovered_login','windows_cp117_windowless_gui_login','windows_cp117_windowless_provider_login','windows_parallel_vm_prepare_transport','windows_parallel_vm_source_inventory','windows_vm_optical_post_collect','native_owner_gui_lifecycle_ssh']
        for name in names:
            with self.subTest(owner=name):
                marker=self.root/('once-'+name)
                source='PADDING='+repr('X'*32000)+'\nfrom pathlib import Path\nimport json\np=Path('+repr(str(marker))+')\np.open("a").write("once\\n")\nprint(json.dumps({"stage":"uid","ok":True,"elapsedMs":0,"summary":{}}))\n'
                argv=transport.build_ssh_argv(self.config,'explicit-peer',5,command=('python3','-I','-B','-c','exec('+repr(source)+')'),ssh_binary=str(self.peer.binary),nested_ssh_binary=str(self.peer.binary))
                old=self.before(name,'ssh_collector_e2big'if name=='native_owner_gui_lifecycle_ssh'else'ssh_stream_e2big');current=importlib.import_module('agent_tools.'+name);events=len(self.peer.events())
                with self.peer.environment(),mock.patch.dict(os.environ,self.fixture.padding()):
                    try:self.invoke(old,name,argv,source)
                    except Exception:pass
                    self.assertFalse(marker.exists());self.assertEqual(events,len(self.peer.events()))
                    # The provider's reviewed current re-pin admits its migrated role; the sealed f54029cf keeps its original pins.
                    result=self.invoke(current,name,argv,source)
                self.assertIsNotNone(result);self.assertEqual('once\n',marker.read_text());self.assertEqual(events+2,len(self.peer.events()))
                self.assertTrue(all(x['commandBytes']<=60000 and x['maxArgumentBytes']<=60000 for x in self.peer.events()[events:]))


    def test_original_missing_time_dependency_after_launch_red_and_fixed_green(self):
        name='windows_cp117_windowless_gui_login';old=self.before(name);current=importlib.import_module('agent_tools.'+name)
        old_marker=self.root/'dependency-before';marker=self.root/'dependency-fixed'
        def argv(path):
            code='from pathlib import Path;import json,sys;sys.stdin.buffer.read(4);Path('+repr(str(path))+').write_text("once");print("{}")'
            return transport.build_ssh_argv(self.config,'explicit-peer',5,command=('python3','-I','-B','-c',code),ssh_binary=str(self.peer.binary),nested_ssh_binary=str(self.peer.binary))
        original=argv(old_marker);children=[];popen=subprocess.Popen
        def retain(*args,**kwargs):
            child=popen(*args,**kwargs);children.append(child);return child
        with self.peer.environment(),mock.patch.object(subprocess,'Popen',side_effect=retain):
            with self.assertRaisesRegex(NameError,'time'):old._stream(original,self.capture(),'diagnostic','nonce','a'*64,{},b'public secret')
        self.assertEqual(1,len(children))
        # The original failed before its try/finally and returned no child.
        # Retain/reap only this positively owned inert local fixture process.
        children[0].communicate(b'xxxx',timeout=5)
        self.assertEqual('once',old_marker.read_text())
        with self.peer.environment():value=current._stream(argv(marker),self.capture(),'diagnostic','nonce','a'*64,{},b'public secret')
        self.assertEqual(({},[]),value);self.assertEqual('once',marker.read_text())


if __name__=='__main__':unittest.main()

"""Actual owned control sockets: readiness before generation and dispatch fences."""
import hashlib,json,os,subprocess,sys,time,types,unittest,uuid
from pathlib import Path
from unittest import mock
if os.name=='posix':
    from agent_tools import readiness,ssh_transport as transport,ssh_dispatch_admission as subject

@unittest.skipUnless(os.name=='posix','POSIX owned control sockets')
class DispatchAdmissionTests(unittest.TestCase):
    def setUp(self):
        from agent_tools.tests.test_readiness_transport import ReadinessTransportTests
        self.fixture=ReadinessTransportTests('runTest');self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.root=self.fixture.root

    def command(self,marker):return ('python3','-I','-B','-c','from pathlib import Path;Path('+repr(str(marker))+').write_text("once");print("{}")')

    def test_explicit_admission_runs_before_build_healthy_dispatch_same_ready(self):
        self.assertEqual([],self.fixture.children)
        with transport.admitted_transport(self.root,'explicit-peer',str(uuid.uuid4()),deadline=time.monotonic()+10)as admission:
            self.assertEqual(1,len(self.fixture.children));self.assertTrue(admission.ready.connection)
            marker=self.root/'sentinel'
            argv=transport.build_ssh_argv(transport.load_config(self.root),'explicit-peer',command=self.command(marker))
            self.assertIs(admission,argv.dispatch_admission)
            result=transport.run_ssh(argv,capture_output=True,timeout=3)
            self.assertEqual((0,b'{}\n',b''),(result.returncode,result.stdout,result.stderr));self.assertEqual('once',marker.read_text())
            self.assertEqual(1,len(self.fixture.children))
        self.assertIsNone(subject.current(self.root,'explicit-peer'))
        with self.assertRaises(readiness.ReadinessBlocked)as raised:transport.run_ssh(argv,capture_output=True,timeout=3)
        self.assertEqual('admission_closed',raised.exception.reason)

    def test_account_change_preserved_unfenced_red_current_prelaunch_green(self):
        folder=Path(__file__).parent/'fixtures/ssh_generic_e2big';raw=(folder/'ssh_transport.py.before.source').read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['beforeSha256'],hashlib.sha256(raw).hexdigest())
        old=types.ModuleType('agent_tools._dispatch_before');old.__package__='agent_tools';old.__file__=str(folder/'ssh_transport.py.before.source')
        with mock.patch.dict(sys.modules,{old.__name__:old}):exec(compile(raw,old.__file__,'exec'),old.__dict__)
        with transport.admitted_transport(self.root,'explicit-peer',str(uuid.uuid4()),deadline=time.monotonic()+10):
            config=transport.load_config(self.root);old_marker=self.root/'old-once';marker=self.root/'blocked-once'
            old_argv=transport.build_ssh_argv(config,'explicit-peer',command=self.command(old_marker))
            argv=transport.build_ssh_argv(config,'explicit-peer',command=self.command(marker))
            self.fixture.mode.write_text('wrong_account')
            old_result=old.run_ssh(old_argv,capture_output=True,timeout=3)
            self.assertEqual(0,old_result.returncode);self.assertTrue(old_marker.exists())  # original causal RED
            with self.assertRaises(readiness.ReadinessBlocked)as raised:transport.popen_ssh(argv,stdout=subprocess.PIPE)
            self.assertEqual('wrong_account',raised.exception.reason);self.assertFalse(marker.exists())
        self.assertEqual(1,len(self.fixture.children))

    def test_pure_builder_outside_context_never_starts_or_recovers(self):
        marker=self.root/'no-dispatch'
        argv=transport.build_ssh_argv(transport.load_config(self.root),'explicit-peer',command=self.command(marker))
        self.assertIsNone(argv.dispatch_admission);self.assertEqual([],self.fixture.children);self.assertFalse(marker.exists())

    def test_sibling_target_cannot_borrow_admission_and_nonpython_carries_guard(self):
        with transport.admitted_transport(self.root,'explicit-peer',str(uuid.uuid4()),deadline=time.monotonic()+10)as admission:
            self.assertIsNone(subject.current(self.root,'other-target'))
            argv=transport.build_ssh_argv(transport.load_config(self.root),'explicit-peer',command=('true',))
            self.assertIs(admission,argv.dispatch_admission);self.assertIsNone(argv.saved_plan)
        with self.assertRaises(readiness.ReadinessBlocked):transport.popen_ssh(argv)

if __name__=='__main__':unittest.main()

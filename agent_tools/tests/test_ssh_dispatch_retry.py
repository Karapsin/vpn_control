"""Actual socket/target execution regression for bounded original packet retry."""
import hashlib,json,os,subprocess,sys,time,types,unittest,uuid
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from agent_tools import readiness,ssh_transport as transport,ssh_automatic_program as automatic
from agent_tools import ssh_dispatch_admission as admissions,ssh_dispatch_retry as subject
from agent_tools.native_review_source_closure import _Held

FIXTURE=Path(__file__).parent/'fixtures/ssh_dispatch_retry'

@unittest.skipUnless(os.name=='posix','owned SSH Unix sockets')
class RetryTests(unittest.TestCase):
    def setUp(self):
        from agent_tools.tests.test_readiness_transport import ReadinessTransportTests
        self.f=ReadinessTransportTests('runTest');self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.root=self.f.root;self.op=str(uuid.uuid4());self.deadline=time.monotonic()+20
        self.counter=self.root/'target-counter'
        self.source=('from pathlib import Path;p=Path('+repr(str(self.counter))+');'
                     'p.write_text(str(int(p.read_text())+1)if p.exists()else"1");print("once")')
        self.intent=self.root/'original-intent.json';self.intent.write_text(json.dumps({'operationId':self.op,'effect':'counter once'}));self.intent.chmod(0o600)
        self.owner_sha=hashlib.sha256(self.intent.read_bytes()).hexdigest();self.held=_Held();self.addCleanup(self.held.close)
        self.held.read(str(self.intent),self.owner_sha,max_bytes=4096)
        self.proofs=[];self.admitted=[];self.built=[]
    def owner(self,proof,attempt):
        self.held.finish();self.held.final_identity_pass()
        self.assertFalse(self.counter.exists());self.proofs.append(proof);return self.owner_sha
    def builder(self,admission,attempt,saved=False):
        self.built.append(admission)
        command=('python3','-I','-B','-c',self.source)
        method=transport.build_saved_program_argv if saved else transport.build_ssh_argv
        return method(transport.load_config(self.root),'explicit-peer',command=command)
    # The stdin-reading staged peer gets explicit EOF, never the caller's stream.
    def submit(self,argv):return transport.run_ssh(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=3)
    @contextmanager
    def factory(self,root,host,op,*,deadline):
        with admissions.admitted_transport(root,host,op,deadline=deadline) as admitted:
            self.admitted.append(admitted);yield admitted
    def run_original(self,**options):
        return subject.run_original(self.root,'explicit-peer',self.op,build=self.builder,submit=self.submit,
            prove_operation_unsubmitted=self.owner,deadline=self.deadline,admission_factory=self.factory,**options)
    def stage_socket(self):
        peer=self.f.binary.read_text().replace(
            'result=subprocess.run(command,stdin=subprocess.DEVNULL,capture_output=True,',
            "result=subprocess.run(command,input=base64.b64decode(request.get('stdin','')),capture_output=True,").replace(
            "client.sendall(json.dumps(request).encode()+b'\\n');reply=receive(client)",
            "if '-O' not in args:request['stdin']=base64.b64encode(sys.stdin.buffer.read()).decode()\n client.sendall(json.dumps(request).encode()+b'\\n');reply=receive(client)")
        self.f.binary.write_text(peer)
    def test_actual_initial_stale_regenerates_same_owner_once_and_closes_old_guard(self):
        original=self.submit
        def submit(argv):
            if not self.proofs:
                admissions.add_dispatch_guard(admissions.current(self.root,'explicit-peer'),
                    lambda:(_ for _ in ()).throw(readiness.ReadinessBlocked('prepared_context_stale',self.op)))
            return original(argv)
        self.submit=submit
        result=self.run_original()
        self.assertEqual((0,b'once\n'),(result.returncode,result.stdout));self.assertEqual('1',self.counter.read_text())
        self.assertEqual(2,len(self.built));self.assertIsNot(self.built[0],self.built[1]);self.assertTrue(all(a.closed for a in self.admitted))
        self.assertEqual(self.op,self.proofs[0].operation_identity)
    def test_actual_poststage_complete_before_red_current_regenerates_green(self):
        self.stage_socket();raw=(FIXTURE/'ssh_automatic_program.py.before.source').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),json.loads((FIXTURE/'provenance.json').read_bytes())['beforeSha256']['ssh_automatic_program.py'])
        old=types.ModuleType('agent_tools._retry_before_'+uuid.uuid4().hex);old.__package__='agent_tools';old.__file__=automatic.__file__
        with mock.patch.dict(sys.modules,{old.__name__:old}):exec(compile(raw,old.__file__,'exec'),old.__dict__)
        with self.factory(self.root,'explicit-peer',self.op,deadline=self.deadline) as admitted:
            plan=old.PlannedArgv(**{key:value for key,value in vars(self.builder(admitted,1,True)).items()if key in old.PlannedArgv.__dataclass_fields__});stage=old._stage
            def stale_old(*a,**kw):
                value=stage(*a,**kw);admissions.add_dispatch_guard(admitted,lambda:(_ for _ in ()).throw(readiness.ReadinessBlocked('prepared_context_stale',self.op)));return value
            with mock.patch.object(old,'_stage',side_effect=stale_old):
                with self.assertRaises(readiness.ReadinessBlocked) as red:
                    with old.automatic_submission(plan):self.fail('old target yielded')
            self.assertNotIsInstance(red.exception,transport.StagedExecutionUnsubmitted)
        self.assertFalse(self.counter.exists());self.admitted.clear();self.built.clear()
        stage=automatic._stage;changed=[]
        def stale(*a,**kw):
            value=stage(*a,**kw)
            if not changed:
                changed.append(True);admitted=admissions.current(self.root,'explicit-peer')
                admissions.add_dispatch_guard(admitted,lambda:(_ for _ in ()).throw(readiness.ReadinessBlocked('prepared_context_stale',self.op)))
            return value
        self.builder=lambda admission,attempt:self.__class__.builder(self,admission,attempt,True)
        with mock.patch.object(automatic,'_stage',side_effect=stale):result=self.run_original()
        self.assertEqual(0,result.returncode);self.assertEqual('1',self.counter.read_text())
        self.assertEqual(2,len(self.built));self.assertIs(type(self.proofs[0]),transport.StagedExecutionUnsubmitted)
        self.assertTrue(self.proofs[0].transfer_submitted)
        history=self.root/'.rag_index/ssh-automatic-program'/self.proofs[0].correlation
        self.assertTrue((history/'staged.json').exists());self.assertTrue((history/'target-execution-unsubmitted.json').exists());self.assertFalse((history/'execution-intent.json').exists())
    def test_unproved_owner_or_raw_guard_never_retries(self):
        for raw in (False,True):
            self.op=str(uuid.uuid4());self.built.clear()
            def submit(argv):
                error=readiness.ReadinessBlocked('prepared_context_stale',self.op)
                if raw:raise error
                raise transport.PrelaunchReadinessRefusal(error,transport.argv_sha256(argv))
            with self.assertRaises(readiness.ReadinessBlocked):subject.run_original(self.root,'explicit-peer',self.op,
                build=self.builder,submit=submit,prove_operation_unsubmitted=lambda *_:None,
                deadline=self.deadline,admission_factory=self.factory)
            self.assertEqual(1,len(self.built));self.assertFalse(self.counter.exists())
    def test_unknown_timeout_and_finished_execution_do_not_retry(self):
        for failure in (subprocess.TimeoutExpired('public',1),readiness.ReadinessBlocked('prepared_context_stale',self.op)):
            self.op=str(uuid.uuid4());self.built.clear()
            def submit(argv):self.submit(argv);raise failure
            with self.assertRaises(type(failure)):subject.run_original(self.root,'explicit-peer',self.op,
                build=self.builder,submit=submit,prove_operation_unsubmitted=self.owner,deadline=self.deadline,admission_factory=self.factory)
            self.assertEqual(1,len(self.built));self.counter.unlink()
    def test_max_three_same_uuid_and_original_held_intent_changed_blocks(self):
        def refused(argv):raise transport.PrelaunchReadinessRefusal(readiness.ReadinessBlocked('prepared_context_stale',self.op),transport.argv_sha256(argv))
        with self.assertRaises(transport.PrelaunchReadinessRefusal):subject.run_original(self.root,'explicit-peer',self.op,
            build=self.builder,submit=refused,prove_operation_unsubmitted=self.owner,deadline=self.deadline,admission_factory=self.factory)
        self.assertEqual(3,len(self.built));self.assertEqual(3,len(self.proofs))
        with self.assertRaises(readiness.ReadinessBlocked):self.run_original()
        self.assertEqual(3,len(self.built));self.op=str(uuid.uuid4());self.built.clear();self.intent.write_text('changed')
        with self.assertRaises(ValueError):subject.run_original(self.root,'explicit-peer',self.op,
            build=self.builder,submit=refused,prove_operation_unsubmitted=self.owner,deadline=self.deadline,admission_factory=self.factory)
        self.assertEqual(1,len(self.built));self.assertFalse(self.counter.exists())
    def test_saved_target_executed_then_stale_is_never_unsubmitted(self):
        self.stage_socket()
        self.builder=lambda admission,attempt:self.__class__.builder(self,admission,attempt,True)
        def submit(argv):
            process=transport.popen_ssh(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            process.communicate(timeout=3)
            admissions.add_dispatch_guard(admissions.current(self.root,'explicit-peer'),
                lambda:(_ for _ in ()).throw(readiness.ReadinessBlocked('prepared_context_stale',self.op)))
            transport.finish_ssh(process)
        self.submit=submit
        with self.assertRaises(readiness.ReadinessBlocked) as error:self.run_original()
        self.assertNotIsInstance(error.exception,transport.StagedExecutionUnsubmitted)
        self.assertEqual('1',self.counter.read_text());self.assertEqual(1,len(self.built));self.assertFalse(self.proofs)
    def test_changed_private_custody_after_stage_has_no_refresh_proof(self):
        self.stage_socket();stage=automatic._stage
        self.builder=lambda admission,attempt:self.__class__.builder(self,admission,attempt,True)
        def changed(*a,**kw):
            result=stage(*a,**kw)
            inventory=self.root/transport.CONFIG_FILENAME
            value=json.loads(inventory.read_bytes());value['hosts']['explicit-peer']['password']='private-test-marker'
            inventory.write_text(json.dumps(value))
            admissions.add_dispatch_guard(admissions.current(self.root,'explicit-peer'),
                lambda:(_ for _ in ()).throw(readiness.ReadinessBlocked('prepared_context_stale',self.op)))
            return result
        with mock.patch.object(automatic,'_stage',side_effect=changed):
            with self.assertRaises(ValueError) as error:self.run_original()
        self.assertNotIsInstance(error.exception,transport.StagedExecutionUnsubmitted)
        self.assertNotIn('private-test-marker',str(error.exception));self.assertFalse(self.proofs)
        self.assertEqual(1,len(self.built));self.assertFalse(self.counter.exists())
    def test_outer_guard_cannot_be_discarded(self):
        with self.factory(self.root,'explicit-peer',self.op,deadline=self.deadline):
            with self.assertRaisesRegex(ValueError,'requires_unwound'):self.run_original()
        self.assertFalse(self.built)

if __name__=='__main__':unittest.main()

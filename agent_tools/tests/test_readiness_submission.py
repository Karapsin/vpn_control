"""Real sockets: original receipt publication and exact no-exec dispatch proof."""
import hashlib,json,os,shlex,shutil,subprocess,sys,time,types,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools import readiness,ssh_transport as transport
if os.name=='posix':
    from agent_tools import readiness_ssh_master as master,readiness_transport as adapter,ssh_dispatch_admission as admission

FIXTURE=Path(__file__).parent/'fixtures/readiness_submission'
def before(name,variant=None):
    filename=name+'.before'+('-'+variant if variant else '')+'.source'
    raw=(FIXTURE/filename).read_bytes()
    key=name+('.'+variant if variant else '')
    assert hashlib.sha256(raw).hexdigest()==json.loads((FIXTURE/'provenance.json').read_bytes())['beforeSha256'][key]
    old=types.ModuleType('agent_tools._submission_before_'+uuid.uuid4().hex);old.__package__='agent_tools';old.__file__=str(FIXTURE/(name+'.before.source'))
    with mock.patch.dict(sys.modules,{old.__name__:old}):exec(compile(raw,old.__file__,'exec'),old.__dict__)
    return old

@unittest.skipUnless(os.name=='posix','POSIX owned SSH sockets')
class SubmissionTests(unittest.TestCase):
    def setUp(self):
        from agent_tools.tests.test_readiness_transport import ReadinessTransportTests
        self.f=ReadinessTransportTests('runTest');self.f.setUp();self.addCleanup(self.f.doCleanups);self.root=self.f.root
    def code(self):
        return ('python3','-I','-B','-c','print("once")')
    def test_lost_ready_original_adapter_red_current_same_owner_green(self):
        old=before('readiness_transport.py')
        self.f.context.adapter=old.TransportAdapter(self.root,'explicit-peer')
        self.f.context.deadline=time.monotonic()+1
        save=master._save;failed=[]
        def lost(d,n,v):
            if n.endswith('.ready.json') and not failed:failed.append(n);raise OSError('inert missing receipt')
            return save(d,n,v)
        with mock.patch.object(master,'_save',side_effect=lost):
            with self.assertRaises(readiness.ReadinessBlocked):self.f.ensure()
        self.assertEqual(1,len(self.f.children))
        self.f.context.adapter=adapter.TransportAdapter(self.root,'explicit-peer');self.f.context.deadline=time.monotonic()+5
        ready=self.f.ensure()
        self.assertTrue(ready.connection);self.assertEqual(1,len(self.f.children))
    def test_original_wrong_rid_and_positive_dead_terminal_without_spawn(self):
        self.f.ensure();owned=master.status(self.root,'explicit-peer');count=len(self.f.children)
        with self.assertRaises((master.MasterUnknown,FileNotFoundError)):master.reconcile_original(self.root,'explicit-peer','b'*64,deadline=time.monotonic()+2)
        self.assertEqual(count,len(self.f.children))
        self.f.children[-1].terminate();self.f.children[-1].wait(timeout=3)
        value=master.reconcile_original(self.root,'explicit-peer',owned['recoveryId'],deadline=time.monotonic()+2)
        self.assertEqual('terminal-failed',value['state']);self.assertEqual(count,len(self.f.children))
        record=json.loads((master._path(self.root,'explicit-peer')/(owned['recoveryId']+'.terminal-failed.json')).read_bytes())
        self.assertTrue(record['knownActorsAbsent']);self.assertTrue(record['privateSocketClosed']);self.assertFalse(record['jobReplayAllowed'])
    def test_exact_initial_guard_old_untyped_red_current_typed_green_pure_still_untyped(self):
        old=before('ssh_transport.py');operation=str(uuid.uuid4())
        with transport.admitted_transport(self.root,'explicit-peer',operation,deadline=time.monotonic()+10):
            argv=transport.build_ssh_argv(transport.load_config(self.root),'explicit-peer',command=self.code())
            self.f.mode.write_text('wrong_account')
            with self.assertRaises(readiness.ReadinessBlocked)as raw:argv.validate_original()
            self.assertNotIsInstance(raw.exception,transport.PrelaunchReadinessRefusal)
            # Preserved complete old boundary returns no proof despite zero exec.
            old_argv=old.BoundInlineArgv(argv.saved_plan,dispatch_admission=argv.dispatch_admission)
            with self.assertRaises(readiness.ReadinessBlocked)as red:old.popen_ssh(old_argv)
            self.assertFalse(hasattr(red.exception,'executable_started'))
            with self.assertRaises(transport.PrelaunchReadinessRefusal)as green:transport.popen_ssh(argv)
            proof=green.exception
            self.assertEqual(operation,proof.operation_identity);self.assertEqual('wrong_account',proof.reason)
            self.assertEqual(transport.argv_sha256(argv),proof.argv_sha256)
            self.assertIs(False,proof.child_handle_returned);self.assertIs(False,proof.executable_started)
    def test_transfer_initial_guard_proof_but_poststage_guard_is_not_proof(self):
        import dataclasses
        from agent_tools import ssh_automatic_program as automatic
        # Extend only this executable seam to forward the real stage stdin
        # through its existing Unix socket, retaining the full generated code.
        peer=self.f.binary.read_text().replace(
            'result=subprocess.run(command,stdin=subprocess.DEVNULL,capture_output=True,',
            "result=subprocess.run(command,input=base64.b64decode(request.get('stdin','')),capture_output=True,").replace(
            "client.sendall(json.dumps(request).encode()+b'\\n');reply=receive(client)",
            "if '-O' not in args:request['stdin']=base64.b64encode(sys.stdin.buffer.read()).decode()\n client.sendall(json.dumps(request).encode()+b'\\n');reply=receive(client)")
        self.f.binary.write_text(peer)
        operation=str(uuid.uuid4())
        with transport.admitted_transport(self.root,'explicit-peer',operation,deadline=time.monotonic()+10):
            plan=transport.build_saved_program_argv(transport.load_config(self.root),'explicit-peer',command=self.code())
            self.f.mode.write_text('wrong_account')
            with self.assertRaises(transport.PrelaunchReadinessRefusal):transport.popen_ssh(plan)
            self.assertFalse((self.root/'.rag_index/ssh-automatic-program').exists())
            # A submission attempt disposes its packet; a proven-unsubmitted owner regenerates.
            with self.assertRaisesRegex(automatic.AutomaticProgramError,'automatic_private_custody_unavailable'):transport.popen_ssh(plan)
            self.f.mode.unlink();stage=automatic._stage
            plan=transport.build_saved_program_argv(transport.load_config(self.root),'explicit-peer',command=self.code())
            def changed(*args,**kwargs):
                result=stage(*args,**kwargs);self.f.mode.write_text('wrong_account');return result
            with mock.patch.object(automatic,'_stage',side_effect=changed):
                with self.assertRaises(readiness.ReadinessBlocked)as error:transport.popen_ssh(plan)
            self.assertNotIsInstance(error.exception,transport.PrelaunchReadinessRefusal)
            self.assertTrue((self.root/'.rag_index/ssh-automatic-program'/plan.correlation/'stage.stdout').exists())
            old=before('ssh_transport.py','reused-stage')
            # That staged packet is disposed too; the same correlation holds fresh
            # custody of the unchanged private files so both callers reach the guard.
            helper=automatic._private_config();outer=transport.connection_host(transport.load_config(self.root),'explicit-peer')
            plan=dataclasses.replace(plan,config_custody=helper.PrivateConfigCustody(transport._private_config_path(self.root)),key_custody=helper.PrivateConfigCustody(outer.identity_file))
            old_argv=old.BoundInlineArgv(plan,dispatch_admission=plan.dispatch_admission)
            # Original complete caller minted a new no-stage proof despite
            # that very correlation already owning a transferred stage.
            with self.assertRaises(old.PrelaunchReadinessRefusal):old.popen_ssh(old_argv)
            with self.assertRaises(readiness.ReadinessBlocked)as repeated:transport.popen_ssh(plan)
            self.assertNotIsInstance(repeated.exception,transport.PrelaunchReadinessRefusal)
    def test_closed_source_initial_guard_before_import_causal_red_green(self):
        from agent_tools import source_module_loader as loader
        tools=Path(transport.__file__).parent
        old=(FIXTURE/'ssh_automatic_program.py.before-closed-source.source').read_bytes()
        self.assertEqual(hashlib.sha256(old).hexdigest(),json.loads((FIXTURE/'provenance.json').read_bytes())['beforeSha256']['ssh_automatic_program.py.closed-source'])
        for original in (True,False):
            folder=self.root/('closed-source-'+str(original));folder.mkdir(mode=0o700)
            for name in ('ssh_transport.py','ssh_automatic_program.py','private_config_custody.py','native_review_source_closure.py','readiness.py','private_inventory_lock.py'):
                shutil.copyfile(tools/name,folder/name)
            if original:(folder/'ssh_automatic_program.py').write_bytes(old)
            (folder/'entry.py').write_text('from pathlib import Path\nfrom . import ssh_transport as t\ndef plan(root):\n return t.build_saved_program_argv(t.load_config(Path(root)),"explicit-peer",command=("python3","-c","print(1)"))\n')
            proxy=loader.Adapter(folder,'entry')
            plan=proxy.plan(str(self.root));automatic=proxy._session.load('ssh_automatic_program');proxy.close()
            if original:
                with self.assertRaises(ModuleNotFoundError):
                    with automatic.automatic_submission(plan):self.fail('closed source escaped')
            else:
                with self.assertRaisesRegex(ValueError,'closed_adapter_source'):
                    with automatic.automatic_submission(plan):self.fail('closed source escaped')
        self.assertEqual([],self.f.children)
        self.assertFalse((self.root/'.rag_index/ssh-automatic-program').exists())

    def test_nested_lost_selection_ack_reconciles_original_without_prepare(self):
        from agent_tools.tests.test_readiness_nested_channel import ReadinessNestedChannelTests
        from agent_tools import readiness_nested_channel as nested
        f=ReadinessNestedChannelTests('runTest');f.setUp();self.addCleanup(f.doCleanups)
        f.admit();original=f.fixture.consumer;old_corr=f.corr;prior=f.fixture.result
        ended={'state':'ended','correlationId':old_corr,'prior':prior,'gatewayBoot':prior['master']['gatewayBoot']}
        def peer(argv,**kwargs):
            corr=shlex.split(argv[-1])[5]
            f.fixture.result=ended if corr==old_corr else {**prior,'correlationId':corr,'controlPath':'/tmp/vpn-channel-'+corr+'/m'}
            return original(argv,**kwargs)
        current=adapter.TransportAdapter(f.root,'archlinux');rid='d'*64
        observed=readiness.Observation('archlinux',current.machine,transport='expired',trusted=True,integrity=True)
        with mock.patch.object(subprocess,'Popen',side_effect=peer):
            with mock.patch.object(nested,'admit',side_effect=OSError('inert lost local publication acknowledgement')):
                with self.assertRaises(OSError):current.recover('reconnect',rid,observed,time.monotonic()+10)
            count=sum(c[6]=='prepare'for c in f.fixture.calls)
            old=before('readiness_transport.py','nested-ack').TransportAdapter(f.root,'archlinux')
            self.assertIsNone(old.reconcile_recovery('reconnect',rid,observed,time.monotonic()+10,1,'a'*64))
            self.assertIs(True,current.reconcile_recovery('reconnect',rid,observed,time.monotonic()+10,1,'a'*64))
            selected=nested.route_options(f.root,'archlinux')
            self.assertEqual(hashlib.sha256((rid+'archlinux').encode()).hexdigest()[:32],selected['correlationId'])
            self.assertIsNone(current.reconcile_recovery('reconnect','e'*64,observed,time.monotonic()+10,1,'a'*64))
        self.assertEqual(count,sum(c[6]=='prepare'for c in f.fixture.calls));self.assertEqual(2,count)
        f.fixture.assert_legacy_unchanged()

    def test_native_projection_serialization_failure_reconciles_same_original_without_second_close(self):
        import ast
        from agent_tools import readiness_workflow
        fixture=Path(__file__).parent/'fixtures/ssh_dispatch_retry'
        raw=(fixture/'native_observation_before.source').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),json.loads((fixture/'provenance.json').read_bytes())['beforeSha256']['native_observation'])
        function=next(node for node in ast.parse(raw).body if isinstance(node,ast.FunctionDef)and node.name=='save')
        self.f.ensure();self.assertEqual(1,len(self.f.children));operation=str(uuid.uuid4());closed=[]
        def close_original_once():
            self.assertFalse(closed);closed.append(self.f.children[0].pid)
            self.f.children[0].terminate();self.f.children[0].wait(timeout=3)
        close_original_once()
        value=self.f.context.adapter.observe(self.f.requirements,time.monotonic()+5)
        self.assertNotEqual('ready',value.transport)
        namespace={'os':os,'json':json,'out':self.root}
        exec(compile(ast.Module(body=[function],type_ignores=[]),'preserved actual native writer','exec'),namespace)
        with self.assertRaises(TypeError):namespace['save']('original-incomplete.json',readiness_workflow.asdict(value))
        # The common public projection fixes only collection. It never repeats
        # the preceding original close; subsequent readiness uses the same UUID.
        projected=readiness_workflow._observation(value)
        (self.root/'fixed-complete.json').write_text(json.dumps(projected))
        self.assertEqual([],projected['idle_blockers'])
        self.f.context.deadline=time.monotonic()+10
        ready=readiness.ensure_ready(self.f.context,self.f.requirements,operation)
        readiness.revalidate(self.f.context,ready)
        self.assertEqual(1,len(closed));self.assertEqual(2,len(self.f.children))
        self.assertTrue((self.root/'original-incomplete.json').exists())

    def test_extra_guards_are_observers_at_actual_dispatch(self):
        calls=[]
        with transport.admitted_transport(self.root,'explicit-peer',str(uuid.uuid4()),deadline=time.monotonic()+10)as owned:
            admission.add_dispatch_guard(owned,lambda:calls.append('guest'))
            self.assertEqual([],calls)
            argv=transport.build_ssh_argv(transport.load_config(self.root),'explicit-peer',command=self.code())
            result=transport.run_ssh(argv,capture_output=True,timeout=3)
            self.assertEqual(0,result.returncode);self.assertTrue(calls)
        with self.assertRaises(ValueError):admission.add_dispatch_guard(owned,lambda:None)

if __name__=='__main__':unittest.main()

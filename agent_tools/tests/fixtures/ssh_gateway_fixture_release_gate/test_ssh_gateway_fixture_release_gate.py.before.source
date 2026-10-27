"""Real inert release admission, original-only no-signal fixture shutdown."""
import ast
from contextlib import contextmanager
import hashlib,json,os,socket,sys,tempfile,time,types,unittest,uuid
from pathlib import Path
from agent_tools.tests import test_ssh_gateway_tmux_master as fixture
from agent_tools.tests import test_ssh_gateway_tmux_master_ssh as adapter_fixture

BEFORE=Path(__file__).parent/'fixtures/ssh_gateway_fixture_release_gate/test_ssh_gateway_tmux_master.py.before.source'
@unittest.skipUnless(os.name=='posix','real owned inert processes/Unix sockets')
class FixtureReleaseGateTests(unittest.TestCase):
    @contextmanager
    def case(self,kind='v1',implementation=fixture):
        case=(adapter_fixture.GatewayAdapterTests if kind=='v2'else implementation.GatewayOwnerTests)('runTest')
        try:case.setUp();yield case
        finally:case.doCleanups()
    def wait(self,predicate,seconds=5):
        deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            result=predicate()
            if result:return result
            time.sleep(.01)
        self.fail('owned fixture observation unavailable')
    def assert_originals_absent(self,records):
        for _,value in records:
            for actor in(value['manager'],value['pane']):
                current=fixture.fixture_observer._identity(actor['pid'])
                self.assertTrue(current is None or current['birth']!=actor['birth'])
    def test_authentic_whole_before_short_gate_red_current_same_delayed_release_green(self):
        raw=BEFORE.read_bytes();self.assertEqual('551216a3c7804b9a6a5213746ae936b5fafde8f77ff96de69f4d2f47d39cd363',hashlib.sha256(raw).hexdigest())
        old=types.ModuleType('_whole_release_gate_before_'+uuid.uuid4().hex);old.__file__=fixture.__file__;sys.modules[old.__name__]=old;exec(compile(raw,str(BEFORE),'exec'),old.__dict__)
        hold=3.5
        for module,short in((old,True),(fixture,False)):
            with self.subTest(short=short),self.case(implementation=module)as case:
                terminal=case.home/'test-pane-terminal.json';text=case.tmux.read_text();anchor='  if child.poll() is not None:break';self.assertEqual(1,text.count(anchor))
                replacement="  if child.poll() is not None:\n   _fd=os.open("+repr(str(terminal))+",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\n   with os.fdopen(_fd,'w')as _out:json.dump({'exitCode':child.returncode,'pid':child.pid},_out)\n   break"
                case.tmux.write_text(text.replace(anchor,replacement));case.prepare();start=time.monotonic()
                if short:self.wait(terminal.exists);self.assertEqual(72,json.loads(terminal.read_bytes())['exitCode'])
                while time.monotonic()-start<hold:time.sleep(.01)
                result=module.owner.operate('release',case.request,case.anchor,'inert-secret');job=module.owner.paths(case.request)[2]
                if short:
                    self.assertEqual('unknown',result['state']);self.assertFalse((job/'child.json').exists());self.assertFalse((job/'release.intent.json').exists())
                else:
                    self.assertEqual('released',result['state']);deadline=time.monotonic()+3
                    while time.monotonic()<deadline:
                        result=module.owner.operate('status',case.request,case.anchor)
                        if result['state']=='ready':break
                        time.sleep(.02)
                    self.assertEqual('ready',result['state']);child=json.loads((job/'child.json').read_bytes())
                    for _ in range(2):self.assertEqual(child,json.loads((job/'child.json').read_bytes()));self.assertEqual('ready',module.owner.operate('status',case.request,case.anchor)['state'])
    def test_authentic_integrated_gateway_only_registry_red_complete_probe_role_green(self):
        from agent_tools import tests as package
        from unittest import mock
        import agent_tools.tests.test_ssh_tmux_disconnect_probe as probe_fixture
        path=BEFORE.with_name('test_ssh_gateway_tmux_master.integrated.before.source');raw=path.read_bytes()
        self.assertEqual('9c5147702bb0ece3700693312b8d36c1775392aebbbd12ccf0d67570d4d0bbd5',hashlib.sha256(raw).hexdigest())
        old=types.ModuleType('_gateway_only_before_'+uuid.uuid4().hex);old.__file__=fixture.__file__;sys.modules[old.__name__]=old;exec(compile(raw,str(path),'exec'),old.__dict__)
        # Compile the complete existing caller against each authentic fixture;
        # only its finite imported fixture binding changes in the counterfactual.
        caller_raw=Path(probe_fixture.__file__).read_bytes()
        for implementation,expected in((old,'unknown'),(fixture,'prepared')):
            module=types.ModuleType('_complete_probe_fixture_'+uuid.uuid4().hex);module.__file__=probe_fixture.__file__
            with mock.patch.object(package,'test_ssh_gateway_tmux_master',implementation):
                exec(compile(caller_raw,probe_fixture.__file__,'exec'),module.__dict__)
            case=module.DisconnectProbeTests('runTest')
            try:
                case.setUp();value=case.make();result=value.prepare();self.assertEqual(expected,result['state'])
                if expected=='prepared':
                    records=case.fixture_registry.records();self.assertEqual(1,len(records));self.assertIsNone(records[0][1]['master'])
                    self.assertIn('time.monotonic()-start<35',case.tmux.read_text())
            finally:case.doCleanups()
            if expected=='prepared':self.assert_originals_absent(records)
    def test_whole_target_reply_mocks_stage_red_explicit_inline_scope_green(self):
        import agent_tools.tests.test_ssh_gateway_bound_carrier as bound
        pairs=(('test_ssh_gateway_bound_carrier.before.source','0e334ff6e2dcf0b7863689cc630f707e432b09ef8e30d2c3b8bc73d1069677b8',bound,'GatewayBoundCarrierTests','test_authentic_old_release_echo_retained_red_public_projection_green',6,0),('test_ssh_gateway_tmux_master_ssh.integrated.before.source','cd4f4ee789bcf7d84589d68b5e9ff6b6ead9ecdf372e5d6eedb8b3322f00c9c1',adapter_fixture,'GatewayAdapterTests','test_readonly_status_actual_child_unknown_and_malformed_reply',0,1))
        for name,digest,current,cls,method,errors,failures in pairs:
            path=BEFORE.with_name(name);raw=path.read_bytes();self.assertEqual(digest,hashlib.sha256(raw).hexdigest())
            old=types.ModuleType('_inline_scope_before_'+uuid.uuid4().hex);old.__file__=current.__file__;sys.modules[old.__name__]=old;exec(compile(raw,str(path),'exec'),old.__dict__)
            for module,expected in((old,(errors,failures)),(current,(0,0))):
                result=unittest.TestResult();getattr(module,cls)(method).run(result)
                self.assertEqual((1,*expected),(result.testsRun,len(result.errors),len(result.failures)),''.join(t for _,t in result.errors+result.failures))
    def test_never_released_v1_and_v2_close_before_owned_roots_removed(self):
        for kind in('v1','v2'):
            with self.subTest(kind=kind):
                case=(adapter_fixture.GatewayAdapterTests if kind=='v2'else fixture.GatewayOwnerTests)('runTest')
                try:
                    case.setUp();case.prepare_adapter()if kind=='v2'else case.prepare();records=case.fixture_registry.records();home=case.home;controller=getattr(case,'controller',None)
                finally:case.doCleanups()
                self.assertFalse(home.exists());self.assertTrue(controller is None or not controller.exists());self.assert_originals_absent(records)
                self.assertEqual([72],[x['workerExitCode']for x in case.fixture_registry.last_closure])
    def test_wrong_nonce_never_stops_worker_or_overwrites_foreign_marker(self):
        with self.case()as case,tempfile.TemporaryDirectory()as outside:
            outside=Path(outside)/'unchanged';outside.write_bytes(b'foreign-data');before=(outside.stat().st_ino,outside.read_bytes());case.prepare();records=case.fixture_registry.records();_,record=records[0];job=Path(record['job']);marker=job/'fixture-stop.json';marker.write_bytes(fixture.owner.canonical({'nonce':'f'*32,'jobIdentity':record['jobIdentity']}));marker.chmod(0o600);original=marker.read_bytes()
            time.sleep(.25);self.assertIsNotNone(fixture.fixture_observer._identity(record['pane']['pid']))
            with self.assertRaisesRegex(ValueError,'foreign_fixture_stop'):case.fixture_registry.finish()
            self.assertEqual(original,marker.read_bytes());self.assertEqual(before,(outside.stat().st_ino,outside.read_bytes()));marker.unlink()
    def test_replaced_job_and_foreign_socket_are_not_touched(self):
        with self.case()as case:
            case.prepare();records=case.fixture_registry.records();_,record=records[0];job=Path(record['job']);moved=job.with_name(job.name+'-original');job.rename(moved);job.mkdir(mode=0o700)
            foreign=socket.socket(socket.AF_UNIX);foreign.bind(str(job/'t'));(job/'t').chmod(0o600);original=(job/'t').stat().st_ino
            try:
                case.fixture_registry.finish();self.assertEqual(original,(job/'t').stat().st_ino);self.assertFalse((job/'fixture-stop.json').exists());self.assert_originals_absent(records)
            finally:foreign.close();(job/'t').unlink();job.rmdir();moved.rename(job)
    def test_foreign_or_reused_actor_receipt_cannot_authorize_cleanup(self):
        with self.case()as case:
            case.prepare();records=case.fixture_registry.records();name,record=records[0];path=case.fixture_registry.path/name;raw=path.read_bytes();changed=dict(record,manager=fixture.fixture_observer._identity(os.getpid()));path.write_bytes(fixture.owner.canonical(changed))
            try:
                with self.assertRaisesRegex(ValueError,'fixture_original_intent_changed'):case.fixture_registry.finish()
                self.assertFalse((Path(record['job'])/'fixture-stop.json').exists());self.assertIsNotNone(fixture.fixture_observer._identity(record['pane']['pid']))
            finally:path.write_bytes(raw)
    def test_missing_original_intent_never_adopts_existing_worker(self):
        with self.case()as case:
            case.prepare();name,record=case.fixture_registry.records()[0];path=case.fixture_registry.path/(name[:-5]+'.intent.json');raw=path.read_bytes();path.unlink()
            try:
                with self.assertRaisesRegex(ValueError,'fixture_original_intent_unavailable'):case.fixture_registry.finish()
                self.assertFalse((Path(record['job'])/'fixture-stop.json').exists());self.assertIsNotNone(fixture.fixture_observer._identity(record['pane']['pid']))
            finally:path.write_bytes(raw);path.chmod(0o600)
    def test_consumed_registry_without_record_preserves_root_not_false_idle(self):
        case=fixture.GatewayOwnerTests('runTest');case.setUp();home=case.home;path=case.fixture_registry.path/'test.intent.json';path.write_bytes(b'{}');path.chmod(0o600)
        try:
            with self.assertRaisesRegex(ValueError,'fixture_owner_publication_unknown'):case.finish()
            self.assertTrue(home.exists());self.assertTrue(path.exists())
        finally:
            path.unlink();case.finish();case.doCleanups();case.fixture_temp.cleanup()
    def test_replaced_registry_stops_before_child_or_foreign_writes(self):
        with self.case()as case:
            original=case.fixture_registry.path;moved=original.with_name(original.name+'-original');original.rename(moved);original.mkdir(mode=0o700)
            sentinel=original/'foreign-data';sentinel.write_bytes(b'untouched');before=(sentinel.stat().st_ino,sentinel.read_bytes())
            try:
                result=fixture.owner.operate('prepare',case.request)
                self.assertEqual('unknown',result['state']);self.assertEqual(['foreign-data'],sorted(p.name for p in original.iterdir()));self.assertEqual(before,(sentinel.stat().st_ino,sentinel.read_bytes()))
            finally:sentinel.unlink();original.rmdir();moved.rename(original)
    def test_ready_budgets_and_no_signal_contract_remain_exact(self):
        before=ast.parse(BEFORE.read_bytes());current=ast.parse(Path(fixture.__file__).read_bytes())
        # Candidate loaders may supply the exact source separately while staged.
        source=getattr(fixture,'_CANDIDATE_SOURCE',None)
        if source is not None:current=ast.parse(source)
        get=lambda tree:next(n for n in ast.walk(tree)if isinstance(n,ast.FunctionDef)and n.name=='ready')
        self.assertEqual(ast.dump(get(before),include_attributes=False),ast.dump(get(current),include_attributes=False))
        with self.case()as case:tree=ast.parse(fixture.fixture_tmux_source(case))
        self.assertFalse(any(isinstance(n,ast.Attribute)and n.attr in('kill','terminate','send_signal','killpg')for n in ast.walk(tree)))
        self.assertIn('for _ in range(3000):',fixture._FIXTURE_GATE)
if __name__=='__main__':unittest.main()

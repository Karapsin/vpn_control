"""Late-ready fixture cleanup awaits its original registry before temp removal."""
import contextlib,errno,hashlib,json,os,re,tempfile,time,types,unittest,uuid
from pathlib import Path
from unittest import mock

from agent_tools import tests as package
from agent_tools.tests import test_ssh_gateway_tmux_master as owner_fixture
from agent_tools.tests import test_ssh_gateway_tmux_master_ssh as adapter_fixture
from agent_tools.tests import test_ssh_gateway_tmux_d606_diagnostic as diagnostic_fixture
from agent_tools.tests import test_ssh_gateway_tmux_ready_reconciliation as ready
from agent_tools.tests import test_ssh_gateway_tmux_reconciliation_status as status_fixture
from agent_tools.tests import test_ssh_tmux_disconnect_probe as probe_fixture
from agent_tools.tests.ssh_gateway_historical_fixture import archived

BEFORE=Path(__file__).parent/'fixtures/ssh_gateway_ready_registry_cleanup/test_ssh_gateway_tmux_ready_reconciliation.py.before.source'
PROVENANCE=Path(__file__).parent/'fixtures/ssh_gateway_ready_registry_cleanup/provenance.json'
BEFORE_SHA='4efc7873a699fcb4449b1f972d24e61f63b1f39d73b3b7107017cf98a6a54238'
ORIGINAL='test_last_body_read_status_source_and_retirement_drift_rejects'
# Every repository GatewayOwnerTests subclass is defined in one of these modules.
SUBCLASS_MODULES=(adapter_fixture,diagnostic_fixture,ready,status_fixture,probe_fixture)
# Fixed fake-tmux manager tail: its done record is published only after t is unlinked.
_DONE=" assert _fixture_id(os.fstat(registry_fd))==registry_identity==_fixture_id(registry.stat(follow_symlinks=False))\n _fixture_publish(registry_fd,record_name[:-5]+'.done.json',"
_EXIT=" os.close(job_fd);os.close(registry_fd);raise SystemExit(0)"


@unittest.skipUnless(os.name=='posix','real owned inert processes/Unix sockets')
class ReadyRegistryCleanupTests(unittest.TestCase):
    def before(self):
        provenance=json.loads(PROVENANCE.read_bytes());raw=BEFORE.read_bytes()
        self.assertEqual((BEFORE_SHA,len(raw),False),(provenance['sourceSha256'],provenance['sourceBytes'],provenance['nativeFailureClaimed']))
        self.assertEqual(BEFORE_SHA,hashlib.sha256(raw).hexdigest());self.assertEqual(status_fixture.__name__+'.ReconciliationStatusTests.'+ORIGINAL,provenance['originalFailureTestId'])
        module=types.ModuleType('_ready_registry_cleanup_before_'+uuid.uuid4().hex);module.__file__=ready.__file__
        exec(compile(raw,str(BEFORE),'exec'),module.__dict__);return module

    def original(self,implementation):
        """Unchanged original status case; only its ReadyReconciliationTests source differs."""
        raw=Path(status_fixture.__file__).read_bytes();caller=types.ModuleType('_ready_registry_cleanup_status_'+uuid.uuid4().hex);caller.__file__=status_fixture.__file__
        with mock.patch.object(package,'test_ssh_gateway_tmux_ready_reconciliation',implementation):exec(compile(raw,status_fixture.__file__,'exec'),caller.__dict__)
        case=caller.ReconciliationStatusTests(ORIGINAL);calls=[]
        actual_write,actual_finish,actual_rmdir=Path.write_text,owner_fixture.FixtureChildren.finish,os.rmdir
        with tempfile.TemporaryDirectory(prefix='vct-registry-control-',dir='/tmp')as control:
            release,published=Path(control)/'release',Path(control)/'published'
            def write(path,text,*args,**kwargs):
                if path==getattr(case,'tmux',None)and _DONE in text and str(release)not in text:
                    # Only the emitted manager's done publication waits for an owned release marker.
                    self.assertEqual((1,1),(text.count(_DONE),text.count(_EXIT)))
                    hold=" _owned_release=pathlib.Path("+repr(str(release))+");_owned_deadline=time.monotonic()+60\n while not _owned_release.exists() and time.monotonic()<_owned_deadline:time.sleep(.01)\n"
                    text=text.replace(_DONE,hold+_DONE).replace(_EXIT," pathlib.Path("+repr(str(published))+").touch()\n"+_EXIT)
                return actual_write(path,text,*args,**kwargs)
            def finish(registry,*args,**kwargs):
                calls.append(registry);release.touch();return actual_finish(registry,*args,**kwargs)
            def rmdir(path,*args,dir_fd=None,**kwargs):
                home=getattr(case,'home',None)
                if home is not None and os.path.basename(path)=='.fixture-children'and os.path.samestat(os.fstat(dir_fd)if dir_fd is not None else os.stat(os.path.dirname(path)or'.'),os.stat(home)):
                    # An unawaited publication lands exactly while rmtree removes the owned registry.
                    release.touch();deadline=time.monotonic()+30
                    while not published.exists():
                        if time.monotonic()>=deadline:raise AssertionError('owned_late_publication_unavailable')
                        time.sleep(.01)
                return actual_rmdir(path,*args,dir_fd=dir_fd,**kwargs)
            with archived()as(adapter,diagnostic),mock.patch.dict(caller.__dict__,{'adapter':adapter,'diagnostic':diagnostic}),\
                 mock.patch.dict(implementation.__dict__,{'adapter':adapter,'diagnostic':diagnostic}),mock.patch.object(Path,'write_text',write),\
                 mock.patch.object(owner_fixture.FixtureChildren,'finish',finish),mock.patch.object(os,'rmdir',rmdir):
                result=unittest.TestResult();case.run(result)
        return case,result,calls

    def assert_originals_end(self,values,seconds=10):
        # The manager publishes its record just before its own natural exit; no signals.
        deadline=time.monotonic()+seconds
        while True:
            alive=[actor for value in values for actor in(value['manager'],value['pane'])if(current:=owner_fixture.fixture_observer._identity(actor['pid']))is not None and current['birth']==actor['birth']]
            if not alive:return
            if time.monotonic()>=deadline:self.fail('original fixture actors remain: '+json.dumps(alive))
            time.sleep(.02)

    def test_authentic_unfixed_finish_late_done_red_delegating_registry_wait_green(self):
        case,result,calls=self.original(self.before())
        registry=Path(case.fixture_temp.name)/'.fixture-children';job='vct-'+uuid.UUID(case.request['correlationId']).hex[:16]
        self.assertEqual((1,0,1,[]),(result.testsRun,len(result.failures),len(result.errors),calls),''.join(t for _,t in result.failures+result.errors))
        self.assertRegex(result.errors[0][1],r"OSError: \[Errno %d\] Directory not empty: '(%s/)?\.fixture-children'"%(errno.ENOTEMPTY,re.escape(case.fixture_temp.name)))
        self.assertEqual([job+'.done.json'],os.listdir(registry));done=json.loads((registry/(job+'.done.json')).read_bytes())
        self.assertEqual((case.fixture_nonce,True,0),(done['nonce'],done['originalSocketRetired'],done['workerExitCode']))
        self.assert_originals_end([done]);case.fixture_temp.cleanup()  # Owned RED leftovers, only after the originals ended.
        case,result,calls=self.original(ready)
        self.assertEqual((1,0,0,[case.fixture_registry]),(result.testsRun,len(result.failures),len(result.errors),calls),''.join(t for _,t in result.failures+result.errors))
        self.assertFalse(os.path.lexists(case.fixture_temp.name));self.assertEqual([job+'.json'],[name for name,_ in case.fixture_registry.last_records])
        self.assert_originals_end(case.fixture_registry.last_closure,0)

    def delegate(self,cls,error,endpoint):
        case=cls('runTest');case.request={};temp=tempfile.TemporaryDirectory(prefix='vct-finish-delegation-',dir='/tmp');case.fixture_temp=temp;case.addCleanup(temp.cleanup)
        case.fixture_registry=registry=mock.Mock(**{'finish.side_effect':error});other=[];case.addCleanup(other.append,True)
        job=Path(temp.name)/'job';job.mkdir();(job/'t').touch()  # Owned endpoint that never closes: the closure's own timeout assertion.
        with mock.patch.object(owner_fixture.owner,'paths',return_value=(None,None,job))if endpoint else contextlib.nullcontext(),\
             mock.patch.object(owner_fixture.owner,'master_path',return_value=job/'absent'/'m')if endpoint else contextlib.nullcontext(),\
             mock.patch.dict(cls.finish.__globals__,{'_CLEANUP_SECONDS':0}):
            try:case.finish()
            except Exception as raised:outcome=raised
            else:outcome=None
        case.doCleanups();retained=os.path.isdir(temp.name)and not temp._finalizer.alive;temp.cleanup()  # Retained past finalization too.
        self.assertEqual([True],other)  # Only the owned temp home is ever retained; other cleanups still run.
        return registry.finish.call_count,outcome,retained

    def test_every_finish_override_delegates_once_and_registry_failure_retains_home(self):
        before=self.before();walked,pending=[],[owner_fixture.GatewayOwnerTests]
        while pending:
            for cls in pending.pop().__subclasses__():
                if cls not in walked:walked.append(cls);pending.append(cls)
        self.assertLessEqual({module.__name__ for module in SUBCLASS_MODULES},{cls.__module__ for cls in walked})
        old=[cls for cls in walked if cls.__module__==before.__name__ and 'finish' in vars(cls)]
        current=[cls for cls in walked if cls.__module__.startswith('agent_tools.')and 'finish' in vars(cls)]
        self.assertEqual([before.ReadyReconciliationTests],old);self.assertIn(ready.ReadyReconciliationTests,current)
        for cls,endpoint in((cls,endpoint)for cls in old+current for endpoint in(False,True)):
            with self.subTest(override=cls.__module__+'.'+cls.__qualname__,endpoint=endpoint):
                failure=ValueError('fixture_original_cleanup_unknown')
                (count,own,kept),(failed,raised,retained)=self.delegate(cls,None,endpoint),self.delegate(cls,failure,endpoint)
                if cls in old:
                    # Unfixed: never awaits the registry, so a registry failure cannot retain the home.
                    self.assertEqual((0,0,False,False),(count,failed,kept,retained))
                else:
                    # One delegated wait; a registry failure propagates and retains the owned home,
                    # while the override's own closure failure is raised, and chained under that
                    # registry failure, instead of being swallowed. isinstance on both, before any
                    # message check: a swallowing except leaves both None (a type comparison is vacuous).
                    # Implicitly chained, never suppressed: 'from None' keeps __context__ yet hides it from the unittest report.
                    self.assertEqual((1,1,False,True),(count,failed,kept,retained));self.assertIs(failure,raised)
                    self.assertIsInstance(own,AssertionError);self.assertIsInstance(raised.__context__,AssertionError);self.assertFalse(raised.__suppress_context__)
                self.assertIn('finite-cleanup' if endpoint else 'could not establish its owned endpoint closure',str(own))  # The intended closure path.


if __name__=='__main__':unittest.main()

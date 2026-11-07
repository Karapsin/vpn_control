"""A public counter start gets a real budget, and a transport timeout stays typed.

Natively (2026-11-06, operation 91e074bf) the 180 s route budget spent 171 s on
readiness, namespace and revalidation packets. The first job packet then had 0.1 s,
its SSH timed out, and the exception left the public route as a raw command line.
The local attempt stays unknown by design, and nothing reached the guest.
"""
import ast,hashlib,json,os,subprocess,sys,tempfile,time,types,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools import mcp_server,native_next_action,readiness,readiness_windows as windows,readiness_windows_jobs as jobs

FIXTURE=Path(__file__).parent/'fixtures/windows_native_tools_20261106'
NATIVE_ADMISSION=171
PACKET_BOUND=120
OPERATION='00000000-0000-4000-8000-000000000001'


def provenance():return json.loads((FIXTURE/'provenance.json').read_bytes())


def before_bytes(filename):
    raw=(FIXTURE/filename).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=provenance()['sha256'][filename]:raise AssertionError(filename+' beforeimage changed')
    return raw


def before_jobs():
    module=types.ModuleType('agent_tools._job_budget_before_'+uuid.uuid4().hex);module.__package__='agent_tools';module.__file__=str(FIXTURE/'jobs.before.source')
    sys.modules[module.__name__]=module;exec(compile(before_bytes('jobs.before.source'),module.__file__,'exec'),module.__dict__);return module


class Stop(Exception):pass


def route_budget(module):
    """The real facade's own deadline, measured at the fixture it reaches."""
    seen=[]
    def context(*,deadline=None):
        seen.append(deadline-time.monotonic());raise Stop()
    backend=types.SimpleNamespace(provider='raw-qemu-windows')
    fixture=types.SimpleNamespace(adapter=types.SimpleNamespace(backend=backend),context=context)
    with mock.patch('agent_tools.readiness_fixture_registry.registered_fixture',return_value=fixture),mock.patch.object(module,'has_original',return_value=False):
        with self_raises(Stop):module.workflow(Path('.'),'start',{'fixtureId':'fixture','operationId':OPERATION,'count':80,'intervalSeconds':.25})
    return seen[0]


class self_raises:
    def __init__(self,kind):self.kind=kind
    def __enter__(self):return self
    def __exit__(self,kind,value,traceback):
        if kind is not self.kind:raise AssertionError('expected '+self.kind.__name__)
        return True


class BudgetTests(unittest.TestCase):
    def test_before_budget_leaves_no_time_for_the_first_job_packet(self):
        self.assertLess(route_budget(before_jobs()),NATIVE_ADMISSION+PACKET_BOUND)
    def test_current_budget_covers_admission_and_two_packets(self):
        self.assertGreaterEqual(route_budget(jobs),NATIVE_ADMISSION+2*PACKET_BOUND)
        self.assertLessEqual(route_budget(jobs),readiness.COLD_BUDGET)


@unittest.skipUnless(os.name=='posix','POSIX private-file custody')
class ShortDeadlineTests(unittest.TestCase):
    def start(self,module):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        root=Path(temporary.name).resolve();root.chmod(0o700)
        executor=object.__new__(module.WindowsJobExecutor);executor.target='target';executor.machine='machine';executor._snapshot={'fixed':True}
        submitted=mock.Mock(return_value={'state':'running','reason':'original_owner_running','identity':{}})
        backend=types.SimpleNamespace(provider='raw-qemu-windows',windows_job_executor=lambda deadline=None:executor)
        fixture=types.SimpleNamespace(adapter=types.SimpleNamespace(backend=backend),context=lambda deadline=None:object(),target='target',machine='machine')
        inputs={'fixtureId':'fixture','operationId':OPERATION,'count':80,'intervalSeconds':.25}
        with mock.patch('agent_tools.readiness_fixture_registry.registered_fixture',return_value=fixture),mock.patch('agent_tools.readiness.ensure_ready',return_value=object()),\
             mock.patch('agent_tools.readiness.revalidate'),mock.patch.object(module.WindowsJobExecutor,'submit',submitted),\
             mock.patch.object(module.WindowsJobExecutor,'snapshot',lambda self:self._snapshot),mock.patch.object(module,'_save_observation',side_effect=lambda path,intent,observed:observed):
            try:result=module.workflow(root,'start',inputs,deadline=time.monotonic()+30)
            except ValueError as error:result=str(error)
        return result,submitted,(root/'.runtime/readiness-windows-guest-jobs/fixture'/OPERATION/'intent.json').exists()
    def test_before_short_deadline_records_an_attempt_it_cannot_finish(self):
        _,submitted,intent=self.start(before_jobs())
        self.assertTrue(intent);submitted.assert_called_once()
    def test_current_short_deadline_refuses_before_any_record_or_submission(self):
        result,submitted,intent=self.start(jobs)
        self.assertEqual('windows_job_budget_insufficient',result);self.assertFalse(intent);submitted.assert_not_called()


def before_guidance():
    filename='next_action-unknown.before.source'
    module=types.ModuleType('agent_tools._guidance_before_'+uuid.uuid4().hex);module.__package__='agent_tools';module.__file__=str(FIXTURE/filename)
    sys.modules[module.__name__]=module;exec(compile(before_bytes(filename),module.__file__,'exec'),module.__dict__);return module


def before_backend():
    filename='windows-reconcile.before.source'
    module=types.ModuleType('agent_tools._backend_before_'+uuid.uuid4().hex);module.__package__='agent_tools';module.__file__=str(FIXTURE/filename)
    sys.modules[module.__name__]=module;exec(compile(before_bytes(filename),module.__file__,'exec'),module.__dict__);return module


@unittest.skipUnless(os.name=='posix','POSIX private-file custody')
class UnknownAfterSubmissionTests(ShortDeadlineTests):
    def submit_times_out(self,module):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        root=Path(temporary.name).resolve();root.chmod(0o700)
        executor=object.__new__(module.WindowsJobExecutor);executor.target='target';executor.machine='machine';executor._snapshot={'fixed':True,'provider':'raw-qemu-windows'}
        backend=types.SimpleNamespace(provider='raw-qemu-windows',windows_job_executor=lambda deadline=None:executor)
        fixture=types.SimpleNamespace(adapter=types.SimpleNamespace(backend=backend),context=lambda deadline=None:object(),target='target',machine='machine')
        inputs={'fixtureId':'fixture','operationId':OPERATION,'count':80,'intervalSeconds':.25}
        with mock.patch('agent_tools.readiness_fixture_registry.registered_fixture',return_value=fixture),mock.patch('agent_tools.readiness.ensure_ready',return_value=object()),\
             mock.patch('agent_tools.readiness.revalidate'),mock.patch.object(module.WindowsJobExecutor,'submit',side_effect=subprocess.TimeoutExpired(['ssh','/private/key'],.1)),\
             mock.patch.object(module.WindowsJobExecutor,'snapshot',lambda self:self._snapshot):
            return module.workflow(root,'start',inputs,deadline=time.monotonic()+300)
    def test_before_timeout_after_the_local_intent_escapes(self):
        with self.assertRaises(subprocess.TimeoutExpired):self.submit_times_out(before_jobs())
    def test_current_timeout_after_the_local_intent_is_unknown_and_points_at_the_original(self):
        result=self.submit_times_out(jobs)
        self.assertEqual(('unknown','windows_job_submission_unknown',False),(result['state'],result['reason'],result['replayAllowed']))
        self.assertEqual('reconcile_original',native_next_action.next_action('vm_workflow','guest-program-start',result)['kind'])
        self.assertEqual('resolve_blocker',before_guidance().next_action('vm_workflow','guest-program-start',result)['kind'])
    # Inherited short-deadline cases already ran in their own class.
    test_before_short_deadline_records_an_attempt_it_cannot_finish=None
    test_current_short_deadline_refuses_before_any_record_or_submission=None


class LeaseUnknownTests(unittest.TestCase):
    def dispatch(self,module):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        executor=object.__new__(module.WindowsLeaseExecutor);executor.root=Path(temporary.name).resolve();executor.binding='binding';executor._snapshot={'host':{}}
        executor.backend=types.SimpleNamespace(_run=mock.Mock(side_effect=subprocess.TimeoutExpired(['ssh','/private/key'],.1)))
        with mock.patch.object(module.WindowsLeaseExecutor,'_guard',create=True),mock.patch.object(module.WindowsLeaseExecutor,'_state',return_value=executor.root):
            return module.WindowsLeaseExecutor._dispatch(executor,'cancel',OPERATION,deadline=time.monotonic()+30)
    def test_before_timeout_escapes_and_current_stays_with_the_original(self):
        with self.assertRaises(subprocess.TimeoutExpired):self.dispatch(before_backend())
        result=self.dispatch(windows)
        self.assertEqual(('unknown','windows_original_lease_transport_unknown','observe_original',False),(result['state'],result['reason'],result['nextAction'],result['replayAllowed']))
        self.assertNotIn('/private/key',json.dumps(result))
    def test_guidance_follows_the_original_for_both_lease_unknowns(self):
        base={'fixtureId':'fixture','operationId':OPERATION,'replayAllowed':False,'state':'unknown','jobState':'unknown'}
        for reason,ok in (('windows_original_lease_transport_unknown',False),('original_lease_evidence_unavailable',True)):
            reply={**base,'reason':reason,'ok':ok}
            self.assertEqual('observe_original',native_next_action.next_action('vm_workflow','readiness-lease-status',reply)['kind'])
            self.assertEqual('resolve_blocker',before_guidance().next_action('vm_workflow','readiness-lease-status',reply)['kind'])
        self.assertEqual('resolve_blocker',native_next_action.next_action('vm_workflow','readiness-lease-status',{**base,'reason':'anything_else','ok':False})['kind'])


class FreshClientTests(unittest.TestCase):
    NATIVE_START=232.9
    def test_before_client_gave_every_call_ninety_seconds(self):
        source=before_bytes('client.before.source').decode()
        self.assertIn('min(90, remaining + CLOSE_GRACE_SECONDS)',source);self.assertNotIn('_read_seconds',source)
        self.assertLess(90,self.NATIVE_START)
    def test_current_client_can_wait_for_a_start_and_keeps_other_reads_short(self):
        tree=ast.parse((Path(__file__).parents[1]/'ssh_program_mcp_client.py').read_text(encoding='utf-8'))
        wanted=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_read_seconds' or isinstance(n,ast.Assign) and getattr(n.targets[0],'id','') in {'CLOSE_GRACE_SECONDS','_LONG_START_READ_SECONDS','_LONG_START_FOLLOW_SECONDS'}]
        namespace={};exec(compile(ast.Module(body=wanted,type_ignores=[]),'client','exec'),namespace)
        self.assertGreater(namespace['_read_seconds']('guest-program-start',700),readiness.COLD_BUDGET)
        self.assertEqual(90,namespace['_read_seconds']('program-start',700));self.assertEqual(90,namespace['_read_seconds']('guest-program-status',700))
        self.assertGreater(namespace['_LONG_START_FOLLOW_SECONDS'],namespace['_LONG_START_READ_SECONDS'])


def compile_branch(text,name):
    """One verbatim route branch as a function over the same free names."""
    body=''.join('    '+line[8:] if line.strip() else line for line in text.splitlines(keepends=True))
    source='def route(action,inputs,_agent_module,REPO_ROOT,subprocess,re,_valid_uuid):\n'+body+'    raise AssertionError("branch not taken")\n'
    namespace={};exec(compile(source,name,'exec'),namespace);return namespace['route']


def before_branches():
    guest,lease=before_bytes('route_timeout.before.source').decode().split('# LEASE\n')
    return compile_branch(guest.split('# GUEST\n')[1],'before-guest'),compile_branch(lease,'before-lease')


def current_branches():
    source=Path(mcp_server.__file__).read_text(encoding='utf-8');lines=source.splitlines(keepends=True);found=[]
    dispatch=next(node for node in ast.walk(ast.parse(source)) if isinstance(node,ast.FunctionDef) and node.name=='_vm_workflow_dispatch')
    branches=[node for node in ast.walk(dispatch) if isinstance(node,ast.If)]
    for marker in ('"guest-program-start", "guest-program-status"','"readiness-lease-acquire", "readiness-lease-status"'):
        rows=[node for node in branches if marker in ''.join(lines[node.test.lineno-1:node.test.end_lineno])]
        if len(rows)!=1:raise AssertionError(marker)
        found.append(compile_branch(''.join(lines[rows[0].lineno-1:rows[0].end_lineno]),'current-'+marker))
    return found


class RouteTimeoutTests(unittest.TestCase):
    secret_argv=['ssh','-i','/private/key','remote program text']
    def call(self,route,action,inputs):
        failing=mock.Mock(side_effect=subprocess.TimeoutExpired(self.secret_argv,.1))
        module=types.SimpleNamespace(workflow=failing,ReadinessBlocked=type('Blocked',(Exception,),{}))
        return route(action,inputs,lambda name:module,Path('.'),subprocess,__import__('re'),lambda value:True)
    def test_before_routes_let_the_raw_command_escape(self):
        guest,lease=before_branches()
        with self.assertRaises(subprocess.TimeoutExpired) as caught:self.call(guest,'guest-program-start',{'fixtureId':'fixture','operationId':OPERATION})
        self.assertIn('/private/key',str(caught.exception))
        with self.assertRaises(subprocess.TimeoutExpired):self.call(lease,'readiness-lease-acquire',{'fixtureId':'fixture','operationId':OPERATION})
    def test_current_start_failure_answers_from_its_retained_record_when_one_exists(self):
        guest,_=current_branches()
        original={'state':'unknown','reason':'windows_job_submission_unknown','operationId':OPERATION,'fixtureId':'fixture','replayAllowed':False}
        def workflow(root,verb,inputs):
            if verb=='start':raise ValueError('windows_job_control_unknown')
            self.assertEqual('status',verb);return original
        module=types.SimpleNamespace(workflow=workflow,ReadinessBlocked=type('Blocked',(Exception,),{}))
        result=guest('guest-program-start',{'fixtureId':'fixture','operationId':OPERATION,'count':80,'intervalSeconds':.25},lambda name:module,Path('.'),subprocess,__import__('re'),lambda value:True)
        self.assertEqual(('unknown','windows_job_submission_unknown',False,False),(result['state'],result['reason'],result['ok'],result['replayAllowed']))
    def test_current_budget_refusal_keeps_its_name_at_the_route(self):
        guest,_=current_branches()
        def workflow(root,verb,inputs):raise ValueError('windows_job_budget_insufficient')
        module=types.SimpleNamespace(workflow=workflow,ReadinessBlocked=type('Blocked',(Exception,),{}))
        result=guest('guest-program-start',{'fixtureId':'fixture','operationId':OPERATION,'count':80,'intervalSeconds':.25},lambda name:module,Path('.'),subprocess,__import__('re'),lambda value:True)
        self.assertEqual(('blocked','windows_job_budget_insufficient'),(result['state'],result['reason']))
    def test_lease_packet_that_ended_uncleanly_points_at_the_original(self):
        reply={'fixtureId':'fixture','operationId':OPERATION,'replayAllowed':False,'state':'unknown','reason':'windows_original_outcome_unknown'}
        self.assertEqual('observe_original',native_next_action.next_action('vm_workflow','readiness-lease-status',reply)['kind'])
        self.assertEqual('resolve_blocker',before_guidance().next_action('vm_workflow','readiness-lease-status',reply)['kind'])
    def test_current_routes_answer_typed_with_no_replay_and_no_command_text(self):
        guest,lease=current_branches()
        for route,action,reason in ((guest,'guest-program-start','guest_program_admission_unavailable'),(lease,'readiness-lease-acquire','readiness_lease_admission_unavailable')):
            result=self.call(route,action,{'fixtureId':'fixture','operationId':OPERATION})
            self.assertEqual(('blocked',reason,False,False),(result['state'],result['reason'],result['ok'],result['replayAllowed']))
            self.assertNotIn('/private/key',json.dumps(result))
            self.assertEqual((OPERATION,'fixture'),(result['operationId'],result['fixtureId']))


if __name__=='__main__':unittest.main()

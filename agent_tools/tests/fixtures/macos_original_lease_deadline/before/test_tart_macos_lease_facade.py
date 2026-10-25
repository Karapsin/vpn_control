"""Actual durable caller admission with a read-only original executor boundary."""
import importlib.util
import os
import json
import socket
import socketserver
import threading
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock
from uuid import uuid4

from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_lease_workflow as current
from agent_tools import readiness


@unittest.skipUnless(os.name == 'posix', 'real detached POSIX execution owner')
class LeaseFacadeTests(unittest.TestCase):
    def background_scenario(self, flow):
        """Whole facade, real TCP observation/recovery and detached owner."""
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();root.chmod(0o700)
            journal=root/'journal';journal.mkdir(mode=0o700)
            owner_root=root/'owner';owner_root.mkdir(mode=0o700)
            operation=str(uuid4());bound=jobs.current_binding('controlled-background','same-machine')
            generation=jobs.root_generation(owner_root)
            program=jobs.Program('controlled-background',b"print('background-once',flush=True)\n",4096)
            events=[];display=['sleeping'];submissions=[]
            class Handler(socketserver.StreamRequestHandler):
                def handle(self):
                    request=json.loads(self.rfile.readline(2048))
                    if request['action']!='observe':events.append(request['action']);display[0]='ready'
                    self.wfile.write(json.dumps({'display':display[0]}).encode()+b'\n')
            server=socketserver.ThreadingTCPServer(('127.0.0.1',0),Handler)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            def request(action):
                with socket.create_connection(server.server_address,timeout=2)as client:
                    client.sendall(json.dumps({'action':action}).encode()+b'\n')
                    return json.loads(client.makefile('rb').readline(2048))
            class Adapter:
                capabilities=frozenset({'wake_display'})
                support=SimpleNamespace(lane='tart-macos')
                backend=SimpleNamespace()
                def observe(self,requirements,deadline):
                    return readiness.Observation('controlled-target','same-machine',connection='connection',boot='boot',
                        account='502',session='known-session',transport='ready',guest='running',guest_agent=True,
                        ordinary_session='locked',display=request('observe')['display'],trusted=True,owned=True,
                        integrity=True,credential_available=True)
                def recover(self,action,rid,observed,deadline):request(action)
            adapter=Adapter()
            class Executor:
                provider='tart-macos'
                def snapshot(self):return {'provider':self.provider,'originalOperationId':operation}
                def submit(self,op,ttl):
                    submissions.append(op);jobs.submit(owner_root,op,bound,program,generation=generation)
                    return {'schemaVersion':1,'provider':self.provider,'operationId':op,'state':'active',
                            'jobState':'running','replayAllowed':False,'nextAction':'observe_original'}
            fixture=SimpleNamespace(adapter=adapter,lease_executor=lambda:Executor(),
                context=lambda:readiness.Context('controlled-target','same-machine',adapter,readiness.RecoveryJournal(journal)))
            try:
                with mock.patch.object(flow.fixtures,'registered_fixture',return_value=fixture):
                    result=flow.workflow(root,'acquire',{'fixtureId':'controlled-mac','operationId':operation,'ttlSeconds':3})
                if not submissions:
                    self.assertEqual(result['state'],'blocked')
                    self.assertFalse((owner_root/operation).exists())
                    return events,False
                end=time.monotonic()+5
                while jobs.observe(owner_root,operation,bound,generation=generation)['state']!='terminal'and time.monotonic()<end:
                    time.sleep(.01)
                self.assertEqual(jobs.collect(owner_root,operation,bound,generation=generation)[1],b'background-once\n')
                self.assertEqual(submissions,[operation]);self.assertEqual(result['state'],'active')
                return events,True
            finally:
                server.shutdown();server.server_close();thread.join(timeout=2)

    def test_old_whole_facade_wakes_locked_display_and_current_background_lease_never_inputs(self):
        events,submitted=self.background_scenario(self.load_before())
        self.assertEqual(events,['wake_display']);self.assertFalse(submitted)
        events,submitted=self.background_scenario(current)
        self.assertEqual(events,[]);self.assertTrue(submitted)
        self.assertEqual(current._external_requirements('raw-qemu-windows'),current._REQ)

    def load_before(self):
        path = Path(__file__).parent/'fixtures/macos_lease_retry.before.source'
        from importlib.machinery import SourceFileLoader
        name = 'agent_tools._macos_lease_retry_before'
        loader = SourceFileLoader(name, str(path))
        spec = importlib.util.spec_from_loader(name, loader)
        module = importlib.util.module_from_spec(spec); loader.exec_module(module)
        return module

    def scenario(self, flow):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); root.chmod(0o700)
            state, _ = flow._paths(root, 'controlled-mac', create=True)
            owner_root = root/'owner'; owner_root.mkdir(mode=0o700)
            operation = str(uuid4()); binding = jobs.current_binding('controlled-provider', 'same-machine')
            generation = jobs.root_generation(owner_root)
            program = jobs.Program('controlled-once', b"print('one-original-execution',flush=True)\n", 4096)
            snapshot = {'provider':'tart-macos', 'originalOperationId':operation}
            identities = ('target','machine','connection','boot','502','session')
            value = {'schemaVersion':2, 'provider':'tart-macos', 'fixtureId':'controlled-mac',
                     'operationId':operation, 'ttlSeconds':3, 'executor':snapshot,
                     'readyIdentities':list(identities), 'sources':dict(flow._LOADED)}
            jobs._publish(state/(operation+'.json'), value)
            submissions = []
            class Original:
                provider = 'tart-macos'
                def observe(self, op):
                    result = jobs.observe(owner_root, op, binding, generation=generation)
                    result.update(provider=self.provider, jobState=result['state'],
                                  state={'unsubmitted':'unsubmitted','running':'active','terminal':'expired'}.get(result['state'],'unknown'),
                                  reason='original_admission_absent' if result['state']=='unsubmitted' else 'original',
                                  nextAction='none')
                    return result
            class Admitted(Original):
                def snapshot(self): return snapshot
                def submit(self, op, ttl):
                    submissions.append(op)
                    jobs.submit(owner_root, op, binding, program, generation=generation)
                    return self.observe(op)
            admitted = Admitted()
            fixture = SimpleNamespace(context=lambda:object(), lease_executor=lambda:admitted)
            ready = SimpleNamespace(identities=lambda:identities)
            with mock.patch.object(flow.fixtures,'lease_executor_from_snapshot',return_value=Original()), \
                 mock.patch.object(flow.fixtures,'registered_fixture',return_value=fixture), \
                 mock.patch.object(flow.readiness,'ensure_ready',return_value=ready), \
                 mock.patch.object(flow.readiness,'revalidate'):
                result = flow.workflow(root,'acquire',{'fixtureId':'controlled-mac','operationId':operation,'ttlSeconds':3})
                if not submissions:
                    self.assertEqual(result['state'],'unknown')
                    self.assertFalse((owner_root/operation).exists())
                    return False
                end = time.monotonic()+5
                while time.monotonic()<end:
                    observed = jobs.observe(owner_root,operation,binding,generation=generation)
                    if observed['state']=='terminal': break
                    time.sleep(.01)
                self.assertEqual(observed['state'],'terminal')
                receipt = jobs.collect(owner_root,operation,binding,generation=generation)
                self.assertEqual(receipt[1], b'one-original-execution\n')
                owner = jobs._record(owner_root/operation/'owner.json')
                for _ in range(2):
                    repeated=flow.workflow(root,'acquire',{'fixtureId':'controlled-mac','operationId':operation,'ttlSeconds':3})
                    self.assertEqual(repeated['operationId'],operation)
                self.assertEqual(submissions,[operation])
                self.assertEqual(jobs._record(owner_root/operation/'owner.json'),owner)
                return True

    def test_whole_before_refuses_original_observer_retry_and_current_submits_once_via_current_admission(self):
        self.assertFalse(self.scenario(self.load_before()))
        self.assertTrue(self.scenario(current))

    def test_only_exact_terminal_cleanup_result_reconciles_original_without_readiness(self):
        operation = str(uuid4())
        value = {'provider':'tart-macos','fixtureId':'controlled-mac','operationId':operation,'executor':{},'ttlSeconds':3}
        result = {'schemaVersion':1,'provider':'tart-macos','operationId':operation,'state':'restore_blocked',
                  'jobState':'terminal','restored':False,'reason':'macos_assertion_release_unverified',
                  'replayAllowed':False,'nextAction':'reconcile_original'}
        normalized=current._external_result(value,result)
        self.assertEqual(normalized['qualificationScope'],'registered_guest_executor')
        for changed in ({'schemaVersion':True},{'restored':None},{'state':'unknown'},{'jobState':'unknown'},
                        {'provider':'raw-qemu-windows'},{'reason':'correlated_terminal'}):
            with self.subTest(changed=changed),self.assertRaises(current.LeaseWorkflowError):
                current._external_result(value,{**result,**changed})
        with tempfile.TemporaryDirectory() as temporary:
            executor=SimpleNamespace(provider='tart-macos',observe=lambda op:result,
                                     reconcile=mock.Mock(return_value={**result,'state':'failed','restored':True,'nextAction':'none'}))
            with mock.patch.object(current.fixtures,'lease_executor_from_snapshot',return_value=executor), \
                 mock.patch.object(current.fixtures,'registered_fixture',side_effect=AssertionError('no readiness')):
                actual=current._external_original(Path(temporary),Path(temporary),'reconcile',value,{})
            executor.reconcile.assert_called_once_with(operation)
            self.assertTrue(actual['restored'])


if __name__=='__main__': unittest.main()

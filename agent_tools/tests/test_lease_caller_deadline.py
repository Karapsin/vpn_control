"""Whole caller beforeimages, real flock/socket waits, no guest effects."""
import hashlib
import importlib.util
from importlib.machinery import SourceFileLoader
import json
import math
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock
from uuid import UUID, uuid4, uuid5

from agent_tools import readiness
from agent_tools import readiness_gui_lease as gui
from agent_tools import readiness_lease_workflow as workflow
from agent_tools import readiness_fixture_registry as registry
from agent_tools import readiness_tart_macos_lease_executor as mac
from agent_tools import readiness_windows as windows

FIXTURE=Path(__file__).parent/'fixtures/lease_caller_deadline'


def before(name):
    pins=json.loads((FIXTURE/'provenance.json').read_bytes())['files']
    path=FIXTURE/(name+'.before.source');raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=pins[path.name]:raise AssertionError('beforeimage drift')
    key='agent_tools._caller_deadline_before_'+name.removesuffix('.py').replace('.', '_').replace('-', '_')
    spec=importlib.util.spec_from_loader(key,SourceFileLoader(key,str(path)))
    module=importlib.util.module_from_spec(spec);sys.modules[key]=module
    spec.loader.exec_module(module);return module


@unittest.skipUnless(os.name=='posix','owned flock and detached POSIX controls')
class CallerDeadlineTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(dir=Path('/tmp').resolve());self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.parent=str(uuid4())
        identities=('target','machine','connection','boot','ordinary','session')
        operation=str(uuid5(UUID(self.parent),json.dumps(['automatic-gui-lease-v1',*identities[:2],identities[3]],separators=(',',':'))))
        self.record={'schemaVersion':1,'fixtureId':'fixture','parentOperationId':self.parent,'operationId':operation,'identities':list(identities),'ttlSeconds':18000}
        self.operation=operation

    def hold_journal(self,state):
        ready=self.root/(uuid4().hex+'.ready')
        code='''import sys,time\nfrom pathlib import Path\nfrom agent_tools.readiness import RecoveryJournal\nwith RecoveryJournal(Path(sys.argv[1])).locked():\n Path(sys.argv[2]).write_text("held")\n time.sleep(.36)\n'''
        child=subprocess.Popen([sys.executable,'-I','-B','-c','import sys;sys.path.insert(0,sys.argv.pop(1));'+code,str(Path(__file__).resolve().parents[2]),str(state),str(ready)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.addCleanup(lambda: child.wait(timeout=5));self.addCleanup(child.stdout.close);self.addCleanup(child.stderr.close)
        limit=time.monotonic()+5
        while not ready.exists():
            if child.poll()is not None:raise AssertionError(child.stderr.read().decode())
            self.assertLess(time.monotonic(),limit);time.sleep(.005)
        return child

    def test_complete_old_gui_and_workflow_real_flock_red_current_green(self):
        old_gui=before('readiness_gui_lease.py');old_flow=before('readiness_lease_workflow.py')
        for module,flow,old in [(old_gui,old_flow,True),(gui,workflow,False)]:
            state,_=workflow._paths(self.root,'fixture',create=True);child=self.hold_journal(state)
            start=time.monotonic();deadline=start+.065
            with mock.patch.object(module,'workflow',flow),mock.patch.object(flow.fixtures,'registered_fixture',side_effect=AssertionError('original cancellation cannot probe guest')):
                with self.assertRaises(readiness.ReadinessBlocked):module.from_record(self.root,self.record).cancel(deadline=deadline)
            elapsed=time.monotonic()-start
            if old:self.assertGreater(elapsed,.25)
            else:self.assertLess(elapsed,.20)
            child.wait(timeout=5)
        self.assertFalse(list(self.root.rglob('*.cancelled.json')))

    def socket_wait(self,deadline):
        # The controlled endpoint has no mutation protocol; its only behavior is
        # an actual delayed byte. The production caller must cap socket waiting.
        left,right=socket.socketpair();finished=threading.Event()
        def server():
            try:finished.wait(.30);right.sendall(b'x')
            except OSError:pass
            finally:right.close()
        thread=threading.Thread(target=server);thread.start()
        try:
            left.settimeout(max(.001,deadline-time.monotonic()));left.recv(1)
        finally:left.close();finished.set();thread.join(2)

    def test_complete_mac_original_observer_socket_old_red_current_green(self):
        old=before('readiness_tart_macos_lease_executor.py')
        for module,is_old in [(old,True),(mac,False)]:
            executor=object.__new__(module.OriginalMacLeaseExecutor);executor._guard=lambda deadline:None;executor._state=lambda operation:self.root
            executor._capsule=lambda *,deadline=None:b'original-only';executor._snapshot={'capsule':{'pin':{'sha256':'a'*64}}}
            calls=[]
            def original(raw,action,operation,*,expected_sha256,deadline):
                calls.append((action,operation,deadline));self.socket_wait(deadline)
                reply={'schemaVersion':1,'operationId':operation,'provider':'tart-macos','state':'unknown','jobState':'unknown','reason':'record_unavailable','replayAllowed':False,'nextAction':'observe_original'}
                return SimpleNamespace(returncode=0,stdout=json.dumps(reply).encode(),stderr=b'')
            executor.custody=SimpleNamespace(original_lease_call=original)
            start=time.monotonic();deadline=start+.065
            if is_old:executor.observe(self.operation)
            else:
                with self.assertRaises(TimeoutError):executor.observe(self.operation,deadline=deadline)
            elapsed=time.monotonic()-start
            self.assertEqual([(a,o)for a,o,_ in calls],[('status',self.operation)])
            if is_old:self.assertGreater(elapsed,.25)
            else:self.assertLess(elapsed,.20);self.assertLessEqual(calls[0][2],deadline)

    def test_complete_windows_original_observer_socket_old_red_current_green(self):
        old=before('readiness_windows.py')
        for module,is_old in [(old,True),(windows,False)]:
            executor=object.__new__(module.WindowsLeaseExecutor);executor._guard=lambda:None;executor._state=lambda operation:self.root
            executor._snapshot={'host':{}};executor.binding='controlled-original-binding';calls=[]
            def dispatch(mode,operation,deadline,**kwargs):
                calls.append((mode,kwargs['lease_operation'],deadline));self.socket_wait(deadline)
                return {'state':'blocked'},None
            executor.backend=SimpleNamespace(_run=dispatch)
            start=time.monotonic();deadline=start+.065
            if is_old:executor.observe(self.operation)
            else:
                with self.assertRaises(TimeoutError):executor.observe(self.operation,deadline=deadline)
            elapsed=time.monotonic()-start
            self.assertEqual(calls[0][:2],('lease-status',self.operation))
            if is_old:self.assertGreater(elapsed,.25)
            else:self.assertLess(elapsed,.20);self.assertLessEqual(calls[0][2],deadline)

    def test_gui_acquire_cancel_fallback_and_reconcile_share_one_absolute_cap(self):
        captured=[];deadline=time.monotonic()+2
        def call(root,action,inputs,*,deadline=None):
            captured.append((action,deadline));self.assertEqual(inputs['operationId'],self.operation)
            if action=='cancel':raise OSError('controlled acknowledgement lost')
            if action=='status':return {'operationId':self.operation,'state':'restore_blocked','jobState':'terminal','restored':False,'restorationState':'unsubmitted','nextAction':'reconcile_original'}
            return {'operationId':self.operation,'state':'restored','jobState':'terminal','restored':True}
        with mock.patch.object(gui.workflow,'workflow',side_effect=call):
            result=gui.from_record(self.root,self.record).cancel(deadline=deadline)
        self.assertTrue(result['restored']);self.assertEqual([a for a,_ in captured],['cancel','status','reconcile']);self.assertTrue(all(d<=deadline for _,d in captured));self.assertEqual(1,len({d for _,d in captured}))
        ready=SimpleNamespace(identities=lambda:tuple(self.record['identities']))
        captured.clear()
        def active(root,action,inputs,*,deadline=None):
            captured.append((action,deadline));self.assertEqual(inputs['operationId'],self.operation)
            return {'operationId':self.operation,'state':'active','jobState':'running'}
        with mock.patch.object(gui.workflow,'workflow',side_effect=active):
            lease=gui.acquire(self.root,'fixture',self.parent,ready,deadline=deadline);lease.guard()
        self.assertEqual(18000,lease.ttl_seconds);self.assertNotIn('deadline',lease.record());self.assertTrue(all(d<=deadline for _,d in captured))

    def test_invalid_and_expired_deadlines_refuse_before_paths_or_dispatch(self):
        inputs={'fixtureId':'fixture','operationId':self.operation,'ttlSeconds':10}
        for value in [True,False,float('nan'),float('inf'),-float('inf'),0,-1,time.monotonic()-1]:
            with mock.patch.object(workflow,'_paths',side_effect=AssertionError('no metadata effect')),mock.patch.object(workflow.fixtures,'registered_fixture',side_effect=AssertionError('no guest probe')):
                result=workflow.workflow(self.root,'acquire',inputs,deadline=value)
            self.assertEqual(result['nextAction'],'resolve_blocker');self.assertIn(result['reason'],{'lease_deadline','lease_deadline_invalid'})
        self.assertFalse((self.root/'.rag_index').exists())

    def test_default_none_preserves_cold_boot_and_original_no_deadline_call_shapes(self):
        class Fixture:
            def context(self):return 'no caller cap'
        self.assertEqual(workflow._bounded_call(Fixture().context,deadline=None),'no caller cap')
        self.assertIsNone(workflow._caller_deadline(None))
        deadline=time.monotonic()+.5;self.assertEqual(workflow._caller_deadline(deadline),deadline)
        self.assertEqual(workflow._bounded_call(lambda *,deadline:deadline,deadline=deadline),deadline)
        with self.assertRaises(TypeError):workflow._bounded_call(Fixture().context,deadline=deadline)
        # No fallback may silently drop an explicit deadline on an old backend.
        with self.assertRaises(registry.FixtureRegistryError):registry._lease_deadline(True)

    def test_caller_timeout_preserves_one_detached_owner_ttl_and_restoration(self):
        from agent_tools.tests.test_readiness_entrypoints import controlled_lease_workflow, finish_controlled_leases
        from agent_tools import durable_remote_job as jobs
        raw=controlled_lease_workflow(self.root);self.addCleanup(finish_controlled_leases,self.root);calls=[]
        def pending(root,action,inputs,*,deadline=None):
            calls.append(action);raw(root,action,inputs,deadline=deadline)
            return {'operationId':inputs['operationId'],'state':'unknown','jobState':'unknown','nextAction':'observe_original'}
        ready=SimpleNamespace(identities=lambda:tuple(self.record['identities']))
        with mock.patch.object(gui.workflow,'workflow',side_effect=pending):
            with self.assertRaises(readiness.ReadinessBlocked):gui.acquire(self.root,'fixture',self.parent,ready,ttl_seconds=.25,deadline=time.monotonic()+.065)
        self.assertEqual(calls.count('acquire'),1);self.assertNotIn('cancel',calls)
        state=self.root/'controlled-lease-jobs';binding=jobs.current_binding('controlled-gui-lease','controlled-setting');generation=jobs.root_generation(state)
        limit=time.monotonic()+5
        while True:
            result=jobs.observe(state,self.operation,binding,generation=generation)
            if result['state']=='terminal':break
            self.assertLess(time.monotonic(),limit);time.sleep(.02)
        self.assertEqual([self.operation],[path.name for path in state.iterdir()if path.is_dir()and len(path.name)==36]);self.assertEqual((self.root/'controlled-lease-setting').read_text(),'sleep')
        status,stdout,stderr=jobs.collect(state,self.operation,binding,generation=generation);self.assertEqual(status['state'],'terminal');self.assertEqual(stderr,b'')
        self.assertEqual(json.loads((state/self.operation/'lease-acquired.json').read_bytes())['ttlSeconds'],.25)

    def test_mac_factory_probes_and_nested_cancel_receive_exact_same_cap(self):
        from agent_tools import readiness_tart_macos_registry as custody
        from agent_tools import readiness_tart_macos as backend
        cap=time.monotonic()+1;seen=[]
        class Custody:
            binding=SimpleNamespace(target='target',machine='machine')
            def guard(self,*,deadline):seen.append(('guard',deadline))
            def close(self):pass
        class Adapter:
            def observe(self,requirements,deadline):seen.append(('observe',deadline))
        with mock.patch.object(custody,'MacCustody',return_value=Custody()),mock.patch.object(backend,'MacTartBackend',return_value=object()),mock.patch.object(registry.providers,'ProviderAdapter',return_value=Adapter()):
            custody.load_registered_fixture(self.root,'fixture',{}, {},deadline=cap)
        self.assertEqual(seen,[('guard',cap),('observe',cap)])
        executor=object.__new__(mac.OriginalMacLeaseExecutor);calls=[]
        def observe(action,operation,*,deadline=None):
            calls.append((action,operation,deadline));return {'state':'active','jobState':'running'}
        executor._observe=observe;executor.cancel(self.operation,deadline=cap)
        self.assertEqual(calls,[('status',self.operation,cap),('cancel',self.operation,cap)])

    def test_acquisition_phase_budget_never_expires_a_healthy_default_handle(self):
        old=before('readiness_gui_lease.phase-cap.py')
        start=time.monotonic();clock=[start];calls=[]
        ready=SimpleNamespace(identities=lambda:tuple(self.record['identities']))
        def reply(root,action,inputs,*,deadline=None):
            calls.append((action,deadline));self.assertGreater(deadline,clock[0])
            return {'operationId':self.operation,'state':'cancelled'if action=='cancel'else'active','jobState':'terminal'if action=='cancel'else'running',**({'restored':True}if action=='cancel'else{})}
        for module,is_old in [(old,True),(gui,False)]:
            clock[0]=start;calls.clear()
            with mock.patch.object(module.time,'monotonic',side_effect=lambda:clock[0]),mock.patch.object(module.workflow,'workflow',side_effect=reply):
                lease=module.acquire(self.root,'fixture',self.parent,ready)
                self.assertEqual(lease.ttl_seconds,18000);clock[0]=start+181
                if is_old:
                    with self.assertRaises(readiness.ReadinessBlocked):lease.guard()
                    with self.assertRaises(readiness.ReadinessBlocked):lease.cancel()
                else:
                    self.assertIsNone(lease.deadline);lease.guard();self.assertEqual(lease.cancel()['state'],'cancelled')
            self.assertTrue(all(d<=start+180 for a,d in calls[:2]))
        clock[0]=start;calls.clear();caller=start+600
        with mock.patch.object(gui.time,'monotonic',side_effect=lambda:clock[0]),mock.patch.object(gui.workflow,'workflow',side_effect=reply):
            lease=gui.acquire(self.root,'fixture',self.parent,ready,deadline=caller);self.assertEqual(lease.deadline,caller)
            self.assertTrue(all(d<=start+180 for _,d in calls));clock[0]=start+181;lease.guard();self.assertLessEqual(calls[-1][1],caller)
            clock[0]=caller
            with self.assertRaises(readiness.ReadinessBlocked):lease.guard()

    def test_all_complete_beforeimages_are_authenticated(self):
        pins=json.loads((FIXTURE/'provenance.json').read_bytes())['files'];self.assertEqual(len(pins),8)
        for name,digest in pins.items():self.assertEqual(hashlib.sha256((FIXTURE/name).read_bytes()).hexdigest(),digest)

if __name__=='__main__':unittest.main()

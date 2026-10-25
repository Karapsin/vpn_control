"""Automatic GUI lease ownership exercised with real retained child jobs."""
from dataclasses import replace
import importlib.util
from importlib.machinery import SourceFileLoader
import json
import os
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock
from uuid import UUID, uuid4, uuid5

from agent_tools import readiness
from agent_tools import readiness_gui_lease as subject
from agent_tools import readiness_lease_reconciliation as repair
from agent_tools import readiness_leases as leases
from agent_tools import durable_remote_job as jobs
from agent_tools.tests import test_readiness_lease_reconciliation as repair_fixture
from agent_tools.tests.test_readiness_entrypoints import before_source, controlled_lease_workflow, finish_controlled_leases


@unittest.skipUnless(os.name == "posix", "protected settings and durable process owners")
class GuiLeaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        raw_execute = controlled_lease_workflow(self.root)
        def execute(root, action, inputs, *, deadline=None):
            if deadline is not None:
                self.assertIn(type(deadline), (int, float))
                self.assertGreater(deadline, time.monotonic())
            return raw_execute(root, action, inputs, deadline=deadline)
        self.execute = execute
        self.patch = mock.patch.object(subject.workflow, 'workflow', side_effect=self.execute)
        self.patch.start(); self.addCleanup(self.patch.stop)
        self.addCleanup(finish_controlled_leases, self.root)
        self.parent = str(uuid4())
        self.ready = SimpleNamespace(identities=lambda: ('target', 'machine', 'connection', 'boot-a', 'ordinary', 'session-a'))

    def acquire(self, **kwargs):
        kwargs.setdefault('ttl_seconds', 2)
        return subject.acquire(self.root, 'fixture', self.parent, self.ready, **kwargs)

    def test_short_expiry_restores_setting_and_invalidates_input_guard(self):
        lease = self.acquire(ttl_seconds=.2)
        self.assertEqual('awake', (self.root/'controlled-lease-setting').read_text())
        self.assertNotEqual(self.parent, lease.operation_identity)
        deadline = time.monotonic() + 5
        while self.execute(self.root, 'status', {'operationId': lease.operation_identity})['jobState'] != 'terminal':
            self.assertLess(time.monotonic(), deadline); time.sleep(.02)
        self.assertEqual('sleep', (self.root/'controlled-lease-setting').read_text())
        with self.assertRaises(readiness.ReadinessBlocked) as caught:
            lease.guard()
        self.assertEqual('gui_lease_not_active', caught.exception.reason)
        self.assertEqual('expired', lease.cancel()['state'])

    def test_production_five_hour_default_is_checked_without_waiting(self):
        lease = subject.acquire(self.root, 'fixture', self.parent, self.ready)
        self.assertEqual(18000, lease.ttl_seconds)
        receipt = json.loads((self.root/'controlled-lease-jobs'/lease.operation_identity/'lease-acquired.json').read_bytes())
        self.assertEqual(18000, receipt['ttlSeconds'])
        self.assertEqual('cancelled', lease.cancel()['state'])
        self.assertEqual('sleep', (self.root/'controlled-lease-setting').read_text())

    def test_lost_acquire_ack_observes_original_and_never_submits_successor(self):
        calls = []
        def lost(root, action, inputs, *, deadline=None):
            calls.append(action)
            result = self.execute(root, action, inputs, deadline=deadline)
            if action == 'acquire':
                raise OSError('inert lost acknowledgement')
            return result
        with mock.patch.object(subject.workflow, 'workflow', side_effect=lost):
            lease = self.acquire()
            lease.cancel()
        self.assertEqual(1, calls.count('acquire'))
        jobs = [p for p in (self.root/'controlled-lease-jobs').iterdir() if p.is_dir() and len(p.name) == 36]
        self.assertEqual([lease.operation_identity], [p.name for p in jobs])

    def test_parent_relation_exists_before_child_admission_and_fresh_cancel_needs_no_guest(self):
        def verify(root, action, inputs, *, deadline=None):
            if action == 'acquire':
                record = json.loads((self.root/'.rag_index/readiness-gui-leases'/(inputs['operationId']+'.json')).read_bytes())
                self.assertEqual(self.parent, record['parentOperationId'])
            return self.execute(root, action, inputs, deadline=deadline)
        with mock.patch.object(subject.workflow, 'workflow', side_effect=verify):
            lease = self.acquire()
        fresh = subject.from_record(self.root, lease.record())
        with mock.patch.object(subject.fixtures, 'registered_fixture', side_effect=AssertionError('no guest recovery')):
            self.assertEqual('cancelled', fresh.cancel()['state'])

    def test_concurrent_callers_share_one_original_parent_and_owner(self):
        results, errors = [], []
        def call():
            try: results.append(self.acquire())
            except Exception as error: errors.append(error)
        threads = [threading.Thread(target=call) for _ in range(3)]
        for thread in threads: thread.start()
        for thread in threads: thread.join(8)
        self.assertEqual([], errors)
        self.assertEqual(3, len(results))
        self.assertEqual(1, len({lease.operation_identity for lease in results}))
        results[0].cancel()
        self.assertEqual(1, len(list((self.root/'.rag_index/readiness-gui-leases').glob('*.json'))))

    def test_new_boot_gets_distinct_child_and_retains_original_history(self):
        old = self.acquire(); old.cancel()
        self.ready = SimpleNamespace(identities=lambda: ('target', 'machine', 'connection', 'boot-b', 'ordinary', 'session-b'))
        new = self.acquire(); new.cancel()
        self.assertNotEqual(old.operation_identity, new.operation_identity)
        self.assertEqual(2, len(list((self.root/'.rag_index/readiness-gui-leases').glob('*.json'))))

    def test_malformed_original_reply_blocks_without_echo_or_second_acquire(self):
        calls = []
        secret = 'INERT-PRIVATE-INPUT-DO-NOT-ECHO'
        def malformed(root,action,inputs,*,deadline=None):
            calls.append(action)
            return {'operationId':inputs['operationId'],'state':[secret],'jobState':'running'}
        with mock.patch.object(subject.workflow,'workflow',side_effect=malformed):
            with self.assertRaises(readiness.ReadinessBlocked) as caught:
                self.acquire()
        self.assertEqual(1,calls.count('acquire'))
        self.assertNotIn(secret,repr(caught.exception.as_dict()))
        self.assertEqual('gui_lease_original_unknown',caught.exception.reason)

    def test_original_startup_unknown_is_causal_red_and_current_observes_green(self):
        path = before_source('readiness_gui_lease.before-startup-observation.source')
        spec = importlib.util.spec_from_loader('agent_tools._before_gui_startup', SourceFileLoader('agent_tools._before_gui_startup', str(path)))
        before = importlib.util.module_from_spec(spec)
        import sys
        sys.modules[spec.name] = before
        self.addCleanup(sys.modules.pop, spec.name)
        spec.loader.exec_module(before)
        def pending(root, action, inputs, *, deadline=None):
            result = self.execute(root, action, inputs, deadline=deadline)
            if action == 'acquire':
                return {'operationId': inputs['operationId'], 'state': 'unknown', 'jobState': 'unknown', 'nextAction': 'observe_original'}
            return result
        with mock.patch.object(subject.workflow, 'workflow', side_effect=pending):
            with self.assertRaises(readiness.ReadinessBlocked) as caught:
                before.acquire(self.root, 'fixture', str(uuid4()), self.ready, ttl_seconds=2)
            self.assertEqual('gui_lease_acquisition_unresolved', caught.exception.reason)
            # End the failed original first: competing owners must stay blocked.
            finish_controlled_leases(self.root)
            current = self.acquire()
            current.cancel()

    def test_original_failed_cleanup_is_causal_red_then_reconciles_once_after_lost_ack(self):
        owned = repair_fixture.LeaseReconciliationTests()
        owned.setUp(); self.addCleanup(owned.tearDown)
        identities = ('socket-target','owned-controlled-avd','dead-connection',owned.boot,'android-user:0',owned.boot+':user:0')
        operation = str(uuid5(UUID(self.parent),json.dumps(['automatic-gui-lease-v1',*identities[:2],identities[3]],separators=(',',':'))))
        record = {'schemaVersion':1,'fixtureId':'socket-fixture','parentOperationId':self.parent,
                  'operationId':operation,'identities':list(identities),'ttlSeconds':.6}
        current = subject.from_record(owned.base,record)
        owned.operations.append(operation)
        config = {'backend':'android','ttlSeconds':.6,'adbPath':str(owned.client),'adbSerial':'emulator-5678',
                  'adbPort':owned.port,'guestBoot':owned.boot,'guestAvd':'owned-controlled-avd'}
        jobs.submit(owned.root,operation,owned.binding,leases._program(owned.root,operation,owned.binding,config),generation=owned.generation)
        owned.until(lambda:leases.inspect(owned.root,operation,owned.binding,generation=owned.generation)['state']=='active')
        owned.stop_daemon(); owned.wait_job(operation)
        self.assertEqual('restore_blocked',leases.inspect(owned.root,operation,owned.binding,generation=owned.generation)['state'])
        original_failed = (owned.root/operation/'lease-terminal.json').read_bytes()
        owned.start_daemon()
        path = before_source('readiness_gui_lease.before-original-reconciliation.source')
        spec = importlib.util.spec_from_loader('agent_tools._before_gui_restore',SourceFileLoader('agent_tools._before_gui_restore',str(path)))
        previous = importlib.util.module_from_spec(spec)
        import sys
        sys.modules[spec.name]=previous; self.addCleanup(sys.modules.pop,spec.name)
        spec.loader.exec_module(previous)
        calls=[]
        def execute(root,action,inputs,*,deadline=None):
            self.assertEqual({'fixtureId':'socket-fixture','operationId':operation},inputs)
            calls.append(action)
            if action=='cancel':
                leases.cancel(owned.root,operation,owned.binding,generation=owned.generation)
            if action=='reconcile':
                repair.admit(owned.root,operation,owned.binding,owned.config(),generation=owned.generation)
                raise OSError('inert lost restoration acknowledgement')
            return leases.inspect(owned.root,operation,owned.binding,generation=owned.generation)
        with mock.patch.object(subject.workflow,'workflow',side_effect=execute):
            with self.assertRaisesRegex(readiness.ReadinessBlocked,'gui_lease_restoration_unresolved'):
                previous.from_record(owned.base,record).cancel(deadline=time.monotonic()+8)
            self.assertEqual('7',json.loads(owned.state.read_text())['value'])
            result=current.cancel(deadline=time.monotonic()+8)
            self.assertEqual('restored',result['state'])
            self.assertEqual('terminal',result['jobState'])
            with self.assertRaisesRegex(readiness.ReadinessBlocked,'gui_lease_not_active'):
                current.guard()
        self.assertEqual(1,calls.count('reconcile'))
        self.assertNotIn('acquire',calls)
        self.assertEqual(['7','3'],json.loads(owned.state.read_text())['writes'])
        self.assertEqual(original_failed,(owned.root/operation/'lease-terminal.json').read_bytes())


if __name__ == '__main__':
    unittest.main()

"""Whole Windows/generic callers with real TCP peers and retained admissions.

Only the Windows/SSH native boundary is modeled. The original discriminant,
fixed generated source validation, typed executor, journals, facade and public
MCP dispatch execute unchanged. Native Windows interruption remains required.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import time
from types import ModuleType
import unittest
from unittest import mock
from uuid import uuid4

from agent_tools import readiness
from agent_tools import readiness_guest_jobs as generic
from agent_tools import readiness_windows_jobs as current
from agent_tools.tests import test_readiness_guest_windows_router as peer

FOLDER = Path(__file__).parent / 'fixtures/windows_jobs_observer_recovery'


def subject():
    if not os.environ.get('VPN_CONTROL_WINDOWS_OBSERVER_BEFORE'):
        return current
    assert os.environ['VPN_CONTROL_WINDOWS_OBSERVER_BEFORE'] == '1'
    path = FOLDER / 'before.source'; raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == json.loads((FOLDER / 'provenance.json').read_text())['sourceSha256']
    module = ModuleType('agent_tools._windows_observer_before')
    module.__file__ = str(path); module.__package__ = 'agent_tools'
    # Dataclasses resolve their defining module during class construction.
    import sys
    sys.modules[module.__name__] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


class OriginalObserverRecoveryTests(unittest.TestCase):
    resolve = peer.GuestWindowsRoutingTests.resolve
    from_snapshot = peer.GuestWindowsRoutingTests.from_snapshot
    fixture = peer.GuestWindowsRoutingTests.fixture
    inputs = peer.GuestWindowsRoutingTests.inputs

    def setUp(self):
        self.jobs = subject()
        self.patch = mock.patch.object(peer, 'windows', self.jobs); self.patch.start(); self.addCleanup(self.patch.stop)
        self.generic_patch = mock.patch.object(generic, 'windows_jobs', self.jobs)
        self.generic_patch.start(); self.addCleanup(self.generic_patch.stop)
        self.failures = 0; self.reason = 'connection_generation_changed'; self.observer_calls = 0
        self.permanent = False; self.initial_running = True
        self.start_ack = False; self.ack_statuses = 0; self.running_status = False
        peer.GuestWindowsRoutingTests.setUp(self)
        case = self; original_handler = self.server.RequestHandlerClass
        self.dropped = 0
        class DroppingObserver(original_handler):
            def handle(channel):
                # Run the real peer request and source validation, then close
                # its actual TCP channel before delivering the retained reply.
                wire = channel.wfile; channel.wfile = io.BytesIO()
                super().handle()
                body = channel.wfile.getvalue(); channel.wfile = wire
                if case.calls[-1]['action'] == 'job-status' and (case.failures or case.permanent):
                    case.failures = max(0, case.failures - 1); case.dropped += 1
                    channel.connection.shutdown(socket.SHUT_RDWR)
                else:
                    wire.write(body)
        self.server.RequestHandlerClass = DroppingObserver
        self.module = generic
        self.fixture('fixture-a', 'libvirt-windows')
        self.inputs_original = self.inputs('fixture-a', count=8, intervalSeconds=.01)
        running = self.module.workflow(self.root, 'start', self.inputs_original)
        self.assertEqual('running', running['state'])
        self.owner = running['identity']; self.lookups.clear()
        self.short = {k: self.inputs_original[k] for k in ('fixtureId', 'operationId')}

    def remote(self, backend, action, operation, deadline, **kwargs):
        # Actual generated fixed source and real TCP peer execute first. A
        # transport guard then refuses the returned observer generation, as
        # the native disconnect did; no replacement job admission occurs.
        dropped = self.dropped
        if action == 'job-status':
            self.observer_calls += 1
        try:
            result = peer.GuestWindowsRoutingTests.remote(self, backend, action, operation, deadline, **kwargs)
        except json.JSONDecodeError:
            self.assertEqual(dropped + 1, self.dropped)
            raise readiness.ReadinessBlocked(self.reason, str(uuid4())) from None
        if action == 'job-start' and self.start_ack or action == 'job-status' and self.ack_statuses:
            if action == 'job-start':
                self.start_ack = False
            else:
                self.ack_statuses -= 1
            for key in ('owner', 'exitCode', 'streams'):
                result.pop(key)
            result.update(state='unknown', reason='original_owner_ack_pending')
        elif action == 'job-start' and self.initial_running or action == 'job-status' and self.running_status:
            self.initial_running = False
            for key in ('exitCode', 'streams'):
                result.pop(key)
            result.update(state='running', reason='original_owner_running')
        return result

    def assert_original(self, result):
        self.assertEqual(self.short['operationId'], result['operationId'])
        self.assertEqual(self.short['fixtureId'], result['fixtureId'])
        self.assertEqual(1, result['durableProtocol'])
        self.assertEqual('fixed-counter', result['qualificationScope'])
        self.assertFalse(result['replayAllowed'])
        self.assertEqual(self.owner, result['identity'])
        self.assertEqual(1, len(self.submissions))
        self.assertEqual([], self.lookups)

    def test_whole_original_observer_generation_loss_reconnects_only_and_collects_once(self):
        self.failures = 1
        with mock.patch.object(time, 'sleep'):
            result = self.module.workflow(self.root, 'reconcile', self.short)
        self.assert_original(result); self.assertEqual('terminal', result['state'])
        self.assertEqual(2, self.observer_calls); self.assertEqual(1, result['executions'])
        self.assertEqual(8, result['counterValues'])
        self.assertTrue(all(row['operation'] == self.short['operationId'] for row in self.calls))
        with mock.patch.object(generic.registry, 'registered_fixture', side_effect=AssertionError('historical registry lookup')):
            self.assertEqual(result, self.module.workflow(self.root, 'collect', self.short))

    def test_permanent_outage_preserves_authenticated_original_unknown_and_auto_guidance(self):
        self.permanent = True
        with mock.patch.object(time, 'sleep'):
            result = self.module.workflow(self.root, 'reconcile', self.short)
        self.assert_original(result); self.assertEqual('unknown', result['state'])
        self.assertEqual('connection_generation_changed', result['reason'])
        self.assertEqual('reconcile_original', result['nextAction']['kind'])
        self.assertEqual(self.short, result['nextAction']['action']['args']['inputs'])
        self.assertEqual(3, self.observer_calls)
        # A fresh original observer closes the same owner, never another start.
        self.permanent = False
        result = self.module.workflow(self.root, 'reconcile', self.short)
        self.assert_original(result); self.assertEqual('terminal', result['state'])

    def test_source_and_integrity_refusals_are_not_retried_or_reclassified(self):
        self.reason = 'integrity_mismatch'; self.failures = 1
        with self.assertRaisesRegex(readiness.ReadinessBlocked, 'integrity_mismatch'):
            self.module.workflow(self.root, 'reconcile', self.short)
        self.assertEqual(1, self.observer_calls); self.assertEqual(1, len(self.submissions))

    def test_short_caller_deadline_does_not_sleep_or_extend_recovery(self):
        self.permanent = True
        with mock.patch.object(time, 'sleep', side_effect=AssertionError('deadline extended')):
            result = self.jobs.workflow(self.root, 'reconcile', self.short, deadline=time.monotonic()+.25)
        self.assert_original(result); self.assertEqual('unknown', result['state'])
        self.assertEqual(1, self.observer_calls)

    def test_initial_ack_publication_waits_same_owner_then_returns_async_running(self):
        self.start_ack = True; self.ack_statuses = 1; self.running_status = True
        inputs = self.inputs('fixture-a', count=30, intervalSeconds=.01)
        with mock.patch.object(time, 'sleep'):
            result = self.module.workflow(self.root, 'start', inputs)
        self.assertEqual('running', result['state'])
        self.assertEqual(inputs['operationId'], result['operationId'])
        self.assertEqual(2, self.observer_calls)
        self.assertEqual(2, len(self.submissions))  # setup original plus this original
        self.assertEqual(1, sum(op == inputs['operationId'] for _,op in self.submissions))

    def test_ack_publication_wait_preserves_pending_original_at_short_deadline(self):
        self.start_ack = True; self.ack_statuses = 10
        inputs = self.inputs('fixture-a', count=30, intervalSeconds=.01)
        with mock.patch.object(time, 'sleep', side_effect=AssertionError('deadline extended')):
            result = self.jobs.workflow(self.root, 'start', inputs, deadline=time.monotonic()+.25)
        self.assertEqual('unknown', result['state'])
        self.assertEqual('original_owner_ack_pending', result['reason'])
        self.assertEqual(inputs['operationId'], result['operationId'])
        self.assertEqual('reconcile_original', result['nextAction']['kind'])
        self.assertEqual(1, self.observer_calls)
        self.assertEqual(1, sum(op == inputs['operationId'] for _,op in self.submissions))

    def test_public_mcp_dispatch_keeps_durable_original_after_transport_failure(self):
        from agent_tools import mcp_server
        self.permanent = True
        original = mcp_server._agent_module
        def module(name):
            return generic if name == 'readiness_guest_jobs' else readiness if name == 'readiness' else original(name)
        with mock.patch.object(mcp_server, 'REPO_ROOT', self.root), mock.patch.object(mcp_server, '_agent_module', side_effect=module), mock.patch.object(time, 'sleep'):
            result = mcp_server._vm_workflow_dispatch('guest-program-reconcile', self.short)
        self.assert_original(result); self.assertEqual('unknown', result['state'])
        self.assertEqual('reconcile_original', result['nextAction']['kind'])

    def test_retry_readonly_guard_cannot_submit_an_absent_remote_admission(self):
        if not hasattr(self.jobs, '_observe_original'):
            self.fail('unfixed observer has no bounded original-only retry boundary')
        executor = self.executors[next(iter(self.executors))]
        # A read observer must not turn positively missing records into a
        # job-start, even when a local start tombstone exists.
        config = self.jobs._config(executor.binding, self.short['operationId'], 8, .01)
        absent = {k: config[k] for k in ('schemaVersion','operationId','machine','boot','rootGeneration','admissionGeneration')}
        absent.update(state='unsubmitted', reason='original_admission_absent', replayAllowed=False)
        state = executor._state(self.short['operationId'])
        (state / 'owner-identity.json').unlink(); (state / 'remote-admission-consumed.json').unlink()
        with mock.patch.object(self.jobs, '_run', return_value=absent) as remote:
            result = executor._dispatch('status', self.short['operationId'], count=8, interval_seconds=.01,
                    deadline=time.monotonic()+5, readonly=True)
        self.assertEqual('unsubmitted', result['state']); self.assertEqual(1, remote.call_count)
        self.assertEqual('job-status', remote.call_args.args[1])


if __name__ == '__main__':
    unittest.main()

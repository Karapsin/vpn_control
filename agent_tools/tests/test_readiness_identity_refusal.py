"""Whole-before RED/GREEN for readiness requests missing their documented identity."""
import ast
import hashlib
import importlib
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock
from agent_tools import mcp_server as server
from agent_tools import native_response_diagnostics as diagnostics
from agent_tools import readiness
from agent_tools import readiness_transport
from agent_tools import readiness_workflow

FIXTURES = Path(__file__).parent / 'fixtures/readiness_identity_refusal'
OPERATION = '123e4567-e89b-42d3-a456-426614174000'
SSH_INVALID = (None, {}, {'operationId': 'not-a-uuid'}, {'operationId': OPERATION.upper()},
               {'operationId': OPERATION, 'extra': True})
VM_INVALID = (('readiness-status', {}), ('readiness-ensure', {'fixtureId': 'fixture'}),
              ('readiness-reboot', {'fixtureId': 'fixture', 'operationId': 'not-a-uuid'}),
              ('readiness-providers', {'unexpected': True}))
REFERENCE = 'agent_tools/tests/test_readiness_identity_refusal.py::test_whole_before_generic_blocker_current_typed_refusal'


def _pinned(leaf):
    raw = (FIXTURES / leaf).read_bytes()
    provenance = json.loads((FIXTURES / 'provenance.json').read_bytes())
    assert hashlib.sha256(raw).hexdigest() == provenance['files'][leaf]['sha256']
    return raw


class _Workflow:
    """Records facade calls and delegates to the real finite input validation."""
    def __init__(self, result=None):
        self.calls, self.result = [], result

    def ssh_workflow(self, root, action, host, identity):
        self.calls.append((action, identity))
        return self.result if self.result is not None else readiness_workflow.ssh_workflow(root, action, host, identity)

    def vm_workflow(self, root, action, inputs):
        self.calls.append((action, inputs))
        return self.result if self.result is not None else readiness_workflow.vm_workflow(root, action, inputs)


def facade(is_before, workflow):
    """Exact public implementation functions, undecorated, over the current helpers."""
    path = FIXTURES / 'mcp_server.before.source' if is_before else Path(server.__file__)
    raw = _pinned('mcp_server.before.source') if is_before else path.read_bytes()
    names = {'_ssh_workflow_impl', '_vm_workflow_impl', '_vm_workflow_dispatch'}
    nodes = [node for node in ast.parse(raw).body if isinstance(node, ast.FunctionDef) and node.name in names]
    for node in nodes:
        node.decorator_list = []
    modules = {'readiness_workflow': workflow, 'readiness': readiness}
    load = lambda name: modules[name] if name in modules else importlib.import_module('agent_tools.' + name)
    ns = {**vars(server), '_agent_module': load}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), ns)
    return ns


def before_diagnostics():
    module = ModuleType('agent_tools._readiness_identity_before_diagnostics')
    module.__package__ = 'agent_tools'
    exec(compile(_pinned('native_response_diagnostics.before.source'), diagnostics.__file__, 'exec'), module.__dict__)
    return module


class ReadinessIdentityRefusalTests(unittest.TestCase):
    def invoke(self, is_before, workflow, tool, action, value):
        ns = facade(is_before, workflow)
        with mock.patch.object(readiness_transport, 'TransportAdapter',
                               side_effect=AssertionError('transport constructed')) as adapter:
            if tool == 'ssh_workflow':
                result = ns['_ssh_workflow_impl'](action, 'archlinux', 15, value, None, None)
            else:
                result = ns['_vm_workflow_impl'](action, value)
        adapter.assert_not_called()
        return result

    def cases(self):
        for value in SSH_INVALID:
            for action in ('readiness-status', 'readiness-ensure'):
                yield 'ssh_workflow', action, value, 'readiness_identity_invalid'
        for action, value in VM_INVALID:
            yield 'vm_workflow', action, value, 'readiness_inputs_invalid'

    def test_whole_before_generic_blocker_current_typed_refusal(self):
        for tool, action, value, reason in self.cases():
            with self.subTest(tool=tool, action=action, value=value):
                before = _Workflow()
                old = self.invoke(True, before, tool, action, value)
                self.assertEqual(('blocked', 'readiness_admission_unavailable'), (old['state'], old['reason']))
                self.assertEqual(1, len(before.calls))
                current = _Workflow()
                new = self.invoke(False, current, tool, action, value)
                expected = {'tool': tool, 'ok': False, 'state': 'refused', 'reason': reason,
                            'nativeActionAllowed': False, 'replayAllowed': False}
                if tool == 'ssh_workflow':
                    expected['host'] = 'archlinux'
                self.assertEqual(expected, new)
                self.assertEqual([], current.calls)

    def test_failure_signature_names_causal_regression_and_missing_fact(self):
        old = before_diagnostics()
        for tool, action, value, reason in self.cases():
            with self.subTest(tool=tool, action=action, value=value):
                refusal = self.invoke(False, _Workflow(), tool, action, value)
                generic = {'tool': tool, 'ok': False, 'state': 'blocked',
                           'reason': 'readiness_admission_unavailable', 'replayAllowed': False}
                for result in (generic, refusal):
                    signature = old.describe(tool, action, result)['failureSignature']
                    self.assertEqual(('unclassified', True),
                                     (signature['basis']['reason'], signature['regressionRequired']))
                described = diagnostics.describe(tool, action, refusal)
                signature = described['failureSignature']
                self.assertEqual((reason, 'failed', REFERENCE, False),
                                 (signature['basis']['reason'], signature['basis']['classification'],
                                  signature['causalRegression'], signature['regressionRequired']))
                self.assertIn('was contacted', described['admissionGap']['missingFact'])
                self.assertFalse(described['admissionGap']['nativeActionAllowed'])
        self.assertTrue(callable(getattr(self, REFERENCE.rsplit('::', 1)[1])))

    def test_documented_inputs_still_reach_the_same_workflow_once(self):
        cases = (('ssh_workflow', 'readiness-status', {'operationId': OPERATION}),
                 ('ssh_workflow', 'readiness-ensure', {'operationId': OPERATION}),
                 ('vm_workflow', 'readiness-status', {'fixtureId': 'fixture', 'operationId': OPERATION}),
                 ('vm_workflow', 'readiness-reboot', {'fixtureId': 'fixture', 'operationId': OPERATION}),
                 ('vm_workflow', 'readiness-providers', {}))
        for tool, action, value in cases:
            with self.subTest(tool=tool, action=action):
                workflow = _Workflow({'ok': True, 'state': 'observed', 'replayAllowed': False})
                result = self.invoke(False, workflow, tool, action, value)
                self.assertEqual({'tool': tool, 'ok': True, 'state': 'observed', 'replayAllowed': False}, result)
                self.assertEqual([(action, value)], workflow.calls)

    def respond(self, is_before, tool, result):
        raw = _pinned('mcp_server.before.source') if is_before else Path(server.__file__).read_bytes()
        nodes = [node for node in ast.parse(raw).body
                 if isinstance(node, ast.FunctionDef) and node.name == '_native_response']
        recorder = SimpleNamespace(bounded_failure_details=lambda action, value: {},
                                   record_failure=mock.Mock(return_value={'evidenceId': 'native-failure-' + '0' * 32}))
        modules = {'native_failure_evidence': recorder}
        load = lambda name: modules[name] if name in modules else importlib.import_module('agent_tools.' + name)
        ns = {**vars(server), '_agent_module': load}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), 'native-response', 'exec'), ns)
        request = {'host': 'archlinux'} if tool == 'ssh_workflow' else {}
        return ns['_native_response'](tool, 'readiness-status', result, request), recorder.record_failure

    def test_whole_before_records_typed_not_ready_status_current_returns_guidance_only(self):
        for tool, state in (('ssh_workflow', 'expired'), ('ssh_workflow', 'not_ready'),
                            ('vm_workflow', 'dead'), ('vm_workflow', 'unavailable')):
            target = {'host': 'archlinux'} if tool == 'ssh_workflow' else {'fixtureId': 'fixture'}
            result = {'tool': tool, **target, 'ok': False, 'state': state, 'operationId': OPERATION,
                      'replayAllowed': False}
            with self.subTest(tool=tool, state=state):
                old, recorded = self.respond(True, tool, dict(result))
                self.assertEqual(1, recorded.call_count)
                self.assertTrue(old['failureSignature']['regressionRequired'])
                new, recorded = self.respond(False, tool, dict(result))
                recorded.assert_not_called()
                self.assertNotIn('failureSignature', new)
                self.assertNotIn('failureEvidence', new)
                self.assertEqual('ensure_ready', new['nextAction']['kind'])
                self.assertEqual(OPERATION, (new['nextAction']['action']['args'].get('identity')
                                             or new['nextAction']['action']['args'].get('inputs'))['operationId'])
        for state in ('blocked', 'unknown'):
            with self.subTest(retained=state):
                new, recorded = self.respond(False, 'ssh_workflow', {
                    'tool': 'ssh_workflow', 'host': 'archlinux', 'ok': False, 'state': state,
                    'operationId': OPERATION, 'replayAllowed': False})
                self.assertEqual(1, recorded.call_count)
                self.assertEqual('resolve_blocker', new['nextAction']['kind'])

    def test_all_retained_whole_before_artifacts_have_exact_custody(self):
        provenance = json.loads((FIXTURES / 'provenance.json').read_bytes())
        self.assertTrue(provenance['nativeFailureClaimed'])
        self.assertEqual('native-failure-2a20e761b626ad77daa95e15d746358f', provenance['originalEvidence'])
        for leaf, pin in provenance['files'].items():
            self.assertEqual(pin['sha256'], hashlib.sha256((FIXTURES / leaf).read_bytes()).hexdigest(), leaf)


if __name__ == '__main__':
    unittest.main()

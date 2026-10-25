"""Native Windows startup uncertainty must continue observing its original job."""
import hashlib
import json
from pathlib import Path
from types import ModuleType
import unittest
from unittest import mock
from agent_tools import native_next_action as current

FAMILY = Path(__file__).parent / 'fixtures/windows_job_ack_guidance'


def retained(name):
    raw = (FAMILY / name).read_bytes()
    digest = json.loads((FAMILY / 'provenance.json').read_bytes())['sourceSha256'][name]
    if hashlib.sha256(raw).hexdigest() != digest:
        raise AssertionError('native startup guidance evidence changed')
    return raw


def old():
    module = ModuleType('agent_tools._windows_ack_guidance_before')
    module.__package__ = 'agent_tools'
    exec(compile(retained('guidance.before.source'), str(FAMILY / 'guidance.before.source'), 'exec'), module.__dict__)
    return module


class WindowsJobAckGuidanceTests(unittest.TestCase):
    def receipt(self):
        return json.loads(retained('receipt.json'))

    def test_complete_before_actual_native_receipt_RED_current_GREEN(self):
        result = self.receipt()
        self.assertEqual('resolve_blocker', old().next_action('vm_workflow', 'guest-program-start', result)['kind'])
        for provider in ('raw-qemu-windows', 'libvirt-windows'):
            for action in ('start', 'status', 'reconcile'):
                with self.subTest(provider=provider, action=action):
                    guidance = current.next_action('vm_workflow', 'guest-program-' + action, {**result, 'provider': provider})
                    self.assertEqual('reconcile_original', guidance['kind'])
                    self.assertFalse(guidance['replayAllowed'])
                    self.assertEqual({'tool': 'vm_workflow', 'action': 'guest-program-reconcile', 'args': {
                        'inputs': {'fixtureId': result['fixtureId'], 'operationId': result['operationId']}}}, guidance['action'])

    def test_unknown_identity_integrity_and_unqualified_reasons_remain_blocked(self):
        result = self.receipt()
        changes = ({'provider': {}}, {'provider': 'foreign'}, {'reason': {}},
            {'reason': 'original_owner_unresolved'}, {'reason': 'original_admission_absent'},
            {'reason': 'ROOT_OWNER'}, {'reason': 'SOURCE_CHANGED'}, {'durableProtocol': True},
            {'qualificationScope': 'unqualified'}, {'schemaVersion': True}, {'replayAllowed': True},
            {'fixtureId': 'foreign;run'}, {'operationId': result['operationId'].upper()})
        for change in changes:
            with self.subTest(change=change):
                guidance = current.next_action('vm_workflow', 'guest-program-status', {**result, **change})
                self.assertEqual('resolve_blocker', guidance['kind'])
                self.assertNotIn('action', guidance)
                self.assertFalse(guidance['replayAllowed'])

    def test_actual_public_mcp_wrapper_preserves_fixed_continuation(self):
        from agent_tools import mcp_server, native_failure_evidence
        from agent_tools.tests.route_adapter import bind_cached_routes
        bind_cached_routes(self, mcp_server, 'native_failure_evidence')
        result = self.receipt()
        with mock.patch.object(mcp_server, '_vm_workflow_impl', return_value=result), \
                mock.patch.object(native_failure_evidence, 'record_failure', return_value={}):
            actual = mcp_server.vm_workflow('guest-program-start', {'fixtureId': result['fixtureId'],
                'operationId': result['operationId'], 'count': 120, 'intervalSeconds': 1})
        self.assertEqual('reconcile_original', actual['nextAction']['kind'])
        self.assertEqual(result['operationId'], actual['nextAction']['action']['args']['inputs']['operationId'])


if __name__ == '__main__':
    unittest.main()

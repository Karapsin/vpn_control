"""The real lease helper consumes provider-resolved immutable catalogue authority."""
import hashlib
import json
from pathlib import Path
import types
import unittest
from unittest import mock

from agent_tools import readiness
from agent_tools import readiness_lease_workflow as current
from agent_tools import tool_action_policy as policy

FIXTURE = Path(__file__).with_name('fixtures')/'lease_provider_policy_runtime'


def before_module():
    provenance = json.loads((FIXTURE/'provenance.json').read_bytes())
    for name, digest in provenance['files'].items():
        if hashlib.sha256((FIXTURE/name).read_bytes()).hexdigest() != digest:
            raise AssertionError('changed lease provider runtime beforeimage')
    path = FIXTURE/'before.source'
    module = types.ModuleType('agent_tools._lease_provider_runtime_before')
    module.__file__ = str(path)
    module.__package__ = 'agent_tools'
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


class LeaseProviderRuntimeTests(unittest.TestCase):
    def test_complete_before_unclassified_lane_inherits_desktop_current_refuses_before_effects(self):
        old = before_module()
        self.assertEqual(readiness.Requirements(frozenset({'interactive_desktop'}), frozenset({'wake_display'})),
                         old._external_requirements('tart-linux'))
        with mock.patch.object(current.readiness, 'ensure_ready', side_effect=AssertionError('no readiness effect')), \
             mock.patch.object(current.fixtures, 'registered_fixture', side_effect=AssertionError('no fixture lookup')):
            for provider in ('tart-linux', 'macos', '', 1, {}, True):
                with self.assertRaisesRegex(policy.ActionPolicyError, 'unclassified_tool_provider'):
                    current._external_requirements(provider)

    def test_actual_helper_selects_exact_declared_provider_and_preserves_all_four_requirements(self):
        expected = {provider: policy.action_policy('vm_workflow', 'readiness-lease-acquire', provider=provider)
                    for provider in policy.PROVIDER_POLICY_ACTIONS['vm_workflow', 'readiness-lease-acquire']}
        with mock.patch.object(current.policies, 'action_policy', wraps=policy.action_policy) as lookup:
            for provider, declared in expected.items():
                value = current._external_requirements(provider)
                self.assertEqual((declared.requirements, declared.permitted_recoveries),
                                 (value.required, value.permitted_recoveries))
                lookup.assert_called_with('vm_workflow', 'readiness-lease-acquire', provider=provider)
        self.assertEqual(before_module()._REQ, current._REQ)
        self.assertEqual(current._REQ, current._external_requirements('android-emulator'))
        self.assertEqual(readiness.Requirements(frozenset({'guest_agent'})),
                         current._external_requirements('tart-macos'))


if __name__ == '__main__':
    unittest.main()

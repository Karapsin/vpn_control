"""Provider declarations match the actual fixed lease readiness boundaries."""
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import MappingProxyType, ModuleType
import unittest
from uuid import uuid4

from agent_tools import readiness_lease_workflow as workflow
from agent_tools import tool_action_policy as policy
from agent_tools.tests import test_tart_macos_lease_facade as facade

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).with_name('fixtures')/'lease_provider_policy'
KEY = ('vm_workflow', 'readiness-lease-acquire')
PROVIDERS = frozenset({'android-emulator', 'raw-qemu-windows', 'libvirt-windows', 'tart-macos'})


class LeaseProviderPolicyTests(unittest.TestCase):
    def before(self):
        provenance = json.loads((FIXTURE/'provenance.json').read_bytes())
        for name, digest in provenance['files'].items():
            self.assertEqual(digest, hashlib.sha256((FIXTURE/name).read_bytes()).hexdigest())
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        directory = Path(temp.name).resolve()
        source = directory/'tool_action_policy.py'
        source.write_bytes((FIXTURE/'policy.before.source').read_bytes())
        (directory/'tool_action_policy.json').write_bytes((FIXTURE/'policy.before.json').read_bytes())
        name = 'agent_tools._lease_provider_policy_before_' + uuid4().hex
        module = ModuleType(name)
        module.__file__ = str(source)
        module.__package__ = 'agent_tools'
        sys.modules[name] = module
        self.addCleanup(sys.modules.pop, name, None)
        exec(compile(source.read_bytes(), str(source), 'exec'), module.__dict__)
        return module

    def document(self):
        return json.loads(policy.MANIFEST_PATH.read_bytes())

    def group(self, document):
        return next(group for group in document['groups']
                    if group['surface'] == KEY[0] and KEY[1] in group['actions'])

    def parse(self, document):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve()/'policy.json'
            path.write_text(json.dumps(document))
            return policy.load_catalog(path)

    def test_complete_before_declares_desktop_wake_current_selects_actual_mac_background_boundary(self):
        before = self.before()
        old = before.action_policy(*KEY)
        runtime = workflow._external_requirements('tart-macos')
        self.assertIn('interactive_desktop', old.requirements)
        self.assertIn('wake_display', old.permitted_recoveries)
        self.assertNotEqual((old.requirements, old.permitted_recoveries),
                            (runtime.required, runtime.permitted_recoveries))
        with self.assertRaises(TypeError):
            before.action_policy(*KEY, provider='tart-macos')
        selected = policy.action_policy(*KEY, provider='tart-macos')
        self.assertEqual((selected.requirements, selected.permitted_recoveries),
                         (runtime.required, runtime.permitted_recoveries))
        self.assertEqual('background_submission', selected.classification)
        self.assertEqual({'guest_agent'}, selected.requirements)
        self.assertFalse(selected.permitted_recoveries)

    def test_other_three_providers_preserve_exact_existing_interactive_requirement(self):
        self.assertEqual(PROVIDERS, policy.PROVIDER_POLICY_ACTIONS[KEY])
        self.assertEqual(PROVIDERS - {'android-emulator'}, workflow._EXECUTOR_PROVIDERS)
        for provider in PROVIDERS - {'tart-macos'}:
            selected = policy.action_policy(*KEY, provider=provider)
            self.assertEqual((selected.requirements, selected.permitted_recoveries),
                             (workflow._REQ.required, workflow._REQ.permitted_recoveries))
            self.assertEqual('interactive_submission', selected.classification)

    def test_manifest_delta_is_only_the_reviewed_provider_group(self):
        self.before()
        before = json.loads((FIXTURE/'policy.before.json').read_bytes())
        actual = self.document()
        variants = self.group(actual).pop('providerPolicies')
        self.assertEqual(before, actual)
        self.assertEqual(PROVIDERS, set(variants))

    def test_provider_selection_is_immutable_and_unknown_never_inherits_base(self):
        base = policy.action_policy(*KEY)
        self.assertEqual(policy.REQUIREMENTS, base.requirements)
        with self.assertRaises(TypeError):
            base.provider_policies['future'] = base.provider_policies['tart-macos']
        with self.assertRaises(FrozenInstanceError):
            base.provider_policies['tart-macos'].classification = 'interactive_submission'
        for provider in ('tart-linux', '', 1, {}, True):
            with self.assertRaisesRegex(policy.ActionPolicyError, 'unclassified_tool_provider'):
                policy.action_policy(*KEY, provider=provider)
        with self.assertRaisesRegex(policy.ActionPolicyError, 'unclassified_tool_provider'):
            policy.action_policy('vm_workflow', 'matrix-status', provider='tart-macos')

    def test_missing_unknown_wrong_type_or_extra_variant_fields_are_rejected(self):
        changes = (
            lambda rows: rows.pop('tart-macos'),
            lambda rows: rows.update({'tart-linux': rows['tart-macos']}),
            lambda rows: rows['tart-macos'].update(extra=True),
            lambda rows: rows['tart-macos'].update(requirements='guest_agent'),
            lambda rows: rows['tart-macos'].update(permittedRecoveries=False),
            lambda rows: rows['tart-macos'].update(requirements=[True]),
            lambda rows: rows['tart-macos'].update(requirements=['guest_agent', 'guest_agent']),
            lambda rows: rows['tart-macos'].update(permittedRecoveries=['reboot']),
            lambda rows: rows['tart-macos'].update(requirements=[]),
        )
        for change in changes:
            document = self.document()
            change(self.group(document)['providerPolicies'])
            with self.assertRaises(policy.ActionPolicyError):
                self.parse(document)

    def test_cross_classification_and_unclassified_action_overrides_are_rejected(self):
        for fields in (
            {'classification': 'local_metadata'},
            {'classification': 'interactive_submission'},
            {'requirements': ['ordinary_session']},
            {'permittedRecoveries': ['wake_display']},
        ):
            document = self.document()
            self.group(document)['providerPolicies']['tart-macos'].update(fields)
            with self.assertRaisesRegex(policy.ActionPolicyError, 'invalid_provider_policy_classification'):
                self.parse(document)
        document = self.document()
        group = self.group(document)
        group['actions']['matrix-status'] = 'vm_workflow:matrix-status'
        with self.assertRaisesRegex(policy.ActionPolicyError, 'invalid_provider_policy_scope'):
            self.parse(document)

    def test_duplicate_provider_json_and_exposure_audit_missing_variants_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve()/'policy.json'
            raw = policy.MANIFEST_PATH.read_text()
            group = self.group(self.document())
            needle = '"providerPolicies": {'
            duplicate = '"tart-macos":' + json.dumps(group['providerPolicies']['tart-macos']) + ','
            self.assertEqual(1, raw.count(needle))
            path.write_text(raw.replace(needle, needle + duplicate))
            with self.assertRaisesRegex(policy.ActionPolicyError, 'duplicate_policy_key'):
                policy.load_catalog(path)
        catalog = dict(policy.CATALOG)
        catalog[KEY] = replace(catalog[KEY], provider_policies=MappingProxyType({}))
        with self.assertRaisesRegex(policy.ActionPolicyError, 'action_provider_policy_audit_failed'):
            policy.audit_action_catalog(ROOT, catalog)
        self.assertTrue(policy.audit_action_catalog(ROOT)['ok'])

    @unittest.skipUnless(__import__('os').name == 'posix', 'real controlled socket/background owner')
    def test_mac_declared_policy_matches_actual_locked_sleeping_facade_with_no_wake(self):
        case = facade.LeaseFacadeTests('test_old_whole_facade_wakes_locked_display_and_current_background_lease_never_inputs')
        try:
            events, submitted = case.background_scenario(workflow)
        finally:
            case.doCleanups()
        self.assertEqual([], events)
        self.assertTrue(submitted)


if __name__ == '__main__':
    unittest.main()

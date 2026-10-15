"""Public planning must report unavailable dependency coverage as a blocker."""
import unittest
from unittest import mock
from agent_tools import mcp_server as subject
from agent_tools.affected_agent_tests import SelectionError

class WorkflowSelectionBlockerTests(unittest.TestCase):
    def test_status_never_reuses_receipt_when_selection_is_unavailable(self):
        with mock.patch.object(subject,'_commands_for',side_effect=SelectionError('PUBLIC_UNMAPPED_DEPENDENCY')),mock.patch.object(subject,'_changed_paths',return_value=[]),mock.patch.object(subject,'_snapshot_fingerprint',return_value='PUBLIC_FP'),mock.patch.object(subject,'_read_json',return_value={'fingerprint':'PUBLIC_FP'}),mock.patch.object(subject,'_repo_state',return_value={'branch':'dev'}),mock.patch.object(subject,'_advisory_runs',return_value=[]),mock.patch.object(subject.docs_assistant,'index_freshness_warnings',return_value=[]):
            result=subject.workflow_status('tool audit','agent-tools',True)
        self.assertFalse(result['ok']);self.assertFalse(result['result']['prepush_receipt_valid'])
        self.assertEqual([],result['result']['recommended_checks'])
        self.assertEqual('check-selection',result['result']['check_selection_blocker']['phase'])

    def test_impact_returns_finite_blocker_without_checks_or_effects(self):
        with mock.patch.object(subject,'_commands_for',side_effect=SelectionError('PUBLIC_UNMAPPED_DEPENDENCY')),mock.patch.object(subject,'_changed_paths',return_value=[]),mock.patch.object(subject,'docs',return_value={'ok':True,'result':{'matches':[]}}):
            result=subject.change_impact('tool audit','agent-tools')
        self.assertFalse(result['ok']);self.assertEqual([],result['result']['recommended_checks'])
        self.assertEqual('check-selection',result['result']['check_selection_blocker']['phase'])

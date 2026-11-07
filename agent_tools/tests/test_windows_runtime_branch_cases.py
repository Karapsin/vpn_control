"""Routine branch body controls; inert OS peers never qualify native actions."""
import unittest
from agent_tools.tests.fixtures.windows_lifecycle_runtime import boundary

class RuntimeBranchBodyTests(unittest.TestCase):
    def test_current_config_recovery_census_off_and_fixture_bodies(self):self.assertEqual(boundary.run_suite('branches'),19)
    def test_every_authentic_branch_failure_runs_full_before_red_current_green(self):
        self.assertEqual(len(boundary.BRANCH_CASES),5)
        for case in boundary.BRANCH_CASES:
            with self.subTest(case=case):boundary.pair(case)
    def test_closing_native_generation_listener_valid_continuity(self):boundary.valid_closing()
    def test_actual_powershell_parser_when_available(self):self.assertFalse(boundary.parser()['targetExecuted'])

if __name__=='__main__':unittest.main()

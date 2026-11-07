"""Routine actual body controls; native Windows acceptance remains separate."""
import unittest
from agent_tools.tests.fixtures.windows_lifecycle_runtime import boundary

class LifecycleBodyTests(unittest.TestCase):
    def test_current_guard_byte_and_original_gui_effect_bodies(self):self.assertEqual(boundary.run_suite('local'),12)
    def test_current_runtime_fixture_tun_and_lease_bodies(self):self.assertEqual(boundary.run_suite('stages'),14)
    def test_current_tun_context_consumer_bodies(self):self.assertEqual(boundary.run_suite('context'),2)
    def test_every_authentic_lifecycle_failure_runs_full_before_red_current_green(self):
        self.assertEqual(len(boundary.LIFECYCLE_CASES),16)
        for case in boundary.LIFECYCLE_CASES:
            with self.subTest(case=case):boundary.pair(case)

if __name__=='__main__':unittest.main()

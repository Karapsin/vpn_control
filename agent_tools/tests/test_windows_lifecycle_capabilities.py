"""Real suite execution under explicit missing capability boundaries."""
import unittest
from agent_tools.tests.fixtures.windows_lifecycle_runtime import capability_probe, boundary, kotlin_data_guard

class LifecycleCapabilityTests(unittest.TestCase):
    def test_whole_suites_with_windows_like_os_without_posix_attributes(self):
        value=capability_probe.run('windows-like');self.assertEqual(value['causalPairs'],21)
    def test_authentic_windows_rename_peer_full_before_red_current_green(self):boundary.rename_peer_pair()
    def test_fixed_kotlin_data_is_retained_across_unchanged_oracle_reads(self):
        for case in ('route','direct'):kotlin_data_guard.pair(case)
        kotlin_data_guard.exercise('after','valid')
    def test_missing_powershell_is_one_explicit_parser_skip(self):
        value=capability_probe.run('without-powershell');self.assertEqual(len(value['skipped']),1)

if __name__=='__main__':unittest.main()

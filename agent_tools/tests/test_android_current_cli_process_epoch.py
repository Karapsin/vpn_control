"""Actual native false process-epoch refusal and exact identity controls."""
import json
import os
from pathlib import Path
import re
import unittest

FIXTURES = Path(__file__).with_name('fixtures')
MODE = os.environ.get('VC_CURRENT_CLI_EPOCH_MODE', 'green')
SOURCE = FIXTURES / ('android_current_cli_epoch_before.source' if MODE == 'red'
                     else 'android_current_cli_epoch_fixed.source')
ACTUAL = json.loads((FIXTURES / 'android_current_cli_epoch_actual.json').read_text())


class CurrentCliProcessEpochTests(unittest.TestCase):
    def observe(self, after=None, pid=None, boot=None):
        records = {'app-stat-after': ACTUAL['afterStat'] if after is None else after,
                   'app-pid-after': ACTUAL['pid'] if pid is None else pid,
                   'guest-boot-after': ACTUAL['boot'] if boot is None else boot}
        consumed = []
        def shell(role, *words):
            consumed.append((role, words))
            return records[role]
        namespace = {'re': re, 'shell': shell, 'pid': ACTUAL['pid'],
                     'stat1': ACTUAL['beforeStat'], 'boot': ACTUAL['boot']}
        # Execute the exact extracted guard and its actual helper, not a rewrite.
        exec(compile(SOURCE.read_text(), str(SOURCE), 'exec'), namespace)
        return consumed

    def changed_field(self, index):
        head, tail = ACTUAL['afterStat'].rsplit(') ', 1)
        fields = tail.split()
        fields[index] = str(int(fields[index]) + 1)
        return head + ') ' + ' '.join(fields)

    def test_actual_native_cpu_memory_fault_changes_keep_same_epoch(self):
        self.assertNotEqual(ACTUAL['beforeStat'], ACTUAL['afterStat'])
        consumed = self.observe()
        self.assertEqual(['app-stat-after', 'app-pid-after', 'guest-boot-after'],
                         [role for role, _ in consumed])

    def test_stat_pid_change_refuses(self):
        changed = ACTUAL['afterStat'].replace(ACTUAL['pid'] + ' (',
                                              str(int(ACTUAL['pid']) + 1) + ' (', 1)
        with self.assertRaises(ValueError): self.observe(after=changed)

    def test_comm_change_refuses(self):
        with self.assertRaises(ValueError):
            self.observe(after=ACTUAL['afterStat'].replace(' (', ' (changed-', 1))

    def test_parent_change_refuses(self):
        with self.assertRaises(ValueError): self.observe(after=self.changed_field(1))

    def test_start_ticks_change_refuses(self):
        with self.assertRaises(ValueError): self.observe(after=self.changed_field(19))

    def test_closing_pid_change_refuses(self):
        with self.assertRaises(ValueError): self.observe(pid=str(int(ACTUAL['pid']) + 1))

    def test_closing_boot_change_refuses(self):
        with self.assertRaises(ValueError): self.observe(boot='changed-guest-boot')

    def test_malformed_stat_refuses(self):
        with self.assertRaises(ValueError): self.observe(after=ACTUAL['afterStat'].split(')')[0])


if __name__ == '__main__':
    unittest.main()

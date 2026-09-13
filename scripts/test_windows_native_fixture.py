import sys
import os
import subprocess
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from windows_native_fixture import (
    original_recipient_actor_classifier,
    original_recipient_actor_guard,
    private_task_root,
)


class WindowsNativeFixtureTest(unittest.TestCase):
    def test_accepts_each_owned_task_prefix_and_derives_exact_private_root(self):
        local = r"C:\Users\visualagent\AppData\Local"
        suffix = "1b1515e2-2fb1-4483-a280-0b2264d058dc"
        for prefix in ("VpnInstallerEntry32-", "VpnInstallerClose32-", "VpnInstallerPreflight32-"):
            task = prefix + suffix
            self.assertEqual(local + "\\" + task, private_task_root(task, local))

    def test_rejects_mismatched_or_nonprivate_task_root_inputs(self):
        local = r"C:\Users\visualagent\AppData\Local"
        with self.assertRaises(ValueError):
            private_task_root("VpnInstallerBogus32-1b1515e2-2fb1-4483-a280-0b2264d058dc", local)
        with self.assertRaises(ValueError):
            private_task_root("VpnInstallerClose32-not-a-uuid", local)
        with self.assertRaises(ValueError):
            private_task_root("VpnInstallerClose32-1b1515e2-2fb1-4483-a280-0b2264d058dc", r"C:\Windows\Temp")

    def test_original_recipient_actor_validates_expected_inputs(self):
        sid = "S-1-5-21-2019561193-2770119108-3772073605-1001"
        self.assertIn("Assert-VpnFixtureOriginalRecipientActor", original_recipient_actor_guard(sid, 1))
        for invalid_sid in ("S-1-5-18", "S-1-5-80-123", "S-1-5-21-1-2-3-4';Invoke-Expression x"):
            with self.assertRaises(ValueError):
                original_recipient_actor_classifier(invalid_sid, 1)
        for invalid_session in (0, -1, True):
            with self.assertRaises(ValueError):
                original_recipient_actor_classifier(sid, invalid_session)

    @unittest.skipUnless(os.name == "nt", "requires Windows PowerShell")
    def test_generated_actor_classifier_blocks_wrong_actor_before_installer_sentinel(self):
        sid = "S-1-5-21-2019561193-2770119108-3772073605-1001"
        script = original_recipient_actor_classifier(sid, 1) + r'''
$wrong=@(
  @{sid='S-1-5-18';session=1},
  @{sid='S-1-5-80-123';session=1},
  @{sid='S-1-5-21-1-2-3-4';session=1},
  @{sid='S-1-5-21-2019561193-2770119108-3772073605-1001';session=2},
  @{sid='S-1-5-21-2019561193-2770119108-3772073605-1001';session=$true},
  @{sid='S-1-5-21-2019561193-2770119108-3772073605-1001';session=0}
)
foreach($case in $wrong){
  $installerSentinel=$false
  try { Assert-VpnFixtureOriginalRecipientActor -ActualSid $case.sid -ActualSession $case.session; $installerSentinel=$true } catch {}
  if($installerSentinel){throw 'wrong actor reached installer sentinel'}
}
$installerSentinel=$false
Assert-VpnFixtureOriginalRecipientActor -ActualSid 'S-1-5-21-2019561193-2770119108-3772073605-1001' -ActualSession 1
$installerSentinel=$true
if(-not $installerSentinel){throw 'expected interactive actor did not reach installer sentinel'}
'''
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()

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
    FIXTURE_READ_COMMAND,
    fixture_stream_reader,
    fixture_proxy_port_selector,
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
    def test_proxy_port_selector_distinguishes_public_and_management_listeners(self):
        script = "$ErrorActionPreference='Stop'\n" + fixture_proxy_port_selector() + r'''
$config = ConvertFrom-Json '{"inbounds":[{"type":"mixed","tag":"vpn-control-management","listen":"127.0.0.1","listen_port":59142},{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":59143}]}'
if ((Get-VpnFixtureProxyPort $config) -ne 59143) { throw 'wrong public listener' }
$config.inbounds = @($config.inbounds[0])
$rejected = $false
try { $null = Get-VpnFixtureProxyPort $config } catch { $rejected = $true }
if (-not $rejected) { throw 'management listener accepted as public' }
'''
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", script],
            capture_output=True, text=True, check=False, timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    @unittest.skipUnless(os.name == "nt", "requires Windows PowerShell")
    def test_fixture_stream_reader_survives_builtin_aliases_and_rejects_truncation(self):
        script = "$ErrorActionPreference='Stop'\n" + fixture_stream_reader() + f"""
$stream = [IO.MemoryStream]::new([byte[]](5,1,0))
try {{
    $actual = {FIXTURE_READ_COMMAND} $stream 2
    if ($actual.Length -ne 2 -or $actual[0] -ne 5 -or $actual[1] -ne 1) {{ throw 'wrong exact bytes' }}
    $rejected = $false
    try {{ $null = {FIXTURE_READ_COMMAND} $stream 2 }} catch {{ $rejected = $true }}
    if (-not $rejected) {{ throw 'truncated fixture stream accepted' }}
}} finally {{ $stream.Dispose() }}
"""
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", script],
            capture_output=True, text=True, check=False, timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

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

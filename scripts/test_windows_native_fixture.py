import sys
import base64
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from xml.etree import ElementTree

sys.path.insert(0, str(Path(__file__).resolve().parent))

from windows_native_fixture import (
    original_recipient_actor_classifier,
    original_recipient_actor_guard,
    private_task_root,
    FIXTURE_READ_COMMAND,
    FIXTURE_OUTPUT_RECEIPT_COMMAND,
    fixture_stream_reader,
    fixture_output_receipt_reader,
    fixture_proxy_port_selector,
    fixture_native_process_capture,
    native_install_helper_fixture_inputs,
    trusted_powershell_file_arguments,
    fixture_progress_only_stderr,
    fixture_hashtable_sum_after_oracle,
)


WINDOWS_POWERSHELL_AVAILABLE = os.name == "nt" and shutil.which("powershell.exe") is not None


class WindowsNativeFixtureTest(unittest.TestCase):
    def test_trusted_powershell_fixture_file_uses_only_process_scoped_bypass_and_literal_argv(self):
        script = r"C:\\fixture root\\trusted build 雪.ps1"
        arguments = ("red green", "ключ", "literal;$HOME|`tick")
        command = trusted_powershell_file_arguments(script, arguments)
        self.assertEqual(
            command,
            (
                "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script,
                *arguments,
            ),
        )
        self.assertNotIn("Set-ExecutionPolicy", command)
        self.assertNotIn("-Scope", command)
        with self.assertRaisesRegex(ValueError, "absolute and end in .ps1"):
            trusted_powershell_file_arguments(r"fixture\\build.ps1", ())
        with self.assertRaisesRegex(ValueError, "tuple of strings"):
            trusted_powershell_file_arguments(script, ["not typed"])  # type: ignore[arg-type]

    def test_install_helper_fixture_inventory_uses_current_project_declarations(self):
        repository = Path(__file__).parents[1]
        inputs = native_install_helper_fixture_inputs(repository)
        self.assertIn("desktopApp/native/windows/InstallHelper/InstallHelper.csproj", inputs)
        self.assertIn("desktopApp/native/windows/InstallHelper/loader.manifest", inputs)
        self.assertIn("desktopApp/native/windows/Directory.Build.props", inputs)
        self.assertIn("desktopApp/native/windows/global.json", inputs)
        project = ElementTree.parse(
            repository / "desktopApp/native/windows/InstallHelper/InstallHelper.csproj"
        )
        declared_sources = {
            (repository / "desktopApp/native/windows/InstallHelper" /
             entry.attrib["Include"].replace("\\", "/")).resolve().relative_to(repository).as_posix()
            for entry in project.findall(".//Compile")
        }
        self.assertTrue(declared_sources.issubset(set(inputs)))

    def test_install_helper_fixture_inventory_follows_renamed_manifest_and_rejects_missing_input(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            helper = root / "desktopApp/native/windows/InstallHelper"
            source = root / "desktopApp/src/main/resources/renamed-source.cs"
            helper.mkdir(parents=True)
            source.parent.mkdir(parents=True)
            (root / "desktopApp/native/windows/Directory.Build.props").write_text("<Project />", encoding="utf-8")
            (root / "desktopApp/native/windows/global.json").write_text("{}", encoding="utf-8")
            (helper / "renamed-loader.manifest").write_text("manifest", encoding="utf-8")
            source.write_text("class Source {}", encoding="utf-8")
            project = helper / "InstallHelper.csproj"
            project.write_text(
                "<Project><PropertyGroup><ApplicationManifest>renamed-loader.manifest</ApplicationManifest>"
                "</PropertyGroup><ItemGroup><Compile Include=\"../../../src/main/resources/renamed-source.cs\" />"
                "</ItemGroup></Project>", encoding="utf-8",
            )
            inputs = native_install_helper_fixture_inputs(root)
            self.assertIn("desktopApp/native/windows/InstallHelper/renamed-loader.manifest", inputs)
            self.assertIn("desktopApp/src/main/resources/renamed-source.cs", inputs)
            (helper / "renamed-loader.manifest").unlink()
            with self.assertRaisesRegex(FileNotFoundError, "renamed-loader.manifest"):
                native_install_helper_fixture_inputs(root)

    def test_install_helper_fixture_inventory_rejects_escape_before_build(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            helper = root / "desktopApp/native/windows/InstallHelper"
            helper.mkdir(parents=True)
            (root / "desktopApp/native/windows/Directory.Build.props").write_text("<Project />", encoding="utf-8")
            (root / "desktopApp/native/windows/global.json").write_text("{}", encoding="utf-8")
            (helper / "InstallHelper.csproj").write_text(
                "<Project><PropertyGroup><ApplicationManifest>../../../../../outside.manifest</ApplicationManifest>"
                "</PropertyGroup></Project>", encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "escapes repository root"):
                native_install_helper_fixture_inputs(root)

    def test_install_helper_fixture_inventory_rejects_msbuild_expressions(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            helper = root / "desktopApp/native/windows/InstallHelper"
            helper.mkdir(parents=True)
            (root / "desktopApp/native/windows/Directory.Build.props").write_text("<Project />", encoding="utf-8")
            (root / "desktopApp/native/windows/global.json").write_text("{}", encoding="utf-8")
            (helper / "InstallHelper.csproj").write_text(
                "<Project><PropertyGroup><ApplicationManifest>$(ManifestName)</ApplicationManifest>"
                "</PropertyGroup></Project>", encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "unsupported InstallHelper input expression"):
                native_install_helper_fixture_inputs(root)

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

    @unittest.skipUnless(WINDOWS_POWERSHELL_AVAILABLE, "requires Windows PowerShell")
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

    @unittest.skipUnless(WINDOWS_POWERSHELL_AVAILABLE, "requires Windows PowerShell")
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

    @unittest.skipUnless(WINDOWS_POWERSHELL_AVAILABLE, "requires Windows PowerShell")
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

    @unittest.skipUnless(WINDOWS_POWERSHELL_AVAILABLE, "requires Windows PowerShell")
    def test_output_receipt_reader_preserves_empty_streams_and_direct_child_exit_code(self):
        script = "$ErrorActionPreference='Stop'\n" + fixture_native_process_capture() + fixture_output_receipt_reader() + rf'''
$root = Join-Path ([IO.Path]::GetTempPath()) ('vpn output receipt ' + [guid]::NewGuid().ToString())
[IO.Directory]::CreateDirectory($root) | Out-Null
try {{
  $tool = (Get-Command powershell.exe -CommandType Application -ErrorAction Stop).Source
  $child = Join-Path $root 'receipt child.ps1'
  [IO.File]::WriteAllText($child, @'
param(
  [AllowEmptyString()][string]$Stdout,
  [AllowEmptyString()][string]$Stderr,
  [int]$ExitCode
)
$utf8 = New-Object Text.UTF8Encoding($false)
foreach($entry in @(
  @{{Stream=[Console]::OpenStandardOutput(); Text=$Stdout}},
  @{{Stream=[Console]::OpenStandardError(); Text=$Stderr}}
)) {{
  $bytes = $utf8.GetBytes($entry.Text)
  $entry.Stream.Write($bytes, 0, $bytes.Length)
}}
exit $ExitCode
'@)
  $cases = @(
    @{{stdout=''; stderr=''; exitCode=0}},
    @{{stdout='stdout only'; stderr=''; exitCode=7}},
    @{{stdout=''; stderr='stderr only'; exitCode=23}},
    @{{stdout='stdout and stderr'; stderr='stderr and stdout'; exitCode=31}}
  )
  $caseNumber = 0
  foreach ($case in $cases) {{
    $stdoutPath = Join-Path $root ("stdout-$caseNumber.txt")
    $stderrPath = Join-Path $root ("stderr-$caseNumber.txt")
    $result = Invoke-VpnFixtureNativeProcess -FilePath $tool `
      -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $child, $case.stdout, $case.stderr, [string]$case.exitCode) `
      -StandardOutputPath $stdoutPath -StandardErrorPath $stderrPath
    $receipt = {FIXTURE_OUTPUT_RECEIPT_COMMAND} -StandardOutputPath $stdoutPath `
      -StandardErrorPath $stderrPath -ExitCode $result.ExitCode
    if ($null -eq $receipt.Stdout -or $receipt.Stdout -cne $case.stdout) {{ throw "stdout was not preserved for case $caseNumber" }}
    if ($null -eq $receipt.Stderr -or $receipt.Stderr -cne $case.stderr) {{ throw "stderr was not preserved for case $caseNumber" }}
    if ($receipt.ExitCode -ne $case.exitCode) {{ throw "exit code was not preserved for case $caseNumber" }}
    $caseNumber++
  }}

  # This is the broken pre-fix receipt expression.  Get-Content emits no
  # pipeline value for an empty file, so calling Trim fails before a receipt
  # can be created.
  $oldExpressionRejected = $false
  try {{ $unused = (Get-Content -LiteralPath (Join-Path $root 'stdout-0.txt') -Raw).Trim() }} catch {{ $oldExpressionRejected = $true }}
  if (-not $oldExpressionRejected) {{ throw 'pre-fix empty stdout expression unexpectedly succeeded' }}
}} finally {{
  Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}}
'''
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", script],
            capture_output=True, text=True, check=False, timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    @unittest.skipUnless(WINDOWS_POWERSHELL_AVAILABLE, "requires Windows PowerShell")
    def test_native_process_capture_keeps_native_stderr_nonterminating_and_uses_real_exit_code(self):
        script = "$ErrorActionPreference='Stop'\n" + fixture_native_process_capture() + r'''
$root = Join-Path ([IO.Path]::GetTempPath()) ('vpn native capture ' + [guid]::NewGuid().ToString())
[IO.Directory]::CreateDirectory($root) | Out-Null
try {
  $tool = (Get-Command powershell.exe -CommandType Application -ErrorAction Stop).Source
  $child = Join-Path $root 'native child script with spaces.ps1'
  $childSource = @'
param(
  [string]$First,
  [string]$Second,
  [int]$ExitCode,
  [AllowEmptyString()][string]$Empty,
  [int]$PayloadBytes
)
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'child-cwd.txt'), [Environment]::CurrentDirectory)
$utf8 = New-Object Text.UTF8Encoding($false)
$stdoutStream = [Console]::OpenStandardOutput()
$stderrStream = [Console]::OpenStandardError()
$stdout = New-Object IO.StreamWriter($stdoutStream, $utf8)
$stderr = New-Object IO.StreamWriter($stderrStream, $utf8)
$stdout.AutoFlush = $true
$stderr.AutoFlush = $true
$stdout.WriteLine('stdout:' + $First + '|emptyLength:' + $Empty.Length)
$stderr.WriteLine('stderr:' + $Second)
$payload = New-Object byte[] 8192
$remaining = $PayloadBytes
while ($remaining -gt 0) {
  $count = [Math]::Min($payload.Length, $remaining)
  $stdoutStream.Write($payload, 0, $count)
  $stderrStream.Write($payload, 0, $count)
  $remaining -= $count
}
exit $ExitCode
'@
  [IO.File]::WriteAllText($child, $childSource)
  $stdout = Join-Path $root 'stdout capture with spaces.txt'
  $stderr = Join-Path $root 'stderr capture with spaces.txt'
  # 256 KiB on each pipe reliably exceeds the Windows anonymous pipe buffer.
  # The helper must drain both pipes concurrently and retain the direct child exit.
  $payloadBytes = 262144
  $successArguments = @('-NoProfile', '-File', $child, 'argument one with spaces', 'argument two with spaces', '0', '', $payloadBytes)

  $merged = Join-Path $root 'merged capture.txt'
  $mergedTerminated = $false
  try {
    & $tool @successArguments *> $merged
  } catch {
    if ($_.ToString() -notmatch 'stderr:argument two with spaces') { throw }
    $mergedTerminated = $true
  }
  if (-not $mergedTerminated) { throw 'merged native stderr did not reproduce the PS5.1 termination' }

  Push-Location -LiteralPath $root
  try {
    $success = Invoke-VpnFixtureNativeProcess -FilePath $tool `
        -Arguments $successArguments `
        -StandardOutputPath $stdout -StandardErrorPath $stderr
  } finally { Pop-Location }
  if ([IO.File]::ReadAllText((Join-Path $root 'child-cwd.txt')) -ne $root) { throw 'native process lost the PowerShell working directory' }
  if ($success.ExitCode -ne 0) { throw 'exit-0 child was not successful' }
  $stdoutBytes = [IO.File]::ReadAllBytes($stdout)
  $stderrBytes = [IO.File]::ReadAllBytes($stderr)
  $stdoutHeader = [Text.Encoding]::UTF8.GetString($stdoutBytes, 0, ('stdout:argument one with spaces|emptyLength:0' + "`r`n").Length)
  $stderrHeader = [Text.Encoding]::UTF8.GetString($stderrBytes, 0, ('stderr:argument two with spaces' + "`r`n").Length)
  if ($stdoutHeader -cne "stdout:argument one with spaces|emptyLength:0`r`n") { throw 'stdout or empty argument was changed' }
  if ($stderrHeader -cne "stderr:argument two with spaces`r`n") { throw 'stderr argument was changed' }
  if ($stdoutBytes.Length -ne ($stdoutHeader.Length + $payloadBytes)) { throw 'stdout payload was not fully captured' }
  if ($stderrBytes.Length -ne ($stderrHeader.Length + $payloadBytes)) { throw 'stderr payload was not fully captured' }

  $failure = Invoke-VpnFixtureNativeProcess -FilePath $tool `
      -Arguments @('-NoProfile', '-File', $child, 'still spaced', 'warning on stderr', '23', '', 0) `
      -StandardOutputPath (Join-Path $root 'second stdout with spaces.txt') `
      -StandardErrorPath (Join-Path $root 'second stderr with spaces.txt')
  if ($failure.ExitCode -ne 23) { throw 'nonzero child exit was not retained' }
  if (([IO.File]::ReadAllText((Join-Path $root 'second stderr with spaces.txt'))).Trim() -cne 'stderr:warning on stderr') { throw 'nonzero stderr was not captured' }

  # A descendant waits for an acknowledgement that can only be written after
  # capture returns. Waiting the entire process tree creates a causal cycle.
  $descendant = Join-Path $root 'waiting descendant.ps1'
  [IO.File]::WriteAllText($descendant, @'
param([string]$Release, [string]$TimedOut)
$deadline = [DateTime]::UtcNow.AddSeconds(20)
while (-not [IO.File]::Exists($Release)) {
  if ([DateTime]::UtcNow -ge $deadline) { [IO.File]::WriteAllText($TimedOut, 'cycle'); exit 0 }
  Start-Sleep -Milliseconds 20
}
'@)
  $parent = Join-Path $root 'launch descendant.ps1'
  [IO.File]::WriteAllText($parent, @'
param([string]$Root)
$quote = { param($value) '"' + $value + '"' }
$arguments = @('-NoProfile', '-File', (& $quote (Join-Path $Root 'waiting descendant.ps1')),
  (& $quote (Join-Path $Root 'release')), (& $quote (Join-Path $Root 'timed-out')))
$startInfo = New-Object Diagnostics.ProcessStartInfo
$startInfo.FileName = Join-Path $PSHOME 'powershell.exe'
$startInfo.Arguments = $arguments -join ' '
$startInfo.UseShellExecute = $true
$startInfo.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
$child = [Diagnostics.Process]::Start($startInfo)
[IO.File]::WriteAllText((Join-Path $Root 'descendant.pid'), [string]$child.Id)
exit 0
'@)
  try {
    $parentResult = Invoke-VpnFixtureNativeProcess -FilePath $tool `
      -Arguments @('-NoProfile', '-File', $parent, $root) `
      -StandardOutputPath (Join-Path $root 'parent.stdout') `
      -StandardErrorPath (Join-Path $root 'parent.stderr')
    if ($parentResult.ExitCode -ne 0) { throw 'descendant launcher failed' }
    if ([IO.File]::Exists((Join-Path $root 'timed-out'))) { throw 'capture waited for a descendant instead of the direct child' }
  } finally {
    [IO.File]::WriteAllText((Join-Path $root 'release'), 'acknowledged')
    $pidFile = Join-Path $root 'descendant.pid'
    if ([IO.File]::Exists($pidFile)) {
      $ownedChild = Get-Process -Id ([int][IO.File]::ReadAllText($pidFile)) -ErrorAction SilentlyContinue
      if ($null -ne $ownedChild) { [void]$ownedChild.WaitForExit(5000); $ownedChild.Dispose() }
    }
  }
} finally {
  Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
'''
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", script],
            capture_output=True, text=True, check=False, timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


CLEANUP_POWERSHELL = shutil.which("powershell.exe") or shutil.which("pwsh")

class WindowsHashtableSumTest(unittest.TestCase):
    BEFORE = "$ErrorActionPreference='Stop';$images=@(@{bytes=[long]200},@{bytes=[long]300});($images|Measure-Object bytes -Sum).Sum"
    AFTER = "$ErrorActionPreference='Stop';$images=@(@{bytes=[long]200},@{bytes=[long]300});[long]$sum=0;foreach($r in $images){$sum+=[long]$r['bytes']};if($sum -ne 500){throw 'SUM_ORACLE'};Write-Output $sum"

    @unittest.skipUnless(CLEANUP_POWERSHELL, "requires PowerShell for typed Hashtable sum")
    def test_portable_typed_sum_reads_hashtable_keys(self):
        done=subprocess.run([CLEANUP_POWERSHELL,'-NoProfile','-NonInteractive','-Command',self.AFTER],capture_output=True,text=True,timeout=20)
        self.assertEqual(done.returncode,0,done.stderr)
        self.assertEqual(done.stdout.strip(),'500')

    @unittest.skipUnless(WINDOWS_POWERSHELL_AVAILABLE, "actual Windows PowerShell5.1 causal native regression; PowerShell7 accepts the before expression")
    def test_windows5_1_authentic_measure_object_red_to_typed_green(self):
        version=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command','$PSVersionTable.PSVersion.ToString()'],capture_output=True,text=True,timeout=20)
        self.assertEqual(version.returncode,0,version.stderr)
        self.assertTrue(version.stdout.strip().startswith('5.1.'),version.stdout)
        before=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',self.BEFORE],capture_output=True,text=True,timeout=20)
        after=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',self.AFTER],capture_output=True,text=True,timeout=20)
        self.assertNotEqual(before.returncode,0,'native PS5.1 before must reproduce the original85878 error')
        self.assertIn('GenericMeasurePropertyNotFound',before.stderr)
        self.assertEqual(after.returncode,0,after.stderr)
        self.assertEqual(after.stdout.strip(),'500')
    @staticmethod
    def _run_progress_control(control, edge=False):
        with tempfile.TemporaryDirectory(prefix="vpn-sum-oracle-") as scratch:
            root = Path(scratch)
            helper = fixture_progress_only_stderr()
            if hashlib.sha256(helper.encode()).hexdigest() != "76e2b5869177c1cbb885397480fddaad3f46a9b1c138b4777b47b6c90080b95b":
                raise AssertionError("authentic fixed progress helper changed")
            legacy = helper.replace(r"\A[0-9]{1,8}\z", r"^[0-9]{1,8}$")
            if hashlib.sha256(legacy.encode()).hexdigest() != "ee1f2b7c6b7254bd7834ee4563f77f7d6177aa8644b25232a082194fa07b32e6":
                raise AssertionError("authentic RefId beforeimage changed")
            before_source = WindowsHashtableSumTest.BEFORE_ORACLE + "\n" + WindowsHashtableSumTest.AFTER_ORACLE_BEFORE + "\n"
            fixed_source = WindowsHashtableSumTest.BEFORE_ORACLE + "\n" + fixture_hashtable_sum_after_oracle() + "\n"
            files = {
                "progress-only.ps1": helper.encode(), "progress-only.ps1.refid-before": legacy.encode(),
                "task-oracle.before.ps1": before_source.encode(), "task.oracle-fixed.oldtuple.ps1": fixed_source.encode(),
                "task.ps1.refid-before": fixed_source.encode(), "task.ps1": fixed_source.encode(),
                "after.stderr.txt": base64.b64decode(WindowsHashtableSumTest.AFTER_STDERR_BASE64, validate=True),
                "after.stdout.txt": b"500\r\n",
                "fixtures.json": gzip.decompress(base64.b64decode(WindowsHashtableSumTest.PROGRESS_FIXTURES_GZIP_BASE64, validate=True)),
                "control.ps1": control.encode(),
            }
            for name, body in files.items():
                (root / name).write_bytes(body)
            completed = subprocess.run(
                [CLEANUP_POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(root / "control.ps1")],
                capture_output=True, text=True, timeout=20,
            )
            # Finite inert records keep causal outcomes visible in routine logs.
            print(completed.stdout, end="")
            if completed.returncode != 0:
                raise AssertionError(completed.stderr + completed.stdout)
            summary = json.loads((root / ("refid-control-summary.json" if edge else "control-summary.json")).read_text())
            if summary["pass"] != (3 if edge else 31) or summary["skip"] != 0 or summary["nativeActions"] != 0:
                raise AssertionError(summary)
            return summary

    @unittest.skipUnless(CLEANUP_POWERSHELL, "requires actual PowerShell for the progress-only XML oracle")
    def test_actual_progress_only_clixml_oracle_preserves_native_error_refusals(self):
        summary = self._run_progress_control(self.PROGRESS_CONTROL)
        self.assertEqual(summary["oldCausalRed"], 1)
        self.assertEqual(summary["fixedControls"], 30)

    @unittest.skipUnless(CLEANUP_POWERSHELL, "requires actual PowerShell for XML RefId final-LF refusal")
    def test_actual_progress_refid_rejects_xml_final_lf(self):
        summary = self._run_progress_control(self.REFID_CONTROL, edge=True)
        self.assertEqual(summary["oldActualDefect"], 1)
        self.assertEqual(summary["newRefusal"], 1)
        self.assertEqual(summary["nativeSampleCompatibility"], 1)


    @staticmethod
    def _run_manifest_array_control(windows51=False):
        with tempfile.TemporaryDirectory(prefix="vpn-manifest-array-") as scratch:
            root = Path(scratch)
            installed = root / "installed"
            installed.mkdir()
            rows = []
            for index in range(209):
                relative = "row-%03d.txt" % index
                body = ("harmless public row %03d\n" % index).encode()
                (installed / relative).write_bytes(body)
                rows.append({"relativePath": relative, "size": len(body), "sha256": hashlib.sha256(body).hexdigest()})
            (root / "expected.json").write_text(json.dumps(rows), encoding="utf-8")
            (root / "assignment.before.ps1").write_text(WindowsHashtableSumTest.MANIFEST_ARRAY_BEFORE, encoding="utf-8")
            (root / "assignment.fixed.ps1").write_text(WindowsHashtableSumTest.MANIFEST_ARRAY_FIXED, encoding="utf-8")
            (root / "count.ps1").write_text(WindowsHashtableSumTest.MANIFEST_ARRAY_COUNT, encoding="utf-8")
            (root / "iteration.ps1").write_text(WindowsHashtableSumTest.MANIFEST_ARRAY_ITERATION, encoding="utf-8")
            (root / "control.ps1").write_text(WindowsHashtableSumTest.MANIFEST_ARRAY_CONTROL, encoding="utf-8")
            completed = subprocess.run(
                [CLEANUP_POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(root / "control.ps1"), "-Windows51", str(int(windows51))],
                capture_output=True, text=True, timeout=20,
            )
            print(completed.stdout, end="")
            if completed.returncode != 0:
                raise AssertionError(completed.stderr + completed.stdout)
            summary = json.loads((root / "array-summary.json").read_text(encoding="utf-8"))
            if summary["pass"] != 7 or summary["skip"] != 0 or summary["nativeActions"] != 0:
                raise AssertionError(summary)
            return summary

    @unittest.skipUnless(CLEANUP_POWERSHELL, "requires actual PowerShell and real filesystem/hash iteration")
    def test_actual_manifest_array_assignment_preserves_full_hash_iteration(self):
        summary = self._run_manifest_array_control()
        self.assertEqual(summary["legacyCount"], 1)
        self.assertEqual(summary["fixedCount"], 209)
        self.assertEqual(summary["fixedHashedFiles"], 209)
        self.assertEqual(summary["lastHashRefusalVisited"], 209)

    @unittest.skipUnless(WINDOWS_POWERSHELL_AVAILABLE, "requires actual Windows PowerShell5.1 ConvertFrom-Json output semantics")
    def test_windows5_1_actual_manifest_array_count_red_to_assignment_green(self):
        summary = self._run_manifest_array_control(windows51=True)
        self.assertFalse(summary["cmdletOutputShapeModeled"])
        self.assertTrue(summary["psVersion"].startswith("5.1."))

    MANIFEST_ARRAY_CONTROL = r'''param([int]$Windows51=0)
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$expected=Join-Path $root 'expected.json'
$installed=Join-Path $root 'installed'
$version=$PSVersionTable.PSVersion
if($Windows51 -and ($version.Major -ne 5 -or $version.Minor -ne 1)){throw 'ACTUAL_WINDOWS_51_REQUIRED'}
$old=[scriptblock]::Create([IO.File]::ReadAllText((Join-Path $root 'assignment.before.ps1')))
$fixed=[scriptblock]::Create([IO.File]::ReadAllText((Join-Path $root 'assignment.fixed.ps1')))
$count=[scriptblock]::Create([IO.File]::ReadAllText((Join-Path $root 'count.ps1')))
$iteration=[scriptblock]::Create([IO.File]::ReadAllText((Join-Path $root 'iteration.ps1')))
# PS7 normally enumerates JSON arrays. Keep that compatibility fact explicit.
. $old;$defaultOld=$rows.Count
. $fixed;$defaultFixed=$rows.Count
$modeled=($version.Major -ge 7)
if($modeled){
 # Actual cmdlet -NoEnumerate recreates the PS5.1 single output-object shape.
 # It does not supply a desired verdict: parsing, assignments and all hashes run.
 function ConvertFrom-Json {
  param([Parameter(ValueFromPipeline=$true)][string]$InputObject)
  process{Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $InputObject -NoEnumerate}
 }
}
function Invoke-ArrayBoundary([scriptblock]$Assignment,[string]$Name){
 $visited=[Collections.Generic.List[string]]::new()
 function Ancestors([string]$Path){
  # External Windows ancestor/token admission is excluded; owned file bytes are real.
  $visited.Add([IO.Path]::GetFileName($Path))
 }
 $rows=$null;$sum=0L;$caught=$null
 try{. $Assignment;. $count;. $iteration}catch{$caught=$_.Exception.Message}
 $record=@{name=$Name;allowed=($null -eq $caught);error=$caught;count=$rows.Count;visited=$visited.Count;sum=$sum;nativeActions=0}
 [Console]::Out.WriteLine(($record|ConvertTo-Json -Compress))
 return $record
}
$red=Invoke-ArrayBoundary $old 'authentic-before-count-red'
if($red.allowed -or $red.error -cne 'BASE_EXPECTED_COUNT' -or $red.count -ne 1 -or $red.visited -ne 0){throw 'OLD_NOT_CAUSAL_RED'}
$green=Invoke-ArrayBoundary $fixed 'fixed-all209-real-hashes-green'
[long]$expectedBytes=0;foreach($r in $rows){$expectedBytes+=[long]$r.size}
if(-not $green.allowed -or $green.count -ne 209 -or $green.visited -ne 209 -or $green.sum -ne $expectedBytes){throw 'FIXED_NOT_FULL_ITERATION_GREEN'}
$original=[IO.File]::ReadAllBytes($expected)
$fixture=Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject ([Text.UTF8Encoding]::new($false,$true)).GetString($original)
# Count refusals must precede any file/hash iteration.
foreach($size in @(208,210)){
 $items=@($fixture)
 if($size -eq 208){$items=$items[0..207]}else{$items+=,$items[0]}
 [IO.File]::WriteAllText($expected,($items|ConvertTo-Json -Compress))
 $r=Invoke-ArrayBoundary $fixed ('fixed-count-'+$size+'-refusal')
 if($r.allowed -or $r.error -cne 'BASE_EXPECTED_COUNT' -or $r.visited -ne 0){throw 'COUNT_REFUSAL'}
}
[IO.File]::WriteAllBytes($expected,$original)
$last=Join-Path $installed 'row-208.txt'
$lastBytes=[IO.File]::ReadAllBytes($last)
$wrong=[byte[]]$lastBytes.Clone();$wrong[0]=$wrong[0] -bxor 1
[IO.File]::WriteAllBytes($last,$wrong)
$badHash=Invoke-ArrayBoundary $fixed 'fixed-last-row-same-size-hash-refusal'
if($badHash.allowed -or $badHash.error -cne 'BASE_FULL_FILE_HASH' -or $badHash.visited -ne 209){throw 'LAST_HASH_NOT_CHECKED'}
[IO.File]::WriteAllBytes($last,$lastBytes[0..($lastBytes.Length-2)])
$badSize=Invoke-ArrayBoundary $fixed 'fixed-last-row-size-refusal'
if($badSize.allowed -or $badSize.error -cne 'BASE_FULL_FILE_HASH' -or $badSize.visited -ne 209){throw 'LAST_SIZE_NOT_CHECKED'}
[IO.File]::WriteAllBytes($last,$lastBytes)
$extra=Join-Path $installed 'unexpected.txt';[IO.File]::WriteAllText($extra,'harmless extra')
$badTree=Invoke-ArrayBoundary $fixed 'fixed-extra-file-tree-count-refusal'
if($badTree.allowed -or $badTree.error -cne 'BASE_TREE_COUNT' -or $badTree.visited -ne 0){throw 'TREE_COUNT_NOT_CHECKED'}
[IO.File]::Delete($extra)
$summary=@{pass=7;skip=0;nativeActions=0;legacyCount=$red.count;fixedCount=$green.count;fixedHashedFiles=$green.visited;lastHashRefusalVisited=$badHash.visited;cmdletOutputShapeModeled=$modeled;defaultCmdletLegacyCount=$defaultOld;defaultCmdletFixedCount=$defaultFixed;psVersion=$version.ToString();scope='Authentic assignments/count/tree/hash loop; real own209TempFS. PS7 -NoEnumerate models only PS5.1 output shape; native ancestor/token/manifest admission excluded.'}
[IO.File]::WriteAllText((Join-Path $root 'array-summary.json'),($summary|ConvertTo-Json -Compress))
[Console]::Out.WriteLine(($summary|ConvertTo-Json -Compress))
'''
    MANIFEST_ARRAY_BEFORE = '$rows=@(Get-Content -LiteralPath $expected -Raw|ConvertFrom-Json);'
    MANIFEST_ARRAY_FIXED = '$decoded=Get-Content -LiteralPath $expected -Raw|ConvertFrom-Json;$rows=@($decoded);'
    MANIFEST_ARRAY_COUNT = "if($rows.Count -ne 209){throw 'BASE_EXPECTED_COUNT'};"
    MANIFEST_ARRAY_ITERATION = "$all=@(Get-ChildItem -LiteralPath $installed -Force -Recurse);if(@($all|Where-Object {$_.Attributes -band 1024}).Count -or @($all|Where-Object {-not $_.PSIsContainer}).Count -ne 209){throw 'BASE_TREE_COUNT'};[long]$sum=0;foreach($r in $rows){$f=Join-Path $installed $r.relativePath;Ancestors $f;if((Get-Item -LiteralPath $f).Length -ne $r.size -or (Get-FileHash -LiteralPath $f).Hash.ToLowerInvariant() -cne $r.sha256){throw 'BASE_FULL_FILE_HASH'};$sum+=[long]$r.size}"

    BEFORE_ORACLE = "if($case -eq 'before' -and ($r.ExitCode -eq 0 -or $stderr -notmatch 'GenericMeasurePropertyNotFound')){throw 'AUTHENTIC_BEFORE_NOT_RED'}"
    AFTER_ORACLE_BEFORE = "if($case -eq 'after' -and ($r.ExitCode -ne 0 -or $stdout.Trim() -cne '500' -or $stderr.Length -ne 0)){throw 'TYPED_AFTER_NOT_GREEN'}"
    AFTER_STDERR_BASE64 = 'IzwgQ0xJWE1MDQo8T2JqcyBWZXJzaW9uPSIxLjEuMC4xIiB4bWxucz0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS9wb3dlcnNoZWxsLzIwMDQvMDQiPjxPYmogUz0icHJvZ3Jlc3MiIFJlZklkPSIwIj48VE4gUmVmSWQ9IjAiPjxUPlN5c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24uUFNDdXN0b21PYmplY3Q8L1Q+PFQ+U3lzdGVtLk9iamVjdDwvVD48L1ROPjxNUz48STY0IE49IlNvdXJjZUlkIj4xPC9JNjQ+PFBSIE49IlJlY29yZCI+PEFWPlByZXBhcmluZyBtb2R1bGVzIGZvciBmaXJzdCB1c2UuPC9BVj48QUk+MDwvQUk+PE5pbCAvPjxQST4tMTwvUEk+PFBDPi0xPC9QQz48VD5Db21wbGV0ZWQ8L1Q+PFNSPi0xPC9TUj48U0Q+IDwvU0Q+PC9QUj48L01TPjwvT2JqPjwvT2Jqcz4='
    PROGRESS_FIXTURES_GZIP_BASE64 = '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'
    PROGRESS_CONTROL = r'''$ErrorActionPreference='Stop'
$root=$PSScriptRoot
. (Join-Path $root 'progress-only.ps1')
function Select-Oracle([string]$Path,[string]$Label){
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput([IO.File]::ReadAllText($Path),[ref]$tokens,[ref]$errors)
 if($errors.Count){throw 'CONTROL_PARSE'}
 $nodes=@($ast.FindAll({param($a) $a -is [Management.Automation.Language.IfStatementAst] -and $a.Extent.Text.Contains("throw '$Label'")},$true))
 if($nodes.Count -ne 1){throw 'ORACLE_COUNT'}
 return [scriptblock]::Create($nodes[0].Extent.Text)
}
$old=Select-Oracle (Join-Path $root 'task-oracle.before.ps1') 'TYPED_AFTER_NOT_GREEN'
$new=Select-Oracle (Join-Path $root 'task.oracle-fixed.oldtuple.ps1') 'TYPED_AFTER_NOT_GREEN'
$beforeOld=Select-Oracle (Join-Path $root 'task-oracle.before.ps1') 'AUTHENTIC_BEFORE_NOT_RED'
$beforeNew=Select-Oracle (Join-Path $root 'task.oracle-fixed.oldtuple.ps1') 'AUTHENTIC_BEFORE_NOT_RED'
$fixtures=[IO.File]::ReadAllText((Join-Path $root 'fixtures.json'))|ConvertFrom-Json
[IO.Directory]::CreateDirectory((Join-Path $root 'owned-stderr-fixtures'))|Out-Null
function Invoke-OracleCase($Body,$Fixture,[string]$Name,[string]$Case='after'){
 $bytes=[Convert]::FromBase64String($Fixture.stderrBase64)
 $err=Join-Path $root ('owned-stderr-fixtures/'+$Name+'.stderr')
 if(Test-Path -LiteralPath $err){throw 'CONTROL_FIXTURE_EXISTS'}
 [IO.File]::WriteAllBytes($err,$bytes)
 $r=[pscustomobject]@{ExitCode=[int]$Fixture.exitCode};$stdout=[string]$Fixture.stdout;$stderr=[IO.File]::ReadAllText($err);$case=$Case
 $caught=$null
 try{& $Body}catch{$caught=$_.Exception.Message}
 $record=@{name=$Name;case=$case;allowed=($null -eq $caught);error=$caught;stderrBytes=$bytes.Length;rawStderrRetained=([Convert]::ToBase64String([IO.File]::ReadAllBytes($err)) -ceq $Fixture.stderrBase64);nativeActions=0}
 [Console]::Out.WriteLine(($record|ConvertTo-Json -Compress))
 return $record
}
# Same public native sample and exact production predicates: causal old RED.
$sample=$fixtures.cases[0]
$red=Invoke-OracleCase $old $sample 'old-native-progress-red'
if($red.allowed -or $red.error -cne 'TYPED_AFTER_NOT_GREEN'){throw 'OLD_NOT_CAUSAL_RED'}
$passed=0
foreach($fixture in $fixtures.cases){
 $record=Invoke-OracleCase $new $fixture ('fixed-'+$fixture.name)
 if($record.allowed -ne [bool]$fixture.allow -or -not $record.rawStderrRetained){throw ('CONTROL_EXPECTATION_'+$fixture.name)}
 if(-not $record.allowed -and $record.error -cne 'TYPED_AFTER_NOT_GREEN'){throw 'REFUSAL_LABEL'}
 $passed++
}
# Both before predicates are exact; authentic error recognition is unchanged.
$bf=[pscustomobject]@{stderrBase64=$fixtures.beforeActualStderrBase64;exitCode=1;stdout=''}
foreach($item in @(@{body=$beforeOld;name='before-old-recognizes-red'},@{body=$beforeNew;name='before-new-recognizes-red'})){
 $r0=Invoke-OracleCase $item.body $bf $item.name 'before';if(-not $r0.allowed){throw 'BEFORE_RECOGNITION_CHANGED'};$passed++
}
$bad=[pscustomobject]@{stderrBase64=$fixtures.beforeActualStderrBase64;exitCode=0;stdout=''}
$r0=Invoke-OracleCase $beforeNew $bad 'before-zero-exit-refused' 'before';if($r0.allowed -or $r0.error -cne 'AUTHENTIC_BEFORE_NOT_RED'){throw 'BEFORE_ZERO_EXIT'};$passed++
$bad=[pscustomobject]@{stderrBase64='';exitCode=1;stdout=''}
$r0=Invoke-OracleCase $beforeNew $bad 'before-missing-error-refused' 'before';if($r0.allowed -or $r0.error -cne 'AUTHENTIC_BEFORE_NOT_RED'){throw 'BEFORE_MISSING_ERROR'};$passed++
$summary=@{scope='Actual PowerShell AST-selected production oracle and real XmlReader; raw files; external native facilities excluded';oldCausalRed=1;fixedControls=$passed;pass=($passed+1);skip=0;nativeActions=0;psVersion=$PSVersionTable.PSVersion.ToString()}|ConvertTo-Json -Compress
[IO.File]::WriteAllText((Join-Path $root 'control-summary.json'),$summary)
'''
    REFID_CONTROL = r'''$ErrorActionPreference='Stop'
$root=$PSScriptRoot
function Select-After([string]$Path){
 $tokens=$null;$errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseInput([IO.File]::ReadAllText($Path),[ref]$tokens,[ref]$errors)
 if($errors.Count){throw 'CONTROL_PARSE'}
 $nodes=@($ast.FindAll({param($a) $a -is [Management.Automation.Language.IfStatementAst] -and $a.Extent.Text.Contains("throw 'TYPED_AFTER_NOT_GREEN'")},$true))
 if($nodes.Count -ne 1){throw 'ORACLE_COUNT'}
 return [scriptblock]::Create($nodes[0].Extent.Text)
}
$old=Select-After (Join-Path $root 'task.ps1.refid-before')
$new=Select-After (Join-Path $root 'task.ps1')
if($old.ToString() -cne $new.ToString()){throw 'PREDICATE_CHANGED'}
$native=[IO.File]::ReadAllBytes((Join-Path $root 'after.stderr.txt'))
$nativeText=([Text.UTF8Encoding]::new($false,$true)).GetString($native)
$slot='<Obj S="progress" RefId="0">'
if(([regex]::Matches($nativeText,[regex]::Escape($slot))).Count -ne 1){throw 'FIXTURE_SLOT_COUNT'}
$malicious=([Text.UTF8Encoding]::new($false,$true)).GetBytes($nativeText.Replace($slot,'<Obj S="progress" RefId="0&#10;">'))
$xml=[Xml.XmlDocument]::new();$xml.LoadXml((([Text.UTF8Encoding]::new($false,$true)).GetString($malicious)).Substring(9).TrimStart([char[]]"`r`n"))
if($xml.DocumentElement.FirstChild.GetAttribute('RefId') -cne "0`n"){throw 'NO_XML_ATTRIBUTE_LF'}
$fixtureRoot=Join-Path $root 'owned-refid-final-fixtures'
if(Test-Path -LiteralPath $fixtureRoot){throw 'FIXTURE_EXISTS'}
[IO.Directory]::CreateDirectory($fixtureRoot)|Out-Null
function Invoke-Case([string]$Name,[string]$Helper,$Body,[byte[]]$Bytes,[bool]$ExpectedAllow){
 . ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $root $Helper))))
 $err=Join-Path $fixtureRoot ($Name+'.stderr')
 [IO.File]::WriteAllBytes($err,$Bytes)
 $r=[pscustomobject]@{ExitCode=0};$stdout=[IO.File]::ReadAllText((Join-Path $root 'after.stdout.txt'));$stderr=[IO.File]::ReadAllText($err);$case='after'
 $caught=$null
 try{& $Body}catch{$caught=$_.Exception.Message}
 $allowed=($null -eq $caught)
 $retained=([Convert]::ToBase64String([IO.File]::ReadAllBytes($err)) -ceq [Convert]::ToBase64String($Bytes))
 $record=@{name=$Name;allowed=$allowed;error=$caught;stderrBytes=$Bytes.Length;rawStderrRetained=$retained;nativeActions=0}
 [Console]::Out.WriteLine(($record|ConvertTo-Json -Compress))
 if($allowed -ne $ExpectedAllow -or -not $retained){throw 'CONTROL_OUTCOME'}
 if(-not $allowed -and $caught -cne 'TYPED_AFTER_NOT_GREEN'){throw 'FOREIGN_REFUSAL'}
}
# .NET $ accepts a final LF. Real XML decodes &#10; before the authentic predicate.
Invoke-Case 'old-accepts-refid-lf-RED' 'progress-only.ps1.refid-before' $old $malicious $true
Invoke-Case 'fixed-refuses-refid-lf-GREEN' 'progress-only.ps1' $new $malicious $false
Invoke-Case 'fixed-native-progress-compatible-GREEN' 'progress-only.ps1' $new $native $true
$summary=@{scope='Actual PS AST-selected same AFTER predicate, real XmlDocument/XmlReader and owned raw files; no native facilities';pass=3;skip=0;oldActualDefect=1;newRefusal=1;nativeSampleCompatibility=1;psVersion=$PSVersionTable.PSVersion.ToString();nativeActions=0}|ConvertTo-Json -Compress
[IO.File]::WriteAllText((Join-Path $root 'refid-control-summary.json'),$summary)
'''


if __name__ == "__main__":
    unittest.main()

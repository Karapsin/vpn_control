import sys
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


if __name__ == "__main__":
    unittest.main()

param([string]$RepositoryRoot)

$ErrorActionPreference = 'Stop'

# Exercise real PowerShell application discovery and the actual producer. The
# sentinels only write private fixture output; no SDK, installer or helper runs.
if ($env:OS -ne 'Windows_NT') {
    Write-Host '[vpn-control] SKIP: Windows native helper builder fixture'
    return
}
if ($PSVersionTable.PSEdition -ne 'Desktop') { throw 'Run this fixture with Windows PowerShell, as used by the production Gradle task' }
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) { $RepositoryRoot = Join-Path $PSScriptRoot '..' }
$repository = [IO.Path]::GetFullPath($RepositoryRoot)
$taskDirectory = Join-Path ([IO.Path]::GetTempPath()) ('vpn-native-builder-test-' + [guid]::NewGuid().ToString())
$originalPath = $env:PATH
$originalTrace = $env:VPN_CONTROL_NATIVE_BUILDER_TEST_TRACE
[IO.Directory]::CreateDirectory($taskDirectory) | Out-Null
try {
    $fixture = Join-Path $taskDirectory 'repository with spaces'
    $inputs = @(
        'scripts\prepare_windows_native_helpers.ps1',
        'scripts\windows_native_helpers.py',
        'desktopApp\native\windows\global.json',
        'desktopApp\native\windows\Directory.Build.props',
        'desktopApp\native\windows\toolchain.lock.json',
        'desktopApp\native\windows\import-policy.json',
        'desktopApp\native\windows\InstallHelper\InstallHelper.csproj',
        'desktopApp\native\windows\InstallHelper\loader.manifest',
        'desktopApp\src\main\resources\windows-install-native.cs',
        'desktopApp\src\main\resources\windows-install-helper-protocol.cs',
        'desktopApp\src\main\resources\windows-install-helper-roles.cs',
        'desktopApp\src\main\resources\windows-install-helper.cs'
    )
    foreach ($relative in $inputs) {
        $source = Join-Path $repository $relative
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Fixture input missing: $relative" }
        $destination = Join-Path $fixture $relative
        [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination)) | Out-Null
        [IO.File]::Copy($source, $destination, $false)
    }
    # Loading the exact copied body avoids changing execution policy in a fixture.
    $producer = [scriptblock]::Create([IO.File]::ReadAllText((Join-Path $fixture 'scripts\prepare_windows_native_helpers.ps1')))
    $first = Join-Path $taskDirectory 'first application'
    $second = Join-Path $taskDirectory 'second application'
    $sourceCode = @'
using System;
using System.IO;
public static class Sentinel_LABEL {
    public static int Main(string[] arguments) {
        if (arguments.Length < 4 || arguments[1] != "sources" || arguments[2] != "--output") return 81;
        string trace = Environment.GetEnvironmentVariable("VPN_CONTROL_NATIVE_BUILDER_TEST_TRACE");
        if (String.IsNullOrEmpty(trace)) return 82;
        File.AppendAllText(trace, "LABEL\n");
        File.WriteAllText(arguments[3], "LABEL");
        return 0;
    }
}
'@
    foreach ($entry in @(@{ directory = $first; label = 'FIRST' }, @{ directory = $second; label = 'SECOND' })) {
        [IO.Directory]::CreateDirectory($entry.directory) | Out-Null
        $executable = Join-Path $entry.directory 'fixture-python.exe'
        Add-Type -TypeDefinition ($sourceCode.Replace('LABEL', $entry.label)) -Language CSharp `
            -OutputAssembly $executable -OutputType ConsoleApplication
        [IO.File]::Copy($executable, (Join-Path $entry.directory 'fixture-dotnet.exe'), $false)
    }

    function Invoke-ProducerCase([string]$Name, [string]$PythonName, [string]$DotnetName, [string]$Expected) {
        $output = Join-Path $taskDirectory $Name
        $trace = Join-Path $taskDirectory ($Name + '.trace')
        $env:VPN_CONTROL_NATIVE_BUILDER_TEST_TRACE = $trace
        & $producer -RepositoryRoot $fixture -Dotnet $DotnetName -Python $PythonName -OutputRoot $output -ValidateOnly
        $calls = @([IO.File]::ReadAllLines($trace))
        if ($calls.Count -ne 1 -or $calls[0] -cne $Expected) { throw 'Producer did not run exactly the first requested application' }
        if ([IO.File]::ReadAllText((Join-Path $output 'native-helper-sources.json')) -cne $Expected) {
            throw 'Producer did not retain the first application output'
        }
        Write-Host ('PASS: ' + $Name)
    }

    $env:PATH = $first + [IO.Path]::PathSeparator + $second + [IO.Path]::PathSeparator + $originalPath
    Invoke-ProducerCase 'explicit-path-positive-control' (Join-Path $first 'fixture-python.exe') `
        (Join-Path $first 'fixture-dotnet.exe') 'FIRST'
    foreach ($application in @('fixture-python.exe', 'fixture-dotnet.exe')) {
        $candidates = @(Get-Command -Name $application -CommandType Application -ErrorAction Stop)
        if ($candidates.Count -ne 2 -or $candidates[0].Source -cne (Join-Path $first $application) -or
            $candidates[1].Source -cne (Join-Path $second $application)) { throw 'Duplicate application discovery was not exercised' }
    }
    Invoke-ProducerCase 'duplicate-path-selects-first' 'fixture-python.exe' 'fixture-dotnet.exe' 'FIRST'
    $env:PATH = $second + [IO.Path]::PathSeparator + $first + [IO.Path]::PathSeparator + $originalPath
    Invoke-ProducerCase 'reversed-path-selects-new-first' 'fixture-python.exe' 'fixture-dotnet.exe' 'SECOND'
    Write-Host '[vpn-control] Windows native helper builder regressions passed: 3'
} finally {
    $env:PATH = $originalPath
    $env:VPN_CONTROL_NATIVE_BUILDER_TEST_TRACE = $originalTrace
    Remove-Item -LiteralPath $taskDirectory -Recurse -Force
}

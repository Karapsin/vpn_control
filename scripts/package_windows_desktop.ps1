param(
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot
$OutputRoot = Join-Path $RepoRoot "desktopApp\build\compose\binaries\main"

function Invoke-CheckedNative {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

Write-Host "[vpn-control] checking Java runtime"
java -version

.\scripts\prepare_sing_box_desktop_runtime.ps1

if (Test-Path $OutputRoot) {
    Write-Host "[vpn-control] cleaning stale package output: $OutputRoot"
    Remove-Item $OutputRoot -Recurse -Force
}

Write-Host "[vpn-control] compiling desktop app"
Invoke-CheckedNative ".\gradlew.bat" ":desktopApp:compileKotlin"

if (-not $SkipTests) {
    Write-Host "[vpn-control] running desktop tests"
    Invoke-CheckedNative ".\gradlew.bat" ":desktopApp:test"
}

Write-Host "[vpn-control] building Windows desktop packages"
Invoke-CheckedNative ".\gradlew.bat" ":desktopApp:packageDistributionForCurrentOS"

Write-Host "[vpn-control] packages written under: $OutputRoot"

$Packages = Get-ChildItem -Path $OutputRoot -Recurse -Include *.exe,*.msi
if (-not $Packages) {
    throw "No Windows installer artifacts were produced under $OutputRoot"
}

$MsiPackage = $Packages |
    Where-Object { $_.Extension -eq ".msi" } |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1
if (-not $MsiPackage) {
    throw "No MSI artifact was produced under $OutputRoot"
}

$ValidationRoot = Join-Path $RepoRoot "desktopApp\build\compose\validation\msi"
if (Test-Path $ValidationRoot) {
    Remove-Item $ValidationRoot -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $ValidationRoot | Out-Null

Write-Host "[vpn-control] validating MSI payload: $($MsiPackage.FullName)"
$MsiArgs = @(
    "/a",
    $MsiPackage.FullName,
    "/qn",
    "TARGETDIR=$ValidationRoot"
)
$MsiProcess = Start-Process -FilePath "msiexec.exe" -ArgumentList $MsiArgs -Wait -PassThru
if ($MsiProcess.ExitCode -ne 0) {
    throw "MSI administrative extraction failed with exit code $($MsiProcess.ExitCode)"
}

$Launcher = Get-ChildItem -Path $ValidationRoot -Recurse -Filter "vpn-control.exe" |
    Select-Object -First 1
if (-not $Launcher) {
    throw "MSI payload is missing vpn-control.exe launcher"
}

$RuntimeRelease = Get-ChildItem -Path $ValidationRoot -Recurse -Filter "release" |
    Where-Object { $_.FullName -match "\\runtime\\release$" } |
    Select-Object -First 1
if (-not $RuntimeRelease) {
    throw "MSI payload is missing bundled runtime\release marker"
}

$RuntimeModules = Get-ChildItem -Path $ValidationRoot -Recurse -Filter "modules" |
    Where-Object { $_.FullName -match "\\runtime\\lib\\modules$" } |
    Select-Object -First 1
if (-not $RuntimeModules) {
    throw "MSI payload is missing bundled runtime\lib\modules image"
}

$AppJars = Get-ChildItem -Path $ValidationRoot -Recurse -Filter "*.jar"
if (-not $AppJars) {
    throw "MSI payload is missing application jars"
}

Write-Host "[vpn-control] verified MSI payload:"
Write-Host " - launcher: $($Launcher.FullName)"
Write-Host " - runtime:  $($RuntimeRelease.DirectoryName)"
Write-Host " - jars:     $($AppJars.Count)"

$Packages | ForEach-Object {
    $Hash = Get-FileHash -Algorithm SHA256 -Path $_.FullName
    Write-Host " - $($_.FullName)"
    Write-Host "   sha256: $($Hash.Hash.ToLowerInvariant())"
}

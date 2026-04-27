param(
    [switch]$SkipTests,
    [switch]$SkipPackageRegressionTests,
    [string]$DistDir = "dist\windows"
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot
$OutputRoot = Join-Path $RepoRoot "desktopApp\build\compose\binaries\main"
$DistRoot = if ([System.IO.Path]::IsPathRooted($DistDir)) {
    $DistDir
} else {
    Join-Path $RepoRoot $DistDir
}

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
$PreviousErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
    java -version 2>&1 | ForEach-Object { Write-Host $_.ToString() }
    $JavaExitCode = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $PreviousErrorActionPreference
}
if ($JavaExitCode -ne 0) {
    throw "java -version failed with exit code $JavaExitCode"
}

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

if (-not $SkipPackageRegressionTests) {
    Write-Host "[vpn-control] running Windows package regression tests"
    & ".\scripts\test_windows_desktop_package.ps1" -PackageRoot $OutputRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Windows package regression tests failed with exit code $LASTEXITCODE"
    }
} else {
    Write-Host "[vpn-control] skipping Windows package regression tests"
}

Write-Host "[vpn-control] copying local Windows installers to: $DistRoot"
New-Item -ItemType Directory -Force -Path $DistRoot | Out-Null
Get-ChildItem -Path $DistRoot -File |
    Where-Object { $_.Extension -in @(".exe", ".msi") -or $_.Name -eq "SHA256SUMS.txt" } |
    Remove-Item -Force

$CopiedPackages = @()
$Packages | Sort-Object Name | ForEach-Object {
    $Target = Join-Path $DistRoot $_.Name
    Copy-Item -Path $_.FullName -Destination $Target -Force
    $CopiedPackages += Get-Item $Target
}

$ChecksumFile = Join-Path $DistRoot "SHA256SUMS.txt"
if (Test-Path $ChecksumFile) {
    Remove-Item $ChecksumFile -Force
}
$CopiedPackages | ForEach-Object {
    $Hash = Get-FileHash -Algorithm SHA256 -Path $_.FullName
    "$($Hash.Hash.ToLowerInvariant())  $($_.Name)" | Out-File -FilePath $ChecksumFile -Encoding ascii -Append
}

Write-Host "[vpn-control] local Windows installers:"
$CopiedPackages | ForEach-Object {
    Write-Host " - $($_.FullName)"
}
Write-Host " - $ChecksumFile"

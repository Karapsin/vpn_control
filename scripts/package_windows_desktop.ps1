param(
    [switch]$SkipTests,
    [switch]$SkipPackageRegressionTests,
    [switch]$SkipInstalledPackageRegressionTests,
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

function Test-GeneratedTrackedPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $Normalized = $Path -replace "\\", "/"
    return (
        $Normalized -like "build/*" -or
        $Normalized -like "app/build/*" -or
        $Normalized -like "shared/*/build/*" -or
        $Normalized -like "desktopApp/build/*" -or
        $Normalized -like "desktopApp/src/main/resources/bin/*" -or
        $Normalized -like "dist/*" -or
        $Normalized -like ".runtime/*"
    )
}

function Assert-ReleaseHygiene {
    $Tracked = & git ls-files
    if ($LASTEXITCODE -ne 0) {
        throw "git ls-files failed with exit code $LASTEXITCODE"
    }
    $BadPaths = @($Tracked | Where-Object { Test-GeneratedTrackedPath $_ })
    if ($BadPaths.Count -gt 0) {
        $List = ($BadPaths | ForEach-Object { " - $_" }) -join [Environment]::NewLine
        throw "Generated release/runtime artifacts are tracked by Git. Remove these files from the index before packaging:$([Environment]::NewLine)$List"
    }
    & bash scripts/check_docs_hygiene.sh
    if ($LASTEXITCODE -ne 0) {
        throw "scripts/check_docs_hygiene.sh failed with exit code $LASTEXITCODE"
    }
    Write-Host "[vpn-control] release hygiene passed"
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

Assert-ReleaseHygiene

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

if (-not $SkipInstalledPackageRegressionTests) {
    Write-Host "[vpn-control] running installed Windows package regression tests"
    & ".\scripts\test_windows_installed_desktop.ps1" -PackageRoot $OutputRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Installed Windows package regression tests failed with exit code $LASTEXITCODE"
    }
} else {
    Write-Host "[vpn-control] skipping installed Windows package regression tests"
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

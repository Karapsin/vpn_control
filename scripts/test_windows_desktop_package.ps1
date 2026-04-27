param(
    [Parameter(Mandatory = $true)]
    [string]$PackageRoot,
    [string]$ValidationRoot
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

if (-not (Test-Path $PackageRoot)) {
    throw "Package root does not exist: $PackageRoot"
}

$ResolvedPackageRoot = (Resolve-Path $PackageRoot).Path
if (-not $ValidationRoot) {
    $ValidationRoot = Join-Path $RepoRoot "desktopApp\build\compose\validation\windows-msi"
}

function Assert-FileExists {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $true)]
        $File
    )

    if (-not $File) {
        throw $Message
    }
    if (-not (Test-Path $File.FullName)) {
        throw "$Message at $($File.FullName)"
    }
    if ($File.Length -le 0) {
        throw "$Message is empty at $($File.FullName)"
    }
}

Write-Host "[vpn-control] package regression root: $ResolvedPackageRoot"

$Packages = Get-ChildItem -Path $ResolvedPackageRoot -Recurse -File -Include *.exe,*.msi
if (-not $Packages) {
    throw "No Windows installer artifacts were produced under $ResolvedPackageRoot"
}

$ExePackage = $Packages |
    Where-Object { $_.Extension -eq ".exe" } |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1
Assert-FileExists "No EXE artifact was produced" $ExePackage

$MsiPackage = $Packages |
    Where-Object { $_.Extension -eq ".msi" } |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1
Assert-FileExists "No MSI artifact was produced" $MsiPackage

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

$Launcher = Get-ChildItem -Path $ValidationRoot -Recurse -File -Filter "vpn-control.exe" |
    Sort-Object Length -Descending |
    Select-Object -First 1
Assert-FileExists "MSI payload is missing vpn-control.exe launcher" $Launcher

$RuntimeRelease = Get-ChildItem -Path $ValidationRoot -Recurse -File -Filter "release" |
    Where-Object { $_.FullName -match "\\runtime\\release$" } |
    Select-Object -First 1
Assert-FileExists "MSI payload is missing bundled runtime\release marker" $RuntimeRelease

$RuntimeModules = Get-ChildItem -Path $ValidationRoot -Recurse -File -Filter "modules" |
    Where-Object { $_.FullName -match "\\runtime\\lib\\modules$" } |
    Select-Object -First 1
Assert-FileExists "MSI payload is missing bundled runtime\lib\modules image" $RuntimeModules

$AppJars = Get-ChildItem -Path $ValidationRoot -Recurse -File -Filter "*.jar"
if (-not $AppJars) {
    throw "MSI payload is missing application jars"
}

$SmokeStateDir = Join-Path $ValidationRoot "smoke-state"
if (Test-Path $SmokeStateDir) {
    Remove-Item $SmokeStateDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $SmokeStateDir | Out-Null

Write-Host "[vpn-control] running extracted app smoke test"
$SmokeProcess = Start-Process `
    -FilePath $Launcher.FullName `
    -ArgumentList @("--smoke-test", "--smoke-test-state-dir", $SmokeStateDir) `
    -PassThru `
    -WindowStyle Hidden
try {
    $Completed = $SmokeProcess.WaitForExit(60000)
    if (-not $Completed) {
        Stop-Process -Id $SmokeProcess.Id -Force -ErrorAction SilentlyContinue
        throw "Extracted app smoke test timed out"
    }
    $SmokeProcess.Refresh()
    if ($SmokeProcess.ExitCode -ne 0) {
        throw "Extracted app smoke test failed with exit code $($SmokeProcess.ExitCode)"
    }
} finally {
    Stop-Process -Id $SmokeProcess.Id -Force -ErrorAction SilentlyContinue
}

$SmokeWorkspace = Join-Path $SmokeStateDir "workspace.json"
if (-not (Test-Path $SmokeWorkspace)) {
    throw "Extracted app smoke test did not write workspace.json"
}

$SmokeTools = Join-Path $SmokeStateDir "runtime\tools"
if (-not (Test-Path $SmokeTools)) {
    throw "Extracted app smoke test did not extract bundled sing-box tools"
}

Write-Host "[vpn-control] verified Windows package regression checks:"
Write-Host " - exe:      $($ExePackage.FullName)"
Write-Host " - msi:      $($MsiPackage.FullName)"
Write-Host " - launcher: $($Launcher.FullName)"
Write-Host " - runtime:  $($RuntimeRelease.DirectoryName)"
Write-Host " - jars:     $($AppJars.Count)"
Write-Host " - smoke:    extracted app launcher"

@($ExePackage, $MsiPackage) | ForEach-Object {
    $Hash = Get-FileHash -Algorithm SHA256 -Path $_.FullName
    Write-Host " - sha256 $($_.Name): $($Hash.Hash.ToLowerInvariant())"
}

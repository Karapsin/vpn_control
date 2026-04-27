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
    $ValidationRoot = Join-Path $RepoRoot "desktopApp\build\compose\validation\windows-installed"
}

function Assert-FileExists {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        throw "$Message at $Path"
    }
    $Item = Get-Item $Path
    if ($Item.Length -le 0) {
        throw "$Message is empty at $Path"
    }
}

function Find-InstalledLauncher {
    param([Parameter(Mandatory = $true)][datetime]$InstalledAfter)

    $Candidates = @(
        (Join-Path $env:LOCALAPPDATA "Programs\vpn-control\vpn-control.exe"),
        (Join-Path $env:LOCALAPPDATA "vpn-control\vpn-control.exe"),
        (Join-Path $env:ProgramFiles "vpn-control\vpn-control.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "vpn-control\vpn-control.exe")
    ) | Where-Object { $_ -and (Test-Path $_) }

    if ($Candidates) {
        return ($Candidates | Sort-Object { (Get-Item $_).LastWriteTimeUtc } -Descending | Select-Object -First 1)
    }

    $Roots = @(
        $env:LOCALAPPDATA,
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)}
    ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

    foreach ($Root in $Roots) {
        $Found = Get-ChildItem -Path $Root -Directory -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -match "vpn-control|VPN Control" -or $_.LastWriteTimeUtc -ge $InstalledAfter.AddMinutes(-2)
            } |
            ForEach-Object {
                Get-ChildItem -Path $_.FullName -Recurse -File -Filter "vpn-control.exe" -ErrorAction SilentlyContinue
            } |
            Sort-Object LastWriteTimeUtc -Descending |
            Select-Object -First 1
        if ($Found) {
            return $Found.FullName
        }
    }

    return $null
}

$MsiPackage = Get-ChildItem -Path $ResolvedPackageRoot -Recurse -File -Include *.msi |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1
if (-not $MsiPackage) {
    throw "No MSI artifact was produced under $ResolvedPackageRoot"
}

if (Test-Path $ValidationRoot) {
    Remove-Item $ValidationRoot -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $ValidationRoot | Out-Null

$InstallLog = Join-Path $ValidationRoot "msi-install.log"
$UninstallLog = Join-Path $ValidationRoot "msi-uninstall.log"
$SmokeStateDir = Join-Path $ValidationRoot "smoke-state"
$InstalledAt = Get-Date
$Launcher = $null

Write-Host "[vpn-control] installing MSI for installed-app regression: $($MsiPackage.FullName)"
$InstallProcess = Start-Process -FilePath "msiexec.exe" -ArgumentList @(
    "/i",
    $MsiPackage.FullName,
    "/qn",
    "/norestart",
    "/L*v",
    $InstallLog
) -Wait -PassThru
if ($InstallProcess.ExitCode -ne 0) {
    throw "MSI install failed with exit code $($InstallProcess.ExitCode). Log: $InstallLog"
}

try {
    $Launcher = Find-InstalledLauncher -InstalledAfter $InstalledAt
    if (-not $Launcher) {
        throw "Installed vpn-control.exe launcher was not found"
    }
    Assert-FileExists "Installed vpn-control.exe launcher is missing" $Launcher

    New-Item -ItemType Directory -Force -Path $SmokeStateDir | Out-Null
    Write-Host "[vpn-control] running installed app smoke test: $Launcher"
    $SmokeProcess = Start-Process `
        -FilePath $Launcher `
        -ArgumentList @("--smoke-test", "--smoke-test-state-dir", $SmokeStateDir) `
        -PassThru `
        -WindowStyle Hidden
    try {
        $Completed = $SmokeProcess.WaitForExit(60000)
        if (-not $Completed) {
            Stop-Process -Id $SmokeProcess.Id -Force -ErrorAction SilentlyContinue
            throw "Installed app smoke test timed out"
        }
        $SmokeProcess.Refresh()
        if ($SmokeProcess.ExitCode -ne 0) {
            throw "Installed app smoke test failed with exit code $($SmokeProcess.ExitCode)"
        }
    } finally {
        Stop-Process -Id $SmokeProcess.Id -Force -ErrorAction SilentlyContinue
    }

    $SmokeWorkspace = Join-Path $SmokeStateDir "workspace.json"
    if (-not (Test-Path $SmokeWorkspace)) {
        throw "Installed app smoke test did not write workspace.json"
    }

    $SmokeTools = Join-Path $SmokeStateDir "runtime\tools"
    if (-not (Test-Path $SmokeTools)) {
        throw "Installed app smoke test did not extract bundled sing-box tools"
    }

    Write-Host "[vpn-control] verified installed Windows package regression checks:"
    Write-Host " - msi:      $($MsiPackage.FullName)"
    Write-Host " - launcher: $Launcher"
    Write-Host " - smoke:    installed app launcher"
} finally {
    Write-Host "[vpn-control] uninstalling MSI after installed-app regression"
    $UninstallProcess = Start-Process -FilePath "msiexec.exe" -ArgumentList @(
        "/x",
        $MsiPackage.FullName,
        "/qn",
        "/norestart",
        "/L*v",
        $UninstallLog
    ) -Wait -PassThru
    if ($UninstallProcess.ExitCode -ne 0) {
        throw "MSI uninstall failed with exit code $($UninstallProcess.ExitCode). Log: $UninstallLog"
    }
}

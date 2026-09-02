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

function Invoke-InstalledSmoke {
    param(
        [Parameter(Mandatory = $true)][string]$Launcher,
        [Parameter(Mandatory = $true)][string]$StateDirectory,
        [Parameter(Mandatory = $true)][string]$Label
    )

    New-Item -ItemType Directory -Force -Path $StateDirectory | Out-Null
    Write-Host "[vpn-control] running $Label smoke test: $Launcher"
    $Process = Start-Process `
        -FilePath $Launcher `
        -ArgumentList @("--smoke-test", "--smoke-test-state-dir", $StateDirectory) `
        -PassThru `
        -WindowStyle Hidden
    try {
        $Completed = $Process.WaitForExit(60000)
        if (-not $Completed) {
            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
            throw "$Label smoke test timed out"
        }
        $Process.Refresh()
        if ($Process.ExitCode -ne 0) {
            throw "$Label smoke test failed with exit code $($Process.ExitCode)"
        }
    } finally {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
    }
    Assert-FileExists "$Label smoke test did not write workspace.json" (Join-Path $StateDirectory "workspace.json")
    Assert-FileExists "$Label smoke test did not extract bundled sing-box" (Join-Path $StateDirectory "runtime\tools\sing-box.exe")
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
$RelaunchStateDir = Join-Path $ValidationRoot "relaunch-state"
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

    Invoke-InstalledSmoke -Launcher $Launcher -StateDirectory $SmokeStateDir -Label "installed app"
    Invoke-InstalledSmoke -Launcher $Launcher -StateDirectory $RelaunchStateDir -Label "installed app relaunch"

    Write-Host "[vpn-control] verified installed Windows package regression checks:"
    Write-Host " - msi:      $($MsiPackage.FullName)"
    Write-Host " - launcher: $Launcher"
    Write-Host " - smoke:    installed app launcher and clean relaunch"
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

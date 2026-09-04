param(
    [ValidateSet("windows")]
    [string]$Platform = "windows",
    [Parameter(Mandatory = $true)]
    [string]$Output,
    [string]$Scenes = ""
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$OutputPath = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Output))
New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null

function Hide-HostConsoleWindows {
    # GitHub's hosted Windows desktop keeps the runner's console in the
    # foreground. Native screenshots must contain the app/OS surface under
    # test, never the runner's own logs.
    if ($env:OS -ne "Windows_NT") { return }
    if (-not ("VpnControlVisualNativeWindow" -as [type])) {
        Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class VpnControlVisualNativeWindow {
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr handle, int command);
}
"@
    }
    $consoleProcesses = @("WindowsTerminal", "OpenConsole", "conhost", "cmd", "powershell", "pwsh")
    Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.MainWindowHandle -ne 0 -and $consoleProcesses -contains $_.ProcessName } |
        ForEach-Object { [VpnControlVisualNativeWindow]::ShowWindow($_.MainWindowHandle, 6) | Out-Null }
}

function Notify-SystemClockChanged {
    if ($env:OS -ne "Windows_NT") { return }
    if (-not ("VpnControlVisualClock" -as [type])) {
        Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class VpnControlVisualClock {
    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr SendMessageTimeout(
        IntPtr window, uint message, UIntPtr wParam, IntPtr lParam,
        uint flags, uint timeout, out UIntPtr result);
}

function Dismiss-HostedVisualResidue {
    if ($env:VPN_CONTROL_VISUAL_PROVIDER -ne "hosted") { return }
    # A recycled hosted image can surface Windows' paging-file warning before the
    # fixture starts. It is unrelated to VPN Control and must not cover evidence.
    Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.MainWindowHandle -ne 0 -and $_.MainWindowTitle -like "System Properties*" } |
        ForEach-Object { $_.CloseMainWindow() | Out-Null }
    Start-Sleep -Seconds 2
}
"@
    }
    $result = [UIntPtr]::Zero
    # WM_TIMECHANGE tells Explorer and native dialogs to redraw their frozen fixture time.
    [VpnControlVisualClock]::SendMessageTimeout(
        [IntPtr]0xffff, 0x001e, [UIntPtr]::Zero, [IntPtr]::Zero, 0x0002, 5000, [ref]$result
    ) | Out-Null
    Start-Sleep -Seconds 2
}

Hide-HostConsoleWindows
$Manifest = Join-Path $RepoRoot "visual-tests\scenes.json"
$Selector = Join-Path $RepoRoot "scripts\select_visual_scenes.py"
$AppScenes = (& python $Selector --manifest $Manifest --platform $Platform --kind app --requested $Scenes).Trim()
if ($LASTEXITCODE -ne 0) { throw "Could not select app-owned visual scenes" }
$NativeScenes = (& python $Selector --manifest $Manifest --platform $Platform --kind native --requested $Scenes).Trim()
if ($LASTEXITCODE -ne 0) { throw "Could not select native visual scenes" }
$env:VPN_CONTROL_VISUAL_PLATFORM = $Platform
$env:VPN_CONTROL_VISUAL_MANIFEST = $Manifest
$env:VPN_CONTROL_VISUAL_OUTPUT = $OutputPath
$env:VPN_CONTROL_VISUAL_SCENES = $AppScenes
if ($AppScenes) {
    & (Join-Path $RepoRoot "gradlew.bat") :desktopApp:visualCapture
    if ($LASTEXITCODE -ne 0) { throw "Desktop app-owned visual capture task failed" }
}

if ($NativeScenes) {
    if ($env:VPN_CONTROL_VISUAL_PROVIDER -ne "hosted" -and $env:VPN_CONTROL_VISUAL_ISOLATED -ne "1") {
        throw "Native desktop capture requires VPN_CONTROL_VISUAL_ISOLATED=1 or an ephemeral hosted runner"
    }
    $VisualPackage = ""
    if (",$NativeScenes," -match ",windows-(msi|update-installer),") {
        & (Join-Path $RepoRoot "scripts\package_windows_desktop.ps1") `
            -SkipTests -SkipPackageRegressionTests -SkipInstalledPackageRegressionTests `
            -DistDir "dist\visual-windows"
        if ($LASTEXITCODE -ne 0) { throw "Could not build the Windows visual installer" }
        $VisualPackage = Get-ChildItem -Path (Join-Path $RepoRoot "dist\visual-windows") -Filter *.msi |
            Sort-Object FullName | Select-Object -First 1 -ExpandProperty FullName
        if (-not $VisualPackage) { throw "Windows visual MSI was not produced" }
    }
    $env:VPN_CONTROL_VISUAL_NATIVE_SCENES = $NativeScenes
    $env:VPN_CONTROL_VISUAL_PACKAGE = $VisualPackage
    Hide-HostConsoleWindows
    Dismiss-HostedVisualResidue
    $OriginalDate = Get-Date
    try {
        Set-Date -Date "2026-09-03T12:00:00" | Out-Null
        Notify-SystemClockChanged
        & (Join-Path $RepoRoot "gradlew.bat") :desktopApp:nativeVisualCapture
        if ($LASTEXITCODE -ne 0) { throw "Desktop native visual capture task failed" }
    } finally {
        Set-Date -Date $OriginalDate | Out-Null
        Notify-SystemClockChanged
    }
}

$Driver = if ($IsWindows) { "cmd.exe /c exit 0" } else { "/usr/bin/true" }
$Validation = @(
    (Join-Path $RepoRoot "scripts\visual_platform.py"),
    "capture-local", "--platform", $Platform, "--driver", $Driver, "--output", $OutputPath
)
foreach ($Scene in ($Scenes -split ',' | Where-Object { $_ })) {
    $Validation += @("--scene", $Scene)
}
python @Validation | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Windows visual capture is incomplete" }

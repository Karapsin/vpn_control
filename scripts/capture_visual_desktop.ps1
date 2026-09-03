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
    & (Join-Path $RepoRoot "gradlew.bat") :desktopApp:nativeVisualCapture
    if ($LASTEXITCODE -ne 0) { throw "Desktop native visual capture task failed" }
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

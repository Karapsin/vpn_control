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
$env:VPN_CONTROL_VISUAL_PLATFORM = $Platform
$env:VPN_CONTROL_VISUAL_MANIFEST = Join-Path $RepoRoot "visual-tests\scenes.json"
$env:VPN_CONTROL_VISUAL_OUTPUT = $OutputPath
$env:VPN_CONTROL_VISUAL_SCENES = $Scenes
& (Join-Path $RepoRoot "gradlew.bat") :desktopApp:visualCapture
if ($LASTEXITCODE -ne 0) { throw "Desktop visual capture task failed" }

$Driver = if ($IsWindows) { "C:\Windows\System32\cmd.exe /c exit 0" } else { "/usr/bin/true" }
$Validation = @(
    (Join-Path $RepoRoot "scripts\visual_platform.py"),
    "capture-local", "--platform", $Platform, "--driver", $Driver, "--output", $OutputPath
)
foreach ($Scene in ($Scenes -split ',' | Where-Object { $_ })) {
    $Validation += @("--scene", $Scene)
}
python @Validation | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Windows visual capture is incomplete" }

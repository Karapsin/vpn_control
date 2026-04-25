param(
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = $env:SING_BOX_VERSION
}
if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = "1.13.4"
}

$RepoRoot = Split-Path -Parent $PSScriptRoot
$CacheDir = Join-Path $RepoRoot ".runtime\sing-box"
$TargetDir = Join-Path $RepoRoot "desktopApp\src\main\resources\bin\windows-amd64"
$Archive = Join-Path $CacheDir "sing-box-$Version-windows-amd64.zip"
$ExtractDir = Join-Path $CacheDir "windows-amd64"
$Url = "https://github.com/SagerNet/sing-box/releases/download/v$Version/sing-box-$Version-windows-amd64.zip"

New-Item -ItemType Directory -Force -Path $CacheDir, $TargetDir | Out-Null

if (-not (Test-Path $Archive)) {
    Write-Host "[vpn-control] downloading sing-box $Version for windows-amd64"
    Invoke-WebRequest -Uri $Url -OutFile $Archive
}

if (Test-Path $ExtractDir) {
    Remove-Item $ExtractDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $ExtractDir | Out-Null
Expand-Archive -Path $Archive -DestinationPath $ExtractDir -Force

$Binary = Get-ChildItem -Path $ExtractDir -Recurse -Filter "sing-box.exe" |
    Select-Object -First 1
if (-not $Binary) {
    throw "sing-box.exe was not found in $Archive"
}

Copy-Item -Path $Binary.FullName -Destination (Join-Path $TargetDir "sing-box.exe") -Force
Write-Host "[vpn-control] bundled windows sing-box at $(Join-Path $TargetDir "sing-box.exe")"

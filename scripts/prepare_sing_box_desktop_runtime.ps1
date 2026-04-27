param(
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = $env:SING_BOX_VERSION
}
if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = "1.13.4"
}

$RepoRoot = Split-Path -Parent $PSScriptRoot
$CacheDir = if ([string]::IsNullOrWhiteSpace($env:VPN_CONTROL_SING_BOX_CACHE_DIR)) {
    Join-Path $RepoRoot ".runtime\sing-box"
} else {
    $env:VPN_CONTROL_SING_BOX_CACHE_DIR
}
$TargetDir = Join-Path $RepoRoot "desktopApp\src\main\resources\bin\windows-amd64"
$Archive = Join-Path $CacheDir "sing-box-$Version-windows-amd64.zip"
$ExtractDir = Join-Path $CacheDir "windows-amd64"
$Url = "https://github.com/SagerNet/sing-box/releases/download/v$Version/sing-box-$Version-windows-amd64.zip"

New-Item -ItemType Directory -Force -Path $CacheDir, $TargetDir | Out-Null

if (-not (Test-Path $Archive)) {
    Write-Host "[vpn-control] downloading sing-box $Version for windows-amd64"
    $LastError = $null
    for ($Attempt = 1; $Attempt -le 3; $Attempt++) {
        try {
            Invoke-WebRequest -Uri $Url -OutFile $Archive -UseBasicParsing
            $LastError = $null
            break
        } catch {
            $LastError = $_
            if (Test-Path $Archive) {
                Remove-Item $Archive -Force -ErrorAction SilentlyContinue
            }
            if ($Attempt -lt 3) {
                Write-Host "[vpn-control] sing-box download attempt $Attempt failed; retrying"
                Start-Sleep -Seconds (2 * $Attempt)
            }
        }
    }
    if ($LastError) {
        throw $LastError
    }
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

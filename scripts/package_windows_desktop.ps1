param(
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

Write-Host "[vpn-control] checking Java runtime"
java -version

.\scripts\prepare_sing_box_desktop_runtime.ps1

Write-Host "[vpn-control] compiling desktop app"
.\gradlew.bat :desktopApp:compileKotlin

if (-not $SkipTests) {
    Write-Host "[vpn-control] running desktop tests"
    .\gradlew.bat :desktopApp:test
}

Write-Host "[vpn-control] building Windows desktop packages"
.\gradlew.bat :desktopApp:packageDistributionForCurrentOS

$OutputRoot = Join-Path $RepoRoot "desktopApp\build\compose\binaries\main"
Write-Host "[vpn-control] packages written under: $OutputRoot"
$Packages = Get-ChildItem -Path $OutputRoot -Recurse -Include *.exe,*.msi
if (-not $Packages) {
    throw "No Windows installer artifacts were produced under $OutputRoot"
}
$Packages | ForEach-Object {
    Write-Host " - $($_.FullName)"
}

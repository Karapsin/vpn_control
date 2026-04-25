param(
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot
$OutputRoot = Join-Path $RepoRoot "desktopApp\build\compose\binaries\main"

Write-Host "[vpn-control] checking Java runtime"
java -version

.\scripts\prepare_sing_box_desktop_runtime.ps1

if (Test-Path $OutputRoot) {
    Write-Host "[vpn-control] cleaning stale package output: $OutputRoot"
    Remove-Item $OutputRoot -Recurse -Force
}

Write-Host "[vpn-control] compiling desktop app"
.\gradlew.bat :desktopApp:compileKotlin

if (-not $SkipTests) {
    Write-Host "[vpn-control] running desktop tests"
    .\gradlew.bat :desktopApp:test
}

Write-Host "[vpn-control] building Windows desktop packages"
.\gradlew.bat :desktopApp:packageDistributionForCurrentOS

Write-Host "[vpn-control] packages written under: $OutputRoot"

$AppImageRoot = Join-Path $OutputRoot "app"
if (-not (Test-Path $AppImageRoot)) {
    throw "Windows app image was not produced under $AppImageRoot"
}

$Launcher = Get-ChildItem -Path $AppImageRoot -Recurse -Filter "vpn-control.exe" |
    Select-Object -First 1
if (-not $Launcher) {
    throw "Windows app image is missing vpn-control.exe launcher under $AppImageRoot"
}

$RuntimeJava = Get-ChildItem -Path $AppImageRoot -Recurse -Filter "java.exe" |
    Where-Object { $_.FullName -match "\\runtime\\bin\\java\.exe$" } |
    Select-Object -First 1
if (-not $RuntimeJava) {
    throw "Windows app image is missing bundled runtime\bin\java.exe under $AppImageRoot"
}

$AppJars = Get-ChildItem -Path $AppImageRoot -Recurse -Filter "*.jar"
if (-not $AppJars) {
    throw "Windows app image is missing application jars under $AppImageRoot"
}

Write-Host "[vpn-control] verified app image:"
Write-Host " - launcher: $($Launcher.FullName)"
Write-Host " - runtime:  $($RuntimeJava.FullName)"
Write-Host " - jars:     $($AppJars.Count)"

$Packages = Get-ChildItem -Path $OutputRoot -Recurse -Include *.exe,*.msi
if (-not $Packages) {
    throw "No Windows installer artifacts were produced under $OutputRoot"
}
$Packages | ForEach-Object {
    $Hash = Get-FileHash -Algorithm SHA256 -Path $_.FullName
    Write-Host " - $($_.FullName)"
    Write-Host "   sha256: $($Hash.Hash.ToLowerInvariant())"
}

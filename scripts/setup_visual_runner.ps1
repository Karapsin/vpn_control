param(
    [ValidateSet("windows")]
    [string]$Platform = "windows"
)

$ErrorActionPreference = "Stop"
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw "Git is required" }
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { throw "Python is required" }
git lfs version | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Git LFS is required" }

Write-Host "Windows guest prerequisites found. Keep an interactive desktop and capture permission enabled."
Write-Host "Install and run the QEMU guest agent for host-driven file transfer and UAC/MSI capture."
Write-Host "Register the Linux libvirt host—not this guest—with: self-hosted,vpn-control-visual,windows-vm"

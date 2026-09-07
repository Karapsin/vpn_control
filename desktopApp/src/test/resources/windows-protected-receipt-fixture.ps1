param([Parameter(Mandatory=$true)][ValidateSet('setup','cleanup')][string]$Action,
      [Parameter(Mandatory=$true)][Guid]$JobId)
$ErrorActionPreference = 'Stop'
# Test fixture only. Execute elevated inside the agent-owned disposable Windows VM.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated fixture setup/cleanup required' }
$root = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'vpn-control-install-jobs'
$job = Join-Path $root $JobId.ToString()
$directorySddl = 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)'
function New-ProtectedDirectory([string]$Path) {
    if (Test-Path -LiteralPath $Path) { throw 'Fixture directory already exists' }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm($directorySddl)
    [IO.Directory]::CreateDirectory($Path, $acl) | Out-Null
}
if ($Action -eq 'setup') {
    if (-not (Test-Path -LiteralPath $root)) { New-ProtectedDirectory $root }
    if ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse root rejected' }
    New-ProtectedDirectory $job
    $status = Join-Path $job 'status.json'
    [IO.File]::WriteAllText($status, '{"nativeReceipt":1}', (New-Object Text.UTF8Encoding($false)))
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;BU)')
    [IO.File]::SetAccessControl($status, $acl)
    Write-Output "protectedJob=$JobId"
} else {
    if ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse root rejected' }
    if ((Get-Item -LiteralPath $job).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse job rejected' }
    $entries = @(Get-ChildItem -LiteralPath $job -Force)
    if ($entries.Count -ne 1 -or $entries[0].Name -ne 'status.json' -or $entries[0].PSIsContainer) { throw 'Unexpected fixture content; preserve for inspection' }
    if ($entries[0].Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse receipt rejected' }
    if ([IO.File]::ReadAllText($entries[0].FullName) -notin @('{"nativeReceipt":1}', '{"nativeReceipt":2}')) { throw 'Not a native receipt fixture' }
    [IO.File]::Delete((Join-Path $job 'status.json'))
    [IO.Directory]::Delete($job)
    # Keep the shared product root: this fixture does not own other jobs.
}

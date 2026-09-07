# Original-user worker. The privileged coordinator never executes the package or this user's code.
function New-ReturnedOwnerStartInfo($Request) {
    $launch = [Diagnostics.ProcessStartInfo]::new($Request['launcher'])
    $launch.UseShellExecute = $false
    # Assert-Request rejects quotes, line controls and trailing separators. The data-only
    # argument is parsed directly by the launcher, never by PowerShell or another shell.
    $launch.Arguments = '--state-dir "'+$Request['stateDirectory']+'"'
    if (-not $Request.ContainsKey('frontendPid')) { $launch.Arguments += ' serve' }
    return $launch
}

$owner = $null
$package = $null
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Original installer user required' }
    $owner = [VpnInstallNative+ProcessPin]::new($OwnerPid)
    if ($owner.Exited -or $owner.Principal -cne $identity.User.Value) { throw 'CONFLICT' }
    $input = [IO.Path]::Combine($owner.LocalAppData(), 'vpn-control-install-inputs', $JobId)
    $null = Pin-Directory $input $owner.Principal
    $request = Read-PinnedRecord ([IO.Path]::Combine($input, 'request.json')) $owner.Principal
    Assert-Request $request $JobId $owner
    $null = Pin-Directory ([IO.Path]::GetDirectoryName($request['packageFile'])) $owner.Principal
    $packageHandle = [VpnInstallNative]::OpenRead($request['packageFile'], $false)
    try {
        [VpnInstallNative]::Inspect($packageHandle, $false, $false, $owner.Principal)
        $package = [IO.FileStream]::new($packageHandle, [IO.FileAccess]::Read)
        $packageHandle = $null
    } finally { if ($packageHandle) { $packageHandle.Dispose() } }
    if ($package.Length -ne $request['packageSize']) { throw 'INVALID_ARGUMENT' }
    $digest = [Security.Cryptography.SHA256]::Create()
    try { $hash = [BitConverter]::ToString($digest.ComputeHash($package)).Replace('-', '').ToLowerInvariant() }
    finally { $digest.Dispose() }
    if ($hash -cne $request['packageSha256']) { throw 'INVALID_ARGUMENT' }
    $package.Position = 0
    # The MSI database is opened read-only while the immutable package handle denies writes/deletion.
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.OpenDatabase($request['packageFile'], 0)
    foreach ($property in @('ProductName', 'UpgradeCode')) {
        $view = $database.OpenView("SELECT ``Value`` FROM ``Property`` WHERE ``Property``='$property'")
        try {
            $view.Execute()
            $row = $view.Fetch()
            $value = if ($row) { $row.StringData(1) } else { '' }
            if (($property -eq 'ProductName' -and $value -cne 'vpn-control') -or
                ($property -eq 'UpgradeCode' -and $value.Trim('{}') -ine '7a5e0a8e-2a7a-4baf-9f2a-5fb2c3529af2')) { throw 'INVALID_ARGUMENT' }
        } finally { $view.Close() }
    }
    [Runtime.InteropServices.Marshal]::FinalReleaseComObject($database) | Out-Null
    [Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer) | Out-Null
    $self = [VpnInstallNative+ProcessPin]::new([uint32]$PID)
    try {
        Write-PrivateRecord ([IO.Path]::Combine($input, 'worker-ready.json')) $owner.Principal (
            '{"version":1,"jobId":"'+$JobId+'","pid":'+$PID+',"startedAtEpochMillis":'+$self.StartedAtEpochMillis+'}')
    } finally { $self.Dispose() }
    $job = [IO.Path]::Combine([VpnInstallNative]::ProgramData(), 'vpn-control-install-jobs', $JobId)
    $deadline = [DateTime]::UtcNow.AddMinutes(10)
    $lastSequence = -1L
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $job) {
            try { $receipt = Read-ProtectedReceipt $job $JobId }
            catch {
                $missing = $_.Exception
                while ($missing -isnot [ComponentModel.Win32Exception] -and $missing.InnerException) {
                    $missing = $missing.InnerException
                }
                # CREATE_NEW exposes the pinned job directory immediately before its
                # first atomic receipt. Only that initial absence is retryable.
                if ($lastSequence -ge 0 -or $missing -isnot [ComponentModel.Win32Exception] -or
                    $missing.NativeErrorCode -notin @(2,3)) { throw }
                Start-Sleep -Milliseconds 100
                continue
            }
            if ($receipt['sequence'] -lt $lastSequence) { throw 'CONFLICT' }
            $lastSequence = $receipt['sequence']
            if ($receipt['phase'] -in @('FAILED','CANCELLED')) { exit 1 }
            if ($receipt['phase'] -eq 'INSTALLING') { break }
        }
        Start-Sleep -Milliseconds 100
    }
    if (-not $receipt -or $receipt['phase'] -ne 'INSTALLING') { throw 'TIMEOUT' }
    # The original token performs per-user installation; no privileged coordinator command execution.
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = [IO.Path]::Combine([Environment]::SystemDirectory, 'msiexec.exe')
    $start.Arguments = '/i "'+$request['packageFile']+'" /qn /norestart REBOOT=ReallySuppress MSIRESTARTMANAGERCONTROL=Disable ALLUSERS=2 MSIINSTALLPERUSER=1'
    $start.UseShellExecute = $false
    $process = [Diagnostics.Process]::Start($start)
    try {
        # Never kill a potentially modifying installer on timeout or close its outcome as "not installed".
        $process.WaitForExit()
        $exitCode = $process.ExitCode
    } finally { $process.Dispose() }
    Write-PrivateRecord ([IO.Path]::Combine($input, 'worker-result.json')) $owner.Principal (
        '{"version":1,"jobId":"'+$JobId+'","exitCode":'+$exitCode+'}')
    # Relaunch is deliberately gated on the protected final receipt and cleared machine gate.
    while ([DateTime]::UtcNow -lt $deadline.AddMinutes(20)) {
        $receipt = Read-ProtectedReceipt $job $JobId
        if ($receipt['phase'] -eq 'SUCCEEDED') { break }
        if ($receipt['phase'] -in @('FAILED','CANCELLED')) { exit 1 }
        Start-Sleep -Milliseconds 100
    }
    if ($receipt['phase'] -ne 'SUCCEEDED') { throw 'OUTCOME_UNKNOWN' }
    # Startup admission may briefly see pending while the coordinator flushes/clears its gate.
    Start-Sleep -Milliseconds 250
    $launch = New-ReturnedOwnerStartInfo $request
    [Diagnostics.Process]::Start($launch).Dispose()
} finally {
    if ($package) { $package.Dispose() }
    if ($owner) { $owner.Dispose() }
    Close-Pins
}

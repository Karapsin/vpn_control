# Elevated fixed coordinator: protected gate/receipts and process inspection only. Never executes an MSI.
$owner = $null; $worker = $null; $frontend = $null
$gate = $null; $cancel = $null
$replacement = $null
$reserved = $false; $exclusive = $false; $pending = $false
$terminal = $false; $installing = $false
$script:sequence = -1L
$script:phase = $null
$script:jobHandle = $null
$script:jobPath = $null
function Publish-Receipt([string]$Phase, [string]$Code = 'OK') {
    $ordered = @('PREPARING','AUTHORIZED','WAITING_FOR_EXIT','INSTALLING','SUCCEEDED','FAILED','CANCELLED')
    if ($Phase -cnotin $ordered -or $Code -cnotmatch '^[A-Z_]{1,40}$' -or
        ($Phase -ceq 'CANCELLED' -and $Code -cne 'CANCELLED') -or
        ($Phase -ceq 'FAILED' -and $Code -cin @('OK','ACCEPTED','CANCELLED')) -or
        ($Phase -cnotin @('FAILED','CANCELLED') -and $Code -cne 'OK')) { throw 'INVALID_ARGUMENT' }
    if ($null -eq $script:phase) {
        if ($Phase -cne 'PREPARING') { throw 'INVALID_ARGUMENT' }
    } elseif ($script:phase -cin @('SUCCEEDED','FAILED','CANCELLED') -or
        ($Phase -cnotin @('FAILED','CANCELLED') -and
        [Array]::IndexOf($ordered,$Phase) -ne [Array]::IndexOf($ordered,$script:phase)+1)) { throw 'INVALID_ARGUMENT' }
    if ($script:sequence -eq [long]::MaxValue) { throw 'INVALID_ARGUMENT' }
    $next = $script:sequence + 1L
    $json = '{"version":1,"jobId":"'+$JobId+'","sequence":'+$next+',"phase":"'+$Phase+'","code":"'+$Code+'"}'
    $name = 'status-'+[Guid]::NewGuid().ToString()+'.tmp'
    $file = [VpnInstallNative]::CreateFile([IO.Path]::Combine($script:jobPath,$name),
        'O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;GR;;;BU)',[Text.Encoding]::UTF8.GetBytes($json))
    $file.Dispose()
    $deadline = [DateTime]::UtcNow.AddSeconds(3)
    while ($true) {
        try {
            [VpnInstallNative]::ReplaceReceipt($script:jobHandle,$name)
            $script:sequence=$next; $script:phase=$Phase
            return
        }
        catch { if ([DateTime]::UtcNow -ge $deadline) { throw }; Start-Sleep -Milliseconds 20 }
    }
}
function Is-Cancelled {
    $cancel.Position = 0
    $value = $cancel.ReadByte()
    if ($value -notin @(0,1)) { throw 'INVALID_ARGUMENT' }
    return ($value -eq 1)
}
try {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'PRIVILEGE_REQUIRED' }
    $owner = [VpnInstallNative+ProcessPin]::new($OwnerPid)
    if ($owner.Exited) { throw 'CONFLICT' }
    $input = [IO.Path]::Combine($owner.LocalAppData(),'vpn-control-install-inputs',$JobId)
    $null = Pin-Directory $input $owner.Principal
    $request = Read-PinnedRecord ([IO.Path]::Combine($input,'request.json')) $owner.Principal
    Assert-Request $request $JobId $owner
    $ready = Read-PinnedRecord ([IO.Path]::Combine($input,'worker-ready.json')) $owner.Principal
    if ($ready.Count -ne 4 -or $ready['version'] -ne 1 -or $ready['jobId'] -cne $JobId -or
        $ready['pid'] -isnot [long] -or $ready['pid'] -le 0 -or $ready['pid'] -gt [uint32]::MaxValue) { throw 'INVALID_ARGUMENT' }
    $worker = [VpnInstallNative+ProcessPin]::new([uint32]$ready['pid'])
    $powershell = [IO.Path]::Combine([Environment]::SystemDirectory,'WindowsPowerShell','v1.0','powershell.exe')
    if ($worker.Exited -or $worker.Principal -cne $owner.Principal -or $worker.Image -ine $powershell -or
        $worker.StartedAtEpochMillis -ne $ready['startedAtEpochMillis']) { throw 'CONFLICT' }
    if ($request.ContainsKey('frontendPid')) {
        $frontend = [VpnInstallNative+ProcessPin]::new([uint32]$request['frontendPid'])
        if ($frontend.Exited -or $frontend.Principal -cne $owner.Principal -or
            $frontend.StartedAtEpochMillis -ne $request['frontendStartedAtEpochMillis'] -or $frontend.Image -ine $request['launcher']) { throw 'CONFLICT' }
    }
    $installation = Pin-Directory ([IO.Path]::GetDirectoryName($request['launcher'])) $owner.Principal
    $replacement = [VpnInstallNative+ExecutableReplacementSet]::new($installation,$owner.Principal)
    $installationId = [VpnInstallNative]::InstallationId($installation)
    $machine = [IO.Path]::Combine([VpnInstallNative]::ProgramData(),'vpn-control-install-jobs')
    # Pin existing ancestry before creating any privileged child; native CREATE_NEW never follows leaves.
    $null = Pin-Directory ([VpnInstallNative]::ProgramData()) $null $true
    try { [VpnInstallNative]::CreateDirectory($machine,'O:BAG:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;GRGX;;;BU)') }
    catch { if (-not [IO.Directory]::Exists($machine)) { throw } }
    $null = Pin-Directory $machine $null
    $gatePath = [IO.Path]::Combine($machine,'gate-'+$installationId)
    try { $gate = [VpnInstallNative]::CreateFile($gatePath,'O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;GR;;;BU)',[byte[]]::new(17)) }
    catch { $gate = [VpnInstallNative]::OpenGate($gatePath,$true) }
    [VpnInstallNative]::Inspect($gate.SafeFileHandle,$false,$false,$null)
    if ($gate.Length -ne 17 -or -not [VpnInstallNative]::TryLock($gate.SafeFileHandle,16,$true)) { throw 'BUSY' }
    $reserved = $true
    $gate.Position = 0
    for ($index=0; $index -lt 17; $index++) { if ($gate.ReadByte() -ne 0) { throw 'BUSY' } }
    $script:jobPath = [IO.Path]::Combine($machine,$JobId)
    [VpnInstallNative]::CreateDirectory($script:jobPath,'O:BAG:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;GRGX;;;BU)')
    $script:jobHandle = Pin-Directory $script:jobPath $null
    $cancel = [VpnInstallNative]::CreateFile([IO.Path]::Combine($script:jobPath,'cancel'),
        ('O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x00120083;;;'+$owner.Principal+')'),[byte[]]@(0))
    Publish-Receipt 'PREPARING'
    $gate.Position=8; $gate.WriteByte(1); $gate.Flush($true); $pending=$true
    Publish-Receipt 'AUTHORIZED'
    $deadline = [DateTime]::UtcNow.AddMinutes(3)
    while (-not [IO.File]::Exists([IO.Path]::Combine($input,'commit.json'))) {
        if ((Is-Cancelled) -or $owner.Exited -or $worker.Exited) { Publish-Receipt 'CANCELLED' 'CANCELLED'; $terminal=$true; return }
        if ([DateTime]::UtcNow -ge $deadline) { throw 'TIMEOUT' }
        Start-Sleep -Milliseconds 100
    }
    $commit = Read-PinnedRecord ([IO.Path]::Combine($input,'commit.json')) $owner.Principal
    if ($commit.Count -ne 2 -or $commit['jobId'] -cne $JobId -or $commit['version'] -ne 1) { throw 'CONFLICT' }
    Publish-Receipt 'WAITING_FOR_EXIT'
    while ($true) {
        if ((Is-Cancelled) -or $worker.Exited) { Publish-Receipt 'CANCELLED' 'CANCELLED'; $terminal=$true; return }
        if ([DateTime]::UtcNow -ge $deadline) { throw 'BUSY' }
        if ($owner.Exited -and ($null -eq $frontend -or $frontend.Exited)) {
            if ([VpnInstallNative]::TryLock($gate.SafeFileHandle,0,$true)) { $exclusive=$true; break }
        }
        Start-Sleep -Milliseconds 100
    }
    # Legacy/nonparticipating copies are not killed. Any uninspectable process fails closed.
    while ($true) {
        if ((Is-Cancelled) -or $worker.Exited) { Publish-Receipt 'CANCELLED' 'CANCELLED'; $terminal=$true; return }
        if ([DateTime]::UtcNow -ge $deadline) { throw 'BUSY' }
        try {
            Assert-NoInstallationCopies ([Diagnostics.Process]::GetProcesses()) $request['launcher'] @(0,4,$PID,$worker.Pid) $replacement
            if ($replacement.TryReady()) { break }
        } catch { if ($_.Exception.Message -cne 'BUSY') { throw } }
        Start-Sleep -Milliseconds 100
    }
    $installing=$true
    Publish-Receipt 'INSTALLING'
    $deadline=[DateTime]::UtcNow.AddMinutes(30)
    while (-not [IO.File]::Exists([IO.Path]::Combine($input,'worker-result.json'))) {
        if ($worker.Exited -or [DateTime]::UtcNow -ge $deadline) { throw 'OUTCOME_UNKNOWN' }
        Start-Sleep -Milliseconds 200
    }
    $result = Read-PinnedRecord ([IO.Path]::Combine($input,'worker-result.json')) $owner.Principal
    if ($result.Count -ne 3 -or $result['version'] -ne 1 -or $result['jobId'] -cne $JobId -or $result['exitCode'] -isnot [long]) { throw 'OUTCOME_UNKNOWN' }
    if ($result['exitCode'] -in @(0,3010)) { Publish-Receipt 'SUCCEEDED' } else { Publish-Receipt 'FAILED' 'RUNTIME_FAILED' }
    $terminal=$true
} catch {
    if ($script:jobHandle -and -not $installing) {
        if ($null -eq $script:phase) { Publish-Receipt 'PREPARING' }
        Publish-Receipt 'FAILED' 'RUNTIME_FAILED'
        $terminal=$true
    }
    # During unknown installation, retain pending=1 and the nonterminal INSTALLING receipt.
    # Recovery must reconcile the actual worker/installer outcome before reopening admission.
    throw
} finally {
    if ($gate) {
        if ($pending -and $terminal) { $gate.Position=8; $gate.WriteByte(0); $gate.Flush($true) }
        if ($exclusive) { [VpnInstallNative]::Unlock($gate.SafeFileHandle,0) }
        if ($reserved) { [VpnInstallNative]::Unlock($gate.SafeFileHandle,16) }
        $gate.Dispose()
    }
    if ($cancel) { $cancel.Dispose() }
    if ($worker) { $worker.Dispose() }
    if ($frontend) { $frontend.Dispose() }
    if ($owner) { $owner.Dispose() }
    if ($replacement) { $replacement.Dispose() }
    Close-Pins
}

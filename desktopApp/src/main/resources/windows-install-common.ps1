# This body is captured with the selected fixed worker before launch, never executed using -File.
$ErrorActionPreference = 'Stop'
$script:pins = [Collections.Generic.List[IDisposable]]::new()

function Pin-Directory([string]$Path, [string]$InputPrincipal, [bool]$FinalIsAncestor = $false) {
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -notmatch '^[A-Za-z]:\\' -or $full.Substring(2).Contains(':')) { throw 'INVALID_ARGUMENT' }
    $root = [IO.Path]::GetPathRoot($full)
    $parts = $full.Substring($root.Length).Split([char]'\', [StringSplitOptions]::RemoveEmptyEntries)
    $current = $root
    $handle = [VpnInstallNative]::OpenDirectory($current)
    $script:pins.Add($handle)
    [VpnInstallNative]::Inspect($handle, $true, $true, $InputPrincipal)
    for ($index = 0; $index -lt $parts.Length; $index++) {
        if ($parts[$index] -eq '.' -or $parts[$index] -eq '..') { throw 'INVALID_ARGUMENT' }
        $current = [IO.Path]::Combine($current, $parts[$index])
        $handle = [VpnInstallNative]::OpenDirectory($current)
        $script:pins.Add($handle)
        $ancestor = $FinalIsAncestor -or $index -ne $parts.Length - 1
        try { [VpnInstallNative]::Inspect($handle, $true, $ancestor, $InputPrincipal) }
        catch {
            if (-not $ancestor) { throw }
            # WRITE_ATTRIBUTES can set a reparse point, except on a directory which cannot become empty.
            # Retain the non-delete-sharing child witness until every use of this ancestry is finished.
            $witness = [VpnInstallNative]::PinNonEmptyAncestor($handle,$InputPrincipal)
            $script:pins.Add($witness)
        }
    }
    return $handle
}

function Read-PinnedRecord([string]$Path, [string]$Principal) {
    $handle = [VpnInstallNative]::OpenRead($Path, $false)
    try {
        [VpnInstallNative]::Inspect($handle, $false, $false, $Principal)
        $stream = [IO.FileStream]::new($handle, [IO.FileAccess]::Read)
        $script:pins.Add($stream)
        $handle = $null
        if ($stream.Length -gt 65536) { throw 'INVALID_ARGUMENT' }
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $count = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($count -le 0) { throw 'UNAVAILABLE' }
            $offset += $count
        }
        return [VpnInstallNative]::ParseFlatRecord([Text.UTF8Encoding]::new($false, $true).GetString($bytes))
    } finally { if ($null -ne $handle) { $handle.Dispose() } }
}

function Assert-Request($Request, [string]$JobId, $Owner) {
    $required = @('version','jobId','principalSid','ownerPid','ownerStartedAtEpochMillis','launcher','packageFile','packageSha256','packageSize','stateDirectory')
    $optional = @('frontendPid','frontendStartedAtEpochMillis')
    if ($Request.Count -ne $required.Length -and $Request.Count -ne ($required.Length + 2)) { throw 'INVALID_ARGUMENT' }
    foreach ($key in $required) { if (-not $Request.ContainsKey($key)) { throw 'INVALID_ARGUMENT' } }
    foreach ($key in $Request.Keys) { if ($key -notin ($required + $optional)) { throw 'INVALID_ARGUMENT' } }
    if ($Request['version'] -ne 1 -or $Request['jobId'] -cne $JobId -or $Request['ownerPid'] -ne $Owner.Pid -or
        $Request['ownerStartedAtEpochMillis'] -ne $Owner.StartedAtEpochMillis -or $Request['principalSid'] -cne $Owner.Principal) { throw 'CONFLICT' }
    if ($Request['packageSha256'] -cnotmatch '^[a-f0-9]{64}$' -or $Request['packageSize'] -isnot [long] -or $Request['packageSize'] -le 0) { throw 'INVALID_ARGUMENT' }
    foreach ($key in @('launcher','packageFile','stateDirectory')) {
        $path = $Request[$key]
        if ($path -isnot [string] -or $path -notmatch '^[A-Za-z]:\\' -or $path.Substring(2) -match '[:/"<>|?*\x00-\x1f]') { throw 'INVALID_ARGUMENT' }
        foreach ($part in $path.Substring(3).Split([char]'\')) {
            if (-not $part -or $part -eq '.' -or $part -eq '..' -or $part.EndsWith('.') -or $part.EndsWith(' ')) { throw 'INVALID_ARGUMENT' }
        }
    }
    if ([IO.Path]::GetFileName($Request['launcher']) -ine 'vpn-control.exe' -or [IO.Path]::GetExtension($Request['packageFile']) -ine '.msi') { throw 'INVALID_ARGUMENT' }
    if ([IO.Path]::GetFileName($Owner.Image) -notin @('vpn-control.exe','vpn-control-cli.exe') -or
        [IO.Path]::GetDirectoryName($Owner.Image) -ine [IO.Path]::GetDirectoryName($Request['launcher'])) { throw 'CONFLICT' }
    if ($Request.ContainsKey('frontendPid')) {
        if ($Request['frontendPid'] -isnot [long] -or $Request['frontendPid'] -le 0 -or $Request['frontendPid'] -gt [uint32]::MaxValue -or
            $Request['frontendStartedAtEpochMillis'] -isnot [long] -or $Request['frontendStartedAtEpochMillis'] -le 0) { throw 'INVALID_ARGUMENT' }
    }
}

function Close-Pins {
    for ($index = $script:pins.Count - 1; $index -ge 0; $index--) { $script:pins[$index].Dispose() }
    $script:pins.Clear()
}

function Write-PrivateRecord([string]$Path, [string]$Principal, [string]$Json) {
    [VpnInstallNative]::PublishPrivateRecord($Path, $Principal, [Text.UTF8Encoding]::new($false,$true).GetBytes($Json))
}

function Close-ProcessImagePins {
    for ($index=$script:pins.Count-1; $index -ge 0; $index--) {
        if ($script:pins[$index] -is [VpnInstallNative+ProcessImagePin]) {
            try { $script:pins[$index].Dispose() } catch { throw 'BUSY' }
            $script:pins.RemoveAt($index)
        }
    }
}

# Internal callable seam; worker command lines cannot supply these readers.
function Assert-NoInstallationCopies($Processes, [string]$Launcher, [uint32[]]$Excluded, $Installation,
    [scriptblock]$ReadImage = { param($Id) [VpnInstallNative+ProcessImagePin]::new([uint32]$Id) },
    [scriptblock]$SameImage = { param($Image, $Captured) $Captured.ContainsImage($Image) }) {
    try {
        # A previous failed native close is still owned and still blocks readiness.
        Close-ProcessImagePins
        foreach ($process in $Processes) {
            if ($process.Id -in $Excluded) { continue }
            $pin=$null
            try {
                $candidate=& $ReadImage $process.Id
                if ($candidate -isnot [VpnInstallNative+ProcessImagePin]) { throw 'BUSY' }
                $pin=$candidate; $script:pins.Add($pin)
                $observation=$pin.Observe()
                if ($observation.Pid -ne $process.Id) { throw 'BUSY' }
                if ($observation.KernelOnly) { continue }
                $same=& $SameImage $observation.Image $Installation
                if ($same -isnot [bool] -or $same) { throw 'BUSY' }
            } catch {
                # A managed HasExited flag, image-query error, or unreadable snapshot
                # never supplies the retained native generation proof.
                throw 'BUSY'
            } finally {
                if ($null -ne $pin) {
                    try { $pin.Dispose() } catch { throw 'BUSY' }
                    $null=$script:pins.Remove($pin)
                }
            }
        }
    } finally { foreach ($process in $Processes) { $process.Dispose() } }
}

function Read-ProtectedReceipt([string]$Job, [string]$JobId) {
    if (-not $script:protectedJob) {
        $null = Pin-Directory $Job $null
        $script:protectedJob = $Job
    } elseif ($script:protectedJob -cne $Job) { throw 'CONFLICT' }
    $handle = [VpnInstallNative]::OpenReceipt([IO.Path]::Combine($Job,'status.json'))
    $stream = $null
    try {
        [VpnInstallNative]::Inspect($handle,$false,$false,$null)
        $stream = [IO.FileStream]::new($handle,[IO.FileAccess]::Read)
        $handle = $null
        if ($stream.Length -gt 4096) { throw 'INVALID_ARGUMENT' }
        $reader = [IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false,$true))
        try { $receipt = [VpnInstallNative]::ParseFlatRecord($reader.ReadToEnd()) } finally { $reader.Dispose() }
        if ($receipt.Count -ne 5 -or $receipt['version'] -ne 1 -or $receipt['jobId'] -cne $JobId -or
            $receipt['sequence'] -isnot [long] -or $receipt['sequence'] -lt 0 -or
            $receipt['phase'] -notin @('PREPARING','AUTHORIZED','WAITING_FOR_EXIT','INSTALLING','SUCCEEDED','FAILED','CANCELLED') -or
            $receipt['code'] -isnot [string]) { throw 'INVALID_ARGUMENT' }
        return $receipt
    } finally { if ($stream) { $stream.Dispose() }; if ($handle) { $handle.Dispose() } }
}

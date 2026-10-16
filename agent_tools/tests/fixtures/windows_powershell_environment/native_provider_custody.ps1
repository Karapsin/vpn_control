param(
    [Parameter(Mandatory=$true)][string]$SourcePath,
    [Parameter(Mandatory=$true)][string]$DataPath,
    [Parameter(Mandatory=$true)][string]$ExpectedDataSha256,
    [Parameter(Mandatory=$true)][string]$EvidenceDirectory,
    [Parameter(Mandatory=$true)][ValidateSet('unfixed_i','sanitized')][string]$Case,
    [Parameter(Mandatory=$true)][string]$ExpectedSourceSha256,
    [Parameter(Mandatory=$true)][int]$ExpectedSourceBytes,
    [Parameter(Mandatory=$true)][string]$CustodyNonce
)
$ErrorActionPreference='Stop'
# This separately pinned observer invokes an unchanged BOM control file. It
# neither decodes provider files nor looks up/imports any command provider.
$script:custodyUtf8=[Text.UTF8Encoding]::new($false,$true)
$script:custodyRows=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
$script:custodyJoins=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$script:custodyDirectories=@()
$script:custodyBodyStarted=$false
$script:custodyBodyCompleted=$false
$script:custodyBodyExit=$null
$script:custodyBodyError=$null
$script:custodyClosingOk=$true
$script:custodyCleanupErrors=[Collections.Generic.List[string]]::new()
$script:custodyEvidence=$null
$script:custodyManifestPath=$null
$script:custodyScriptPath=$null
$script:custodyNoBomCp=$null
$script:custodyPendingStream=$null
$global:PublicNativeProviderCustodyV1=@{case=$Case;rows=$script:custodyRows;joins=$script:custodyJoins;evidence=$null;noBomCp=$null}

function Get-CustodySha256([byte[]]$raw){
    $algorithm=[Security.Cryptography.SHA256]::Create()
    try{return [BitConverter]::ToString($algorithm.ComputeHash($raw)).Replace('-','').ToLowerInvariant()}
    finally{$algorithm.Dispose()}
}
function ConvertTo-CustodyField([string]$value){
    $bytes=$script:custodyUtf8.GetBytes($value)
    if($bytes.Length -gt 8192){throw 'PUBLIC_NATIVE_CUSTODY_FIELD_BOUND'}
    return [Convert]::ToBase64String($bytes)
}
function Write-CustodyRecord([string]$name,[string[]]$lines){
    if($null -eq $script:custodyEvidence -or $name -cnotmatch '^[a-z][a-z0-9.-]{0,63}\.record$'){throw 'PUBLIC_NATIVE_CUSTODY_RECORD_NAME'}
    $all=[Collections.Generic.List[string]]::new()
    [void]$all.Add('schemaVersion=1')
    foreach($line in $lines){
        if($line -cnotmatch '^[A-Za-z][A-Za-z0-9]*=[\x20-\x7e]*$' -or $script:custodyUtf8.GetByteCount($line)+1 -gt 16384){throw 'PUBLIC_NATIVE_CUSTODY_RECORD_LINE'}
        [void]$all.Add($line)
    }
    [void]$all.Add('recordComplete=1')
    $raw=$script:custodyUtf8.GetBytes(([string]::Join("`n",$all.ToArray())+"`n"))
    if($raw.Length -gt 65536){throw 'PUBLIC_NATIVE_CUSTODY_RECORD_BOUND'}
    $finalPath=[IO.Path]::Combine($script:custodyEvidence,$name);$pendingPath=$finalPath+'.pending'
    $stream=[IO.File]::Open($pendingPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try{$stream.Write($raw,0,$raw.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    [IO.File]::Move($pendingPath,$finalPath)
}
function Get-CustodyFileState([IO.FileInfo]$info){
    $info.Refresh()
    if(-not $info.Exists -or ($info.Attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Directory))){throw 'PUBLIC_NATIVE_CUSTODY_FILE'}
    return ([string]$info.Length+':'+[string]$info.CreationTimeUtc.Ticks+':'+[string]$info.LastWriteTimeUtc.Ticks+':'+[string][int]$info.Attributes)
}
function Read-CustodyHeldFile([string]$role,[string]$path,[int]$bound,[bool]$saveRaw){
    $info=[IO.FileInfo]::new($path)
    $state=Get-CustodyFileState $info
    if($info.Length -lt 1 -or $info.Length -gt $bound){throw 'PUBLIC_NATIVE_CUSTODY_FILE_BOUND'}
    $script:custodyPendingStream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $stream=$script:custodyPendingStream
    # The pending slot owns the returned handle across row allocation/enrolment.
    $row=@{role=$role;path=$path;info=$info;state=$state;stream=$stream;raw=$null;sha256=$null;rawEof=$false;closed=$false;closing=$false}
    $script:custodyRows.Add($role,$row)
    $script:custodyPendingStream=$null
    if($stream.Length -ne $info.Length){throw 'PUBLIC_NATIVE_CUSTODY_GENERATION'}
    $raw=[byte[]]::new([int]$stream.Length);$offset=0
    while($offset -lt $raw.Length){$count=$stream.Read($raw,$offset,$raw.Length-$offset);if($count -le 0){throw 'PUBLIC_NATIVE_CUSTODY_EOF'};$offset+=$count}
    if($stream.ReadByte() -ne -1){throw 'PUBLIC_NATIVE_CUSTODY_EOF'}
    $row.raw=$raw;$row.sha256=Get-CustodySha256 $raw;$row.rawEof=$true
    if((Get-CustodyFileState $info) -cne $state){throw 'PUBLIC_NATIVE_CUSTODY_GENERATION'}
    if($saveRaw){
        $saved=[IO.File]::Open([IO.Path]::Combine($script:custodyEvidence,$role+'.raw'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try{$saved.Write($raw,0,$raw.Length);$saved.Flush($true)}finally{$saved.Dispose()}
    }
    $leading=[byte[]]::new([Math]::Min(4,$raw.Length));[Array]::Copy($raw,0,$leading,0,$leading.Length)
    Write-CustodyRecord ($role+'.input.record') @(
        'kind=PROVIDER_CUSTODY_INPUT_V1',('case='+$Case),('role='+$role),
        ('pathUtf8Base64='+(ConvertTo-CustodyField $path)),('bytes='+[string]$raw.Length),
        ('sha256='+$row.sha256),('leadingBytesBase64='+[Convert]::ToBase64String($leading)),
        ('generation='+$state),'rawEof=1','shareReadDenyWriteDelete=1',('savedRaw='+[string][int]$saveRaw)
    )
    return $row
}
function Confirm-CustodyRow([object]$row){
    if($null -eq $row.raw -or -not $row.rawEof -or $row.stream.Length -ne $row.raw.Length -or (Get-CustodyFileState $row.info) -cne $row.state){throw 'PUBLIC_NATIVE_CUSTODY_CLOSING'}
    $row.stream.Position=0
    $algorithm=[Security.Cryptography.SHA256]::Create()
    try{$hash=[BitConverter]::ToString($algorithm.ComputeHash($row.stream)).Replace('-','').ToLowerInvariant()}
    finally{$algorithm.Dispose()}
    if($row.stream.ReadByte() -ne -1 -or $hash -cne $row.sha256 -or (Get-CustodyFileState $row.info) -cne $row.state){throw 'PUBLIC_NATIVE_CUSTODY_CLOSING'}
    $row.closing=$true
}
function global:Confirm-PublicNativeProviderDecodeInput([string]$role,[string]$canonicalPath,[byte[]]$raw,[string]$existingShaBase64,[int]$noBomCp){
    # Explicit process-owned context avoids relying on the invoked script's
    # dynamic/script scope. This function itself emits no pipeline objects.
    $context=$global:PublicNativeProviderCustodyV1
    if($null -eq $context -or $context.case -cne 'sanitized' -or ($role -cne 'manifest' -and $role -cne 'script') -or -not $context.rows.ContainsKey($role) -or $context.joins.Contains($role)){throw 'PUBLIC_NATIVE_CUSTODY_JOIN_ROLE'}
    $row=$context.rows[$role]
    if(-not [IO.Path]::IsPathRooted($canonicalPath) -or -not [string]::Equals($canonicalPath,$row.path,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFullPath($canonicalPath) -cne $canonicalPath){throw 'PUBLIC_NATIVE_CUSTODY_JOIN_PATH'}
    if($null -eq $raw -or $raw.Length -ne $row.raw.Length -or $noBomCp -ne $context.noBomCp){throw 'PUBLIC_NATIVE_CUSTODY_JOIN_CONTEXT'}
    $claimed=[Convert]::FromBase64String($existingShaBase64)
    if($claimed.Length -ne 32 -or [Convert]::ToBase64String($claimed) -cne $existingShaBase64){throw 'PUBLIC_NATIVE_CUSTODY_JOIN_SHA'}
    $algorithm=[Security.Cryptography.SHA256]::Create()
    try{$actual=[BitConverter]::ToString($algorithm.ComputeHash($raw)).Replace('-','').ToLowerInvariant()}finally{$algorithm.Dispose()}
    if($actual -cne $row.sha256 -or [BitConverter]::ToString($claimed).Replace('-','').ToLowerInvariant() -cne $actual){throw 'PUBLIC_NATIVE_CUSTODY_JOIN_SHA'}
    for($index=0;$index -lt $raw.Length;$index++){if($raw[$index] -ne $row.raw[$index]){throw 'PUBLIC_NATIVE_CUSTODY_JOIN_BYTES'}}
    $row.info.Refresh()
    $state=([string]$row.info.Length+':'+[string]$row.info.CreationTimeUtc.Ticks+':'+[string]$row.info.LastWriteTimeUtc.Ticks+':'+[string][int]$row.info.Attributes)
    if(-not $row.info.Exists -or ($row.info.Attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Directory)) -or $state -cne $row.state -or $row.stream.Length -ne $row.raw.Length -or -not $row.rawEof){throw 'PUBLIC_NATIVE_CUSTODY_JOIN_GENERATION'}
    $row.stream.Position=0;$algorithm=[Security.Cryptography.SHA256]::Create()
    try{$heldHash=[BitConverter]::ToString($algorithm.ComputeHash($row.stream)).Replace('-','').ToLowerInvariant()}finally{$algorithm.Dispose()}
    if($row.stream.ReadByte() -ne -1 -or $heldHash -cne $actual){throw 'PUBLIC_NATIVE_CUSTODY_JOIN_HELD_HASH'}
    $utf8=[Text.UTF8Encoding]::new($false,$true);$pathRaw=$utf8.GetBytes($canonicalPath)
    if($pathRaw.Length -gt 8192){throw 'PUBLIC_NATIVE_CUSTODY_FIELD_BOUND'}
    $lines=[string[]]@(
        'schemaVersion=1','kind=PROVIDER_CUSTODY_DECODE_JOIN_V1',('case='+$context.case),('role='+$role),
        ('pathUtf8Base64='+[Convert]::ToBase64String($pathRaw)),('bytes='+[string]$raw.Length),
        ('sha256='+$actual),('existingShaBase64='+$existingShaBase64),('noBomCodePage='+[string]$noBomCp),
        'exactSnapshotBytesEqual=1','heldGenerationEqual=1','heldHashEqual=1','snapshotRawEof=1','recordComplete=1'
    )
    $record=$utf8.GetBytes(([string]::Join("`n",$lines)+"`n"))
    if($record.Length -gt 65536){throw 'PUBLIC_NATIVE_CUSTODY_RECORD_BOUND'}
    foreach($line in $lines){if($utf8.GetByteCount($line)+1 -gt 16384){throw 'PUBLIC_NATIVE_CUSTODY_RECORD_LINE'}}
    $finalPath=[IO.Path]::Combine($context.evidence,$role+'.join.record');$pendingPath=$finalPath+'.pending'
    $saved=[IO.File]::Open($pendingPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try{$saved.Write($record,0,$record.Length);$saved.Flush($true)}finally{$saved.Dispose()}
    [IO.File]::Move($pendingPath,$finalPath)
    [void]$context.joins.Add($role)
}

try{
    if($Case -cne 'unfixed_i' -and $Case -cne 'sanitized'){throw 'PUBLIC_NATIVE_CUSTODY_CASE'}
    if($ExpectedSourceSha256 -cnotmatch '^[a-f0-9]{64}$' -or $ExpectedDataSha256 -cnotmatch '^[a-f0-9]{64}$' -or $ExpectedSourceBytes -lt 1 -or $ExpectedSourceBytes -gt 131069 -or $CustodyNonce -cnotmatch '^[a-f0-9]{32}$'){throw 'PUBLIC_NATIVE_CUSTODY_AUTHORITY'}
    foreach($path in @($SourcePath,$DataPath,$EvidenceDirectory)){if(-not [IO.Path]::IsPathRooted($path) -or [IO.Path]::GetFullPath($path) -cne $path){throw 'PUBLIC_NATIVE_CUSTODY_ARGUMENT_PATH'}}
    $evidenceInfo=[IO.DirectoryInfo]::new($EvidenceDirectory);$evidenceInfo.Refresh()
    if(-not $evidenceInfo.Exists -or ($evidenceInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $evidenceInfo.Name -cne ($Case+'.'+$CustodyNonce) -or $evidenceInfo.GetFileSystemInfos().Length -ne 0){throw 'PUBLIC_NATIVE_CUSTODY_EVIDENCE_DIRECTORY'}
    $script:custodyEvidence=$EvidenceDirectory
    $global:PublicNativeProviderCustodyV1.evidence=$EvidenceDirectory
    $providerHome=[IO.Path]::GetFullPath([string]$PSHOME)
    $modulesPath=[IO.Path]::Combine($providerHome,'Modules');$utilityPath=[IO.Path]::Combine($modulesPath,'Microsoft.PowerShell.Utility')
    foreach($path in @($providerHome,$modulesPath,$utilityPath)){
        $info=[IO.DirectoryInfo]::new($path);$info.Refresh()
        if(-not $info.Exists -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'PUBLIC_NATIVE_CUSTODY_DIRECTORY'}
        $script:custodyDirectories+=,@{path=$path;state=([string]$info.CreationTimeUtc.Ticks+':'+[string][int]$info.Attributes)}
    }
    $script:custodyManifestPath=[IO.Path]::GetFullPath([IO.Path]::Combine($utilityPath,'Microsoft.PowerShell.Utility.psd1'))
    $script:custodyScriptPath=[IO.Path]::GetFullPath([IO.Path]::Combine($utilityPath,'Microsoft.PowerShell.Utility.psm1'))
    $version=$PSVersionTable.PSVersion;$edition=[string]$PSVersionTable.PSEdition
    $platform=[Environment]::OSVersion.Platform;$coreAssembly=[Object].Assembly.GetName().Name
    $defaultCp=[Text.Encoding]::Default.CodePage
    if($version.Major -eq 5 -and $version.Minor -eq 1 -and $edition -ceq 'Desktop' -and $platform -eq [PlatformID]::Win32NT -and $coreAssembly -ceq 'mscorlib' -and $defaultCp -ge 1 -and $defaultCp -le 65535 -and $defaultCp -notin @(1200,1201,12000,12001,65000)){$script:custodyNoBomCp=$defaultCp}
    elseif($version.Major -ge 6 -and $edition -ceq 'Core' -and $defaultCp -eq 65001 -and $coreAssembly -ceq 'System.Private.CoreLib'){$script:custodyNoBomCp=65001}
    else{throw 'PUBLIC_NATIVE_CUSTODY_ENGINE'}
    $global:PublicNativeProviderCustodyV1.noBomCp=$script:custodyNoBomCp
    Write-CustodyRecord 'context.record' @(
        'kind=PROVIDER_CUSTODY_CONTEXT_V1',('case='+$Case),('nonce='+$CustodyNonce),
        ('sourcePathUtf8Base64='+(ConvertTo-CustodyField $SourcePath)),('expectedSourceSha256='+$ExpectedSourceSha256),('expectedSourceBytes='+[string]$ExpectedSourceBytes),
        ('dataPathUtf8Base64='+(ConvertTo-CustodyField $DataPath)),('dataSha256='+$ExpectedDataSha256),
        ('psHomeUtf8Base64='+(ConvertTo-CustodyField $providerHome)),('psVersion='+$version.ToString()),('psEdition='+$edition),
        ('platform='+[string]$platform),('coreAssembly='+$coreAssembly),('clrVersion='+[Environment]::Version.ToString()),
        ('defaultCodePage='+[string]$defaultCp),('noBomCodePage='+[string]$script:custodyNoBomCp),
        'crossCaseContinuousLock=0','nativeStdoutModified=0','providerLookupBeforeBody=0'
    )
    $source=Read-CustodyHeldFile 'control' $SourcePath 131072 $false
    if($source.raw.Length -ne $ExpectedSourceBytes+3 -or $source.raw[0] -ne 239 -or $source.raw[1] -ne 187 -or $source.raw[2] -ne 191){throw 'PUBLIC_NATIVE_CUSTODY_SOURCE_CARRIER'}
    $body=[byte[]]::new($ExpectedSourceBytes);[Array]::Copy($source.raw,3,$body,0,$body.Length)
    if((Get-CustodySha256 $body) -cne $ExpectedSourceSha256){throw 'PUBLIC_NATIVE_CUSTODY_SOURCE_SHA'}
    $data=Read-CustodyHeldFile 'public-data' $DataPath 34 $false
    if($data.raw.Length -ne 34 -or $data.sha256 -cne $ExpectedDataSha256){throw 'PUBLIC_NATIVE_CUSTODY_DATA_SHA'}
    $manifest=Read-CustodyHeldFile 'manifest' $script:custodyManifestPath 131072 $true
    $providerScript=Read-CustodyHeldFile 'script' $script:custodyScriptPath 8388608 $true
    Write-CustodyRecord 'body-intent.record' @(
        'kind=PROVIDER_CUSTODY_BODY_INTENT_V1',('case='+$Case),('sourceSha256='+$ExpectedSourceSha256),
        ('carrierSha256='+$source.sha256),('sourceBytes='+[string]$ExpectedSourceBytes),
        'originalArgumentCount=2','originalArgumentStringsPreserved=1','bothProviderInputsHeld=1'
    )
    $originalArgs=[string[]]@($DataPath,$ExpectedDataSha256)
    $global:LASTEXITCODE=0
    $script:custodyBodyStarted=$true
    try{
        & $SourcePath @originalArgs
        $script:custodyBodyExit=[int]$global:LASTEXITCODE
        $script:custodyBodyCompleted=$true
    }catch{
        $script:custodyBodyError=$_
        throw
    }
}finally{
    if($null -ne $script:custodyPendingStream){
        $script:custodyClosingOk=$false
        try{$script:custodyPendingStream.Dispose();[void]$script:custodyCleanupErrors.Add('enrolment-incomplete-pending-handle-disposed')}
        catch{[void]$script:custodyCleanupErrors.Add('pending-dispose:'+$_.FullyQualifiedErrorId)}
        finally{$script:custodyPendingStream=$null}
    }
    foreach($role in @('manifest','script','public-data','control')){
        if($script:custodyRows.ContainsKey($role)){
            $row=$script:custodyRows[$role]
            try{Confirm-CustodyRow $row}catch{$script:custodyClosingOk=$false;[void]$script:custodyCleanupErrors.Add($role+':'+$_.FullyQualifiedErrorId)}
            finally{try{$row.stream.Dispose();$row.closed=$true}catch{$script:custodyClosingOk=$false;[void]$script:custodyCleanupErrors.Add($role+':dispose:'+ $_.FullyQualifiedErrorId)}}
        }
    }
    foreach($saved in $script:custodyDirectories){
        try{$info=[IO.DirectoryInfo]::new($saved.path);$info.Refresh();if(-not $info.Exists -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ([string]$info.CreationTimeUtc.Ticks+':'+[string][int]$info.Attributes) -cne $saved.state){throw 'PUBLIC_NATIVE_CUSTODY_DIRECTORY_CLOSING'}}
        catch{$script:custodyClosingOk=$false;[void]$script:custodyCleanupErrors.Add('directory:'+ $_.FullyQualifiedErrorId)}
    }
    if($null -ne $script:custodyEvidence){
        try{
            $errorId='';$errorType='';if($null -ne $script:custodyBodyError){$errorId=[string]$script:custodyBodyError.FullyQualifiedErrorId;$errorType=$script:custodyBodyError.Exception.GetType().FullName}
            $bodyExit='none';if($null -ne $script:custodyBodyExit){$bodyExit=[string]$script:custodyBodyExit}
            $cleanup=[string]::Join('|',$script:custodyCleanupErrors.ToArray())
            $closed=0;foreach($row in $script:custodyRows.Values){if($row.closed){$closed++}}
            Write-CustodyRecord 'closing.record' @(
                'kind=PROVIDER_CUSTODY_CLOSING_V1',('case='+$Case),('bodyStarted='+[string][int]$script:custodyBodyStarted),
                ('bodyCompleted='+[string][int]$script:custodyBodyCompleted),('bodyExit='+$bodyExit),('bodyThrew='+[string][int]($null -ne $script:custodyBodyError)),
                ('bodyErrorIdUtf8Base64='+(ConvertTo-CustodyField $errorId)),('bodyErrorTypeUtf8Base64='+(ConvertTo-CustodyField $errorType)),
                ('enrolledHandles='+[string]$script:custodyRows.Count),('disposedHandles='+[string]$closed),('custodyClosingOk='+[string][int]$script:custodyClosingOk),
                ('manifestJoin='+[string][int]$script:custodyJoins.Contains('manifest')),('scriptJoin='+[string][int]$script:custodyJoins.Contains('script')),
                ('cleanupErrorsUtf8Base64='+(ConvertTo-CustodyField $cleanup)),
                'crossCaseContinuousLock=0','rawPairTransported=0','nativeAdmissionClaim=0'
            )
        }catch{$script:custodyClosingOk=$false}
    }
}
if(-not $script:custodyClosingOk){throw 'PUBLIC_NATIVE_CUSTODY_CLOSING'}
if(-not $script:custodyBodyStarted -or -not $script:custodyBodyCompleted){throw 'PUBLIC_NATIVE_CUSTODY_BODY_UNKNOWN'}
exit $script:custodyBodyExit

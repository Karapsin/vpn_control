$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$script:C=@{pins=[Collections.Generic.List[object]]::new();unknown=$null;releaseAttempted=$false}
function Park-Original([string]$Reason,[object]$ErrorObject){$script:C.unknown=@{reason=$Reason;primary=$ErrorObject};while($true){[Threading.Thread]::Sleep(1000)}}
$bridgeRecord=([Text.UTF8Encoding]::new($false,$true)).GetString([Convert]::FromBase64String('@@BRIDGE_PIN_BASE64@@'))|ConvertFrom-Json
$script:C.bridge=[IO.File]::Open($bridgeRecord.path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
$bridge=$script:C.bridge
$bridgeIdentity=('{0:x8}:{1:x16}' -f [uint32]$bridgeRecord.nativeIdentity.volumeSerial,[uint64]$bridgeRecord.nativeIdentity.fileIndex)
if($bridge.Length -gt 65536 -or [VpnHeldProgram]::Identity($bridge.SafeFileHandle) -cne $bridgeIdentity){throw 'SC_FIXED_NATIVE_BRIDGE_IDENTITY'}
$bridgeHash=[Security.Cryptography.SHA256]::Create();try{$actual=([BitConverter]::ToString($bridgeHash.ComputeHash($bridge))).Replace('-','').ToLowerInvariant()}finally{$bridgeHash.Dispose()}
if($actual -cne $bridgeRecord.sha256){throw 'SC_FIXED_NATIVE_BRIDGE_SHA'}
$bridge.Position=0;$bridgeReader=[IO.StreamReader]::new($bridge,[Text.UTF8Encoding]::new($false,$true),$false,65536,$true)
try{$bridgeText=$bridgeReader.ReadToEnd()}finally{$bridgeReader.Dispose()}
Add-Type -TypeDefinition $bridgeText -ReferencedAssemblies @('System','System.Core')

function Assert-Id([object]$Actual,[object]$Expected) {
$keys=@($Expected.PSObject.Properties.Name)
if($Actual.Count -ne $keys.Count){throw 'SC_NATIVE_IDENTITY_SCHEMA'}
foreach($key in $keys){if(-not $Actual.ContainsKey($key) -or [string]$Actual[$key] -cne [string]$Expected.$key){throw 'SC_NATIVE_IDENTITY_CHANGED'}}
}
function Assert-Pin([object]$Pin) {
$handle=if($Pin.directory){$Pin.handle}else{$Pin.stream.SafeFileHandle}
Assert-Id ([ScFacts]::Identity($handle,$Pin.directory)) $Pin.record.nativeIdentity
$security=[ScFacts]::Security($handle)
if($security[0] -cne $Pin.record.security.ownerSid -or $security[1] -cne $Pin.record.security.sddl){throw 'SC_PIN_SECURITY_CHANGED'}
$named=$null
try{
$named=if($Pin.directory){[ScFacts]::OpenDirectory($Pin.record.path)}else{[ScFacts]::OpenHeld($Pin.record.path)}
$namedHandle=if($Pin.directory){$named}else{$named.SafeFileHandle}
Assert-Id ([ScFacts]::Identity($namedHandle,$Pin.directory)) $Pin.record.nativeIdentity
$namedSecurity=[ScFacts]::Security($namedHandle)
if($namedSecurity[0] -cne $Pin.record.security.ownerSid -or $namedSecurity[1] -cne $Pin.record.security.sddl){throw 'SC_NAMED_SECURITY_CHANGED'}
}finally{if($null -ne $named){$named.Dispose()}}
}
function Get-PinHash([object]$Pin) {
Assert-Pin $Pin;$Pin.stream.Position=0;$hash=[Security.Cryptography.SHA256]::Create()
try{$value=([BitConverter]::ToString($hash.ComputeHash($Pin.stream))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
if($value -cne $Pin.record.sha256){throw 'SC_PIN_DIGEST_CHANGED'}
Assert-Pin $Pin;return $value
}
function Add-FilePin([object]$Record) {
$pin=@{record=$Record;directory=$false;stream=[ScFacts]::OpenHeld($Record.path)}
$script:C.pins.Add($pin);[void](Get-PinHash $pin);return $pin
}

try{
$requestRecord=([Text.UTF8Encoding]::new($false,$true)).GetString([Convert]::FromBase64String('@@REQUEST_PIN_BASE64@@'))|ConvertFrom-Json
$pin=Add-FilePin $requestRecord
if($pin.stream.Length -gt 4194304){throw 'ACK_REQUEST_BOUND'}
$pin.stream.Position=0;$reader=[IO.StreamReader]::new($pin.stream,[Text.UTF8Encoding]::new($false,$true),$false,65536,$true)
try{$request=$reader.ReadToEnd()|ConvertFrom-Json}finally{$reader.Dispose()}
$releaseBytes=[Convert]::FromBase64String('@@RELEASE_BASE64@@')
$release=([Text.UTF8Encoding]::new($false,$true)).GetString($releaseBytes)|ConvertFrom-Json
if($request.operationId -cne '@@OPERATION@@' -or $release.collectorOperationId -cne $request.operationId -or $request.closeHold.releasePath -cne (Join-Path $request.operationRoot 'close-release.json') -or $release.collectorRequestSha256 -cne $requestRecord.sha256 -or $release.bootIdentifier -cne $request.context.bootIdentifier){throw 'ACK_FIXED_REQUEST_RELEASE_JOIN'}
$required='O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;'+$request.context.ordinarySid+')'
if($requestRecord.security.ownerSid -cne 'S-1-5-18' -or $requestRecord.security.sddl -cne $required){throw 'ACK_MACHINE_REQUEST_POLICY'}
foreach($record in $request.directoryPins){$p=@{record=$record;directory=$true;handle=[ScFacts]::OpenDirectory($record.path)};$script:C.pins.Add($p);Assert-Pin $p}
foreach($record in $request.filePins){[void](Add-FilePin $record)}
$roots=@($script:C.pins|Where-Object {$_.directory -and $_.record.path -ceq $request.operationRoot})
$rootPolicy='O:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;'+$request.context.ordinarySid+')'
if($roots.Count -ne 1 -or $roots[0].record.security.ownerSid -cne 'S-1-5-18' -or $roots[0].record.security.sddl -cne $rootPolicy){throw 'ACK_ROOT_MACHINE_POLICY'}
$readyRecord=([Text.UTF8Encoding]::new($false,$true)).GetString([Convert]::FromBase64String('@@READY_PIN_BASE64@@'))|ConvertFrom-Json
if($readyRecord.path -cne $request.closeHold.holdReadyPath -or $readyRecord.sha256 -cne $release.holdReadySha256){throw 'ACK_READY_FIXED_PATH_SHA'}
$ready=Add-FilePin $readyRecord
Assert-Id ([ScFacts]::Identity($ready.stream.SafeFileHandle,$false)) $release.holdReadyNativeIdentity
$token=[ScFacts]::Token()
if($token[0] -cne 'S-1-5-18' -or $token[1] -cne '0' -or $token[2] -cne '1' -or [ScFacts]::BootIdentifier() -cne $request.context.bootIdentifier){throw 'ACK_NATIVE_SYSTEM_BOOT'}
foreach($p in $script:C.pins){Assert-Pin $p;if(-not $p.directory){[void](Get-PinHash $p)}}
$script:C.releaseAttempted=$true
[ScFacts]::PublishMachineFile($request.closeHold.releasePath,$releaseBytes,$request.context.ordinarySid)
# Publication is one-way. Ordinary task liveness is deliberately not required after this exact release.
$script:C.published=[ScFacts]::OpenHeld($request.closeHold.releasePath);$published=$script:C.published
$publishedSecurity=[ScFacts]::Security($published.SafeFileHandle)
if($publishedSecurity[0] -cne 'S-1-5-18' -or $publishedSecurity[1] -cne $required -or $published.Length -ne $releaseBytes.Length){throw 'ACK_PUBLISHED_NATIVE_POLICY'}
$hash=[Security.Cryptography.SHA256]::Create();try{$sha=([BitConverter]::ToString($hash.ComputeHash($published))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
$expectedHash=[Security.Cryptography.SHA256]::Create();try{$expectedSha=([BitConverter]::ToString($expectedHash.ComputeHash($releaseBytes))).Replace('-','').ToLowerInvariant()}finally{$expectedHash.Dispose()}
if($sha -cne $expectedSha){throw 'ACK_PUBLISHED_BYTES'}
foreach($p in $script:C.pins){Assert-Pin $p;if(-not $p.directory){[void](Get-PinHash $p)}}
$r=[ordered]@{schemaVersion=1;state='collector-release-published';operationId=$request.operationId;requestSha256=$requestRecord.sha256;releasePath=$request.closeHold.releasePath;releaseSha256=$sha;releaseNativeIdentity=[ScFacts]::Identity($published.SafeFileHandle,$false);sourceClosing=$true;originalCollectorKnownClosed=$true;productMutation=$false}
[Console]::WriteLine(($r|ConvertTo-Json -Depth 8 -Compress))
}catch{Park-Original 'ACK_ORIGINAL_UNKNOWN' $_}

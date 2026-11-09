$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$script:C=[ordered]@{process=$null;started=$false;pins=[Collections.Generic.List[object]]::new();pumps=@();outputs=@();request=$null;root=$null;event=0;unknown=$null;self=$null;selfBirth=$null}

function Park-Original([string]$Reason,[object]$ErrorObject) {
$script:C.unknown=@{reason=$Reason;primary=$ErrorObject}
try{
if($null -ne $script:C.root){
Assert-OperationRootPolicy
$bytes=[Text.UTF8Encoding]::new($false).GetBytes((@{schemaVersion=1;state='unknown';reason=$Reason;operationId=$script:C.request.operationId;originalNamespaceRetained=$true;replayAllowed=$false}|ConvertTo-Json -Compress))
$notice=[IO.File]::Open((Join-Path $script:C.root 'task-owner-parked.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
try{$notice.Write($bytes,0,$bytes.Length);$notice.Flush($true)}finally{$notice.Dispose()}
}
}catch{$script:C.unknown.noticeError=$_}
while($true){[Threading.Thread]::Sleep(1000)}
}
function Write-OwnedEvent([string]$Kind,[object]$Value) {
try{
Assert-OperationRootPolicy
if($script:C.event -ge 8192){throw 'SC_EVENT_COUNT_BOUND'}
$data=[Text.UTF8Encoding]::new($false).GetBytes((@{schemaVersion=1;operationId=$script:C.request.operationId;ownerPid=$PID;ownerBirthFileTimeUtc=$script:C.selfBirth;ordinal=$script:C.event;kind=$Kind;value=$Value}|ConvertTo-Json -Depth 20 -Compress))
if($data.Length -gt 262144){throw 'SC_EVENT_BYTE_BOUND'}
$path=Join-Path $script:C.root ('task-event-{0:D6}-{1}.json' -f $script:C.event,$Kind);$script:C.event++
[ScFacts]::PublishMachineFile($path,$data,$script:C.request.context.ordinarySid)
}catch{Park-Original 'SC_EVENT_JOURNAL_UNKNOWN' $_}
}

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
$RequestPinBase64='@@REQUEST_PIN_BASE64@@'
$requestRecord=([Text.UTF8Encoding]::new($false,$true)).GetString([Convert]::FromBase64String($RequestPinBase64))|ConvertFrom-Json
$requestPin=Add-FilePin $requestRecord
if($requestPin.stream.Length -gt 4194304){throw 'SYSTEM_REQUEST_BOUND'}
$requestPin.stream.Position=0;$reader=[IO.StreamReader]::new($requestPin.stream,[Text.UTF8Encoding]::new($false,$true),$false,65536,$true)
try{$script:C.request=$reader.ReadToEnd()|ConvertFrom-Json}finally{$reader.Dispose()}
$r=$script:C.request;$script:C.root=$r.operationRoot
$requiredFilePolicy='O:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;'+$r.context.ordinarySid+')'
if($requestRecord.security.ownerSid -cne 'S-1-5-18' -or $requestRecord.security.sddl -cne $requiredFilePolicy){throw 'SC_MACHINE_REQUEST_FILE_POLICY'}
if($r.schemaVersion -ne 1 -or $r.operationId -cne '@@OPERATION@@' -or $r.ordinaryTaskOperationId -cne '@@ORDINARY_OPERATION@@' -or $r.scope -cne '@@SCOPE@@' -or $r.requestPath -cne $requestRecord.path){throw 'SYSTEM_REQUEST_OPERATION_JOIN'}
if(@($r.filePins).Count -gt 4096 -or @($r.directoryPins).Count -gt 1024){throw 'SYSTEM_PIN_CAPACITY'}
foreach($record in $r.directoryPins){$pin=@{record=$record;directory=$true;handle=[ScFacts]::OpenDirectory($record.path)};$script:C.pins.Add($pin);Assert-Pin $pin}
foreach($record in $r.filePins){[void](Add-FilePin $record)}
$expected=(@@MODULES_BASE64@@)
$expected=([Text.UTF8Encoding]::new($false,$true)).GetString([Convert]::FromBase64String($expected))|ConvertFrom-Json
if(@($r.modules.PSObject.Properties).Count -ne 9){throw 'SC_FIXED_SOURCE_ROLE_COUNT'}
foreach($property in $expected.PSObject.Properties){
$role=$property.Name;$record=$r.modules.$role
if($record.sha256 -cne $property.Value){throw 'SC_FIXED_SOURCE_DIGEST'}
$source=@($script:C.pins|Where-Object {-not $_.directory -and $_.record.path -ceq $record.path -and $_.record.sha256 -ceq $property.Value})
if($source.Count -ne 1){throw 'SC_FIXED_SOURCE_NATIVE_PIN'}
}
$gp=@($script:C.pins|Where-Object {-not $_.directory -and $_.record.path -ceq $r.modules.taskGuard.path -and $_.record.sha256 -ceq $r.modules.taskGuard.sha256})
if($gp.Count -ne 1 -or $gp[0].stream.Length -gt 32768){throw 'SC_FIXED_TASK_GUARD_SOURCE'}
[void](Get-PinHash $gp[0]);$gp[0].stream.Position=0
$gr=[IO.StreamReader]::new($gp[0].stream,[Text.UTF8Encoding]::new($false,$true),$false,65536,$true)
try{$gt=$gr.ReadToEnd()}finally{$gr.Dispose()}
$tokens=$null;$errors=$null;[void][Management.Automation.Language.Parser]::ParseInput($gt,[ref]$tokens,[ref]$errors)
if(@($errors).Count -ne 0){throw 'SC_FIXED_TASK_GUARD_PARSE'}
. ([scriptblock]::Create($gt))
Assert-Context
$exe=$r.pythonRuntime.interpreterPath;$worker=$r.modules.worker.path
if($r.pythonRuntime.version -cne '3.13.15' -or $r.pythonRuntime.architecture -cne 'amd64' -or (Join-Path $r.pythonRuntime.root 'python.exe') -cne $exe){throw 'SC_FIXED_PYTHON_ROLE'}
if(@($r.treePins).Count -ne 1 -or $r.treePins[0].role -cne 'python-runtime' -or $r.treePins[0].root -cne $r.pythonRuntime.root){throw 'SYSTEM_COMPLETE_PYTHON_TREE'}
foreach($name in @('python.exe','python313.dll','Lib/os.py','Lib/subprocess.py','Lib/threading.py','Lib/json/__init__.py','Lib/ctypes/__init__.py','DLLs/_ctypes.pyd')){if($name -cnotin @($r.treePins[0].files)){throw 'SYSTEM_PYTHON_REQUIRED_FILE'}}
if(@($script:C.pins|Where-Object {-not $_.directory -and $_.record.path -ceq $exe}).Count -ne 1 -or (Get-Item -LiteralPath $exe).VersionInfo.ProductVersion -notmatch '^3\.13\.15(?:\.0)?(?:\s|$)'){throw 'SYSTEM_ADMITTED_PYTHON_IMAGE'}
if([long]$r.rawStreamLimitBytes -lt 4096 -or [long]$r.rawStreamLimitBytes -gt 2097152){throw 'SYSTEM_RAW_BOUND'}
$arguments=@('-I','-S','-B',$worker,'--request',$requestRecord.path,'--request-sha256',$requestRecord.sha256,'--request-pin-base64',$RequestPinBase64)
$line=($arguments|ForEach-Object {ConvertTo-OwnedArgument ([string]$_)}) -join ' '
$complete=(ConvertTo-OwnedArgument $exe)+' '+$line
if(([Text.Encoding]::Unicode.GetByteCount($complete)/2+1) -gt 32767 -or [Text.Encoding]::UTF8.GetByteCount((@{path=$exe;arg=$arguments}|ConvertTo-Json -Depth 8 -Compress)) -gt 60000){throw 'SYSTEM_CHILD_COMMAND_BOUND'}
$script:C.self=[Diagnostics.Process]::GetCurrentProcess();$script:C.selfBirth=([ScFacts]::Birth($script:C.self.Handle)).ToString([Globalization.CultureInfo]::InvariantCulture)
Write-OwnedEvent 'submission-intent' @{scope=$r.scope;fileName=$exe;argv=$arguments;sourceAndRuntimePinsHeld=$true;nativeToken=[ScFacts]::Token();requestSha256=$requestRecord.sha256;replayAllowed=$false}
foreach($name in @('stdout','stderr')){$file=[IO.File]::Open((Join-Path $r.operationRoot ('collector-child.'+$name+'.raw')),[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read);$script:C.outputs+=,$file}
Assert-Context
$start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$exe;$start.Arguments=$line;$start.WorkingDirectory=$r.operationRoot;$start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
foreach($name in @('DISPLAY','WAYLAND_DISPLAY','JAVA_TOOL_OPTIONS','_JAVA_OPTIONS','JDK_JAVA_OPTIONS','PYTHONPATH','PYTHONHOME')){$start.EnvironmentVariables.Remove($name)}
$script:C.process=[Diagnostics.Process]::new();$script:C.process.StartInfo=$start
if(-not $script:C.process.Start()){throw 'SYSTEM_ORIGINAL_START_FALSE'}
$script:C.started=$true
$script:C.pumps+=,[ScRawPump]::new($script:C.process.StandardOutput.BaseStream,$script:C.outputs[0],[long]$r.rawStreamLimitBytes)
$script:C.pumps+=,[ScRawPump]::new($script:C.process.StandardError.BaseStream,$script:C.outputs[1],[long]$r.rawStreamLimitBytes)
foreach($pump in $script:C.pumps){$pump.Start()}
$script:C.childBirth=([ScFacts]::Birth($script:C.process.Handle)).ToString([Globalization.CultureInfo]::InvariantCulture)
Write-OwnedEvent 'submitted' @{pid=$script:C.process.Id;birthFileTimeUtc=$script:C.childBirth;originalHandleRetained=$true}
Wait-Child
Assert-Context
foreach($pin in $script:C.pins){if(-not $pin.directory){[void](Get-PinHash $pin)}}
$captures=@()
for($i=0;$i -lt 2;$i++){
$output=$script:C.outputs[$i];$output.Flush($true)
if($output.Length -ne $script:C.pumps[$i].Bytes -or $output.Length -gt $r.rawStreamLimitBytes){throw 'SYSTEM_RAW_FULL_COUNT'}
$output.Position=0;$bytes=New-Object byte[] ([int]$output.Length);$offset=0
while($offset -lt $bytes.Length){$count=$output.Read($bytes,$offset,$bytes.Length-$offset);if($count -le 0){throw 'SYSTEM_RAW_EXACT_READ'};$offset+=$count}
$h=[Security.Cryptography.SHA256]::Create();try{$digest=([BitConverter]::ToString($h.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}
$captures+=,@{name=@('stdout','stderr')[$i];sizeBytes=$bytes.Length;sha256=$digest;base64=[Convert]::ToBase64String($bytes);eof=$script:C.pumps[$i].Eof;nativeIdentity=[ScFacts]::Identity($output.SafeFileHandle,$false)}
}
if($script:C.process.ExitCode -ne 0 -or $captures[1].sizeBytes -ne 0){Park-Original 'SC_CHILD_FAILURE' @{exitCode=$script:C.process.ExitCode;captures=$captures}}
$r=[ordered]@{schemaVersion=1;state='collector-closed';operationId=$r.operationId;ordinaryTaskOperationId=$r.ordinaryTaskOperationId;scope=$r.scope;collectorSourceSha256=$r.modules.collector.sha256;requestSha256=$requestRecord.sha256;requestNativeIdentity=$requestRecord.nativeIdentity;worker=@{pid=$script:C.process.Id;birthFileTimeUtc=$script:C.childBirth;image=$exe;sessionId=$script:C.process.SessionId;exitCode=$script:C.process.ExitCode;bothEof=$true;originalHandleRetained=$true};captures=$captures;sourceClosing=$true;productMutation=$false}
Write-OwnedEvent 'terminal' $r
Assert-Context
[Console]::WriteLine(($r|ConvertTo-Json -Depth 8 -Compress))
}catch{Park-Original 'SC_ORIGINAL_UNKNOWN' $_}

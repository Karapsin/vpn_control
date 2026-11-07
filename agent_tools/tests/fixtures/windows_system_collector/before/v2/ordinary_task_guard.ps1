
function Assert-OperationRootPolicy {
 $root=@($script:C.pins|Where-Object {$_.directory -and $_.record.path -ceq $script:C.request.operationRoot})
 $sddl='O:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;'+$script:C.request.context.ordinarySid+')'
 if($root.Count -ne 1 -or $root[0].record.security.ownerSid -cne 'S-1-5-18' -or $root[0].record.security.sddl -cne $sddl){throw 'SC_MACHINE_WRITER_ROOT_POLICY'}
 Assert-Pin $root[0]
}
function Read-PinnedJson([object]$Record) {
 $pins=@($script:C.pins|Where-Object {-not $_.directory -and $_.record.path -ceq $Record.path -and $_.record.sha256 -ceq $Record.sha256})
 if($pins.Count -ne 1 -or $pins[0].stream.Length -gt 4194304){throw 'SC_ORIGINAL_TASK_DOCUMENT_PIN'}
 $pin=$pins[0];[void](Get-PinHash $pin);$pin.stream.Position=0
 $reader=[IO.StreamReader]::new($pin.stream,[Text.UTF8Encoding]::new($false,$true),$false,65536,$true)
 try{$value=$reader.ReadToEnd()|ConvertFrom-Json}finally{$reader.Dispose()}
 Assert-Pin $pin;return $value
}
function Assert-OriginalTask {
 $r=$script:C.request;$t=$r.ordinaryTask;$c=$r.context
 if($null -eq $script:C.ordinaryProcesses){
  $script:C.ordinaryProcesses=[Collections.Generic.List[object]]::new()
  foreach($role in @('owner','worker')){
   $expected=$t.($role+'Actor');$holder=@{role=$role;expected=$expected;process=$null};$script:C.ordinaryProcesses.Add($holder)
   $holder.process=[Diagnostics.Process]::GetProcessById([int]$expected.pid);[void]$holder.process.Handle
  }
 }
 foreach($holder in $script:C.ordinaryProcesses){
  $p=$holder.process;$e=$holder.expected
  if($p.HasExited -or ([ScFacts]::Birth($p.Handle)).ToString([Globalization.CultureInfo]::InvariantCulture) -cne [string]$e.creationFileTime -or $p.SessionId -ne $c.ordinarySessionId -or $p.MainModule.FileName -ine $e.image){throw 'SC_ORIGINAL_TASK_NATIVE_GENERATION'}
  $token=[ScFacts]::ProcessToken($p.Handle)
  if($token[0] -cne $c.ordinarySid -or $token[1] -cne [string]$c.ordinarySessionId -or $token[2] -cne '0' -or $token[3] -cne '1'){throw 'SC_ORIGINAL_TASK_ORDINARY_TOKEN'}
  if((Get-FileHash -LiteralPath $e.image -Algorithm SHA256).Hash.ToLowerInvariant() -cne $e.sha256){throw 'SC_ORIGINAL_TASK_IMAGE_DIGEST'}
  $row=@(Get-CimInstance Win32_Process -Filter ('ProcessId='+[string]$e.pid))
  if($row.Count -ne 1){throw 'SC_ORIGINAL_TASK_CURRENT_COMMANDLINE'}
  $argv=@($t.($holder.role+'Argv'));$tail=(@($argv|Select-Object -Skip 1)|ForEach-Object {ConvertTo-OwnedArgument ([string]$_)}) -join ' '
  $expectedLine=(ConvertTo-OwnedArgument ([string]$argv[0]))+' '+$tail
  $quoted='"'+[string]$argv[0]+'" '+$tail
  if($row[0].CommandLine -cne $expectedLine -and $row[0].CommandLine -cne $quoted){throw 'SC_ORIGINAL_TASK_EXACT_COMMANDLINE'}
  if($holder.role -ceq 'worker' -and $row[0].ParentProcessId -ne $t.ownerActor.pid){throw 'SC_ORIGINAL_TASK_WORKER_PARENT'}
  if($p.HasExited -or ([ScFacts]::Birth($p.Handle)).ToString([Globalization.CultureInfo]::InvariantCulture) -cne [string]$e.creationFileTime){throw 'SC_ORIGINAL_TASK_CHANGED_DURING_CIM_READ'}
 }
 $b=Read-PinnedJson $t.bootstrapRequestPin;$w=Read-PinnedJson $t.workerRequestPin
 foreach($doc in @($b,$w)){
  if($doc.operationId -cne $r.ordinaryTaskOperationId -or $doc.context.bootIdentifier -cne $c.bootIdentifier -or $doc.context.machineGuid -cne $c.machineGuid -or $doc.context.ordinarySid -cne $c.ordinarySid -or $doc.context.ordinarySessionId -ne $c.ordinarySessionId){throw 'SC_ORIGINAL_TASK_REQUEST_CONTEXT'}
 }
 if($b.operationRoot -cne $w.operationRoot -or $w.workspace -cne $r.collectorRequest.context.workspace -or $b.bootstrap.mode -cne 'python-worker' -or $b.bootstrap.pythonPath -cne $t.workerActor.image -or $b.bootstrap.workerPath -cne $t.workerSourcePin.path -or $b.bootstrap.workerRequestPath -cne $t.workerRequestPin.path -or $b.bootstrap.workerRequestSha256 -cne $t.workerRequestPin.sha256){throw 'SC_ORIGINAL_TASK_SOURCE_REQUEST_JOIN'}
}
function Assert-Context {
$c=$script:C.request.context;$token=[ScFacts]::Token()
if($token[0] -cne 'S-1-5-18' -or $token[1] -cne '0' -or $token[2] -cne '1'){throw 'SC_TOKEN_SESSION'}
if(-not [Environment]::Is64BitProcess -or $PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5){throw 'SC_PS51_AMD64'}
if([ScFacts]::BootIdentifier() -cne $c.bootIdentifier){throw 'SC_NATIVE_BOOT'}
if((Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture) -cne $c.bootFileTimeUtc){throw 'SC_CIM_BOOT'}
if((Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid -ine $c.machineGuid -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -ine $c.hardwareUuid){throw 'SC_MACHINE_HARDWARE'}
Assert-OperationRootPolicy;Assert-OriginalTask
foreach($pin in $script:C.pins){Assert-Pin $pin}
foreach($tree in $script:C.request.treePins){
$actual=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$todo=[Collections.Generic.Stack[IO.DirectoryInfo]]::new();$todo.Push([IO.DirectoryInfo]::new($tree.root))
while($todo.Count -gt 0){
$directory=$todo.Pop();if(($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){throw 'SYSTEM_TREE_DIRECTORY_REPARSE'}
foreach($item in $directory.GetFileSystemInfos()){
if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){throw 'SYSTEM_TREE_ENTRY_REPARSE'}
if($item -is [IO.DirectoryInfo]){$todo.Push($item)}else{
$relative=$item.FullName.Substring($tree.root.Length+1).Replace('\','/')
if(-not $actual.Add($relative) -or $actual.Count -gt 4096){throw 'SYSTEM_TREE_ALIAS_OR_BOUND'}
if(@($script:C.pins|Where-Object {-not $_.directory -and $_.record.path -ceq $item.FullName}).Count -ne 1){throw 'SYSTEM_TREE_FILE_NOT_PINNED'}
}
}
}
if(-not $actual.SetEquals([string[]]$tree.files)){throw 'SYSTEM_TREE_MEMBERSHIP_CHANGED'}
}
}
function ConvertTo-OwnedArgument([AllowEmptyString()][string]$Argument) {
if($Argument.Length -eq 0){return '""'}
if($Argument -notmatch '[\s"]'){return $Argument}
$out=[Text.StringBuilder]::new();[void]$out.Append('"');$slashes=0
foreach($character in $Argument.ToCharArray()){
if($character -eq '\'){$slashes++}
elseif($character -eq '"'){[void]$out.Append('\',2*$slashes+1);[void]$out.Append('"');$slashes=0}
else{if($slashes -gt 0){[void]$out.Append('\',$slashes)};[void]$out.Append($character);$slashes=0}
}
if($slashes -gt 0){[void]$out.Append('\',2*$slashes)};[void]$out.Append('"');return $out.ToString()
}
function Wait-Child {
$next=[DateTime]::UtcNow.AddSeconds(30)
while($true){
foreach($pump in $script:C.pumps){if($null -ne $pump.Error){Park-Original 'SC_RAW_CAPTURE_UNKNOWN' $pump.Error}}
try{$exited=$script:C.process.WaitForExit(100)}catch{Park-Original 'SC_ORIGINAL_HANDLE_UNKNOWN' $_}
if($exited -and $script:C.pumps[0].Eof -and $script:C.pumps[1].Eof){return}
if([DateTime]::UtcNow -ge $next){Write-OwnedEvent 'pending' @{pid=$script:C.process.Id;birthFileTimeUtc=$script:C.childBirth;stdoutEof=$script:C.pumps[0].Eof;stderrEof=$script:C.pumps[1].Eof;originalHandleRetained=$true;replayAllowed=$false};$next=[DateTime]::UtcNow.AddSeconds(30)}
[Threading.Thread]::Sleep(100)
}
}

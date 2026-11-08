$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
@@INPUT@@
@@ASSERTIONS@@
@@POLICY_VALIDATOR@@
$script:P=[ordered]@{pins=[Collections.Generic.List[object]]::new();folder=$null;registered=$false;launchConsumed=$false}
function N($value,$code){if(-not $value){throw $code}}
function Hash-Bytes([byte[]]$raw){$h=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($h.ComputeHash($raw))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
function Open-Pin($record,$directory){
 $p=@{record=$record;directory=$directory;handle=$null;stream=$null};$script:P.pins.Add($p)
 if($directory){$p.handle=[OrdinaryNativeFacts]::OpenDirectory($record.path);Assert-Pin $p}else{$p.stream=[OrdinaryNativeFacts]::OpenHeld($record.path);[void](Get-PinHash $p)}
 return $p
}
function Read-PinBytes($p,$limit){
 [void](Get-PinHash $p);N ($p.stream.Length -le $limit) 'RUN_PIN_BOUND'
 $p.stream.Position=0;$b=New-Object byte[] ([int]$p.stream.Length);$at=0
 while($at -lt $b.Length){$n=$p.stream.Read($b,$at,$b.Length-$at);N ($n -gt 0) 'RUN_PIN_SHORT_READ';$at+=$n}
 return ,$b
}
function Read-Shared([string]$path){
 $f=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
 try{
  N ($f.Length -le 67108864) 'RUN_SHARED_BOUND'
  $b=New-Object byte[] ([int]$f.Length);$at=0
  while($at -lt $b.Length){$n=$f.Read($b,$at,$b.Length-$at);N ($n -gt 0) 'RUN_SHARED_SHORT_READ';$at+=$n}
  return ,$b
 }finally{$f.Dispose()}
}
function Guard-Full {
 N ([OrdinaryNativeFacts]::BootIdentifier() -ceq $m.context.bootIdentifier) 'RUN_BOOT'
 N ((Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid -ieq $m.context.machineGuid) 'RUN_MACHINE'
 foreach($p in $script:P.pins){if($p.directory){Assert-Pin $p}else{[void](Get-PinHash $p)}}
}
function Sid-Of([string]$value){
 if($value -cmatch '\AS-1-'){return ([Security.Principal.SecurityIdentifier]::new($value)).Value}
 return ([Security.Principal.NTAccount]::new($value)).Translate([Security.Principal.SecurityIdentifier]).Value
}
function Is-TaskAbsent($record){
 $x=$record.Exception
 while($null -ne $x){if($x.HResult -eq -2147024894){return $true};$x=$x.InnerException}
 return $false
}
function Read-Status([string]$root,[int]$number){
 $names=@(Get-ChildItem -LiteralPath $root -File -Force|ForEach-Object {$_.Name})
 $taskEvents=@($names|Where-Object {$_ -cmatch '\Atask-event-[0-9]{6}-[0-9A-Za-z_.-]+\.json\z'}|Sort-Object)
 $workerEvents=@($names|Where-Object {$_ -cmatch '\Aevent-[0-9]{6}-[0-9A-Za-z_.-]+\.json\z'}|Sort-Object)
 $kinds=@($workerEvents|Select-Object -Last 16|ForEach-Object {($_ -creplace '\Aevent-[0-9]{6}-','') -creplace '\.json\z',''})
 return [ordered]@{schemaVersion=1;operationId=$m.operationId;poll=$number;lastTaskOrdinal=($taskEvents.Count-1);lastEventOrdinal=($workerEvents.Count-1);pendingKinds=$kinds;parkedFiles=@($names|Where-Object {$_ -ceq 'owner-parked.json' -or $_ -ceq 'task-owner-parked.json'})}
}
function Write-Status($value){
 $path=Join-Path $m.workspace 'scenario-status.json';$temporary=$path+'.new'
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($value|ConvertTo-Json -Depth 4 -Compress))
 $file=[IO.File]::Open($temporary,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
 if([IO.File]::Exists($path)){[IO.File]::Replace($temporary,$path,[NullString]::Value)}else{[IO.File]::Move($temporary,$path)}
}
function Read-FirstEvent([string]$root){
 $found=@(Get-ChildItem -LiteralPath $root -File -Filter 'task-event-000000-*.json')
 if($found.Count -ne 1){return $null}
 try{return ([Text.UTF8Encoding]::new($false,$true).GetString((Read-Shared $found[0].FullName))|ConvertFrom-Json)}catch{return $null}
}
# The owner and its child carry this operation on their command line, in their source and request paths.
function Count-OperationProcesses {
 return @(Get-CimInstance Win32_Process -OperationTimeoutSec 30|Where-Object {([string]$_.CommandLine).Contains($m.operationId)}).Count
}
$r=$null
try{
@@NATIVE@@
 N ($m.schemaVersion -eq 1 -and @('qualification','python-install','python-worker') -ccontains $m.mode) 'RUN_CLOSED_MODE'
 N ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ceq 'S-1-5-18' -and [IntPtr]::Size -eq 8) 'RUN_SYSTEM'
 $requestPin=Open-Pin $m.taskRequestPin $false
 $q=[Text.UTF8Encoding]::new($false,$true).GetString((Read-PinBytes $requestPin 4194304))|ConvertFrom-Json
 N (($q.context|ConvertTo-Json -Compress) -ceq ($m.context|ConvertTo-Json -Compress) -and $q.operationId -ceq $m.operationId -and $q.bootstrap.mode -ceq $m.mode) 'RUN_REQUEST_BINDING'
 foreach($record in @($q.directoryPins)){[void](Open-Pin $record $true)}
 foreach($record in @($q.filePins)){[void](Open-Pin $record $false)}
 Guard-Full
 $root=$q.operationRoot;$name=$m.taskName
 N ($name -ceq ('VpnControlOrdinary-'+$q.operationId)) 'RUN_TASK_NAME'
 $service=New-Object -ComObject 'Schedule.Service';$service.Connect();$folder=$service.GetFolder('\');$script:P.folder=$folder
 $present=$null;try{$present=$folder.GetTask($name)}catch{N (Is-TaskAbsent $_) 'RUN_TASK_ABSENCE_OBSERVATION'};N ($null -eq $present) 'RUN_TASK_EXISTS'
 $definition=$service.NewTask(0);$definition.XmlText=$m.taskXml
 $script:P.registered=$true
 $registered=$folder.RegisterTaskDefinition($name,$definition,2,$m.context.ordinarySid,$null,3,$null)
 $observed=Get-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction Stop
 Assert-OrdinaryTaskPolicy -Xml ([string]$registered.Xml) -CmdletSid (Sid-Of ([string]$observed.Principal.UserId)) -CmdletRunLevel ([string]$observed.Principal.RunLevel) -CmdletLogonType ([string]$observed.Principal.LogonType) -ComSid (Sid-Of ([string]$registered.Definition.Principal.UserId)) -ComRunLevel ([int]$registered.Definition.Principal.RunLevel) -ComLogonType ([int]$registered.Definition.Principal.LogonType)
 Guard-Full
 $script:P.launchConsumed=$true
 $running=$registered.Run($null)
 $instance=[string]$running.InstanceGuid
 $until=[DateTime]::UtcNow.AddSeconds([double]$m.deadlineSeconds);$nextStatus=[DateTime]::MinValue
 $parent=$null;$start=$null;$birth=$null;$commandMatched=$false;$enginePid=0;$polls=0;$statusFailures=0;$end=$null;$parked=@();$lastStatus=$null
 while($null -eq $end){
  $now=[DateTime]::UtcNow
  if($now -ge $nextStatus){
   N ([OrdinaryNativeFacts]::BootIdentifier() -ceq $m.context.bootIdentifier) 'RUN_BOOT_WAIT'
   $polls++;$lastStatus=Read-Status $root $polls
   try{Write-Status $lastStatus}catch{$statusFailures++}
   $parked=@($lastStatus.parkedFiles)
   if($parked.Count -gt 0){$end='parked';break}
   if($null -eq $parent -and $polls -ge 2 -and [int]$registered.GetInstances(0).Count -eq 0){$end='ended';break}
   $nextStatus=$now.AddSeconds(5)
  }
  if($now -ge $until){$end='deadline';break}
  if($null -eq $parent){
   if($null -eq $start){
    $start=Read-FirstEvent $root
    if($null -eq $start){[Threading.Thread]::Sleep(200);continue}
    N ($start.operationId -ceq $q.operationId -and $start.ordinal -eq 0 -and [int]$start.ownerPid -gt 0) 'RUN_FIRST_EVENT'
   }
   try{$parent=Get-Process -Id ([int]$start.ownerPid);$null=$parent.Handle}catch{$parent=$null}
   if($null -eq $parent){$end='ended';break}
   $birth=([OrdinaryNativeFacts]::Birth($parent.Handle)).ToString([Globalization.CultureInfo]::InvariantCulture)
   N ($null -eq $start.ownerBirthFileTimeUtc -or [string]$start.ownerBirthFileTimeUtc -ceq $birth) 'RUN_OWNER_IDENTITY'
   # A refused owner exits at once and an exited process has no image to read. That proves nothing:
   # the retained handle still gives its exit code, so the closing path reports a known failure.
   $image=$null;try{$image=[string]$parent.Path}catch{$image=$null}
   if(-not $parent.HasExited){
    N ($image -ieq 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe') 'RUN_OWNER_IDENTITY'
    # A missed read leaves the command line unmatched: a known failure, not an unknown outcome.
    $line='';try{$cim=Get-CimInstance Win32_Process -Filter ('ProcessId='+$parent.Id) -OperationTimeoutSec 5;if($null -ne $cim){$line=[string]$cim.CommandLine}}catch{$line=''}
    $commandMatched=$line.EndsWith(' '+$m.taskArguments,[StringComparison]::Ordinal)
   }
   try{$running.Refresh();$enginePid=[int]$running.EnginePID}catch{$enginePid=0}
  }
  if($parent.WaitForExit(1000)){$end='exited'}
 }
 if($end -ceq 'exited' -or $end -ceq 'ended'){
  # Ended means no owner was seen to exit: an empty instance list or a failed lookup is not proof by itself.
  if($end -ceq 'ended'){N ((Count-OperationProcesses) -eq 0) 'RUN_OPERATION_PROCESS_ALIVE'}
  $settle=[DateTime]::UtcNow.AddSeconds(30)
  while([int]$registered.GetInstances(0).Count -gt 0){N ([DateTime]::UtcNow -lt $settle) 'RUN_INSTANCE_STILL_RUNNING';[Threading.Thread]::Sleep(200)}
  $ownerExit=$null;if($null -ne $parent){$parent.WaitForExit();$ownerExit=[int]$parent.ExitCode}
  $lastResult=[int]$registered.LastTaskResult
  Guard-Full
  $rows=[Collections.Generic.List[object]]::new();$terminal=$null;$refused=$false;$ordinal=0
  foreach($file in @(Get-ChildItem -LiteralPath $root -File -Filter 'task-event-*.json'|Sort-Object Name)){
   N ($ordinal -lt 512) 'RUN_EVENT_BOUND'
   $raw=Read-Shared $file.FullName;$value=[Text.UTF8Encoding]::new($false,$true).GetString($raw)|ConvertFrom-Json
   N ($value.operationId -ceq $q.operationId -and $value.ordinal -eq $ordinal) 'RUN_EVENT_CHAIN'
   $rows.Add([ordered]@{name=$file.Name;bytes=$raw.Length;sha256=(Hash-Bytes $raw);kind=[string]$value.kind});$ordinal++
   if($value.kind -ceq 'terminal'){$terminal=$value}
   if($value.kind -ceq 'refused-before-native-start'){$refused=$true}
  }
  # A journal that opened and shows neither means an owner that died: its child may be live, so nothing is deleted.
  N ($rows.Count -eq 0 -or $null -ne $terminal -or $refused) 'RUN_CHILD_OUTCOME_UNKNOWN'
  $streams=[Collections.Generic.List[object]]::new()
  if($null -ne $terminal){
   foreach($role in @('stdout','stderr')){
    $stream=Read-Shared (Join-Path $root ('task-child.'+$role+'.raw'));$digest=Hash-Bytes $stream
    $captured=@($terminal.value.rawStreams|Where-Object {$_.name -ceq $role})
    N ($captured.Count -eq 1 -and $captured[0].eof -and $captured[0].sizeBytes -eq $stream.Length -and $captured[0].sha256 -ceq $digest) 'RUN_RAW_STREAM'
    $streams.Add([ordered]@{name=$role;bytes=$stream.Length;sha256=$digest})
   }
  }
  $workers=@(Get-ChildItem -LiteralPath $root -File -Filter 'event-*.json').Count
  $folder.DeleteTask($name,0);$deleted=$false
  try{$null=$folder.GetTask($name)}catch{N (Is-TaskAbsent $_) 'RUN_TASK_DELETE_OBSERVATION';$deleted=$true}
  N $deleted 'RUN_TASK_NOT_DELETED'
  Guard-Full
  $r=[ordered]@{schemaVersion=1;state='task-finished';operationId=$q.operationId;taskName=$name;instanceGuid=$instance;enginePid=$enginePid;ownerPid=$(if($null -eq $start){$null}else{[int]$start.ownerPid});ownerBirthFileTimeUtc=$birth;ownerExitCode=$ownerExit;lastTaskResult=$lastResult;terminalExitCode=$(if($null -eq $terminal){$null}else{[int]$terminal.value.exitCode});commandLineMatched=$commandMatched;events=@($rows.ToArray());rawStreams=@($streams.ToArray());workerEvents=$workers;taskDeleted=$deleted;polls=$polls;statusFailures=$statusFailures;parkedFiles=@();sourceClosing=$true;productOperation=$false}
 }else{
  # A parked owner or a passed row deadline: report and touch nothing. The task,
  # its owner and every file stay exactly as they are for reading the original.
  $r=[ordered]@{schemaVersion=1;state=$(if($end -ceq 'parked'){'owner-parked'}else{'deadline'});operationId=$q.operationId;taskName=$name;instanceGuid=$instance;enginePid=$enginePid;ownerPid=$(if($null -eq $start){$null}else{[int]$start.ownerPid});polls=$polls;statusFailures=$statusFailures;parkedFiles=$parked;lastStatus=$lastStatus;taskDeleted=$false;sourceClosing=$false;productOperation=$false}
 }
}catch{
 $code=[string]$_.Exception.Message;if($code.Length -gt 200){$code=$code.Substring(0,200)}
 $unknown=$script:P.launchConsumed
 if(-not $unknown -and $script:P.registered){
  # Registered and never run: nothing started, so the task can go and this stays a refusal.
  try{$script:P.folder.DeleteTask($m.taskName,0)}catch{if(-not (Is-TaskAbsent $_)){$unknown=$true}}
 }
 $r=[ordered]@{schemaVersion=1;state=$(if($unknown){'post-launch-unknown'}else{'refused-before-launch'});operationId=$m.operationId;code=$code;taskDeleted=$false;sourceClosing=$false;productOperation=$false}
}
foreach($p in $script:P.pins){try{if($p.directory){$p.handle.Dispose()}elseif($null -ne $p.stream){$p.stream.Dispose()}}catch{}}
[Console]::WriteLine(($r|ConvertTo-Json -Depth 8 -Compress))

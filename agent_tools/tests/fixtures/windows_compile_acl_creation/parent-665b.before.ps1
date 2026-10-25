# NEW finite compile-only parent. No GUI, input, pipes, login or source-selected command.
# Configuration/native payload are fixed by the reviewed source builder.
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$clock=[Diagnostics.Stopwatch]::StartNew()
$config=__FIXED_CONFIG__
$nativeBase64='__FIXED_NATIVE_BASE64__'
$childTemplateBase64='__FIXED_CHILD_BASE64__'
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$self=[Diagnostics.Process]::GetCurrentProcess()
if($sid -cne 'S-1-5-18' -or $self.SessionId -ne 0){throw 'COMPILE_PARENT_SYSTEM_SESSION'}
$family=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'VPNControlCompileOnly-v1'
$machineRoot=Join-Path $family $config.machine
$job=Join-Path $machineRoot $config.operationId
function PrivateDirectory([string]$path){
 if(Test-Path -LiteralPath $path){$a=Get-Acl -LiteralPath $path;if(-not $a.AreAccessRulesProtected -or $a.Owner -notin @('NT AUTHORITY\SYSTEM','S-1-5-18') -or ((Get-Item -Force -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'COMPILE_DIRECTORY_CUSTODY'};foreach($r in $a.Access){if($r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-18' -or $r.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow){throw 'COMPILE_DIRECTORY_ACL'}};return}
 $a=[Security.AccessControl.DirectorySecurity]::new();$a.SetSecurityDescriptorSddlForm('O:SYG:SYD:P(A;OICI;FA;;;SY)');[IO.Directory]::CreateDirectory($path,$a)|Out-Null
}
function Save([string]$path,$value){
 $bytes=[Text.Encoding]::UTF8.GetBytes(($value|ConvertTo-Json -Depth 16 -Compress));$temp=$path+'.pending-'+[guid]::NewGuid().ToString('N');$f=[IO.FileStream]::new($temp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try{$a=[Security.AccessControl.FileSecurity]::new();$a.SetSecurityDescriptorSddlForm('O:SYG:SYD:P(A;;FA;;;SY)');$f.SetAccessControl($a);$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
 [IO.File]::Move($temp,$path)
}
function Hash([byte[]]$bytes){$h=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($h.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
function NeedBudget {if($clock.Elapsed.TotalSeconds -ge $config.budgetSeconds){throw 'COMPILE_ABSOLUTE_DEADLINE'}}
function ReadFixed([string]$path){$f=[IO.FileStream]::new($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);try{if($f.Length -le 0 -or $f.Length -gt 65536){throw 'COMPILE_RECORD_BOUND'};$b=New-Object byte[] ([int]$f.Length);$n=0;while($n -lt $b.Length){$k=$f.Read($b,$n,$b.Length-$n);if($k -le 0){throw 'COMPILE_RECORD_SHORT'};$n+=$k};return ([Text.Encoding]::UTF8.GetString($b)|ConvertFrom-Json)}finally{$f.Dispose()}}
PrivateDirectory $family;PrivateDirectory $machineRoot;PrivateDirectory (Join-Path $machineRoot 'admissions')
# Early parent identity exists before CIM, child launch or ANY Add-Type.
$parent=[ordered]@{pid=$self.Id;birth=$self.StartTime.ToUniversalTime().ToFileTimeUtc().ToString();session=$self.SessionId;sid=$sid;image=$self.MainModule.FileName;sourceSha256=$VcEarlySourceSha}
$index=Join-Path (Join-Path $machineRoot 'admissions') ($config.operationId+'.json')
Save $index ([ordered]@{schemaVersion=1;purpose='compile-only';config=$config;parent=$parent;nativeSha256=$config.nativeSha256;inputAuthority=$false;replayAllowed=$false})
# Missing/partial/foreign history is never deleted or relabelled as idle.
if(Test-Path -LiteralPath $job){throw 'COMPILE_ORIGINAL_ALREADY_ADMITTED'}
PrivateDirectory $job
Save (Join-Path $job 'parent.json') ([ordered]@{operationId=$config.operationId;parent=$parent;sourceSha256=$VcEarlySourceSha;inputAuthority=$false})
NeedBudget
$machine=Get-CimInstance Win32_ComputerSystemProduct -OperationTimeoutSec 5
$os=Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 5
if(([guid]$machine.UUID).ToString('D') -cne $config.machine -or $os.LastBootUpTime.ToUniversalTime().ToString('o') -cne $config.boot){throw 'COMPILE_GUEST_EPOCH'}
NeedBudget
$native=[Convert]::FromBase64String($nativeBase64)
if((Hash $native) -cne $config.nativeSha256){throw 'COMPILE_NATIVE_SOURCE'}
$sourceFile=Join-Path $job 'native.cs'
$stage=[IO.FileStream]::new($sourceFile,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
$acl=[Security.AccessControl.FileSecurity]::new();$acl.SetSecurityDescriptorSddlForm('O:SYG:SYD:P(A;;FA;;;SY)');try{$stage.SetAccessControl($acl);$stage.Write($native,0,$native.Length);$stage.Flush($true)}finally{$stage.Dispose()}
$source=[IO.FileStream]::new($sourceFile,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
$process=$null;$stdout=$null;$stderr=$null;$childKnown=$false;$complete=$false
try{
 $childText=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($childTemplateBase64))
 $childSource=$childText.Replace('__CHILD_CONFIG__',($config|ConvertTo-Json -Depth 12 -Compress)).Replace('__CHILD_ROOT_BASE64__',[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($job)))
 $childBytes=[Text.Encoding]::UTF8.GetBytes($childSource);$childSha=Hash $childBytes
 Save (Join-Path $job 'child-launch.intent.json') ([ordered]@{operationId=$config.operationId;parent=$parent;childSourceSha256=$childSha;nativeSha256=$config.nativeSha256;replayAllowed=$false})
 $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=Join-Path ([Environment]::GetFolderPath('Windows')) 'System32\WindowsPowerShell\v1.0\powershell.exe';$start.Arguments='-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$s=[Console]::In.ReadToEnd(); & ([ScriptBlock]::Create($s))"';$start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
 NeedBudget;$process=[Diagnostics.Process]::new();$process.StartInfo=$start
 if(-not $process.Start()){throw 'COMPILE_CHILD_LAUNCH_UNKNOWN'}
 $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
 $actor=[ordered]@{pid=$process.Id;birth=$process.StartTime.ToUniversalTime().ToFileTimeUtc().ToString();session=$process.SessionId;image=$process.MainModule.FileName;sourceSha256=$childSha}
 if($actor.session -ne 0 -or $actor.image -ine $start.FileName){throw 'COMPILE_CHILD_ACTOR'}
 Save (Join-Path $job 'child.actor.json') $actor;$childKnown=$true
 # Child receives fixed source only after its original actual identity is saved.
 $write=$process.StandardInput.WriteAsync($childSource)
 while(-not $write.IsCompleted){NeedBudget;[Threading.Thread]::Sleep(10)}
 $write.GetAwaiter().GetResult();$process.StandardInput.Close()
 $readyPath=Join-Path $job 'child.ready.json'
 while(-not (Test-Path -LiteralPath $readyPath)){NeedBudget;if($process.HasExited){throw 'COMPILE_CHILD_EARLY_EXIT'};[Threading.Thread]::Sleep(10)}
 $ready=ReadFixed $readyPath
 if($ready.operationId -cne $config.operationId -or $ready.pid -ne $actor.pid -or $ready.birth -cne $actor.birth -or $ready.sid -cne 'S-1-5-18' -or $ready.session -ne 0 -or $ready.sourceSha256 -cne $childSha -or $ready.nativeSha256 -cne $config.nativeSha256 -or $ready.releaseNonce -cne $config.releaseNonce){throw 'COMPILE_CHILD_READY_IDENTITY'}
 $actor.Add('sid',$ready.sid);Save (Join-Path $job 'child.verified.json') $actor
 NeedBudget
 # Exactly one release. Lost acknowledgement cannot create another child.
 Save (Join-Path $job 'release.json') ([ordered]@{operationId=$config.operationId;parent=$parent;child=$actor;releaseNonce=$config.releaseNonce;nativeSha256=$config.nativeSha256;replayAllowed=$false})
 while(-not $process.WaitForExit(25)){NeedBudget}
 while(-not ($stdout.IsCompleted -and $stderr.IsCompleted)){NeedBudget;[Threading.Thread]::Sleep(10)}
 $out=[Text.Encoding]::UTF8.GetBytes($stdout.GetAwaiter().GetResult());$err=[Text.Encoding]::UTF8.GetBytes($stderr.GetAwaiter().GetResult())
 # Compiler diagnostics are public-source-only and are retained BEFORE gates.
 foreach($role in @('stdout','stderr')){$raw=if($role -eq 'stdout'){$out}else{$err};$f=[IO.FileStream]::new((Join-Path $job ($role+'.bin')),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.SetAccessControl($acl);$n=[Math]::Min($raw.Length,1048576);$f.Write($raw,0,$n);$f.Flush($true)}finally{$f.Dispose()}}
 $source.Position=0;$again=New-Object byte[] ([int]$source.Length);$n=0;while($n -lt $again.Length){$k=$source.Read($again,$n,$again.Length-$n);if($k -le 0){throw 'COMPILE_CLOSING_SOURCE_SHORT'};$n+=$k};if((Hash $again) -cne $config.nativeSha256){throw 'COMPILE_CLOSING_SOURCE_CHANGED'}
 $terminal=[ordered]@{schemaVersion=1;operationId=$config.operationId;state='terminal';parent=$parent;child=$actor;compilerMetadata=$ready.compilerMetadata;exitCode=$process.ExitCode;waitSignaled=$true;stdoutEOF=$true;stderrEOF=$true;stdoutBytes=$out.Length;stderrBytes=$err.Length;stdoutSha256=(Hash $out);stderrSha256=(Hash $err);overflow=($out.Length -gt 1048576 -or $err.Length -gt 1048576);nativeSha256=$config.nativeSha256;compileSucceeded=($process.ExitCode -eq 0 -and [Text.Encoding]::UTF8.GetString($out) -ceq "COMPILE_ONLY_OK`n" -and $err.Length -eq 0);inputAuthority=$false;nativeQualified=$false;replayAllowed=$false}
 Save (Join-Path $job 'terminal.json') $terminal;$complete=$true
}finally{
 # Stop ONLY this retained Process handle on deadline/cancel/source failure.
 # A failed/unknown launch never authorizes PID-only cleanup or replacement.
 if($null -ne $process -and $childKnown -and -not $process.HasExited){Save (Join-Path $job 'stop.intent.json') ([ordered]@{operationId=$config.operationId;child=$actor;originalOnly=$true;replayAllowed=$false});$process.Kill();[void]$process.WaitForExit(5000)}
 if(-not $complete){
  # Preserve original failure diagnostics/EOF even when no successful terminal
  # assertion is possible. This is not permission to replace the original.
  $closed=$false
  if($childKnown -and $process.HasExited -and $null -ne $stdout -and $null -ne $stderr){
   $closed=$stdout.Wait(5000) -and $stderr.Wait(5000)
   if($closed){foreach($role in @('stdout','stderr')){$task=if($role -eq 'stdout'){$stdout}else{$stderr};$raw=[Text.Encoding]::UTF8.GetBytes($task.GetAwaiter().GetResult());$path=Join-Path $job ($role+'.failure.bin');$f=[IO.FileStream]::new($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.SetAccessControl($acl);$f.Write($raw,0,[Math]::Min($raw.Length,1048576));$f.Flush($true)}finally{$f.Dispose()}}}
  }
  Save (Join-Path $job 'unknown.json') ([ordered]@{operationId=$config.operationId;childIdentityKnown=$childKnown;actualChildExitAndBothEOF=$closed;inputAuthority=$false;replayAllowed=$false})
 }
 $source.Dispose();if($null -ne $process){$process.Dispose()}
}
[Console]::WriteLine(($terminal|ConvertTo-Json -Depth 16 -Compress))

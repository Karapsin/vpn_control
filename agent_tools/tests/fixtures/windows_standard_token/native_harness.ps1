$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$account=Get-LocalUser -Name $ExpectedUser -ErrorAction Stop
$sid=$account.SID.Value
$processes=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -OperationTimeoutSec 5 | Where-Object { $r=Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid; $r.ReturnValue -eq 0 -and $r.Sid -ceq $sid })
if($processes.Count -ne 1){throw 'UNIQUE_USER_EXPLORER'}
$process=Get-Process -Id $processes[0].ProcessId -ErrorAction Stop
$birth=$process.StartTime.ToFileTimeUtc();$session=$process.SessionId
$beforeSource=$BeforeSource.Replace('__CTX_SID__',$sid).Replace('__CTX_SESSION_CSHARP__',('Info(t,12)!='+$session))
$afterSource=$AfterSource.Replace('__CTX_SID__',$sid).Replace('__CTX_SESSION_CSHARP__',('Info(t,12)!='+$session))
Add-Type -TypeDefinition $beforeSource -ReferencedAssemblies @('System','System.Core')
Add-Type -TypeDefinition $afterSource -ReferencedAssemblies @('System','System.Core')
$originalSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$read=[BeforeOwnerToken]::Read($process.Id,$birth)
if($read[0] -cne $sid -or $read[1] -cne '0' -or $read[2] -cne '1' -or $read[3] -cne 'False' -or $read[4] -cne 'False'){throw 'EXPECTED_STANDARD_TOKEN'}
$oldRefused=$false;$context=$null
try{$context=[BeforeOwnerToken]::Impersonate($process.Id,$birth)}catch{$oldRefused=$true}finally{if($context){$context.Undo();$context.Dispose()}}
if(-not $oldRefused){throw 'BEFORE_RED_MISSING'}
$context=[AfterOwnerToken]::Impersonate($process.Id,$birth)
try{if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne $sid){throw 'FIXED_IMPERSONATION_SID'}}finally{$context.Undo();$context.Dispose()}
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne $originalSid){throw 'IMPERSONATION_NOT_CLOSED'}
$wrongBirthRefused=$false
try{$context=[AfterOwnerToken]::Impersonate($process.Id,($birth+1));$context.Undo();$context.Dispose()}catch{$wrongBirthRefused=$true}
$systemRefused=$false
try{$p=Get-Process -Id $PID;$context=[AfterOwnerToken]::Impersonate($p.Id,$p.StartTime.ToFileTimeUtc());$context.Undo();$context.Dispose()}catch{$systemRefused=$true}
if(-not $wrongBirthRefused -or -not $systemRefused){throw 'FIXED_NEGATIVE_MISSING'}
[Console]::Out.WriteLine((@{nonce=$OperationId;state='standard-token-causal-observed';pid=$process.Id;birth=$birth;sid=$sid;sessionId=$session;elevation=[int]$read[1];elevationType=[int]$read[2];adminMember=[bool]::Parse($read[3]);adminEnabled=[bool]::Parse($read[4]);oldGuardRefused=$oldRefused;fixedImpersonationClosed=$true;wrongBirthRefused=$wrongBirthRefused;systemRefused=$systemRefused;productAction=$false}|ConvertTo-Json -Compress))

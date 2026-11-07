param([Parameter(Mandatory=$true)][int]$TargetPid,
      [Parameter(Mandatory=$true)][UInt64]$CreationFileTime)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if($TargetPid -le 0 -or $CreationFileTime -le 0){throw 'EXACT_TARGET_REQUIRED'}
$process=Get-Process -Id $TargetPid -ErrorAction Stop
try {
 $null=$process.Handle
 if($process.HasExited -or [UInt64]$process.StartTime.ToFileTimeUtc() -ne $CreationFileTime){throw 'TARGET_GENERATION_CHANGED'}
 $table=@(Get-NetTCPConnection -State Listen -ErrorAction Stop)
 if($table.Count -gt 16384){throw 'LISTENER_TABLE_BOUND'}
 $rows=@($table|Where-Object {$_.OwningProcess -eq $TargetPid}|ForEach-Object {@{address=[string]$_.LocalAddress;port=[int]$_.LocalPort;pid=[int]$_.OwningProcess}})
 if($process.HasExited -or [UInt64]$process.StartTime.ToFileTimeUtc() -ne $CreationFileTime){throw 'TARGET_GENERATION_CHANGED'}
 @{schemaVersion=1;pid=$TargetPid;creationFileTime=[string]$CreationFileTime;listeners=$rows}|ConvertTo-Json -Depth 4 -Compress
}finally{$process.Dispose()}

param([Parameter(Mandatory=$true)][string]$GuiPath,[Parameter(Mandatory=$true)][string]$CliPath,[Parameter(Mandatory=$true)][string]$Workspace,[Parameter(Mandatory=$true)][int]$ExpectedSession)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;
public static class PostbootArgs {
 [DllImport("shell32.dll",SetLastError=true)]static extern IntPtr CommandLineToArgvW([MarshalAs(UnmanagedType.LPWStr)]string c,out int n);
 [DllImport("kernel32.dll")]static extern IntPtr LocalFree(IntPtr p);
 public static string[] Read(string c){int n;IntPtr p=CommandLineToArgvW(c,out n);if(p==IntPtr.Zero||n<1||n>128)throw new InvalidOperationException("actual-argv-bound");try{string[] a=new string[n];for(int i=0;i<n;i++)a[i]=Marshal.PtrToStringUni(Marshal.ReadIntPtr(p,i*IntPtr.Size));return a;}finally{if(LocalFree(p)!=IntPtr.Zero)throw new InvalidOperationException("argv-buffer-close");}}
}
'@
$runtime=Join-Path $Workspace 'runtime\tools\sing-box.exe';$held=[Collections.Generic.List[Diagnostics.Process]]::new()
try{
 $all=@(Get-CimInstance Win32_Process -OperationTimeoutSec 10);if($all.Count-gt16384){throw 'finite-startup-census'}
 # Initial rows discover possible PIDs only; they grant no argv/parent authority.
 $rows=@();foreach($candidate in $all){
  if($candidate.SessionId-ne$ExpectedSession -or $candidate.ExecutablePath-notin@($GuiPath,$CliPath,$runtime)){continue}
  $p=Get-Process -Id ([int]$candidate.ProcessId);$null=$p.Handle;$held.Add($p)
  $birth=$p.StartTime.ToFileTimeUtc()
  if($p.HasExited -or $p.SessionId-ne$ExpectedSession -or $p.Path-notin@($GuiPath,$CliPath,$runtime)){throw 'original-startup-census-actor'}
  # Hold the original process handle BEFORE reading its current CIM metadata.
  # Do not equate CIM microsecond CreationDate with native100ns FILETIME.
  $fresh=@(Get-CimInstance Win32_Process -Filter ('ProcessId='+$p.Id) -OperationTimeoutSec 5)
  if($fresh.Count-ne1 -or [int]$fresh[0].ProcessId-ne$p.Id){throw 'exact-current-startup-census-row'}
  $row=$fresh[0]
  if($p.HasExited -or $p.StartTime.ToFileTimeUtc()-ne$birth -or $row.SessionId-ne$p.SessionId -or $p.Path-ine$row.ExecutablePath){throw 'original-startup-census-metadata-closing'}
  $args=@([PostbootArgs]::Read([string]$row.CommandLine))
  $rows+=,@{pid=$p.Id;parentPid=[int]$row.ParentProcessId;creationFileTime=$birth;image=$p.Path;sessionId=$p.SessionId;argv=$args}
 }
 foreach($p in $held){if($p.HasExited){throw 'startup-census-actor-ended'}}
 [Console]::WriteLine((@{schemaVersion=1;collector='prequery-native-startup-census';pid=$PID;creationFileTime=(Get-Process -Id $PID).StartTime.ToFileTimeUtc();sessionId=$ExpectedSession;rows=$rows}|ConvertTo-Json -Depth 8 -Compress))
}finally{foreach($p in $held){$p.Dispose()}}

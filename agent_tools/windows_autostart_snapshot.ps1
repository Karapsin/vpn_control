$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
public static class VcAutostartNative {
 [DllImport("ntdll.dll")] static extern int NtQuerySystemInformation(int c, byte[] b, int n, out int r);
 [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr p,uint a,out IntPtr t);
 [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr t,int c,out int v,int n,out int r);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool IsProcessInJob(IntPtr p, IntPtr j, out bool inJob);
 public static string Boot() {
  byte[] b=new byte[32]; int r; int status=NtQuerySystemInformation(90,b,b.Length,out r);
  if(status!=0 || r!=b.Length) throw new Exception("BOOT_IDENTIFIER_NATIVE_QUERY");
  byte[] guid=new byte[16]; Array.Copy(b,0,guid,0,16); return new Guid(guid).ToString();
 }
 public static int Elevated() {
  IntPtr t; if(!OpenProcessToken(Process.GetCurrentProcess().Handle,8,out t)) throw new Exception("TOKEN_OPEN");
  try {int v,r; if(!GetTokenInformation(t,20,out v,4,out r)||r!=4)throw new Exception("TOKEN_ELEVATION"); return v;}
  finally {if(!CloseHandle(t))throw new Exception("TOKEN_CLOSE");}
 }
 public static bool InJob() {
  bool v; if(!IsProcessInJob(Process.GetCurrentProcess().Handle,IntPtr.Zero,out v))throw new Exception("PROCESS_JOB_QUERY");return v;
 }
}
'@
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$machine = $null
$key = $null
try {
 $process = [Diagnostics.Process]::GetCurrentProcess()
 $service = New-Object -ComObject 'Schedule.Service'
 $service.Connect()
 $folder = $service.GetFolder('\')
 $taskData = @{ state = 'absent' }
 try {
  $task = $folder.GetTask('VPN Control')
  $xml = [string]$task.Xml
  $sddl = [string]$task.GetSecurityDescriptor(7)
  if ($xml.Length -gt 65536 -or $sddl.Length -gt 32768) { throw 'TASK_BEFOREIMAGE_BOUND' }
  $instances = $task.GetInstances(0)
  if ($instances.Count -gt 16) { throw 'TASK_INSTANCE_BOUND' }
  $running = @()
  foreach ($instance in $instances) {
   $action = [string]$instance.CurrentAction
   if ($action.Length -gt 16384) { throw 'TASK_ACTION_BOUND' }
   $running += ,@{ instanceGuid = [string]$instance.InstanceGuid; enginePid = [int]$instance.EnginePID;
    state = [int]$instance.State; currentAction = $action }
  }
  $lastRun = [DateTime]$task.LastRunTime
  $taskData = @{state='present'; path=[string]$task.Path; xml=$xml; sddl=$sddl; enabled=[bool]$task.Enabled;
   lastRunFileTimeUtc=[string]$lastRun.ToUniversalTime().ToFileTimeUtc(); lastTaskResult=[int]$task.LastTaskResult;
   schedulerState=[int]$task.State; runningInstances=$running }
 } catch [System.Runtime.InteropServices.COMException] {
  if ($_.Exception.HResult -ne -2147024894) { throw }
 }
 $run = @{state='absent'; keyState='absent'}
 $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Run',$false)
 if ($null -ne $key) {
  $acl = $key.GetAccessControl([Security.AccessControl.AccessControlSections]7).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]7)
  $run = @{state='absent'; keyState='present'; keySddl=$acl}
  $names = $key.GetValueNames()
  if ($names.Length -gt 4096) { throw 'RUN_VALUE_NAME_BOUND' }
  if ($names -ccontains 'VPN Control') {
   $value = $key.GetValue('VPN Control',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
   if ($value -isnot [string] -or $value.Length -gt 16384) { throw 'LEGACY_RUN_VALUE_TYPE_BOUND' }
   $run = @{state='present'; keyState='present'; keySddl=$acl; kind=[string]$key.GetValueKind('VPN Control'); value=$value}
  }
 }
 $machine = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Cryptography',$false)
 if ($null -eq $machine) { throw 'MACHINE_KEY_ABSENT' }
 $machineGuid = [string]$machine.GetValue('MachineGuid')
 $openingBoot = [VcAutostartNative]::Boot()
 $result = @{schemaVersion=2; collector='exact-autostart-read-only-v2'; sid=$identity.User.Value;
  sessionId=$process.SessionId; pid=$process.Id; creationFileTime=[string]$process.StartTime.ToUniversalTime().ToFileTimeUtc();
  elevated=[VcAutostartNative]::Elevated(); inJob=[VcAutostartNative]::InJob();
  bootIdentifier=$openingBoot; machineGuid=$machineGuid; task=$taskData; run=$run}
 if ([VcAutostartNative]::Boot() -cne $openingBoot) { throw 'BOOT_CHANGED_DURING_COLLECTION' }
 $json = $result | ConvertTo-Json -Depth 12 -Compress
 if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 262143) { throw 'SNAPSHOT_UTF8_BOUND' }
 [Console]::WriteLine($json)
} finally {
 if ($null -ne $key) { $key.Dispose() }
 if ($null -ne $machine) { $machine.Dispose() }
 $identity.Dispose()
}

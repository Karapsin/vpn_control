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
 [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool LookupAccountNameW(string s,string n,byte[] sid,ref int sidSize,System.Text.StringBuilder d,ref int dSize,out int use);
 // The SID this machine's authority maps an account name to; null only for ERROR_NONE_MAPPED (1332). Every other
 // outcome throws, so a failed lookup never reads as an unmapped or a mapped name.
 public static string AccountSid(string name) {
  int size=0,dsize=0,use;
  if(LookupAccountNameW(null,name,null,ref size,null,ref dsize,out use)) throw new Exception("ACCOUNT_LOOKUP_SIZE");
  int e=Marshal.GetLastWin32Error(); if(e==1332) return null;
  if(e!=122||size<8||size>68||dsize<1||dsize>1024) throw new Exception("ACCOUNT_LOOKUP_"+e);
  byte[] sid=new byte[size]; var domain=new System.Text.StringBuilder(dsize);
  if(!LookupAccountNameW(null,name,sid,ref size,domain,ref dsize,out use)) throw new Exception("ACCOUNT_LOOKUP_"+Marshal.GetLastWin32Error());
  return SidString(sid,size);
 }
 // A binary SID in its string form: revision 1, the 48-bit big-endian authority, then little-endian subauthorities.
 public static string SidString(byte[] b,int n) {
  if(n<8||n>b.Length||b[0]!=1||n!=8+4*b[1]) throw new Exception("ACCOUNT_SID_SHAPE");
  ulong a=0; for(int i=2;i<8;i++) a=(a<<8)|b[i];
  var s=new System.Text.StringBuilder("S-1-"+a);
  for(int i=0;i<b[1];i++) s.Append('-').Append(BitConverter.ToUInt32(b,8+4*i));
  return s.ToString();
 }
}
'@
function Test-TaskAbsent($record) {
 # Only ERROR_FILE_NOT_FOUND (0x80070002) anywhere in the exception chain proves the task absent. Native Windows
 # PowerShell raises it from Task Scheduler as a bare FileNotFoundException, other hosts as a COMException or wrapped
 # in a MethodInvocationException, so no exception type is matched. Access denied and every other error is not absence.
 $x = $record.Exception
 while ($null -ne $x) { if ($x.HResult -eq -2147024894) { return $true }; $x = $x.InnerException }
 return $false
}
function Get-StartupTask($folder) {
 # Only the lookup itself may prove absence; a later read of a present task that fails is never absence.
 try { return $folder.GetTask('VPN Control') } catch { if (-not (Test-TaskAbsent $_)) { throw } }
 return $null
}
function Resolve-AccountSid([string]$name) { return [VcAutostartNative]::AccountSid($name) }
function Get-TaskAccounts([string]$xml) {
 # Task Scheduler keeps a principal's SID but may store a logon trigger's user as an account name: native 7ca6638a read
 # DESKTOP-4MOOMEI\fixtureuser for a trigger registered with the ordinary SID. Each distinct principal or logon-trigger
 # UserId that is no SID is looked up here, on the guest, as this ordinary user, and recorded with what it maps to.
 # The owner takes a name only when it maps to exactly its own SID; an unmapped name stays null.
 $settings = [Xml.XmlReaderSettings]::new()
 $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
 $settings.XmlResolver = $null
 $reader = [Xml.XmlReader]::Create([IO.StringReader]::new($xml), $settings)
 $document = [Xml.XmlDocument]::new()
 $document.XmlResolver = $null
 try { $document.Load($reader) } finally { $reader.Dispose() }
 $names = [Xml.XmlNamespaceManager]::new($document.NameTable)
 $names.AddNamespace('t', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
 $nodes = $document.SelectNodes('/t:Task/t:Principals/t:Principal/t:UserId | /t:Task/t:Triggers/t:LogonTrigger/t:UserId', $names)
 if ($nodes.Count -gt 8) { throw 'TASK_ACCOUNT_BOUND' }
 $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
 foreach ($node in $nodes) {
  $name = [string]$node.InnerText
  if ($name.Length -gt 512) { throw 'TASK_ACCOUNT_BOUND' }
  if ($name.Length -eq 0 -or $name -cmatch '\AS-1-[0-9]+(-[0-9]+)+\z' -or -not $seen.Add($name)) { continue }
  [ordered]@{ name = $name; sid = (Resolve-AccountSid $name) }
 }
}
$identity =[Security.Principal.WindowsIdentity]::GetCurrent()
$machine = $null
$key = $null
try {
 $process = [Diagnostics.Process]::GetCurrentProcess()
 $service = New-Object -ComObject 'Schedule.Service'
 $service.Connect()
 $folder = $service.GetFolder('\')
 $taskData = @{ state = 'absent' }
 $task = Get-StartupTask $folder
 if ($null -ne $task) {
  $xml = [string]$task.Xml
  # SECURITY_INFORMATION OWNER|GROUP|DACL, never the SACL: READ_CONTROL on the user's own task, which the product's
  # schtasks /Change and /Delete as this same user already need.
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
  $accounts = @(Get-TaskAccounts $xml)
  $taskData = @{state='present'; path=[string]$task.Path; xml=$xml; sddl=$sddl; enabled=[bool]$task.Enabled;
   lastRunFileTimeUtc=[string]$lastRun.ToUniversalTime().ToFileTimeUtc(); lastTaskResult=[int]$task.LastTaskResult;
   schedulerState=[int]$task.State; runningInstances=$running; accounts=$accounts }
 }
 $run = @{state='absent'; keyState='absent'}
 $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Run',$false)
 if ($null -ne $key) {
  # Owner, group and DACL, as the task's GetSecurityDescriptor(7) reads them (SECURITY_INFORMATION 1|2|4). In .NET's
  # AccessControlSections 7 is Audit|Access|Owner: the SACL needs SeSecurityPrivilege, which no ordinary token holds.
  $sections = [Security.AccessControl.AccessControlSections]'Access, Owner, Group'
  $acl = $key.GetAccessControl($sections).GetSecurityDescriptorSddlForm($sections)
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
 $result = @{schemaVersion=3; collector='exact-autostart-read-only-v3'; sid=$identity.User.Value;
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

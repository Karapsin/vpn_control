$ErrorActionPreference='Stop';Add-Type -TypeDefinition @'

using System; using System.ComponentModel; using System.Runtime.InteropServices; using System.Security.Principal;
public static class Cp117OwnerToken {
 [DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool CloseHandle(IntPtr h);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetProcessTimes(IntPtr p,out long creation,out long exit,out long kernel,out long user);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool OpenProcessToken(IntPtr p,uint access,out IntPtr token);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool GetTokenInformation(IntPtr t,int kind,IntPtr data,int size,out int needed);
 static int Info(IntPtr t,int kind) { IntPtr b=Marshal.AllocHGlobal(4); try { int n;if(!GetTokenInformation(t,kind,b,4,out n)||n!=4)throw new Win32Exception(Marshal.GetLastWin32Error());return Marshal.ReadInt32(b);}finally{Marshal.FreeHGlobal(b);} }
 [StructLayout(LayoutKind.Sequential)]struct Group { public IntPtr sid;public uint attributes; }
 [StructLayout(LayoutKind.Sequential)]struct Groups { public uint count;public Group first; }
 static bool[] Admin(IntPtr t) {
  int n;GetTokenInformation(t,2,IntPtr.Zero,0,out n);if(n<=0||n>32768)throw new InvalidOperationException("groups-bound");IntPtr b=Marshal.AllocHGlobal(n);
  try {int used;if(!GetTokenInformation(t,2,b,n,out used)||used>n)throw new Win32Exception(Marshal.GetLastWin32Error());int count=Marshal.ReadInt32(b);if(count<0||count>256)throw new InvalidOperationException("groups-count");int offset=Marshal.OffsetOf(typeof(Groups),"first").ToInt32(),stride=Marshal.SizeOf(typeof(Group));bool member=false,enabled=false;
   if(offset+count*stride>used)throw new InvalidOperationException("groups-shape");
   for(int i=0;i<count;i++){Group g=(Group)Marshal.PtrToStructure(IntPtr.Add(b,offset+i*stride),typeof(Group));if(new SecurityIdentifier(g.sid).Value=="S-1-5-32-544"){member=true;enabled=(g.attributes&4)!=0&&(g.attributes&16)==0;}}
   return new bool[]{member,enabled};
  }finally{Marshal.FreeHGlobal(b);}
 }
 public static WindowsImpersonationContext Impersonate(int pid,long creation) {
  IntPtr p=OpenProcess(0x1000,false,pid),t=IntPtr.Zero;if(p==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
  try {long c,e,k,u;if(!GetProcessTimes(p,out c,out e,out k,out u)||c!=creation)throw new InvalidOperationException("process-generation");
   if(!OpenProcessToken(p,10,out t))throw new Win32Exception(Marshal.GetLastWin32Error());
   using(WindowsIdentity id=new WindowsIdentity(t)){if(id.User.Value!="S-1-5-21-606332539-4179368406-55829832-1000"||Info(t,20)!=0||Info(t,18)!=3||Info(t,12)!=1)throw new InvalidOperationException("impersonation-token");}
   return WindowsIdentity.Impersonate(t);
  }finally{if(t!=IntPtr.Zero)CloseHandle(t);CloseHandle(p);}
 }

 public static string[] Read(int pid,long creation) {
  IntPtr p=OpenProcess(0x1000,false,pid),t=IntPtr.Zero;if(p==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
  try {long c,e,k,u;if(!GetProcessTimes(p,out c,out e,out k,out u)||c!=creation)throw new InvalidOperationException("process-generation");
   if(!OpenProcessToken(p,10,out t))throw new Win32Exception(Marshal.GetLastWin32Error());
   using(WindowsIdentity id=new WindowsIdentity(t)) {bool[] admin=Admin(t);
    return new string[]{id.User.Value,Info(t,20).ToString(),Info(t,18).ToString(),admin[0].ToString(),admin[1].ToString(),Info(t,12).ToString()}; }
  }finally{if(t!=IntPtr.Zero)CloseHandle(t);CloseHandle(p);}
 }
}

'@ -ReferencedAssemblies @('System','System.Core')
$account=@(Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND Name='parityagent'");if($account.Count -ne 1){throw 'ACCOUNT_COUNT'};$rows=@();$xs=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'");if($xs.Count -gt 4){throw 'EXPLORER_BOUND'};foreach($x in $xs){$p=$null;try{$p=Get-Process -Id $x.ProcessId;$ignore=$p.Handle;$birth=$p.StartTime.ToFileTimeUtc();$a=[Cp117OwnerToken]::Read($p.Id,$birth);if($a[0] -eq $account[0].SID){$again=[Cp117OwnerToken]::Read($p.Id,$birth);if(($a -join '|') -cne ($again -join '|') -or $p.HasExited){throw 'TOKEN_DRIFT'};$rows+=@{pid=$p.Id;parentPid=$x.ParentProcessId;birth=$birth;sid=$a[0];elevated=$a[1];elevationType=$a[2];adminMember=$a[3];adminEnabled=$a[4];session=$a[5];image=$p.Path;tokenStable=$true}}}finally{if($p){$p.Dispose()}}};@{schema=1;accountName=$account[0].Name;accountSid=$account[0].SID;accountDisabled=$account[0].Disabled;computerUser=(Get-CimInstance Win32_ComputerSystem).UserName;explorerTokens=$rows;readOnly=$true}|ConvertTo-Json -Depth 5 -Compress
if($rows.Count -ne 1 -or $rows[0].pid -ne 4512 -or $rows[0].birth -ne 134357313540855812 -or $rows[0].sid -cne 'S-1-5-21-606332539-4179368406-55829832-1000' -or $rows[0].elevated -cne '0' -or $rows[0].elevationType -cne '3' -or $rows[0].session -cne '1'){throw 'CONSOLE_TOKEN'}
$os=Get-CimInstance Win32_OperatingSystem;$disk=Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'";if($os.LastBootUpTime.ToUniversalTime().ToString('o') -cne '2026-10-05T23:28:49.1890040Z' -or $os.FreePhysicalMemory -lt 262144 -or $disk.FreeSpace -lt 2147483648){throw 'GUEST_BOOT_RESOURCE'}
$actors=@(Get-CimInstance Win32_Process|Where-Object {$_.Name -match '^(vpn-control|vpn-control-cli|vpn-control-install-helper|sing-box|consent|msiexec)\.exe$'});if(@($actors|Where-Object {$_.Name -match '^(vpn-control-install-helper|sing-box|consent)\.exe$'}).Count){throw 'RETURN_HELPER_RUNTIME_CONSENT_LIVE'}


$expected=@(@{pid=7688;parent=9624;birth=134361658211392523;cli=$true},@{pid=1460;parent=7688;birth=134361658215095099;cli=$true},@{pid=1192;parent=9624;birth=134361658267118236;cli=$false},@{pid=5812;parent=1192;birth=134361658268206671;cli=$false});$known=@(Get-CimInstance Win32_Process|Where-Object {$_.Name -in @('vpn-control.exe','vpn-control-cli.exe') -and $_.ProcessId -in @($expected.pid)});if($known.Count -ne 4){throw 'CURRENT_EPOCH_POPULATION'};foreach($x in $known){$r=@($expected|Where-Object {$_.pid -eq $x.ProcessId});$p=$null;try{$path=if($r[0].cli){'C:\Users\parityagent\AppData\Local\vpn-control\vpn-control-cli.exe'}else{'C:\Users\parityagent\AppData\Local\vpn-control\vpn-control.exe'};$hash=if($r[0].cli){'c3420952d4ea6b144e84b0534faad72d87f06782c1b6e162652ae314df97c562'}else{'e007e11c5c1d00925c95a48e3fed25825e9d26ab03cbe1ecd124dd8e69a7326d'};$p=Get-Process -Id $x.ProcessId;$null=$p.Handle;$birth=$p.StartTime.ToFileTimeUtc();$t=[Cp117OwnerToken]::Read($p.Id,$birth);if($r.Count -ne 1 -or $p.HasExited -or $birth -ne $r[0].birth -or $x.ParentProcessId -ne $r[0].parent -or $p.Path -ine $path -or $t[0] -cne 'S-1-5-21-606332539-4179368406-55829832-1000' -or $t[1] -cne '0' -or $t[2] -cne '3' -or $t[3] -cne 'True' -or $t[4] -cne 'False' -or $t[5] -cne '1' -or (Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant() -cne $hash){throw 'CURRENT_EPOCH_SYSTEM_NATIVE'}}finally{if($p){$p.Dispose()}}};$svc=Get-CimInstance Win32_Service -Filter "Name='msiserver'";if($svc.State -cne 'Stopped' -or $svc.ProcessId -ne 0 -or $actors.Count -ne 4 -or @($actors|Where-Object {$_.ProcessId -notin @($known.ProcessId)}).Count){throw 'CURRENT_EPOCH_FOREIGN_ACTOR'}
$root='C:\Users\parityagent\AppData\Local\VpnControl\persistent-recovery-owner-a0e4e274-f0a7-4346-a4b1-bee9783beb83\install-operation-5af06759-d163-40c4-9ac1-900422a8a1aa';$task='VpnControlSecondaryGuiReadonly-5af06759-d163-40c4-9ac1-900422a8a1aa'
if((Test-Path -LiteralPath $root) -or (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue)){throw 'FIXTURE_NOT_FRESH'}
$stageContext=[Cp117OwnerToken]::Impersonate(4512,134357313540855812)
try{
[IO.Directory]::CreateDirectory($root)|Out-Null
$acl=[Security.AccessControl.DirectorySecurity]::new();$sid=[Security.Principal.SecurityIdentifier]::new('S-1-5-21-606332539-4179368406-55829832-1000');$acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false);foreach($v in @($sid,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'))){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($v,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))};[IO.Directory]::SetAccessControl($root,$acl)
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne $sid.Value -or ([IO.Directory]::GetAccessControl($root)).GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $sid.Value){throw 'STAGE_CREATOR_OWNER'}
}finally{$stageContext.Undo();$stageContext.Dispose()}
$source=Join-Path $root 'sources';[IO.Directory]::CreateDirectory($source)|Out-Null
foreach($row in $PayloadFiles){$dest=if($row.name -ceq 'recovery.task.ps1' -or $row.name -ceq 'trust.p12'){Join-Path $root $row.name}else{Join-Path $source $row.name};$b=[Convert]::FromBase64String($row.base64);if($b.Length -ne $row.bytes -or ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($b))).Replace('-','').ToLowerInvariant() -cne $row.sha256){throw 'PAYLOAD_HASH'};$f=[IO.File]::Open($dest,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()};if((Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash.ToLowerInvariant() -cne $row.sha256){throw 'STAGE_READBACK'}}
$exe='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe';$args='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $root 'recovery.task.ps1')+'"';if(($exe.Length+$args.Length+3) -gt 30000){throw 'WHOLE_COMMAND_BOUND'}
$action=New-ScheduledTaskAction -Execute $exe -Argument $args;$principal=New-ScheduledTaskPrincipal -UserId 'VPNPARITYX64\parityagent' -LogonType Interactive -RunLevel Limited;$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries;Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings|Out-Null
$registered=Get-ScheduledTask -TaskName $task;if([string]$registered.Principal.RunLevel -cne 'Limited' -or [string]$registered.Principal.LogonType -cne 'Interactive'){throw 'FIXTURE_PRINCIPAL'}

Start-ScheduledTask -TaskName $task
[Console]::Out.WriteLine((@{state='SAME_GUI_READONLY_TASK_TRIGGERED';task=$task;root=$root;readOnly=$false;productRequest=$true;keys=0}|ConvertTo-Json -Compress))

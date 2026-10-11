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
$root='C:\Users\parityagent\AppData\Local\VpnControl\install-operation-f752de9b-c379-4462-aa9a-14d2bec0f33e';$correlation='f752de9b-c379-4462-aa9a-14d2bec0f33e';$origin='C:\Users\parityagent\AppData\Local\VpnControl\persistent-recovery-owner-a0e4e274-f0a7-4346-a4b1-bee9783beb83';$state=Join-Path $origin 'state';
Add-Type -TypeDefinition @'
using System;using System.Text;using System.Runtime.InteropServices;public static class RecoveryScope{[DllImport("msi.dll",CharSet=CharSet.Unicode)]public static extern uint MsiEnumProductsEx(string p,string s,uint c,uint i,StringBuilder product,out uint context,StringBuilder sid,ref uint length);[DllImport("msi.dll",CharSet=CharSet.Unicode)]public static extern uint MsiGetProductInfoEx(string p,string s,uint c,string key,StringBuilder value,ref uint length);}
'@
function Scope([string]$product,[bool]$present){$code=[Text.StringBuilder]::new(39);$sid=[Text.StringBuilder]::new(256);[uint32]$length=255;[uint32]$msiContext=0;$errno=[RecoveryScope]::MsiEnumProductsEx($product,$id.User.Value,2,0,$code,[ref]$msiContext,$sid,[ref]$length);if(-not $present){if($errno -ne 259){throw ('REGISTRATION_NOT_ABSENT_'+$errno)};return @{productCode=$product;present=$false;scope=2;sid=$id.User.Value}};if($errno -ne 0 -or $msiContext -ne 2 -or $sid.ToString() -cne $id.User.Value){throw ('REGISTRATION_CONTEXT_'+$errno)};$more=[Text.StringBuilder]::new(39);$ms=[Text.StringBuilder]::new(256);[uint32]$ml=255;[uint32]$mc=0;if([RecoveryScope]::MsiEnumProductsEx($product,$id.User.Value,2,1,$more,[ref]$mc,$ms,[ref]$ml) -ne 259){throw 'REGISTRATION_NOT_UNIQUE'};return @{productCode=$code.ToString();present=$true;scope=2;sid=$sid.ToString()}}
function Version([string]$product,[string]$expected){$v=[Text.StringBuilder]::new(128);[uint32]$n=127;$e=[RecoveryScope]::MsiGetProductInfoEx($product,$id.User.Value,2,'VersionString',$v,[ref]$n);if($e -ne 0 -or $v.ToString() -cne $expected){throw 'REGISTRATION_VERSION'};return $v.ToString()}

function Ancestors([string]$p){$c=$p;while($c){if((Get-Item -LiteralPath $c -Force).Attributes -band 1024){throw 'RECOVERY_REPARSE'};$n=Split-Path -Parent $c;if($n -eq $c){break};$c=$n}}


function Durable([string]$p,[string]$s){$b=[Text.UTF8Encoding]::new($false).GetBytes($s);$f=[IO.File]::Open($p,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
function Result($v){Durable (Join-Path $root 'result.json') ($v|ConvertTo-Json -Depth 8 -Compress)}

$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
function CurrentGui {
$expected=@(@{pid=7688;parent=9624;birth=134361658211392523;cli=$true},@{pid=1460;parent=7688;birth=134361658215095099;cli=$true},@{pid=1192;parent=9624;birth=134361658267118236;cli=$false},@{pid=5812;parent=1192;birth=134361658268206671;cli=$false});$seen=@();foreach($r in $expected){$p=$null;try{$path=if($r.cli){$cli}else{$gui};$p=Get-Process -Id $r.pid;$null=$p.Handle;$t=[Cp117OwnerToken]::Read($p.Id,$r.birth);$x=Get-CimInstance Win32_Process -Filter ('ProcessId='+$r.pid);if($p.HasExited -or $p.StartTime.ToFileTimeUtc() -ne $r.birth -or $p.Path -ine $path -or $t[0] -cne $id.User.Value -or $t[1] -cne '0' -or $t[2] -cne '3' -or $t[3] -cne 'True' -or $t[4] -cne 'False' -or $t[5] -cne '1' -or -not $x -or $x.ParentProcessId -ne $r.parent){throw 'CURRENT_PERSISTENT_ROLE_WITNESS'};$seen+=@{pid=$p.Id;parentPid=$x.ParentProcessId;birth=$r.birth;cimUtc=$x.CreationDate.ToUniversalTime().ToString('o');role=$(if($r.cli){'persistentCLI'}else{'GUIFrontend'})}}finally{if($p){$p.Dispose()}}};return @{ownerMode='persistentServe';ownerPid=1460;ownerBirth=134361658215095099;chain=$seen;sid=$id.User.Value;session=1;elevationType=3;guiAttached=$true}
}
try{
$id=[Security.Principal.WindowsIdentity]::GetCurrent();$limited=-not ([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);if($id.User.Value -cne 'S-1-5-21-606332539-4179368406-55829832-1000' -or -not $limited -or (Get-Process -Id $PID).SessionId -ne 1){throw 'OWNER_PRINCIPAL'}
$cli='C:\Users\parityagent\AppData\Local\vpn-control\vpn-control-cli.exe';if((Get-FileHash -LiteralPath $cli).Hash.ToLowerInvariant() -cne 'c3420952d4ea6b144e84b0534faad72d87f06782c1b6e162652ae314df97c562'){throw 'BASE_CLI_PIN'}
$sc=Scope '{82885B65-2CC0-34EB-A9A2-231DD2F555E2}' $true;$null=Version $sc.productCode '2.2.5';$epin=Join-Path $origin 'sources\expected-base-image.json';if((Get-FileHash -LiteralPath $epin).Hash.ToLowerInvariant() -cne '2ebedac8cb0f717a98abf62c413396aa8239aaac80af7727a435bef5cae998f7'){throw 'BASE_MANIFEST_PIN'};$decoded=Get-Content -LiteralPath $epin -Raw|ConvertFrom-Json;$rows=@($decoded);$installed=Split-Path $cli -Parent;$entries=@(Get-ChildItem -LiteralPath $installed -Force -Recurse);if($rows.Count -ne 209 -or @($entries|Where-Object {$_.Attributes -band 1024}).Count -or @($entries|Where-Object {-not $_.PSIsContainer}).Count -ne 209){throw 'BASE_FULL_COUNT'};[long]$sum=0;foreach($r in $rows){$f=Join-Path $installed $r.relative;Ancestors $f;if((Get-Item -LiteralPath $f).Length -ne $r.bytes -or (Get-FileHash -LiteralPath $f).Hash.ToLowerInvariant() -cne $r.sha256){throw 'BASE_FULL_HASH'};$sum+=[long]$r.bytes};if($sum -ne 200463210){throw 'BASE_FULL_BYTES'}
$gui=Join-Path $installed 'vpn-control.exe';if((Get-FileHash -LiteralPath $gui).Hash.ToLowerInvariant() -cne 'e007e11c5c1d00925c95a48e3fed25825e9d26ab03cbe1ecd124dd8e69a7326d'){throw 'BASE_GUI_IMAGE_PIN'}


$opening=CurrentGui
foreach($q in @($origin,$state)){Ancestors $q;$acl=Get-Acl -LiteralPath $q;if(($q -ceq $origin -and -not $acl.AreAccessRulesProtected) -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $id.User.Value){throw 'OWNER_STATE_ACL'};foreach($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($ace.IdentityReference.Value -notin @($id.User.Value,'S-1-5-18') -or $ace.AccessControlType -cne 'Allow'){throw 'OWNER_STATE_FOREIGN_ACE'}}}
$endpoint=Join-Path $state 'activation.port';Ancestors $endpoint;$ei=Get-Item -LiteralPath $endpoint -Force;if($ei.Length -gt 4096 -or $ei.Length -le 0){throw 'ENDPOINT_BOUND'};$ep=Get-Content -LiteralPath $endpoint -Raw|ConvertFrom-Json;if($ep.schemaVersion -ne 1 -or $ep.controllerId -cne '61325099-3095-4d6c-b9c4-6fc884e15f1a'){throw 'SAME_CONTROLLER_BINDING'};$listeners=@(Get-NetTCPConnection -State Listen -LocalPort $ep.port -ErrorAction Stop);if($listeners.Count -ne 1 -or $listeners[0].LocalAddress -cne '127.0.0.1' -or $listeners[0].OwningProcess -ne 1460){throw 'CURRENT_ENDPOINT_OWNER_SOCKET'}
function Query([string]$name,[string[]]$commandArgs,[int]$seconds=10){$raw=(& $cli --state-dir $state --json --controller-id $ep.controllerId --timeout-seconds $seconds @commandArgs|Out-String);$rc=$LASTEXITCODE;Durable (Join-Path $root ($name+'.json')) $raw;Durable (Join-Path $root ($name+'.exit')) ([string]$rc);$v=$raw|ConvertFrom-Json;if($rc -ne 0 -or $v.code -cne 'OK' -or ($v.final -isnot [bool]) -or $v.final -ne $true -or $v.controllerId -cne $ep.controllerId){throw ('PUBLIC_'+$name)};return $v}

$status=Query 'status' @('status');$ops=Query 'operations' @('operations','list');$up=Query 'updates' @('updates','status')

if($status.restartRequired -isnot [bool] -or $status.restartRequired -ne $false -or $status.data.runtimeRunning -isnot [bool] -or $status.data.runtimeRunning -ne $false -or $null -ne $status.data.activeLocationId -or $null -ne $status.data.activeMode -or $null -ne $status.data.runtimeId){throw 'CURRENT_PUBLIC_OFF_OR_PENDING'}
if($ops.data.PSObject.Properties.Name -cnotcontains 'operations' -or $ops.data.operations -isnot [Array] -or @($ops.data.operations).Count -gt 256 -or $up.data.PSObject.Properties.Name -cnotcontains 'installations' -or $up.data.installations -isnot [Array] -or @($up.data.installations).Count -gt 256){throw 'PUBLIC_LIST_SCHEMA'}
foreach($r in @($ops.data.operations)+@($up.data.installations)){if($r.final -isnot [bool] -or $r.final -ne $true){throw 'NONTERMINAL_OPERATION_OR_INSTALL'}}
$all=@(Get-CimInstance Win32_Process|Where-Object {$_.Name -match '^(vpn-control|vpn-control-cli|vpn-control-install-helper|sing-box|consent|msiexec)\.exe$'});$svc=Get-CimInstance Win32_Service -Filter "Name='msiserver'";foreach($a in $all){if($a.Name -in @('vpn-control.exe','vpn-control-cli.exe') -and $a.ProcessId -in @($opening.chain.pid)){continue};if($a.Name -ieq 'msiexec.exe' -and $a.ProcessId -eq $svc.ProcessId -and $a.SessionId -eq 0 -and $svc.State -ceq 'Running'){continue};throw 'NATIVE_RUNTIME_OR_INSTALLER_ACTOR'}
$ready=Query 'ready' @('updates','status');$cache=Join-Path $state 'updates\vpn-control-2.2.6.msi';Ancestors $cache;$cacheItem=Get-Item -LiteralPath $cache -Force;if($cacheItem.Length -ne 131223924 -or (Get-FileHash -LiteralPath $cache).Hash.ToLowerInvariant() -cne '27270314b2a39f9f47dab550290dbefd0745d50090f6e17f925ef0271cfa67aa' -or $ready.data.phase -cne 'ready' -or $ready.data.availableVersion -cne '2.2.6' -or $ready.data.downloadedBytes -ne 131223924 -or $ready.data.totalBytes -ne 131223924){throw 'CURRENT_TARGET_READY_FULLHASH'}
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$b='{"originalSid":"S-1-5-21-606332539-4179368406-55829832-1000"}'|ConvertFrom-Json
Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class ChainToken{[DllImport("kernel32.dll",SetLastError=true)]public static extern IntPtr OpenProcess(uint a,bool i,uint p);[DllImport("advapi32.dll",SetLastError=true)]public static extern bool OpenProcessToken(IntPtr p,uint a,out IntPtr t);[DllImport("advapi32.dll",SetLastError=true)]public static extern bool GetTokenInformation(IntPtr t,int c,IntPtr b,uint n,out uint r);[DllImport("kernel32.dll")]public static extern bool CloseHandle(IntPtr h);}'
function Info($token,[int]$kind){$buf=[Runtime.InteropServices.Marshal]::AllocHGlobal(4);try{[uint32]$count=0;if(-not[ChainToken]::GetTokenInformation($token,$kind,$buf,4,[ref]$count)-or $count -ne 4){throw 'TOKEN_INFO'};return [Runtime.InteropServices.Marshal]::ReadInt32($buf)}finally{[Runtime.InteropServices.Marshal]::FreeHGlobal($buf)}}
$explorer=Get-Process -Id 4512 -ErrorAction Stop;if($explorer.StartTime.ToFileTimeUtc() -ne 134357313540855812 -or $explorer.SessionId -ne 1){throw 'CONSOLE_BIRTH'}
$ph=[ChainToken]::OpenProcess(0x1000,$false,4512);$token=[IntPtr]::Zero;if($ph -eq [IntPtr]::Zero){throw 'CONSOLE_PROCESS'}
try{if(-not[ChainToken]::OpenProcessToken($ph,10,[ref]$token)){throw 'CONSOLE_TOKEN'};$identity=[Security.Principal.WindowsIdentity]::new($token);try{$sid=$identity.User.Value;$enabled=[Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);$elevated=Info $token 20;$type=Info $token 18;if($sid -cne $b.originalSid -or $enabled -or $elevated -ne 0 -or $type -ne 3){throw 'FILTERED_TOKEN_CHANGED'}}finally{$identity.Dispose()}}finally{if($token -ne [IntPtr]::Zero){[ChainToken]::CloseHandle($token)|Out-Null};[ChainToken]::CloseHandle($ph)|Out-Null}
$owner=Get-Process -Id 1460 -ErrorAction Stop;$launcher=Get-Process -Id 7688 -ErrorAction Stop;[Console]::Out.WriteLine((@{state='CURRENT_TYPED_GETPROCESS_BIRTHS';explorer4512=$explorer.StartTime.ToFileTimeUtc();owner1460=$owner.StartTime.ToFileTimeUtc();launcher7688=$launcher.StartTime.ToFileTimeUtc();source='GetProcess.StartTime.ToFileTimeUtc';effects=$false}|ConvertTo-Json -Compress));if($owner.StartTime.ToFileTimeUtc() -ne 134361658215095099 -or $launcher.StartTime.ToFileTimeUtc() -ne 134361658211392523 -or $owner.SessionId -ne 1){throw 'ORIGINAL_OWNER_BIRTH'}

Durable (Join-Path $root 'fresh-input-prefix-admission.json') (@{state='ACTUAL_CONTEXT_TOKEN_ALL_GETPROCESS_PREFIX_GREEN';owner1460=$owner.StartTime.ToFileTimeUtc();launcher7688=$launcher.StartTime.ToFileTimeUtc();explorer4512=$explorer.StartTime.ToFileTimeUtc();sid=$sid;elevated=$elevated;elevationType=$type;inputKeys=0;effects=$false}|ConvertTo-Json -Compress)
Durable (Join-Path $root 'intent.json') (@{correlationId='f752de9b-c379-4462-aa9a-14d2bec0f33e';controllerId=$ep.controllerId;configurationRevision=$ready.configurationRevision;targetVersion='2.2.6';targetHash='27270314b2a39f9f47dab550290dbefd0745d50090f6e17f925ef0271cfa67aa';originalSid=$id.User.Value;sessionId=1;ownerPid=1460;limited=$limited;state='INSTALL_INTENT'}|ConvertTo-Json -Compress)
$wireRaw=(& $cli --state-dir $state --json --controller-id $ep.controllerId --if-revision $ready.configurationRevision --async --timeout-seconds 120 updates install|Out-String);Durable (Join-Path $root 'request.json') $wireRaw
$requestExit=$LASTEXITCODE;Durable (Join-Path $root 'request.exit') ([string]$requestExit);$request=Get-Content -LiteralPath (Join-Path $root 'request.json') -Raw|ConvertFrom-Json
Result @{schema=1;state='PUBLIC_INSTALL_REQUEST_OBSERVED';correlationId='f752de9b-c379-4462-aa9a-14d2bec0f33e';exit=$requestExit;request=$request;originalSid=$id.User.Value;sessionId=1;limited=$limited;oldOwnerPid=1460;replayAllowed=$false;installerRequested=$true}
if($requestExit -ne 0 -or $request.code -cne 'ACCEPTED' -or $request.final -ne $false -or $request.controllerId -cne $ep.controllerId -or $request.operationId -notmatch '^[0-9a-f-]{36}$'){throw 'REQUEST_UNCERTAIN'}
function Try-CurrentBinding {
try{
if(-not('SecondaryJournalRead' -as [type])){Add-Type -TypeDefinition @'
using System;using System.IO;using System.Collections.Generic;using System.Runtime.InteropServices;using System.Security.AccessControl;using Microsoft.Win32.SafeHandles;
public static class SecondaryJournalRead {
 [StructLayout(LayoutKind.Sequential)]public struct Info {public uint Attr,CH,CL,AH,AL,WH,WL,Volume,SizeHigh,SizeLow,Links,IdHigh,IdLow;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern SafeFileHandle CreateFile(string p,uint access,uint share,IntPtr sa,uint create,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info i);
 [DllImport("kernel32.dll",SetLastError=true)]static extern uint GetFileType(SafeFileHandle h);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool GetVolumeInformationByHandleW(SafeFileHandle h,IntPtr name,uint n,IntPtr serial,IntPtr maximum,out uint flags,IntPtr fs,uint f);
 [DllImport("advapi32.dll",SetLastError=true)]static extern uint GetSecurityInfo(SafeFileHandle h,uint kind,uint flags,out IntPtr owner,IntPtr group,out IntPtr dacl,IntPtr sacl,out IntPtr descriptor);
 [DllImport("advapi32.dll")]static extern bool IsValidSecurityDescriptor(IntPtr sd);
 [DllImport("advapi32.dll")]static extern uint GetSecurityDescriptorLength(IntPtr sd);
 [DllImport("kernel32.dll")]static extern IntPtr LocalFree(IntPtr p);
 static string Id(Info i){return i.Volume+":"+i.IdHigh+":"+i.IdLow+":"+i.Attr+":"+i.CH+":"+i.CL+":"+i.WH+":"+i.WL+":"+i.SizeHigh+":"+i.SizeLow+":"+i.Links;}
 static string DirectoryId(Info i){return i.Volume+":"+i.IdHigh+":"+i.IdLow+":"+i.Attr+":"+i.CH+":"+i.CL;}
 static Info Inspect(SafeFileHandle h,bool dir){Info i;if(h.IsInvalid||GetFileType(h)!=1||!GetFileInformationByHandle(h,out i)||(i.Attr&0x400)!=0||((i.Attr&0x10)!=0)!=dir||(!dir&&i.Links!=1))throw new IOException("JOURNAL_HANDLE_SCHEMA");return i;}
 public static void Permissions(RawSecurityDescriptor sd,string sid){if(sd==null||sd.Owner==null||sd.Owner.Value!=sid||sd.DiscretionaryAcl==null||sd.DiscretionaryAcl.Count==0||sd.DiscretionaryAcl.Count>4096)throw new IOException("JOURNAL_PERMISSIONS");bool readable=false;foreach(GenericAce raw in sd.DiscretionaryAcl){CommonAce a=raw as CommonAce;if(a==null||a.AceQualifier!=AceQualifier.AccessAllowed||a.SecurityIdentifier.Value!=sid||((int)a.AceFlags&0x18)!=0)throw new IOException("JOURNAL_PERMISSIONS");if((a.AccessMask&1)!=0)readable=true;}if(!readable)throw new IOException("JOURNAL_PERMISSIONS");}
 public static void DirectoryPermissions(RawSecurityDescriptor sd,string sid){if(sd==null||sd.Owner==null||sd.Owner.Value!=sid||sd.DiscretionaryAcl==null||sd.DiscretionaryAcl.Count==0||sd.DiscretionaryAcl.Count>4096)throw new IOException("JOURNAL_DIRECTORY_PERMISSIONS");bool readable=false;foreach(GenericAce raw in sd.DiscretionaryAcl){CommonAce a=raw as CommonAce;if(a==null||a.AceQualifier!=AceQualifier.AccessAllowed||(a.SecurityIdentifier.Value!=sid&&a.SecurityIdentifier.Value!="S-1-5-18"&&a.SecurityIdentifier.Value!="S-1-5-32-544")||((int)a.AceFlags&~0x13)!=0)throw new IOException("JOURNAL_DIRECTORY_PERMISSIONS");if(a.SecurityIdentifier.Value==sid&&(a.AccessMask&1)!=0)readable=true;}if(!readable)throw new IOException("JOURNAL_DIRECTORY_PERMISSIONS");}
 static string Security(SafeFileHandle h,string sid,bool directory=false){uint flags;if(!GetVolumeInformationByHandleW(h,IntPtr.Zero,0,IntPtr.Zero,IntPtr.Zero,out flags,IntPtr.Zero,0)||(flags&8)==0)throw new IOException("JOURNAL_ACL_VOLUME");IntPtr o,d,sd;uint code=GetSecurityInfo(h,1,5,out o,IntPtr.Zero,out d,IntPtr.Zero,out sd);if(code!=0)throw new IOException("JOURNAL_SECURITY_INFO");try{if(!IsValidSecurityDescriptor(sd))throw new IOException("JOURNAL_SECURITY_DESCRIPTOR");uint n=GetSecurityDescriptorLength(sd);if(n==0||n>65536)throw new IOException("JOURNAL_SECURITY_BOUND");byte[] b=new byte[n];Marshal.Copy(sd,b,0,(int)n);if(directory)DirectoryPermissions(new RawSecurityDescriptor(b,0),sid);else Permissions(new RawSecurityDescriptor(b,0),sid);return Convert.ToBase64String(b);}finally{LocalFree(sd);}}
 public static byte[] Bounded(Stream stream){byte[] b=new byte[4097];int at=0,n;while(at<b.Length&&(n=stream.Read(b,at,b.Length-at))!=0)at+=n;if(at==0||at>4096)throw new IOException("JOURNAL_FILE_BOUND");byte[] result=new byte[at];Array.Copy(b,result,at);return result;}
 public static void Same(string before,string after){if(before!=after)throw new IOException("JOURNAL_CHANGED");}
 static SafeFileHandle Open(string p,bool dir){return CreateFile(p,dir?0x20080u:0x80020000u,dir?3u:1u,IntPtr.Zero,3,0x00200000u|(dir?0x02000000u:0u),IntPtr.Zero);}
 public static byte[] Read(string path,string state,string sid){List<SafeFileHandle> parents=new List<SafeFileHandle>();List<string> names=new List<string>();List<string> pins=new List<string>();List<string> security=new List<string>();try{
  for(string p=Path.GetDirectoryName(path);p!=null;p=Path.GetDirectoryName(p)){var h=Open(p,true);parents.Add(h);names.Add(p);pins.Add(DirectoryId(Inspect(h,true)));security.Add(String.Equals(p,state,StringComparison.OrdinalIgnoreCase)?Security(h,sid,true):null);if(Path.GetPathRoot(p)==p)break;}
  using(var h=Open(path,false)){string before=Id(Inspect(h,false)),acl=Security(h,sid);Info i=Inspect(h,false);if(i.SizeHigh!=0||i.SizeLow==0||i.SizeLow>4096)throw new IOException("JOURNAL_FILE_BOUND");byte[] body;using(var f=new FileStream(h,FileAccess.Read,4097,false)){body=Bounded(f);Same(before,Id(Inspect(h,false)));Same(acl,Security(h,sid));using(var named=Open(path,false)){Same(before,Id(Inspect(named,false)));Same(acl,Security(named,sid));}}
   for(int x=0;x<parents.Count;x++){Same(pins[x],DirectoryId(Inspect(parents[x],true)));if(security[x]!=null)Same(security[x],Security(parents[x],sid,true));using(var named=Open(names[x],true)){Same(pins[x],DirectoryId(Inspect(named,true)));if(security[x]!=null)Same(security[x],Security(named,sid,true));}}return body;}
 }finally{foreach(var h in parents)h.Dispose();}}
}
'@}
$journals=@();$population=[IO.Directory]::EnumerateFileSystemEntries($state,'.install-correlation-*').GetEnumerator();try{while($population.MoveNext()){if($journals.Count -ge 256){throw 'JOURNAL_RESOURCE_BOUND'};$journals+=,(Get-Item -LiteralPath $population.Current -Force)}}finally{$population.Dispose()};$bound=@();$seen=@();$journalTotalBytes=0
foreach($file in $journals){
 if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Name -cnotmatch '^\.install-correlation-[0-9a-f]{64}\.json$' -or $file.Length -le 0 -or $file.Length -gt 4096){throw 'JOURNAL_FILE_SCHEMA'}
 $journalTotalBytes+=$file.Length;if($journalTotalBytes -gt 1048576){throw 'JOURNAL_TOTAL_BYTES'}
 $journalBytes=[SecondaryJournalRead]::Read($file.FullName,$state,$id.User.Value);if($journalBytes.Length -ne $file.Length){throw 'JOURNAL_CHANGED'}
 $j=[Text.UTF8Encoding]::new($false,$true).GetString($journalBytes)|ConvertFrom-Json;$keys=@($j.PSObject.Properties.Name|Sort-Object);$expected=@('controllerId','jobId','operationId','requestId','version','workspaceKey');if($keys -contains 'receiptAuthority'){$expected+=,'receiptAuthority';if($j.receiptAuthority -isnot [string] -or $j.receiptAuthority -cne 'MACHINE'){throw 'JOURNAL_AUTHORITY'}};$expected=@($expected|Sort-Object)
 if(($keys -join ',') -cne ($expected -join ',') -or ($j.version -isnot [int] -and $j.version -isnot [long]) -or $j.version -ne 1 -or $j.workspaceKey -isnot [string] -or $j.workspaceKey -cne 'd94ed56fa2ae3b80c12a1694f2eec1cac73ce7a3192bc5cedb483087d40b98c7'){throw 'JOURNAL_SCHEMA'}
 foreach($key in @('controllerId','operationId','requestId')){if($j.$key -isnot [string] -or [string]::IsNullOrWhiteSpace($j.$key) -or $j.$key.Length -gt 256 -or @($j.$key.ToCharArray()|Where-Object {[int]$_ -lt 32}).Count -ne 0){throw 'JOURNAL_IDENTIFIER'}}
 [Guid]$jobGuid=[Guid]::Empty;if($j.jobId -isnot [string] -or -not[Guid]::TryParse($j.jobId,[ref]$jobGuid) -or $jobGuid.ToString('D') -cne $j.jobId){throw 'JOURNAL_JOB'}
 $controllerEscaped=$j.controllerId.Replace('\','\\').Replace('"','\"');$operationEscaped=$j.operationId.Replace('\','\\').Replace('"','\"');$canonical='{"controllerId":"'+$controllerEscaped+'","operationId":"'+$operationEscaped+'"}';$digest=[Security.Cryptography.SHA256]::Create();try{$nameHash=([BitConverter]::ToString($digest.ComputeHash([Text.UTF8Encoding]::new($false,$true).GetBytes($canonical)))).Replace('-','').ToLowerInvariant()}finally{$digest.Dispose()}
 if($file.Name -cne ('.install-correlation-'+$nameHash+'.json')){throw 'JOURNAL_FILENAME_BINDING'}
 foreach($previous in $seen){if($previous.jobId -ceq $j.jobId -or ($previous.controllerId -ceq $j.controllerId -and ($previous.requestId -ceq $j.requestId -or $previous.operationId -ceq $j.operationId))){throw 'JOURNAL_CONFLICT'}}
 $seen+=,$j;if($j.controllerId -ceq $request.controllerId -and $j.requestId -ceq $request.requestId -and $j.operationId -ceq $request.operationId){$bound+=,$j}
}
if($bound.Count -ne 1){throw 'NEW_JOURNAL_BINDING'};$j=$bound[0]
$helper='C:\Users\parityagent\AppData\Local\vpn-control\app\native\windows-amd64\vpn-control-install-helper.exe';$helperHash=(Get-FileHash -LiteralPath $helper -Algorithm SHA256).Hash.ToLowerInvariant();if($helperHash -cne '920127c5ce9030b48d75cc7ac50d82c090c2823bea1f28091e3c1933c85303d4'){throw 'HELPER_BYTES'}
$inputPath='C:\Users\parityagent\AppData\Local\vpn-control-install-inputs\'+$j.jobId+'\request.json';$inputBytes=[IO.File]::ReadAllBytes($inputPath);if($inputBytes.Length -gt 65536){throw 'CURRENT_INPUT_SIZE'};$digest=[Security.Cryptography.SHA256]::Create();try{$internalSha=([BitConverter]::ToString($digest.ComputeHash($inputBytes))).Replace('-','').ToLowerInvariant()}finally{$digest.Dispose()};$r=[Text.UTF8Encoding]::new($false,$true).GetString($inputBytes)|ConvertFrom-Json

if($r.jobId -cne $j.jobId -or $r.principalSid -cne $id.User.Value -or $r.ownerPid -ne 1460 -or $r.stateDirectory -cne $state -or $r.packageSha256 -cne '27270314b2a39f9f47dab550290dbefd0745d50090f6e17f925ef0271cfa67aa'){throw 'CURRENT_INPUT_BINDING'}
Durable (Join-Path $root 'uac-binding.json') (@{schema=1;state='NEW_INSTALL_JOB_HELPER_INPUT_BOUND';jobId=$j.jobId;requestId=$j.requestId;operationId=$j.operationId;controllerId=$j.controllerId;helperSha256=$helperHash;internalRequestSha256=$internalSha;ownerPid=1460;originalSid=$id.User.Value;limited=$limited;sessionId=1;targetSha256=$r.packageSha256;workspaceKey=$j.workspaceKey;inputBound=$true;effects=$false}|ConvertTo-Json -Compress)

return $true
}catch{if(-not(Test-Path -LiteralPath (Join-Path $root 'ui-binding-error.private'))){Durable (Join-Path $root 'ui-binding-error.private') ($_|Out-String)};return $false}
}
function Test-ExactKeyAck($ack,$binding,$request,[string]$correlation){
 return ($null -ne $binding -and $ack.schema -eq 1 -and $ack.state -ceq 'FIXTURE_APPROVAL_KEY_ACK_ONLY' -and $ack.correlationId -ceq $correlation -and $ack.jobId -ceq $binding.jobId -and $ack.requestId -ceq $request.requestId -and $ack.operationId -ceq $request.operationId -and $ack.controllerId -ceq $request.controllerId -and $ack.inputAcknowledged -is [bool] -and $ack.inputAcknowledged -eq $true -and $ack.approvalSucceeded -is [bool] -and $ack.approvalSucceeded -eq $false -and ($ack.commandId -is [int] -or $ack.commandId -is [long]) -and $ack.commandId -gt 0 -and $ack.frameSha256 -cmatch '^[0-9a-f]{64}$')
}
$uiBound=$false;$keyAckObserved=$false;$uiDeadline=[DateTime]::UtcNow.AddSeconds(180)
# This fixture-only marker records matching QMP key ACK, never product approval.
# Keep the sole original90s ready poll available after actual prompt interaction.
while([DateTime]::UtcNow -lt $uiDeadline){
 if(-not $uiBound){$uiBound=Try-CurrentBinding}
 $markerPath=Join-Path $root 'uac-grant-key-acknowledged.json'
 if(Test-Path -LiteralPath $markerPath){
  $keyAck=Get-Content -LiteralPath $markerPath -Raw|ConvertFrom-Json
  $binding=if($uiBound){Get-Content -LiteralPath (Join-Path $root 'uac-binding.json') -Raw|ConvertFrom-Json}else{$null}
  if(-not(Test-ExactKeyAck $keyAck $binding $request 'f752de9b-c379-4462-aa9a-14d2bec0f33e')){throw 'FIXTURE_KEY_ACK_TUPLE'}
  $keyAckObserved=$true;break
 }
 Start-Sleep -Milliseconds 100
}
Durable (Join-Path $root 'fixture-ui-wait-result.json') (@{keyAckObserved=$keyAckObserved;approvalSucceeded=$false;requestId=$request.requestId;operationId=$request.operationId;replayAllowed=$false}|ConvertTo-Json -Compress)
# Same original operation only. The bound status ACK allows the product's ordinary exit gate.
$pollDeadline=[DateTime]::UtcNow.AddSeconds(90);$index=0;$ackObserved=$false
while([DateTime]::UtcNow -lt $pollDeadline){
 if(-not $uiBound){$uiBound=Try-CurrentBinding}
 $path=Join-Path $root ('operation-'+$index+'.json')
$wireRaw=(& $cli --state-dir $state --json --controller-id $ep.controllerId --timeout-seconds 3 operations status $request.operationId|Out-String);Durable $path $wireRaw
 $pollExit=$LASTEXITCODE;Durable (Join-Path $root ('operation-'+$index+'.exit')) ([string]$pollExit)
 $index++;$op=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
 if($op.controllerId -ceq $ep.controllerId -and $op.operationId -ceq $request.operationId){
  if($pollExit -eq 0 -and $op.code -ceq 'ACCEPTED' -and $op.final -eq $false -and $op.data.handoffReady -eq $true){$ackObserved=$true;break}
  if($op.final -eq $true){break}
 }
 Start-Sleep -Milliseconds 250
}
Durable (Join-Path $root 'ack-poll-result.json') (@{schema=1;state='SAME_OPERATION_ACK_POLL_CLOSED';requestId=$request.requestId;operationId=$request.operationId;controllerId=$ep.controllerId;handoffAckObserved=$ackObserved;queryCount=$index;replayAllowed=$false;installerResubmitted=$false}|ConvertTo-Json -Compress)

}catch{Durable (Join-Path $root 'primary-error.private') ($_|Out-String);if(-not(Test-Path -LiteralPath (Join-Path $root 'result.json'))){Result @{schema=1;state='PUBLIC_INSTALL_PRE_REQUEST_FAILED';correlationId='f752de9b-c379-4462-aa9a-14d2bec0f33e';errorClass=$_.FullyQualifiedErrorId;errorMessage=$_.Exception.Message;replayAllowed=$false}};exit 1}

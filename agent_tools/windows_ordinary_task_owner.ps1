param(
 [Parameter(Mandatory=$true)][string]$RequestPath,
 [Parameter(Mandatory=$true)][string]$RequestSha256,
 [Parameter(Mandatory=$true)][string]$RequestPinBase64
)
# Whole-owner native qualification is required before any new task or child.
# A qualified SYSTEM producer authenticates/holds this whole source before the
# new Limited / InteractiveToken task starts it. No credentials are accepted.
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$script:Owned=[ordered]@{process=$null;started=$false;pins=[Collections.Generic.List[object]]::new();pumps=@();outputs=@();request=$null;root=$null;event=0;unknown=$null;self=$null;selfBirth=$null}

function Park-Original([string]$Reason,[object]$ErrorObject) {
 $script:Owned.unknown=@{reason=$Reason;primary=$ErrorObject}
 try{
  if($null -ne $script:Owned.root){
   $bytes=[Text.UTF8Encoding]::new($false).GetBytes((@{schemaVersion=1;state='unknown';reason=$Reason;operationId=$script:Owned.request.operationId;originalNamespaceRetained=$true;replayAllowed=$false}|ConvertTo-Json -Compress))
   $notice=[IO.File]::Open((Join-Path $script:Owned.root 'task-owner-parked.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
   try{$notice.Write($bytes,0,$bytes.Length);$notice.Flush($true)}finally{$notice.Dispose()}
  }
 }catch{$script:Owned.unknown.noticeError=$_}
 while($true){[Threading.Thread]::Sleep(1000)}
}
function Write-OwnedEvent([string]$Kind,[object]$Value) {
 try{
  if($script:Owned.event -ge 8192){throw 'TASK_EVENT_COUNT_BOUND'}
  $data=[Text.UTF8Encoding]::new($false).GetBytes((@{schemaVersion=1;operationId=$script:Owned.request.operationId;ownerPid=$PID;ownerBirthFileTimeUtc=$script:Owned.selfBirth;ordinal=$script:Owned.event;kind=$Kind;value=$Value}|ConvertTo-Json -Depth 20 -Compress))
  if($data.Length -gt 262144){throw 'TASK_EVENT_BYTE_BOUND'}
  $path=Join-Path $script:Owned.root ('task-event-{0:D6}-{1}.json' -f $script:Owned.event,$Kind);$script:Owned.event++
  $file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
  try{$file.Write($data,0,$data.Length);$file.Flush($true)}finally{$file.Dispose()}
 }catch{Park-Original 'TASK_EVENT_JOURNAL_UNKNOWN' $_}
}

Add-Type -TypeDefinition @'
using System;using System.IO;using System.Text;using System.Threading.Tasks;using System.ComponentModel;using System.Runtime.InteropServices;using System.Security.Principal;using Microsoft.Win32.SafeHandles;using System.Collections.Generic;
public static class OrdinaryNativeFacts {
 [DllImport("kernel32.dll")]static extern IntPtr GetCurrentProcess();
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool CloseHandle(IntPtr h);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern SafeFileHandle CreateFile(string p,uint access,uint share,IntPtr sec,uint create,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetFileInformationByHandle(SafeFileHandle h,out FI i);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetProcessTimes(IntPtr h,out long c,out long e,out long k,out long u);
 [DllImport("kernel32.dll")]static extern IntPtr LocalFree(IntPtr p);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool OpenProcessToken(IntPtr p,uint access,out IntPtr t);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool GetTokenInformation(IntPtr t,int kind,IntPtr data,int size,out int needed);
 [DllImport("advapi32.dll")]static extern uint GetSecurityInfo(SafeFileHandle h,int type,uint info,out IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl,out IntPtr sd);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(IntPtr sd,uint revision,uint info,out IntPtr text,out uint len);
 [DllImport("ntdll.dll")]static extern int NtQuerySystemInformation(int kind,IntPtr data,int size,out int returned);
 [StructLayout(LayoutKind.Sequential,Pack=4)]struct FI {public uint attr;public long creation;public long access;public long write;public uint volume;public uint sizeHi;public uint sizeLo;public uint links;public uint indexHi;public uint indexLo;}
 [StructLayout(LayoutKind.Sequential)]struct Group {public IntPtr sid;public uint attributes;}
 [StructLayout(LayoutKind.Sequential)]struct Groups {public uint count;public Group first;}
 static void Win(bool ok){if(!ok)throw new Win32Exception(Marshal.GetLastWin32Error());}
 static int Scalar(IntPtr t,int kind){IntPtr b=Marshal.AllocHGlobal(4);try{int n;Win(GetTokenInformation(t,kind,b,4,out n));if(n!=4)throw new InvalidOperationException("scalar-size");return Marshal.ReadInt32(b);}finally{Marshal.FreeHGlobal(b);}}
 public static string[] Token(){IntPtr t;Win(OpenProcessToken(GetCurrentProcess(),8,out t));try{
  int n;GetTokenInformation(t,2,IntPtr.Zero,0,out n);if(n<=0||n>65536)throw new InvalidOperationException("groups-bound");IntPtr b=Marshal.AllocHGlobal(n);
  try{int used;Win(GetTokenInformation(t,2,b,n,out used));int count=Marshal.ReadInt32(b),offset=Marshal.OffsetOf(typeof(Groups),"first").ToInt32(),stride=Marshal.SizeOf(typeof(Group));if(count<0||count>256||offset+count*stride>used)throw new InvalidOperationException("groups-shape");bool member=false,enabled=false;
   for(int i=0;i<count;i++){Group g=(Group)Marshal.PtrToStructure(IntPtr.Add(b,offset+i*stride),typeof(Group));if(new SecurityIdentifier(g.sid).Value=="S-1-5-32-544"){member=true;enabled=(g.attributes&4)!=0&&(g.attributes&16)==0;}}
   using(WindowsIdentity id=new WindowsIdentity(t)){return new string[]{id.User.Value,Scalar(t,12).ToString(),Scalar(t,20).ToString(),Scalar(t,18).ToString(),member.ToString(),enabled.ToString()};}
  }finally{Marshal.FreeHGlobal(b);}
 }finally{CloseHandle(t);}}
 public static string BootIdentifier(){IntPtr b=Marshal.AllocHGlobal(32);try{int n;int status=NtQuerySystemInformation(90,b,32,out n);if(status!=0||n!=32)throw new InvalidOperationException("boot-private-ABI-unqualified");byte[] bytes=new byte[16];Marshal.Copy(b,bytes,0,16);Guid g=new Guid(bytes);if(g==Guid.Empty)throw new InvalidOperationException("boot-zero");return g.ToString();}finally{Marshal.FreeHGlobal(b);}}
 public static long Birth(IntPtr process){long c,e,k,u;Win(GetProcessTimes(process,out c,out e,out k,out u));return c;}
 public static SafeFileHandle OpenDirectory(string p){SafeFileHandle h=CreateFile(p,0x20080,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);Win(!h.IsInvalid);return h;}
 public static FileStream OpenHeld(string p){SafeFileHandle h=CreateFile(p,0x80020000,1,IntPtr.Zero,3,0x02200000,IntPtr.Zero);Win(!h.IsInvalid);try{return new FileStream(h,FileAccess.Read,65536,false);}catch{h.Dispose();throw;}}
 public static Dictionary<string,object> Identity(SafeFileHandle h,bool directory){FI i;Win(GetFileInformationByHandle(h,out i));if((i.attr&0x400)!=0||((i.attr&0x10)!=0)!=directory||(!directory&&i.links!=1))throw new InvalidOperationException("file-type-reparse-link");var r=new Dictionary<string,object>();r["attributes"]=i.attr;r["volumeSerial"]=i.volume;r["fileIndex"]=((ulong)i.indexHi<<32)|i.indexLo;if(!directory){r["sizeBytes"]=((ulong)i.sizeHi<<32)|i.sizeLo;r["links"]=i.links;r["creationFileTime"]=i.creation.ToString(System.Globalization.CultureInfo.InvariantCulture);r["lastWriteFileTime"]=i.write.ToString(System.Globalization.CultureInfo.InvariantCulture);}return r;}
 public static string[] Security(SafeFileHandle h){IntPtr owner,sd;uint code=GetSecurityInfo(h,1,5,out owner,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,out sd);if(code!=0)throw new Win32Exception((int)code);try{IntPtr text;uint len;Win(ConvertSecurityDescriptorToStringSecurityDescriptor(sd,1,5,out text,out len));try{return new string[]{new SecurityIdentifier(owner).Value,Marshal.PtrToStringUni(text)};}finally{LocalFree(text);}}finally{LocalFree(sd);}}
}
public sealed class RetainedRawPump {
 public readonly Stream Input;public readonly FileStream Output;public readonly long Limit;public Task Task;
 public volatile bool Eof;public volatile string Error;public byte[] Pending;public long Bytes;
 public RetainedRawPump(Stream input,FileStream output,long limit){Input=input;Output=output;Limit=limit;}
 public void Start(){if(Task!=null)throw new InvalidOperationException("pump-already-started");Task=System.Threading.Tasks.Task.Run((Action)Run);}
 void Run(){try{byte[] b=new byte[65536];while(true){int want=(int)Math.Min(b.Length,Math.Max(1,Limit-Bytes+1));int n=Input.Read(b,0,want);if(n==0){Output.Flush(true);Eof=true;return;}Pending=new byte[n];Buffer.BlockCopy(b,0,Pending,0,n);Output.Write(Pending,0,n);Bytes+=n;Pending=null;if(Bytes>Limit)throw new InvalidOperationException("raw-bound-retained");}}catch(Exception e){Error=e.GetType().FullName+":"+e.Message;}}
}
'@ -ReferencedAssemblies @('System','System.Core')

function Assert-NativeIdentity([object]$Actual,[object]$Expected) {
 $keys=@($Expected.PSObject.Properties.Name)
 if($Actual.Count -ne $keys.Count){throw 'TASK_NATIVE_IDENTITY_SCHEMA'}
 foreach($key in $keys){if(-not $Actual.ContainsKey($key) -or [string]$Actual[$key] -cne [string]$Expected.$key){throw 'TASK_NATIVE_IDENTITY_CHANGED'}}
}
function Assert-Pin([object]$Pin) {
 $handle=if($Pin.directory){$Pin.handle}else{$Pin.stream.SafeFileHandle}
 Assert-NativeIdentity ([OrdinaryNativeFacts]::Identity($handle,$Pin.directory)) $Pin.record.nativeIdentity
 $security=[OrdinaryNativeFacts]::Security($handle)
 if($security[0] -cne $Pin.record.security.ownerSid -or $security[1] -cne $Pin.record.security.sddl){throw 'TASK_PIN_SECURITY_CHANGED'}
 $named=$null
 try{
  $named=if($Pin.directory){[OrdinaryNativeFacts]::OpenDirectory($Pin.record.path)}else{[OrdinaryNativeFacts]::OpenHeld($Pin.record.path)}
  $namedHandle=if($Pin.directory){$named}else{$named.SafeFileHandle}
  Assert-NativeIdentity ([OrdinaryNativeFacts]::Identity($namedHandle,$Pin.directory)) $Pin.record.nativeIdentity
  $namedSecurity=[OrdinaryNativeFacts]::Security($namedHandle)
  if($namedSecurity[0] -cne $Pin.record.security.ownerSid -or $namedSecurity[1] -cne $Pin.record.security.sddl){throw 'TASK_NAMED_SECURITY_CHANGED'}
 }finally{if($null -ne $named){$named.Dispose()}}
}
function Get-PinHash([object]$Pin) {
 Assert-Pin $Pin;$Pin.stream.Position=0;$hash=[Security.Cryptography.SHA256]::Create()
 try{$value=([BitConverter]::ToString($hash.ComputeHash($Pin.stream))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
 if($value -cne $Pin.record.sha256){throw 'TASK_PIN_DIGEST_CHANGED'}
 Assert-Pin $Pin;return $value
}
function Add-FilePin([object]$Record) {
 $pin=@{record=$Record;directory=$false;stream=[OrdinaryNativeFacts]::OpenHeld($Record.path)}
 $script:Owned.pins.Add($pin);[void](Get-PinHash $pin);return $pin
}
function Assert-Context {
 $c=$script:Owned.request.context;$token=[OrdinaryNativeFacts]::Token()
 if($c.bootFileTimeUtc -isnot [string] -or $c.bootFileTimeUtc -cnotmatch '\A[1-9][0-9]{0,18}\z'){throw 'TASK_EXACT_BOOT_FILETIME_STRING'}
 if($token[0] -cne $c.ordinarySid -or $token[1] -cne [string]$c.ordinarySessionId -or $token[2] -cne '0' -or $token[3] -cne '1' -or $token[4] -cne 'False' -or $token[5] -cne 'False'){throw 'TASK_STANDARD_TOKEN'}
 if(-not [Environment]::Is64BitProcess -or -not [Environment]::Is64BitOperatingSystem -or $PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5){throw 'TASK_PS51_AMD64'}
 if($env:USERPROFILE -ine $c.profileRoot -or $env:LOCALAPPDATA -ine $c.localAppData){throw 'TASK_PROFILE'}
 if([OrdinaryNativeFacts]::BootIdentifier() -cne $c.bootIdentifier){throw 'TASK_NATIVE_BOOT'}
 if((Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToFileTimeUtc() -ne [long]$c.bootFileTimeUtc){throw 'TASK_CIM_BOOT'}
 if((Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid -ine $c.machineGuid){throw 'TASK_MACHINE_GUID'}
 foreach($pin in $script:Owned.pins){Assert-Pin $pin}
 foreach($tree in $script:Owned.request.treePins){
  $actual=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  $todo=[Collections.Generic.Stack[IO.DirectoryInfo]]::new();$todo.Push([IO.DirectoryInfo]::new($tree.root))
  while($todo.Count -gt 0){
   $directory=$todo.Pop();if(($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){throw 'TASK_TREE_DIRECTORY_REPARSE'}
   foreach($item in $directory.GetFileSystemInfos()){
    if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){throw 'TASK_TREE_ENTRY_REPARSE'}
    if($item -is [IO.DirectoryInfo]){$todo.Push($item)}
    else{
     $relative=$item.FullName.Substring($tree.root.Length+1).Replace('\','/')
     if(-not $actual.Add($relative) -or $actual.Count -gt 8192){throw 'TASK_TREE_ALIAS_OR_BOUND'}
     if(@($script:Owned.pins|Where-Object {-not $_.directory -and $_.record.path -ceq $item.FullName}).Count -ne 1){throw 'TASK_TREE_FILE_NOT_PINNED'}
    }
   }
  }
  if(-not $actual.SetEquals([string[]]$tree.files)){throw 'TASK_TREE_MEMBERSHIP_CHANGED'}
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
function Wait-OriginalChild {
 $next=[DateTime]::UtcNow.AddSeconds(30)
 while($true){
  foreach($pump in $script:Owned.pumps){if($null -ne $pump.Error){Park-Original 'TASK_RAW_CAPTURE_UNKNOWN' $pump.Error}}
  try{$exited=$script:Owned.process.WaitForExit(100)}catch{Park-Original 'TASK_ORIGINAL_HANDLE_UNKNOWN' $_}
  if($exited -and $script:Owned.pumps[0].Eof -and $script:Owned.pumps[1].Eof){return}
  if([DateTime]::UtcNow -ge $next){Write-OwnedEvent 'pending' @{pid=$script:Owned.process.Id;birthFileTimeUtc=$script:Owned.childBirth;stdoutEof=$script:Owned.pumps[0].Eof;stderrEof=$script:Owned.pumps[1].Eof;originalHandleRetained=$true;replayAllowed=$false};$next=[DateTime]::UtcNow.AddSeconds(30)}
  [Threading.Thread]::Sleep(100)
 }
}

try{
 $requestRecord=([Text.UTF8Encoding]::new($false,$true)).GetString([Convert]::FromBase64String($RequestPinBase64))|ConvertFrom-Json
 if($requestRecord.path -cne $RequestPath -or $requestRecord.sha256 -cne $RequestSha256){throw 'TASK_REQUEST_ARGUMENT_BINDING'}
 $requestPin=Add-FilePin $requestRecord
 if($requestPin.stream.Length -gt 4194304){throw 'TASK_REQUEST_BOUND'}
 $requestPin.stream.Position=0;$reader=[IO.StreamReader]::new($requestPin.stream,[Text.UTF8Encoding]::new($false,$true),$false,65536,$true)
 try{$script:Owned.request=$reader.ReadToEnd()|ConvertFrom-Json}finally{$reader.Dispose()}
 $r=$script:Owned.request;$script:Owned.root=$r.operationRoot
 if($r.schemaVersion -ne 1 -or ([Guid]::Parse($r.operationId)).ToString() -cne $r.operationId){throw 'TASK_REQUEST_SCHEMA'}
 if(@($r.filePins).Count -gt 4096 -or @($r.directoryPins).Count -gt 1024){throw 'TASK_PIN_CAPACITY'}
 foreach($record in $r.directoryPins){$pin=@{record=$record;directory=$true;handle=[OrdinaryNativeFacts]::OpenDirectory($record.path)};$script:Owned.pins.Add($pin);Assert-Pin $pin}
 foreach($record in $r.filePins){[void](Add-FilePin $record)}
 $sourcePin=@($script:Owned.pins|Where-Object {-not $_.directory -and $_.record.path -ceq $PSCommandPath})
 if($sourcePin.Count -ne 1){throw 'TASK_WHOLE_SOURCE_PIN'}
 Assert-Context
 $mode=$r.bootstrap.mode
 if($mode -ceq 'qualification'){
  $exe='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
  if(@($script:Owned.pins|Where-Object {-not $_.directory -and $_.record.path -ceq $r.bootstrap.qualificationSourcePath}).Count -ne 1){throw 'TASK_QUALIFICATION_SOURCE_PIN'}
  $arguments=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$r.bootstrap.qualificationSourcePath)+@($r.bootstrap.qualificationArguments)
 }elseif($mode -ceq 'python-install'){
  $exe=$r.bootstrap.pythonInstallerPath
  if($r.bootstrap.pythonLogPath -notlike ($r.operationRoot+'\*') -or (Test-Path -LiteralPath $r.bootstrap.pythonLogPath)){throw 'TASK_NEW_PYTHON_LOG'}
  if($r.bootstrap.pythonTargetDir -notlike ($r.context.localAppData+'\*') -or (Test-Path -LiteralPath $r.bootstrap.pythonTargetDir)){throw 'TASK_NEW_PERUSER_PYTHON_ROOT'}
  $arguments=@('/quiet','InstallAllUsers=0','PrependPath=0','Include_launcher=0','Include_pip=0','Include_test=0','/log',$r.bootstrap.pythonLogPath,('TargetDir='+$r.bootstrap.pythonTargetDir))
  $installerPin=@($script:Owned.pins|Where-Object {-not $_.directory -and $_.record.path -ceq $exe})
  if($installerPin.Count -ne 1 -or $installerPin[0].record.sha256 -cne 'edec09c4853aeae9ac36efb8c9f95b6b8e2fee65eee56d9767a8b7c69c574403' -or $installerPin[0].stream.Length -ne 29452944){throw 'TASK_EXACT_PYTHON_INSTALLER'}
  $signature=Get-AuthenticodeSignature -LiteralPath $exe
  if($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or $signature.SignerCertificate.Subject -notmatch 'O=Python Software Foundation'){throw 'TASK_PYTHON_INSTALLER_SIGNER'}
  $h=[Security.Cryptography.SHA256]::Create();try{$cert=([BitConverter]::ToString($h.ComputeHash($signature.SignerCertificate.RawData))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}
  if($cert -cne $r.bootstrap.pythonInstallerSignerCertificateSha256){throw 'TASK_PYTHON_INSTALLER_CERT_BINDING'}
 }elseif($mode -ceq 'python-worker'){
  $exe=$r.bootstrap.pythonPath
  $arguments=@('-I','-S','-B',$r.bootstrap.workerPath,'--request',$r.bootstrap.workerRequestPath,'--request-sha256',$r.bootstrap.workerRequestSha256,'--request-pin-base64',$r.bootstrap.workerRequestPinBase64)
  foreach($path in @($exe,$r.bootstrap.workerPath,$r.bootstrap.workerRequestPath)){if(@($script:Owned.pins|Where-Object {-not $_.directory -and $_.record.path -ceq $path}).Count -ne 1){throw 'TASK_WORKER_INPUT_NOT_PINNED'}}
  # Interpreter architecture/version/signature and complete runtime tree are a
  # separate native admission, then all resulting exact files are held here.
  if((Get-Item -LiteralPath $exe).VersionInfo.ProductVersion -notmatch '^3\.13\.15(?:\.0)?(?:\s|$)'){throw 'TASK_PYTHON_METADATA_VERSION'}
  $runtime=$r.pythonRuntime
  if($null -eq $runtime -or $runtime.version -cne '3.13.15' -or $runtime.architecture -cne 'amd64' -or $runtime.interpreterPath -cne $exe -or (Join-Path $runtime.root 'python.exe') -cne $exe){throw 'TASK_PYTHON_RUNTIME_ROLE_BINDING'}
  $runtimeTrees=@($r.treePins|Where-Object {$_.role -ceq 'python-runtime' -and $_.root -ceq $runtime.root})
  if($runtimeTrees.Count -ne 1){throw 'TASK_COMPLETE_PYTHON_RUNTIME_TREE_REQUIRED'}
  $runtimeNames=[Collections.Generic.HashSet[string]]::new([string[]]($runtimeTrees[0].files),[StringComparer]::Ordinal)
  foreach($name in @('python.exe','python313.dll','Lib/os.py','Lib/subprocess.py','Lib/threading.py','Lib/json/__init__.py','Lib/ctypes/__init__.py','DLLs/_ctypes.pyd')){if(-not $runtimeNames.Contains($name)){throw 'TASK_REQUIRED_PYTHON_RUNTIME_FILE_MISSING'}}
 }else{throw 'TASK_BOOTSTRAP_MODE'}
 if(@($script:Owned.pins|Where-Object {-not $_.directory -and $_.record.path -ceq $exe}).Count -ne 1){throw 'TASK_EXECUTABLE_NOT_PINNED'}
 if([long]$r.rawStreamLimitBytes -lt 4096 -or [long]$r.rawStreamLimitBytes -gt 67108864){throw 'TASK_RAW_RESOURCE_BOUND'}
 $line=($arguments|ForEach-Object {if($null -eq $_ -or ([string]$_).Contains([char]0)){throw 'TASK_ARG_NUL'};ConvertTo-OwnedArgument ([string]$_)}) -join ' '
 $complete=(ConvertTo-OwnedArgument $exe)+' '+$line
 if(([Text.Encoding]::Unicode.GetByteCount($complete)/2+1) -gt 32767){throw 'TASK_WINDOWS_COMMAND_LIMIT'}
 if([Text.Encoding]::UTF8.GetByteCount((@{path=$exe;arg=$arguments}|ConvertTo-Json -Depth 8 -Compress)) -gt 60000){throw 'TASK_COMMAND_JSON_LIMIT'}
 $script:Owned.self=[Diagnostics.Process]::GetCurrentProcess();$script:Owned.selfBirth=([OrdinaryNativeFacts]::Birth($script:Owned.self.Handle)).ToString([Globalization.CultureInfo]::InvariantCulture)
 Write-OwnedEvent 'submission-intent' @{mode=$mode;fileName=$exe;argv=$arguments;commandUtf16Units=([Text.Encoding]::Unicode.GetByteCount($complete)/2+1);sourceAndPackagePinsHeld=$true;nativeToken=[OrdinaryNativeFacts]::Token()}
 foreach($name in @('stdout','stderr')){$file=[IO.File]::Open((Join-Path $r.operationRoot ('task-child.'+$name+'.raw')),[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read);$script:Owned.outputs+=,$file}
 Assert-Context
 $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$exe;$start.Arguments=$line;$start.WorkingDirectory=$r.operationRoot;$start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
 foreach($name in @('DISPLAY','WAYLAND_DISPLAY','JAVA_TOOL_OPTIONS','_JAVA_OPTIONS','JDK_JAVA_OPTIONS','PYTHONPATH','PYTHONHOME')){$start.EnvironmentVariables.Remove($name)}
 $script:Owned.process=[Diagnostics.Process]::new();$script:Owned.process.StartInfo=$start
 # Store Process before Start; any post-Start exception parks the same object.
 if(-not $script:Owned.process.Start()){throw 'TASK_NATIVE_START_FALSE'}
 $script:Owned.started=$true
 $script:Owned.pumps+=,[RetainedRawPump]::new($script:Owned.process.StandardOutput.BaseStream,$script:Owned.outputs[0],[long]$r.rawStreamLimitBytes)
 $script:Owned.pumps+=,[RetainedRawPump]::new($script:Owned.process.StandardError.BaseStream,$script:Owned.outputs[1],[long]$r.rawStreamLimitBytes)
 foreach($pump in $script:Owned.pumps){$pump.Start()}
 $script:Owned.childBirth=([OrdinaryNativeFacts]::Birth($script:Owned.process.Handle)).ToString([Globalization.CultureInfo]::InvariantCulture)
 Write-OwnedEvent 'submitted' @{pid=$script:Owned.process.Id;birthFileTimeUtc=$script:Owned.childBirth;originalHandleRetained=$true}
 Wait-OriginalChild
 Assert-Context
 foreach($pin in $script:Owned.pins){if(-not $pin.directory){[void](Get-PinHash $pin)}}
 $exit=[int]$script:Owned.process.ExitCode
 $outputs=@();for($i=0;$i -lt 2;$i++){
  $output=$script:Owned.outputs[$i];$output.Flush($true);$output.Position=0;$h=[Security.Cryptography.SHA256]::Create()
  try{$outputHash=([BitConverter]::ToString($h.ComputeHash($output))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}
  $outputs+=,@{name=@('stdout','stderr')[$i];sizeBytes=$script:Owned.pumps[$i].Bytes;eof=$script:Owned.pumps[$i].Eof;sha256=$outputHash;nativeIdentity=[OrdinaryNativeFacts]::Identity($output.SafeFileHandle,$false)}
 }
 # Capture installer log only after its original process is known terminal.
 $log=$null
 if($mode -ceq 'python-install'){
  try{
   $logStream=[OrdinaryNativeFacts]::OpenHeld($r.bootstrap.pythonLogPath);$script:Owned.logStream=$logStream
   if($logStream.Length -gt 67108864){throw 'TASK_PYTHON_LOG_BOUND'}
   $h=[Security.Cryptography.SHA256]::Create();try{$logHash=([BitConverter]::ToString($h.ComputeHash($logStream))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}
   $log=@{path=$r.bootstrap.pythonLogPath;sizeBytes=$logStream.Length;sha256=$logHash;nativeIdentity=[OrdinaryNativeFacts]::Identity($logStream.SafeFileHandle,$false)}
  }catch{Park-Original 'TASK_PYTHON_LOG_CLOSING_UNKNOWN' $_}
 }
 Write-OwnedEvent 'terminal' @{pid=$script:Owned.process.Id;birthFileTimeUtc=$script:Owned.childBirth;exitCode=$exit;rawStreams=$outputs;log=$log;sourceClosing=$true;rebootRequired=($exit -eq 3010);installedAdmissionComplete=$false;fullWindowsAcceptance=$false}
 # All native work and raw EOF are known before explicit disposal. No finally
 # removes or disposes a live/unknown child, task, package, source or raw file.
 foreach($output in $script:Owned.outputs){$output.Dispose()}
 if($null -ne $script:Owned.logStream){$script:Owned.logStream.Dispose()}
 $script:Owned.process.Dispose()
 $script:Owned.self.Dispose()
 foreach($pin in $script:Owned.pins){if($pin.directory){$pin.handle.Dispose()}else{$pin.stream.Dispose()}}
 exit $exit
}catch{
 if($script:Owned.started -or $null -ne $script:Owned.process){Park-Original 'TASK_POST_SUBMISSION_UNKNOWN' $_}
 # Pre-submission refusal has no installer child. Keep a diagnostic when its
 # already-authenticated private root is available; never submit another task.
 if($null -ne $script:Owned.root){Write-OwnedEvent 'refused-before-native-start' @{errorClass=$_.Exception.GetType().FullName;message=$_.Exception.Message;childStarted=$false;replayAllowed=$false}}
 throw
}

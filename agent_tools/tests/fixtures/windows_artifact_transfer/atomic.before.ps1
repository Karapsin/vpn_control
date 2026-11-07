param([Parameter(Mandatory=$true)][string]$ExpectedSourceSha256,[Parameter(Mandatory=$true)][IO.FileStream]$HeldSource,[Parameter(Mandatory=$true)][string]$SourcePath)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18' -or (Get-Process -Id $PID).SessionId -ne 0 -or -not [Environment]::Is64BitProcess -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSEdition -cne 'Desktop'){throw 'ARTIFACT_SYSTEM_CONTEXT'}
$transfer='17222d9f-3f33-4746-8920-2c28c8659c52';$root='C:\ProgramData\VpnControlTransferProbe-17222d9f-3f33-4746-8920-2c28c8659c52';$path='C:\ProgramData\VpnControlTransferProbe-17222d9f-3f33-4746-8920-2c28c8659c52\probe.bin';$sid='S-1-5-21-4099058025-2437077614-260217637-1001'
if($transfer -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -or $root -cne ('C:\ProgramData\VpnControlTransferProbe-'+$transfer) -or [IO.Path]::GetFileName($path) -cnotin @('probe.bin')){throw 'ARTIFACT_ASSIGNED_SCOPE'}
if([IO.Path]::GetDirectoryName($root) -cne 'C:\ProgramData' -or [IO.Path]::GetDirectoryName($path) -cne $root){throw 'ARTIFACT_EXACT_PATH'}
foreach($name in @('C:\ProgramData','C:\')){if(((Get-Item -LiteralPath $name -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){throw 'ARTIFACT_PARENT_REPARSE'}}
function Read-ArtifactAcl([string]$Path,[bool]$Directory){
 $item=Get-Item -LiteralPath $Path -Force;if($item.PSIsContainer -ne $Directory -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){throw 'ARTIFACT_FILE_KIND'}
 $a=Get-Acl -LiteralPath $Path;$owner=$a.GetOwner([Security.Principal.SecurityIdentifier]).Value;$rules=@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]));if($owner -cne 'S-1-5-18' -or $rules.Count -ne 3 -or ($Directory -and -not $a.AreAccessRulesProtected)){throw 'ARTIFACT_ACL_OWNER'}
 $seen=@{};foreach($r in $rules){$id=$r.IdentityReference.Value;if($seen.ContainsKey($id) -or $r.AccessControlType -ne 'Allow' -or $r.IsInherited -eq $Directory){throw 'ARTIFACT_ACL_RULE'};$seen[$id]=$true;$rights=if($id -ceq 'S-1-5-18' -or $id -ceq 'S-1-5-32-544'){0x1f01ff}elseif($id -ceq $sid){0x1200a9}else{throw 'ARTIFACT_ACL_SID'};if([int]$r.FileSystemRights -ne $rights){throw 'ARTIFACT_ACL_RIGHTS'}}
 return [ordered]@{ownerSid=$owner;sddl=$a.Sddl;rules=3;protected=$a.AreAccessRulesProtected}
}
function Held-ArtifactSha([IO.FileStream]$File){$File.Position=0;$h=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($h.ComputeHash($File))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
Add-Type -TypeDefinition @'
using System;using System.ComponentModel;using System.Runtime.InteropServices;using Microsoft.Win32.SafeHandles;
public static class VpnArtifactHandle {
 [StructLayout(LayoutKind.Sequential)]struct Info { public uint Attributes,CreationLow,CreationHigh,AccessLow,AccessHigh,WriteLow,WriteHigh,Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow; }
 [DllImport("kernel32.dll")]static extern IntPtr GetCurrentProcess();
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool DuplicateHandle(IntPtr process,SafeFileHandle source,IntPtr target,out SafeFileHandle result,uint access,bool inherit,uint options);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetFileInformationByHandle(SafeFileHandle source,out Info result);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
 public static SafeFileHandle ReadOnly(SafeFileHandle source){SafeFileHandle result;if(!DuplicateHandle(GetCurrentProcess(),source,GetCurrentProcess(),out result,0x120089,false,0))throw new Win32Exception(Marshal.GetLastWin32Error());return result;}
 public static string Identity(SafeFileHandle source){Info r;if(!GetFileInformationByHandle(source,out r))throw new Win32Exception(Marshal.GetLastWin32Error());if(r.Links!=1)throw new InvalidOperationException("program-link-count");return r.Volume.ToString("x8")+":"+r.IndexHigh.ToString("x8")+r.IndexLow.ToString("x8");}
 public static int Refusal(string path,uint access){using(SafeFileHandle h=CreateFile(path,access,7,IntPtr.Zero,3,128,IntPtr.Zero)){return h.IsInvalid?Marshal.GetLastWin32Error():0;}}
}
'@ -ReferencedAssemblies @('System','System.Core')

Add-Type -TypeDefinition @'
using System;using System.ComponentModel;using System.Runtime.InteropServices;
public static class VpnCreateArtifactDirectory {
 [StructLayout(LayoutKind.Sequential)]struct Attributes {public int Length;public IntPtr Descriptor;[MarshalAs(UnmanagedType.Bool)]public bool Inherit;}
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text,uint revision,out IntPtr descriptor,out uint size);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool CreateDirectory(string path,ref Attributes attributes);
 [DllImport("kernel32.dll")]static extern IntPtr LocalFree(IntPtr memory);
 public static void New(string path,string sddl){IntPtr descriptor;uint size;if(!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl,1,out descriptor,out size))throw new Win32Exception(Marshal.GetLastWin32Error());try{Attributes a=new Attributes();a.Length=Marshal.SizeOf(typeof(Attributes));a.Descriptor=descriptor;a.Inherit=false;if(!CreateDirectory(path,ref a))throw new Win32Exception(Marshal.GetLastWin32Error());}finally{LocalFree(descriptor);}}
}
'@ -ReferencedAssemblies @('System','System.Core')
$sddl='O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;S-1-5-21-4099058025-2437077614-260217637-1001)'
if(Test-Path -LiteralPath $root){throw 'ARTIFACT_ROOT_EXISTS'}
[VpnCreateArtifactDirectory]::New($root,$sddl);$rootAcl=Read-ArtifactAcl $root $true
$f=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
try{
 $security=Get-Acl -LiteralPath $path;$originalOwner=$security.GetOwner([Security.Principal.SecurityIdentifier]).Value;$security.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18'));[IO.File]::SetAccessControl($path,$security);$fileAcl=Read-ArtifactAcl $path $false
 $f.Flush($true);$identity=[VpnArtifactHandle]::Identity($f.SafeFileHandle);$hash=Held-ArtifactSha $f;if($f.Length -ne 0 -or $hash -cne 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'){throw 'ARTIFACT_EMPTY_FILE'}
 $self=Get-Process -Id $PID;$result=[ordered]@{schemaVersion=1;state='created';transferId=$transfer;deploymentId='d493a373-1d2c-4ab0-bfd4-e93575019dce';rootPath=$root;filePath=$path;fileIdentity=$identity;rootAcl=$rootAcl;fileAcl=$fileAcl;originalFileOwnerSid=$originalOwner;bytes=0;sha256=$hash;rootCreateNew=$true;fileCreateNew=$true;parentChainNoReparse=$true;creatorPid=$PID;creatorBirthFileTime=$self.StartTime.ToUniversalTime().ToFileTimeUtc();creatorSessionId=$self.SessionId;principalSid='S-1-5-18';productOperation=$false}
 $refused=$false;try{[VpnCreateArtifactDirectory]::New($root,$sddl)}catch{$native=$_.Exception.GetBaseException();if($native -isnot [ComponentModel.Win32Exception] -or $native.NativeErrorCode -ne 183){throw};$refused=$true};if(-not $refused){throw 'PROBE_DIRECTORY_EXISTING_NOT_REFUSED'}
 $rootClosing=Read-ArtifactAcl $root $true;$fileClosing=Read-ArtifactAcl $path $false;if($rootClosing.sddl -cne $rootAcl.sddl -or $fileClosing.sddl -cne $fileAcl.sddl -or [VpnArtifactHandle]::Identity($f.SafeFileHandle) -cne $identity -or (Held-ArtifactSha $f) -cne $hash){throw 'PROBE_ENDPOINT_CLOSING'}
 foreach($name in @('C:\ProgramData','C:\',$root,$path)){if(((Get-Item -LiteralPath $name -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){throw 'PROBE_CLOSING_REPARSE'}}
 $result.pid=$PID;$result.birthFileTime=$self.StartTime.ToUniversalTime().ToFileTimeUtc();$result.atomicDirectoryCreateQualified=$true;$result.existingDirectoryRefused183=$refused;$result.aclClosing=$true;$result.fileIdentityClosing=$true;$result.nativeMechanismOnly=$true;$result.taskOperation=$false
 [pscustomobject]$result
}finally{$f.Dispose()}

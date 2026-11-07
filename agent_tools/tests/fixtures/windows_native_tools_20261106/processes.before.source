"""Read-only native process identities for Windows idle admission.

WMI omits image paths for protected processes. A missing native handle, birth,
image or protection observation remains a blocker; a familiar name is no proof.
"""
import sys

_EXECUTING_CODE=sys._getframe().f_code

NATIVE=r'''
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class RecoveryProcessIdentity {
 [DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool QueryFullProcessImageName(IntPtr h,uint flags,StringBuilder name,ref uint count);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetProcessTimes(IntPtr h,out long creation,out long exit,out long kernel,out long user);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetProcessInformation(IntPtr h,int kind,out uint protection,uint size);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern int GetPackageFullName(IntPtr h,ref uint length,StringBuilder name);
 [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);
 public class Facts {public uint pid;public string image;public string nativeImage;public string birth;public uint protection;public int openError;public int imageError;public int nativeError;public int birthError;public int protectionError;public string package;public int packageError;}
 public static Facts Read(uint pid){
  var r=new Facts();r.pid=pid;var h=OpenProcess(0x1000,false,pid);
  if(h==IntPtr.Zero){r.openError=Marshal.GetLastWin32Error();return r;}
  try{
   var b=new StringBuilder(32768);uint n=32768;
   if(QueryFullProcessImageName(h,0,b,ref n))r.image=b.ToString();else r.imageError=Marshal.GetLastWin32Error();
   b=new StringBuilder(32768);n=32768;
   if(QueryFullProcessImageName(h,1,b,ref n))r.nativeImage=b.ToString();else r.nativeError=Marshal.GetLastWin32Error();
   long c,e,k,u;if(GetProcessTimes(h,out c,out e,out k,out u))r.birth=c.ToString();else r.birthError=Marshal.GetLastWin32Error();
   uint p;if(GetProcessInformation(h,7,out p,4))r.protection=p;else r.protectionError=Marshal.GetLastWin32Error();
   n=0;int error=GetPackageFullName(h,ref n,null);
   if(error==122&&n>0&&n<=4096){b=new StringBuilder((int)n);error=GetPackageFullName(h,ref n,b);if(error==0)r.package=b.ToString();}
   r.packageError=error;return r;
  }finally{CloseHandle(h);}
 }
 // CIM datetime has microsecond resolution; native FILETIME has 100ns ticks.
 // Compare decimal strings, avoiding floating point rounding near 10^17.
 public static bool SameBirth(Facts f,string cimBirth){return f.birthError==0&&f.birth!=null&&f.birth.Length>=2&&f.birth.Substring(0,f.birth.Length-1)+"0"==cimBirth;}
 public static bool Kernel(Facts f,string name,uint parent,uint session,string cimBirth){
  if(f.pid==0)return name=="System Idle Process"&&parent==0&&session==0&&f.openError==87;
  if(f.openError!=0||f.protectionError!=0||f.protection!=5||session!=0||!SameBirth(f,cimBirth))return false;
  if(f.pid==4)return name=="System"&&parent==0&&f.nativeError==0&&f.nativeImage==""&&f.imageError==31;
  return parent==4&&f.nativeError==0&&((name=="Registry"&&f.nativeImage=="Registry")||(name=="Memory Compression"&&f.nativeImage=="MemCompression"));
 }
 public static bool Image(Facts f,string name,string cimBirth){
  if(f.openError!=0||f.imageError!=0||f.protectionError!=0||!SameBirth(f,cimBirth)||String.IsNullOrEmpty(f.image))return false;
  if(!(f.protection<=5||f.protection==0xfffffffe))return false;
  return String.Equals(System.IO.Path.GetFileName(f.image),name,StringComparison.OrdinalIgnoreCase);
 }
}
'''


def powershell_source():
    return "Add-Type -TypeDefinition @'\n"+NATIVE+"\n'@\n"+_ROLES


# Package.VerifyContentIntegrityAsync checks content, not origin or status:
# https://learn.microsoft.com/uwp/api/windows.applicationmodel.package.verifycontentintegrityasync
# Require all three independently. No package repair, deployment or setting API.
_ROLES=r'''
$RecoveryRoleSignatures=@{};$RecoveryRolePackages=@{}
function Test-RecoveryMicrosoftSignature([string]$path) {
 if($RecoveryRoleSignatures.ContainsKey($path)){return [bool]$RecoveryRoleSignatures[$path]}
 $valid=$false
 try {
  $signature=Get-AuthenticodeSignature -LiteralPath $path
  $publishers=@('CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US','CN=Microsoft Windows Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US','CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US')
  $valid=($signature.Status -eq 'Valid' -and $null -ne $signature.SignerCertificate -and $publishers -contains $signature.SignerCertificate.Subject)
 } catch {$valid=$false}
 $RecoveryRoleSignatures[$path]=[bool]$valid;return [bool]$valid
}
function Test-RecoveryWidgetPackage([object]$native,[string]$ordinary) {
 if($native.packageError -ne 0 -or [string]::IsNullOrEmpty($native.package)){return $false}
 $full=[string]$native.package
 if($full -notmatch '^Microsoft\.WidgetsPlatformRuntime_[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+_x64__8wekyb3d8bbwe$'){return $false}
 $expected=$env:ProgramFiles+'\WindowsApps\'+$full+'\WidgetService\WidgetService.exe'
 if(-not [string]::Equals($native.image,$expected,[StringComparison]::OrdinalIgnoreCase)){return $false}
 if($RecoveryRolePackages.ContainsKey($full)){return [bool]$RecoveryRolePackages[$full]}
 $valid=$false
 try {
  Add-Type -AssemblyName System.Runtime.WindowsRuntime
  $null=[Windows.Management.Deployment.PackageManager,Windows.Management.Deployment,ContentType=WindowsRuntime]
  $manager=[Windows.Management.Deployment.PackageManager]::new();$package=$manager.FindPackageForUser($ordinary,$full)
  if($package.Id.Name -ne 'Microsoft.WidgetsPlatformRuntime' -or $package.Id.FullName -ne $full -or $package.Id.PublisherId -ne '8wekyb3d8bbwe' -or $package.Id.Publisher -ne 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US' -or $package.SignatureKind.ToString() -notin @('Store','System') -or -not $package.Status.VerifyIsOK() -or -not [string]::Equals($package.InstalledLocation.Path,($env:ProgramFiles+'\WindowsApps\'+$full),[StringComparison]::OrdinalIgnoreCase)){throw 'PROCESS_PACKAGE_TRUST'}
  $methods=@([System.WindowsRuntimeSystemExtensions].GetMethods()|Where-Object {$_.Name -eq 'AsTask' -and $_.IsGenericMethodDefinition -and $_.GetGenericArguments().Count -eq 1 -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'})
  if($methods.Count -ne 1){throw 'PROCESS_PACKAGE_ASYNC'}
  $task=$methods[0].MakeGenericMethod([bool]).Invoke($null,@($package.VerifyContentIntegrityAsync()))
  $valid=($task.Wait(8000) -and [bool]$task.Result)
 } catch {$valid=$false}
 $RecoveryRolePackages[$full]=[bool]$valid;return [bool]$valid
}
function Get-RecoveryOneDriveMetadata([object]$p,[string]$ordinary) {
 $profile=$null;$hive=$null;$accounts=$null
 try {
  $owner=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction Stop
  if($owner.ReturnValue -ne 0){return $null}
  $profile=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(('SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\'+$ordinary),$false)
  if($null -eq $profile){return $null}
  $profileRoot=[Environment]::ExpandEnvironmentVariables([string]$profile.GetValue('ProfileImagePath'))
  if([string]::IsNullOrEmpty($profileRoot)){return $null}
  $hive=[Microsoft.Win32.Registry]::Users.OpenSubKey($ordinary,$false)
  if($null -eq $hive){return $null}
  $accounts=$hive.OpenSubKey('Software\Microsoft\OneDrive\Accounts',$false)
  if($null -ne $accounts){
   $slots=@($accounts.GetSubKeyNames());if($slots.Count -gt 32){return $null}
   foreach($slot in $slots){
    if($slot -ne 'Personal' -and $slot -notmatch '^Business[1-9][0-9]?$'){return $null}
    $account=$accounts.OpenSubKey($slot,$false)
    if($null -eq $account){return $null}
    try {
     # Read names only. No account IDs, addresses, tokens or folders are read.
     $fields=@($account.GetValueNames());if($fields.Count -gt 256){return $null}
     foreach($field in @('UserEmail','UserFolder','Cid','TenantId','AccountId','ServiceEndpointUri','ScopeId')){if($fields -contains $field){return $null}}
    }finally{$account.Dispose()}
   }
  }
  return @{ownerSid=$owner.Sid;profileRoot=$profileRoot;hiveLoaded=$true;accountsKnown=$true;configuredFieldsAbsent=$true}
 }catch{return $null}finally{foreach($key in @($accounts,$hive,$profile)){if($null -ne $key){$key.Dispose()}}}
}
function Test-RecoveryUnconfiguredOneDrive([object]$p,[object]$native,[string]$ordinary,[UInt32]$console) {
 if([UInt32]$p.SessionId -ne $console){return $false}
 $metadata=Get-RecoveryOneDriveMetadata $p $ordinary
 return [bool]($null -ne $metadata -and $metadata.hiveLoaded -eq $true -and $metadata.accountsKnown -eq $true -and $metadata.configuredFieldsAbsent -eq $true -and [string]::Equals($metadata.ownerSid,$ordinary,[StringComparison]::OrdinalIgnoreCase) -and -not [string]::IsNullOrEmpty($metadata.profileRoot) -and [string]::Equals($native.image,($metadata.profileRoot+'\AppData\Local\Microsoft\OneDrive\OneDrive.exe'),[StringComparison]::OrdinalIgnoreCase) -and (Test-RecoveryMicrosoftSignature $native.image))
}
function Test-RecoveryWebView([object]$p,[object]$native,[string]$ordinary,[UInt32]$console) {
 if([UInt32]$p.SessionId -ne $console -or $native.packageError -ne 0 -or $native.package -notmatch '^MicrosoftWindows\.Client\.(CBS|WebExperience)_[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+_x64__cw5n1h2txyewy$'){return $false}
 $pattern='^'+[regex]::Escape(${env:ProgramFiles(x86)}+'\Microsoft\EdgeWebView\Application\')+'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\\msedgewebview2\.exe$'
 if($native.image -notmatch $pattern -or -not (Test-RecoveryMicrosoftSignature $native.image)){return $false}
 $seen=@{};$child=$p;$childNative=$native
 for($depth=0;$depth -lt 8;$depth++){
  $parentId=[UInt32]$child.ParentProcessId
  if($seen.ContainsKey($parentId) -or -not $RecoveryRoleProcessMap.ContainsKey($parentId)){return $false}
  $seen[$parentId]=$true;$parent=$RecoveryRoleProcessMap[$parentId]
  $parentNative=[RecoveryProcessIdentity]::Read($parentId)
  $birth=if($null -eq $parent.CreationDate){''}else{$parent.CreationDate.ToUniversalTime().ToFileTimeUtc().ToString()}
  if(-not [RecoveryProcessIdentity]::Image($parentNative,[string]$parent.Name,$birth) -or [UInt32]$parent.SessionId -ne $console -or $parentNative.packageError -ne 0 -or $parentNative.package -ne $native.package -or [UInt64]$parentNative.birth -gt [UInt64]$childNative.birth){return $false}
  if($parent.Name -eq 'SearchHost.exe'){
   return [bool]($parentNative.package -match '^MicrosoftWindows\.Client\.CBS_' -and $parentNative.image -eq ($env:SystemRoot+'\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe') -and (Test-RecoveryMicrosoftSignature $parentNative.image))
  }
  if($parent.Name -eq 'Widgets.exe'){
   return [bool]($parentNative.package -match '^MicrosoftWindows\.Client\.WebExperience_' -and (Test-RecoveryExtraRole $parent $parentNative $ordinary $console))
  }
  if($parent.Name -ne 'msedgewebview2.exe' -or $parentNative.image -notmatch $pattern -or -not (Test-RecoveryMicrosoftSignature $parentNative.image)){return $false}
  $child=$parent;$childNative=$parentNative
 }
 return $false
}
function Test-RecoveryInstalledDefender([object]$p,[object]$native) {
 try {
  $name=[string]$p.Name;$candidateId=[UInt32]$p.ProcessId
  if($name -eq 'MsMpEng.exe'){$serviceName='WinDefend';$ownerSid='S-1-5-18'}
  elseif($name -eq 'NisSrv.exe'){$serviceName='WdNisSvc';$ownerSid='S-1-5-19'}
  else{return $false}
  $image=$env:ProgramFiles+'\Windows Defender\'+$name
  $creation=if($null -eq $p.CreationDate){''}else{$p.CreationDate.ToUniversalTime().ToFileTimeUtc().ToString()}
  if($candidateId -eq 0 -or $native.pid -ne $candidateId -or [UInt32]$p.SessionId -ne 0 -or $native.protection -ne 3 -or -not [RecoveryProcessIdentity]::Image($native,$name,$creation) -or -not [string]::Equals($native.image,$image,[StringComparison]::OrdinalIgnoreCase) -or -not (Test-RecoveryMicrosoftSignature $image)){return $false}
  $owner=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction Stop
  if($owner.ReturnValue -ne 0 -or $owner.Sid -ne $ownerSid){return $false}
  $services=@(Get-CimInstance Win32_Service -Filter ('ProcessId = '+$candidateId) -ErrorAction Stop)
  if($services.Count -ne 1 -or $services[0].Name -ne $serviceName -or $services[0].State -ne 'Running' -or [UInt32]$services[0].ProcessId -ne $candidateId){return $false}
  $parentId=[UInt32]$p.ParentProcessId
  if(-not $RecoveryRoleProcessMap.ContainsKey($parentId)){return $false}
  $parent=$RecoveryRoleProcessMap[$parentId];$parentNative=[RecoveryProcessIdentity]::Read($parentId)
  $parentCreation=if($null -eq $parent.CreationDate){''}else{$parent.CreationDate.ToUniversalTime().ToFileTimeUtc().ToString()}
  $parentImage=$env:SystemRoot+'\System32\services.exe'
  if($parent.Name -ne 'services.exe' -or [UInt32]$parent.SessionId -ne 0 -or -not [RecoveryProcessIdentity]::Image($parentNative,'services.exe',$parentCreation) -or -not [string]::Equals($parentNative.image,$parentImage,[StringComparison]::OrdinalIgnoreCase) -or [UInt64]$parentNative.birth -gt [UInt64]$native.birth -or -not (Test-RecoveryMicrosoftSignature $parentImage)){return $false}
  $parentOwner=Invoke-CimMethod -InputObject $parent -MethodName GetOwnerSid -ErrorAction Stop
  if($parentOwner.ReturnValue -ne 0 -or $parentOwner.Sid -ne 'S-1-5-18'){return $false}
  $fresh=[RecoveryProcessIdentity]::Read($candidateId)
  return [bool]([RecoveryProcessIdentity]::Image($fresh,$name,$creation) -and $fresh.birth -eq $native.birth -and $fresh.protection -eq 3 -and [string]::Equals($fresh.image,$image,[StringComparison]::OrdinalIgnoreCase))
 }catch{return $false}
}
function Test-RecoveryExtraRole([object]$p,[object]$native,[string]$ordinary,[UInt32]$console) {
 $name=[string]$p.Name;$path=[string]$native.image;$session=[UInt32]$p.SessionId
 if($name -in @('MsMpEng.exe','NisSrv.exe')){return [bool](Test-RecoveryInstalledDefender $p $native)}
 if($name -eq 'msedgewebview2.exe'){return [bool](Test-RecoveryWebView $p $native $ordinary $console)}
 if($name -eq 'OneDrive.exe'){return [bool](Test-RecoveryUnconfiguredOneDrive $p $native $ordinary $console)}
 if($name -eq 'WidgetService.exe' -and $session -eq $console){return [bool](Test-RecoveryWidgetPackage $native $ordinary)}
 $shape=$false
 if($name -eq 'wlms.exe' -and $session -eq 0){$shape=($path -eq ($env:SystemRoot+'\System32\wlms\wlms.exe'))}
 elseif($name -eq 'DefenderSessionHelper.exe' -and $native.protection -eq 3){$shape=($path -match ('^'+[regex]::Escape($env:ProgramData+'\Microsoft\Windows Defender\Platform\')+'[0-9.]+-[0-9]+\\DefenderSessionHelper\.exe$'))}
 elseif($name -eq 'CrossDeviceResume.exe' -and $session -eq $console){$shape=($path -eq ($env:SystemRoot+'\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\CrossDeviceResume.exe'))}
 elseif($name -eq 'MoNotificationUx.exe' -and $session -eq $console){$shape=($path -eq ($env:SystemRoot+'\UUS\amd64\MoNotificationUx.exe'))}
 elseif($name -eq 'Widgets.exe' -and $session -eq $console -and $native.packageError -eq 0 -and $native.package -match '^MicrosoftWindows\.Client\.WebExperience_[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+_x64__cw5n1h2txyewy$'){$shape=($path -eq ($env:ProgramFiles+'\WindowsApps\'+$native.package+'\Dashboard\Widgets.exe'))}
 return [bool]($shape -and (Test-RecoveryMicrosoftSignature $path))
}
'''

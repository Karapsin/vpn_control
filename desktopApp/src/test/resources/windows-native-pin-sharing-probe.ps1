# Real folders, real pins. Run by DesktopWindowsNativeHelperPinSharingNativeTest after it compiled
# windows-install-native.cs and windows-vpn-user-files.cs (with windows-vpn-cache-resources.cs).
# A folder pin of the native helpers lets other programs rename and hard-link into its folder and never
# lets the folder move; a witness lets its own writer write and refuses deletion; an image pin refuses
# writers. The pin the helpers took before (listing access, read sharing only) refuses renames into the
# folder: Windows opens the folder of the new name for FILE_ADD_FILE ([MS-FSA] 2.1.5.15.12).
Add-Type -TypeDefinition @'
using System; using System.Text; using System.Runtime.InteropServices; using Microsoft.Win32.SafeHandles;
public static class NativePinSharingFixture {
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool MoveFileExW(string from,string to,uint flags);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateHardLinkW(string link,string existing,IntPtr security);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool DeleteFileW(string path);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetLongPathNameW(string path,StringBuilder buffer,uint length);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
 // Win32 renames and links by full path, as other programs make them; results are Win32 error codes.
 public static int Move(string from,string to) { return MoveFileExW(from,to,0) ? 0 : Marshal.GetLastWin32Error(); }
 public static int Link(string link,string existing) { return CreateHardLinkW(link,existing,IntPtr.Zero) ? 0 : Marshal.GetLastWin32Error(); }
 public static int Delete(string path) { return DeleteFileW(path) ? 0 : Marshal.GetLastWin32Error(); }
 public static int Write(string path) {
  using (SafeFileHandle file=CreateFileW(path,0x40000000,7,IntPtr.Zero,3,0,IntPtr.Zero)) { return file.IsInvalid ? Marshal.GetLastWin32Error() : 0; }
 }
 // PinParents compares the handle's final path with the requested one: expand 8.3 temporary names.
 public static string Long(string path) {
  StringBuilder buffer=new StringBuilder(32768); uint length=GetLongPathNameW(path,buffer,32768);
  if (length==0 || length>=32768) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
  return buffer.ToString();
 }
 public static SafeFileHandle DenyingWriteSharing(string path) {
  SafeFileHandle file=CreateFileW(path,0x20081,1,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
  if (file.IsInvalid) { int code=Marshal.GetLastWin32Error(); file.Dispose(); throw new System.ComponentModel.Win32Exception(code); }
  return file;
 }
}
'@
$ErrorActionPreference='Stop'
$results=[Collections.Generic.List[string]]::new()
function Expect([string]$What,[int]$Actual,[int]$Expected) {
 if ($Actual -ne $Expected) { throw ($What+' returned '+$Actual+', expected '+$Expected) }
 $results.Add($What+'='+$Actual)
}
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$base=Join-Path ([NativePinSharingFixture]::Long([IO.Path]::GetTempPath())) ('vpn-pin-sharing-'+[Guid]::NewGuid().ToString())
[VpnInstallNative]::CreateDirectory($base,('O:'+$sid+'G:'+$sid+'D:P(A;OICI;FA;;;'+$sid+')'))
$pinned=Join-Path $base 'pinned'; $outside=Join-Path $base 'outside'; $moved=Join-Path $base 'moved'
foreach ($folder in @($pinned,$outside,(Join-Path $outside 'folder'))) { [IO.Directory]::CreateDirectory($folder) | Out-Null }
$held=Join-Path $pinned 'held.txt'; [IO.File]::WriteAllText($held,'witness')
$image=Join-Path $pinned 'vpn-control.exe'; [IO.File]::WriteAllBytes($image,[byte[]]@(77,90))
foreach ($name in @('file','link','resource','unfixed')) { [IO.File]::WriteAllText((Join-Path $outside $name),$name) }
$pin=$null; $witness=$null; $file=$null; $parents=$null; $unfixed=$null
try {
 # VpnInstallNative.OpenDirectory and PinNonEmptyAncestor: the install helper's and the broker admission's folder pins.
 $pin=[VpnInstallNative]::OpenDirectory($pinned)
 $witness=[VpnInstallNative]::PinNonEmptyAncestor($pin,$sid)
 Expect 'rename-file-into-pinned-folder' ([NativePinSharingFixture]::Move((Join-Path $outside 'file'),(Join-Path $pinned 'file'))) 0
 Expect 'rename-folder-into-pinned-folder' ([NativePinSharingFixture]::Move((Join-Path $outside 'folder'),(Join-Path $pinned 'folder'))) 0
 Expect 'hard-link-into-pinned-folder' ([NativePinSharingFixture]::Link((Join-Path $pinned 'link'),(Join-Path $outside 'link'))) 0
 Expect 'rename-pinned-folder' ([NativePinSharingFixture]::Move($pinned,$moved)) 32
 Expect 'write-witness' ([NativePinSharingFixture]::Write($held)) 0
 Expect 'delete-witness' ([NativePinSharingFixture]::Delete($held)) 32
 # VpnInstallNative.OpenFile: the broker admission's image pins.
 $file=[VpnInstallNative]::OpenFile($image)
 Expect 'write-pinned-image' ([NativePinSharingFixture]::Write($image)) 32
 Expect 'rename-pinned-image' ([NativePinSharingFixture]::Move($image,(Join-Path $outside 'moved.exe'))) 32
 $file.Dispose(); $file=$null; $witness.Dispose(); $witness=$null; $pin.Dispose(); $pin=$null
 # windows-vpn-user-files.cs PinParents: every folder from the volume root to a resource's folder.
 $method=[VpnScopedStorage.OriginalUser].GetMethod('PinParents',[Reflection.BindingFlags]'NonPublic,Static')
 $parents=$method.Invoke($null,[object[]]@($pinned,$null))
 Expect 'rename-file-into-resource-folder' ([NativePinSharingFixture]::Move((Join-Path $outside 'resource'),(Join-Path $pinned 'resource'))) 0
 Expect 'rename-resource-folder' ([NativePinSharingFixture]::Move($pinned,$moved)) 32
 [IDisposable].GetMethod('Dispose').Invoke($parents,$null); $parents=$null
 # The rule itself, on any source: the pin the helpers took before refuses a rename into its folder.
 $unfixed=[NativePinSharingFixture]::DenyingWriteSharing($pinned)
 Expect 'rename-into-folder-pinned-without-write-sharing' ([NativePinSharingFixture]::Move((Join-Path $outside 'unfixed'),(Join-Path $pinned 'unfixed'))) 32
 $unfixed.Dispose(); $unfixed=$null
 Expect 'rename-released-folder' ([NativePinSharingFixture]::Move($pinned,$moved)) 0
 'NATIVE_PIN_SHARING_OK '+($results -join ' ')
} finally {
 foreach ($handle in @($unfixed,$file,$witness,$pin)) { if ($null -ne $handle) { $handle.Dispose() } }
 if ($null -ne $parents) { [IDisposable].GetMethod('Dispose').Invoke($parents,$null) }
 [IO.Directory]::Delete($base,$true)
}

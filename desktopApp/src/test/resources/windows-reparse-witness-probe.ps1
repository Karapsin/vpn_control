Add-Type -TypeDefinition @'
using System; using System.IO; using System.Text; using System.Runtime.InteropServices; using Microsoft.Win32.SafeHandles;
public static class ReparseWitnessAttack {
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string p,uint a,uint s,IntPtr d,uint c,uint f,IntPtr t);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool DeviceIoControl(SafeFileHandle h,uint c,byte[] b,uint n,IntPtr o,uint z,out uint r,IntPtr v);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool DeleteFileW(string p);
 public static SafeFileHandle AttributesOnly(string p) {var h=CreateFileW(p,0x100,7,IntPtr.Zero,3,0x02200000,IntPtr.Zero); if(h.IsInvalid) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()); return h;}
 public static int Set(SafeFileHandle h,string target) {
  var sub=Encoding.Unicode.GetBytes(@"\??\"+target); var print=Encoding.Unicode.GetBytes(target);
  var m=new MemoryStream(); var w=new BinaryWriter(m);
  w.Write(0xA0000003u);w.Write((ushort)(8+sub.Length+2+print.Length+2));w.Write((ushort)0);
  w.Write((ushort)0);w.Write((ushort)sub.Length);w.Write((ushort)(sub.Length+2));w.Write((ushort)print.Length);
  w.Write(sub);w.Write((ushort)0);w.Write(print);w.Write((ushort)0);w.Flush();var b=m.ToArray();uint n;
  return DeviceIoControl(h,0x900A4,b,(uint)b.Length,IntPtr.Zero,0,out n,IntPtr.Zero)?0:Marshal.GetLastWin32Error();
 }
 public static int Remove(SafeFileHandle h) {var b=new byte[8];Array.Copy(BitConverter.GetBytes(0xA0000003u),b,4);uint n;return DeviceIoControl(h,0x900AC,b,8,IntPtr.Zero,0,out n,IntPtr.Zero)?0:Marshal.GetLastWin32Error();}
 public static int Delete(string p) {return DeleteFileW(p)?0:Marshal.GetLastWin32Error();}
}
'@
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$base=Join-Path ([IO.Path]::GetTempPath()) ('vpn-witness-attack-'+[Guid]::NewGuid().ToString())
[VpnInstallNative]::CreateDirectory($base,('O:'+$sid+'G:'+$sid+'D:P(A;OICI;FA;;;'+$sid+')'))
$parent=Join-Path $base 'ancestor'; $target=Join-Path $base 'target'; $child=Join-Path $parent 'held'
[IO.Directory]::CreateDirectory($parent)|Out-Null; [IO.Directory]::CreateDirectory($target)|Out-Null
$pin=$null; $attack=$null; $witness=$null; $reparse=$false
try {
 $pin=[VpnInstallNative]::OpenDirectory($parent)
 $attack=[ReparseWitnessAttack]::AttributesOnly($parent)
 $empty=[ReparseWitnessAttack]::Set($attack,$target)
 if($empty -ne 0) {throw ('Empty attrs-only baseline failed '+$empty)}
 $reparse=$true
 if([ReparseWitnessAttack]::Remove($attack) -ne 0) {throw 'Cannot remove baseline junction'}
 $reparse=$false
 [IO.File]::WriteAllText($child,'fixture')
 $witness=[VpnInstallNative]::PinNonEmptyAncestor($pin,$sid)
 $nonempty=[ReparseWitnessAttack]::Set($attack,$target)
 if($nonempty -eq 0) {$reparse=$true;throw 'Nonempty witness failed to prevent reparse'}
 if($nonempty -ne 145) {throw ('Unexpected nonempty rejection '+$nonempty)}
 $delete=[ReparseWitnessAttack]::Delete($child)
 Write-Output ('DELETE_RESULT='+$delete+' EXISTS='+[IO.File]::Exists($child))
 $afterDelete=[ReparseWitnessAttack]::Set($attack,$target)
 Write-Output ('REPARSE_AFTER_DELETE='+$afterDelete)
 if($afterDelete -eq 0) {$reparse=$true; if([ReparseWitnessAttack]::Remove($attack) -ne 0) {throw 'Post-delete junction cleanup failed'}; $reparse=$false}
 if($delete -ne 32) {throw ('Retained child deletion was not sharing violation '+$delete)}
 $witness.Dispose();$witness=$null
 if([ReparseWitnessAttack]::Delete($child) -ne 0) {throw 'Released child could not be deleted'}
 'REPARSE_WITNESS_OK empty=0 nonempty=145 pinned-delete=32'
} finally {
 if($reparse) {if([ReparseWitnessAttack]::Remove($attack) -ne 0) {throw 'Fixture junction cleanup failed'}}
 if($witness) {$witness.Dispose()}; if($attack) {$attack.Dispose()}; if($pin) {$pin.Dispose()}
 [IO.Directory]::Delete($base,$true)
}

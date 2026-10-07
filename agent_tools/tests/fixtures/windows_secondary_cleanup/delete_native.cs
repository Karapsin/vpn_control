using System; using System.Runtime.InteropServices; using Microsoft.Win32.SafeHandles;
public static class StaleLockNative {
 [StructLayout(LayoutKind.Sequential)] public struct Disposition { [MarshalAs(UnmanagedType.Bool)] public bool DeleteFile; }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern SafeFileHandle CreateFile(string name,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle file,int kind,ref Disposition value,int size);
 public static void MarkDelete(SafeFileHandle file){var value=new Disposition{DeleteFile=true};if(!SetFileInformationByHandle(file,4,ref value,Marshal.SizeOf(typeof(Disposition))))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());}
}

$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
public static class TokenRestoreProbe {
 [StructLayout(LayoutKind.Sequential)]struct Luid {public UInt32 Low;public Int32 High;}
 [StructLayout(LayoutKind.Sequential)]struct Privilege {public UInt32 Count;public Luid Id;public UInt32 Attributes;}
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool OpenProcessToken(IntPtr process,UInt32 access,out IntPtr token);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool LookupPrivilegeValueW(string system,string name,out Luid value);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool GetTokenInformation(IntPtr token,int type,IntPtr data,int length,out int returned);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool AdjustTokenPrivileges(IntPtr token,bool disable,ref Privilege value,int length,out Privilege previous,out int returned);
 [DllImport("advapi32.dll",EntryPoint="AdjustTokenPrivileges",SetLastError=true)]static extern bool RestoreTokenPrivileges(IntPtr token,bool disable,ref Privilege value,int length,IntPtr previous,IntPtr returned);
 [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr handle);
 static void Need(bool yes){if(!yes)throw new Exception("TOKEN_RESTORE_PROBE_FAILED");}
 static UInt32 Attributes(IntPtr token,Luid id){
  int size;GetTokenInformation(token,3,IntPtr.Zero,0,out size);Need(size>0&&size<=65536);IntPtr data=Marshal.AllocHGlobal(size);
  try{Need(GetTokenInformation(token,3,data,size,out size));int count=Marshal.ReadInt32(data);Need(count>=0&&count<=1024);
   for(int n=0;n<count;n++){IntPtr row=IntPtr.Add(data,4+n*12);if((UInt32)Marshal.ReadInt32(row)==id.Low&&Marshal.ReadInt32(row,4)==id.High)return (UInt32)Marshal.ReadInt32(row,8);}
   throw new Exception("TOKEN_RESTORE_PROBE_PRIVILEGE_UNAVAILABLE");
  }finally{Marshal.FreeHGlobal(data);}
 }
 public static string Run(){
  // Only this short-lived child token changes. No guest account, service,
  // policy, credential, desktop, registry or persistent setting is modified.
  IntPtr token;Need(OpenProcessToken(Process.GetCurrentProcess().Handle,0x28,out token));
  Privilege previous=new Privilege();bool changed=false;
  try{Luid id;Need(LookupPrivilegeValueW(null,"SeChangeNotifyPrivilege",out id));UInt32 original=Attributes(token,id);
   var toggle=new Privilege{Count=1,Id=id,Attributes=(original&2)==0?2u:0u};int size;
   Need(AdjustTokenPrivileges(token,false,ref toggle,Marshal.SizeOf(typeof(Privilege)),out previous,out size)&&Marshal.GetLastWin32Error()==0);changed=true;
   Privilege ignored;int returned;bool wrong=AdjustTokenPrivileges(token,false,ref previous,0,out ignored,out returned);int error=Marshal.GetLastWin32Error();
   Need(!wrong&&error==122);
   Need(RestoreTokenPrivileges(token,false,ref previous,0,IntPtr.Zero,IntPtr.Zero));
   Need(Attributes(token,id)==original);changed=false;
   return "{\"schemaVersion\":1,\"oldRestoreSucceeded\":false,\"oldRestoreError\":122,\"fixedRestoreSucceeded\":true,\"originalTokenRestored\":true}";
  }finally{try{if(changed)Need(RestoreTokenPrivileges(token,false,ref previous,0,IntPtr.Zero,IntPtr.Zero));}finally{CloseHandle(token);}}
 }
}
'@
[Console]::WriteLine([TokenRestoreProbe]::Run())

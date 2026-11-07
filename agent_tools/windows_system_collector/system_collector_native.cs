using System;using System.IO;using System.Text;using System.Threading.Tasks;using System.ComponentModel;using System.Runtime.InteropServices;using System.Security.Principal;using Microsoft.Win32.SafeHandles;using System.Collections.Generic;
public static class ScFacts {
[DllImport("kernel32.dll")]static extern IntPtr GetCurrentProcess();
[DllImport("kernel32.dll",SetLastError=true)]static extern bool CloseHandle(IntPtr h);
[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,EntryPoint="CreateFileW")]static extern IntPtr CreateNew(string p,uint access,uint share,ref SA sec,uint create,uint flags,IntPtr template);
[DllImport("kernel32.dll",SetLastError=true)]static extern bool WriteFile(IntPtr h,byte[] bytes,uint count,out uint written,IntPtr overlap);
[DllImport("kernel32.dll",SetLastError=true)]static extern bool FlushFileBuffers(IntPtr h);
[DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text,uint revision,out IntPtr sd,out uint size);
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
[StructLayout(LayoutKind.Sequential)]struct SA {public int length;public IntPtr descriptor;public int inherit;}
public sealed class WriteCustody {public IntPtr Handle;public byte[] Bytes;public byte[] Pending;public int Offset;public bool Closed;}
public static readonly List<WriteCustody> Writes=new List<WriteCustody>();
public static void PublishMachineFile(string path,byte[] bytes,string ordinarySid){
if(bytes==null||bytes.Length==0||bytes.Length>262144||!System.Text.RegularExpressions.Regex.IsMatch(ordinarySid,@"^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$"))throw new InvalidOperationException("machine-publication-input");
IntPtr sd;uint size;Win(ConvertStringSecurityDescriptorToSecurityDescriptor("O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;"+ordinarySid+")",1,out sd,out size));
var item=new WriteCustody(){Bytes=bytes};Writes.Add(item);
try{var sa=new SA(){length=Marshal.SizeOf(typeof(SA)),descriptor=sd,inherit=0};item.Handle=CreateNew(path,0x40020000,1,ref sa,1,0x00200080,IntPtr.Zero);Win(item.Handle!=new IntPtr(-1));}
finally{LocalFree(sd);}
while(item.Offset<bytes.Length){int remaining=bytes.Length-item.Offset;item.Pending=new byte[remaining];Buffer.BlockCopy(bytes,item.Offset,item.Pending,0,remaining);uint count;Win(WriteFile(item.Handle,item.Pending,(uint)remaining,out count,IntPtr.Zero));if(count==0||count>remaining)throw new InvalidOperationException("machine-positive-write");item.Offset+=(int)count;item.Pending=null;}
Win(FlushFileBuffers(item.Handle));Win(CloseHandle(item.Handle));item.Closed=true;
}
static void Win(bool ok){if(!ok)throw new Win32Exception(Marshal.GetLastWin32Error());}
static int Scalar(IntPtr t,int kind){IntPtr b=Marshal.AllocHGlobal(4);try{int n;Win(GetTokenInformation(t,kind,b,4,out n));if(n!=4)throw new InvalidOperationException("scalar-size");return Marshal.ReadInt32(b);}finally{Marshal.FreeHGlobal(b);}}
public static string[] Token(){return ProcessToken(GetCurrentProcess());}
public static string[] ProcessToken(IntPtr process){IntPtr t;Win(OpenProcessToken(process,8,out t));try{using(WindowsIdentity id=new WindowsIdentity(t)){return new string[]{id.User.Value,Scalar(t,12).ToString(),Scalar(t,20).ToString(),Scalar(t,18).ToString()};}}finally{CloseHandle(t);}}
public static string BootIdentifier(){IntPtr b=Marshal.AllocHGlobal(32);try{int n;int status=NtQuerySystemInformation(90,b,32,out n);if(status!=0||n!=32)throw new InvalidOperationException("boot-private-ABI-unqualified");byte[] bytes=new byte[16];Marshal.Copy(b,bytes,0,16);Guid g=new Guid(bytes);if(g==Guid.Empty)throw new InvalidOperationException("boot-zero");return g.ToString();}finally{Marshal.FreeHGlobal(b);}}
public static long Birth(IntPtr process){long c,e,k,u;Win(GetProcessTimes(process,out c,out e,out k,out u));return c;}
public static SafeFileHandle OpenDirectory(string p){SafeFileHandle h=CreateFile(p,0x20080,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);Win(!h.IsInvalid);return h;}
public static FileStream OpenHeld(string p){SafeFileHandle h=CreateFile(p,0x80020000,1,IntPtr.Zero,3,0x02200000,IntPtr.Zero);Win(!h.IsInvalid);try{return new FileStream(h,FileAccess.Read,65536,false);}catch{h.Dispose();throw;}}
public static Dictionary<string,object> Identity(SafeFileHandle h,bool directory){FI i;Win(GetFileInformationByHandle(h,out i));if((i.attr&0x400)!=0||((i.attr&0x10)!=0)!=directory||(!directory&&i.links!=1))throw new InvalidOperationException("file-type-reparse-link");var r=new Dictionary<string,object>();r["attributes"]=i.attr;r["volumeSerial"]=i.volume;r["fileIndex"]=((ulong)i.indexHi<<32)|i.indexLo;if(!directory){r["sizeBytes"]=((ulong)i.sizeHi<<32)|i.sizeLo;r["links"]=i.links;r["creationFileTime"]=i.creation.ToString(System.Globalization.CultureInfo.InvariantCulture);r["lastWriteFileTime"]=i.write.ToString(System.Globalization.CultureInfo.InvariantCulture);}return r;}
public static string[] Security(SafeFileHandle h){IntPtr owner,sd;uint code=GetSecurityInfo(h,1,5,out owner,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,out sd);if(code!=0)throw new Win32Exception((int)code);try{IntPtr text;uint len;Win(ConvertSecurityDescriptorToStringSecurityDescriptor(sd,1,5,out text,out len));try{return new string[]{new SecurityIdentifier(owner).Value,Marshal.PtrToStringUni(text)};}finally{LocalFree(text);}}finally{LocalFree(sd);}}
}
public sealed class ScRawPump {
public readonly Stream Input;public readonly FileStream Output;public readonly long Limit;public Task Task;
public volatile bool Eof;public volatile string Error;public byte[] Pending;public long Bytes;
public ScRawPump(Stream input,FileStream output,long limit){Input=input;Output=output;Limit=limit;}
public void Start(){if(Task!=null)throw new InvalidOperationException("pump-already-started");Task=System.Threading.Tasks.Task.Run((Action)Run);}
void Run(){try{byte[] b=new byte[65536];while(true){int want=(int)Math.Min(b.Length,Math.Max(1,Limit-Bytes+1));int n=Input.Read(b,0,want);if(n==0){Output.Flush(true);Eof=true;return;}Pending=new byte[n];Buffer.BlockCopy(b,0,Pending,0,n);Output.Write(Pending,0,n);Bytes+=n;Pending=null;if(Bytes>Limit)throw new InvalidOperationException("raw-bound-retained");}}catch(Exception e){Error=e.GetType().FullName+":"+e.Message;}}
}

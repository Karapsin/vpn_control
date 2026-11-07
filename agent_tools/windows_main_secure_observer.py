"""PRIVATE fixed read-only SYSTEM/session-2 observer and suspended launcher.

This is a source generator, not a transport. Only the sole current VM operator
may bind its genuinely observed inputs to canonical build_guest_exec. All actual
bindings in this preparation remain NULL. No CP117 route or identity is reused.
"""
from __future__ import annotations

import base64
import hashlib
import gzip
import json
from pathlib import PureWindowsPath
import re
import uuid


def need(value, code):
    if not value:
        raise ValueError(code)


COMMON_NAMES = {"schemaVersion", "taskBinding", "ordinarySid", "approvingAdminSid", "approvingAdminAccount",
                "guestBootIdentifier", "machineGuid", "ordinaryActors", "qemuIdentity", "powershellSha256"}


def _validate_common(value, names):
    need(type(value) is dict and set(value) == names and value["schemaVersion"] == 1, "observer-schema")
    need(type(value["taskBinding"]) is dict and set(value["taskBinding"]) == {
        "ordinaryTaskOperationId", "productOperationId", "originRequestId", "controllerId"}, "observer-task-binding")
    for item in [*value["taskBinding"].values(), value["guestBootIdentifier"], value["machineGuid"]]:
        need(type(item) is str and str(uuid.UUID(item)) == item, "observer-uuid")
    for key in ("ordinarySid", "approvingAdminSid"):
        need(type(value[key]) is str and re.fullmatch(r"S-1-5-21-(?:[0-9]+-){3}[0-9]+", value[key]), "observer-sid")
    need(value["ordinarySid"] != value["approvingAdminSid"], "distinct-approval-principal")
    need(type(value["approvingAdminAccount"]) is str and re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,31}", value["approvingAdminAccount"]), "observer-account")
    need(type(value["powershellSha256"]) is str and re.fullmatch("[0-9a-f]{64}", value["powershellSha256"]), "observer-powershell")
    rows = value["ordinaryActors"]
    keys = {"role", "pid", "parentPid", "creationFileTime", "image", "sha256", "sid", "sessionId",
            "elevation", "elevationType", "administratorMember", "administratorEnabled"}
    need(type(rows) is list and {row.get("role") for row in rows} == {"ordinaryOwner", "serve", "gui"}
         and len(rows) == 3, "observer-fixed-roles")
    for row in rows:
        need(type(row) is dict and set(row) == keys and type(row["pid"]) is int and row["pid"] > 0
             and type(row["parentPid"]) is int and row["parentPid"] > 0
             and type(row["creationFileTime"]) is int and row["creationFileTime"] > 0
             and row["sid"] == value["ordinarySid"] and row["sessionId"] == 2
             and type(row["sessionId"]) is int and row["elevation"] == 0 and row["elevationType"] == 1
             and row["administratorMember"] is False and row["administratorEnabled"] is False,
             "observer-ordinary-actor")
        path = PureWindowsPath(row["image"])
        need(path.is_absolute() and not path.drive.startswith("\\\\") and ".." not in path.parts
             and re.fullmatch("[0-9a-f]{64}", row["sha256"]), "observer-image")
    by_role = {row["role"]: row for row in rows}
    need(len({row["pid"] for row in rows}) == 3
         and by_role["serve"]["parentPid"] == by_role["ordinaryOwner"]["pid"]
         and by_role["gui"]["parentPid"] == by_role["ordinaryOwner"]["pid"], "observer-sibling-topology")
    _validate_qemu(value["qemuIdentity"])
    return by_role


def validate_discovery(value):
    """Read-only common actor binding, with no invented installer authority."""
    _validate_common(value, COMMON_NAMES)
    return value


def validate(value):
    by_role = _validate_common(value, COMMON_NAMES | {"pendingRequest", "correlationRecord", "packageFile"})
    pending = value["pendingRequest"]
    need(type(pending) is dict and set(pending) == {"path", "sha256", "sizeBytes", "jobId", "ownerPid",
         "ownerStartedAtEpochMillis", "principalSid", "launcher", "nativeIdentity", "security"}, "observer-pending-request")
    need(type(pending["sizeBytes"]) is int and 0 < pending["sizeBytes"] <= 65536
         and re.fullmatch("[0-9a-f]{64}", pending["sha256"])
         and str(uuid.UUID(pending["jobId"])) == pending["jobId"]
         and pending["principalSid"] == value["ordinarySid"]
         and pending["ownerPid"] == by_role["serve"]["pid"]
         and pending["ownerStartedAtEpochMillis"] == by_role["serve"]["creationFileTime"] // 10000 - 11644473600000
         and pending["launcher"].casefold() == by_role["gui"]["image"].casefold(), "observer-pending-lineage")
    p = PureWindowsPath(pending["path"])
    need(p.is_absolute() and not p.drive.startswith("\\\\") and ".." not in p.parts
         and p.name == "request.json" and p.parent.name == pending["jobId"], "observer-pending-path")
    correlation = value["correlationRecord"]
    need(type(correlation) is dict and set(correlation) == {"path", "sha256", "sizeBytes", "record", "resolvedWorkspace", "nativeIdentity", "security"}
         and type(correlation["sizeBytes"]) is int and 0 < correlation["sizeBytes"] <= 4096
         and re.fullmatch("[0-9a-f]{64}", correlation["sha256"]), "observer-correlation-metadata")
    record = correlation["record"]
    binding = value["taskBinding"]
    workspace = correlation["resolvedWorkspace"]
    need(type(workspace) is str and str(PureWindowsPath(workspace)) == workspace, "observer-actual-resolved-workspace")
    expected_record = dict(version=1,controllerId=binding["controllerId"],requestId=binding["originRequestId"],
        operationId=binding["productOperationId"],jobId=pending["jobId"],workspaceKey=hashlib.sha256(workspace.encode()).hexdigest())
    filename = ".install-correlation-"+hashlib.sha256(json.dumps({"controllerId":binding["controllerId"],
        "operationId":binding["productOperationId"]},separators=(",",":")).encode()).hexdigest()+".json"
    need(record == expected_record and correlation["path"] == str(PureWindowsPath(workspace)/filename), "observer-public-native-correlation-join")
    package = value["packageFile"]
    need(type(package) is dict and set(package) == {"path", "sha256", "sizeBytes", "nativeIdentity", "security"}
         and package["path"] == str(p.parent/"package.msi")
         and type(package["sizeBytes"]) is int and package["sizeBytes"] > 0
         and re.fullmatch("[0-9a-f]{64}", package["sha256"]), "observer-actual-pending-package")
    for native_file in (pending, correlation, package):
        need(type(native_file["nativeIdentity"]) is str and re.fullmatch("[0-9a-f]{8}:[0-9a-f]{16}", native_file["nativeIdentity"])
             and type(native_file["security"]) is dict and set(native_file["security"]) == {"ownerSid", "sddl"}
             and native_file["security"]["ownerSid"] == value["ordinarySid"]
             and type(native_file["security"]["sddl"]) is str and 0 < len(native_file["security"]["sddl"]) <= 8192,
             "observer-actual-private-file-identity-security")
    return value


def _validate_qemu(qemu):
    # This is not admission by itself; the host bridge independently observes
    # process, boot, argv, both socket ownership and connected SO_PEERCRED.
    need(type(qemu) is dict and set(qemu) == {"deployment_id", "host_boot_id", "pid", "parent_pid", "start_ticks",
         "uid", "argv_sha256", "qmp_socket", "qga_socket"}
         and qemu["deployment_id"] == "d493a373-1d2c-4ab0-bfd4-e93575019dce"
         and str(uuid.UUID(qemu["host_boot_id"])) == qemu["host_boot_id"]
         and all(type(qemu[k]) is int and qemu[k] > 0 for k in ("pid", "parent_pid", "start_ticks", "uid"))
         and re.fullmatch("[0-9a-f]{64}", qemu["argv_sha256"])
         and qemu["qmp_socket"] == "/home/kardinal/vc-win-d493a3731d2c/qmp.sock"
         and qemu["qga_socket"] == "/home/kardinal/vc-win-d493a3731d2c/qga.sock", "observer-qemu-binding")


NATIVE = r'''using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
public static class MainSecureRead {
 [StructLayout(LayoutKind.Sequential)] public struct LUID {public uint low;public int high;}
 [StructLayout(LayoutKind.Sequential)] public struct TP {public uint count;public LUID id;public uint attributes;}
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] public struct SI {public int cb;public string reserved,desktop,title;public uint x,y,xSize,ySize,xChars,yChars,fill,flags;public short show,reserved2;public IntPtr reservedPtr,input,output,error;}
 [StructLayout(LayoutKind.Sequential)] public struct PI {public IntPtr process,thread;public uint pid,tid;}
 [StructLayout(LayoutKind.Sequential)] struct SIEX {public SI startup;public IntPtr list;}
 [StructLayout(LayoutKind.Sequential)] struct Accounting {public long user,kernel,periodUser,periodKernel;public uint faults,total,active,terminated;}
 [StructLayout(LayoutKind.Sequential)] struct Group {public IntPtr sid;public uint attributes;}
 [StructLayout(LayoutKind.Sequential)] struct Groups {public uint count;public Group first;}
 [StructLayout(LayoutKind.Sequential)] struct Rect {public int left,top,right,bottom;}
 [StructLayout(LayoutKind.Sequential)] struct Gui {public uint size,flags;public IntPtr active,focus,capture,menu,move,caret;public Rect rect;}
 [StructLayout(LayoutKind.Sequential)] public struct SA {public int length;public IntPtr descriptor;public int inherit;}
 [StructLayout(LayoutKind.Sequential)] struct FileInfo {public uint attributes,creationLo,creationHi,accessLo,accessHi,writeLo,writeHi,volume,sizeHi,sizeLo,links,indexHi,indexLo;}
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr p,uint a,out IntPtr t);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool ImpersonateLoggedOnUser(IntPtr token);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool RevertToSelf();
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr t,int k,IntPtr b,int n,out int used);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupPrivilegeValue(string s,string n,out LUID id);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr t,bool d,ref TP p,int n,IntPtr old,IntPtr used);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool DuplicateTokenEx(IntPtr t,uint a,IntPtr b,int l,int type,out IntPtr copy);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool SetTokenInformation(IntPtr t,int k,ref uint session,uint n);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcessAsUser(IntPtr t,string app,StringBuilder command,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr env,string cwd,ref SI si,out PI pi);
 [DllImport("advapi32.dll",EntryPoint="CreateProcessAsUserW",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcessAsUserEx(IntPtr t,string app,StringBuilder command,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr env,string cwd,ref SIEX si,out PI pi);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFile(string p,uint access,uint share,ref SA a,uint creation,uint flags,IntPtr template);
 [DllImport("kernel32.dll",EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr HoldFile(string p,uint access,uint share,IntPtr a,uint creation,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(IntPtr h,out FileInfo info);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr p,int count,int flags,ref IntPtr size);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr p,uint flags,IntPtr attribute,IntPtr value,IntPtr size,IntPtr old,IntPtr returned);
 [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr p);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr a,string name);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int kind,out Accounting value,int size,out int used);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool FlushFileBuffers(IntPtr file);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern uint ResumeThread(IntPtr thread);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern uint WaitForSingleObject(IntPtr process,uint ms);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetExitCodeProcess(IntPtr process,out uint code);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string s,uint r,out IntPtr b,out uint n);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateDirectory(string p,ref SA a);
 [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
 [DllImport("user32.dll")] static extern IntPtr GetProcessWindowStation();
 [DllImport("user32.dll")] static extern IntPtr GetThreadDesktop(uint t);
 [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
 [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool GetUserObjectInformation(IntPtr h,int k,StringBuilder n,uint size,out uint used);
 [DllImport("user32.dll",SetLastError=true)] static extern bool GetGUIThreadInfo(uint t,ref Gui g);
 [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr w,out uint pid);
 [DllImport("user32.dll")] static extern IntPtr GetKeyboardLayout(uint t);
 [DllImport("user32.dll")] static extern IntPtr GetAncestor(IntPtr w,uint k);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr w,StringBuilder n,int c);
 [DllImport("user32.dll",EntryPoint="GetWindowLongPtrW")] static extern IntPtr GetWindowLongPtr(IntPtr w,int n);
 [DllImport("user32.dll",SetLastError=true)] static extern IntPtr SendMessageTimeout(IntPtr w,uint m,IntPtr p,IntPtr l,uint flags,uint timeout,out UIntPtr result);
 static void Need(bool x){if(!x)throw new Win32Exception(Marshal.GetLastWin32Error());}
 static int Info(IntPtr token,int kind){IntPtr b=Marshal.AllocHGlobal(4);try{int n;Need(GetTokenInformation(token,kind,b,4,out n)&&n==4);return Marshal.ReadInt32(b);}finally{Marshal.FreeHGlobal(b);}}
 public static object[] Token(IntPtr process){IntPtr t;Need(OpenProcessToken(process,8,out t));try{int size;GetTokenInformation(t,2,IntPtr.Zero,0,out size);Need(size>0&&size<=32768);IntPtr b=Marshal.AllocHGlobal(size);bool member=false,enabled=false;try{int n;Need(GetTokenInformation(t,2,b,size,out n)&&n<=size);int count=Marshal.ReadInt32(b),offset=Marshal.OffsetOf(typeof(Groups),"first").ToInt32(),stride=Marshal.SizeOf(typeof(Group));Need(count>=0&&count<=256&&offset+count*stride<=n);for(int i=0;i<count;i++){Group g=(Group)Marshal.PtrToStructure(IntPtr.Add(b,offset+i*stride),typeof(Group));if(new SecurityIdentifier(g.sid).Value=="S-1-5-32-544"){member=true;enabled=(g.attributes&4)!=0&&(g.attributes&16)==0;}}}finally{Marshal.FreeHGlobal(b);}using(WindowsIdentity id=new WindowsIdentity(t)){return new object[]{id.User.Value,Info(t,12),Info(t,20),Info(t,18),member,enabled};}}finally{Need(CloseHandle(t));}}
 public static IntPtr BeginOrdinaryRead(IntPtr process,string sid){object[] f=Token(process);Need((string)f[0]==sid&&(int)f[1]==2&&(int)f[2]==0&&(int)f[3]==1&&!(bool)f[4]&&!(bool)f[5]);IntPtr t;Need(OpenProcessToken(process,14,out t));if(!ImpersonateLoggedOnUser(t)){int e=Marshal.GetLastWin32Error();CloseHandle(t);throw new Win32Exception(e);}return t;}
 public static void EndOrdinaryRead(IntPtr token){Need(RevertToSelf());Need(CloseHandle(token));}
 static void Enable(IntPtr t,string name){LUID id;Need(LookupPrivilegeValue(null,name,out id));TP p=new TP();p.count=1;p.id=id;p.attributes=2;Need(AdjustTokenPrivileges(t,false,ref p,0,IntPtr.Zero,IntPtr.Zero));Need(Marshal.GetLastWin32Error()==0);}
 public static void PrivateDirectory(string path){IntPtr b;uint n;Need(ConvertStringSecurityDescriptorToSecurityDescriptor("O:SYG:SYD:P(A;OICI;FA;;;SY)",1,out b,out n));try{SA a=new SA();a.length=Marshal.SizeOf(typeof(SA));a.descriptor=b;Need(CreateDirectory(path,ref a));}finally{LocalFree(b);}}
 public static IntPtr DirectoryPin(string path){IntPtr h=HoldFile(path,0x80,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);Need(h!=new IntPtr(-1));FileInfo f;Need(GetFileInformationByHandle(h,out f)&&(f.attributes&0x400)==0&&(f.attributes&0x10)!=0);return h;}
 public static string FileIdentity(IntPtr h,bool directory){FileInfo f;Need(GetFileInformationByHandle(h,out f)&&(f.attributes&0x400)==0&&((f.attributes&0x10)!=0)==directory&&(directory||f.links==1));return f.volume.ToString("x8")+":"+f.indexHi.ToString("x8")+f.indexLo.ToString("x8");}
 static PI owned;static IntPtr output=IntPtr.Zero,error=IntPtr.Zero,input=IntPtr.Zero,job=IntPtr.Zero;
 public static PI Owned(){return owned;}
 static IntPtr File(string path,uint access,uint creation){SA a=new SA();a.length=Marshal.SizeOf(typeof(SA));a.inherit=1;IntPtr h=CreateFile(path,access,creation==3?3u:1u,ref a,creation,128,IntPtr.Zero);Need(h!=new IntPtr(-1));return h;}
 public static PI Suspended(string directory){IntPtr t=IntPtr.Zero,copy=IntPtr.Zero,list=IntPtr.Zero,handles=IntPtr.Zero;bool initialized=false;try{Need(owned.pid==0);Need(OpenProcessToken(GetCurrentProcess(),0x2B,out t));Enable(t,"SeTcbPrivilege");Enable(t,"SeIncreaseQuotaPrivilege");Enable(t,"SeAssignPrimaryTokenPrivilege");Need(DuplicateTokenEx(t,0x02000000,IntPtr.Zero,2,1,out copy));uint session=2;Need(SetTokenInformation(copy,12,ref session,4));output=File(directory+"\\child.stdout.bin",0x40000000,1);error=File(directory+"\\child.stderr.bin",0x40000000,1);input=File("NUL",0x80000000,3);job=CreateJobObject(IntPtr.Zero,null);Need(job!=IntPtr.Zero);IntPtr size=IntPtr.Zero;InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref size);Need(size.ToInt64()>0&&size.ToInt64()<=65536);list=Marshal.AllocHGlobal(size);Need(InitializeProcThreadAttributeList(list,1,0,ref size));initialized=true;handles=Marshal.AllocHGlobal(IntPtr.Size*3);Marshal.WriteIntPtr(handles,0,input);Marshal.WriteIntPtr(handles,IntPtr.Size,output);Marshal.WriteIntPtr(handles,IntPtr.Size*2,error);Need(UpdateProcThreadAttribute(list,0,new IntPtr(0x20002),handles,new IntPtr(IntPtr.Size*3),IntPtr.Zero,IntPtr.Zero));SIEX s=new SIEX();s.startup.cb=Marshal.SizeOf(typeof(SIEX));s.startup.desktop=@"WinSta0\Winlogon";s.startup.flags=0x100;s.startup.input=input;s.startup.output=output;s.startup.error=error;s.list=list;PI p;const string app=@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";StringBuilder command=new StringBuilder("\""+app+"\" -NoProfile -NonInteractive -File \""+directory+"\\observer.ps1\"",32768);Need(command.Length<32767);Need(CreateProcessAsUserEx(copy,app,command,IntPtr.Zero,IntPtr.Zero,true,0x08080004,IntPtr.Zero,directory,ref s,out p));owned=p;Need(AssignProcessToJobObject(job,p.process));return p;}finally{if(initialized)DeleteProcThreadAttributeList(list);if(list!=IntPtr.Zero)Marshal.FreeHGlobal(list);if(handles!=IntPtr.Zero)Marshal.FreeHGlobal(handles);if(copy!=IntPtr.Zero)Need(CloseHandle(copy));if(t!=IntPtr.Zero)Need(CloseHandle(t));}}
 public static void CaptureClosed(){Accounting a;int n;Need(job!=IntPtr.Zero&&QueryInformationJobObject(job,1,out a,Marshal.SizeOf(typeof(Accounting)),out n)&&n==Marshal.SizeOf(typeof(Accounting))&&a.active==0);Need(FlushFileBuffers(output));Need(FlushFileBuffers(error));Need(CloseHandle(input));input=IntPtr.Zero;Need(CloseHandle(output));output=IntPtr.Zero;Need(CloseHandle(error));error=IntPtr.Zero;Need(CloseHandle(job));job=IntPtr.Zero;}
 static string ObjectName(IntPtr h){StringBuilder n=new StringBuilder(128);uint size;Need(h!=IntPtr.Zero&&GetUserObjectInformation(h,2,n,256,out size)&&size<=256);return n.ToString();}
 public static string[] Desktop(){return new string[]{ObjectName(GetProcessWindowStation()),ObjectName(GetThreadDesktop(GetCurrentThreadId()))};}
 public static long[] Focus(uint thread,uint expectedPid){Gui g=new Gui();g.size=(uint)Marshal.SizeOf(typeof(Gui));if(!GetGUIThreadInfo(thread,ref g)||g.focus==IntPtr.Zero)return null;uint pid;uint tid=GetWindowThreadProcessId(g.focus,out pid);Need(pid==expectedPid&&tid==thread);return new long[]{g.focus.ToInt64(),GetAncestor(g.focus,2).ToInt64(),tid,GetKeyboardLayout(thread).ToInt64()};}
 public static long[] FocusDiscovery(){Gui g=new Gui();g.size=(uint)Marshal.SizeOf(typeof(Gui));if(!GetGUIThreadInfo(0,ref g)||g.focus==IntPtr.Zero)return null;uint pid;uint tid=GetWindowThreadProcessId(g.focus,out pid);Need(pid>0&&tid>0);return new long[]{g.focus.ToInt64(),GetAncestor(g.focus,2).ToInt64(),tid,GetKeyboardLayout(tid).ToInt64(),pid};}
 public static int PasswordLength(IntPtr window){StringBuilder n=new StringBuilder(128);Need(GetClassName(window,n,128)>0&&n.ToString()=="Edit"&&(GetWindowLongPtr(window,-16).ToInt64()&0x20)!=0);UIntPtr result;Need(SendMessageTimeout(window,0x000E,IntPtr.Zero,IntPtr.Zero,2,1000,out result)!=IntPtr.Zero);ulong length=result.ToUInt64();Need(length<=64);return (int)length;}
}'''


CHILD = r'''$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$dir='__DIR__';$nonce='__NONCE__';$e=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__EXPECTED__'))|ConvertFrom-Json
$nativePath=Join-Path $dir 'native.cs';if((Get-FileHash -LiteralPath $nativePath -Algorithm SHA256).Hash.ToLowerInvariant()-cne'__NATIVE_SHA__'){throw 'reader-fixed-native-source'};Add-Type -Path $nativePath -ReferencedAssemblies @('System','System.Core')
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes,WindowsBase
function Need($v,$c){if(-not$v){throw $c}}
function HashBytes($b){$h=[Security.Cryptography.SHA256]::Create();try{return([BitConverter]::ToString($h.ComputeHash($b))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
function WritePrivate($name,$v){$b=[Text.Encoding]::UTF8.GetBytes(($v|ConvertTo-Json -Depth 14 -Compress));$f=[IO.FileStream]::new((Join-Path $dir $name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
function ProcessFacts($id){$p=Get-Process -Id $id;$null=$p.Handle;$script:held.Add($p);$c=Get-CimInstance Win32_Process -Filter ('ProcessId='+$id) -OperationTimeoutSec 5;Need($null-ne$c -and -not$p.HasExited)'actor-current';$t=[MainSecureRead]::Token($p.Handle);return [ordered]@{pid=$p.Id;parentPid=[int]$c.ParentProcessId;creationFileTime=$p.StartTime.ToFileTimeUtc();image=$p.Path;sha256=(Get-FileHash -LiteralPath $p.Path -Algorithm SHA256).Hash.ToLowerInvariant();sid=$t[0];sessionId=[int]$t[1];elevation=[int]$t[2];elevationType=[int]$t[3];administratorMember=[bool]$t[4];administratorEnabled=[bool]$t[5]}}
$held=[Collections.Generic.List[Diagnostics.Process]]::new()
try {
 $self=Get-Process -Id $PID;$null=$self.Handle;$held.Add($self);$selfCim=Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID) -OperationTimeoutSec 5
 $b=Get-Content -LiteralPath (Join-Path $dir 'child.json') -Raw|ConvertFrom-Json
 $sourcePath=Join-Path $dir 'observer.ps1';Need($PSCommandPath-ieq$sourcePath)'reader-fixed-file';$sourceSha=(Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
 Need([IntPtr]::Size-eq8 -and [Security.Principal.WindowsIdentity]::GetCurrent().User.Value-ceq'S-1-5-18' -and $self.SessionId-eq2 -and $self.StartTime.ToFileTimeUtc()-eq$b.creationFileTime -and $b.pid-eq$PID -and $b.parentPid-eq$selfCim.ParentProcessId -and $b.nonce-ceq$nonce -and $b.sourceSha256-ceq$sourceSha)'reader-held-identity-source'
 $desktop=[MainSecureRead]::Desktop();Need($desktop[0]-ceq'WinSta0' -and $desktop[1]-ceq'Winlogon')'actual-secure-desktop'
 $boot=Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 5
 $guid=(Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid;$nativeMachineGuid=([Guid]$guid).ToString()
 # SYSTEM_BOOT_ENVIRONMENT_INFORMATION.BootIdentifier matches the ordinary owner.
 Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class MainBootRead{[DllImport("ntdll.dll")]static extern int NtQuerySystemInformation(int k,IntPtr b,int n,out int used);public static string Read(){IntPtr b=Marshal.AllocHGlobal(32);try{int used;if(NtQuerySystemInformation(90,b,32,out used)!=0||used<16||used>32)throw new InvalidOperationException("boot-native");return((Guid)Marshal.PtrToStructure(b,typeof(Guid))).ToString();}finally{Marshal.FreeHGlobal(b);}}}'
 Need([MainBootRead]::Read()-ceq$e.guestBootIdentifier -and $guid-ieq$e.machineGuid)'guest-generation'
 $actors=@();foreach($wanted in $e.ordinaryActors){$actual=ProcessFacts([int]$wanted.pid);foreach($key in @('pid','parentPid','creationFileTime','sid','sessionId','elevation','elevationType','administratorMember','administratorEnabled')){Need($actual[$key]-ceq$wanted.$key)'ordinary-actor-facts'};Need($actual.image-ieq$wanted.image -and $actual.sha256-ceq$wanted.sha256)'ordinary-actor-image';$actual.role=$wanted.role;$actors+=,$actual}
 function Rid($node){$r=@($node.GetRuntimeId());Need($r.Count-gt0 -and $r.Count-le32)'selection-runtime-id';return [string]::Join(',',$r)}
 function Within($ancestor,$node){$target=Rid $ancestor;for($d=0;$null-ne$node -and $d-le8;$d++){if((Rid $node)-ceq$target){return $true};$node=[Windows.Automation.TreeWalker]::RawViewWalker.GetParent($node)};return $false}
 $pending=$e.pendingRequest;$serve=@($held|Where-Object{$_.Id-eq$pending.ownerPid});Need($serve.Count-eq1)'retained-ordinary-read-token';$readToken=[MainSecureRead]::BeginOrdinaryRead($serve[0].Handle,$e.ordinarySid);$cf=$null;$f=$null
 try{
 $corr=$e.correlationRecord;$walk=$corr.path;while($walk){Need(-not((Get-Item -LiteralPath $walk -Force).Attributes-band[IO.FileAttributes]::ReparsePoint))'correlation-reparse';$up=Split-Path -Parent $walk;if($up-eq$walk){break};$walk=$up};$ca=Get-Acl -LiteralPath $corr.path;Need($ca.GetOwner([Security.Principal.SecurityIdentifier]).Value-ceq$e.ordinarySid -and $ca.AreAccessRulesProtected)'correlation-private-owner';$rules=@($ca.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]));Need($rules.Count-eq1 -and $rules[0].IdentityReference.Value-ceq$e.ordinarySid -and $rules[0].AccessControlType-eq'Allow')'correlation-private-rules'
 $cf=[IO.FileStream]::new($corr.path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);Need($cf.Length-eq$corr.sizeBytes -and $cf.Length-gt0 -and $cf.Length-le4096 -and [MainSecureRead]::FileIdentity($cf.SafeFileHandle.DangerousGetHandle(),$false)-ceq$corr.nativeIdentity)'correlation-held-identity-size';Need($ca.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]5)-ceq$corr.security.sddl)'correlation-held-security';$cb=New-Object byte[]([int]$cf.Length);$co=0;while($co-lt$cb.Length){$n=$cf.Read($cb,$co,$cb.Length-$co);Need($n-gt0)'correlation-short';$co+=$n};Need((HashBytes $cb)-ceq$corr.sha256)'correlation-full-bytes';$cv=[Text.UTF8Encoding]::new($false,$true).GetString($cb)|ConvertFrom-Json;Need(@($cv.PSObject.Properties.Name).Count-eq6)'correlation-closed-schema';foreach($key in @('version','controllerId','requestId','operationId','jobId','workspaceKey')){Need($cv.$key-ceq$corr.record.$key)'correlation-public-operation-native-job-join'}
 $path=$pending.path;$walk=$path;while($walk){Need(-not((Get-Item -LiteralPath $walk -Force).Attributes-band[IO.FileAttributes]::ReparsePoint))'pending-reparse';$parent=Split-Path -Parent $walk;if($parent-eq$walk){break};$walk=$parent}
 $f=[IO.FileStream]::new($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);try{$pa=Get-Acl -LiteralPath $path;Need([MainSecureRead]::FileIdentity($f.SafeFileHandle.DangerousGetHandle(),$false)-ceq$pending.nativeIdentity -and $pa.GetOwner([Security.Principal.SecurityIdentifier]).Value-ceq$pending.security.ownerSid -and $pa.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]5)-ceq$pending.security.sddl)'pending-identity-security';Need($f.Length-eq$pending.sizeBytes -and $f.Length-gt0 -and $f.Length-le65536)'pending-size';$raw=New-Object byte[]([int]$f.Length);$off=0;while($off-lt$raw.Length){$n=$f.Read($raw,$off,$raw.Length-$off);Need($n-gt0)'pending-short';$off+=$n};Need((HashBytes $raw)-ceq$pending.sha256)'pending-bytes';$request=[Text.UTF8Encoding]::new($false,$true).GetString($raw)|ConvertFrom-Json;foreach($key in @('jobId','ownerPid','ownerStartedAtEpochMillis','principalSid','launcher')){Need($request.$key-ceq$pending.$key)'pending-original-lineage'}
 $pkg=$e.packageFile;$pf=[IO.FileStream]::new($pkg.path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);try{$ps=Get-Acl -LiteralPath $pkg.path;Need($pf.Length-eq$pkg.sizeBytes -and [MainSecureRead]::FileIdentity($pf.SafeFileHandle.DangerousGetHandle(),$false)-ceq$pkg.nativeIdentity -and $ps.GetOwner([Security.Principal.SecurityIdentifier]).Value-ceq$pkg.security.ownerSid -and $ps.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]5)-ceq$pkg.security.sddl)'pending-package-native-identity-security';$ph=[Security.Cryptography.SHA256]::Create();try{$packageHash=([BitConverter]::ToString($ph.ComputeHash($pf))).Replace('-','').ToLowerInvariant()}finally{$ph.Dispose()};Need($packageHash-ceq$pkg.sha256 -and $request.packageFile-ceq$pkg.path -and $request.packageSha256-ceq$pkg.sha256 -and $request.packageSize-eq$pkg.sizeBytes -and $request.stateDirectory-ceq$corr.resolvedWorkspace)'pending-source-target-package-join'
 [MainSecureRead]::EndOrdinaryRead($readToken);$readToken=[IntPtr]::Zero
 $consents=@(Get-CimInstance Win32_Process -Filter "Name='consent.exe'" -OperationTimeoutSec 5|Where-Object{$_.SessionId-eq2});Need($consents.Count-eq1)'unique-current-consent';$consent=ProcessFacts([int]$consents[0].ProcessId);$sig=Get-AuthenticodeSignature -LiteralPath $consent.image;Need($consent.sid-ceq'S-1-5-18' -and $consent.image-ieq'C:\Windows\System32\consent.exe' -and $sig.Status-eq'Valid' -and $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)-ceq'Microsoft Windows')'authentic-current-consent'
 $consent.Remove('elevation');$consent.Remove('elevationType');$consent.Remove('administratorMember');$consent.Remove('administratorEnabled');$consent.signatureStatus=[string]$sig.Status;$consent.signerName='Microsoft Windows'
 $process=$held[$held.Count-1];$focus=@();foreach($thread in $process.Threads){$r=[MainSecureRead]::Focus([uint32]$thread.Id,[uint32]$consent.pid);if($null-ne$r){$focus+=,@($r)}};Need($focus.Count-eq1)'unique-secure-focus';$focus=$focus[0];Need($focus[3].ToString('X16')-ceq'0000000004090409')'actual-us-layout'
 $edit=[Windows.Automation.AutomationElement]::FromHandle([IntPtr]$focus[0]);$p=$edit.Current;Need($p.ProcessId-eq$consent.pid -and $p.ControlType-eq[Windows.Automation.ControlType]::Edit -and $p.IsPassword -and $p.HasKeyboardFocus -and $p.IsKeyboardFocusable -and $p.IsEnabled -and -not$p.IsOffscreen)'actual-password-focus'
 $length=[MainSecureRead]::PasswordLength([IntPtr]$focus[0]);$root=[Windows.Automation.AutomationElement]::FromHandle([IntPtr]$focus[1]);$queue=[Collections.Generic.Queue[object]]::new();$queue.Enqueue(@($root,0));$visits=0;$accounts=@();$nodes=@();$walker=[Windows.Automation.TreeWalker]::RawViewWalker
 while($queue.Count){$entry=$queue.Dequeue();$node=$entry[0];$depth=[int]$entry[1];$visits++;Need($visits-le128 -and $depth-le8)'secure-ui-census-bound';$n=$node.Current;Need($n.ProcessId-eq$consent.pid)'secure-ui-owner';$nodes+=,$node;if(-not$n.IsPassword -and $n.Name-ceq$e.approvingAdminAccount -and $n.IsEnabled -and -not$n.IsOffscreen -and $n.ControlType-eq[Windows.Automation.ControlType]::Text){$accounts+=,$node};$child=$walker.GetFirstChild($node);while($null-ne$child){Need($queue.Count+$visits-lt128)'secure-ui-edge-bound';$queue.Enqueue(@($child,$depth+1));$child=$walker.GetNextSibling($child)}}
 $relations=@();foreach($item in $nodes){$ip=$null;if(-not$item.TryGetCurrentPattern([Windows.Automation.SelectionItemPattern]::Pattern,[ref]$ip) -or -not$ip.Current.IsSelected -or -not(Within $item $edit)){continue};$container=$ip.Current.SelectionContainer;Need($null-ne$container -and $container.Current.ProcessId-eq$consent.pid)'actual-selection-container';$sp=$null;Need($container.TryGetCurrentPattern([Windows.Automation.SelectionPattern]::Pattern,[ref]$sp) -and -not$sp.Current.CanSelectMultiple)'actual-single-selection-provider';$chosen=@($sp.Current.GetSelection());Need($chosen.Count-eq1 -and (Rid $chosen[0])-ceq(Rid $item))'actual-selected-item';$labels=@($accounts|Where-Object{Within $item $_});if($labels.Count-ne1){continue};$relations+=,@{kind='uia-selected-item-containing-password';selectedItemRuntimeId=@($item.GetRuntimeId());selectionContainerRuntimeId=@($container.GetRuntimeId());passwordRuntimeId=@($edit.GetRuntimeId());accountLabelRuntimeId=@($labels[0].GetRuntimeId())}}
 Need($relations.Count-eq1)'selected-account-password-relation';$relation=$relations[0]
 Need($accounts.Count-eq1)'selected-account-name';$account=@(Get-CimInstance Win32_UserAccount -Filter ("LocalAccount=TRUE AND Name='"+$e.approvingAdminAccount+"'") -OperationTimeoutSec 5);Need($account.Count-eq1 -and $account[0].SID-ceq$e.approvingAdminSid -and -not$account[0].Disabled -and -not$account[0].Lockout)'selected-account-native-sid'
 $rid=@($edit.GetRuntimeId());Need($rid.Count-gt0 -and $rid.Count-le32)'password-runtime-id'
 foreach($wanted in $e.ordinaryActors){$again=Get-Process -Id $wanted.pid;try{Need(-not$again.HasExited -and $again.StartTime.ToFileTimeUtc()-eq$wanted.creationFileTime -and $again.SessionId-eq2)'ordinary-closing'}finally{$again.Dispose()}}
 Need([MainBootRead]::Read()-ceq$e.guestBootIdentifier -and $self.StartTime.ToFileTimeUtc()-eq$b.creationFileTime)'reader-boot-closing'
 WritePrivate 'result.json' @{schemaVersion=1;taskBinding=$e.taskBinding;qemuIdentity=$e.qemuIdentity;guestBootIdentifier=$e.guestBootIdentifier;machineGuid=$nativeMachineGuid;ordinaryActors=$actors;consentActor=$consent;pendingRequest=$pending;correlationRecord=$corr;packageFile=$pkg;secureDesktop=@{windowStation=$desktop[0];desktop=$desktop[1];keyboardLayout=$focus[3].ToString('X16');focusOwnerPid=[int]$consent.pid;focusThreadId=[int]$focus[2];passwordFocused=$true;passwordLengthObserved=$length;selectedAccountName=$account[0].Name;selectedAccountSid=$account[0].SID;passwordControlRuntimeId=$rid;selectedAccountRelation=$relation};observer=@{pid=$PID;parentPid=[int]$selfCim.ParentProcessId;creationFileTime=$self.StartTime.ToFileTimeUtc();sid='S-1-5-18';sessionId=2;sourceSha256=$sourceSha;launcherSourceSha256='__LAUNCHER_SHA__';nativeRecordSha256='__NATIVE_RECORD_SHA__'}}
 }finally{$pf.Dispose()}
 }finally{if($null-ne$f){$f.Dispose()}}
 }finally{if($null-ne$cf){$cf.Dispose()};if($readToken-ne[IntPtr]::Zero){[MainSecureRead]::EndOrdinaryRead($readToken)}}
}finally{foreach($p in $held){$p.Dispose()}}
'''


# The common fixed prefix performs actual self/source/desktop/boot and ordinary
# actor reads. It ends BEFORE any installer file assumptions. This separate
# result is deliberately incompatible with validate_observation/input approval.
DISCOVERY_CHILD = CHILD.partition(" $pending=$e.pendingRequest;")[0] + r'''
 $consents=@(Get-CimInstance Win32_Process -Filter "Name='consent.exe'" -OperationTimeoutSec 5|Where-Object{$_.SessionId-eq2});Need($consents.Count-eq1)'unique-current-consent';$consent=ProcessFacts([int]$consents[0].ProcessId);$sig=Get-AuthenticodeSignature -LiteralPath $consent.image;Need($consent.sid-ceq'S-1-5-18' -and $consent.image-ieq'C:\Windows\System32\consent.exe' -and $sig.Status-eq'Valid' -and $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)-ceq'Microsoft Windows')'authentic-current-consent'
 $consent.signatureStatus=[string]$sig.Status;$consent.signerName='Microsoft Windows';$focus=[MainSecureRead]::FocusDiscovery();$focusRecord=$null;$focusActor=$null;$nodes=@();$truncated=$false;$uiaError=$null
 if($null-ne$focus){
  $focusActor=ProcessFacts([int]$focus[4]);$fs=Get-AuthenticodeSignature -LiteralPath $focusActor.image;$focusActor.signatureStatus=[string]$fs.Status;$focusActor.signerName=$null;if($null-ne$fs.SignerCertificate){$focusActor.signerName=$fs.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)}
  $focusRecord=@{focusHwnd=$focus[0];rootHwnd=$focus[1];threadId=$focus[2];keyboardLayout=$focus[3].ToString('X16');ownerPid=$focus[4]}
  try{
   $root=[Windows.Automation.AutomationElement]::FromHandle([IntPtr]$focus[1]);$queue=[Collections.Generic.Queue[object]]::new();$queue.Enqueue(@($root,0));$walker=[Windows.Automation.TreeWalker]::RawViewWalker
   while($queue.Count-gt0){if($nodes.Count-ge64){$truncated=$true;break};$entry=$queue.Dequeue();$node=$entry[0];$depth=[int]$entry[1];$n=$node.Current;$name=$null;if(-not$n.IsPassword){$name=$n.Name;if($name.Length-gt128){$name=$name.Substring(0,128);$truncated=$true}};$rid=@($node.GetRuntimeId());Need($rid.Count-le32)'discovery-runtime-id-bound';$rect=$n.BoundingRectangle
    $nodes+=,@{depth=$depth;processId=$n.ProcessId;controlType=$n.ControlType.ProgrammaticName;nativeWindowHandle=$n.NativeWindowHandle;runtimeId=$rid;name=$name;isPassword=$n.IsPassword;hasKeyboardFocus=$n.HasKeyboardFocus;isKeyboardFocusable=$n.IsKeyboardFocusable;isEnabled=$n.IsEnabled;isOffscreen=$n.IsOffscreen;rectangle=@($rect.X,$rect.Y,$rect.Width,$rect.Height)}
    if($depth-ge8){$truncated=$true;continue};$child=$walker.GetFirstChild($node);while($null-ne$child){if($queue.Count-ge128){$truncated=$true;break};$queue.Enqueue(@($child,$depth+1));$child=$walker.GetNextSibling($child)}
   }
  }catch{$uiaError='READ_ONLY_UIA_CENSUS_UNAVAILABLE'}
 }
 foreach($wanted in $e.ordinaryActors){$again=Get-Process -Id $wanted.pid;try{Need(-not$again.HasExited -and $again.StartTime.ToFileTimeUtc()-eq$wanted.creationFileTime -and $again.SessionId-eq2)'ordinary-closing'}finally{$again.Dispose()}}
 Need([MainBootRead]::Read()-ceq$e.guestBootIdentifier -and $self.StartTime.ToFileTimeUtc()-eq$b.creationFileTime)'reader-boot-closing'
 WritePrivate 'result.json' @{schemaVersion=2;state='CURRENT_SECURE_PROMPT_OBSERVATION_ONLY';taskBinding=$e.taskBinding;qemuIdentity=$e.qemuIdentity;guestBootIdentifier=$e.guestBootIdentifier;ordinaryActors=$actors;consentActor=$consent;secureDesktop=@{windowStation=$desktop[0];desktop=$desktop[1];focus=$focusRecord;focusActor=$focusActor;uiaNodes=$nodes;censusTruncated=$truncated;uiaError=$uiaError};inputCapability=$null;productTargetAuthority=$null;observer=@{pid=$PID;parentPid=[int]$selfCim.ParentProcessId;creationFileTime=$self.StartTime.ToFileTimeUtc();sid='S-1-5-18';sessionId=2;sourceSha256=$sourceSha;launcherSourceSha256='__LAUNCHER_SHA__';nativeRecordSha256='__NATIVE_RECORD_SHA__'}}
}finally{foreach($p in $held){$p.Dispose()}}
'''


PARENT = r'''$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$dir='__DIR__';$nonce='__NONCE__';$childSource=@'
__CHILD_SOURCE__
'@
$childSha='__CHILD_SHA__';$expectedPs='__POWERSHELL_SHA__';$sourcePin=$null;$nativePin=$null;$parentPin=[IntPtr]::Zero;$directoryPin=[IntPtr]::Zero
function Need($v,$c){if(-not$v){throw $c}}
function WritePrivate($name,$v){$b=[Text.Encoding]::UTF8.GetBytes(($v|ConvertTo-Json -Depth 14 -Compress));$f=[IO.FileStream]::new((Join-Path $dir $name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
function ReadCapture($name){Need($name-cin@('child.stdout.bin','child.stderr.bin'))'fixed-capture-role';$path=Join-Path $dir $name;Need(-not((Get-Item -LiteralPath $path -Force).Attributes-band[IO.FileAttributes]::ReparsePoint))'capture-reparse';$f=[IO.FileStream]::new($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);try{$identity=[MainSecureRead]::FileIdentity($f.SafeFileHandle.DangerousGetHandle(),$false);$a=Get-Acl -LiteralPath $path;Need($a.GetOwner([Security.Principal.SecurityIdentifier]).Value-ceq'S-1-5-18')'capture-system-owner';$rules=@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]));Need($rules.Count-eq1 -and $rules[0].IdentityReference.Value-ceq'S-1-5-18' -and $rules[0].AccessControlType-eq'Allow' -and [int]$rules[0].FileSystemRights-eq0x1f01ff)'capture-private-system-rules';Need($f.Length-ge0 -and $f.Length-le65536)'capture-bound';$b=New-Object byte[]([int]$f.Length);$o=0;while($o-lt$b.Length){$n=$f.Read($b,$o,$b.Length-$o);Need($n-gt0)'capture-short';$o+=$n};$h=[Security.Cryptography.SHA256]::Create();try{$sha=([BitConverter]::ToString($h.ComputeHash($b))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()};Need([MainSecureRead]::FileIdentity($f.SafeFileHandle.DangerousGetHandle(),$false)-ceq$identity -and $f.Length-eq$b.Length)'capture-held-closing';return @{path=$path;bytes=$b.Length;sha256=$sha;base64=[Convert]::ToBase64String($b);nativeIdentity=$identity;security=@{ownerSid='S-1-5-18';sddl=$a.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]5)};writersClosedByOwnedJobAndHandles=$true}}finally{$f.Dispose()}}
function Park($code){try{WritePrivate 'unknown.json' @{schemaVersion=1;nonce=$nonce;state='UNKNOWN';code=$code;replayAllowed=$false;ownedChildRetained=($null-ne$pi)}}catch{};while($true){Start-Sleep -Seconds 1}}
$pi=$null;$known=$false
try{
 Need([IntPtr]::Size-eq8 -and [Security.Principal.WindowsIdentity]::GetCurrent().User.Value-ceq'S-1-5-18' -and [Diagnostics.Process]::GetCurrentProcess().SessionId-eq0)'actual-system-session-zero-parent'
 $native=@'
__NATIVE__
'@
 Add-Type -TypeDefinition $native -ReferencedAssemblies @('System','System.Core')
 Need(-not((Get-Item -LiteralPath 'C:\ProgramData' -Force).Attributes-band[IO.FileAttributes]::ReparsePoint))'private-parent-reparse'
 $parentPin=[MainSecureRead]::DirectoryPin('C:\ProgramData');$parentIdentity=[MainSecureRead]::FileIdentity($parentPin,$true)
 [MainSecureRead]::PrivateDirectory($dir);$directoryPin=[MainSecureRead]::DirectoryPin($dir);$directoryIdentity=[MainSecureRead]::FileIdentity($directoryPin,$true)
 $nativePath=Join-Path $dir 'native.cs';$nativeBytes=[Text.Encoding]::UTF8.GetBytes($native);$f=[IO.FileStream]::new($nativePath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$f.Write($nativeBytes,0,$nativeBytes.Length);$f.Flush($true)}finally{$f.Dispose()};$nativePin=[IO.FileStream]::new($nativePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$nativeIdentity=[MainSecureRead]::FileIdentity($nativePin.SafeFileHandle.DangerousGetHandle(),$false)
 $application='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
 Need((Get-FileHash -LiteralPath $application -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$expectedPs)'fixed-powershell-bytes'
 WritePrivate 'intent.json' @{schemaVersion=1;nonce=$nonce;sourceSha256=$childSha;ordinaryTaskOperationId='__TASK__';productOperationId='__PRODUCT__';state='consumed';replayAllowed=$false}
 $sourcePath=Join-Path $dir 'observer.ps1';$sourceBytes=[Text.Encoding]::UTF8.GetBytes($childSource);$f=[IO.FileStream]::new($sourcePath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$f.Write($sourceBytes,0,$sourceBytes.Length);$f.Flush($true)}finally{$f.Dispose()};$sourcePin=[IO.FileStream]::new($sourcePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$sourceIdentity=[MainSecureRead]::FileIdentity($sourcePin.SafeFileHandle.DangerousGetHandle(),$false);Need((Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$childSha)'child-full-source-pin'
 $pi=[MainSecureRead]::Suspended($dir)
 $p=Get-Process -Id $pi.pid;$null=$p.Handle
 try{
  $token=[MainSecureRead]::Token($pi.process);$birth=$p.StartTime.ToFileTimeUtc();$cim=Get-CimInstance Win32_Process -Filter ('ProcessId='+$pi.pid) -OperationTimeoutSec 5
  Need($token[0]-ceq'S-1-5-18' -and $token[1]-eq2 -and $p.SessionId-eq2 -and $p.Path-ieq$application -and $cim.ParentProcessId-eq$PID -and $p.StartTime.ToFileTimeUtc()-eq$birth -and -not$p.HasExited)'held-suspended-system-session-two-child'
  WritePrivate 'child.json' @{schemaVersion=1;nonce=$nonce;pid=[int]$pi.pid;parentPid=$PID;creationFileTime=$birth;sessionId=2;sourceSha256=$childSha}
  Need([MainSecureRead]::ResumeThread($pi.thread)-eq1)'resume-one-owned-original'
  $wait=[MainSecureRead]::WaitForSingleObject($pi.process,25000);if($wait-ne0){Park 'read-only-observer-terminal-unknown'}
  [uint32]$exit=0;Need([MainSecureRead]::GetExitCodeProcess($pi.process,[ref]$exit))'reader-exit';[MainSecureRead]::CaptureClosed();$captures=@{stdout=(ReadCapture 'child.stdout.bin');stderr=(ReadCapture 'child.stderr.bin')};WritePrivate 'capture.json' $captures;$known=$true
  WritePrivate 'terminal.json' @{schemaVersion=1;nonce=$nonce;pid=[int]$pi.pid;creationFileTime=$birth;exitCode=$exit;knownTerminal=$true;replayAllowed=$false}
  Need($exit-eq0)'reader-refused'
  Need([MainSecureRead]::FileIdentity($nativePin.SafeFileHandle.DangerousGetHandle(),$false)-ceq$nativeIdentity -and [MainSecureRead]::FileIdentity($sourcePin.SafeFileHandle.DangerousGetHandle(),$false)-ceq$sourceIdentity -and [MainSecureRead]::FileIdentity($parentPin,$true)-ceq$parentIdentity -and [MainSecureRead]::FileIdentity($directoryPin,$true)-ceq$directoryIdentity)'source-directory-held-closing'
 $result=Join-Path $dir 'result.json';Need(-not((Get-Item -LiteralPath $result -Force).Attributes-band[IO.FileAttributes]::ReparsePoint))'result-reparse'
  $f=[IO.FileStream]::new($result,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);try{Need($f.Length-gt0 -and $f.Length-le65536)'result-bound';$b=New-Object byte[]([int]$f.Length);$o=0;while($o-lt$b.Length){$n=$f.Read($b,$o,$b.Length-$o);Need($n-gt0)'result-short';$o+=$n};$v=[Text.UTF8Encoding]::new($false,$true).GetString($b)|ConvertFrom-Json;Need($v.observer.pid-eq$pi.pid -and $v.observer.parentPid-eq$PID -and $v.observer.creationFileTime-eq$birth -and $v.observer.sourceSha256-ceq$childSha)'result-original-child-binding';$observation=$v;$childRecord=@{pid=[int]$pi.pid;creationFileTime=$birth;sessionId=2;exitCode=$exit;sourceSha256=$childSha;nonce=$nonce;knownTerminal=$true}}finally{$f.Dispose()}
 }finally{$p.Dispose()}
}catch{if($null-eq$pi -and ('MainSecureRead'-as[type])){$owned=[MainSecureRead]::Owned();if($owned.pid-gt0){$pi=$owned}};if($null-ne$pi -and -not$known){Park 'observer-launch-or-close-unknown'};[Console]::Error.WriteLine('CURRENT_MAIN_READ_ONLY_OBSERVER_REFUSED');exit 1}
finally{if($null-ne$pi -and $known){if(-not[MainSecureRead]::CloseHandle($pi.thread)-or -not[MainSecureRead]::CloseHandle($pi.process)){Park 'owned-handle-close-unknown'};if($null-ne$sourcePin){$sourcePin.Dispose()};if($null-ne$nativePin){$nativePin.Dispose()};if($directoryPin-ne[IntPtr]::Zero -and -not[MainSecureRead]::CloseHandle($directoryPin)){Park 'directory-close-unknown'};if($parentPin-ne[IntPtr]::Zero -and -not[MainSecureRead]::CloseHandle($parentPin)){Park 'parent-close-unknown'}}}
$r=[ordered]@{schemaVersion=1;state='current-main-input-read-only-observed';observation=$observation;child=$childRecord;childTerminalObserved=$known;captures=$captures;productOperation=$false;taskOperation=$false;inputPerformed=$false};[pscustomobject]$r
'''


def render(expected, nonce, native_record_sha256):
    validate(expected)
    return _assemble_fixed(expected, nonce, native_record_sha256, CHILD)


def render_discovery(expected, nonce, native_record_sha256):
    """Fixed read-only inspection, never an input/credential admission packet."""
    validate_discovery(expected)
    return _assemble_fixed(expected, nonce, native_record_sha256, DISCOVERY_CHILD)


def _assemble_fixed(expected, nonce, native_record_sha256, child_template):
    need(type(nonce) is str and str(uuid.UUID(nonce)) == nonce, "observer-nonce")
    need(type(native_record_sha256) is str and re.fullmatch("[0-9a-f]{64}", native_record_sha256), "observer-native-record")
    directory = r"C:\ProgramData\VpnControlMainInputRead-" + nonce
    payload = base64.b64encode(json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()).decode()
    # The child records a stable launcher TEMPLATE digest. Actual emitted parent
    # bytes are separately held and joined by the original outer owner; this
    # deliberately avoids a circular child↔parent digest construction.
    launcher_template_sha = hashlib.sha256(PARENT.encode()).hexdigest()
    child = child_template.replace("__DIR__", directory).replace("__NONCE__", nonce).replace("__EXPECTED__", payload).replace("__NATIVE_SHA__", hashlib.sha256(NATIVE.encode()).hexdigest())
    child = child.replace("__LAUNCHER_SHA__", launcher_template_sha).replace("__NATIVE_RECORD_SHA__", native_record_sha256)
    child_sha = hashlib.sha256(child.encode("utf-8")).hexdigest()
    need("\n'@" not in child, "fixed-child-literal-boundary")
    parent = PARENT.replace("__DIR__", directory).replace("__NONCE__", nonce).replace("__CHILD_SOURCE__", child).replace("__CHILD_SHA__", child_sha).replace("__NATIVE__", NATIVE)
    parent = parent.replace("__POWERSHELL_SHA__", expected["powershellSha256"]).replace("__TASK__", expected["taskBinding"]["ordinaryTaskOperationId"]).replace("__PRODUCT__", expected["taskBinding"]["productOperationId"])
    need("__" not in parent and "__" not in child, "observer-unfilled-slot")
    need(len(parent.encode()) <= 65536, "observer-fixed-parent-expansion-bound")
    # Compact only this internally generated finite parent; no supplied script
    # selector exists. Preserve its exact full bytes/hash and bounded expansion.
    # The normal canonical automatic saved-source transport remains unchanged.
    packed_parent = base64.b64encode(gzip.compress(parent.encode(), mtime=0)).decode()
    parent_sha = hashlib.sha256(parent.encode()).hexdigest()
    program = "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'\n"
    program += "$packed=[IO.MemoryStream]::new([Convert]::FromBase64String('" + packed_parent + "'));$gzip=[IO.Compression.GZipStream]::new($packed,[IO.Compression.CompressionMode]::Decompress);$expanded=[IO.MemoryStream]::new();try{$buffer=New-Object byte[] 4096;while(($n=$gzip.Read($buffer,0,$buffer.Length))-gt0){if($expanded.Length+$n-gt65536){throw 'FIXED_PARENT_EXPANSION_BOUND'};$expanded.Write($buffer,0,$n)};$bytes=$expanded.ToArray()}finally{$gzip.Dispose();$packed.Dispose();$expanded.Dispose()}\n"
    program += "$hash=[Security.Cryptography.SHA256]::Create();try{$actual=([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()};if($bytes.Length-ne" + str(len(parent.encode())) + "-or$actual-cne'" + parent_sha + "'){throw 'FIXED_PARENT_SOURCE'};$text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes);$value=&([ScriptBlock]::Create($text));if($value-isnot[Management.Automation.PSCustomObject]){throw 'FIXED_PARENT_RESULT'}\n"
    program += "$r=[ordered]@{schemaVersion=$value.schemaVersion;state=$value.state;observation=$value.observation;child=$value.child;childTerminalObserved=$value.childTerminalObserved;captures=$value.captures;productOperation=$false;taskOperation=$false;inputPerformed=$false;fixedParentSha256='" + parent_sha + "'};[Console]::WriteLine(($r|ConvertTo-Json -Depth 8 -Compress))\n"
    return {"parent": parent, "child": child, "program": program, "childUtf8Sha256": child_sha,
            "parentUtf8Sha256": parent_sha, "programUtf8Sha256": hashlib.sha256(program.encode()).hexdigest(),
            "launcherTemplateSha256": launcher_template_sha, "directory": directory,
            "sessionTransfer": "SYSTEM/0 -> suspended SYSTEM/2 -> WinSta0\\Winlogon read only",
            "inputPerformed": False}

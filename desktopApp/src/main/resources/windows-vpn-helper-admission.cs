// Fixed packaged broker entry admission. Component probes may call Run directly;
// the product entrypoint always establishes this independent native lifetime fence.
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

public static class VpnPackagedBrokerAdmission {
 internal interface Handle { }
 internal sealed class Owner {
  internal readonly uint Pid;internal readonly long Created;
  internal readonly string Sid,Image;internal readonly bool Alive;
  internal Owner(uint pid,long created,string sid,string image,bool alive) { Pid=pid;Created=created;Sid=sid;Image=image;Alive=alive; }
  public override string ToString() { return "Native broker owner (<redacted>)"; }
 }
 // The production overload constructs FixedNative itself. No worker argument,
 // serialized request, JVM property, environment variable or manifest selects this seam.
 internal interface Native {
  Handle OpenOwner(uint pid);Owner ObserveOwner(Handle owner);string CurrentImage();
  Handle Open(string path);Handle OpenGate(string path);
  string Canonical(Handle file);string Identity(Handle file);int Machine(Handle file);
  void Inspect(Handle file,bool directory,bool ancestor,string principal);
  void LinkedAncestor(Handle parent,Handle child,string principal);
  string InstallationId(Handle directory);string ProgramData();IEnumerable<string> Children(Handle directory);
  bool LockShared(Handle gate);void UnlockShared(Handle gate);byte[] ReadGate(Handle gate);
  void Close(Handle handle);void CloseAuxiliary();
 }

 public sealed class Lease : IDisposable {
  readonly Native native;readonly List<Handle> handles=new List<Handle>();
  Handle gate,primaryImage;bool locked,disposed;
  internal Lease(Native native) { this.native=native; }
  internal Handle Keep(Handle handle) { Need(handle!=null,"UNAVAILABLE");handles.Add(handle);return handle; }
  internal void Locked(Handle value) { gate=value;locked=true; }
  internal void PrimaryImage(Handle value) { primaryImage=value; }
  internal void Reject(Handle value) { native.Close(value);handles.Remove(value); }
  public void Dispose() {
   if(disposed) return;
   Exception failure=null;
   // Original executable and shared gate are the final fences, including after
   // JVM exit. A failed intermediate close must not let MSI pass its write probe.
   for(int index=handles.Count-1;index>=0;index--) {
    Handle handle=handles[index];
    if(Object.ReferenceEquals(handle,gate)||Object.ReferenceEquals(handle,primaryImage)) continue;
    try { native.Close(handle);handles.RemoveAt(index); }
    catch(Exception error) { if(failure==null) failure=error; }
   }
   if(failure!=null) throw failure;
   native.CloseAuxiliary();
   if(gate!=null) {
    if(locked) { native.UnlockShared(gate);locked=false; }
    native.Close(gate);handles.Remove(gate);gate=null;
   }
   if(primaryImage!=null) { native.Close(primaryImage);handles.Remove(primaryImage);primaryImage=null; }
   Need(handles.Count==0,"UNAVAILABLE");disposed=true;
  }
  public override string ToString() { return "Packaged broker admission (<redacted>)"; }
 }
 internal sealed class CleanupPending : IOException {
  internal readonly Lease Retained;
  internal CleanupPending(Lease retained) : base("UNAVAILABLE") { Retained=retained; }
 }

 public static Lease Retain(uint pid,long created,string sid) { return Retain(pid,created,sid,new FixedNative()); }
 internal static Lease Retain(uint pid,long created,string sid,Native native) {
  Need(pid>0&&created>0&&new SecurityIdentifier(sid).Value==sid,"INVALID_ARGUMENT");
  Lease lease=new Lease(native);
  try {
   Handle process=lease.Keep(native.OpenOwner(pid));
   Owner owner=native.ObserveOwner(process);RequireOwner(owner,pid,created,sid);
   string query=PlainPath(owner.Image);
   // Pin the queried leaf before following its canonical spelling. The full linked
   // ancestry is admitted below, before opening a pipe or accepting runtime input.
   Handle original=lease.Keep(native.Open(query));lease.PrimaryImage(original);native.Inspect(original,false,false,sid);
   string image=PlainPath(native.Canonical(original));string leaf=Path.GetFileName(image);
   Need(String.Equals(leaf,"vpn-control.exe",StringComparison.OrdinalIgnoreCase)||
        String.Equals(leaf,"vpn-control-cli.exe",StringComparison.OrdinalIgnoreCase),"UNAVAILABLE");
   Need(native.Machine(original)==0x8664,"UNSUPPORTED");
   List<Handle> application=PinAncestry(image,false,sid,native,lease);
   Handle linkedImage=application[application.Count-1];
   Need(native.Identity(linkedImage)==native.Identity(original)&&native.Canonical(linkedImage)==native.Canonical(original),"CONFLICT");
   Handle applicationRoot=application[application.Count-2];
   string root=PlainPath(native.Canonical(applicationRoot));
   string expected=root+"\\app\\native\\windows-amd64\\vpn-control-vpn-broker.exe";
   List<Handle> helper=PinAncestry(expected,false,sid,native,lease);
   Handle expectedHelper=helper[helper.Count-1];
   Handle actualHelper=lease.Keep(native.Open(PlainPath(native.CurrentImage())));
   native.Inspect(actualHelper,false,false,sid);
   Need(native.Machine(actualHelper)==0x8664&&native.Identity(actualHelper)==native.Identity(expectedHelper)&&
        native.Canonical(actualHelper)==native.Canonical(expectedHelper),"PERMISSION_DENIED");
   // Installation identity uses the same native invariant uppercase path bytes as
   // ordinary admission and the installer coordinator, including the extended prefix.
   string id=native.InstallationId(applicationRoot);
   string programData=PlainPath(native.ProgramData());
   List<Handle> protectedParents=PinAncestry(programData,true,null,native,lease);
   Handle parent=protectedParents[protectedParents.Count-1];
   Handle product=null;
   try { product=lease.Keep(native.Open(programData+"\\vpn-control-install-jobs")); }
   catch(Win32Exception failure) { if(failure.NativeErrorCode!=2) throw; }
   if(product!=null) {
    native.LinkedAncestor(parent,product,null);native.Inspect(product,true,false,null);
    Handle gate=null;
    try { gate=lease.Keep(native.OpenGate(programData+"\\vpn-control-install-jobs\\gate-"+id)); }
    catch(Win32Exception failure) { if(failure.NativeErrorCode!=2) throw; }
    if(gate!=null) {
     Need(Parent(native.Canonical(gate))==native.Canonical(product).TrimEnd('\\'),"CONFLICT");
     native.Inspect(gate,false,false,null);
     Need(native.LockShared(gate),"BUSY");lease.Locked(gate);
     native.Inspect(gate,false,false,null);byte[] bytes=native.ReadGate(gate);
     Need(bytes!=null&&bytes.Length==17,"CONFLICT");
     for(int index=0;index<bytes.Length;index++) Need(index==8 ? bytes[index]<=1 : bytes[index]==0,"CONFLICT");
     Need(bytes[8]==0,"BUSY");
    }
   }
   Owner rechecked=native.ObserveOwner(process);RequireOwner(rechecked,pid,created,sid);
   Need(rechecked.Image==owner.Image,"CONFLICT");
   // Missing first gate deliberately retains both native executable pins. Existing
   // installer sibling write probes remain BUSY even after the JVM owner exits.
   return lease;
  } catch {
   try { lease.Dispose(); } catch { throw new CleanupPending(lease); }
   throw;
  }
 }

 static List<Handle> PinAncestry(string path,bool directory,string principal,Native native,Lease lease) {
  string prefix=path.Substring(0,3);var paths=new List<string>();paths.Add(prefix);
  if(path.Length>3) foreach(string part in path.Substring(3).Split('\\')) { prefix=prefix.TrimEnd('\\')+"\\"+part;paths.Add(prefix); }
  var result=new List<Handle>();Handle previous=null;
  for(int index=0;index<paths.Count;index++) {
   Handle file=lease.Keep(native.Open(paths[index]));
   if(previous!=null) native.LinkedAncestor(previous,file,principal);
   if(index==paths.Count-1) {
    if(directory) TailAncestor(file,principal,native,lease);
    else native.Inspect(file,false,false,principal);
   }
   result.Add(file);previous=file;
  }
  return result;
 }
 static void TailAncestor(Handle directory,string principal,Native native,Lease lease) {
  try { native.Inspect(directory,true,true,principal);return; } catch(IOException) { }
  // The final ProgramData ancestor may need a retained nonempty witness even
  // when the product root has never existed. Enumeration never selects runtime inputs.
  string root=native.Canonical(directory).TrimEnd('\\');int count=0;
  foreach(string name in native.Children(directory)) {
   if(++count>4096) break;
   if(String.IsNullOrEmpty(name)||name=="."||name==".."||name.IndexOfAny(new[]{'\\','/',':','\0'})>=0) continue;
   Handle child=null;bool accepted=false;
   try {
    child=lease.Keep(native.Open(root+"\\"+name));native.LinkedAncestor(directory,child,principal);accepted=true;
   } catch(Win32Exception) { } catch(IOException) { }
   finally { if(child!=null&&!accepted) lease.Reject(child); }
   if(accepted) return;
  }
  throw new IOException("PERMISSION_DENIED");
 }
 static void RequireOwner(Owner owner,uint pid,long created,string sid) {
  Need(owner!=null&&owner.Pid==pid&&owner.Created==created&&owner.Sid==sid&&owner.Alive,"PERMISSION_DENIED");
 }
 static string Parent(string path) { return path.Substring(0,path.LastIndexOf('\\')); }
 static string PlainPath(string path) {
  Need(!String.IsNullOrEmpty(path)&&path.Length<32768,"INVALID_ARGUMENT");
  if(path.StartsWith("\\\\?\\",StringComparison.Ordinal)) path=path.Substring(4);
  Need(path.Length>=3&&((path[0]>='A'&&path[0]<='Z')||(path[0]>='a'&&path[0]<='z'))&&path[1]==':'&&path[2]=='\\',"UNSUPPORTED");
  Need(path.IndexOf('\0')<0&&path.IndexOf('/')<0&&path.IndexOf(':',2)<0&&Path.GetFullPath(path)==path,"INVALID_ARGUMENT");
  if(path.Length>3) foreach(string part in path.Substring(3).Split('\\'))
   Need(part.Length>0&&part!="."&&part!=".."&&!part.EndsWith(".",StringComparison.Ordinal)&&!part.EndsWith(" ",StringComparison.Ordinal),"INVALID_ARGUMENT");
  return path;
 }
 static void Need(bool value,string code) { if(!value) throw new IOException(code); }

 sealed class FixedNative : Native {
  sealed class File : Handle { internal readonly SafeFileHandle Value;internal readonly FileStream Stream;internal bool NativeClosed;
   internal File(SafeFileHandle value,FileStream stream=null) { Value=value;Stream=stream; } }
  sealed class Process : Handle { internal IntPtr Value;internal Process(IntPtr value) { Value=value; } }
  readonly List<IntPtr> tokens=new List<IntPtr>();
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr process,out long created,out long exited,out long kernel,out long user);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  [DllImport("kernel32.dll",SetLastError=true)] static extern uint GetProcessId(IntPtr process);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr process,uint timeout);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageNameW(IntPtr process,uint flags,StringBuilder image,ref uint count);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandleW(SafeFileHandle file,StringBuilder path,uint count,uint flags);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle file,int kind,byte[] buffer,uint count);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
  static void Checked(bool value) { if(!value) throw new Win32Exception(Marshal.GetLastWin32Error()); }

  public Handle OpenOwner(uint pid) {
   IntPtr handle=OpenProcess(0x00101000,false,pid);Checked(handle!=IntPtr.Zero);return new Process(handle);
  }
  public Owner ObserveOwner(Handle owner) {
   IntPtr process=((Process)owner).Value;Need(process!=IntPtr.Zero,"UNAVAILABLE");
   uint pid=GetProcessId(process);long created,exited,kernel,user;
   Checked(GetProcessTimes(process,out created,out exited,out kernel,out user));
   string image=Image(process);IntPtr token;Checked(OpenProcessToken(process,8,out token));tokens.Add(token);
   string sid;
   try { using(var identity=new WindowsIdentity(token)) { sid=identity.User.Value; } }
   finally { Checked(CloseHandle(token));tokens.Remove(token); }
   uint state=WaitForSingleObject(process,0);Need(state==0||state==258,"UNAVAILABLE");
   return new Owner(pid,created,sid,image,state==258);
  }
  static string Image(IntPtr process) {
   var path=new StringBuilder(32768);uint count=32768;Checked(QueryFullProcessImageNameW(process,0,path,ref count));
   Need(count>0&&count<32768,"UNAVAILABLE");return path.ToString();
  }
  public string CurrentImage() { return Image(GetCurrentProcess()); }
  public Handle Open(string path) { return new File(VpnInstallNative.OpenDirectory(path)); }
  public Handle OpenGate(string path) { FileStream stream=VpnInstallNative.OpenGate(path,false);return new File(stream.SafeFileHandle,stream); }
  public string Canonical(Handle handle) {
   var path=new StringBuilder(32768);uint count=GetFinalPathNameByHandleW(((File)handle).Value,path,32768,0);
   Need(count>0&&count<32768,"UNAVAILABLE");return path.ToString();
  }
  public string Identity(Handle handle) {
   byte[] bytes=new byte[24];Checked(GetFileInformationByHandleEx(((File)handle).Value,18,bytes,24));
   return BitConverter.ToString(bytes);
  }
  public int Machine(Handle handle) {
   // Borrow, never transfer ownership of the immutable input handle to the reader.
   using(var borrowed=new SafeFileHandle(((File)handle).Value.DangerousGetHandle(),false))
   using(var input=new FileStream(borrowed,FileAccess.Read,8192,false)) {
    Need(input.Length>=64,"UNSUPPORTED");var header=new byte[64];Exact(input,header);Need(header[0]=='M'&&header[1]=='Z',"UNSUPPORTED");
    uint offset=BitConverter.ToUInt32(header,60);Need(offset>=64&&offset<=input.Length-6,"UNSUPPORTED");
    input.Position=offset;header=new byte[6];Exact(input,header);Need(BitConverter.ToUInt32(header,0)==0x4550,"UNSUPPORTED");
    return BitConverter.ToUInt16(header,4);
   }
  }
  static void Exact(Stream input,byte[] bytes) {
   int position=0;while(position<bytes.Length) { int count=input.Read(bytes,position,bytes.Length-position);Need(count>0,"CONFLICT");position+=count; }
  }
  public void Inspect(Handle file,bool directory,bool ancestor,string principal) { VpnInstallNative.Inspect(((File)file).Value,directory,ancestor,principal); }
  public void LinkedAncestor(Handle parent,Handle child,string principal) { VpnInstallNative.InspectLinkedAncestor(((File)parent).Value,((File)child).Value,principal); }
  public string InstallationId(Handle directory) { return VpnInstallNative.InstallationId(((File)directory).Value); }
  public string ProgramData() { return VpnInstallNative.ProgramData(); }
  public IEnumerable<string> Children(Handle directory) {
   int count=0;
   foreach(string path in Directory.EnumerateFileSystemEntries(Canonical(directory))) {
    if(++count>4096) yield break;
    yield return Path.GetFileName(path);
   }
  }
  public bool LockShared(Handle gate) { return VpnInstallNative.TryLock(((File)gate).Value,0,false); }
  public void UnlockShared(Handle gate) { VpnInstallNative.Unlock(((File)gate).Value,0); }
  public byte[] ReadGate(Handle gate) {
   var file=(File)gate;Need(file.Stream!=null&&file.Stream.Length==17,"CONFLICT");file.Stream.Position=0;
   var bytes=new byte[17];Exact(file.Stream,bytes);Need(file.Stream.ReadByte()==-1,"CONFLICT");return bytes;
  }
  public void Close(Handle handle) {
   var process=handle as Process;
   if(process!=null) { if(process.Value!=IntPtr.Zero) { Checked(CloseHandle(process.Value));process.Value=IntPtr.Zero; } return; }
   var file=(File)handle;
   if(!file.NativeClosed) { Checked(CloseHandle(file.Value.DangerousGetHandle()));file.NativeClosed=true;file.Value.SetHandleAsInvalid(); }
   if(file.Stream!=null) file.Stream.Dispose();file.Value.Dispose();
  }
  public void CloseAuxiliary() {
   Exception failure=null;
   for(int index=tokens.Count-1;index>=0;index--) try { Checked(CloseHandle(tokens[index]));tokens.RemoveAt(index); }
   catch(Exception error) { if(failure==null) failure=error; }
   if(failure!=null) throw failure;
  }
 }
}

// Captured fixed source. This broker accepts bytes, never an elevated user-workspace executable path.
using System;
using System.IO;
using System.IO.Pipes;
using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;
public static class VpnRuntimeBroker {
 [StructLayout(LayoutKind.Sequential)] struct SA { public int n; public IntPtr d; public int inherit; }
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct SI {
  public int cb; public string reserved,desktop,title; public int x,y,xs,ys,xc,yc,fill,flags; public short show,reserved2;
  public IntPtr reservedPtr,input,output,error;
 }
 [StructLayout(LayoutKind.Sequential)] struct SX { public SI si; public IntPtr attributes; }
 [StructLayout(LayoutKind.Sequential)] struct PI { public IntPtr process,thread; public int pid,tid; }
 [StructLayout(LayoutKind.Sequential)] struct LIMIT {
  public long processTime,jobTime; public uint flags; public UIntPtr min,max; public uint active; public UIntPtr affinity;
  public uint priority,scheduling; public long rOps,wOps,oOps,rBytes,wBytes,oBytes; public UIntPtr processMemory,jobMemory,peakProcess,peakJob;
 }
 [StructLayout(LayoutKind.Sequential)] struct ACCOUNTING {
  public long user,kernel,periodUser,periodKernel; public uint faults,total,active,terminated;
 }
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll")] static extern bool GetProcessTimes(IntPtr p,out long create,out long exit,out long kernel,out long user);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h,uint time);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool DuplicateHandle(IntPtr source,IntPtr h,IntPtr target,out IntPtr copy,uint access,bool inherit,uint options);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll",EntryPoint="QueryInformationJobObject",SetLastError=true)] static extern bool QueryJobLimits(IntPtr job,int type,ref LIMIT info,int length,IntPtr returned);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll",EntryPoint="QueryInformationJobObject",SetLastError=true)] static extern bool QueryJobAccounting(IntPtr job,int type,ref ACCOUNTING info,int length,IntPtr returned);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll")] static extern bool TerminateJobObject(IntPtr job,uint code);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,int flags,ref IntPtr size);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr key,IntPtr value,IntPtr size,IntPtr old,IntPtr returned);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string app,StringBuilder command,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr env,string cwd,ref SX startup,out PI info);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe,out uint pid);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafePipeHandle CreateNamedPipe(string name,uint openMode,uint pipeMode,uint max,uint output,uint input,uint timeout,ref SA security);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string p,uint a,uint share,IntPtr sa,uint disposition,uint flags,IntPtr template);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern uint GetFinalPathNameByHandle(SafeFileHandle h,StringBuilder path,uint count,uint flags);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll")] static extern bool SetHandleInformation(IntPtr h,uint mask,uint flags);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll")] static extern bool GenerateConsoleCtrlEvent(uint signal,uint group);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll")] static extern bool AllocConsole();
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("advapi32.dll")] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle file,int kind,IntPtr information,uint length);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll")] static extern uint GetFileType(SafeFileHandle file);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool GetVolumeInformationByHandleW(SafeFileHandle file,IntPtr name,uint nameSize,IntPtr serial,IntPtr maximum,out uint flags,IntPtr fileSystem,uint fileSystemSize);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("advapi32.dll",SetLastError=true)] static extern uint GetSecurityInfo(SafeFileHandle file,int kind,uint requested,out IntPtr owner,IntPtr group,out IntPtr dacl,IntPtr sacl,out IntPtr descriptor);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("advapi32.dll")] static extern bool IsValidSecurityDescriptor(IntPtr descriptor);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr pointer);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateDirectory(string path,ref SA security);
 static void Need(bool value) { if(!value) throw new IOException("VPN broker prerequisite failed"); }
 static void CreatePrivateDirectory(string path,DirectorySecurity protection) {
  byte[] descriptor=protection.GetSecurityDescriptorBinaryForm();var retained=GCHandle.Alloc(descriptor,GCHandleType.Pinned);
  try {
   var security=new SA();security.n=Marshal.SizeOf<SA>();security.d=retained.AddrOfPinnedObject();
   // Native CreateDirectory fails if any object already occupies this exact path. The supplied
   // protected ACL is installed atomically, before another principal could open a new directory.
   Need(CreateDirectory(path,ref security));
  } finally { retained.Free(); }
 }
 static void ReportFailure(BinaryWriter writer,Exception failure) {
  byte code=4;
  if(failure is OutOfMemoryException || (failure is IOException && (((uint)failure.HResult&0xffff)==112 || ((uint)failure.HResult&0xffff)==39))) code=3;
  else if(failure is UnauthorizedAccessException) code=2;
  else if(failure is ArgumentException || failure is DecoderFallbackException) code=1;
  try { writer.Write(code); writer.Flush(); } catch { }
 }
 static bool Trusted(string sid) { return sid=="S-1-5-18" || sid=="S-1-5-32-544"; }
 static void AdmissionNeed(bool value) { if(!value) throw new UnauthorizedAccessException("PERMISSION_DENIED"); }
 static string FinalPath(SafeFileHandle file) {
  var name=new StringBuilder(32768);uint size=GetFinalPathNameByHandle(file,name,32768,0);
  AdmissionNeed(size>0&&size<32768);string value=name.ToString();
  AdmissionNeed(value.StartsWith("\\\\?\\",StringComparison.Ordinal)&&!value.StartsWith("\\\\?\\UNC\\",StringComparison.OrdinalIgnoreCase));
  return value.Substring(4);
 }
 static uint ObjectAttributes(SafeFileHandle file) {
  AdmissionNeed(GetFileType(file)==1);IntPtr info=Marshal.AllocHGlobal(8);
  try {
   AdmissionNeed(GetFileInformationByHandleEx(file,9,info,8));
   uint attributes=unchecked((uint)Marshal.ReadInt32(info));
   AdmissionNeed((attributes&0x400)==0&&Marshal.ReadInt32(info,4)==0);return attributes;
  } finally { Marshal.FreeHGlobal(info); }
 }
 static void VerifyDirectory(SafeFileHandle file,bool leaf,bool witnessed) {
  AdmissionNeed(!leaf||!witnessed);AdmissionNeed((ObjectAttributes(file)&16)!=0);
  uint volume;AdmissionNeed(GetVolumeInformationByHandleW(file,IntPtr.Zero,0,IntPtr.Zero,IntPtr.Zero,out volume,IntPtr.Zero,0)&&(volume&8)!=0);
  IntPtr owner,dacl,descriptor;AdmissionNeed(GetSecurityInfo(file,1,5,out owner,IntPtr.Zero,out dacl,IntPtr.Zero,out descriptor)==0);
  try {
   AdmissionNeed(IsValidSecurityDescriptor(descriptor));uint length=GetSecurityDescriptorLength(descriptor);
   AdmissionNeed(length>0&&length<=1048576);var bytes=new byte[length];Marshal.Copy(descriptor,bytes,0,bytes.Length);
   var security=new RawSecurityDescriptor(bytes,0);AdmissionNeed(security.Owner!=null);
   string sid=security.Owner.Value;
   AdmissionNeed(Trusted(sid)||!leaf&&sid=="S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
   var acl=security.DiscretionaryAcl;AdmissionNeed(acl!=null&&acl.Count<=4096);
   foreach(GenericAce entry in acl) {
    AdmissionNeed(entry.AceType==AceType.AccessAllowed||entry.AceType==AceType.AccessDenied);
    var ace=entry as CommonAce;AdmissionNeed(ace!=null);
    if(entry.AceType==AceType.AccessDenied||(entry.AceFlags&AceFlags.InheritOnly)!=0||Trusted(ace.SecurityIdentifier.Value)) continue;
    uint allowed=0xA01200A9U|(!leaf?6U:0U)|(!leaf&&witnessed?0x110U:0U);
    AdmissionNeed((unchecked((uint)ace.AccessMask)&~allowed)==0);
   }
  } finally { LocalFree(descriptor); }
 }
 static void PinWitness(string path,SafeFileHandle parent,System.Collections.Generic.List<SafeFileHandle> retained) {
  string canonical=FinalPath(parent).TrimEnd('\\');int visited=0;
  foreach(string childPath in Directory.EnumerateFileSystemEntries(path)) {
   if(++visited>4096) break;
   var child=CreateFile(childPath,0x20081,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
   if(child.IsInvalid) { child.Dispose();continue; }
   bool accepted=false;
   try {
    ObjectAttributes(child);
    AdmissionNeed(String.Equals(Path.GetDirectoryName(FinalPath(child)).TrimEnd('\\'),canonical,StringComparison.Ordinal));
    AdmissionNeed(FinalPath(parent).TrimEnd('\\')==canonical);VerifyDirectory(parent,false,true);
    retained.Add(child);accepted=true;return;
   } catch(UnauthorizedAccessException) { }
   finally { if(!accepted) child.Dispose(); }
  }
  throw new UnauthorizedAccessException("PERMISSION_DENIED");
 }
 static SafeFileHandle Pin(string path,bool leaf,System.Collections.Generic.List<SafeFileHandle> retained) {
  // FILE_LIST_DIRECTORY participates in deny-delete sharing; metadata-only handles do not pin a directory.
  var h=CreateFile(path,0x20081,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero); Need(!h.IsInvalid);
  try {
   AdmissionNeed(String.Equals(FinalPath(h).TrimEnd('\\'),Path.GetFullPath(path).TrimEnd('\\'),StringComparison.OrdinalIgnoreCase));
   try { VerifyDirectory(h,leaf,false); }
   catch(UnauthorizedAccessException) {
    if(leaf) throw;
    // Validate all other rights first. A retained linked child alone permits attribute/EA writes.
    VerifyDirectory(h,false,true);PinWitness(path,h,retained);
   }
   return h;
  } catch { h.Dispose(); throw; }
 }
 static byte[] Blob(BinaryReader reader,int limit) { int n=reader.ReadInt32(); Need(n>0&&n<=limit); var b=reader.ReadBytes(n); Need(b.Length==n); return b; }
 static void ConfigurationBlob(BinaryReader reader,string path,bool allowEmpty=false) {
  long total=0;
  using(var file=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None)) using(var hash=SHA256.Create()) {
   while(true) {
    int count=reader.ReadInt32(); Need(count>=0&&count<=65536); if(count==0) break;
    byte[] chunk=reader.ReadBytes(count); Need(chunk.Length==count); file.Write(chunk,0,count);
    hash.TransformBlock(chunk,0,count,null,0); total=checked(total+count);
   }
   hash.TransformFinalBlock(new byte[0],0,0); Need((allowEmpty||total>0)&&reader.ReadInt64()==total);
   byte[] expected=reader.ReadBytes(32); Need(expected.Length==32);
   int different=0; for(int index=0;index<32;index++) different|=hash.Hash[index]^expected[index]; Need(different==0);
   file.Flush(true);
  }
 }
 static System.Collections.Generic.Dictionary<string,string> Resources(BinaryReader reader,string stage,System.Collections.Generic.List<string> owned) {
  int count=reader.ReadInt32(); Need(count>=0);
  var result=new System.Collections.Generic.Dictionary<string,string>(StringComparer.Ordinal);
  for(int index=0;index<count;index++) {
   string id=new UTF8Encoding(false,true).GetString(Blob(reader,36)); Guid parsed;
   Need(Guid.TryParseExact(id,"D",out parsed)&&parsed.ToString("D")==id);
   string extension=new UTF8Encoding(false,true).GetString(Blob(reader,5)); Need(extension==".json"||extension==".srs"||extension==".bin");
   string name="resource-"+id+extension,path=Path.Combine(stage,name); Need(!result.ContainsKey("vpn-control-resource:"+id));
   owned.Add(name); ConfigurationBlob(reader,path,true); result.Add("vpn-control-resource:"+id,path);
  }
  return result;
 }
 static bool ReadFileField(string key,string context,string type) {
  return (context.EndsWith("/tls",StringComparison.Ordinal)&&(key=="certificate_path"||key=="client_certificate_path"||key=="key_path"||key=="client_key_path")) ||
   (context.EndsWith("/tls/ech",StringComparison.Ordinal)&&(key=="key_path"||key=="config_path")) ||
   (context=="/certificate"&&key=="certificate_path") ||
   (context=="/dns/servers/*"&&type=="hosts"&&key=="path") ||
   (context=="/route/rule_set/*"&&type=="local"&&key=="path") ||
   (context=="/services/*"&&type=="derp"&&key=="mesh_psk_file") ||
   (context=="/outbounds/*"&&type=="ssh"&&key=="private_key_path");
 }
 static object ResourceValue(object value,System.Collections.Generic.Dictionary<string,string> resources) {
  var array=value as object[];
  if(array!=null) { var mapped=new object[array.Length]; for(int i=0;i<array.Length;i++) mapped[i]=ResourceValue(array[i],resources); return mapped; }
  string reference=value as string,path; Need(reference!=null&&resources!=null&&resources.TryGetValue(reference,out path));
  return resources[reference];
 }
 static void Config(object value,string context,string stage,System.Collections.Generic.Dictionary<string,string> resources) {
  var map=value as System.Collections.Generic.Dictionary<string,object>;
  if(map!=null) {
   object kind; string type=map.TryGetValue("type",out kind)?kind as string:null;
   bool url=(context=="/dns/servers/*"&&(type=="https"||type=="h3")) ||
    ((context=="/outbounds/*/transport"||context=="/inbounds/*/transport")&&(type=="ws"||type=="http"||type=="httpupgrade")) ||
    (context=="/outbounds/*"&&type=="http");
   bool cache=context=="/experimental/cache_file";
   if(cache) Need(map.Count==2&&map.ContainsKey("enabled")&&map["enabled"] is bool&&map.ContainsKey("path")&&Equals(map["path"],"cache.db"));
   foreach(string key in new System.Collections.Generic.List<string>(map.Keys)) {
    object child=map[key];
    if(ReadFileField(key,context,type)) { map[key]=ResourceValue(child,resources); continue; }
    Need(key!="output"&&key!="external_ui"&&key!="directory"&&!key.EndsWith("_directory",StringComparison.Ordinal)&&
     (key=="cache_file"||!key.EndsWith("_file",StringComparison.Ordinal))&&
     (key!="cache_file"||context=="/experimental")&&(key=="process_path"||key=="tcp_multi_path"||!key.EndsWith("_path",StringComparison.Ordinal)));
    if(key=="masquerade"&&child is string) Need(!((string)child).StartsWith("file:",StringComparison.OrdinalIgnoreCase));
    if(key=="path") {
     string path=child as string;
     Need(cache||(url&&path!=null));
    }
    Config(child,context+"/"+key,stage,resources);
   }
   // This destination is chosen only by the broker; no caller-selected privileged cache path survives.
   if(cache&&stage!=null) map["path"]=Path.Combine(stage,"cache.db");
  } else { var array=value as object[]; if(array!=null) foreach(var item in array) Config(item,context+"/*",stage,resources); }
 }
 public static string NormalizeConfiguration(string text,string stage) {
  return NormalizeConfiguration(text,stage,null);
 }
 static string NormalizeConfiguration(string text,string stage,System.Collections.Generic.Dictionary<string,string> resources) {
  // Parsing materializes the logical document. Native resource failure is distinct from invalid input.
  var parser=new System.Web.Script.Serialization.JavaScriptSerializer(); parser.MaxJsonLength=Int32.MaxValue;
  var root=parser.DeserializeObject(text); Need(root is System.Collections.Generic.Dictionary<string,object>);
  Config(root,"",stage,resources); return parser.Serialize(root);
 }
 static void CleanupStage(string stage,SafeFileHandle stagePin,System.Collections.Generic.List<string> resources) {
  // The retained private directory cannot be replaced while its exact known children are removed.
  // Never recursively erase unexpected content or follow a child reparse point.
  var names=new System.Collections.Generic.List<string>(new[]{"sing-box.exe","config.json","received.json","runtime.log","cache.db"}); names.AddRange(resources);
  var deadline=Stopwatch.StartNew();
  foreach(string name in names) {
   string path=Path.Combine(stage,name);
   while(File.Exists(path)) {
    if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0) return;
    try { File.Delete(path); break; }
    catch(Exception failure) {
     // Image scanning can retain a deny-delete reader briefly after the owned child exits.
     // Retry only this known child while the original private parent remains pinned.
     int error=failure.HResult&0xffff;
     if(!(failure is IOException || failure is UnauthorizedAccessException) ||
       (error!=5 && error!=32 && error!=33) || deadline.ElapsedMilliseconds>=5000) throw;
     Thread.Sleep(50);
    }
   }
  }
  if(Directory.GetFileSystemEntries(stage).Length!=0) return;
  stagePin.Dispose();
  Directory.Delete(stage); // Nonrecursive even if a privileged actor replaces this now-empty directory.
 }
 public static void Run(string pipeName,uint ownerPid,long ownerStart,string ownerSid,string expectedHash) {
  IntPtr owner=OpenProcess(0x101040,false,ownerPid); Need(owner!=IntPtr.Zero);
  IntPtr job=IntPtr.Zero,attributes=IntPtr.Zero,jobSlot=IntPtr.Zero,handles=IntPtr.Zero; bool jobAdmitted=false; PI child=new PI();
  var pins=new System.Collections.Generic.List<SafeFileHandle>(); string stage=null; SafeFileHandle stagePin=null;
  var resourceFiles=new System.Collections.Generic.List<string>();
  Thread watchdog=null; int watchdogDone=0;
  try {
   long c,e,k,u; Need(GetProcessTimes(owner,out c,out e,out k,out u)&&c==ownerStart);
   IntPtr token; Need(OpenProcessToken(owner,8,out token));
   try { using(var identity=new WindowsIdentity(token)) Need(identity.User.Value==ownerSid); } finally { CloseHandle(token); }
   // The retained OpenProcess handle and native FILETIME bind this exact process object.
   // Do not re-resolve its PID through a second, independently raced managed process lookup.
   var acl=new PipeSecurity(); acl.SetAccessRuleProtection(true,false);
   acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(ownerSid),PipeAccessRights.ReadWrite,AccessControlType.Allow));
   acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier("S-1-5-32-544"),PipeAccessRights.FullControl,AccessControlType.Allow));
   byte[] descriptor=acl.GetSecurityDescriptorBinaryForm(); var pinned=GCHandle.Alloc(descriptor,GCHandleType.Pinned); SafePipeHandle server;
   try { var security=new SA(); security.n=Marshal.SizeOf<SA>(); security.d=pinned.AddrOfPinnedObject();
    server=CreateNamedPipe("\\\\.\\pipe\\"+pipeName,0x40080003,8,1,65536,65536,0,ref security); Need(!server.IsInvalid);
   } finally { pinned.Free(); }
   using(var pipe=new NamedPipeServerStream(PipeDirection.InOut,true,false,server)) {
    var connection=pipe.BeginWaitForConnection(null,null); Need(connection.AsyncWaitHandle.WaitOne(180000)); pipe.EndWaitForConnection(connection);
    uint peer; Need(GetNamedPipeClientProcessId(pipe.SafePipeHandle,out peer)&&peer==ownerPid&&WaitForSingleObject(owner,0)==258);
    // Interrupt the protocol so normal finally disposal confirms child exit and cleans private input.
    // Environment.Exit bypasses finally and leaves every completed stage behind after owner death.
    watchdog=new Thread(()=>{ while(Volatile.Read(ref watchdogDone)==0) {
     if(WaitForSingleObject(owner,250)==0) { try { pipe.Dispose(); } catch { } return; }
    }}); watchdog.IsBackground=true; watchdog.Start();
    using(var reader=new BinaryReader(pipe,Encoding.UTF8,true)) using(var writer=new BinaryWriter(pipe,Encoding.UTF8,true)) {
     try {
     Need(reader.ReadInt32()==4);
     // Duplicate only authority the authenticated ordinary owner already retained before UAC.
     // A fresh anonymous job pins every possible child even if its creation acknowledgment is lost.
     Need(DuplicateHandle(owner,new IntPtr(reader.ReadInt64()),GetCurrentProcess(),out job,0,false,2));
     var limits=new LIMIT(); var accounting=new ACCOUNTING();
     Need(QueryJobLimits(job,9,ref limits,Marshal.SizeOf<LIMIT>(),IntPtr.Zero)&&limits.flags==0x2008&&limits.active==1);
     Need(QueryJobAccounting(job,1,ref accounting,Marshal.SizeOf<ACCOUNTING>(),IntPtr.Zero)&&accounting.total==0&&accounting.active==0);
     jobAdmitted=true;
     byte[] image=Blob(reader,192*1024*1024);
     using(var sha=SHA256.Create()) Need(BitConverter.ToString(sha.ComputeHash(image)).Replace("-","").ToLowerInvariant()==expectedHash);
     string root=Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
     var ancestors=new System.Collections.Generic.Stack<string>(); for(var d=new DirectoryInfo(root);d!=null;d=d.Parent) ancestors.Push(d.FullName);
     foreach(var ancestor in ancestors) pins.Add(Pin(ancestor,false,pins));
     stage=Path.Combine(root,"vpn-control-vpn-"+Guid.NewGuid().ToString("D")); Need(!Directory.Exists(stage)&&!File.Exists(stage));
     var protection=new DirectorySecurity(); protection.SetAccessRuleProtection(true,false); protection.SetOwner(new SecurityIdentifier("S-1-5-32-544"));
     foreach(var sid in new[]{"S-1-5-18","S-1-5-32-544"}) protection.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid),FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
     CreatePrivateDirectory(stage,protection); stagePin=Pin(stage,true,pins); pins.Add(stagePin);
     string executable=Path.Combine(stage,"sing-box.exe"),configuration=Path.Combine(stage,"config.json"),log=Path.Combine(stage,"runtime.log");
     using(var f=new FileStream(executable,FileMode.CreateNew,FileAccess.Write,FileShare.None)) f.Write(image,0,image.Length);
     string received=Path.Combine(stage,"received.json"); ConfigurationBlob(reader,received);
     var resources=Resources(reader,stage,resourceFiles);
     string normalized=NormalizeConfiguration(File.ReadAllText(received,new UTF8Encoding(false,true)),stage,resources);
     using(var f=new StreamWriter(new FileStream(configuration,FileMode.CreateNew,FileAccess.Write,FileShare.None),new UTF8Encoding(false,true))) f.Write(normalized);
     normalized=null; File.Delete(received);
     using(var output=new FileStream(log,FileMode.CreateNew,FileAccess.ReadWrite,FileShare.ReadWrite))
     using(var input=new FileStream(configuration,FileMode.Open,FileAccess.Read,FileShare.Read)) {
      IntPtr outHandle=output.SafeFileHandle.DangerousGetHandle(),inHandle=input.SafeFileHandle.DangerousGetHandle();
      Need(SetHandleInformation(outHandle,1,1)&&SetHandleInformation(inHandle,1,1));
      IntPtr size=IntPtr.Zero; InitializeProcThreadAttributeList(IntPtr.Zero,2,0,ref size); attributes=Marshal.AllocHGlobal(size);
      Need(InitializeProcThreadAttributeList(attributes,2,0,ref size)); jobSlot=Marshal.AllocHGlobal(IntPtr.Size); Marshal.WriteIntPtr(jobSlot,job);
      handles=Marshal.AllocHGlobal(IntPtr.Size*2); Marshal.WriteIntPtr(handles,0,inHandle); Marshal.WriteIntPtr(handles,IntPtr.Size,outHandle);
      Need(UpdateProcThreadAttribute(attributes,0,new IntPtr(0x2000d),jobSlot,new IntPtr(IntPtr.Size),IntPtr.Zero,IntPtr.Zero));
      Need(UpdateProcThreadAttribute(attributes,0,new IntPtr(0x20002),handles,new IntPtr(IntPtr.Size*2),IntPtr.Zero,IntPtr.Zero));
      AllocConsole(); var start=new SX(); start.si.cb=Marshal.SizeOf<SX>(); start.si.flags=0x100; start.si.input=inHandle; start.si.output=start.si.error=outHandle; start.attributes=attributes;
      string windows=Environment.GetFolderPath(Environment.SpecialFolder.Windows);
      IntPtr environment=Marshal.StringToHGlobalUni("PATH="+Path.Combine(windows,"System32")+"\0SystemRoot="+windows+"\0TEMP="+stage+"\0TMP="+stage+"\0\0");
      try { Need(CreateProcess(executable,new StringBuilder("\""+executable+"\" run -c stdin"),IntPtr.Zero,IntPtr.Zero,true,0x80000|0x200|0x400|4,environment,stage,ref start,out child)); }
      finally { Marshal.FreeHGlobal(environment); }
      // The original owner already retains this exact job; no undiscoverable duplicated child
      // handle leaks if the acknowledgment is lost. Only COMMIT executes the suspended child.
      writer.Write((byte)0); writer.Write(child.pid); writer.Flush();
      Need(reader.ReadByte()==3); Need(ResumeThread(child.thread)==1); writer.Write((byte)0); writer.Flush(); long offset=0;
      while(true) {
       int command=reader.ReadByte(); Need(command==0||command==1||command==2);
       if(command!=0) {
        if(command==1) GenerateConsoleCtrlEvent(1,(uint)child.pid);
        if(command==2||WaitForSingleObject(child.process,5000)!=0) Need(TerminateJobObject(job,1));
       }
       bool alive=WaitForSingleObject(child.process,0)!=0; byte[] recent;
       using(var logs=new FileStream(log,FileMode.Open,FileAccess.Read,FileShare.ReadWrite)) {
        logs.Position=offset; recent=new byte[(int)Math.Min(65536,Math.Max(0,logs.Length-offset))]; int read=logs.Read(recent,0,recent.Length); offset+=read; Array.Resize(ref recent,read);
       }
       writer.Write(alive); writer.Write(recent.Length); writer.Write(recent); writer.Flush();
       if(!alive) break;
      }
     }
     } catch(Exception failure) { ReportFailure(writer,failure); throw; }
    }
   }
  } finally {
   Volatile.Write(ref watchdogDone,1);
   bool watchdogExited=watchdog==null || watchdog.Join(1000);
   if(job!=IntPtr.Zero) { if(jobAdmitted) TerminateJobObject(job,1); CloseHandle(job); }
   bool childExited=child.process==IntPtr.Zero || WaitForSingleObject(child.process,10000)==0;
   if(child.process!=IntPtr.Zero) CloseHandle(child.process);
   if(child.thread!=IntPtr.Zero) CloseHandle(child.thread);
   if(attributes!=IntPtr.Zero) { DeleteProcThreadAttributeList(attributes); Marshal.FreeHGlobal(attributes); }
   if(jobSlot!=IntPtr.Zero) Marshal.FreeHGlobal(jobSlot); if(handles!=IntPtr.Zero) Marshal.FreeHGlobal(handles);
   // Retain an uncertain child's inputs. Confirmed terminal inputs have no recovery purpose.
   if(childExited && stage!=null && stagePin!=null) { try { CleanupStage(stage,stagePin,resourceFiles); } catch { } }
   for(int i=pins.Count-1;i>=0;i--) pins[i].Dispose();
   if(watchdogExited) CloseHandle(owner); // Do not close a native handle while another thread waits on it.
  }
 }
}

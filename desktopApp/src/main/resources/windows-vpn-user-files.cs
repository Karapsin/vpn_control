// Mutable runtime bytes are published with the captured owner's token, never the helper's token.
// The broker must retain its private source and journal until publication is authoritative.
namespace VpnScopedStorage {
 using System;
 using System.IO;
 using System.Text;
 using System.Collections.Generic;
 using System.Runtime.InteropServices;
 using System.Security.Principal;
 using System.Security.Cryptography;
 using Microsoft.Win32.SafeHandles;

 public sealed class Destination {
  public readonly string Path,ParentIdentity;
  public Destination(string path,string parentIdentity) { Path=path; ParentIdentity=parentIdentity; }
  public override string ToString() { return "Runtime resource destination (<redacted>)"; }
 }
 public sealed class Target {
  public readonly string Path,ParentIdentity,FileIdentity,Sha256;
  public readonly long ByteCount;
  public Target(string path,string parentIdentity,string fileIdentity,long byteCount,string sha256) {
   Path=path; ParentIdentity=parentIdentity; FileIdentity=fileIdentity;
   ByteCount=byteCount; Sha256=sha256;
  }
  public override string ToString() { return "Runtime resource (<redacted>)"; }
 }
 public sealed class Publication {
  public readonly string Phase,TemporaryName,TemporaryIdentity,BackupName,OriginalIdentity,Sha256;
  public readonly long ByteCount;
  public Publication(string phase,string temporaryName,string temporaryIdentity,string backupName,string originalIdentity,long byteCount,string sha256) {
   Phase=phase; TemporaryName=temporaryName; TemporaryIdentity=temporaryIdentity;
   BackupName=backupName; OriginalIdentity=originalIdentity;
   ByteCount=byteCount; Sha256=sha256;
  }
  public override string ToString() { return "Runtime resource publication (<redacted>)"; }
 }
 public sealed class OwnerIdentity {
  public readonly long ProcessId,CreationFileTime;
  public readonly string Sid;
  public OwnerIdentity(long pid,long creation,string sid) {
   if(pid<1||pid>UInt32.MaxValue||creation<=0||new SecurityIdentifier(sid).Value!=sid) throw new IOException("INVALID_ARGUMENT");
   ProcessId=pid; CreationFileTime=creation; Sid=sid;
  }
  public override string ToString() { return "Original native owner (<redacted>)"; }
 }
 public sealed class OriginalUser : IDisposable {
  [StructLayout(LayoutKind.Sequential)] struct INFO {
   public uint attributes,createdLow,createdHigh,accessedLow,accessedHigh,writtenLow,writtenHigh;
   public uint volume,sizeHigh,sizeLow,links,indexHigh,indexLow;
  }
  [StructLayout(LayoutKind.Sequential)] struct SECURITY { public int size; public IntPtr descriptor; public int inherit; }
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool DuplicateTokenEx(IntPtr token,uint access,IntPtr security,int level,int type,out IntPtr copy);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string value,uint revision,out IntPtr descriptor,IntPtr length);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("advapi32.dll",SetLastError=true)] static extern uint GetSecurityInfo(SafeFileHandle file,int kind,uint requested,out IntPtr owner,IntPtr group,out IntPtr dacl,IntPtr sacl,out IntPtr descriptor);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle file,out INFO info);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandle(SafeFileHandle file,StringBuilder path,uint length,uint flags);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle file,int kind,IntPtr value,uint length);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("ntdll.dll")] static extern int NtSetInformationFile(SafeFileHandle file,IntPtr status,IntPtr value,uint length,int kind);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll")] static extern uint GetFileType(SafeFileHandle file);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool GetVolumeInformationByHandleW(SafeFileHandle file,IntPtr name,uint nameSize,IntPtr serial,IntPtr maximum,out uint flags,IntPtr fileSystem,uint fileSystemSize);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll")] static extern uint GetProcessId(IntPtr process);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll")] static extern bool GetProcessTimes(IntPtr process,out long created,out long exited,out long kernel,out long user);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr handle);
  readonly string sid;
  public readonly OwnerIdentity Owner;
  IntPtr token;
  public OriginalUser(IntPtr admittedOwner,string expectedSid) {
   sid=new SecurityIdentifier(expectedSid).Value;
   long created,exited,kernel,user; Need(GetProcessTimes(admittedOwner,out created,out exited,out kernel,out user),"PERMISSION_DENIED");
   Owner=new OwnerIdentity(GetProcessId(admittedOwner),created,sid);
   IntPtr original; Need(OpenProcessToken(admittedOwner,10,out original),"PERMISSION_DENIED");
   try {
    using(var identity=new WindowsIdentity(original)) Need(identity.User.Value==sid,"PERMISSION_DENIED");
    Need(DuplicateTokenEx(original,14,IntPtr.Zero,2,2,out token),"PERMISSION_DENIED");
   } finally { CloseHandle(original); }
  }
  public T Run<T>(Func<T> action) {
   Need(token!=IntPtr.Zero,"OUTCOME_UNKNOWN");
   // WindowsIdentity retains a duplicate of our admitted token. RunImpersonated restores the
   // previous identity even on failure and does not borrow the approving administrator's token.
   using(var retained=new WindowsIdentity(token)) {
    return WindowsIdentity.RunImpersonated(retained.AccessToken,()=>{
     using(var identity=WindowsIdentity.GetCurrent(true))
      Need(identity!=null&&identity.User.Value==sid,"PERMISSION_DENIED");
     return action();
    });
   }
  }
  static void Need(bool value,string code) { if(!value) throw new IOException(code); }
  static string Canonical(string path) {
   Need(!String.IsNullOrEmpty(path)&&System.IO.Path.IsPathRooted(path),"INVALID_ARGUMENT");
   return System.IO.Path.GetFullPath(path);
  }
  static INFO Inspect(SafeFileHandle file,bool directory) {
   INFO info=new INFO(); Need(GetFileType(file)==1&&GetFileInformationByHandle(file,out info),"UNAVAILABLE");
   Need((info.attributes&0x400)==0&&((info.attributes&16)!=0)==directory,"CONFLICT");
   Need(directory||info.links==1,"UNSUPPORTED"); return info;
  }
  static string Identity(INFO info) { return info.volume.ToString("x8")+info.indexHigh.ToString("x8")+info.indexLow.ToString("x8"); }
  static Target Snapshot(string path,string parentIdentity,SafeFileHandle file) {
   if(file==null) return new Target(path,parentIdentity,null,0,null);
   var info=Inspect(file,false);
   // Borrow the already admitted handle while preserving its ownership and file position.
   using(var borrowed=new SafeFileHandle(file.DangerousGetHandle(),false))
   using(var input=new FileStream(borrowed,FileAccess.Read,65536,false)) using(var digest=SHA256.Create()) {
    input.Position=0; byte[] hash=digest.ComputeHash(input); long bytes=input.Position; input.Position=0;
    Need(bytes==((long)info.sizeHigh<<32|info.sizeLow),"CONFLICT");
    return new Target(path,parentIdentity,Identity(info),bytes,BitConverter.ToString(hash).Replace("-","").ToLowerInvariant());
   }
  }
  static string Final(SafeFileHandle file) {
   var path=new StringBuilder(32768); uint size=GetFinalPathNameByHandle(file,path,32768,0);
   Need(size>0&&size<32768,"UNAVAILABLE"); string value=path.ToString();
   if(value.StartsWith("\\\\?\\UNC\\",StringComparison.OrdinalIgnoreCase)) return "\\\\"+value.Substring(8);
   return value.StartsWith("\\\\?\\",StringComparison.Ordinal)?value.Substring(4):value;
  }
  static SafeFileHandle Open(string path,uint access,uint share,bool allowMissing=false) {
   var file=CreateFile(path,access,share,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
   if(file.IsInvalid) {
    int error=Marshal.GetLastWin32Error(); file.Dispose();
    if(allowMissing&&error==2) return null;
    throw new IOException(error==5?"PERMISSION_DENIED":error==32?"BUSY":"UNAVAILABLE");
   }
   try { Need(String.Equals(Final(file),path,StringComparison.OrdinalIgnoreCase),"CONFLICT"); return file; }
   catch { file.Dispose(); throw; }
  }
  sealed class Parents : IDisposable {
   public readonly List<SafeFileHandle> Handles=new List<SafeFileHandle>();
   public void Dispose() { for(int i=Handles.Count-1;i>=0;i--) Handles[i].Dispose(); }
  }
  static Parents PinParents(string parent,string expected=null) {
   var pins=new Parents(); var paths=new Stack<string>();
   for(var directory=new DirectoryInfo(parent);directory!=null;directory=directory.Parent) paths.Push(directory.FullName);
   try {
    foreach(string path in paths) {
     // Listing access plus deny-write/delete sharing pins both rename and reparse mutation.
     var file=Open(path,0x81,1); pins.Handles.Add(file); Inspect(file,true);
    }
    Need(expected==null||Identity(Inspect(pins.Handles[pins.Handles.Count-1],true))==expected,"CONFLICT");
    return pins;
   } catch { pins.Dispose(); throw; }
  }
  public Destination AdmitDestination(string requested) { return Run(()=>{
   string path=Canonical(requested),parent=System.IO.Path.GetDirectoryName(path);
   using(var pins=PinParents(parent)) {
    return new Destination(path,Identity(Inspect(pins.Handles[pins.Handles.Count-1],true)));
   }
  }); }
  // Mutable inputs bind their current file only at commit, after the previous owned runtime has
  // stopped and published its latest bytes. Authorization never permits a different parent.
  public Target CaptureCurrent(Destination admitted) { return Run(()=>{
   Need(admitted!=null&&Canonical(admitted.Path)==admitted.Path&&
    System.Text.RegularExpressions.Regex.IsMatch(admitted.ParentIdentity??"","\\A[a-f0-9]{24}\\z"),"INVALID_ARGUMENT");
   using(var pins=PinParents(System.IO.Path.GetDirectoryName(admitted.Path),admitted.ParentIdentity))
   using(var file=Open(admitted.Path,0x80000000,1,true)) {
    return Snapshot(admitted.Path,admitted.ParentIdentity,file);
   }
  }); }
  public Target Capture(string requested) { return CaptureCurrent(AdmitDestination(requested)); }
  void RequirePrivate(SafeFileHandle file) {
   uint flags; Need(GetVolumeInformationByHandleW(file,IntPtr.Zero,0,IntPtr.Zero,IntPtr.Zero,out flags,IntPtr.Zero,0)&&
    (flags&8)!=0,"PERMISSION_DENIED");
   IntPtr owner,dacl,descriptor;
   Need(GetSecurityInfo(file,1,5,out owner,IntPtr.Zero,out dacl,IntPtr.Zero,out descriptor)==0,"PERMISSION_DENIED");
   try {
    uint size=GetSecurityDescriptorLength(descriptor); Need(size>0&&size<=65536,"PERMISSION_DENIED");
    byte[] bytes=new byte[size]; Marshal.Copy(descriptor,bytes,0,bytes.Length);
    var security=new System.Security.AccessControl.RawSecurityDescriptor(bytes,0);
    Need(security.Owner!=null&&security.Owner.Value==sid&&security.DiscretionaryAcl!=null,"PERMISSION_DENIED");
    foreach(System.Security.AccessControl.GenericAce entry in security.DiscretionaryAcl) {
     var ace=entry as System.Security.AccessControl.CommonAce; Need(ace!=null&&!ace.IsCallback,"PERMISSION_DENIED");
     if(ace.AceQualifier==System.Security.AccessControl.AceQualifier.AccessDenied||
      (ace.AceFlags&System.Security.AccessControl.AceFlags.InheritOnly)!=0) continue;
     Need(ace.AceQualifier==System.Security.AccessControl.AceQualifier.AccessAllowed&&
      (ace.SecurityIdentifier.Value==sid||ace.AccessMask==0),"PERMISSION_DENIED");
    }
   } finally { LocalFree(descriptor); }
  }
  public void ValidateScope(Target record,string scopeId) {
   PublicationJournal.ValidateTarget(record); Guid parsed;
   Need(Guid.TryParseExact(scopeId,"D",out parsed)&&parsed.ToString("D")==scopeId,"INVALID_ARGUMENT");
   byte[] expected=Encoding.UTF8.GetBytes("{\"schemaVersion\":1,\"scopeId\":\""+scopeId+"\"}");
   Run(()=>{
    Need(record.FileIdentity!=null&&record.ByteCount==expected.Length,"CONFLICT");
    using(var pins=PinParents(System.IO.Path.GetDirectoryName(record.Path),record.ParentIdentity))
    using(var file=Match(record,0x80020000)) {
     RequirePrivate(file);
     using(var borrowed=new SafeFileHandle(file.DangerousGetHandle(),false))
     using(var input=new FileStream(borrowed,FileAccess.Read,65536,false)) {
      byte[] bytes=new byte[expected.Length+1]; int count=0,read;
      while(count<bytes.Length&&(read=input.Read(bytes,count,bytes.Length-count))>0) count+=read;
      Need(count==expected.Length,"CONFLICT");
      for(int index=0;index<count;index++) Need(bytes[index]==expected[index],"CONFLICT");
     }
    }
    return true;
   });
  }
  static SafeFileHandle Match(Target target,uint access) {
   var file=Open(target.Path,access,1,true);
   try {
    Need((file==null?null:Identity(Inspect(file,false)))==target.FileIdentity,"CONFLICT");
    var current=Snapshot(target.Path,target.ParentIdentity,file);
    Need(current.ByteCount==target.ByteCount&&current.Sha256==target.Sha256,"CONFLICT");
    return file;
   } catch { if(file!=null) file.Dispose(); throw; }
  }
  public bool CopyInput(Target target,Stream destination) { return Run(()=>{
   using(var pins=PinParents(System.IO.Path.GetDirectoryName(target.Path),target.ParentIdentity))
   using(var file=Match(target,0x80000000)) {
    if(file==null) return false;
    using(var input=new FileStream(file,FileAccess.Read,65536,false)) input.CopyTo(destination,65536);
    return true;
   }
  }); }
  SafeFileHandle CreatePrivate(string path) {
   IntPtr descriptor; Need(ConvertStringSecurityDescriptorToSecurityDescriptor("O:"+sid+"D:P(A;;FA;;;"+sid+")",1,out descriptor,IntPtr.Zero),"PERMISSION_DENIED");
   IntPtr address=Marshal.AllocHGlobal(Marshal.SizeOf<SECURITY>());
   try {
    var security=new SECURITY(); security.size=Marshal.SizeOf<SECURITY>(); security.descriptor=descriptor;
    Marshal.StructureToPtr(security,address,false);
    var file=CreateFile(path,0xc0010000,1,address,1,0x80200000,IntPtr.Zero);
    if(file.IsInvalid) { file.Dispose(); throw new IOException("PERSISTENCE_FAILED"); }
    return file;
   } finally { Marshal.FreeHGlobal(address); LocalFree(descriptor); }
  }
  static void Rename(SafeFileHandle file,string destination) {
   Need(IntPtr.Size==8,"UNSUPPORTED"); string leaf=System.IO.Path.GetFileName(destination);
   Need(leaf.Length>0&&leaf!="."&&leaf!=".."&&leaf.IndexOfAny(new[]{'\\','/',':','\0'})<0,"INVALID_ARGUMENT");
   Need(String.Equals(System.IO.Path.GetDirectoryName(Final(file)),System.IO.Path.GetDirectoryName(destination),StringComparison.OrdinalIgnoreCase),"CONFLICT");
   byte[] name=Encoding.Unicode.GetBytes(leaf);
   int length=20+name.Length; IntPtr value=Marshal.AllocHGlobal(length),status=Marshal.AllocHGlobal(16);
   try {
    for(int index=0;index<20;index++) Marshal.WriteByte(value,index,0);
    for(int index=0;index<16;index++) Marshal.WriteByte(status,index,0);
    Marshal.WriteInt32(value,16,name.Length); Marshal.Copy(name,0,IntPtr.Add(value,20),name.Length);
    // NT's sibling form uses the source's retained parent. A Win32 full-path rename reopens that
    // parent for write access and conflicts with the pins that prevent reparse/rename races.
    // ReplaceIfExists remains false, preserving any destination introduced after admission.
    Need(NtSetInformationFile(file,status,value,(uint)length,10)==0,"PERSISTENCE_FAILED");
   } finally { Marshal.FreeHGlobal(status); Marshal.FreeHGlobal(value); }
  }
  static void Delete(SafeFileHandle file) {
   IntPtr value=Marshal.AllocHGlobal(4);
   try { Marshal.WriteInt32(value,1); Need(SetFileInformationByHandle(file,4,value,4),"PERSISTENCE_FAILED"); }
   finally { Marshal.FreeHGlobal(value); }
  }
  internal static void ValidatePublication(Target target,Publication checkpoint) {
   string prefix=".vpn-control-resource-";
   Need(checkpoint!=null&&checkpoint.TemporaryName!=null&&checkpoint.TemporaryName.StartsWith(prefix,StringComparison.Ordinal)&&
    checkpoint.TemporaryName.EndsWith(".tmp",StringComparison.Ordinal),"INVALID_ARGUMENT");
   string id=checkpoint.TemporaryName.Substring(prefix.Length,checkpoint.TemporaryName.Length-prefix.Length-4); Guid parsed;
   Need(Guid.TryParseExact(id,"D",out parsed)&&parsed.ToString("D")==id&&checkpoint.BackupName==prefix+id+".backup","INVALID_ARGUMENT");
   Need(checkpoint.OriginalIdentity==target.FileIdentity&&checkpoint.ByteCount>=0&&
    System.Text.RegularExpressions.Regex.IsMatch(checkpoint.TemporaryIdentity??"","\\A[a-f0-9]{24}\\z")&&
    System.Text.RegularExpressions.Regex.IsMatch(checkpoint.Sha256??"","\\A[a-f0-9]{64}\\z"),"INVALID_ARGUMENT");
   Need(checkpoint.Phase=="PREPARED"||checkpoint.Phase=="ORIGINAL_MOVING"||checkpoint.Phase=="ORIGINAL_MOVED"||
    checkpoint.Phase=="PUBLISHING"||checkpoint.Phase=="PUBLISHED","INVALID_ARGUMENT");
  }
  /** Read-only reconciliation of the protected write-ahead journal; never repeats a publication. */
  public bool PublicationCommitted(Target target,Publication checkpoint) { return Run(()=>{
   ValidatePublication(target,checkpoint);
   // This protected checkpoint was emitted only after the native no-replace rename succeeded.
   // Later user deletion or modification cannot erase that already established history.
   if(checkpoint.Phase=="PUBLISHED") return true;
   using(var pins=PinParents(System.IO.Path.GetDirectoryName(target.Path),target.ParentIdentity))
   using(var file=Open(target.Path,0x80000000,1,true)) {
    if(file!=null&&Identity(Inspect(file,false))==checkpoint.TemporaryIdentity) {
     var current=Snapshot(target.Path,target.ParentIdentity,file);
     Need(current.ByteCount==checkpoint.ByteCount&&current.Sha256==checkpoint.Sha256,"OUTCOME_UNKNOWN");
     return true;
    }
    // A response lost around rename has no safe negative inference from an absent/foreign target.
    // Keep its source and journal; callers must not treat uncertainty as permission to overwrite.
    Need(checkpoint.Phase!="PUBLISHING","OUTCOME_UNKNOWN");
    return false;
   }
  }); }
  /** Disposal follows established publication and touches only the exact journal-owned siblings. */
  public void CleanupCommitted(Target target,Publication checkpoint) {
   Need(PublicationCommitted(target,checkpoint),"CONFLICT");
   Run(()=>{
    string parent=System.IO.Path.GetDirectoryName(target.Path);
    using(var pins=PinParents(parent,target.ParentIdentity)) {
     string backup=System.IO.Path.Combine(parent,checkpoint.BackupName);
     using(var original=Open(backup,0x80010000,1,true)) {
      if(original!=null) {
       var observed=Snapshot(backup,target.ParentIdentity,original);
       Need(target.FileIdentity!=null&&observed.FileIdentity==target.FileIdentity&&
        observed.ByteCount==target.ByteCount&&observed.Sha256==target.Sha256,"CONFLICT");
       Delete(original);
      }
     }
     string temporary=System.IO.Path.Combine(parent,checkpoint.TemporaryName);
     using(var file=Open(temporary,0x80010000,1,true)) {
      if(file!=null) {
       var observed=Snapshot(temporary,target.ParentIdentity,file);
       Need(observed.FileIdentity==checkpoint.TemporaryIdentity&&observed.ByteCount==checkpoint.ByteCount&&
        observed.Sha256==checkpoint.Sha256,"CONFLICT");
       Delete(file);
      }
     }
    }
    return true;
   });
  }
  public Target Publish(Target target,Stream retainedSource,Action<Publication> checkpoint) { return Run(()=>{
   string parent=System.IO.Path.GetDirectoryName(target.Path),id=Guid.NewGuid().ToString("D");
   string temporaryName=".vpn-control-resource-"+id+".tmp",backupName=".vpn-control-resource-"+id+".backup";
   using(var pins=PinParents(parent,target.ParentIdentity)) using(var original=Match(target,0xc0010000))
   using(var temporary=CreatePrivate(System.IO.Path.Combine(parent,temporaryName))) {
    string next=Identity(Inspect(temporary,false));
    // The journal callback writes through a previously admitted private handle; it must not open
    // privileged paths while this thread deliberately retains the original user's token.
    using(var output=new FileStream(temporary,FileAccess.ReadWrite,65536,false)) {
     retainedSource.CopyTo(output,65536); output.Flush(true);
     var committed=Snapshot(target.Path,target.ParentIdentity,temporary);
     Action<string> record=phase=>checkpoint(new Publication(phase,temporaryName,next,backupName,target.FileIdentity,committed.ByteCount,committed.Sha256));
     record("PREPARED");
     if(original!=null) { record("ORIGINAL_MOVING"); Rename(original,System.IO.Path.Combine(parent,backupName)); record("ORIGINAL_MOVED"); }
     record("PUBLISHING"); Rename(temporary,target.Path); record("PUBLISHED");
     if(original!=null) Delete(original);
     return committed;
    }
   }
  }); }
  public void Dispose() { if(token!=IntPtr.Zero) { Need(CloseHandle(token),"OUTCOME_UNKNOWN"); token=IntPtr.Zero; } }
 }

 /** One publication's protected write-ahead record. It never opens paths or starts work on recovery.
  * The caller retains the admitted private handle and the source bytes until explicit reconciliation.
  */
 public sealed class PublicationJournal {
  const int MaximumFrame=393216; // Fixed metadata: two Windows paths, native identities and digests.
  readonly FileStream storage;
  readonly string jobId,resourceId,scopeId,controllerId;
  readonly OwnerIdentity nativeOwner;
  readonly Target scopeRecord;
  byte[] chain=new byte[32];
  bool writing,failed;
  public Target Target { get; private set; }
  public Publication Last { get; private set; }
  public bool IncompleteTail { get; private set; }
  public override string ToString() { return "Runtime publication journal (<redacted>)"; }
  PublicationJournal(FileStream admitted,string job,string resource,OwnerIdentity owner,string scope,string controller,Target proof) {
   Need(admitted!=null&&admitted.CanRead&&admitted.CanSeek,"INVALID_ARGUMENT");
   Uuid(job); Uuid(resource); Uuid(scope); Uuid(controller); Need(owner!=null,"INVALID_ARGUMENT");
   ValidateTarget(proof); Need(proof.FileIdentity!=null,"INVALID_ARGUMENT");
   storage=admitted; jobId=job; resourceId=resource; nativeOwner=owner; scopeId=scope; controllerId=controller; scopeRecord=proof;
  }
  static void Need(bool value,string code) { if(!value) throw new IOException(code); }
  static void Uuid(string value) { Guid parsed; Need(Guid.TryParseExact(value,"D",out parsed)&&parsed.ToString("D")==value,"INVALID_ARGUMENT"); }
  static bool Hex(string value,int digits) { return System.Text.RegularExpressions.Regex.IsMatch(value??"","\\A[a-f0-9]{"+digits+"}\\z"); }
  internal static void ValidateTarget(Target target) {
   Need(target!=null&&!String.IsNullOrEmpty(target.Path)&&target.Path.Length<=32767&&
    Path.IsPathRooted(target.Path)&&Path.GetFullPath(target.Path)==target.Path&&
    Hex(target.ParentIdentity,24)&&target.ByteCount>=0,"INVALID_ARGUMENT");
   Need(target.FileIdentity==null ? target.ByteCount==0&&target.Sha256==null :
    Hex(target.FileIdentity,24)&&Hex(target.Sha256,64),"INVALID_ARGUMENT");
  }
  internal static void Text(BinaryWriter writer,string value) {
   if(value==null) { writer.Write(-1); return; }
   byte[] bytes=new UTF8Encoding(false,true).GetBytes(value); writer.Write(bytes.Length); writer.Write(bytes);
  }
  internal static string Text(BinaryReader reader,int maximum,bool nullable=false) {
   int length=reader.ReadInt32(); if(length==-1&&nullable) return null;
   Need(length>=0&&length<=maximum,"OUTCOME_UNKNOWN");
   byte[] bytes=reader.ReadBytes(length); Need(bytes.Length==length,"OUTCOME_UNKNOWN");
   return new UTF8Encoding(false,true).GetString(bytes);
  }
  static byte[] Digest(byte[] previous,byte[] payload) {
   using(var hash=SHA256.Create()) {
    hash.TransformBlock(previous,0,previous.Length,null,0); hash.TransformFinalBlock(payload,0,payload.Length); return hash.Hash;
   }
  }
  static bool Equal(byte[] left,byte[] right) {
   if(left.Length!=right.Length) return false; int mismatch=0;
   for(int index=0;index<left.Length;index++) mismatch|=left[index]^right[index]; return mismatch==0;
  }
  internal static void WriteTarget(BinaryWriter writer,Target target) {
   Text(writer,target.Path); Text(writer,target.ParentIdentity); Text(writer,target.FileIdentity);
   writer.Write(target.ByteCount); Text(writer,target.Sha256);
  }
  internal static Target ReadTarget(BinaryReader reader) {
   var target=new Target(Text(reader,131068),Text(reader,24),Text(reader,24,true),reader.ReadInt64(),Text(reader,64,true));
   ValidateTarget(target); return target;
  }
  static bool SameTarget(Target first,Target second) {
   return String.Equals(first.Path,second.Path,StringComparison.OrdinalIgnoreCase)&&first.ParentIdentity==second.ParentIdentity&&
    first.FileIdentity==second.FileIdentity&&first.ByteCount==second.ByteCount&&first.Sha256==second.Sha256;
  }
  void Append(Action<BinaryWriter> record) {
   Need(writing&&!failed&&!IncompleteTail&&storage.CanWrite,"CONFLICT");
   byte[] payload;
   using(var bytes=new MemoryStream()) {
    using(var writer=new BinaryWriter(bytes,new UTF8Encoding(false,true),true)) record(writer);
    Need(bytes.Length>0&&bytes.Length<=MaximumFrame,"INVALID_ARGUMENT"); payload=bytes.ToArray();
   }
   byte[] digest=Digest(chain,payload);
   try {
    storage.Position=storage.Length;
    using(var writer=new BinaryWriter(storage,new UTF8Encoding(false,true),true)) {
     writer.Write(payload.Length); writer.Write(payload); writer.Write(digest); writer.Flush();
    }
    storage.Flush(true); chain=digest;
   } catch { failed=true; throw new IOException("PERSISTENCE_FAILED"); }
  }
  public static PublicationJournal Create(FileStream admitted,string job,string resource,OwnerIdentity owner,string scope,string controller,Target proof,Target target) {
   ValidateTarget(target); var journal=new PublicationJournal(admitted,job,resource,owner,scope,controller,proof);
   Need(admitted.Length==0&&admitted.CanWrite,"CONFLICT"); journal.writing=true; journal.Target=target;
   journal.Append(writer=>{
    writer.Write((byte)1); writer.Write(3); Text(writer,job); Text(writer,resource);
    Text(writer,owner.Sid); writer.Write(owner.ProcessId); writer.Write(owner.CreationFileTime); Text(writer,scope); Text(writer,controller);
    WriteTarget(writer,proof); WriteTarget(writer,target);
   });
   return journal;
  }
  static bool SamePublication(Publication first,Publication next) {
   return first.TemporaryName==next.TemporaryName&&first.TemporaryIdentity==next.TemporaryIdentity&&
    first.BackupName==next.BackupName&&first.OriginalIdentity==next.OriginalIdentity&&
    first.ByteCount==next.ByteCount&&first.Sha256==next.Sha256;
  }
  void ValidateNext(Publication next) {
   OriginalUser.ValidatePublication(Target,next);
   string expected=Last==null?"PREPARED":Last.Phase=="PREPARED"?
    (Target.FileIdentity==null?"PUBLISHING":"ORIGINAL_MOVING"):
    Last.Phase=="ORIGINAL_MOVING"?"ORIGINAL_MOVED":Last.Phase=="ORIGINAL_MOVED"?"PUBLISHING":
    Last.Phase=="PUBLISHING"?"PUBLISHED":null;
   Need(next.Phase==expected&&(Last==null||SamePublication(Last,next)),"CONFLICT");
  }
  public void Record(Publication next) {
   ValidateNext(next);
   Append(writer=>{
    writer.Write((byte)2); Text(writer,next.Phase); Text(writer,next.TemporaryName); Text(writer,next.TemporaryIdentity);
    Text(writer,next.BackupName); Text(writer,next.OriginalIdentity); writer.Write(next.ByteCount); Text(writer,next.Sha256);
   });
   Last=next;
  }
  // Opening is always read-only. A torn tail preserves the last validated evidence, never authority
  // to repeat the rename or truncate a record that might describe an already completed publication.
  public static PublicationJournal Open(FileStream admitted,string job,string resource,OwnerIdentity owner,string scope,string controller,Target proof) {
   var journal=new PublicationJournal(admitted,job,resource,owner,scope,controller,proof);
   try { journal.Read(); return journal; }
   catch(IOException error) {
    if(error.Message=="PERMISSION_DENIED"||error.Message=="CONFLICT") throw;
    throw new IOException("OUTCOME_UNKNOWN");
   } catch(OutOfMemoryException) { throw new IOException("RESOURCE_EXHAUSTED"); }
   catch { throw new IOException("OUTCOME_UNKNOWN"); }
  }
  void Read() {
   storage.Position=0; int records=0;
   using(var reader=new BinaryReader(storage,new UTF8Encoding(false,true),true)) {
    while(storage.Position<storage.Length) {
     if(storage.Length-storage.Position<4) { IncompleteTail=true; break; }
     int size=reader.ReadInt32(); Need(size>0&&size<=MaximumFrame,"OUTCOME_UNKNOWN");
     if(storage.Length-storage.Position<(long)size+32) { IncompleteTail=true; break; }
     byte[] payload=reader.ReadBytes(size),hash=reader.ReadBytes(32),expected=Digest(chain,payload);
     Need(payload.Length==size&&Equal(hash,expected),"OUTCOME_UNKNOWN");
     using(var bytes=new MemoryStream(payload,false)) using(var fields=new BinaryReader(bytes,new UTF8Encoding(false,true))) {
      byte type=fields.ReadByte();
      if(records==0) {
       Need(type==1&&fields.ReadInt32()==3,"OUTCOME_UNKNOWN");
       Need(Text(fields,36)==jobId&&Text(fields,36)==resourceId,"CONFLICT");
       Need(Text(fields,184)==nativeOwner.Sid,"PERMISSION_DENIED");
       Need(fields.ReadInt64()==nativeOwner.ProcessId&&fields.ReadInt64()==nativeOwner.CreationFileTime,"CONFLICT");
       Need(Text(fields,36)==scopeId&&Text(fields,36)==controllerId,"CONFLICT");
       Need(SameTarget(ReadTarget(fields),scopeRecord),"CONFLICT");
       Target=ReadTarget(fields);
      } else {
       Need(type==2&&records<=5,"OUTCOME_UNKNOWN");
       var next=new Publication(Text(fields,24),Text(fields,64),Text(fields,24),Text(fields,68),
        Text(fields,24,true),fields.ReadInt64(),Text(fields,64));
       ValidateNext(next); Last=next;
      }
      Need(bytes.Position==bytes.Length,"OUTCOME_UNKNOWN");
     }
     chain=hash; records++;
    }
   }
   Need(records>0,"OUTCOME_UNKNOWN");
  }
 }

 /** One cache belonging to an already captured runtime. Private streams are admitted by the broker;
  * every user-path operation remains inside OriginalUser. This object never replays failed writes.
  */
 public sealed class CacheLease {
  readonly OriginalUser original;
  readonly string jobId,resourceId,scopeId,controllerId;
  readonly Target scopeRecord;
  readonly Destination destination;
  PublicationJournal journal;
  Target captured;
  PublicationResult result;
  public CacheLease(OriginalUser user,Destination admitted,string job,string resource,string scope,string controller,Target proof) {
   original=user; destination=admitted; jobId=job; resourceId=resource; scopeId=scope; controllerId=controller; scopeRecord=proof;
  }
  public override string ToString() { return "Retained runtime cache (<redacted>)"; }
  public void CaptureAtCommit(FileStream admittedCache,FileStream admittedJournal) {
   if(journal!=null||captured!=null) throw new IOException("CONFLICT");
   original.ValidateScope(scopeRecord,scopeId);
   var current=original.CaptureCurrent(destination);
   // The destination identity survives owner loss before the child starts. A failed copy cannot
   // erase its correlation or become authority to replace the ordinary user's cache.
   journal=PublicationJournal.Create(admittedJournal,jobId,resourceId,original.Owner,scopeId,controllerId,scopeRecord,current);
   if(admittedCache.Length!=0) throw new IOException("CONFLICT");
   original.CopyInput(current,admittedCache); admittedCache.Flush(true); captured=current;
  }
  public PublicationResult PublishAfterExit(Stream retainedCache,Func<bool> exactChildExited) {
   if(captured==null||journal==null) throw new IOException("CONFLICT");
   // The broker supplies its retained native child's wait result, never a caller-controlled flag.
   if(!exactChildExited()) throw new IOException("BUSY");
   if(result!=null) return result;
   Publication latest=null;
   try {
    original.ValidateScope(scopeRecord,scopeId);
    retainedCache.Position=0;
    original.Publish(captured,retainedCache,checkpoint=>{ latest=checkpoint; journal.Record(checkpoint); });
    result=new PublicationResult(jobId,resourceId,"PUBLISHED",null);
   } catch(Exception failure) {
    bool committed=latest!=null&&latest.Phase=="PUBLISHED";
    if(!committed&&latest!=null) {
     try { committed=original.PublicationCommitted(captured,latest); } catch { }
    }
    result=new PublicationResult(jobId,resourceId,committed?"COMMITTED_CLEANUP_PENDING":"PENDING_PUBLICATION",Code(failure));
   }
   return result;
  }
  static string Code(Exception failure) {
   string code=failure.Message;
   if(code=="CONFLICT"||code=="PERMISSION_DENIED"||code=="OUTCOME_UNKNOWN") return code;
   if(failure is UnauthorizedAccessException) return "PERMISSION_DENIED";
   return "PERSISTENCE_FAILED"; // Native byte/space failures do not turn a known child exit into unknown.
  }
 }
 public sealed class PublicationResult {
  public readonly string JobId,ResourceId,Disposition,Code;
  public PublicationResult(string job,string resource,string disposition,string code) {
   JobId=job; ResourceId=resource; Disposition=disposition; Code=code;
  }
  public override string ToString() { return "Runtime resource result (<redacted>)"; }
 }

 public sealed class ResourceIdentity {
  public readonly string Id,Kind;
  public ResourceIdentity(string id,string kind) {
   Guid parsed;
   if(!Guid.TryParseExact(id,"D",out parsed)||parsed.ToString("D")!=id||(kind!="CACHE"&&kind!="OUTPUT"))
    throw new IOException("INVALID_ARGUMENT");
   Id=id; Kind=kind;
  }
  public override string ToString() { return "Native resource identity (<redacted>)"; }
 }
 public sealed class RuntimeResourceBinding {
  public readonly string JobId,ScopeId,ControllerId;
  public readonly OwnerIdentity NativeOwner;
  public readonly Target ScopeRecord;
  readonly ResourceIdentity[] resources;
  public ResourceIdentity[] Resources { get { return (ResourceIdentity[])resources.Clone(); } }
  public RuntimeResourceBinding(string job,string scope,string controller,OwnerIdentity owner,Target proof,ResourceIdentity[] entries) {
   foreach(string id in new[]{job,scope,controller}) {
    Guid parsed; if(!Guid.TryParseExact(id,"D",out parsed)||parsed.ToString("D")!=id) throw new IOException("INVALID_ARGUMENT");
   }
   PublicationJournal.ValidateTarget(proof);
   if(owner==null||proof.FileIdentity==null||entries==null||entries.Length==0) throw new IOException("INVALID_ARGUMENT");
   var ids=new HashSet<string>(StringComparer.Ordinal);
   foreach(var entry in entries) if(entry==null||!ids.Add(entry.Id)) throw new IOException("INVALID_ARGUMENT");
   JobId=job; ScopeId=scope; ControllerId=controller; NativeOwner=owner; ScopeRecord=proof;
   resources=(ResourceIdentity[])entries.Clone();
   Array.Sort(resources,(a,b)=>StringComparer.Ordinal.Compare(a.Id,b.Id));
  }
  public override string ToString() { return "Native resource correlation (<redacted>)"; }
  public static RuntimeResourceBinding Read(BinaryReader reader) {
   try {
    if(reader.ReadInt32()!=1) throw new IOException("INCOMPATIBLE_PROTOCOL");
    string job=PublicationJournal.Text(reader,36),scope=PublicationJournal.Text(reader,36),controller=PublicationJournal.Text(reader,36);
    var owner=new OwnerIdentity(reader.ReadInt64(),reader.ReadInt64(),PublicationJournal.Text(reader,184));
    Target proof=PublicationJournal.ReadTarget(reader);int count=reader.ReadInt32();
    if(count<=0) throw new IOException("INVALID_ARGUMENT");
    // Metadata is bounded independently of configuration streams. Validate the minimum encoded
    // identity size before allocating a caller-sized array, including on a truncated frame.
    if(count>(8*1024*1024)/49) throw new IOException("RESOURCE_EXHAUSTED");
    if(reader.BaseStream.CanSeek&&count>(reader.BaseStream.Length-reader.BaseStream.Position)/49)
     throw new IOException("INVALID_ARGUMENT");
    var resources=new ResourceIdentity[count];
    for(int i=0;i<count;i++) {
     resources[i]=new ResourceIdentity(PublicationJournal.Text(reader,36),PublicationJournal.Text(reader,6));
     if(i>0&&StringComparer.Ordinal.Compare(resources[i-1].Id,resources[i].Id)>=0) throw new IOException("INVALID_ARGUMENT");
    }
    return new RuntimeResourceBinding(job,scope,controller,owner,proof,resources);
   } catch(OutOfMemoryException) { throw new IOException("RESOURCE_EXHAUSTED"); }
  }
  internal byte[] CanonicalBytes() {
   try {
    using(var bytes=new MemoryStream()) {
     using(var writer=new BinaryWriter(bytes,new UTF8Encoding(false,true),true)) {
      writer.Write(1); PublicationJournal.Text(writer,JobId); PublicationJournal.Text(writer,ScopeId); PublicationJournal.Text(writer,ControllerId);
      writer.Write(NativeOwner.ProcessId); writer.Write(NativeOwner.CreationFileTime); PublicationJournal.Text(writer,NativeOwner.Sid);
      PublicationJournal.WriteTarget(writer,ScopeRecord); writer.Write(resources.Length);
      foreach(var resource in resources) { PublicationJournal.Text(writer,resource.Id); PublicationJournal.Text(writer,resource.Kind); }
     }
     return bytes.ToArray();
    }
   } catch(OutOfMemoryException) { throw new IOException("RESOURCE_EXHAUSTED"); }
  }
 }

 /** The fixed native broker admits an exclusive protected file before entering this class and
  * retains that handle through its entire mutable-resource lifetime. A cold helper uses the same
  * gate: observing a missing stage alone can never close admission or prove a runtime outcome.
  */
 public sealed class ResourceAdmissionGate {
  readonly FileStream storage;
  readonly byte[] binding;
  byte[] chain=new byte[32];
  bool failed;
  public bool AdmissionClosed { get; private set; }
  public bool HadOriginalAdmission { get; private set; }
  public bool CommitIntended { get; private set; }
  ResourceAdmissionGate(FileStream exclusive,RuntimeResourceBinding expected) {
   if(exclusive==null||!exclusive.CanRead||!exclusive.CanWrite||!exclusive.CanSeek) throw new IOException("INVALID_ARGUMENT");
   storage=exclusive; binding=expected.CanonicalBytes();
  }
  public override string ToString() { return "Protected resource admission (<redacted>)"; }
  internal bool Matches(RuntimeResourceBinding expected) { return expected!=null&&Equal(binding,expected.CanonicalBytes()); }
  static void Need(bool value,string code) { if(!value) throw new IOException(code); }
  static byte[] Hash(byte[] prior,byte[] bytes) {
   using(var digest=SHA256.Create()) { digest.TransformBlock(prior,0,prior.Length,null,0); digest.TransformFinalBlock(bytes,0,bytes.Length); return digest.Hash; }
  }
  static bool Equal(byte[] left,byte[] right) {
   if(left.Length!=right.Length) return false;
   int different=0; for(int i=0;i<left.Length;i++) different|=left[i]^right[i]; return different==0;
  }
  void Append(byte[] payload) {
   Need(!failed,"CONFLICT");
   byte[] digest=Hash(chain,payload);
   try {
    storage.Position=storage.Length;
    using(var writer=new BinaryWriter(storage,new UTF8Encoding(false,true),true)) {
     writer.Write(payload.Length); writer.Write(payload); writer.Write(digest); writer.Flush();
    }
    storage.Flush(true); chain=digest;
   } catch { failed=true; throw new IOException("PERSISTENCE_FAILED"); }
  }
  void Initialize(bool closed) {
   Need(storage.Length==0,"CONFLICT");
   var payload=new byte[checked(binding.Length+2)]; payload[0]=1; payload[1]=(byte)(closed?1:0);
   Buffer.BlockCopy(binding,0,payload,2,binding.Length); Append(payload);
   AdmissionClosed=closed; HadOriginalAdmission=!closed;
  }
  public static ResourceAdmissionGate CreateForOriginal(FileStream exclusive,RuntimeResourceBinding binding,Func<bool> retainedOriginalAlive) {
   var gate=new ResourceAdmissionGate(exclusive,binding);
   Need(exclusive.Length==0,"CONFLICT");
   // Called while the protected gate is exclusively held, after any competing recovery finished.
   // The fixed helper supplies the retained native process wait; it is never a protocol flag.
   Need(retainedOriginalAlive(),"CANCELLED");
   gate.Initialize(false); return gate;
  }
  public static ResourceAdmissionGate CloseForRecovery(FileStream exclusive,RuntimeResourceBinding binding,Func<bool> retainedOriginalExited) {
   var gate=new ResourceAdmissionGate(exclusive,binding);
   Need(retainedOriginalExited(),"BUSY");
   if(exclusive.Length==0) gate.Initialize(true);
   else {
    gate.Read();
    if(!gate.AdmissionClosed) { gate.Append(new byte[]{2}); gate.AdmissionClosed=true; }
   }
   return gate;
  }
  public void CloseAfterNativeReconciliation() {
   if(AdmissionClosed) return;
   Append(new byte[]{2}); AdmissionClosed=true;
  }
  public void MarkCommitIntent() {
   Need(HadOriginalAdmission&&!AdmissionClosed&&!CommitIntended,"CONFLICT");
   Append(new byte[]{3}); CommitIntended=true;
  }
  void Read() {
   storage.Position=0; int count=0;
   try {
    using(var reader=new BinaryReader(storage,new UTF8Encoding(false,true),true)) {
     while(storage.Position<storage.Length) {
      Need(storage.Length-storage.Position>=4&&count<3,"OUTCOME_UNKNOWN");
      int size=reader.ReadInt32();
      // The expected binding fixes this metadata frame's exact size; it is not a config limit.
      Need(size==(count==0?checked(binding.Length+2):1)&&storage.Length-storage.Position>=(long)size+32,"OUTCOME_UNKNOWN");
      byte[] payload=reader.ReadBytes(size),digest=reader.ReadBytes(32);
      Need(Equal(Hash(chain,payload),digest),"OUTCOME_UNKNOWN");
      if(count==0) {
       Need(payload[0]==1&&(payload[1]==0||payload[1]==1),"OUTCOME_UNKNOWN");
       var actual=new byte[binding.Length]; Buffer.BlockCopy(payload,2,actual,0,actual.Length);
       Need(Equal(actual,binding),"CONFLICT"); AdmissionClosed=payload[1]==1; HadOriginalAdmission=!AdmissionClosed;
      } else {
       Need(!AdmissionClosed,"OUTCOME_UNKNOWN");
       if(payload[0]==3) { Need(HadOriginalAdmission&&!CommitIntended,"OUTCOME_UNKNOWN");CommitIntended=true; }
       else { Need(payload[0]==2,"OUTCOME_UNKNOWN");AdmissionClosed=true; }
      }
      chain=digest; count++;
     }
    }
    Need(count>0,"OUTCOME_UNKNOWN");
   } catch(OutOfMemoryException) { throw new IOException("RESOURCE_EXHAUSTED"); }
  }
 }
}

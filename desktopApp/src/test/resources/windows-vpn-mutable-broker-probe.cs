using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using VpnScopedStorage;

public static class MutableBrokerProbe {
 [StructLayout(LayoutKind.Sequential)] struct Limit {
  public long processTime,jobTime; public uint flags; public UIntPtr min,max; public uint active; public UIntPtr affinity;
  public uint priority,scheduling; public long rOps,wOps,oOps,rBytes,wBytes,oBytes; public UIntPtr processMemory,jobMemory,peakProcess,peakJob;
 }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr sa,string name);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int type,ref Limit value,int size);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 static void Need(bool value,string message) { if(!value) throw new Exception(message); }
 static string Hash(byte[] bytes) { using(var sha=SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-","").ToLowerInvariant(); }
 static void Text(BinaryWriter writer,string value) { var bytes=new UTF8Encoding(false,true).GetBytes(value); writer.Write(bytes.Length);writer.Write(bytes); }
 static void Content(BinaryWriter writer,byte[] bytes) {
  for(int offset=0;offset<bytes.Length;) { int count=Math.Min(65536,bytes.Length-offset);writer.Write(count);writer.Write(bytes,offset,count);offset+=count; }
  writer.Write(0);writer.Write((long)bytes.Length);using(var sha=SHA256.Create()) writer.Write(sha.ComputeHash(bytes));
 }
 static void Protect(string path,string sid) {
  var acl=new System.Security.AccessControl.FileSecurity();acl.SetOwner(new SecurityIdentifier(sid));acl.SetAccessRuleProtection(true,false);
  acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(new SecurityIdentifier(sid),System.Security.AccessControl.FileSystemRights.FullControl,System.Security.AccessControl.AccessControlType.Allow));
  File.SetAccessControl(path,acl);
 }
 public static string Ready(string root,string childImage) { return Run(root,childImage,0); }
 public static string LargeConfiguration(string root,string childImage) { return Run(root,childImage,9*1024*1024); }
 static string Run(string root,string childImage,int padding) {
  byte[] image=File.ReadAllBytes(childImage);
  using(var owner=Process.GetCurrentProcess()) using(var identity=WindowsIdentity.GetCurrent())
  using(var original=new OriginalUser(owner.Handle,identity.User.Value)) {
   string scope=Guid.NewGuid().ToString("D"),scopeFile=Path.Combine(root,"scope.json"),cache=Path.Combine(root,"ordinary-cache.db");
   File.WriteAllText(scopeFile,"{\"schemaVersion\":1,\"scopeId\":\""+scope+"\"}",new UTF8Encoding(false));Protect(scopeFile,identity.User.Value);
   File.WriteAllText(cache,"initial-A",new UTF8Encoding(false));
   var proof=original.Capture(scopeFile);var destination=original.AdmitDestination(cache);
   string id=Guid.NewGuid().ToString("D"),jobId=Guid.NewGuid().ToString("D");
   var binding=new RuntimeResourceBinding(jobId,scope,Guid.NewGuid().ToString("D"),original.Owner,proof,new[]{new ResourceIdentity(id,"CACHE")});
   IntPtr job=CreateJobObject(IntPtr.Zero,null);Need(job!=IntPtr.Zero,"Fixture job creation failed");
   var limit=new Limit();limit.flags=0x2008;limit.active=1;
   Need(SetInformationJobObject(job,9,ref limit,Marshal.SizeOf<Limit>()),"Fixture job configuration failed");
   string pipeName="vpn-control-vpn-"+Guid.NewGuid().ToString("D");Exception serverFailure=null;
   var server=new Thread(delegate() {
    try { VpnRuntimeBroker.Run(pipeName,(uint)owner.Id,owner.StartTime.ToUniversalTime().ToFileTimeUtc(),identity.User.Value,Hash(image)); }
    catch(Exception failure) { serverFailure=failure; }
   });server.IsBackground=true;server.Start();
   try {
    using(var pipe=new NamedPipeClientStream(".",pipeName,PipeDirection.InOut,PipeOptions.None)) {
     pipe.Connect(10000);
     using(var reader=new BinaryReader(pipe,Encoding.UTF8,true)) using(var writer=new BinaryWriter(pipe,Encoding.UTF8,true)) {
      byte[] metadata;
      using(var bytes=new MemoryStream()) {
       using(var fields=new BinaryWriter(bytes,Encoding.UTF8,true)) {
        fields.Write(binding.CanonicalBytes());Text(fields,destination.Path);Text(fields,destination.ParentIdentity);
       }
       metadata=bytes.ToArray();
      }
      writer.Write(5);writer.Write(job.ToInt64());writer.Write(metadata.Length);writer.Write(metadata);
      writer.Write(image.Length);writer.Write(image);
      string config="{\"padding\":\""+new string('x',padding)+"\",\"experimental\":{\"cache_file\":{\"enabled\":true,\"path\":\"vpn-control-mutable:"+id+"\",\"cache_id\":\"fixture\",\"store_fakeip\":true}}}";
      Content(writer,Encoding.UTF8.GetBytes(config));writer.Write(0);writer.Flush();
      int ready=reader.ReadByte();Need(ready==0,"Expected mutable READY=0; actual="+ready);
      int child=reader.ReadInt32();Need(child>0,"Mutable child identity missing");
      Need(File.ReadAllText(cache)=="initial-A","Readiness changed original cache");
      File.WriteAllText(cache,"latest-A",new UTF8Encoding(false));
      writer.Write((byte)3);writer.Flush();Need(reader.ReadByte()==0,"Mutable commit failed");
      bool alive;int polls=0;
      do {
       writer.Write((byte)0);writer.Flush();alive=reader.ReadBoolean();int count=reader.ReadInt32();
       Need(count>=0&&count<=65536,"Unbounded native log frame");Need(reader.ReadBytes(count).Length==count,"Truncated log frame");
       if(alive) Thread.Sleep(20);
       Need(++polls<500,"Inert mutable child did not exit");
      } while(alive);
      Need(reader.ReadInt32()==1,"Terminal metadata schema missing");
      Need(ReadText(reader)==jobId&&reader.ReadInt32()==1&&ReadText(reader)==id,"Terminal resource identity changed");
      Need(reader.ReadByte()==0,"Terminal resource kind changed");
      int disposition=reader.ReadByte(),code=reader.ReadByte();bool cleanup=reader.ReadBoolean();
      Need((disposition==1&&code==0)||(disposition==2&&code==4),"Unexpected native publication disposition");
      Need(!cleanup,"Intermediate broker falsely confirmed protected cleanup");
     }
    }
    Need(server.Join(15000),"Fixed broker cleanup did not finish");
    Need(serverFailure==null,"Fixed broker failed after native reply: "+(serverFailure==null?"":serverFailure.GetType().Name));
    Need(File.ReadAllText(cache)=="latest-A|owned-B","Commit did not capture latest A and publish exact B");
    if(padding==0) RejectRepeatedAdmission(owner,identity.User.Value,image,binding,destination,cache);
    return "MUTABLE_BROKER_OK:1:"+jobId;
   } finally {
    CloseHandle(job);server.Join(15000);
   }
  }
 }
 static void RejectRepeatedAdmission(Process owner,string sid,byte[] image,RuntimeResourceBinding binding,Destination destination,string cache) {
  string stage=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"vpn-control-vpn-"+binding.JobId);
  string gate=Path.Combine(stage,".admission");byte[] originalGate=File.ReadAllBytes(gate);
  string cacheBytes=File.ReadAllText(cache);string[] names=Directory.GetFileSystemEntries(stage);Array.Sort(names,StringComparer.Ordinal);
  IntPtr job=CreateJobObject(IntPtr.Zero,null);Need(job!=IntPtr.Zero,"Competing fixture job creation failed");
  var limit=new Limit();limit.flags=0x2008;limit.active=1;Need(SetInformationJobObject(job,9,ref limit,Marshal.SizeOf<Limit>()),"Competing fixture job setup failed");
  string pipeName="vpn-control-vpn-"+Guid.NewGuid().ToString("D");
  var server=new Thread(delegate() {
   try { VpnRuntimeBroker.Run(pipeName,(uint)owner.Id,owner.StartTime.ToUniversalTime().ToFileTimeUtc(),sid,Hash(image)); }
   catch(Exception) { }
  });server.IsBackground=true;server.Start();
  try {
   using(var pipe=new NamedPipeClientStream(".",pipeName,PipeDirection.InOut,PipeOptions.None)) {
    pipe.Connect(10000);
    using(var reader=new BinaryReader(pipe,Encoding.UTF8,true)) using(var writer=new BinaryWriter(pipe,Encoding.UTF8,true)) {
     byte[] metadata;
     using(var memory=new MemoryStream()) {
      using(var fields=new BinaryWriter(memory,Encoding.UTF8,true)) { fields.Write(binding.CanonicalBytes());Text(fields,destination.Path);Text(fields,destination.ParentIdentity); }
      metadata=memory.ToArray();
     }
     writer.Write(5);writer.Write(job.ToInt64());writer.Write(metadata.Length);writer.Write(metadata);writer.Write(image.Length);writer.Write(image);writer.Flush();
     Need(reader.ReadByte()==6,"Competing first-gate admission did not fail CONFLICT");
    }
   }
   Need(server.Join(15000),"Competing broker failed to finish");
   string[] after=Directory.GetFileSystemEntries(stage);Array.Sort(after,StringComparer.Ordinal);
   Need(Hash(originalGate)==Hash(File.ReadAllBytes(gate))&&cacheBytes==File.ReadAllText(cache)&&String.Join("|",names)==String.Join("|",after),
    "Competing admission changed an established gate, resources or publication");
  } finally { CloseHandle(job);server.Join(15000); }
 }
 static string ReadText(BinaryReader reader) { int count=reader.ReadInt32();Need(count>=0&&count<=184,"Invalid text frame");return new UTF8Encoding(false,true).GetString(reader.ReadBytes(count)); }
}

public static class MutableBrokerStateProbe {
 static void Need(bool value,string message) { if(!value) throw new Exception(message); }
 static void Fails(string code,Action action) {
  try { action(); } catch(IOException failure) { Need(failure.Message==code,"Wrong bounded failure: "+failure.Message);return; }
  throw new Exception("Missing rejection: "+code);
 }
 static RuntimeResourceBinding Binding(string root) {
  return new RuntimeResourceBinding(Guid.NewGuid().ToString("D"),Guid.NewGuid().ToString("D"),Guid.NewGuid().ToString("D"),
   new OwnerIdentity(123,133000000000000000,"S-1-5-21-101-102-103-1000"),
   new Target(Path.Combine(root,"scope.json"),new string('a',24),new string('b',24),76,new string('c',64)),
   new[]{new ResourceIdentity(Guid.NewGuid().ToString("D"),"CACHE")});
 }
 static byte[] Metadata(RuntimeResourceBinding binding,string root) {
  using(var memory=new MemoryStream()) {
   using(var writer=new BinaryWriter(memory,Encoding.UTF8,true)) {
    writer.Write(binding.CanonicalBytes());PublicationJournal.Text(writer,Path.Combine(root,"ordinary-cache.db"));
    PublicationJournal.Text(writer,binding.ScopeRecord.ParentIdentity);
   }
   return memory.ToArray();
  }
 }
 static byte[] Frame(byte[] metadata,int? length=null) {
  using(var memory=new MemoryStream()) {
   using(var writer=new BinaryWriter(memory,Encoding.UTF8,true)) { writer.Write(length??metadata.Length);writer.Write(metadata); }
   return memory.ToArray();
  }
 }
 static RuntimeResourcePreparation Read(byte[] bytes,OwnerIdentity owner) {
  using(var memory=new MemoryStream(bytes)) using(var reader=new BinaryReader(memory,Encoding.UTF8,true))
   return RuntimeResourcePreparation.ReadFrameForOwner(reader,owner);
 }
 public static string MetadataFrames(string root) {
  var binding=Binding(root);byte[] metadata=Metadata(binding,root);
  using(var memory=new MemoryStream()) {
   byte[] frame=Frame(metadata);memory.Write(frame,0,frame.Length);memory.WriteByte(99);memory.Position=0;
   using(var reader=new BinaryReader(memory,Encoding.UTF8,true)) {
    var result=RuntimeResourcePreparation.ReadFrameForOwner(reader,binding.NativeOwner);
    Need(result.Binding.JobId==binding.JobId&&reader.ReadByte()==99,"Metadata consumed the next image/config frame");
   }
  }
  Fails("RESOURCE_EXHAUSTED",()=>Read(Frame(new byte[0],8*1024*1024+1),binding.NativeOwner));
  Fails("INVALID_ARGUMENT",()=>Read(Frame(new byte[2],5),binding.NativeOwner));
  Fails("INVALID_ARGUMENT",()=>Read(Frame(new byte[0],0),binding.NativeOwner));
  var trailing=new byte[metadata.Length+1];Array.Copy(metadata,trailing,metadata.Length);
  Fails("INVALID_ARGUMENT",()=>Read(Frame(trailing),binding.NativeOwner));
  Fails("PERMISSION_DENIED",()=>Read(Frame(metadata),new OwnerIdentity(124,binding.NativeOwner.CreationFileTime,binding.NativeOwner.Sid)));
  int countOffset=binding.CanonicalBytes().Length-4-4-36-4-5;
  byte[] inflated=(byte[])metadata.Clone();Array.Copy(BitConverter.GetBytes(Int32.MaxValue),0,inflated,countOffset,4);
  Fails("RESOURCE_EXHAUSTED",()=>Read(Frame(inflated),binding.NativeOwner));
  return "MUTABLE_METADATA_OK:7";
 }
 static void InvalidConfiguration(Action action) {
  try { action(); } catch(IOException) { return; } catch(ArgumentException) { return; }
  throw new Exception("Unadmitted mutable path was normalized");
 }
 public static string ConfigurationMapping(string root) {
  string id=Guid.NewGuid().ToString("D"),reference="vpn-control-mutable:"+id;
  string destination=Path.Combine(root,"cache-"+id+".db");
  var mapped=new Dictionary<string,string>(StringComparer.Ordinal);mapped.Add(reference,destination);
  string config="{\"experimental\":{\"cache_file\":{\"enabled\":true,\"path\":\""+reference+"\",\"cache_id\":\"kept\",\"store_fakeip\":true,\"store_rdrc\":false,\"rdrc_timeout\":\"3d\"}}}";
  string result=VpnRuntimeBroker.NormalizeConfiguration(config,root,null,mapped);
  var parser=new System.Web.Script.Serialization.JavaScriptSerializer();
  var actual=(Dictionary<string,object>)parser.DeserializeObject(result);
  var cache=(Dictionary<string,object>)((Dictionary<string,object>)actual["experimental"])["cache_file"];
  Need(cache.Count==6&&(string)cache["path"]==destination&&(string)cache["cache_id"]=="kept"&&
   Equals(cache["store_fakeip"],true)&&Equals(cache["store_rdrc"],false)&&(string)cache["rdrc_timeout"]=="3d","Mutable cache semantics changed");
  InvalidConfiguration(()=>VpnRuntimeBroker.NormalizeConfiguration(config.Replace(reference,"C:/unadmitted.db"),root,null,mapped));
  InvalidConfiguration(()=>VpnRuntimeBroker.NormalizeConfiguration(config.Replace(reference,"vpn-control-mutable:"+Guid.NewGuid().ToString("D")),root,null,mapped));
  InvalidConfiguration(()=>VpnRuntimeBroker.NormalizeConfiguration(config.Replace("\"cache_id\":\"kept\"","\"unknown_file\":\"other.db\""),root,null,mapped));
  InvalidConfiguration(()=>VpnRuntimeBroker.NormalizeConfiguration("{}",root,null,mapped));
  return "MUTABLE_CONFIGURATION_OK:5";
 }
 sealed class Storage : FileStream {
  internal bool FailFlush;
  internal Action Flushed;
  internal Storage(string path):base(path,FileMode.CreateNew,FileAccess.ReadWrite,FileShare.None) { }
  public override void Flush(bool disk) {
   if(FailFlush) throw new IOException("fixture flush failure");
   base.Flush(disk);if(disk&&Flushed!=null) Flushed();
  }
 }
 sealed class Batch : RuntimeResourceLifecycle.Batch {
  internal readonly List<string> Events=new List<string>();
  internal bool CaptureFails;
  internal int CloseFailures;
  internal PublicationResult[] Result;
  public void CaptureAtCommit() { Events.Add("capture");if(CaptureFails) throw new IOException("CONFLICT"); }
  public void MarkCommitIntent() { Events.Add("mark"); }
  public void BeginPublicationAfterExit() { Events.Add("publish"); }
  public PublicationResult[] Snapshot() { return Result; }
  public void WaitForPublication() { Events.Add("wait"); }
  public void CloseRetainedStreams() { Events.Add("close");if(CloseFailures-- >0) throw new IOException("PERSISTENCE_FAILED"); }
 }
 public static string Ordering(string root) {
  for(int scenario=0;scenario<6;scenario++) {
   string path=Path.Combine(root,"gate-"+scenario);var binding=Binding(root);
   using(var storage=new Storage(path)) {
    if(scenario==0) {
     int waited=0;Fails("CANCELLED",()=>ResourceAdmissionGate.CreateForOriginal(storage,binding,()=>{waited++;return false;}));
     Need(waited==1&&storage.Length==0,"Owner exit wrote original admission");
     var cold=ResourceAdmissionGate.CloseForRecovery(storage,binding,()=>true);long length=storage.Length;
     Fails("CONFLICT",()=>ResourceAdmissionGate.CreateForOriginal(storage,binding,()=>{waited++;return true;}));
     Need(cold.AdmissionClosed&&!cold.HadOriginalAdmission&&storage.Length==length&&waited==1,"Delayed original rewrote first closed gate");
    } else {
     var gate=ResourceAdmissionGate.CreateForOriginal(storage,binding,()=>true);var batch=new Batch();bool exited=false;
     var flow=new RuntimeResourceLifecycle(binding,batch,gate,()=>exited);
     storage.Flushed=()=>batch.Events.Add("durable");
     if(scenario==1) {
      batch.CaptureFails=true;Fails("CONFLICT",()=>flow.Commit(()=>batch.Events.Add("resume")));
      Need(String.Join(",",batch.Events)=="capture"&&!gate.CommitIntended,"Failed fresh capture resumed B");
     } else if(scenario==2) {
      storage.FailFlush=true;Fails("PERSISTENCE_FAILED",()=>flow.Commit(()=>batch.Events.Add("resume")));
      Need(String.Join(",",batch.Events)=="capture"&&!gate.CommitIntended,"Lost commit write resumed B");storage.FailFlush=false;
     } else if(scenario==3) {
      Fails("OUTCOME_UNKNOWN",()=>flow.Commit(()=>{batch.Events.Add("resume");throw new IOException("OUTCOME_UNKNOWN");}));
      Need(String.Join(",",batch.Events)=="capture,durable,mark,resume"&&gate.CommitIntended,"Uncertain resume lost prior durable intent: "+String.Join(",",batch.Events)+"; intended="+gate.CommitIntended);
     } else if(scenario==4) {
      flow.Commit(()=>batch.Events.Add("resume"));
      Need(String.Join(",",batch.Events)=="capture,durable,mark,resume","Commit ordering changed");
      Fails("CONFLICT",()=>flow.Commit(()=>batch.Events.Add("resumed-twice")));
      Fails("BUSY",()=>flow.AfterConfirmedExit());Need(!batch.Events.Contains("publish"),"Publication preceded exact child exit");
      exited=true;var pending=flow.AfterConfirmedExit();Need(pending[0].Disposition=="PENDING_PUBLICATION"&&pending[0].Code=="OUTCOME_UNKNOWN","Missing publication became terminal success");
      batch.Result=new[]{new PublicationResult(binding.JobId,binding.Resources[0].Id,"PUBLISHED",null)};
      using(var terminal=new MemoryStream()) {
       using(var writer=new BinaryWriter(terminal,Encoding.UTF8,true)) flow.WriteTerminal(writer);
       Need(terminal.ToArray()[terminal.Length-1]==0,"Published bytes falsely confirmed protected disposal");
      }
      batch.CloseFailures=1;Fails("PERSISTENCE_FAILED",()=>flow.FinishAfterConfirmedExit());Need(!gate.AdmissionClosed,"Unclosed resource streams lost admission gate");
      flow.FinishAfterConfirmedExit();Need(gate.AdmissionClosed,"Confirmed close retry did not finish gate");
      storage.Flushed=null;
      var recovered=ResourceAdmissionGate.CloseForRecovery(storage,binding,()=>true);
      Need(recovered.AdmissionClosed&&recovered.HadOriginalAdmission&&recovered.CommitIntended,"Cold read lost the exact durable commit/closed chain");
     } else {
      var other=Binding(root);Fails("CONFLICT",()=>new RuntimeResourceLifecycle(other,batch,gate,()=>true));
      bool blocked=false;try { using(var competing=new FileStream(path,FileMode.CreateNew,FileAccess.ReadWrite,FileShare.None)) { } }
      catch(IOException) { blocked=true; }Need(blocked,"First-gate competitor replaced retained storage");
      long length=storage.Length;Fails("CONFLICT",()=>ResourceAdmissionGate.CreateForOriginal(storage,binding,()=>true));
      Need(storage.Length==length,"Repeated original truncated prior binding");
     }
    }
   }
   File.Delete(path);
  }
  return "MUTABLE_ORDERING_OK:6";
 }
}

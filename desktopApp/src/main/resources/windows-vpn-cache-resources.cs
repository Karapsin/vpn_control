// Only the fixed broker constructs this batch from an authenticated, captured resource binding.
namespace VpnScopedStorage {
 using System;
 using System.IO;
 using System.Threading;
 using System.Collections.Generic;

 public sealed class MutableResourceInput {
  public readonly ResourceIdentity Identity;
  public readonly Destination Destination;
  public MutableResourceInput(ResourceIdentity identity,Destination destination) {
   if(identity==null||destination==null) throw new IOException("INVALID_ARGUMENT");
   Identity=identity; Destination=destination;
  }
  public override string ToString() { return "Captured mutable resource (<redacted>)"; }
 }

 /** Decoding is side-effect free. The broker supplies the already retained native owner's identity. */
 public sealed class RuntimeResourcePreparation {
  internal const int MaximumMetadataBytes=8*1024*1024;
  public readonly RuntimeResourceBinding Binding;
  readonly MutableResourceInput[] inputs;
  RuntimeResourcePreparation(RuntimeResourceBinding binding,MutableResourceInput[] captured) {
   Binding=binding;inputs=captured;
  }
  public MutableResourceInput[] Inputs { get { return (MutableResourceInput[])inputs.Clone(); } }
  public override string ToString() { return "Native resource preparation (<redacted>)"; }
  public static RuntimeResourcePreparation ReadFrameForOwner(BinaryReader reader,OwnerIdentity expected) {
   int length=reader.ReadInt32();
   if(length<=0) throw new IOException("INVALID_ARGUMENT");
   if(length>MaximumMetadataBytes) throw new IOException("RESOURCE_EXHAUSTED");
   byte[] bytes=reader.ReadBytes(length);
   if(bytes.Length!=length) throw new IOException("INVALID_ARGUMENT");
   using(var frame=new MemoryStream(bytes,false))
   using(var fields=new BinaryReader(frame,new System.Text.UTF8Encoding(false,true),true)) {
    var result=ReadForOwner(fields,expected);
    if(frame.Position!=frame.Length) throw new IOException("INVALID_ARGUMENT");
    return result;
   }
  }
  public static RuntimeResourcePreparation ReadForOwner(BinaryReader reader,OwnerIdentity expected) {
   try {
    if(expected==null) throw new IOException("INVALID_ARGUMENT");
    var binding=RuntimeResourceBinding.Read(reader);var actual=binding.NativeOwner;
    if(actual.ProcessId!=expected.ProcessId||actual.CreationFileTime!=expected.CreationFileTime||actual.Sid!=expected.Sid)
     throw new IOException("PERMISSION_DENIED");
    var identities=binding.Resources;var captured=new MutableResourceInput[identities.Length];
    for(int i=0;i<identities.Length;i++) {
     string path=PublicationJournal.Text(reader,131068),parent=PublicationJournal.Text(reader,24);
     if(path.Length==0||path.Length>32767||path.IndexOf('\0')>=0||!Path.IsPathRooted(path)||
       !System.Text.RegularExpressions.Regex.IsMatch(parent,"\\A[a-f0-9]{24}\\z")) throw new IOException("INVALID_ARGUMENT");
     captured[i]=new MutableResourceInput(identities[i],new Destination(path,parent));
    }
    return new RuntimeResourcePreparation(binding,captured);
   } catch(OutOfMemoryException) { throw new IOException("RESOURCE_EXHAUSTED"); }
  }
  internal void Write(BinaryWriter writer) {
   writer.Write(Binding.CanonicalBytes());
   foreach(var input in inputs) {
    PublicationJournal.Text(writer,input.Destination.Path);PublicationJournal.Text(writer,input.Destination.ParentIdentity);
   }
  }
 }

 /** The caller retains the admitted protected parent and gate, and owns every returned private
  * stream. No elevated user-path IO exists here: OriginalUser controls admission, capture, and
  * publication. Native child exit and resource publication are independently observable.
  */
 public sealed class RuntimeCacheResources {
  sealed class Entry {
   public readonly string Id,Kind,DataName,JournalName;
   public readonly CacheLease Lease;
   public FileStream Journal;
   public bool Captured;
   public Entry(ResourceIdentity identity,CacheLease lease) {
    Id=identity.Id; Kind=identity.Kind; DataName=OwnedDataName(identity);
    JournalName="publication-"+Id+".journal"; Lease=lease;
   }
  }
  readonly object sync=new object();
  readonly RuntimeResourceBinding binding;
  readonly List<Entry> entries=new List<Entry>();
  readonly Func<string,FileMode,FileStream> privateFile;
  readonly Func<bool> exactChildExited;
  bool prepared,commitIntent,disposed;
  Thread publisher;
  PublicationResult[] result;

  public RuntimeCacheResources(OriginalUser original,RuntimeResourceBinding admitted,
    MutableResourceInput[] captured,Func<string,FileMode,FileStream> openAdmittedPrivateFile,
    Func<bool> retainedNativeChildExited) {
   if(original==null||admitted==null||captured==null||openAdmittedPrivateFile==null||retainedNativeChildExited==null)
    throw new IOException("INVALID_ARGUMENT");
   if(original.Owner.ProcessId!=admitted.NativeOwner.ProcessId||original.Owner.CreationFileTime!=admitted.NativeOwner.CreationFileTime||
     original.Owner.Sid!=admitted.NativeOwner.Sid) throw new IOException("PERMISSION_DENIED");
   var identities=new List<ResourceIdentity>();
   foreach(var input in captured) {
    if(input==null||(input.Identity.Kind!="CACHE"&&input.Identity.Kind!="OUTPUT")) throw new IOException("UNSUPPORTED");
    identities.Add(input.Identity);
   }
   var expected=new RuntimeResourceBinding(admitted.JobId,admitted.ScopeId,admitted.ControllerId,
    admitted.NativeOwner,admitted.ScopeRecord,identities.ToArray());
   if(Convert.ToBase64String(expected.CanonicalBytes())!=Convert.ToBase64String(admitted.CanonicalBytes()))
    throw new IOException("CONFLICT");
   original.ValidateScope(admitted.ScopeRecord,admitted.ScopeId);
   // Recheck each ordinary parent before authorization readiness. Its bytes are deliberately not
   // captured yet: actual A may still be writing its cache until the manager commits replacement.
   var destinations=new Dictionary<string,HashSet<string>>(StringComparer.Ordinal);
   foreach(var input in captured) {
    var current=original.AdmitDestination(input.Destination.Path);
    if(current.ParentIdentity!=input.Destination.ParentIdentity||
      !String.Equals(current.Path,input.Destination.Path,StringComparison.OrdinalIgnoreCase)) throw new IOException("CONFLICT");
    HashSet<string> leaves;
    if(!destinations.TryGetValue(current.ParentIdentity,out leaves)) {
     leaves=new HashSet<string>(StringComparer.OrdinalIgnoreCase);destinations.Add(current.ParentIdentity,leaves);
    }
    if(!leaves.Add(Path.GetFileName(current.Path))) throw new IOException("CONFLICT");
    entries.Add(new Entry(input.Identity,new CacheLease(original,input.Destination,admitted.JobId,
     input.Identity.Id,admitted.ScopeId,admitted.ControllerId,admitted.ScopeRecord)));
   }
   binding=admitted; privateFile=openAdmittedPrivateFile; exactChildExited=retainedNativeChildExited;
  }
  public override string ToString() { return "Owned mutable runtime files (<redacted>)"; }

  internal static string OwnedDataName(ResourceIdentity identity) {
   if(identity==null) throw new IOException("INVALID_ARGUMENT");
   if(identity.Kind=="CACHE") return "cache-"+identity.Id+".db";
   if(identity.Kind=="OUTPUT") return "output-"+identity.Id+".log";
   throw new IOException("UNSUPPORTED");
  }

  public string[] OwnedNames() {
   var names=new List<string>();
   foreach(var entry in entries) { names.Add(entry.DataName); names.Add(entry.JournalName); }
   return names.ToArray();
  }
  public Dictionary<string,string> ConfigurationPaths(string admittedStage,string kind=null) {
   if(kind!=null&&kind!="CACHE"&&kind!="OUTPUT") throw new IOException("INVALID_ARGUMENT");
   var paths=new Dictionary<string,string>(StringComparer.Ordinal);
   foreach(var entry in entries)
    if(kind==null||entry.Kind==kind) paths.Add("vpn-control-mutable:"+entry.Id,Path.Combine(admittedStage,entry.DataName));
   return kind!=null&&paths.Count==0?null:paths;
  }
  public void CaptureAtCommit() {
   lock(sync) {
    if(prepared||disposed||publisher!=null) throw new IOException("CONFLICT");
    // Capture is one-shot even if a later resource fails. Neither a retry nor recovery can erase
    // the first journal and silently retarget a different version of the ordinary destination.
    prepared=true;
    foreach(var entry in entries) {
     entry.Journal=privateFile(entry.JournalName,FileMode.CreateNew);
     using(var cache=privateFile(entry.DataName,FileMode.CreateNew)) entry.Lease.CaptureAtCommit(cache,entry.Journal);
     entry.Captured=true;
     // Close the seed writer before sing-box opens its private database or appends to its private
     // log. Both begin with the latest ordinary bytes after A stopped; no user path reaches B.
    }
   }
  }
  public void MarkCommitIntent() {
   lock(sync) {
    if(!prepared||disposed||publisher!=null||commitIntent) throw new IOException("CONFLICT");
    foreach(var entry in entries) if(!entry.Captured) throw new IOException("CONFLICT");
    commitIntent=true;
   }
  }
  public void BeginPublicationAfterExit() {
   lock(sync) {
    if(disposed) throw new IOException("CONFLICT");
    if(publisher!=null||result!=null) return;
    if(!exactChildExited()) throw new IOException("BUSY");
    if(!commitIntent) {
     var known=new List<PublicationResult>();
     foreach(var entry in entries) known.Add(new PublicationResult(binding.JobId,entry.Id,"NO_MUTABLE_HANDOFF",null));
     result=known.ToArray(); return;
    }
    publisher=new Thread(Publish); publisher.IsBackground=false; publisher.Start();
   }
  }
  void Publish() {
   var completed=new List<PublicationResult>();
   foreach(var entry in entries) {
    try {
     using(var bytes=privateFile(entry.DataName,FileMode.Open))
      completed.Add(entry.Lease.PublishAfterExit(bytes,exactChildExited));
    } catch(Exception failure) {
     string code=failure.Message;
     if(code!="PERMISSION_DENIED"&&code!="CONFLICT"&&code!="OUTCOME_UNKNOWN") code="PERSISTENCE_FAILED";
     completed.Add(new PublicationResult(binding.JobId,entry.Id,"PENDING_PUBLICATION",code));
    }
   }
   lock(sync) result=completed.ToArray();
  }
  public PublicationResult[] Snapshot() {
   lock(sync) return result==null?null:(PublicationResult[])result.Clone();
  }
  public void WaitForPublication() {
   Thread worker; lock(sync) worker=publisher;
   if(worker!=null) worker.Join(); // Fixed helper cleanup, never the controller's status thread.
  }
  public void CloseRetainedStreams() {
   lock(sync) {
    if(disposed) return;
    if(publisher!=null&&publisher.IsAlive) throw new IOException("BUSY");
    foreach(var entry in entries) {
     if(entry.Journal!=null) { entry.Journal.Dispose(); entry.Journal=null; }
    }
    disposed=true;
   }
  }
 }

 /** The fixed broker creates the concrete adapter from admitted native storage. The internal
  * behavior seam exercises ordering without allowing pipe callers to supply native outcome flags.
  */
 internal sealed class RuntimeResourceLifecycle {
  // Only the fixed broker supplies this admitted storage. It never comes from a wire flag.
  internal interface TerminalStorage {
   byte[] CapturePrivateInputManifest();
   void DisposePrivateInputs(byte[] manifest);
   void PublishTerminal(byte[] record);
   byte[] ReadTerminal();
  }
  internal interface Batch {
   void CaptureAtCommit(); void MarkCommitIntent(); void BeginPublicationAfterExit();
   PublicationResult[] Snapshot(); void WaitForPublication(); void CloseRetainedStreams();
  }
  sealed class NativeBatch : Batch {
   readonly RuntimeCacheResources value;
   internal NativeBatch(RuntimeCacheResources batch) { value=batch; }
   public void CaptureAtCommit() { value.CaptureAtCommit(); }
   public void MarkCommitIntent() { value.MarkCommitIntent(); }
   public void BeginPublicationAfterExit() { value.BeginPublicationAfterExit(); }
   public PublicationResult[] Snapshot() { return value.Snapshot(); }
   public void WaitForPublication() { value.WaitForPublication(); }
   public void CloseRetainedStreams() { value.CloseRetainedStreams(); }
  }
  readonly RuntimeResourceBinding binding;
  readonly Batch batch;
  readonly ResourceAdmissionGate gate;
  readonly Func<bool> exactChildExited;
  internal TerminalStorage RetainedTerminalStorage { get; private set; }
  bool attempted,closed,terminalConfirmed;
  PublicationResult[] retainedPublication;
  byte[] retainedManifest;
  internal RuntimeResourceLifecycle(RuntimeResourceBinding admitted,RuntimeCacheResources resources,
    ResourceAdmissionGate admission,Func<bool> retainedNativeChildExited)
   : this(admitted,new NativeBatch(resources),admission,retainedNativeChildExited) { }
  internal RuntimeResourceLifecycle(RuntimeResourceBinding admitted,RuntimeCacheResources resources,
    ResourceAdmissionGate admission,Func<bool> retainedNativeChildExited,TerminalStorage terminalStorage)
   : this(admitted,new NativeBatch(resources),admission,retainedNativeChildExited,terminalStorage) { }
  internal RuntimeResourceLifecycle(RuntimeResourceBinding admitted,Batch resources,
    ResourceAdmissionGate admission,Func<bool> retainedNativeChildExited) {
   if(admitted==null||resources==null||admission==null||retainedNativeChildExited==null||
     admission.AdmissionClosed||!admission.HadOriginalAdmission||!admission.Matches(admitted)) throw new IOException("CONFLICT");
   binding=admitted;batch=resources;gate=admission;exactChildExited=retainedNativeChildExited;
  }
  internal RuntimeResourceLifecycle(RuntimeResourceBinding admitted,Batch resources,
    ResourceAdmissionGate admission,Func<bool> retainedNativeChildExited,TerminalStorage terminalStorage)
   : this(admitted,resources,admission,retainedNativeChildExited) {
   if(terminalStorage==null) throw new IOException("INVALID_ARGUMENT");
   RetainedTerminalStorage=terminalStorage;
  }
  internal void Commit(Action resumeExactSuspendedChild) {
   if(attempted||closed||resumeExactSuspendedChild==null) throw new IOException("CONFLICT");
   attempted=true;
   batch.CaptureAtCommit();
   gate.MarkCommitIntent(); // Durable before a possibly successful native resume.
   batch.MarkCommitIntent();
   resumeExactSuspendedChild();
  }
  internal PublicationResult[] AfterConfirmedExit() {
   if(!exactChildExited()) throw new IOException("BUSY");
   if(retainedPublication!=null) return (PublicationResult[])retainedPublication.Clone();
   var result=batch.Snapshot();
   if(result!=null) return result;
   batch.BeginPublicationAfterExit();
   result=batch.Snapshot();
   if(result!=null) return result;
   var pending=new List<PublicationResult>();
   foreach(var resource in binding.Resources)
    pending.Add(new PublicationResult(binding.JobId,resource.Id,"PENDING_PUBLICATION","OUTCOME_UNKNOWN"));
   return pending.ToArray();
  }
  internal void FinishAfterConfirmedExit() {
   if(closed) return;
   if(!exactChildExited()) throw new IOException("BUSY");
   // A validated durable intent is sufficient to resume exact private disposal. Never reread
   // inputs that a prior attempt may already have deleted, or repeat ordinary publication.
   byte[] receipt=RetainedTerminalStorage==null?null:RetainedTerminalStorage.ReadTerminal();
   if(receipt!=null) retainedPublication=ReadTerminalReceipt(receipt);
   else {
    batch.BeginPublicationAfterExit();batch.WaitForPublication();
    var published=KnownTerminalPublication();
    batch.CloseRetainedStreams();
    if(RetainedTerminalStorage!=null) {
     byte[] manifest=RetainedTerminalStorage.CapturePrivateInputManifest();
     receipt=TerminalReceipt(manifest,published);
     RetainedTerminalStorage.PublishTerminal(receipt); // Durable BEFORE the first deletion.
     retainedPublication=ReadTerminalReceipt(receipt);
    }
   }
   batch.CloseRetainedStreams();
   if(RetainedTerminalStorage!=null) RetainedTerminalStorage.DisposePrivateInputs(retainedManifest);
   gate.CloseAfterNativeReconciliation();
   terminalConfirmed=RetainedTerminalStorage!=null;closed=true;
  }

  PublicationResult[] KnownTerminalPublication() {
   var known=batch.Snapshot();
   if(known==null||known.Length!=binding.Resources.Length) throw new IOException("OUTCOME_UNKNOWN");
   var byId=new Dictionary<string,PublicationResult>(StringComparer.Ordinal);
   foreach(var item in known) {
    if(item==null||item.JobId!=binding.JobId||byId.ContainsKey(item.ResourceId)) throw new IOException("CONFLICT");
    byId.Add(item.ResourceId,item);
   }
   foreach(var identity in binding.Resources) {
    PublicationResult item;if(!byId.TryGetValue(identity.Id,out item)) throw new IOException("CONFLICT");
    if(item.Code!=null||(item.Disposition!="PUBLISHED"&&item.Disposition!="NO_MUTABLE_HANDOFF"))
     throw new IOException("OUTCOME_UNKNOWN");
   }
   return known;
  }
  byte[] TerminalReceipt(byte[] manifest,PublicationResult[] published) {
   if(manifest==null||manifest.Length==0) throw new IOException("CONFLICT");
   using(var hash=System.Security.Cryptography.SHA256.Create()) {
    byte[] authority=hash.ComputeHash(binding.CanonicalBytes());
    using(var bytes=new MemoryStream()) using(var writer=new BinaryWriter(bytes,System.Text.Encoding.UTF8,true)) {
     writer.Write(3);writer.Write(authority);writer.Write(manifest.Length);writer.Write(manifest);writer.Write(published.Length);
     foreach(var item in published) { PublicationJournal.Text(writer,item.ResourceId);PublicationJournal.Text(writer,item.Disposition); }
     writer.Flush();byte[] payload=bytes.ToArray();writer.Write(hash.ComputeHash(payload));writer.Flush();return bytes.ToArray();
    }
   }
  }
  PublicationResult[] ReadTerminalReceipt(byte[] record) {
   try {
    if(record.Length<77) throw new IOException("CONFLICT");
    using(var hash=System.Security.Cryptography.SHA256.Create()) {
     byte[] checksum=hash.ComputeHash(record,0,record.Length-32);
     for(int i=0;i<32;i++) if(checksum[i]!=record[record.Length-32+i]) throw new IOException("CONFLICT");
     using(var bytes=new MemoryStream(record,0,record.Length-32,false))
     using(var reader=new BinaryReader(bytes,new System.Text.UTF8Encoding(false,true),true)) {
      if(reader.ReadInt32()!=3) throw new IOException("CONFLICT");
      byte[] authority=hash.ComputeHash(binding.CanonicalBytes());
      for(int i=0;i<32;i++) if(reader.ReadByte()!=authority[i]) throw new IOException("CONFLICT");
      int manifestLength=reader.ReadInt32();
      if(manifestLength<=0||manifestLength>bytes.Length-bytes.Position-4) throw new IOException("CONFLICT");
      byte[] manifest=reader.ReadBytes(manifestLength);
      if(reader.ReadInt32()!=binding.Resources.Length) throw new IOException("CONFLICT");
      var expected=new HashSet<string>(StringComparer.Ordinal);
      foreach(var identity in binding.Resources) expected.Add(identity.Id);
      var result=new List<PublicationResult>();
      for(int i=0;i<binding.Resources.Length;i++) {
       string id=PublicationJournal.Text(reader,36),disposition=PublicationJournal.Text(reader,32);
       if(!expected.Remove(id)||(disposition!="PUBLISHED"&&disposition!="NO_MUTABLE_HANDOFF")) throw new IOException("CONFLICT");
       result.Add(new PublicationResult(binding.JobId,id,disposition,null));
      }
      if(bytes.Position!=bytes.Length) throw new IOException("CONFLICT");
      retainedManifest=manifest;return result.ToArray();
     }
    }
   } catch(EndOfStreamException) { throw new IOException("CONFLICT"); }
     catch(System.Text.DecoderFallbackException) { throw new IOException("CONFLICT"); }
  }
  bool terminalResponseAttempted;
  internal void FinishAfterTransportClosed() {
   // Once terminal evidence was attempted, leave any remaining work for explicit
   // recovery rather than changing the reported outcome behind the caller.
   if(!terminalResponseAttempted) FinishAfterConfirmedExit();
  }
  internal void CompleteAndWriteTerminal(BinaryWriter writer,Action releaseRuntimeInputs) {
   if(releaseRuntimeInputs==null) throw new IOException("INVALID_ARGUMENT");
   // The fixed broker supplies its own retained config/log streams. Release them before
   // hashing/removing private inputs, then report the final publication and cleanup together.
   try {
    releaseRuntimeInputs();
    FinishAfterConfirmedExit();
   } catch(IOException) { /* Preserve durable intent and report cleanup unconfirmed. */ }
     catch(UnauthorizedAccessException) { /* Original evidence remains retained. */ }
   terminalResponseAttempted=true;
   WriteTerminal(writer);
  }
  internal void WriteTerminal(BinaryWriter writer) {
   var result=AfterConfirmedExit();var identities=binding.Resources;
   if(result.Length!=identities.Length) throw new IOException("CONFLICT");
   var byId=new Dictionary<string,PublicationResult>(StringComparer.Ordinal);
   foreach(var item in result) {
    if(item==null||item.JobId!=binding.JobId||byId.ContainsKey(item.ResourceId)) throw new IOException("CONFLICT");
    byId.Add(item.ResourceId,item);
   }
   writer.Write(1);PublicationJournal.Text(writer,binding.JobId);writer.Write(identities.Length);
   foreach(var identity in identities) {
    PublicationResult item;if(!byId.TryGetValue(identity.Id,out item)) throw new IOException("CONFLICT");
    byte disposition,code;
    switch(item.Disposition) {
     case "NO_MUTABLE_HANDOFF":disposition=0;break;
     case "PUBLISHED":disposition=1;break;
     case "PENDING_PUBLICATION":disposition=2;break;
     case "COMMITTED_CLEANUP_PENDING":disposition=3;break;
     default:throw new IOException("CONFLICT");
    }
    switch(item.Code) {
     case null:code=0;break;
     case "PERSISTENCE_FAILED":code=1;break;
     case "PERMISSION_DENIED":code=2;break;
     case "CONFLICT":code=3;break;
     case "OUTCOME_UNKNOWN":code=4;break;
     default:throw new IOException("CONFLICT");
    }
    if((disposition<2)!=(code==0)) throw new IOException("CONFLICT");
    PublicationJournal.Text(writer,identity.Id);writer.Write((byte)(identity.Kind=="CACHE"?0:1));
    writer.Write(disposition);writer.Write(code);
   }
   writer.Write(terminalConfirmed);
  }
 }
}

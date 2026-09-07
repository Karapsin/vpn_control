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
  public readonly RuntimeResourceBinding Binding;
  readonly MutableResourceInput[] inputs;
  RuntimeResourcePreparation(RuntimeResourceBinding binding,MutableResourceInput[] captured) {
   Binding=binding;inputs=captured;
  }
  public MutableResourceInput[] Inputs { get { return (MutableResourceInput[])inputs.Clone(); } }
  public override string ToString() { return "Native resource preparation (<redacted>)"; }
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
   public readonly string Id,DataName,JournalName;
   public readonly CacheLease Lease;
   public FileStream Journal;
   public bool Captured;
   public Entry(string id,CacheLease lease) {
    Id=id; DataName="cache-"+id+".db"; JournalName="publication-"+id+".journal"; Lease=lease;
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
    if(input==null||input.Identity.Kind!="CACHE") throw new IOException("UNSUPPORTED");
    identities.Add(input.Identity);
   }
   var expected=new RuntimeResourceBinding(admitted.JobId,admitted.ScopeId,admitted.ControllerId,
    admitted.NativeOwner,admitted.ScopeRecord,identities.ToArray());
   if(Convert.ToBase64String(expected.CanonicalBytes())!=Convert.ToBase64String(admitted.CanonicalBytes()))
    throw new IOException("CONFLICT");
   original.ValidateScope(admitted.ScopeRecord,admitted.ScopeId);
   // Recheck each ordinary parent before authorization readiness. Its bytes are deliberately not
   // captured yet: actual A may still be writing its cache until the manager commits replacement.
   foreach(var input in captured) {
    var current=original.AdmitDestination(input.Destination.Path);
    if(current.ParentIdentity!=input.Destination.ParentIdentity||
      !String.Equals(current.Path,input.Destination.Path,StringComparison.OrdinalIgnoreCase)) throw new IOException("CONFLICT");
    entries.Add(new Entry(input.Identity.Id,new CacheLease(original,input.Destination,admitted.JobId,
     input.Identity.Id,admitted.ScopeId,admitted.ControllerId,admitted.ScopeRecord)));
   }
   binding=admitted; privateFile=openAdmittedPrivateFile; exactChildExited=retainedNativeChildExited;
  }
  public override string ToString() { return "Owned runtime cache batch (<redacted>)"; }

  public string[] OwnedNames() {
   var names=new List<string>();
   foreach(var entry in entries) { names.Add(entry.DataName); names.Add(entry.JournalName); }
   return names.ToArray();
  }
  public Dictionary<string,string> ConfigurationPaths(string admittedStage) {
   var paths=new Dictionary<string,string>(StringComparer.Ordinal);
   foreach(var entry in entries) paths.Add("vpn-control-mutable:"+entry.Id,Path.Combine(admittedStage,entry.DataName));
   return paths;
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
     // Close the cache writer before sing-box opens or replaces its private database. The retained
     // protected directory and native child identity guard later reads; no user path is reopened.
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
}

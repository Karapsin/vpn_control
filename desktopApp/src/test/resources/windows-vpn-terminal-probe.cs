using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;
using VpnScopedStorage;

// Same-assembly ordinary-file fixture. No runtime, UAC, installer, or token impersonation.
internal static class RuntimeTerminalProbe {
 sealed class Batch : RuntimeResourceLifecycle.Batch {
  internal PublicationResult[] Result;
  internal int CloseFailures,CommitCalls; internal bool CaptureFails,BeginFails;
  public void CaptureAtCommit() { if(CaptureFails) throw new IOException("CONFLICT"); }
  public void MarkCommitIntent() { CommitCalls++; }
  public void BeginPublicationAfterExit() { if(BeginFails) throw new IOException("CONFLICT"); }
  public PublicationResult[] Snapshot() { return Result; }
  public void WaitForPublication() { }
  public void CloseRetainedStreams() {
   if(CloseFailures-- >0) throw new IOException("PERSISTENCE_FAILED");
  }
 }
 sealed class Storage : RuntimeResourceLifecycle.TerminalStorage {
  internal readonly string Payload,Receipt;
  internal int DisposeFailures,PartialDeleteFailures,PreWriteFailures,PublishFailures,Disposals,Publications;
  internal Storage(string root) {
   Payload=Path.Combine(root,"owned-private-input");Receipt=Path.Combine(root,"terminal-receipt");
   File.WriteAllText(Payload,"fixture-private-input",new UTF8Encoding(false,true));
  }
  public byte[] CapturePrivateInputManifest() {
   using(var input=File.OpenRead(Payload)) using(var hash=SHA256.Create()) return hash.ComputeHash(input);
  }
  public void DisposePrivateInputs(byte[] manifest) {
   if(DisposeFailures-- >0) throw new IOException("PERSISTENCE_FAILED");
   File.Delete(Payload);Disposals++;
   if(PartialDeleteFailures-- >0) throw new IOException("PERSISTENCE_FAILED");
  }
  public void PublishTerminal(byte[] record) {
   if(PreWriteFailures-- >0) throw new IOException("PERSISTENCE_FAILED");
   using(var output=new FileStream(Receipt,FileMode.CreateNew,FileAccess.Write,FileShare.None)) {
    output.Write(record,0,record.Length);output.Flush(true);Publications++;
   }
   if(PublishFailures-- >0) throw new IOException("PERSISTENCE_FAILED");
  }
  public byte[] ReadTerminal() { try { return File.ReadAllBytes(Receipt); } catch(FileNotFoundException) { return null; } }
 }
 sealed class GateStorage : FileStream {
  internal bool FailFlush;
  internal GateStorage(string path):base(path,FileMode.CreateNew,FileAccess.ReadWrite,FileShare.None) { }
  public override void Flush(bool flushToDisk) {
   if(FailFlush) throw new IOException("PERSISTENCE_FAILED");
   base.Flush(flushToDisk);
  }
 }
 static void Need(bool value,string message) { if(!value) throw new Exception(message); }
 static void Fails(string expected,Action action) {
  try { action(); } catch(IOException error) { Need(error.Message==expected,"Unexpected failure: "+error.Message);return; }
  throw new Exception("Expected "+expected);
 }
 static bool Confirmed(RuntimeResourceLifecycle flow) {
  using(var bytes=new MemoryStream()) {
   using(var writer=new BinaryWriter(bytes,Encoding.UTF8,true)) flow.WriteTerminal(writer);
   return bytes.ToArray()[bytes.Length-1]==1;
  }
 }
 static RuntimeResourceBinding Binding(string root,string job=null) {
  string hash=new string('a',64),identity=new string('a',24);
  return new RuntimeResourceBinding(job??"00000000-0000-0000-0000-000000000001",
   "00000000-0000-0000-0000-000000000002","00000000-0000-0000-0000-000000000003",
   new OwnerIdentity(912,134332558909139351,"S-1-5-21-1-2-3-1001"),
   new Target(Path.Combine(root,"scope"),identity,identity,1,hash),
   new[]{new ResourceIdentity("00000000-0000-0000-0000-000000000004","OUTPUT")});
 }
 static void Case(string root,int scenario) {
  Directory.CreateDirectory(root);var binding=Binding(root);var storage=new Storage(root);
  using(var admission=new GateStorage(Path.Combine(root,"admission"))) {
   var gate=ResourceAdmissionGate.CreateForOriginal(admission,binding,()=>true);
   bool exited=scenario!=2;var batch=new Batch();
   var flow=new RuntimeResourceLifecycle(binding,batch,gate,()=>exited,storage);
   if(scenario!=1) flow.Commit(()=>{});
   string disposition=scenario==1?"NO_MUTABLE_HANDOFF":scenario==5?"PENDING_PUBLICATION":"PUBLISHED";
   batch.Result=new[]{new PublicationResult(binding.JobId,binding.Resources[0].Id,disposition,scenario==5?"CONFLICT":null)};
   if(scenario==13) {
    storage.DisposeFailures=1;
    using(var bytes=new MemoryStream()) {
     using(var writer=new BinaryWriter(bytes,Encoding.UTF8,true)) flow.CompleteAndWriteTerminal(writer,()=>{});
     Need(bytes.ToArray()[bytes.Length-1]==0,"Cleanup failure reported confirmed");
     flow.FinishAfterTransportClosed();
     Need(File.Exists(storage.Payload)&&!Confirmed(flow),"Post-response finalizer changed reported cleanup outcome");
    }
   } else if(scenario==12) {
    bool released=false;
    using(var bytes=new MemoryStream()) {
     using(var writer=new BinaryWriter(bytes,Encoding.UTF8,true)) flow.CompleteAndWriteTerminal(writer,()=>released=true);
     Need(released,"Terminal response preceded input release");
     Need(bytes.ToArray()[bytes.Length-1]==1,"Terminal response preceded authoritative cleanup");
     Need(!File.Exists(storage.Payload)&&File.Exists(storage.Receipt),"Final response lacks durable cleanup");
    }
   } else if(scenario==2) {
    Fails("BUSY",()=>flow.FinishAfterConfirmedExit());
    Need(File.Exists(storage.Payload)&&!File.Exists(storage.Receipt),"Live child lost private inputs");
   } else if(scenario==5) {
    Fails("OUTCOME_UNKNOWN",()=>flow.FinishAfterConfirmedExit());
    Need(File.Exists(storage.Payload)&&!File.Exists(storage.Receipt)&&!Confirmed(flow),"Failed publication was disposed or confirmed");
   } else if(scenario==6) {
    storage.PreWriteFailures=1;
    Fails("PERSISTENCE_FAILED",()=>flow.FinishAfterConfirmedExit());
    Need(File.Exists(storage.Payload)&&!File.Exists(storage.Receipt),"Pre-write failure deleted input or created a receipt");
   } else if(scenario==7) {
    storage.PartialDeleteFailures=1;
    Fails("PERSISTENCE_FAILED",()=>flow.FinishAfterConfirmedExit());
    Need(!File.Exists(storage.Payload)&&File.Exists(storage.Receipt),"Partial deletion did not retain its durable cleanup intent");
    var coldBatch=new Batch();coldBatch.CaptureFails=true;coldBatch.BeginFails=true;
    var recreated=new RuntimeResourceLifecycle(binding,coldBatch,gate,()=>true,storage);
    recreated.FinishAfterConfirmedExit();
    Need(storage.Publications==1&&File.Exists(storage.Receipt),"Cold reconciliation reread a deleted input or duplicated terminal publication");
   } else if(scenario==8) {
    storage.PublishFailures=1;
    Fails("PERSISTENCE_FAILED",()=>flow.FinishAfterConfirmedExit());
    Need(File.Exists(storage.Payload)&&File.Exists(storage.Receipt),"Post-write acknowledgement loss lost durable intent or input");
   } else if(scenario==9) {
    File.WriteAllBytes(storage.Receipt,new byte[]{2,7,9});
    Fails("CONFLICT",()=>flow.FinishAfterConfirmedExit());
    Need(File.Exists(storage.Payload),"Corrupt receipt deleted private input");
   } else if(scenario==10) {
    string foreignRoot=Path.Combine(root,"foreign");Directory.CreateDirectory(foreignRoot);
    var foreignBinding=Binding(foreignRoot,"00000000-0000-0000-0000-000000000099");var foreignStorage=new Storage(foreignRoot);
    using(var foreignAdmission=new FileStream(Path.Combine(foreignRoot,"admission"),FileMode.CreateNew,FileAccess.ReadWrite,FileShare.None)) {
     var foreignGate=ResourceAdmissionGate.CreateForOriginal(foreignAdmission,foreignBinding,()=>true);var foreignBatch=new Batch();
     foreignBatch.Result=new[]{new PublicationResult(foreignBinding.JobId,foreignBinding.Resources[0].Id,"PUBLISHED",null)};
     var foreignFlow=new RuntimeResourceLifecycle(foreignBinding,foreignBatch,foreignGate,()=>true,foreignStorage);foreignFlow.Commit(()=>{});
     foreignStorage.DisposeFailures=1;Fails("PERSISTENCE_FAILED",()=>foreignFlow.FinishAfterConfirmedExit());
     File.Copy(foreignStorage.Receipt,storage.Receipt);
    }
    Fails("CONFLICT",()=>flow.FinishAfterConfirmedExit());
    Need(File.Exists(storage.Payload),"Foreign valid receipt deleted target input");
    foreach(var name in new[]{"owned-private-input","terminal-receipt","admission"}) File.Delete(Path.Combine(foreignRoot,name));
    Directory.Delete(foreignRoot);
   } else if(scenario==11) {
    admission.FailFlush=true;
    Fails("PERSISTENCE_FAILED",()=>flow.FinishAfterConfirmedExit());
    Need(File.Exists(storage.Receipt)&&!Confirmed(flow),"Gate-close failure falsely confirmed terminal cleanup");
   } else {
    if(scenario==3) batch.CloseFailures=1;
    if(scenario==4) storage.DisposeFailures=1;
    if(scenario==3||scenario==4) {
     Fails("PERSISTENCE_FAILED",()=>flow.FinishAfterConfirmedExit());
     Need(File.Exists(storage.Payload)&&!Confirmed(flow),"Failed cleanup discarded private input");
     Need(scenario==3?!File.Exists(storage.Receipt):File.Exists(storage.Receipt),"Cleanup intent ordering changed");
    }
    flow.FinishAfterConfirmedExit();
    Need(!File.Exists(storage.Payload),"Successful publication left private runtime inputs");
    Need(File.Exists(storage.Receipt)&&Confirmed(flow),"Successful disposal lacks bound terminal confirmation");
    flow.FinishAfterConfirmedExit();
    Need(storage.Disposals==1&&storage.Publications==1,"Confirmed cleanup was replayed");
    Need(batch.CommitCalls==(scenario==1?0:1),"Cleanup replayed runtime commit");
   }
  }
  // Exact inert fixture files only; never recursive product cleanup.
  foreach(var name in new[]{"owned-private-input","terminal-receipt","admission"}) File.Delete(Path.Combine(root,name));
  Directory.Delete(root);
 }
 public static int Main(string[] args) {
  if(args.Length!=1) return 2;int failed=0;
  for(int scenario=0;scenario<14;scenario++) {
   try { Case(Path.Combine(args[0],"terminal-"+scenario),scenario);Console.WriteLine("PASS "+scenario); }
   catch(Exception error) { failed++;Console.WriteLine("FAIL "+scenario+" "+error.Message); }
  }
  Console.WriteLine("TERMINAL_PROBE selected=14 failed="+failed);return failed==0?0:1;
 }
}

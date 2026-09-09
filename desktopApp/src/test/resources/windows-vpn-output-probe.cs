using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Collections.Generic;
using VpnScopedStorage;
using VpnScopedConfiguration;

// Inert original-user IO and the actual production parser/batch. No child, installer, UAC or VPN.
public static class OutputProbe {
 static int selected,failed;
 static void Need(bool value,string message) { if(!value) throw new Exception(message); }
 static void Case(string name,Action action) {
  selected++;
  try { action(); Console.WriteLine("PASS "+name); }
  catch(Exception error) { failed++;Console.Error.WriteLine("FAIL "+name+" "+error); }
 }
 static void Protect(string path,string sid) {
  var acl=new FileSecurity();acl.SetAccessRuleProtection(true,false);acl.SetOwner(new SecurityIdentifier(sid));
  acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid),FileSystemRights.FullControl,AccessControlType.Allow));
  FileSystemAclExtensions.SetAccessControl(new FileInfo(path),acl);
 }
 static void WritePrefix(string path,int bytes) {
  using(var output=new FileStream(path,FileMode.Create,FileAccess.Write,FileShare.Read)) {
   var block=new byte[65536];Array.Fill(block,(byte)'A');
   while(bytes>0) { int count=Math.Min(block.Length,bytes);output.Write(block,0,count);bytes-=count; }
   output.Flush(true);
  }
 }
 static string Hash(string path) {
  using(var input=File.OpenRead(path))using(var hash=System.Security.Cryptography.SHA256.Create())
   return Convert.ToHexString(hash.ComputeHash(input));
 }
 static void Batch(string root,int scenario) {
  Directory.CreateDirectory(root);
  string scope=Guid.NewGuid().ToString("D"),controller=Guid.NewGuid().ToString("D"),resource=Guid.NewGuid().ToString("D");
  string scopePath=Path.Combine(root,"scope.json"),target=Path.Combine(root,"user-output.log");
  string sid=WindowsIdentity.GetCurrent().User.Value;
  File.WriteAllText(scopePath,"{\"schemaVersion\":1,\"scopeId\":\""+scope+"\"}",new UTF8Encoding(false,true));Protect(scopePath,sid);
  using(var owner=System.Diagnostics.Process.GetCurrentProcess())using(var original=new OriginalUser(owner.Handle,sid)) {
   var proof=original.Capture(scopePath);var destination=original.AdmitDestination(target);
   var identity=new ResourceIdentity(resource,"OUTPUT");
   var binding=new RuntimeResourceBinding(Guid.NewGuid().ToString("D"),scope,controller,original.Owner,proof,new[]{identity});
   bool exited=false;
   var batch=new RuntimeCacheResources(original,binding,new[]{new MutableResourceInput(identity,destination)},
    (name,mode)=>new FileStream(Path.Combine(root,name),mode,FileAccess.ReadWrite,FileShare.Read,65536,FileOptions.WriteThrough),()=>exited);
   try {
    // Admission preceded both writes. This is the latest A data at commit, never a preparation snapshot.
    if(scenario!=1) { WritePrefix(target,scenario==4?9*1024*1024:8);File.AppendAllText(target,"|late-A",new UTF8Encoding(false)); }
    batch.CaptureAtCommit();
    Need(batch.ConfigurationPaths(root,"CACHE")==null,"OUTPUT acquired CACHE path authority");
    string retained=batch.ConfigurationPaths(root,"OUTPUT")["vpn-control-mutable:"+resource];
    Need(Path.GetFileName(retained)=="output-"+resource+".log","OUTPUT lost its owned file kind");
    Need(scenario==1?new FileInfo(retained).Length==0:Hash(target)==Hash(retained),"Lost latest A prefix");
    File.AppendAllText(retained,"|owned-B",new UTF8Encoding(false));
    if(scenario!=3) batch.MarkCommitIntent();
    bool busy=false;try { batch.BeginPublicationAfterExit(); }catch(IOException e) { busy=e.Message=="BUSY"; }
    Need(busy,"Published before exact exit");
    if(scenario==2) File.WriteAllText(target,"external-writer",new UTF8Encoding(false));
    exited=true;batch.BeginPublicationAfterExit();batch.WaitForPublication();var results=batch.Snapshot();
    Need(results!=null&&results.Length==1,"Missing publication result");
    if(scenario==2) {
     Need(results[0].Disposition=="PENDING_PUBLICATION"&&results[0].Code=="CONFLICT"&&File.ReadAllText(target)=="external-writer","Overwrote external writer");
     Need(File.ReadAllText(retained).EndsWith("|late-A|owned-B"),"Lost pending output bytes");
    } else if(scenario==3) {
     Need(results[0].Disposition=="NO_MUTABLE_HANDOFF"&&!File.ReadAllText(target).Contains("owned-B"),"Aborted output became authoritative");
    } else {
     Need(results[0].Disposition=="PUBLISHED"&&results[0].Code==null&&Hash(target)==Hash(retained),"Output publication mismatch");
     Need(File.ReadAllText(target).EndsWith(scenario==1?"|owned-B":"|late-A|owned-B"),"Append prefix mismatch");
     File.WriteAllText(target,"later-user-write",new UTF8Encoding(false));batch.BeginPublicationAfterExit();batch.WaitForPublication();
     Need(File.ReadAllText(target)=="later-user-write","Publication replayed");
    }
   } finally { exited=true;batch.WaitForPublication();batch.CloseRetainedStreams(); }
   foreach(string name in batch.OwnedNames())File.Delete(Path.Combine(root,name));
  }
  File.Delete(target);File.Delete(scopePath);Directory.Delete(root);
 }
 static void RetainedScope(string root) {
  Directory.CreateDirectory(root);string scope=Guid.NewGuid().ToString("D"),sid=WindowsIdentity.GetCurrent().User.Value;
  string path=Path.Combine(root,"scope.json");
  File.WriteAllText(path,"{\"schemaVersion\":1,\"scopeId\":\""+scope+"\"}",new UTF8Encoding(false,true));Protect(path,sid);
  using(var process=System.Diagnostics.Process.GetCurrentProcess())using(var original=new OriginalUser(process.Handle,sid)) {
   var captured=original.Capture(path);original.ValidateScope(captured,scope);
  }
  File.Delete(path);Directory.Delete(root);
 }
 static void RetainedCopy(string root) {
  Directory.CreateDirectory(root);string sid=WindowsIdentity.GetCurrent().User.Value;
  string path=Path.Combine(root,"input.bin"),copy=Path.Combine(root,"copy.bin");WritePrefix(path,9*1024*1024+17);
  using(var process=System.Diagnostics.Process.GetCurrentProcess())using(var original=new OriginalUser(process.Handle,sid)) {
   var captured=original.Capture(path);
   using(var output=new FileStream(copy,FileMode.CreateNew,FileAccess.Write))Need(original.CopyInput(captured,output),"Input disappeared");
   Need(new FileInfo(copy).Length==captured.ByteCount&&Hash(path)==Hash(copy),"Retained native handle copied from the wrong position");
  }
  File.Delete(path);File.Delete(copy);Directory.Delete(root);
 }
 const string OutputReference="vpn-control-mutable:00000000-0000-0000-0000-000000000042";
 const string CacheReference="vpn-control-mutable:00000000-0000-0000-0000-000000000043";
 static Dictionary<string,string> OutputPaths(string root) { return new Dictionary<string,string>(StringComparer.Ordinal) {{OutputReference,Path.Combine(root,"output.log")}}; }
 static Dictionary<string,string> CachePaths(string root) { return new Dictionary<string,string>(StringComparer.Ordinal) {{CacheReference,Path.Combine(root,"cache.db")}}; }
 static string LogConfig(string reference) { return "{\"log\":{\"output\":"+JsonSerializer.Serialize(reference)+"}}"; }
 static void RejectConfig(string text,string root,Dictionary<string,string> caches=null,Dictionary<string,string> outputs=null) {
  bool rejected=false;try { VpnRuntimeBroker.NormalizeConfiguration(text,root,null,caches,outputs); }catch(ArgumentException e) { rejected=e.Message=="INVALID_ARGUMENT"; }
  Need(rejected,"Unexpected configuration admission");
 }
 static void DuplicateDestination(string root) {
  Directory.CreateDirectory(root);string scope=Guid.NewGuid().ToString("D"),controller=Guid.NewGuid().ToString("D"),sid=WindowsIdentity.GetCurrent().User.Value;
  string scopePath=Path.Combine(root,"scope.json"),target=Path.Combine(root,"shared.db");
  File.WriteAllText(scopePath,"{\"schemaVersion\":1,\"scopeId\":\""+scope+"\"}",new UTF8Encoding(false,true));Protect(scopePath,sid);
  using(var process=System.Diagnostics.Process.GetCurrentProcess())using(var original=new OriginalUser(process.Handle,sid)) {
   var first=new ResourceIdentity(Guid.NewGuid().ToString("D"),"CACHE");var second=new ResourceIdentity(Guid.NewGuid().ToString("D"),"OUTPUT");
   var binding=new RuntimeResourceBinding(Guid.NewGuid().ToString("D"),scope,controller,original.Owner,original.Capture(scopePath),new[]{first,second});
   int opens=0;bool rejected=false;RuntimeCacheResources batch=null;
   try {
    batch=new RuntimeCacheResources(original,binding,new[]{new MutableResourceInput(first,original.AdmitDestination(target)),new MutableResourceInput(second,original.AdmitDestination(target.ToUpperInvariant()))},
     (name,mode)=>{opens++;throw new Exception("Duplicate intent reached protected file creation");},()=>false);
   }catch(IOException e) { rejected=e.Message=="CONFLICT"; }
   finally { if(batch!=null)batch.CloseRetainedStreams(); }
   Need(rejected&&opens==0&&!File.Exists(target),"Same physical destination accepted for competing CACHE and OUTPUT jobs");
  }
  File.Delete(scopePath);Directory.Delete(root);
 }
 public static int Main(string[] args) {
  Need(args.Length==1&&Directory.Exists(args[0])&&Directory.GetFileSystemEntries(args[0]).Length==0,"New owned fixture root required");
  Console.WriteLine("OUTPUT_CONTEXT framework="+System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription+" process="+System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture+" os="+System.Runtime.InteropServices.RuntimeInformation.OSArchitecture);
  foreach(string destination in new[]{"","stdout","stderr"}) {
   string selectedDestination=destination;
   Case("console:"+destination,()=>{
    string input="{\"log\":{\"output\":"+JsonSerializer.Serialize(selectedDestination)+"}}";
    using(var parsed=JsonDocument.Parse(VpnRuntimeBroker.NormalizeConfiguration(input,args[0])))
     Need(parsed.RootElement.GetProperty("log").GetProperty("output").GetString()==selectedDestination,"Changed console semantics");
   });
  }
  Case("disabled-output",()=>{
   using(var parsed=JsonDocument.Parse(VpnRuntimeBroker.NormalizeConfiguration("{\"log\":{\"disabled\":true,\"output\":\"unused.log\"}}",args[0])))
    Need(parsed.RootElement.GetProperty("log").GetProperty("output").GetString()=="","Unused output path survived");
  });
  Case("retained-scope-reread",()=>RetainedScope(Path.Combine(args[0],"retained-scope")));
  Case("retained-input-copy",()=>RetainedCopy(Path.Combine(args[0],"retained-copy")));
  Case("output-file-binding",()=>{
   var paths=OutputPaths(args[0]);using(var parsed=JsonDocument.Parse(VpnRuntimeBroker.NormalizeConfiguration(LogConfig(OutputReference),args[0],null,null,paths)))
    Need(parsed.RootElement.GetProperty("log").GetProperty("output").GetString()==paths[OutputReference],"Output reference did not bind private file");
  });
  Case("cache-output-distinct-bindings",()=>{
   var outputs=OutputPaths(args[0]);var caches=CachePaths(args[0]);
   string text="{\"log\":{\"output\":\""+OutputReference+"\"},\"experimental\":{\"cache_file\":{\"enabled\":true,\"path\":\""+CacheReference+"\",\"cache_id\":\"preserve\"}}}";
   using(var parsed=JsonDocument.Parse(VpnRuntimeBroker.NormalizeConfiguration(text,args[0],null,caches,outputs))) {
    Need(parsed.RootElement.GetProperty("log").GetProperty("output").GetString()==outputs[OutputReference],"Output kind lost");
    Need(parsed.RootElement.GetProperty("experimental").GetProperty("cache_file").GetProperty("path").GetString()==caches[CacheReference],"Cache kind lost");
   }
  });
  Case("kind-specific-configuration-rejections",()=>{
   var outputs=OutputPaths(args[0]);var caches=CachePaths(args[0]);
   RejectConfig(LogConfig(CacheReference),args[0],caches,null);
   RejectConfig("{\"experimental\":{\"cache_file\":{\"enabled\":true,\"path\":\""+OutputReference+"\"}}}",args[0],null,outputs);
   RejectConfig("{\"child\":{\"log\":{\"output\":\""+OutputReference+"\"}}}",args[0],null,outputs);
   RejectConfig(LogConfig("stdout"),args[0],null,outputs);
   RejectConfig(LogConfig("foreign.log"),args[0],null,outputs);
   foreach(string text in new[]{"{\"log\":{\"output\":false}}","{\"log\":{\"disabled\":\"true\",\"output\":\"stdout\"}}","{\"log\":{\"output\":null}}"})RejectConfig(text,args[0]);
  });
  Case("disabled-cache-metadata-with-output",()=>{
   string text="{\"log\":{\"output\":\""+OutputReference+"\"},\"experimental\":{\"cache_file\":{\"enabled\":false,\"path\":\"cache.db\",\"cache_id\":\"preserve\",\"store_fakeip\":true}}}";
   using(var parsed=JsonDocument.Parse(VpnRuntimeBroker.NormalizeConfiguration(text,args[0],null,null,OutputPaths(args[0])))) {
    var cache=parsed.RootElement.GetProperty("experimental").GetProperty("cache_file");
    Need(!cache.GetProperty("enabled").GetBoolean()&&cache.GetProperty("cache_id").GetString()=="preserve","Disabled cache metadata changed");
   }
  });
  Case("output-logical-document-over-frame-size",()=>{
   string payload=new string('x',9*1024*1024);
   string text="{\"log\":{\"output\":\""+OutputReference+"\"},\"opaque\":\""+payload+"\"}";
   using(var parsed=JsonDocument.Parse(VpnRuntimeBroker.NormalizeConfiguration(text,args[0],null,null,OutputPaths(args[0]))))
    Need(parsed.RootElement.GetProperty("opaque").GetString()==payload,"Output configuration capped at control frame size");
  });
  Case("duplicate-mutable-destination",()=>DuplicateDestination(Path.Combine(args[0],"duplicate-destination")));
  for(int scenario=0;scenario<5;scenario++) { int current=scenario;Case("output-batch:"+scenario,()=>Batch(Path.Combine(args[0],"batch-"+current),current)); }
  Console.WriteLine("OUTPUT_PROBE selected="+selected+" failed="+failed);return failed==0?0:1;
 }
}

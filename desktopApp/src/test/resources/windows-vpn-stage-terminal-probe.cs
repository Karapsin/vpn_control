using System;
using System.IO;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using VpnScopedStorage;

// Opt-in SYSTEM fixture: protected disposable stage only, with no broker child, pipe, runtime or UAC.
internal static class RuntimeStageTerminalProbe {
 static SafeFileHandle Pin(string path,System.Collections.Generic.List<SafeFileHandle> retained) {
  var method=typeof(VpnRuntimeBroker).GetMethod("Pin",BindingFlags.Static|BindingFlags.NonPublic);
  try { return (SafeFileHandle)method.Invoke(null,new object[]{path,true,retained}); }
  catch(TargetInvocationException error) { throw error.InnerException; }
 }
 static void Need(bool value,string message) { if(!value) throw new Exception(message); }
 static void Fails(Action action) { try { action(); } catch(IOException) { return; } throw new Exception("Expected protected rejection"); }
 static void Protect(string path) {
  var acl=new DirectorySecurity();acl.SetOwner(new SecurityIdentifier("S-1-5-32-544"));acl.SetAccessRuleProtection(true,false);
  foreach(var sid in new[]{"S-1-5-18","S-1-5-32-544"}) acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid),FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
  new DirectoryInfo(path).SetAccessControl(acl);
 }
 static VpnRuntimeBroker.StageTerminalStorage Storage(string root,out SafeFileHandle pin,out FileStream gate,System.Collections.Generic.List<SafeFileHandle> retained) {
  Directory.CreateDirectory(root);Protect(root);gate=new FileStream(Path.Combine(root,".admission"),FileMode.CreateNew,FileAccess.ReadWrite,FileShare.None);gate.WriteByte(1);gate.Flush(true);File.WriteAllText(Path.Combine(root,"payload"),"original");
  pin=Pin(root,retained);return new VpnRuntimeBroker.StageTerminalStorage(root,pin,new System.Collections.Generic.List<string>{"payload"},new System.Collections.Generic.List<string>());
 }
 static void Case(string root,int scenario) {
  SafeFileHandle pin=null;FileStream gate=null;var retained=new System.Collections.Generic.List<SafeFileHandle>();try {
   var storage=Storage(root,out pin,out gate,retained);byte[] manifest=storage.CapturePrivateInputManifest();storage.PublishTerminal(new byte[]{1});
   if(scenario==0) { File.WriteAllText(Path.Combine(root,"payload"),"altered");Fails(()=>storage.DisposePrivateInputs(manifest));Need(File.Exists(Path.Combine(root,"payload")),"Altered input was deleted"); }
   else if(scenario==1) { File.WriteAllText(Path.Combine(root,"unexpected"),"x");Fails(()=>storage.DisposePrivateInputs(manifest));Need(File.Exists(Path.Combine(root,"payload")),"Unexpected child allowed cleanup"); }
   else { File.Delete(Path.Combine(root,"payload"));storage.DisposePrivateInputs(manifest);Need(File.Exists(Path.Combine(root,"terminal-resource-receipt")),"Missing listed retry lost receipt"); }
  } finally { if(gate!=null) gate.Dispose();if(pin!=null) pin.Dispose();for(int i=retained.Count-1;i>=0;i--) retained[i].Dispose();foreach(var name in new[]{"payload","unexpected","terminal-resource-receipt",".admission"}) { var path=Path.Combine(root,name);if(File.Exists(path)) File.Delete(path); } if(Directory.Exists(root)) Directory.Delete(root); }
 }
 public static int Main(string[] args) { if(args.Length!=1)return 2;int failed=0;for(int i=0;i<3;i++)try{Case(Path.Combine(args[0],"stage-"+i),i);Console.WriteLine("PASS "+i);}catch(Exception error){failed++;Console.WriteLine("FAIL "+i+" "+error.Message);}Console.WriteLine("STAGE_TERMINAL_PROBE selected=3 failed="+failed);return failed==0?0:1; }
}

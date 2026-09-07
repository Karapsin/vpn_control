namespace VpnBrokerFixtures {
public static class AncestorProbe {
 sealed class Pins : System.IDisposable {
  public System.IDisposable Parent;public readonly System.Collections.Generic.List<Microsoft.Win32.SafeHandles.SafeFileHandle> Children=new System.Collections.Generic.List<Microsoft.Win32.SafeHandles.SafeFileHandle>();
  public void Dispose() { if(Parent!=null) Parent.Dispose();for(int i=Children.Count-1;i>=0;i--) Children[i].Dispose(); }
 }
 static System.IDisposable Pin(string path,bool leaf) {
  var method=typeof(VpnRuntimeBroker).GetMethod("Pin",System.Reflection.BindingFlags.Static|System.Reflection.BindingFlags.NonPublic);
  var pins=new Pins();try { pins.Parent=(System.IDisposable)method.Invoke(null,method.GetParameters().Length==2?new object[]{path,leaf}:new object[]{path,leaf,pins.Children});return pins; }
  catch(System.Reflection.TargetInvocationException failure) { pins.Dispose();throw failure.InnerException; }
 }
 static void Protect(string path,System.Security.AccessControl.FileSystemRights extra=0) {
  var acl=new System.Security.AccessControl.DirectorySecurity();
  acl.SetOwner(new System.Security.Principal.SecurityIdentifier("S-1-5-32-544"));
  acl.SetAccessRuleProtection(true,false);
  foreach(string sid in new[]{"S-1-5-18","S-1-5-32-544"}) acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
   new System.Security.Principal.SecurityIdentifier(sid),System.Security.AccessControl.FileSystemRights.FullControl,
   System.Security.AccessControl.InheritanceFlags.ContainerInherit|System.Security.AccessControl.InheritanceFlags.ObjectInherit,
   System.Security.AccessControl.PropagationFlags.None,System.Security.AccessControl.AccessControlType.Allow));
  acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier("S-1-5-32-545"),
   System.Security.AccessControl.FileSystemRights.ReadAndExecute|System.Security.AccessControl.FileSystemRights.WriteAttributes|
   System.Security.AccessControl.FileSystemRights.WriteExtendedAttributes|extra,System.Security.AccessControl.AccessControlType.Allow));
  System.IO.Directory.SetAccessControl(path,acl);
 }
 [System.Runtime.InteropServices.DllImport("kernel32.dll",CharSet=System.Runtime.InteropServices.CharSet.Unicode,SetLastError=true)]
 static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFile(string path,uint access,uint share,System.IntPtr security,uint create,uint flags,System.IntPtr template);
 public static void PrepareOrdinary(string root) {
  foreach(string name in new[]{"empty","nonempty"}) { string path=System.IO.Path.Combine(root,name);System.IO.Directory.CreateDirectory(path);Protect(path); }
  string witness=System.IO.Path.Combine(root,"nonempty","witness.txt");System.IO.File.WriteAllText(witness,"owned witness");
  var acl=new System.Security.AccessControl.FileSecurity();acl.SetAccessRuleProtection(true,false);
  foreach(string sid in new[]{"S-1-5-18","S-1-5-32-544"}) acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier(sid),System.Security.AccessControl.FileSystemRights.FullControl,System.Security.AccessControl.AccessControlType.Allow));
  acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier("S-1-5-32-545"),System.Security.AccessControl.FileSystemRights.Read|System.Security.AccessControl.FileSystemRights.Delete,System.Security.AccessControl.AccessControlType.Allow));System.IO.File.SetAccessControl(witness,acl);
 }
 static bool DeleteAuthority(string path) {
  using(var handle=CreateFile(path,0x10000,3,System.IntPtr.Zero,3,0x02200000,System.IntPtr.Zero)) {
   if(!handle.IsInvalid) return true;
   int code=System.Runtime.InteropServices.Marshal.GetLastWin32Error();if(code!=32) throw new System.IO.IOException("Unexpected authority result "+code);return false;
  }
 }
 public static string RunOrdinary(string root) {
  bool rejected=false;try { using(Pin(System.IO.Path.Combine(root,"empty"),false)) {} } catch(System.UnauthorizedAccessException) { rejected=true; }
  if(!rejected) throw new System.IO.IOException("Empty mutable ancestor accepted");
  string nonempty=System.IO.Path.Combine(root,"nonempty"),witness=System.IO.Path.Combine(nonempty,"witness.txt");
  if(!DeleteAuthority(witness)) throw new System.IO.IOException("Fixture authority missing before admission");
  using(Pin(nonempty,false)) { if(DeleteAuthority(witness)) throw new System.IO.IOException("Witness was not pinned"); }
  if(!DeleteAuthority(witness)) throw new System.IO.IOException("Witness remained pinned after closure");
  var ancestors=new System.Collections.Generic.Stack<string>();for(var d=new System.IO.DirectoryInfo(System.Environment.GetFolderPath(System.Environment.SpecialFolder.CommonApplicationData));d!=null;d=d.Parent) ancestors.Push(d.FullName);
  var actual=new System.Collections.Generic.List<System.IDisposable>();try { foreach(string ancestor in ancestors) actual.Add(Pin(ancestor,false)); } finally { for(int i=actual.Count-1;i>=0;i--) actual[i].Dispose(); }
  return "BROKER_ANCESTOR_ORDINARY_OK:3";
 }
 public static string Run(string root) {
  string empty=System.IO.Path.Combine(root,"empty");System.IO.Directory.CreateDirectory(empty);Protect(empty);
  System.IDisposable admitted=null;bool rejected=false;
  try { admitted=Pin(empty,false); } catch(System.IO.IOException) { rejected=true; } catch(System.UnauthorizedAccessException) { rejected=true; }
  finally { if(admitted!=null) admitted.Dispose(); }
  if(!rejected) throw new System.IO.IOException("Empty attribute-writable ancestor reached privileged admission");
  System.IO.Directory.Delete(empty);
  string nonempty=System.IO.Path.Combine(root,"nonempty");System.IO.Directory.CreateDirectory(nonempty);Protect(nonempty);
  string witness=System.IO.Path.Combine(nonempty,"witness.txt"),moved=System.IO.Path.Combine(nonempty,"moved.txt");System.IO.File.WriteAllText(witness,"owned witness");
  using(Pin(nonempty,false)) {
   bool pinned=false;try { System.IO.File.Move(witness,moved); } catch(System.IO.IOException) { pinned=true; } catch(System.UnauthorizedAccessException) { pinned=true; }
   if(!pinned) throw new System.IO.IOException("Ancestor admission failed to retain a linked child");
  }
  System.IO.File.Move(witness,moved);System.IO.File.Move(moved,witness);
  rejected=false;try { using(Pin(nonempty,true)) { } } catch(System.UnauthorizedAccessException) { rejected=true; }
  if(!rejected) throw new System.IO.IOException("Protected leaf accepted untrusted attribute mutation");
  Protect(nonempty,System.Security.AccessControl.FileSystemRights.DeleteSubdirectoriesAndFiles);
  rejected=false;try { using(Pin(nonempty,false)) { } } catch(System.UnauthorizedAccessException) { rejected=true; }
  if(!rejected) throw new System.IO.IOException("Witness admitted dangerous ancestor mutation");
  System.IO.File.Delete(witness);System.IO.Directory.Delete(nonempty);
  var ancestors=new System.Collections.Generic.Stack<string>();for(var d=new System.IO.DirectoryInfo(System.Environment.GetFolderPath(System.Environment.SpecialFolder.CommonApplicationData));d!=null;d=d.Parent) ancestors.Push(d.FullName);
  var actual=new System.Collections.Generic.List<System.IDisposable>();try { foreach(string ancestor in ancestors) actual.Add(Pin(ancestor,false)); } finally { for(int i=actual.Count-1;i>=0;i--) actual[i].Dispose(); }
  return "BROKER_ANCESTOR_OK:5";
 }
}
}

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
namespace VpnBrokerFixtures {
/** The broker's owner open with fake identities: the same user's elevation, another administrator's
 * (over-the-shoulder) elevation, a token without SeDebugPrivilege, and a PID that is not a denial. */
public static class OwnerAccessProbe {
 sealed class Scope : IDisposable {
  readonly Fake owner;
  public Scope(Fake fake) { owner=fake; }
  public void Dispose() { owner.Log.Add("revert");owner.Active=false; }
 }
 sealed class Fake : VpnBrokerOwnerProcess.Native {
  public readonly List<string> Log=new List<string>();
  public bool Active,HoldsDebug=true;
  public int Plain,Privileged; // the Win32 error of each open, 0 for a handle
  public IntPtr Open(uint access,uint pid,out int error) {
   Log.Add((Active?"privileged-open:":"open:")+access.ToString("x")+":"+pid);
   error=Active?Privileged:Plain;return error==0?new IntPtr(0x4242):IntPtr.Zero;
  }
  public IDisposable DebugPrivilegeOnThisThread() {
   Log.Add("debug");if(!HoldsDebug) return null;Active=true;return new Scope(this);
  }
 }
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenThreadToken(IntPtr thread,uint access,bool self,out IntPtr token);
 static void Need(bool value,string message) { if(!value) throw new Exception(message); }
 static string Case(Fake fake,out IntPtr handle,out int error) {
  handle=VpnBrokerOwnerProcess.Open(77,0x101040,fake,out error);return String.Join(",",fake.Log.ToArray());
 }
 static bool Impersonating() {
  IntPtr token;if(!OpenThreadToken(GetCurrentThread(),8,true,out token)) return false;
  CloseHandle(token);return true;
 }
 public static string Run() {
  IntPtr handle;int error;string log;var granted=new IntPtr(0x4242);
  var same=new Fake();log=Case(same,out handle,out error);
  Need(log=="open:101040:77"&&handle==granted&&error==0,"same-user elevation touched the privilege: "+log);
  var shoulder=new Fake();shoulder.Plain=5;log=Case(shoulder,out handle,out error);
  Need(log=="open:101040:77,debug,privileged-open:101040:77,revert"&&handle==granted&&error==0&&!shoulder.Active,
   "over-the-shoulder elevation did not open its owner under a reverted thread privilege: "+log+":"+error);
  var unheld=new Fake();unheld.Plain=5;unheld.HoldsDebug=false;log=Case(unheld,out handle,out error);
  Need(log=="open:101040:77,debug"&&handle==IntPtr.Zero&&error==5,"a token without the privilege did not fail closed: "+log+":"+error);
  var gone=new Fake();gone.Plain=87;log=Case(gone,out handle,out error);
  Need(log=="open:101040:77"&&handle==IntPtr.Zero&&error==87,"a refusal other than ACCESS_DENIED was retried: "+log+":"+error);
  var refused=new Fake();refused.Plain=5;refused.Privileged=5;log=Case(refused,out handle,out error);
  Need(log=="open:101040:77,debug,privileged-open:101040:77,revert"&&handle==IntPtr.Zero&&error==5&&!refused.Active,
   "a refused privileged open was not reverted and reported: "+log+":"+error);
  // Real natives: this process is its own owner (same identity, no privilege), and a privilege scope,
  // when this token holds SeDebugPrivilege, impersonates only until it is disposed.
  uint self=(uint)System.Diagnostics.Process.GetCurrentProcess().Id;
  IntPtr own=VpnBrokerOwnerProcess.Open(self,0x101040,out error);
  Need(own!=IntPtr.Zero&&error==0,"the broker's own-identity owner open failed: "+error);CloseHandle(own);
  Need(!Impersonating(),"the thread impersonated before any privilege scope");
  var type=typeof(VpnBrokerOwnerProcess).GetNestedType("FixedNative",System.Reflection.BindingFlags.NonPublic);
  var native=(VpnBrokerOwnerProcess.Native)Activator.CreateInstance(type,true);
  using(var scope=native.DebugPrivilegeOnThisThread()) {
   Need(scope==null?!Impersonating():Impersonating(),"the privilege scope and the thread token disagree");
  }
  Need(!Impersonating(),"the privilege scope left the thread impersonating");
  return "BROKER_OWNER_ACCESS_OK:6";
 }
}
}

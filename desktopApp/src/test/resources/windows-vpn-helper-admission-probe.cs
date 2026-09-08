using System;
using System.IO;
using System.ComponentModel;
using System.Collections.Generic;

public static class PackagedBrokerAdmissionProbe {
 const string Sid="S-1-5-21-1-2-3-1001",Image="C:\\Apps\\VPN\\vpn-control-cli.exe";
 const string Helper="C:\\Apps\\VPN\\app\\native\\windows-amd64\\vpn-control-vpn-broker.exe";
 static void Need(bool value,string message) { if(!value) throw new Exception(message); }
 static void Fails(string code,Action action) {
  try { action(); } catch(IOException error) { Need(error.Message==code,"Wrong bounded error");return; }
  throw new Exception("Missing rejection: "+code);
 }
 static VpnPackagedBrokerAdmission.Lease Retain(Fake native) { return VpnPackagedBrokerAdmission.Retain(123,456,Sid,native); }
 public static string Run() {
  int cases=0;
  foreach(bool productAbsent in new[]{false,true}) {
   var fake=new Fake();fake.MissingProduct=productAbsent;fake.MissingGate=!productAbsent;
   var lease=Retain(fake);Need(fake.OwnerReads==2,"Owner generation was not rechecked");
   Need(fake.Primary!=null&&!fake.Primary.Closed,"First missing gate discarded actual executable fence");
   fake.Alive=false;Need(!fake.Primary.Closed,"Owner exit released the helper's executable fence");
   lease.Dispose();Need(fake.AllClosed,"Admission leaked handles");Need(fake.Closed[fake.Closed.Count-1]==fake.Primary,"Primary executable was not the last close");cases++;
  }
  for(int change=0;change<4;change++) {
   var fake=new Fake();fake.OwnerChange=change;
   Fails("PERMISSION_DENIED",()=>Retain(fake));Need(fake.AllClosed,"Rejected owner leaked handles");cases++;
  }
  {
   var fake=new Fake();fake.OwnerImage="C:\\Apps\\VPN\\java.exe";
   Fails("UNAVAILABLE",()=>Retain(fake));Need(fake.AllClosed,"Unapproved native image leaked handles");cases++;
  }
  {
   var fake=new Fake();fake.ActualHelper="C:\\Elsewhere\\vpn-control-vpn-broker.exe";
   Fails("PERMISSION_DENIED",()=>Retain(fake));Need(fake.AllClosed,"Foreign helper leaked handles");cases++;
  }
  {
   var fake=new Fake();fake.ImageMachine=0xaa64;
   Fails("UNSUPPORTED",()=>Retain(fake));Need(fake.AllClosed,"Wrong machine leaked handles");cases++;
  }
  {
   var fake=new Fake();fake.GateBytes[8]=1;
   Fails("BUSY",()=>Retain(fake));Need(fake.AllClosed&&fake.Unlocks==1,"Pending gate lost its lock");cases++;
  }
  {
   var fake=new Fake();fake.LockAvailable=false;
   Fails("BUSY",()=>Retain(fake));Need(fake.Reads==0&&fake.AllClosed,"Busy gate was read or leaked");cases++;
  }
  {
   var fake=new Fake();fake.GateBytes[16]=1;
   Fails("CONFLICT",()=>Retain(fake));Need(fake.AllClosed,"Corrupt gate leaked handles");cases++;
  }
  {
   var fake=new Fake();fake.GateError=5;
   try { Retain(fake);throw new Exception("Access denied inferred missing gate"); }
   catch(Win32Exception error) { Need(error.NativeErrorCode==5,"Gate failure changed"); }
   Need(fake.AllClosed,"Gate query failure leaked handles");cases++;
  }
  {
   var fake=new Fake();fake.RejectParent="C:\\Apps";
   Fails("PERMISSION_DENIED",()=>Retain(fake));Need(fake.AllClosed,"Ancestor rejection leaked handles");cases++;
  }
  {
   var fake=new Fake();var lease=Retain(fake);
   var rejected=fake.Handles.FindLast(value=>value.Path==Helper);rejected.CloseFailures=1;
   try { lease.Dispose();throw new Exception("Close failure was hidden"); } catch(Win32Exception) { }
   Need(!rejected.Closed&&!fake.Primary.Closed&&fake.Unlocks==0,"Failed cleanup dropped the executable/gate fence");
   lease.Dispose();lease.Dispose();Need(fake.AllClosed&&fake.Unlocks==1,"Cleanup retry did not close exact retained objects");cases++;
  }
  {
   var fake=new Fake();fake.Witness=true;fake.WitnessCloseFailures=2;
   try { Retain(fake);throw new Exception("Rejected witness did not retain cleanup ownership"); }
   catch(VpnPackagedBrokerAdmission.CleanupPending failure) {
    Need(!fake.Primary.Closed&&!fake.AllClosed,"Rejected witness lost its primary fence");
    failure.Retained.Dispose();Need(fake.AllClosed,"Rejected witness retry leaked handles");
   }
   cases++;
  }
  return "PACKAGED_BROKER_ADMISSION_OK:"+cases;
 }
 public static string RunEntrypoint() {
  int cases=0;
  for(int scenario=0;scenario<6;scenario++) {
   var fake=new Fake();
   if(scenario==1) fake.MissingProduct=true;
   if(scenario==2) fake.OwnerChange=1;
   if(scenario==3) fake.GateBytes[8]=1;
   if(scenario==4) fake.ActualHelper="C:\\Elsewhere\\vpn-control-vpn-broker.exe";
   string[] args={"vpn-control-vpn-00000000-0000-0000-0000-000000000041","123","456",Sid,new string('a',64)};
   int called=0,code;string error;var previous=Console.Error;
   using(var output=new StringWriter()) {
    try {
     Console.SetError(output);
     code=VpnRuntimeBrokerEntry.Execute(args,invocation=>VpnRuntimeBrokerEntry.RunAdmitted(invocation,fake,admitted=>{
      called++;Need(fake.Primary!=null&&!fake.Primary.Closed&&!fake.AllClosed,"Runner lost its admission fence");
      Need(admitted.OwnerProcessId==123&&admitted.OwnerCreationFileTime==456&&admitted.OwnerSid==Sid,"Runner received a different owner");
      if(scenario==5) throw new IOException("Injected runner failure");
     }));
    } finally { Console.SetError(previous); }
    error=output.ToString().Trim();
   }
   bool accepted=scenario<2;
   Need(code==(accepted?0:1),"Wrong entrypoint outcome");
   Need(called==((accepted||scenario==5)?1:0),"Rejected admission reached runner");
   Need(error==(accepted?"":"RUNTIME_FAILED"),"Entrypoint exposed an unbounded failure");
   Need(fake.AllClosed,"Entrypoint failed to dispose its retained native scope");
   cases++;
  }
  return "PACKAGED_BROKER_ENTRY_FENCE_OK:"+cases;
 }
 public static int Main() {
  try { Console.WriteLine("CONTEXT_SID="+System.Security.Principal.WindowsIdentity.GetCurrent().User.Value);Console.WriteLine("PROCESS_BITS="+(IntPtr.Size*8));Console.WriteLine("FRAMEWORK="+Environment.Version);Console.WriteLine(Run());Console.WriteLine(RunEntrypoint());return 0; }
  catch(Exception error) { Console.Error.WriteLine(error);return 1; }
 }
 sealed class H : VpnPackagedBrokerAdmission.Handle {
  internal readonly string Path;internal bool Closed;internal int CloseFailures;
  internal H(string path) { Path=path; }
 }
 sealed class Fake : VpnPackagedBrokerAdmission.Native {
  internal readonly List<H> Handles=new List<H>(),Closed=new List<H>();
  internal H Primary;internal bool MissingProduct,MissingGate,Alive=true,LockAvailable=true,Witness;
  internal int OwnerReads,OwnerChange=-1,ImageMachine=0x8664,Reads,Unlocks,GateError,WitnessCloseFailures;
  internal string OwnerImage=Image,ActualHelper=Helper,RejectParent;
  internal byte[] GateBytes=new byte[17];
  internal bool AllClosed { get { return Handles.TrueForAll(value=>value.Closed); } }
  H Keep(string path) { var handle=new H(Plain(path));Handles.Add(handle);return handle; }
  static string Plain(string path) { return path.StartsWith("\\\\?\\",StringComparison.Ordinal) ? path.Substring(4) : path; }
  public VpnPackagedBrokerAdmission.Handle OpenOwner(uint pid) { return Keep("owner-process"); }
  public VpnPackagedBrokerAdmission.Owner ObserveOwner(VpnPackagedBrokerAdmission.Handle value) {
   Need(!((H)value).Closed,"Queried closed owner");OwnerReads++;
   bool changed=OwnerReads==2;
   return new VpnPackagedBrokerAdmission.Owner(changed&&OwnerChange==0 ? 124u : 123u,
    changed&&OwnerChange==1 ? 457 : 456,changed&&OwnerChange==2 ? "S-1-5-21-1-2-3-1002" : Sid,
    OwnerImage,Alive&&!(changed&&OwnerChange==3));
  }
  public string CurrentImage() { return ActualHelper; }
  public VpnPackagedBrokerAdmission.Handle Open(string path) {
   path=Plain(path);
   if(path.EndsWith("vpn-control-install-jobs",StringComparison.Ordinal)&&MissingProduct) throw new Win32Exception(2);
   H handle=Keep(path);if(Primary==null&&path==OwnerImage) Primary=handle;
   if(path.EndsWith("witness",StringComparison.Ordinal)) handle.CloseFailures=WitnessCloseFailures;
   return handle;
  }
  public VpnPackagedBrokerAdmission.Handle OpenGate(string path) {
   if(MissingGate) throw new Win32Exception(2);if(GateError!=0) throw new Win32Exception(GateError);return Keep(path);
  }
  public string Canonical(VpnPackagedBrokerAdmission.Handle file) {
   string path=((H)file).Path;
   return "\\\\?\\"+(Witness&&path.EndsWith("witness",StringComparison.Ordinal) ? "C:\\Elsewhere\\witness" : path);
  }
  public string Identity(VpnPackagedBrokerAdmission.Handle file) { return ((H)file).Path; }
  public int Machine(VpnPackagedBrokerAdmission.Handle file) { return ImageMachine; }
  public void Inspect(VpnPackagedBrokerAdmission.Handle file,bool directory,bool ancestor,string principal) {
   H handle=(H)file;Need(!handle.Closed,"Inspected closed file");
   if(Witness&&handle.Path=="C:\\ProgramData"&&ancestor) throw new IOException("PERMISSION_DENIED");
  }
  public void LinkedAncestor(VpnPackagedBrokerAdmission.Handle parent,VpnPackagedBrokerAdmission.Handle child,string principal) {
   if(((H)parent).Path==RejectParent) throw new IOException("PERMISSION_DENIED");
   string actualParent=Path.GetDirectoryName(Canonical(child)).TrimEnd('\\');
   if(actualParent!=Canonical(parent).TrimEnd('\\')) throw new IOException("CONFLICT");
  }
  public string InstallationId(VpnPackagedBrokerAdmission.Handle directory) { return "00000000-0000-0000-0000-000000000041"; }
  public string ProgramData() { return "C:\\ProgramData"; }
  public IEnumerable<string> Children(VpnPackagedBrokerAdmission.Handle directory) { return new[]{"witness"}; }
  public bool LockShared(VpnPackagedBrokerAdmission.Handle gate) { return LockAvailable; }
  public void UnlockShared(VpnPackagedBrokerAdmission.Handle gate) { Unlocks++; }
  public byte[] ReadGate(VpnPackagedBrokerAdmission.Handle gate) { Reads++;return (byte[])GateBytes.Clone(); }
  public void Close(VpnPackagedBrokerAdmission.Handle value) {
   var handle=(H)value;Need(!handle.Closed,"Handle closed twice");
   if(handle.CloseFailures>0) { handle.CloseFailures--;throw new Win32Exception(32); }
   handle.Closed=true;Closed.Add(handle);
  }
  public void CloseAuxiliary() { }
 }
}

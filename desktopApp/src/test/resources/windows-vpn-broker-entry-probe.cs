using System;
using System.IO;
public static class BrokerEntryAuthorityProbe {
 static void Need(bool value,string message) { if(!value) throw new Exception(message); }
 public static string Run(string mode) {
  string digest=mode=="mismatch"?new string('b',64):new string('a',64);
  string[] args={"vpn-control-vpn-11111111-1111-1111-1111-111111111111","123","133000000000000000",
   "S-1-5-21-101-102-103-1000",digest};
  int calls=0,code;string error;var prior=Console.Error;
  using(var output=new StringWriter()) {
   try {
    Console.SetError(output);
    code=VpnRuntimeBrokerEntry.Execute(args,invocation=>{calls++;Need(invocation.RuntimeSha256==digest,"Invocation changed before fixed runner");});
   } finally { Console.SetError(prior); }
   error=output.ToString().Trim();
  }
  if(mode=="match") Need(code==0&&calls==1&&error=="","Matching compiled runtime was not admitted exactly once");
  // A refused runtime authority exits with its own step code (VpnBrokerStep.RuntimeAuthority).
  else Need(code==11&&calls==0&&error==(mode=="missing"?"UNAVAILABLE":"PERMISSION_DENIED"),
   "Missing or mismatched runtime authority reached the privileged runner: "+code+":"+calls+":"+error);
  using(var output=new StringWriter()) {
   try { Console.SetError(output);code=VpnRuntimeBrokerEntry.Execute(new string[0],invocation=>{calls++;}); }
   finally { Console.SetError(prior); }
   Need(code==10&&output.ToString().Trim()=="INVALID_ARGUMENT"&&calls==(mode=="match"?1:0),"Malformed argument classification changed");
  }
  using(var output=new StringWriter()) {
   // A runner failure exits with the last step the runner entered, and 1 when it entered none.
   try {
    Console.SetError(output);
    code=VpnRuntimeBrokerEntry.Execute(args,invocation=>{VpnBrokerStep.Enter(VpnBrokerStep.Job);throw new IOException("fixture");});
   } finally { Console.SetError(prior); }
   Need(code==(mode=="match"?34:11),"A runner failure did not exit with its step: "+code);
   try {
    Console.SetError(output);
    code=VpnRuntimeBrokerEntry.Execute(args,invocation=>{throw new IOException("fixture");});
   } finally { Console.SetError(prior); }
   Need(code==(mode=="match"?1:11),"An unclassified runner failure did not exit 1: "+code);
  }
  return "BROKER_AUTHORITY_OK:"+mode+":4";
 }
}

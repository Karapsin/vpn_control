// Fixed NativeAOT entrypoint. Runtime configuration and resources arrive only on the authenticated pipe.
using System;
using System.Globalization;
[assembly:System.Runtime.InteropServices.DefaultDllImportSearchPaths(System.Runtime.InteropServices.DllImportSearchPath.System32)]
public static class VpnRuntimeBrokerEntry {
 public sealed class Invocation {
  public readonly string PipeName,OwnerSid,RuntimeSha256;
  public readonly uint OwnerProcessId;
  public readonly long OwnerCreationFileTime;
  internal Invocation(string pipe,uint pid,long created,string sid,string digest) {
   PipeName=pipe;OwnerProcessId=pid;OwnerCreationFileTime=created;OwnerSid=sid;RuntimeSha256=digest;
  }
  public override string ToString() { return "Native broker invocation (<redacted>)"; }
 }
 public static Invocation Parse(string[] args) {
  if(args==null||args.Length!=5) throw new ArgumentException("INVALID_ARGUMENT");
  foreach(string argument in args) if(argument==null||argument.IndexOf('\0')>=0) throw new ArgumentException("INVALID_ARGUMENT");
  const string prefix="vpn-control-vpn-";Guid id;
  if(!args[0].StartsWith(prefix,StringComparison.Ordinal)||
    !Guid.TryParseExact(args[0].Substring(prefix.Length),"D",out id)||prefix+id.ToString("D")!=args[0])
   throw new ArgumentException("INVALID_ARGUMENT");
  uint pid;long created;
  if(!UInt32.TryParse(args[1],NumberStyles.None,CultureInfo.InvariantCulture,out pid)||pid==0||pid.ToString(CultureInfo.InvariantCulture)!=args[1]||
    !Int64.TryParse(args[2],NumberStyles.None,CultureInfo.InvariantCulture,out created)||created<=0||created.ToString(CultureInfo.InvariantCulture)!=args[2])
   throw new ArgumentException("INVALID_ARGUMENT");
  VpnScopedStorage.OwnerIdentity owner;
  try { owner=new VpnScopedStorage.OwnerIdentity(pid,created,args[3]); }
  catch(System.IO.IOException) { throw new ArgumentException("INVALID_ARGUMENT"); }
  if(args[4].Length!=64) throw new ArgumentException("INVALID_ARGUMENT");
  foreach(char digit in args[4]) if(!((digit>='0'&&digit<='9')||(digit>='a'&&digit<='f'))) throw new ArgumentException("INVALID_ARGUMENT");
  return new Invocation(args[0],pid,created,owner.Sid,args[4]);
 }
 public static int Main(string[] args) {
  return Execute(args,invocation=>RunAdmitted(invocation,null,admitted=>VpnRuntimeBroker.Run(admitted.PipeName,
   admitted.OwnerProcessId,admitted.OwnerCreationFileTime,admitted.OwnerSid,admitted.RuntimeSha256)));
 }
 // Production Main supplies no adapter: the fixed native implementation captures the original
 // process/image/gate itself. The same-assembly fixture can inject only that typed native boundary.
 internal static void RunAdmitted(Invocation invocation,VpnPackagedBrokerAdmission.Native native,Action<Invocation> run) {
  using(var admission=native==null ? VpnPackagedBrokerAdmission.Retain(invocation.OwnerProcessId,
   invocation.OwnerCreationFileTime,invocation.OwnerSid) : VpnPackagedBrokerAdmission.Retain(invocation.OwnerProcessId,
   invocation.OwnerCreationFileTime,invocation.OwnerSid,native)) {
   run(invocation);
  }
 }
 sealed class AuthorityFailure : Exception {
  internal readonly string Code;
  internal AuthorityFailure(string code) { Code=code; }
 }
 static void RequireRuntimeAuthority(Invocation invocation) {
#if VPN_RUNTIME_AUTHORITY
  if(!String.Equals(invocation.RuntimeSha256,VpnBrokerRuntimeAuthority.Sha256,StringComparison.Ordinal))
   throw new AuthorityFailure("PERMISSION_DENIED");
#else
  throw new AuthorityFailure("UNAVAILABLE");
#endif
 }
 internal static int Execute(string[] args,Action<Invocation> run) {
  try {
   Invocation invocation=Parse(args);
   RequireRuntimeAuthority(invocation);
   run(invocation);
   return 0;
  } catch(AuthorityFailure failure) { Console.Error.WriteLine(failure.Code);return 1;
  } catch(OutOfMemoryException) { Console.Error.WriteLine("RESOURCE_EXHAUSTED");return 1; }
  catch(ArgumentException) { Console.Error.WriteLine("INVALID_ARGUMENT");return 1; }
  catch(Exception) { Console.Error.WriteLine("RUNTIME_FAILED");return 1; }
 }
}

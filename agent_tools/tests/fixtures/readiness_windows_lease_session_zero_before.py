"""Fixed Windows execution-state lease programs for trusted guest executors.

There is no transport, arbitrary command or public ownership API here. Enroll a
private guest root directly, retain its native file identity outside the guest,
then bind every operation to that root and actual machine/boot/session identity.
Acquisition admits once before launching one detached native owner. Lost QGA
acknowledgements only permit observing that original UUID. Cancellation writes a
correlated marker; it never signals a PID. The owner calls SetThreadExecutionState
and clears its own requests on the same native thread. No credential-locking,
automatic-sign-in, power-plan or registry setting is changed.
"""
from dataclasses import asdict, dataclass
import base64
import hashlib
import json
import math
import re
from uuid import UUID

from agent_tools.readiness_windows_guest import WTS_NATIVE

MAX_TTL_SECONDS = 18_000
_BOOT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z\Z")
_SID = re.compile(r"S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\Z")
_ROOT = re.compile(r"[0-9a-f]{8}:[0-9a-f]{16}:[0-9a-f]{16}\Z")


def _need(condition, reason):
    if not condition:
        raise ValueError(reason)


def _uuid(value):
    try:
        _need(type(value) is str and str(UUID(value)) == value, "windows_lease_identity_invalid")
    except (ValueError, TypeError, AttributeError):
        raise ValueError("windows_lease_identity_invalid") from None
    return value


@dataclass(frozen=True)
class WindowsLeaseBinding:
    machine: str
    boot: str
    account: str
    session: str
    root_generation: str

    def __post_init__(self):
        _uuid(self.machine)
        _need(type(self.boot) is str and _BOOT.fullmatch(self.boot), "windows_lease_boot_invalid")
        _need(type(self.account) is str and _SID.fullmatch(self.account), "windows_lease_account_invalid")
        _need(type(self.session) is str and re.fullmatch(r"[0-9]{1,10}:[0-9]{1,19}", self.session), "windows_lease_session_invalid")
        console, logon = map(int, self.session.split(":"))
        _need(0 <= console < 2**32-1 and 0 < logon < 2**63, "windows_lease_session_invalid")
        _need(type(self.root_generation) is str and _ROOT.fullmatch(self.root_generation), "windows_lease_root_invalid")


def _config(binding, operation, ttl=0):
    _need(type(binding) is WindowsLeaseBinding, "windows_lease_binding_invalid")
    console, logon = map(int, binding.session.split(":"))
    return {"schemaVersion": 1, "machine": binding.machine, "boot": binding.boot, "account": binding.account,
            "session": binding.session, "rootGeneration": binding.root_generation,
            "console": console, "logon": str(logon), "operationId": _uuid(operation), "ttlSeconds": ttl}


def _prefix():
    source = ("using System.IO;\nusing System.Diagnostics;\nusing System.Collections.Generic;\n"
              "using System.Text;\nusing System.Threading;\nusing System.Management;\n"
              "using System.Security.AccessControl;\nusing System.Security.Cryptography;\n"
              "using System.Web.Script.Serialization;\n" + WTS_NATIVE + "\n" + _NATIVE)
    return ("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'\n"
            "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\n"
            "Add-Type -TypeDefinition @'\n" + source + "\n'@ -ReferencedAssemblies @('System','System.Core','System.Management','System.Web.Extensions')\n")


def _literal(value):
    return "([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + base64.b64encode(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).decode() + "')))"


def enrollment_source(machine, boot):
    _uuid(machine)
    _need(type(boot) is str and _BOOT.fullmatch(boot), "windows_lease_boot_invalid")
    return (_prefix() + "[Console]::WriteLine([NativeLease]::Enroll(" +
            _literal({"machine": machine, "boot": boot}) + "))\n").encode()


def program(action, binding, operation, *, ttl_seconds=None):
    """Only fixed actions; callers must submit saved source or protected stdin."""
    _need(action in {"acquire", "status", "cancel"}, "windows_lease_action_invalid")
    if action == "acquire":
        _need(type(ttl_seconds) in (int, float) and math.isfinite(ttl_seconds)
              and .1 <= ttl_seconds <= MAX_TTL_SECONDS, "windows_lease_ttl_invalid")
    else:
        _need(ttl_seconds is None, "windows_lease_unexpected_ttl")
    config = _config(binding, operation, ttl_seconds if action == "acquire" else 0)
    prefix = _prefix()
    owner = (prefix + "[NativeLease]::Own(" + _literal(config) + ")\n").encode()
    call = "[Console]::WriteLine([NativeLease]::Control('" + action + "'," + _literal(config)
    if action == "acquire":
        call += ",'" + base64.b64encode(owner).decode() + "','" + hashlib.sha256(owner).hexdigest() + "'"
    else:
        call += ",$null,$null"
    return (prefix + call + "))\n").encode()


def validate_enrollment(value, machine, boot):
    _uuid(machine)
    _need(type(value) is dict and set(value) == {"schemaVersion", "machine", "boot", "rootGeneration"}
          and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
          and value["machine"] == machine and value["boot"] == boot
          and type(value["rootGeneration"]) is str and _ROOT.fullmatch(value["rootGeneration"]),
          "windows_lease_enrollment_invalid")
    return value["rootGeneration"]


def validate_observation(value, binding, operation, *, original_identity=None):
    """Validate privately retained QGA output, then remove raw retained streams.

    A missing guest owner is UNKNOWN, including after a lost launch ACK. This
    function never turns observation into permission to launch a replacement.
    """
    _config(binding, operation)
    required = {"schemaVersion", "operationId", "machine", "boot", "rootGeneration", "state", "reason", "replayAllowed"}
    optional = {"admissionNonce", "programSha256", "owner", "jobState", "restored", "retainedStreams"}
    _need(type(value) is dict and required <= set(value) <= required | optional, "windows_lease_observation_invalid")
    _need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["operationId"] == operation
          and value["machine"] == binding.machine and value["boot"] == binding.boot
          and value["rootGeneration"] == binding.root_generation and value["replayAllowed"] is False,
          "windows_lease_observation_identity_changed")
    _need(type(value["state"]) is str and value["state"] in {
          "unsubmitted", "unknown", "starting", "active", "expired", "cancelled", "failed", "restore_blocked"},
          "windows_lease_observation_invalid")
    reasons = {"original_admission_absent", "original_admission_pending", "original_owner_ack_pending",
               "original_owner_unresolved", "original_owner_running", "lease_deadline_reached", "original_lease_cancelled",
               "execution_state_failed", "execution_state_release_unverified", "original_lease_evidence_unavailable",
               "guest_identity_changed", "ordinary_session_changed", "root_generation_changed", "root_owner", "root_acl",
               "original_identity_changed", "original_ttl_changed", "receipt_identity_changed", "source_integrity"}
    _need(type(value["reason"]) is str and value["reason"] in reasons, "windows_lease_observation_invalid")
    identity = {}
    if "admissionNonce" in value or "programSha256" in value:
        _uuid(value.get("admissionNonce"))
        _need(type(value.get("programSha256")) is str and bool(re.fullmatch(r"[0-9a-f]{64}", value["programSha256"])),
              "windows_lease_observation_invalid")
        identity.update(admissionNonce=value["admissionNonce"], programSha256=value["programSha256"])
    if "owner" in value:
        owner = value["owner"]
        _need(type(owner) is dict and set(owner) == {"pid", "birth", "threadId"}
              and type(owner["pid"]) is int and 0 < owner["pid"] < 2**32
              and type(owner["threadId"]) is int and 0 < owner["threadId"] < 2**32
              and type(owner["birth"]) is str and bool(re.fullmatch(r"[0-9]{1,19}", owner["birth"]))
              and 0 < int(owner["birth"]) < 2**64 and len(identity) == 2,
              "windows_lease_owner_invalid")
        identity["owner"] = dict(owner)
    if original_identity is not None:
        _need(type(original_identity) is dict and {"admissionNonce", "programSha256"} <= set(original_identity)
              <= {"admissionNonce", "programSha256", "owner"}
              and all(identity.get(key) == item for key, item in original_identity.items()),
              "windows_lease_original_owner_changed")
    job_state = value.get("jobState", "unknown")
    _need(type(job_state) is str and job_state in {"unknown", "running", "terminal"}, "windows_lease_observation_invalid")
    if "restored" in value:
        _need(type(value["restored"]) is bool, "windows_lease_observation_invalid")
    terminal_states = {"expired", "cancelled", "failed", "restore_blocked"}
    if value["state"] in {"active", "starting"} | terminal_states:
        _need("owner" in identity and job_state != "unknown", "windows_lease_owner_invalid")
    if value["state"] in terminal_states:
        _need("restored" in value, "windows_lease_observation_invalid")
    streams = {}
    if job_state == "terminal":
        _need(value["state"] in terminal_states and type(value.get("retainedStreams")) is dict
              and set(value["retainedStreams"]) == {"stdout", "stderr"}, "windows_lease_streams_incomplete")
        for name, stream in value["retainedStreams"].items():
            _need(type(stream) is dict and set(stream) == {"bytes", "sha256", "base64"}
                  and type(stream["bytes"]) is int and 0 <= stream["bytes"] <= 4096
                  and type(stream["base64"]) is str and len(stream["base64"]) <= 5464
                  and type(stream["sha256"]) is str, "windows_lease_streams_invalid")
            try:
                raw = base64.b64decode(stream["base64"], validate=True)
            except (ValueError, TypeError):
                raise ValueError("windows_lease_streams_invalid") from None
            _need(len(raw) == stream["bytes"] and hashlib.sha256(raw).hexdigest() == stream["sha256"],
                  "windows_lease_streams_invalid")
            streams[name] = {"bytes": len(raw), "sha256": stream["sha256"]}
    else:
        _need("retainedStreams" not in value, "windows_lease_streams_incomplete")
    state = value["state"]
    complete = state in {"expired", "cancelled"} and value.get("restored") is True and job_state == "terminal"
    observe = (state in {"active", "starting"} and job_state == "running" or
               state in {"expired", "cancelled"} and value.get("restored") is True and job_state == "running" or
               state == "unknown" and value["reason"] in {"original_owner_ack_pending", "original_admission_pending"})
    result = {key: value[key] for key in required}
    result.update(jobState=job_state, identity=identity, ok=complete or observe,
                  nextAction="none" if complete else "observe_original" if observe else "resolve_blocker")
    if "restored" in value:
        result["restored"] = value["restored"]
    if streams:
        result["streams"] = streams
    return result


_NATIVE = r'''
public static class NativeLease {
 const UInt32 Continuous=0x80000000, SystemRequired=1, DisplayRequired=2;
 static JavaScriptSerializer Json=new JavaScriptSerializer(){MaxJsonLength=262144};
 [DllImport("kernel32.dll",SetLastError=true)]static extern UInt32 SetThreadExecutionState(UInt32 flags);
 [DllImport("kernel32.dll")]static extern UInt32 GetCurrentThreadId();
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool CreateDirectoryW(string path,IntPtr security);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr CreateFileW(string path,UInt32 access,UInt32 share,IntPtr security,UInt32 disposition,UInt32 flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetFileInformationByHandle(IntPtr handle,out FileInfoNative info);
 [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr handle);
 [StructLayout(LayoutKind.Sequential)]struct FileInfoNative {public UInt32 Attributes;public System.Runtime.InteropServices.ComTypes.FILETIME Created,Accessed,Written;public UInt32 Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;}
 static void Need(bool yes,string reason){if(!yes)throw new Exception(reason);}
 static Dictionary<string,object> Read(string path){Need(new FileInfo(path).Length<=262144,"RECORD_BOUND");NoLink(path);return Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(path,Encoding.UTF8));}
 static string S(Dictionary<string,object> v,string key){return Convert.ToString(v[key],System.Globalization.CultureInfo.InvariantCulture);}
 static string Hash(byte[] value){using(var h=SHA256.Create())return BitConverter.ToString(h.ComputeHash(value)).Replace("-","").ToLowerInvariant();}
 static void Write(string path,Dictionary<string,object> value){byte[] raw=Encoding.UTF8.GetBytes(Json.Serialize(value));using(var f=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None)){f.Write(raw,0,raw.Length);f.Flush(true);}}
 static void NoLink(string path){Need((File.GetAttributes(path)&FileAttributes.ReparsePoint)==0,"REPARSE_POINT");}
 static void Private(string path){
  if(!Directory.Exists(path)){
   var acl=new DirectorySecurity();var system=new SecurityIdentifier("S-1-5-18");acl.SetOwner(system);acl.SetAccessRuleProtection(true,false);
   foreach(string sid in new[]{"S-1-5-18","S-1-5-32-544"})acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid),FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
   Directory.CreateDirectory(path,acl);
  }
  NoLink(path);var actual=Directory.GetAccessControl(path);Need(actual.GetOwner(typeof(SecurityIdentifier)).Value=="S-1-5-18","ROOT_OWNER");
  foreach(FileSystemAccessRule row in actual.GetAccessRules(true,true,typeof(SecurityIdentifier)))Need(row.AccessControlType==AccessControlType.Allow&&(row.IdentityReference.Value=="S-1-5-18"||row.IdentityReference.Value=="S-1-5-32-544"),"ROOT_ACL");
 }
 static string Root(Dictionary<string,object> c){return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"VPNControlRecoveryLeases-v1",S(c,"machine"));}
 static string Tag(string path){
  NoLink(path);IntPtr h=CreateFileW(path,0,7,IntPtr.Zero,3,0x02000000,IntPtr.Zero);Need(h!=new IntPtr(-1),"ROOT_HANDLE");
  try{FileInfoNative i;Need(GetFileInformationByHandle(h,out i),"ROOT_IDENTITY");UInt64 birth=((UInt64)(UInt32)i.Created.dwHighDateTime<<32)|(UInt32)i.Created.dwLowDateTime;
   return i.Volume.ToString("x8")+":"+i.IndexHigh.ToString("x8")+i.IndexLow.ToString("x8")+":"+birth.ToString("x16");}finally{CloseHandle(h);}
 }
 static void Machine(Dictionary<string,object> c){
  Need(WindowsIdentity.GetCurrent().User.Value=="S-1-5-18","SYSTEM_REQUIRED");
  string machine=null,boot=null;
  using(var q=new ManagementObjectSearcher("SELECT UUID FROM Win32_ComputerSystemProduct"))foreach(ManagementObject row in q.Get())machine=new Guid(Convert.ToString(row["UUID"])).ToString("D");
  using(var q=new ManagementObjectSearcher("SELECT LastBootUpTime FROM Win32_OperatingSystem"))foreach(ManagementObject row in q.Get())boot=ManagementDateTimeConverter.ToDateTime(Convert.ToString(row["LastBootUpTime"])).ToUniversalTime().ToString("o");
  Need(machine==S(c,"machine")&&boot==S(c,"boot"),"GUEST_IDENTITY_CHANGED");
 }
 static void Session(Dictionary<string,object> c){
  UInt32 id=Convert.ToUInt32(c["console"]);Need(SessionFacts.WTSGetActiveConsoleSessionId()==id,"SESSION_CHANGED");var info=SessionFacts.Read(id);
  Need(info.Data.Logon.ToString()==S(c,"logon")&&info.Data.State==0&&info.Data.Flags==1&&SessionFacts.Sid(id)==S(c,"account"),"ORDINARY_SESSION_CHANGED");
 }
 static string Guard(Dictionary<string,object> c){Machine(c);string root=Root(c);Private(root);Need(Tag(root)==S(c,"rootGeneration"),"ROOT_GENERATION_CHANGED");return root;}
 static Dictionary<string,object> Correlation(Dictionary<string,object> c,Dictionary<string,object> intent){
  var value=new Dictionary<string,object>();foreach(string k in new[]{"operationId","machine","boot","account","session","rootGeneration"})value[k]=c[k];
  value["schemaVersion"]=1;value["nonce"]=intent["nonce"];value["programSha256"]=intent["programSha256"];return value;
 }
 static void Correlate(Dictionary<string,object> value,Dictionary<string,object> expected){foreach(var p in expected)Need(value.ContainsKey(p.Key)&&Json.Serialize(value[p.Key])==Json.Serialize(p.Value),"RECEIPT_IDENTITY_CHANGED");}
 static string Birth(int pid){try{using(var p=Process.GetProcessById(pid)){if(p.HasExited)return null;return p.StartTime.ToUniversalTime().ToFileTimeUtc().ToString();}}catch(ArgumentException){return null;}}
 static Dictionary<string,object> Projection(Dictionary<string,object> c,string state,string reason){return new Dictionary<string,object>{{"schemaVersion",1},{"operationId",c["operationId"]},{"machine",c["machine"]},{"boot",c["boot"]},{"rootGeneration",c["rootGeneration"]},{"state",state},{"reason",reason},{"replayAllowed",false}};}
 public static string Enroll(string raw){var c=Json.Deserialize<Dictionary<string,object>>(raw);Machine(c);string parent=Path.GetDirectoryName(Root(c));Private(parent);Private(Root(c));Private(Path.Combine(Root(c),"operations"));return Json.Serialize(new Dictionary<string,object>{{"schemaVersion",1},{"machine",c["machine"]},{"boot",c["boot"]},{"rootGeneration",Tag(Root(c))}});}
 static Dictionary<string,object> Original(Dictionary<string,object> c,string job){var intent=Read(Path.Combine(job,"intent.json"));foreach(string k in new[]{"operationId","machine","boot","account","session","rootGeneration"})Need(S(intent,k)==S(c,k),"ORIGINAL_IDENTITY_CHANGED");return intent;}
 static Dictionary<string,object> Observe(Dictionary<string,object> c){
  string root=Guard(c),job=Path.Combine(root,"operations",S(c,"operationId"));
  if(!Directory.Exists(job))return Projection(c,"unsubmitted","original_admission_absent");
  NoLink(job);string path=Path.Combine(job,"intent.json");if(!File.Exists(path))return Projection(c,"unknown","original_admission_pending");
  var intent=Original(c,job);var correlation=Correlation(c,intent);string ownerPath=Path.Combine(job,"owner.json");
  if(!File.Exists(ownerPath)){var pending=Projection(c,"unknown","original_owner_ack_pending");pending["admissionNonce"]=intent["nonce"];pending["programSha256"]=intent["programSha256"];return pending;}
  var owner=Read(ownerPath);Correlate(owner,correlation);int pid=Convert.ToInt32(owner["pid"]);string birth=S(owner,"birth");bool alive=Birth(pid)==birth;
  var result=Projection(c,"unknown","original_owner_unresolved");result["admissionNonce"]=intent["nonce"];result["programSha256"]=intent["programSha256"];result["owner"]=new Dictionary<string,object>{{"pid",pid},{"birth",birth},{"threadId",owner["threadId"]}};
  result["jobState"]=alive?"running":"unknown";string terminalPath=Path.Combine(job,"terminal.json");
  if(File.Exists(terminalPath)){
   var terminal=Read(terminalPath);Correlate(terminal,correlation);Need(S(terminal,"birth")==birth&&Convert.ToInt32(terminal["pid"])==pid,"TERMINAL_OWNER_CHANGED");
   result["state"]=terminal["state"];result["reason"]=terminal["reason"];result["restored"]=terminal["restored"];
   if(!alive){
    try{
     var streams=new Dictionary<string,object>();foreach(string name in new[]{"stdout","stderr"}){
      string stream=Path.Combine(job,name+".bin");NoLink(stream);using(var f=new FileStream(stream,FileMode.Open,FileAccess.Read,FileShare.None)){
       Need(f.Length<=4096,"STREAM_OVERFLOW");byte[] data=new byte[(int)f.Length];int n=0;while(n<data.Length){int size=f.Read(data,n,data.Length-n);Need(size>0,"STREAM_INCOMPLETE");n+=size;}
       streams[name]=new Dictionary<string,object>{{"bytes",data.Length},{"sha256",Hash(data)},{"base64",Convert.ToBase64String(data)}};
      }
     }
     result["jobState"]="terminal";result["retainedStreams"]=streams;
    }catch(IOException){result["jobState"]="running";}
   }
  }else if(alive){result["state"]=File.Exists(Path.Combine(job,"active.json"))?"active":"starting";result["reason"]="original_owner_running";}
  return result;
 }
 public static string Control(string action,string raw,string ownerBase64,string programSha){
  var c=Json.Deserialize<Dictionary<string,object>>(raw);
  try{
   string root=Guard(c),job=Path.Combine(root,"operations",S(c,"operationId"));
   if(action=="acquire"){
    Session(c);
    if(!CreateDirectoryW(job,IntPtr.Zero)){Need(Marshal.GetLastWin32Error()==183,"ADMISSION_CREATE");var prior=Original(c,job);Need(Convert.ToDouble(prior["ttlSeconds"])==Convert.ToDouble(c["ttlSeconds"]),"ORIGINAL_TTL_CHANGED");return Json.Serialize(Observe(c));}
    byte[] owner=Convert.FromBase64String(ownerBase64);Need(Hash(owner)==programSha,"SOURCE_INTEGRITY");
    string script=Path.Combine(job,"owner.ps1");using(var f=new FileStream(script,FileMode.CreateNew,FileAccess.Write,FileShare.None)){f.Write(owner,0,owner.Length);f.Flush(true);}
    var intent=new Dictionary<string,object>(c);intent["nonce"]=Guid.NewGuid().ToString("D");intent["programSha256"]=programSha;Write(Path.Combine(job,"intent.json"),intent);
    Machine(c);Session(c);Need(Tag(root)==S(c,"rootGeneration"),"ROOT_GENERATION_CHANGED");
    string ps=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),@"System32\WindowsPowerShell\v1.0\powershell.exe");
    string command="\"\""+ps+"\" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \""+script+"\" 1>\""+Path.Combine(job,"stdout.bin")+"\" 2>\""+Path.Combine(job,"stderr.bin")+"\"\"";
    var start=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"cmd.exe"),"/d /s /c "+command){UseShellExecute=false,CreateNoWindow=true};
    using(var process=Process.Start(start)){var launch=Correlation(c,intent);launch["pid"]=process.Id;launch["birth"]=Birth(process.Id);Write(Path.Combine(job,"launcher.json"),launch);}
   }else if(action=="cancel"){
    var intent=Original(c,job);var request=Correlation(c,intent);string path=Path.Combine(job,"cancel.json");
    if(File.Exists(path))Correlate(Read(path),request);else Write(path,request);
   }else Need(action=="status","ACTION_INVALID");
   return Json.Serialize(Observe(c));
  }catch(Exception error){string reason="original_lease_evidence_unavailable";
   foreach(string known in new[]{"GUEST_IDENTITY_CHANGED","ORDINARY_SESSION_CHANGED","ROOT_GENERATION_CHANGED","ROOT_OWNER","ROOT_ACL","ORIGINAL_IDENTITY_CHANGED","ORIGINAL_TTL_CHANGED","RECEIPT_IDENTITY_CHANGED","SOURCE_INTEGRITY"})if(error.Message==known)reason=known.ToLowerInvariant();
   return Json.Serialize(Projection(c,"unknown",reason));}
 }
 public static void Own(string raw){
  var c=Json.Deserialize<Dictionary<string,object>>(raw);string root=Guard(c),job=Path.Combine(root,"operations",S(c,"operationId"));
  var intent=Original(c,job);var correlation=Correlation(c,intent);Need(Hash(File.ReadAllBytes(Path.Combine(job,"owner.ps1")))==S(intent,"programSha256"),"OWNER_SOURCE_CHANGED");
  using(var fence=new FileStream(Path.Combine(job,"owner-fence"),FileMode.CreateNew,FileAccess.Write,FileShare.None)){fence.WriteByte(1);fence.Flush(true);}
  int pid=Process.GetCurrentProcess().Id;string birth=Birth(pid);UInt32 thread=GetCurrentThreadId();
  var identity=new Dictionary<string,object>(correlation){{"pid",pid},{"birth",birth},{"threadId",thread}};Write(Path.Combine(job,"owner.json"),identity);
  string state="failed",reason="execution_state_failed";bool restored=false;UInt32 previous=0;
  try{
   Machine(c);Session(c);Need(Tag(root)==S(c,"rootGeneration"),"ROOT_GENERATION_CHANGED");
   previous=SetThreadExecutionState(Continuous|SystemRequired|DisplayRequired);Need(previous!=0,"EXECUTION_STATE_REJECTED");
   var active=new Dictionary<string,object>(identity){{"appliedFlags",Continuous|SystemRequired|DisplayRequired},{"previousFlags",previous}};Write(Path.Combine(job,"active.json"),active);
   var watch=Stopwatch.StartNew();state="expired";reason="lease_deadline_reached";
   while(watch.Elapsed.TotalSeconds<Convert.ToDouble(intent["ttlSeconds"])){
    Need(GetCurrentThreadId()==thread,"OWNER_THREAD_CHANGED");string cancel=Path.Combine(job,"cancel.json");
    if(File.Exists(cancel)){Correlate(Read(cancel),correlation);state="cancelled";reason="original_lease_cancelled";break;}
    Thread.Sleep(50);
   }
  }catch(Exception){state="failed";reason="execution_state_failed";}
  finally{
   restored=GetCurrentThreadId()==thread&&SetThreadExecutionState(Continuous)!=0;
   if(!restored){state="restore_blocked";reason="execution_state_release_unverified";}
   var terminal=new Dictionary<string,object>(identity){{"state",state},{"reason",reason},{"restored",restored},{"previousFlags",previous}};
   Need(Tag(root)==S(c,"rootGeneration"),"ROOT_GENERATION_CHANGED");Correlate(Original(c,job),correlation);Write(Path.Combine(job,"terminal.json"),terminal);
  }
 }
}
'''

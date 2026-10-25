"""Observation-only admission of the reviewed Windows default-owner rejection.

This is a finite historical-proof reader, not a job recovery or replay route.
Only an explicitly accepted, authenticated pre-execution rejection can join idle
inventory. The original UNKNOWN outcome and consumed claim are never modified.
"""
from dataclasses import dataclass, field
import ast
import base64
import hashlib
import inspect
import json
import re
from pathlib import Path

_EXECUTING_CODE = inspect.currentframe().f_code
_BEFORE_SHA = "caf379b37636f1adcd6cea365b0a8840cbabf8810cdb28a65e50c0a53cf672b8"
_DIAGNOSTIC_SHA = "5a4b74ce0afcb52561df7d5cf27be460dfd19c016854d5ca108df1ce34b6ca55"
_DIAGNOSTIC_CALLER_SHA = "7209afe5b175c169edfb2b52d141e089ceecb01598f0ad259143e50299b54d2f"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_AUTHORITY = object()


def _need(value, reason="windows_preexec_proof_invalid"):
    if not value:
        raise ValueError(reason)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _payload(root, relative):
    import os
    import stat
    from . import readiness_fixture_registry as registry
    from . import private_inventory_lock as private
    _need(type(relative) is str and not Path(relative).is_absolute()
          and relative.startswith(".runtime/"), "windows_preexec_path_invalid")
    path = registry._under(str(Path(root) / relative), Path(root) / ".runtime")
    presented = private.PresentedPath(path.parent)
    with private.Directory(presented.canonical) as directory:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory.fd)
        try:
            info = os.fstat(descriptor)
            _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                  and not stat.S_IMODE(info.st_mode) & 0o022 and 0 <= info.st_size <= 1048576,
                  "windows_preexec_evidence_unsafe")
            raw = os.read(descriptor, 1048577)
            generation = private._generation(info)
            _need(len(raw) == info.st_size and private._generation(os.fstat(descriptor)) == generation
                  == private._generation(os.stat(path.name, dir_fd=directory.fd, follow_symlinks=False)),
                  "windows_preexec_evidence_changed")
            presented.guard(); directory.guard()
            digest = hashlib.sha256(raw).hexdigest()
            _need(stat.S_IMODE(info.st_mode) == 0o600 or
                  (stat.S_IMODE(info.st_mode) == 0o644 and digest == _BEFORE_SHA),
                  "windows_preexec_evidence_unsafe")
            return raw, {"generation": list(generation), "sha256": digest}
        finally:
            os.close(descriptor)


def _assignments(raw, names):
    found = {}
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in names:
                _need(name not in found)
                found[name] = ast.literal_eval(node.value)
    _need(set(found) == set(names))
    return found


def _frame(result, prepared, script, receipt):
    """Authenticate the retained original controller's complete terminal frame."""
    _need(type(result) is dict and result.get("state") == "observed"
          and result.get("operationId") == prepared["controllerId"]
          and result.get("machine") == prepared["binding"]["spec"]["deploymentId"]
          and result.get("provider") == prepared["binding"]["provider"]
          and result.get("job") == receipt
          and all(result.get(k) == v for k, v in prepared["host"].items()))
    control = result.get("jobController")
    _need(type(control) is dict and set(control) == {"intent", "ack", "terminal"})
    intent, ack, terminal = (control[k] for k in ("intent", "ack", "terminal"))
    _need(type(intent) is dict)
    digest = hashlib.sha256(script.encode()).hexdigest()
    expected = {"schemaVersion":1,"operationId":prepared["controllerId"],
                "label":intent.get("label"),"sourceSha256":digest}
    _need(intent.get("operationId") == expected["operationId"]
          and intent.get("sourceSha256") == digest and intent.get("controllerIdentity") == expected
          and intent.get("actor") == prepared["host"]["actor"]
          and intent.get("hostBoot") == prepared["host"]["hostBoot"] and intent.get("replayAllowed") is False
          and type(intent.get("label")) is str and type(ack) is dict
          and ack.get("operationId") == expected["operationId"] and ack.get("label") == intent["label"]
          and ack.get("replayAllowed") is False and type(ack.get("ack")) is dict)
    _need(type(terminal) is dict and terminal.get("exited") is True
          and type(terminal.get("exitcode")) is int and terminal["exitcode"] == 0
          and terminal.get("out-truncated", False) is False and terminal.get("err-truncated", False) is False)
    try:
        error = base64.b64decode(terminal.get("err-data", ""), validate=True)
        raw = base64.b64decode(terminal.get("out-data", ""), validate=True)
        _need(not error and 0 < len(raw) <= 65536)
        body = json.loads(raw.decode("utf-8-sig"))
    except (ValueError, TypeError, UnicodeError):
        raise ValueError("windows_preexec_controller_invalid") from None
    _need(type(body) is dict and set(body) == set(expected) | {"owner", "result"}
          and all(body.get(k) == v for k, v in expected.items()) and body["result"] == receipt)
    owner = body.get("owner")
    _need(type(owner) is dict and set(owner) == {"pid", "birth"}
          and type(owner["pid"]) is int and 0 < owner["pid"] < 2**31
          and owner["pid"] == ack["ack"].get("pid") and type(owner["birth"]) is str
          and re.fullmatch(r"[1-9][0-9]{0,19}", owner["birth"]) and int(owner["birth"]) < 2**64)
    return owner


@dataclass(frozen=True)
class PreexecRejection:
    """Opaque authenticated evidence; values are public infrastructure identities."""
    configuration: str
    proof_sha256: str
    _root: Path = field(repr=False, compare=False)
    _pins: tuple = field(repr=False, compare=False)
    _authority: object = field(repr=False, compare=False)

    def guard(self):
        _need(self._authority is _AUTHORITY, "windows_preexec_authority_invalid")
        for path, expected in self._pins:
            _, actual = _payload(self._root, path)
            _need(actual == expected, "windows_preexec_evidence_changed")
        return json.loads(self.configuration)


def authenticate_preexec_rejection(root, proof_relative_path, expected_sha256, binding):
    """Read only the explicitly reviewed rejection; never execute old source."""
    from . import readiness_windows_jobs as jobs
    _need(type(binding) is jobs.WindowsJobBinding and type(expected_sha256) is str
          and _DIGEST.fullmatch(expected_sha256))
    root = Path(root).resolve(strict=True)
    raw, proof_pin = _payload(root, proof_relative_path)
    _need(proof_pin["sha256"] == expected_sha256, "windows_preexec_proof_changed")
    proof = json.loads(raw)
    _need(type(proof) is dict and proof.get("schemaVersion") == 1
          and type(proof["schemaVersion"]) is int
          and proof.get("kind") == "windows-job-authenticated-preexec-rejection"
          and proof.get("state") == "preexec-rejected" and proof.get("originalOutcome") == "unknown"
          and proof.get("originalOutcomePreserved") is True
          and all(proof.get(k) is False for k in ("replayAllowed", "startAuthority", "cleanupAuthority"))
          and proof.get("reason") == "atomic_directory_default_owner_rejected_before_owner_source_and_launch"
          and proof.get("machine") == binding.machine)
    operation = jobs._uuid(proof.get("operationId"))
    controller = jobs._uuid(proof.get("controllerOperationId"))
    observation = jobs._uuid(proof.get("readOnlyObservationId"))
    attestation = proof.get("exclusiveOperatorAttestation")
    _need(type(attestation) is dict and all(attestation.get(k) is True for k in
          ("oneSubmission", "workersIssuedNoGuestEffects", "noConcurrentWriterRepairReplayAclChangeOrCleanup"))
          and type(attestation.get("operator")) is str and bool(attestation["operator"])
          and type(attestation.get("scope")) is str and bool(attestation["scope"]))
    evidence = proof.get("evidence")
    _need(type(evidence) is dict and 1 <= len(evidence) <= 64)
    values, pins, total = {}, [(proof_relative_path, proof_pin)], 0
    for path, expected in evidence.items():
        _need(type(expected) is dict and set(expected) == {"bytes", "sha256"}
              and type(expected["bytes"]) is int and expected["bytes"] >= 0
              and type(expected["sha256"]) is str and _DIGEST.fullmatch(expected["sha256"]))
        data, pin = _payload(root, path)
        total += len(data)
        _need(total <= 4194304 and len(data) == expected["bytes"] and pin["sha256"] == expected["sha256"],
              "windows_preexec_evidence_changed")
        values[path], pins = data, pins + [(path, pin)]
    before = [data for path, data in values.items() if hashlib.sha256(data).hexdigest() == _BEFORE_SHA]
    _need(len(before) == 1, "windows_preexec_phase_unreviewed")
    native = _assignments(before[0], {"_NATIVE"})["_NATIVE"]
    _need(type(native) is str and native.count('Need(CreateDirectoryW(job,IntPtr.Zero),"ADMISSION_CREATE");Private(job);') == 1)
    # The immutable reviewed producer rejects that private-directory check before
    # it writes owner.ps1/intent.json or calls CreateProcessW. No old Python runs.
    stage = native.index('Need(CreateDirectoryW(job,IntPtr.Zero),"ADMISSION_CREATE");Private(job);')
    _need(stage < native.index('string script=Path.Combine(job,"owner.ps1");', stage)
          < native.index('Need(CreateProcessW(', stage))
    old_prefix = jobs._prefix().replace(jobs._NATIVE, native, 1)
    prefix = ".runtime/readiness-windows-jobs-controllers/" + operation + "/" + controller + "/"
    _need(prefix + "prepared.json" in values and prefix + "result.json" in values)
    prepared = json.loads(values[prefix + "prepared.json"])
    _need(type(prepared) is dict and prepared.get("controllerId") == controller
          and prepared.get("operationId") == operation and prepared.get("mode") == "job-start"
          and prepared.get("binding", {}).get("spec", {}).get("deploymentId") == binding.machine)
    packet_path = prefix + "job-start.py"
    _need(packet_path in values and hashlib.sha256(values[packet_path]).hexdigest() == prepared.get("packetSha256"))
    literal = jobs._packet_literals(values[packet_path])
    _need(literal["OPERATION"] == controller and literal["MODE"] == "job-start"
          and literal["JOB_EXPECTED"] == prepared["host"] and literal["SPEC"] == prepared["binding"]["spec"]
          and literal["CONTEXT"] == prepared["binding"]["context"] and literal["PROVIDER"] == prepared["binding"]["provider"])
    script = literal["JOB_SCRIPT"]
    _need(type(script) is str and script.startswith(old_prefix))
    matches = re.findall(r"FromBase64String\('([A-Za-z0-9+/=]+)'\)", script[len(old_prefix):])
    _need(len(matches) == 1)
    config = json.loads(base64.b64decode(matches[0], validate=True))
    _need(type(config) is dict and config == jobs._config(binding, operation, config.get("count"), config.get("intervalMilliseconds", 0)/1000))
    owner = (old_prefix + "[NativeJob]::Own(" + jobs._literal(config) + ")\n").encode()
    program_sha = hashlib.sha256(owner).hexdigest()
    expected_script = old_prefix + "[Console]::WriteLine([NativeJob]::Control('start'," + jobs._literal(config) + ",'" + base64.b64encode(owner).decode() + "','" + program_sha + "'))\n"
    _need(script == expected_script, "windows_preexec_original_source_changed")
    receipt = {key: config[key] for key in ("schemaVersion", "operationId", "machine", "boot", "rootGeneration", "admissionGeneration")}
    receipt.update(state="unknown", reason="windows_job_root_owner", replayAllowed=False)
    result = json.loads(values[prefix + "result.json"])
    controller_owner = _frame(result, prepared, script, receipt)
    diag_prefix = ".runtime/tool-recovery-windows/direct/admitted-" + observation + "/"
    _need(diag_prefix + "caller.py" in values and diag_prefix + "result.json" in values)
    caller = values[diag_prefix + "caller.py"]
    _need(hashlib.sha256(caller).hexdigest() == _DIAGNOSTIC_CALLER_SHA, "windows_preexec_phase_unreviewed")
    diagnostic = _assignments(caller, {"SESSION_SCRIPT"})["SESSION_SCRIPT"]
    _need(type(diagnostic) is str and hashlib.sha256(diagnostic.encode()).hexdigest() == _DIAGNOSTIC_SHA,
          "windows_preexec_phase_unreviewed")
    observed = json.loads(values[diag_prefix + "result.json"])
    _need(type(observed) is dict and observed.get("operationId") == observation and observed.get("state") == "observed"
          and observed.get("machine") == binding.machine and observed.get("provider") == prepared["binding"]["provider"]
          and all(observed.get(k) == v for k, v in prepared["host"].items()))
    facts = observed.get("sessionFacts")
    _need(type(facts) is dict and all(facts.get(k) == v for k, v in receipt.items() if k not in {"state", "reason", "replayAllowed"})
          and facts.get("visibilityComplete") is True and facts.get("controllerAbsent") is True
          and facts.get("controllerPid") == controller_owner["pid"] and facts.get("controllerBirth") == controller_owner["birth"]
          and facts.get("entries") == [] and type(facts.get("entryCount")) is int and facts["entryCount"] == 0
          and facts.get("matchingActors") == [] and type(facts.get("actorCount")) is int and facts["actorCount"] == 0
          and facts.get("tokenUserSid") == "S-1-5-18" and facts.get("tokenDefaultOwnerSid") == "S-1-5-32-544"
          and facts.get("jobOwnerSid") == "S-1-5-32-544" and facts.get("sessionId") == 0 and facts.get("replayAllowed") is False)
    rules = [{"sid":sid,"rights":"FullControl","inherited":True} for sid in ("S-1-5-18", "S-1-5-32-544")]
    _need(facts.get("jobRules") == rules and facts.get("programSha256") == program_sha)
    unchanged = proof.get("claimAndDirectoryUnchanged")
    _need(type(unchanged) is dict and set(unchanged) == {"claimGeneration", "claimNonce", "claimSha256", "jobGeneration", "programSha256"}
          and all(facts.get(k) == v for k, v in unchanged.items()))
    jobs._uuid(facts["claimNonce"])
    for key in ("claimGeneration", "jobGeneration"):
        _need(type(facts[key]) is str and jobs._ROOT.fullmatch(facts[key]))
    _need(type(facts["claimSha256"]) is str and _DIGEST.fullmatch(facts["claimSha256"]))
    claim = dict(config, nonce=facts["claimNonce"], programSha256=program_sha)
    configuration = dict(claim, claimGeneration=facts["claimGeneration"], claimSha256=facts["claimSha256"],
                         jobGeneration=facts["jobGeneration"], controllerPid=controller_owner["pid"],
                         controllerBirth=controller_owner["birth"], proofSha256=expected_sha256)
    return PreexecRejection(_canonical(configuration), expected_sha256, root, tuple(pins), _AUTHORITY)


def _records(root, target, machine, *, create=False):
    from . import readiness_windows as windows
    from . import durable_remote_job as durable
    from . import readiness_windows_jobs as jobs
    jobs._uuid(machine)
    _need(type(target) is str and 1 <= len(target) <= 512)
    parent = Path(root).resolve(strict=True) / ".runtime/readiness-windows-preexec"
    if create:
        windows._directory(parent)
    elif not parent.exists() and not parent.is_symlink():
        return None
    durable._private(parent, directory=True)
    _need(parent.resolve() == parent, "windows_preexec_path_invalid")
    label = hashlib.sha256(_canonical([target, machine]).encode()).hexdigest()
    directory = parent / label
    if create:
        windows._directory(directory)
    elif not directory.exists() and not directory.is_symlink():
        return None
    durable._private(directory, directory=True)
    _need(directory.resolve() == directory, "windows_preexec_path_invalid")
    return directory


def register_preexec_rejection(root, target, binding, proof_relative_path, reviewed_sha256):
    """Explicit private metadata admission; confers no guest execution authority."""
    from . import readiness_windows as windows
    from . import readiness_fixture_registry as registry
    proof = authenticate_preexec_rejection(root, proof_relative_path, reviewed_sha256, binding)
    configuration = proof.guard()
    directory = _records(root, target, binding.machine, create=True)
    path = directory / (configuration["operationId"] + ".json")
    record = {"schemaVersion":1,"target":target,"machine":binding.machine,"operationId":configuration["operationId"],
              "proofPath":proof_relative_path,"proofSha256":reviewed_sha256,"binding":json.loads(_canonical(configuration))}
    try:
        windows._save(path, record)
    except FileExistsError:
        _need(registry._json(path)[0] == record, "windows_preexec_acceptance_changed")
    return proof


def preexec_rejections(root, target, binding):
    """Pure accepted-proof lookup, preserving missing/changed-history blockers."""
    from . import readiness_fixture_registry as registry
    from . import readiness_windows_jobs as jobs
    _need(type(binding) is jobs.WindowsJobBinding)
    directory = _records(root, target, binding.machine)
    if directory is None:
        return ()
    paths = sorted(directory.iterdir())
    _need(len(paths) <= 16, "windows_preexec_evidence_bound")
    result = []
    for path in paths:
        _need(path.suffix == ".json" and jobs._uuid(path.stem) == path.stem)
        record, pin = registry._json(path)
        _need(type(record) is dict and set(record) == {"schemaVersion", "target", "machine", "operationId", "proofPath", "proofSha256", "binding"}
              and type(record["schemaVersion"]) is int and record["schemaVersion"] == 1
              and record["target"] == target and record["machine"] == binding.machine and record["operationId"] == path.stem)
        # A historical proof is authenticated against its original boot, then the
        # guest inventory separately fences the positively observed current boot.
        old = record["binding"]
        original = jobs.WindowsJobBinding(binding.machine, old["boot"], binding.root_generation, binding.admission_generation)
        proof = authenticate_preexec_rejection(root, record["proofPath"], record["proofSha256"], original)
        _need(proof.guard() == old, "windows_preexec_acceptance_changed")
        relative = str(path.relative_to(Path(root).resolve(strict=True)))
        result.append(PreexecRejection(proof.configuration, proof.proof_sha256, proof._root,
                                      proof._pins + ((relative, pin),), _AUTHORITY))
    return tuple(result)


def inventory_component(machine, boot, root_generation, admission_generation, *, rejections=(), continuity=None):
    """Fixed extra CLR definitions plus validated config for composite idle.

    The caller supplies the unchanged jobs._prefix() once, then these definitions.
    It may replace only the outer config's boot with its freshly observed OS boot;
    the guest separately compares that boot with every immutable original proof.
    """
    from . import readiness_windows_jobs as jobs
    binding = jobs.WindowsJobBinding(machine, boot, root_generation, admission_generation)
    _need(type(rejections) is tuple and 0 < len(rejections) <= 16, "windows_preexec_inventory_invalid")
    _need(continuity is None, "windows_preexec_storage_continuity_unqualified")
    values, seen = [], set()
    for proof in rejections:
        _need(type(proof) is PreexecRejection, "windows_preexec_authority_invalid")
        value = proof.guard()
        _need(value["machine"] == machine and value["rootGeneration"] == root_generation
              and value["admissionGeneration"] == admission_generation, "windows_preexec_namespace_changed")
        # Historical boot support requires a separately qualified source-held
        # storage witness. No caller dictionary or boolean can grant it.
        _need(value["boot"] == boot, "windows_preexec_storage_continuity_required")
        _need(value["operationId"] not in seen, "windows_preexec_inventory_invalid")
        seen.add(value["operationId"]); values.append(value)
    config = {"schemaVersion":1,"machine":binding.machine,"boot":binding.boot,
              "rootGeneration":binding.root_generation,"admissionGeneration":binding.admission_generation,
              "rejections":values}
    definitions = ("Add-Type -TypeDefinition @'\n" + _INVENTORY +
                   "\n'@ -ReferencedAssemblies @('System','System.Core','System.Management','System.Web.Extensions')\n")
    return definitions, config


def inventory_source(machine, boot, root_generation, admission_generation, *, rejections=(), continuity=None):
    """Build a fixed observer; no guest file creation, replay or ACL changes."""
    from . import readiness_windows_jobs as jobs
    definitions, config = inventory_component(machine, boot, root_generation, admission_generation,
                                              rejections=rejections, continuity=continuity)
    return (jobs._prefix() + definitions +
            "[Console]::WriteLine([NativePreexecInventory]::Run([NativeJob]," + jobs._literal(config) + "))\n").encode()


def validate_inventory(value, machine, boot, root_generation, admission_generation, *, rejections=(), continuity=None):
    from . import readiness_windows_jobs as jobs
    inventory_source(machine, boot, root_generation, admission_generation, rejections=rejections, continuity=continuity)
    return jobs.validate_inventory(value, machine, boot, root_generation, admission_generation)


_INVENTORY = r'''
using System;using System.IO;using System.Text;using System.Diagnostics;using System.Reflection;using System.Collections.Generic;
using System.Management;using System.Runtime.InteropServices;using System.Security.AccessControl;using System.Security.Principal;
using System.Security.Cryptography;using System.Web.Script.Serialization;
public sealed class NativePreexecInventory {
 static JavaScriptSerializer Json=new JavaScriptSerializer(){MaxJsonLength=262144};
 readonly Type job;
 NativePreexecInventory(Type type){job=type;}
 static void Need(bool yes){if(!yes)throw new Exception("PREEXEC_CUSTODY_CHANGED");}
 object Call(string name,params object[] args){var method=job.GetMethod(name,BindingFlags.NonPublic|BindingFlags.Static);Need(method!=null);return method.Invoke(null,args);}
 static string S(Dictionary<string,object> v,string key){return Convert.ToString(v[key],System.Globalization.CultureInfo.InvariantCulture);}
 static string Hash(byte[] value){using(var h=SHA256.Create())return BitConverter.ToString(h.ComputeHash(value)).Replace("-","").ToLowerInvariant();}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr CreateFileW(string path,UInt32 access,UInt32 share,IntPtr security,UInt32 disposition,UInt32 flags,IntPtr template);
 [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr handle);
 [DllImport("shell32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr CommandLineToArgvW(string command,out int count);
 [DllImport("kernel32.dll")]static extern IntPtr LocalFree(IntPtr value);
 static string[] Arguments(string text){int count;IntPtr buffer=CommandLineToArgvW(text,out count);Need(buffer!=IntPtr.Zero);try{Need(count>0&&count<=1024);var result=new string[count];for(int n=0;n<count;n++)result[n]=Marshal.PtrToStringUni(Marshal.ReadIntPtr(buffer,n*IntPtr.Size));return result;}finally{LocalFree(buffer);}}
 void Census(string owner){
  string canonical=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),@"System32\WindowsPowerShell\v1.0\powershell.exe");int total=0;
  using(var query=new ManagementObjectSearcher("SELECT ProcessId,ExecutablePath,CommandLine,SessionId FROM Win32_Process WHERE Name='powershell.exe'"))foreach(ManagementObject p in query.Get()){
   Need(++total<=1024&&p["ExecutablePath"]!=null&&p["CommandLine"]!=null);
   Need(string.Equals(Convert.ToString(p["ExecutablePath"]),canonical,StringComparison.OrdinalIgnoreCase));
   string[] argv=Arguments(Convert.ToString(p["CommandLine"]));
   for(int n=1;n<argv.Length;n++)if(string.Equals(argv[n],"-File",StringComparison.OrdinalIgnoreCase)){
    Need(n+1<argv.Length);if(string.Equals(argv[n+1],owner,StringComparison.OrdinalIgnoreCase)){
     var sid=p.InvokeMethod("GetOwnerSid",(ManagementBaseObject)null,(InvokeMethodOptions)null);Need(sid!=null&&Convert.ToInt32(sid["ReturnValue"])==0&&Convert.ToString(sid["Sid"])=="S-1-5-18"&&Convert.ToInt32(p["SessionId"])==0);
     // A live or raced matching owner is a blocker, never evidence of absence.
     Need(false);
    }
   }
  }
 }
 void JobAcl(string path){
  var acl=Directory.GetAccessControl(path);Need(acl.GetOwner(typeof(SecurityIdentifier)).Value=="S-1-5-32-544"&&!acl.AreAccessRulesProtected);
  var allowed=new HashSet<string>();int count=0;
  foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier))){
   Need(++count<=2&&rule.IsInherited&&rule.AccessControlType==AccessControlType.Allow&&rule.FileSystemRights==FileSystemRights.FullControl
     &&rule.InheritanceFlags==(InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit)&&rule.PropagationFlags==PropagationFlags.None);
   Need(allowed.Add(rule.IdentityReference.Value));
  }
  Need(count==2&&allowed.SetEquals(new[]{"S-1-5-18","S-1-5-32-544"}));
 }
 void Rejection(Dictionary<string,object> c,Dictionary<string,object> proof,string root,string claim){
  foreach(string key in new[]{"machine","boot","rootGeneration","admissionGeneration"})Need(S(c,key)==S(proof,key));
  string op=S(proof,"operationId"),jobPath=Path.Combine(root,"operations",op);
  Need(Path.GetFileName(claim)==op+".json");Call("NoLink",jobPath);
  IntPtr held=CreateFileW(jobPath,0x00020080,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);Need(held!=new IntPtr(-1));
  try{
   using(var file=new FileStream(claim,FileMode.Open,FileAccess.Read,FileShare.Read)){
    Need(file.Length>0&&file.Length<=262144);byte[] raw=new byte[(int)file.Length];int offset=0;
    while(offset<raw.Length){int n=file.Read(raw,offset,raw.Length-offset);Need(n>0);offset+=n;}
    Need(Hash(raw)==S(proof,"claimSha256")&&(string)Call("Tag",claim)==S(proof,"claimGeneration"));
    var intent=Json.Deserialize<Dictionary<string,object>>(Encoding.UTF8.GetString(raw));
    foreach(string key in new[]{"schemaVersion","operationId","machine","boot","rootGeneration","admissionGeneration","count","intervalMilliseconds","nonce","programSha256"})Need(intent.ContainsKey(key)&&Json.Serialize(intent[key])==Json.Serialize(proof[key]));
    Need(intent.Count==10&&(string)Call("Tag",jobPath)==S(proof,"jobGeneration"));
    JobAcl(jobPath);Need(Directory.GetFileSystemEntries(jobPath).Length==0);
    Need((string)Call("Birth",Convert.ToInt32(proof["controllerPid"]))!=S(proof,"controllerBirth"));
    Census(Path.Combine(jobPath,"owner.ps1"));
    Call("Machine",c,false);Need((string)Call("RootGuard",c)==root);
    Call("NoLink",jobPath);JobAcl(jobPath);Need((string)Call("Tag",jobPath)==S(proof,"jobGeneration")&&Directory.GetFileSystemEntries(jobPath).Length==0
      &&(string)Call("Tag",claim)==S(proof,"claimGeneration"));
    file.Position=0;byte[] after=new byte[raw.Length];int read=0;while(read<after.Length){int n=file.Read(after,read,after.Length-read);Need(n>0);read+=n;}Need(file.Length==raw.Length&&Hash(after)==Hash(raw));
   }
  }finally{CloseHandle(held);}
 }
 string Inventory(Dictionary<string,object> c){
  var blockers=new List<Dictionary<string,object>>();var result=new Dictionary<string,object>{{"schemaVersion",1},{"machine",c["machine"]},{"boot",c["boot"]},{"rootGeneration",c["rootGeneration"]},{"admissionGeneration",c["admissionGeneration"]},{"visibilityComplete",false},{"terminalCount",0},{"blockers",blockers}};
  FileStream admission=null;
  try{
   Call("Machine",c,false);string root=(string)Call("RootGuard",c);
   var proofs=new Dictionary<string,Dictionary<string,object>>();foreach(object item in (System.Collections.IEnumerable)c["rejections"]){var proof=(Dictionary<string,object>)item;Need(proofs.Count<16&&!proofs.ContainsKey(S(proof,"operationId")));proofs.Add(S(proof,"operationId"),proof);}
   string lockPath=Path.Combine(root,"admission.lock");Need(File.Exists(lockPath));Call("FileTag",lockPath);admission=new FileStream(lockPath,FileMode.Open,FileAccess.ReadWrite,FileShare.None);
   string[] claims=Directory.GetFileSystemEntries(Path.Combine(root,"admissions"));Need(claims.Length<=1024);var seen=new HashSet<string>();int terminal=0;
   foreach(string path in claims){
    Guid op;string name=Path.GetFileNameWithoutExtension(path);Need(Path.GetExtension(path)==".json"&&Guid.TryParse(name,out op)&&op.ToString("D")==name&&seen.Add(name));
    if(proofs.ContainsKey(name))Rejection(c,proofs[name],root,path);
    else{var intent=(Dictionary<string,object>)Call("Read",path);Need(S(intent,"operationId")==name);var observed=(Dictionary<string,object>)Call("Observe",intent);if(S(observed,"state")=="terminal")terminal++;else blockers.Add(new Dictionary<string,object>{{"operationId",name},{"reason","job_original_work_not_terminal"}});}
   }
   foreach(string name in proofs.Keys)Need(seen.Contains(name));
   foreach(string path in Directory.GetFileSystemEntries(Path.Combine(root,"operations")))Need(Directory.Exists(path)&&seen.Contains(Path.GetFileName(path)));
   Call("Machine",c,false);Call("RootGuard",c);result["terminalCount"]=terminal;result["visibilityComplete"]=true;
  }catch(Exception){blockers.Add(new Dictionary<string,object>{{"operationId",null},{"reason","job_inventory_unavailable"}});}finally{if(admission!=null)admission.Dispose();}return Json.Serialize(result);
 }
 public static string Run(Type job,string raw){return new NativePreexecInventory(job).Inventory(Json.Deserialize<Dictionary<string,object>>(raw));}
}
'''

"""One guarded API29 48 MiB public routing-document acceptance run.

The tool accepts no arbitrary remote command or input file.  It generates the
fixed 56,000-domain fixture in an owned private job, journals before submission,
and observes the same worker after transport loss.  Uncertain results are never
resubmitted.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any

try:
    from . import android_admission_readback, android_cli_stage, android_observation, android_package_install, native_artifact_registry, ssh_transport
except ImportError:  # pragma: no cover
    import android_admission_readback, android_cli_stage, android_observation, android_package_install, native_artifact_registry, ssh_transport


_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FIXTURE_SHA = "8ee46b5adc12d9f4a043f45360691ff02d86073f09a3bd3f2873d6c421706051"
_FIXTURE_SIZE = 11_536_164
_DOMAIN_COUNT = 56_000

_HEAP_PROBE = r'''import json,subprocess,sys
adb,serial,avd=sys.argv[1:]
def get(*words):
 try: result=subprocess.run([adb,"-s",serial,"shell","-T",*words],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=15,check=False)
 except (OSError,subprocess.TimeoutExpired): return None
 if result.returncode or len(result.stdout)>1024: return None
 try: return result.stdout.decode("utf-8","strict").strip()
 except UnicodeError: return None
names={get("getprop","ro.kernel.qemu.avd_name"),get("getprop","ro.boot.qemu.avd_name")}-{None,""}
heap=get("getprop","dalvik.vm.heapsize"); growth=get("getprop","dalvik.vm.heapgrowthlimit")
ready=get("id","-u")=="2000" and get("getprop","ro.build.version.sdk")=="29" and names=={avd} and get("getprop","ro.product.cpu.abi")=="x86_64" and isinstance(heap,str) and heap.lower()=="48m" and isinstance(growth,str) and growth.lower() in ("","48m")
print(json.dumps({"ready":ready},separators=(",",":")))'''

_PUBLIC_PREFLIGHT = android_observation._canonical_cli_environment_source() + r'''
import json,pathlib,subprocess,sys
adb,cli,serial,owner,revision=sys.argv[1:]
env=public_cli_environment(adb,pathlib.Path(cli))
def read(*words):
 try: result=subprocess.run([cli,"--json","--android","--serial",serial,"--timeout-seconds","30",*words],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=35,env=env,check=False)
 except (OSError,subprocess.TimeoutExpired): return None
 if result.returncode or len(result.stdout)>65536: return None
 try: return json.loads(result.stdout)
 except (ValueError,UnicodeError): return None
status=read("status"); operations=read("operations","list")
ready=all(isinstance(v,dict) and v.get("ok") is True and v.get("final") is True and v.get("code")=="OK" and v.get("controllerId")==owner and v.get("configurationRevision")==int(revision) for v in (status,operations))
ready=ready and isinstance(status.get("data"),dict) and status["data"].get("runtimeRunning") is False and status["data"].get("runtimeObservation")=="stopped" and isinstance(operations.get("data"),dict) and operations["data"].get("operations")==[]
print(json.dumps({"ready":ready},separators=(",",":")))'''


def _journal(root: Path | str, correlation: str) -> Path:
    return Path(root).resolve() / ".rag_index" / "android-document-jobs" / (correlation + ".json")


def _lease(root: Path | str, host: str, device: str, correlation: str) -> Path:
    return _journal(root, correlation).parent / ("lease-" + host + "-" + device + ".json")


def _claim_device(root: Path | str, host: str, device: str, correlation: str) -> None:
    path = _lease(root, host, device, correlation)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("Android document lease directory is not private")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(json.dumps({"host": host, "device": device, "correlationId": correlation},
                                sort_keys=True, separators=(",", ":")).encode() + b"\n")
        output.flush(); os.fsync(output.fileno())
    directory = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(directory)
    finally: os.close(directory)


def _release_device(root: Path | str, host: str, device: str, correlation: str) -> bool:
    """Release only the exact terminal owner; unknown work retains its lease."""
    path = _lease(root, host, device, correlation)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return True  # An earlier collect already released this terminal lease.
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            return False
        with os.fdopen(fd, "rb", closefd=False) as source:
            raw = source.read(1025)
        if len(raw) > 1024 or json.loads(raw) != {"host": host, "device": device, "correlationId": correlation}:
            return False
        current = path.lstat()
        if current.st_dev != info.st_dev or current.st_ino != info.st_ino:
            return False
        path.unlink()
        directory = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
        return True
    except (OSError, ValueError, TypeError):
        return False
    finally:
        os.close(fd)


def _save(root: Path | str, intent: dict[str, Any]) -> None:
    path = _journal(root, intent["correlationId"])
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("Android document journal is not private")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(json.dumps(intent, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        output.flush(); os.fsync(output.fileno())
    directory = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(directory)
    finally: os.close(directory)


def _reserve(root: Path | str, intent: dict[str, Any]) -> None:
    # A local journal failure must not leave an apparently active device lease.
    _save(root, intent)
    _claim_device(root, intent["host"], intent["device"], intent["correlationId"])


def _load(root: Path | str, correlation: str) -> dict[str, Any] | None:
    path = _journal(root, correlation)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                return None
            raw = source.read(8193)
        if len(raw) > 8192: return None
        value = json.loads(raw)
        return value if isinstance(value, dict) and value.get("correlationId") == correlation else None
    except (OSError, ValueError):
        return None


_REMOTE = android_observation._canonical_cli_environment_source() + r'''
import hashlib,json,os,pathlib,re,stat,subprocess,sys,time
adb,cli,serial,avd,api,root,correlation,package_hash,owner,revision,fixture_hash,fixture_size=sys.argv[1:]
def fail(reason):
 print(json.dumps({"state":"unknown","reason":reason},separators=(",",":"))); raise SystemExit(0)
def invoke(args,timeout=45,limit=16777216,env=None,allowed=(0,)):
 try: done=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout,env=env,check=False)
 except (OSError,subprocess.TimeoutExpired): fail("command_outcome_unknown")
 if done.returncode not in allowed or len(done.stdout)>limit: fail("command_failed")
 try: return done.stdout.decode("utf-8","strict").strip()
 except UnicodeError: fail("command_encoding")
def shell(*words): return invoke([adb,"-s",serial,"shell","-T",*words])
def public(*words,limit=16777216,timeout=120,allowed=(0,)):
 raw=invoke([cli,"--json","--android","--serial",serial,"--timeout-seconds",str(timeout),*words],timeout=timeout+15,limit=limit,env=environment,allowed=allowed)
 try: value=json.loads(raw)
 except ValueError: fail("public_result_invalid")
 if not isinstance(value,dict): fail("public_result_invalid")
 return value
def final(value,controller,reason):
 if value.get("ok") is not True or value.get("final") is not True or value.get("code")!="OK" or value.get("controllerId")!=controller: fail(reason)
def package():
 paths=[x.removeprefix("package:") for x in shell("pm","path","com.kardinal.vpncontrol").splitlines() if x.startswith("package:") and x.endswith("/base.apk")]
 if len(paths)!=1 or not paths[0].startswith("/data/app/"): fail("package_path_invalid")
 pair=shell("sha256sum",paths[0]).split()
 if len(pair)!=2 or pair[1]!=paths[0]: fail("package_hash_invalid")
 return pair[0]
if shell("id","-u")!="2000" or shell("getprop","ro.build.version.sdk")!=api or {x for x in (shell("getprop","ro.kernel.qemu.avd_name"),shell("getprop","ro.boot.qemu.avd_name")) if x}!={avd} or shell("getprop","ro.product.cpu.abi")!="x86_64": fail("device_identity_changed")
if shell("getprop","dalvik.vm.heapsize").lower()!="48m" or shell("getprop","dalvik.vm.heapgrowthlimit").lower() not in ("","48m"): fail("heap_not_48m")
if package()!=package_hash: fail("package_changed")
environment=public_cli_environment(adb,pathlib.Path(cli))
base=pathlib.Path(root); info=base.lstat()
if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: fail("private_root_invalid")
job=base/("android-document-job-"+correlation); info=job.lstat()
if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: fail("job_invalid")
opening=public("status",limit=16384,timeout=30); final(opening,owner,"opening_status_changed")
if opening.get("configurationRevision")!=int(revision) or opening.get("data",{}).get("runtimeRunning") is not False or opening.get("data",{}).get("runtimeObservation")!="stopped": fail("opening_runtime_changed")
operations=public("operations","list",limit=16384,timeout=30); final(operations,owner,"opening_operations_changed")
history=operations.get("data",{}).get("operations")
if operations.get("configurationRevision")!=int(revision) or not isinstance(history,list) or any(not isinstance(x,dict) or x.get("final") is not True for x in history): fail("opening_history_nonterminal")
os.umask(0o077)
original=job/"opening-routing.json"
export=public("routing","export","--output",str(original),limit=16384,timeout=300); final(export,owner,"opening_export_failed")
oinfo=original.lstat()
if not stat.S_ISREG(oinfo.st_mode) or oinfo.st_uid!=os.getuid() or stat.S_IMODE(oinfo.st_mode)!=0o600 or not 0<oinfo.st_size<=67108864: fail("opening_export_unsafe")
original_bytes=original.read_bytes(); original_hash=hashlib.sha256(original_bytes).hexdigest()
try: original_document=json.loads(original_bytes)
except ValueError: fail("opening_export_invalid")
if original_document.get("type")!="vpn_control_routing_rules" or original_document.get("version")!=7 or not isinstance(original_document.get("rules"),dict): fail("opening_export_invalid")
prefix="."+"a"*60+"."+"b"*60+"."+"c"*60+".example.test"
fixture={"type":"vpn_control_routing_rules","version":7,"rules":{"ignore_rules":False,"block_quic_udp_443":False,"proxy_packages":[],"direct_domain_suffixes":[f"d{i:05d}"+prefix for i in range(56000)]}}
fixture_bytes=json.dumps(fixture).encode()
if len(fixture_bytes)!=int(fixture_size) or hashlib.sha256(fixture_bytes).hexdigest()!=fixture_hash: fail("fixture_generation_mismatch")
target=job/"routing-v7-56000.json"
with target.open("xb") as output: output.write(fixture_bytes); output.flush(); os.fsync(output.fileno())
if stat.S_IMODE(target.stat().st_mode)!=0o600: fail("fixture_file_unsafe")
imported=public("--controller-id",owner,"--if-revision",revision,"routing","import","--input",str(target),limit=16384,timeout=300)
final(imported,owner,"import_not_final")
operation_id=imported.get("operationId")
if operation_id:
 waited=public("--controller-id",owner,"operations","wait",operation_id,limit=16384,timeout=300); final(waited,owner,"retained_wait_failed")
 if waited.get("operationId")!=operation_id: fail("retained_operation_changed")
read=public("routing","show",limit=16777216,timeout=300); final(read,owner,"full_read_failed")
routing=read.get("data",{}).get("routing")
if not isinstance(routing,dict) or routing.get("rules")!=fixture["rules"] or read.get("configurationRevision",-1)<=int(revision): fail("full_read_mismatch")
new_revision=read["configurationRevision"]
noop=public("--controller-id",owner,"--if-revision",str(new_revision),"routing","import","--input",str(target),limit=16384,timeout=300); final(noop,owner,"new_request_noop_failed")
if noop.get("configurationRevision")!=new_revision: fail("new_request_changed_revision")
private=job/"fixture-export.json"
export=public("routing","export","--output",str(private),limit=16384,timeout=300); final(export,owner,"private_export_failed")
pinfo=private.lstat()
if not stat.S_ISREG(pinfo.st_mode) or pinfo.st_uid!=os.getuid() or stat.S_IMODE(pinfo.st_mode)!=0o600 or pinfo.st_size<=int(fixture_size): fail("private_export_unsafe")
try: exported=json.loads(private.read_bytes())
except ValueError: fail("private_export_invalid")
if exported.get("rules")!=fixture["rules"]: fail("private_export_mismatch")
private_hash=hashlib.sha256(private.read_bytes()).hexdigest()
pid=shell("pidof","com.kardinal.vpncontrol").split()
if len(pid)!=1 or not pid[0].isdigit(): fail("owner_pid_unknown")
invoke([adb,"-s",serial,"shell","-T","am","kill","com.kardinal.vpncontrol"],timeout=30)
for _ in range(40):
 observed=invoke([adb,"-s",serial,"shell","-T","pidof","com.kardinal.vpncontrol"],timeout=15,allowed=(0,1)).split()
 if pid[0] not in observed: break
 time.sleep(.25)
else: fail("old_owner_process_survived")
cold=public("status",limit=16384,timeout=60)
cold_owner=cold.get("controllerId")
if not isinstance(cold_owner,str) or not cold_owner or cold_owner==owner: fail("cold_owner_not_replaced")
final(cold,cold_owner,"cold_status_invalid")
if cold.get("data",{}).get("runtimeRunning") is not False: fail("cold_runtime_started")
cold_read=public("routing","show",limit=16777216,timeout=300); final(cold_read,cold_owner,"cold_read_failed")
if cold_read.get("data",{}).get("routing",{}).get("rules")!=fixture["rules"]: fail("cold_read_mismatch")
restore=public("--controller-id",cold_owner,"--if-revision",str(cold_read["configurationRevision"]),"routing","import","--input",str(original),limit=16384,timeout=300); final(restore,cold_owner,"restore_not_final")
closing=public("routing","show",limit=16777216,timeout=300); final(closing,cold_owner,"closing_read_failed")
if closing.get("data",{}).get("routing",{}).get("rules")!=original_document["rules"]: fail("restore_mismatch")
last=public("status",limit=16384,timeout=30); final(last,cold_owner,"closing_status_invalid")
if last.get("data",{}).get("runtimeRunning") is not False: fail("closing_runtime_started")
if package()!=package_hash: fail("closing_package_changed")
print(json.dumps({"state":"complete","sourcePackageSha256":package_hash,"device":{"uid":"2000","api":int(api),"avd":avd,"heap":"48m"},"opening":{"controllerId":owner,"revision":int(revision),"routingSha256":original_hash,"routingBytes":len(original_bytes)},"fixture":{"sha256":fixture_hash,"bytes":len(fixture_bytes),"domainCount":56000},"import":{"operationId":operation_id,"revision":new_revision},"fullRead":True,"newRequestNoop":True,"retainedWait":bool(operation_id),"privateExport":{"sha256":private_hash,"bytes":pinfo.st_size,"mode":"0600"},"coldRead":True,"restore":{"controllerId":cold_owner,"openingRulesRestored":True,"runtimeOff":True},"sameRequestRetry":False},separators=(",",":")))
'''


def _worker(remote_source: str, args: list[str]) -> str:
    command = ["python3", "-I", "-B", "-c", "exec(" + repr(remote_source) + ")", *args]
    return r'''import json,os,pathlib,subprocess,sys,time
job=pathlib.Path(sys.argv[1])
while not (job/"release").exists(): time.sleep(.02)
try:
 done=subprocess.run(''' + repr(command) + r''',stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=1800,check=False)
 if done.returncode or len(done.stdout)>16384: value={"state":"unknown","reason":"worker_failed"}
 else:
  observed=json.loads(done.stdout)
  value={"state":"complete" if observed.get("state")=="complete" else "unknown","result":observed if observed.get("state")=="complete" else None,"reason":None if observed.get("state")=="complete" else observed.get("reason","scenario_unknown")}
except (OSError,subprocess.TimeoutExpired,ValueError,UnicodeError): value={"state":"unknown","reason":"worker_unknown"}
temporary=job/"result.json.tmp"; final=job/"result.json"
payload=json.dumps(value,sort_keys=True,separators=(",",":")).encode()+b"\n"
fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
with os.fdopen(fd,"wb") as output: output.write(payload); output.flush(); os.fsync(output.fileno())
os.replace(temporary,final)
directory=os.open(job,os.O_RDONLY); os.fsync(directory); os.close(directory)
'''


_SUBMIT = android_admission_readback._ASYNC_SUBMIT.replace("android-readback-job-", "android-document-job-")
_STATUS = r'''import hashlib,json,os,pathlib,re,stat,sys
root,correlation,expected_json=sys.argv[1:]
def emit(state,reason=None,**extra):
 print(json.dumps({"state":state,"reason":reason,"correlationId":correlation,**extra},separators=(",",":"))); raise SystemExit(0)
job=pathlib.Path(root)/("android-document-job-"+correlation)
try:
 info=job.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: emit("unknown","unsafe_job")
 def private(name,limit=16384):
  path=job/name; fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)); info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600: emit("unknown","unsafe_"+name)
  with os.fdopen(fd,"rb") as source: raw=source.read(limit+1)
  if len(raw)>limit: emit("unknown","oversized_"+name)
  return json.loads(raw)
 intent=private("intent.json")
 if intent!=json.loads(expected_json) or intent.get("fixtureRoot")!=root: emit("unknown","intent_mismatch")
 identity=private("identity.json"); pid=identity.get("pid"); ticks=identity.get("startTicks")
 if type(pid) is not int or type(ticks) is not int or pid<=0 or ticks<=0: emit("unknown","identity_invalid")
 try: receipt=private("result.json")
 except FileNotFoundError: receipt=None
 if receipt is not None:
  if receipt.get("state")=="complete" and isinstance(receipt.get("result"),dict):
   value=receipt["result"]
   if value.get("state")!="complete" or value.get("sourcePackageSha256")!=intent.get("packageSha256"): emit("unknown","terminal_binding_invalid",identity=identity)
   opening=value.get("opening"); fixture=value.get("fixture"); exported=value.get("privateExport"); restored=value.get("restore")
   if not all(isinstance(x,dict) for x in (opening,fixture,exported,restored)): emit("unknown","terminal_shape_invalid",identity=identity)
   if opening.get("controllerId")!=intent.get("expectedOwner") or opening.get("revision")!=intent.get("expectedRevision") or fixture!={"sha256":intent.get("fixtureSha256"),"bytes":intent.get("fixtureSize"),"domainCount":56000}: emit("unknown","terminal_guard_invalid",identity=identity)
   directory=os.open(job,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0))
   try:
    dinfo=os.fstat(directory)
    if not stat.S_ISDIR(dinfo.st_mode) or dinfo.st_uid!=os.getuid() or stat.S_IMODE(dinfo.st_mode)!=0o700: emit("unknown","private_directory_invalid",identity=identity)
    for name,expected,size in (("opening-routing.json",opening.get("routingSha256"),opening.get("routingBytes")),("routing-v7-56000.json",fixture.get("sha256"),fixture.get("bytes")),("fixture-export.json",exported.get("sha256"),exported.get("bytes"))):
     fd=os.open(name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0),dir_fd=directory)
     with os.fdopen(fd,"rb") as source:
      info=os.fstat(source.fileno())
      if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or type(size) is not int or not 0<size<=67108864 or info.st_size!=size or not isinstance(expected,str) or re.fullmatch(r"[0-9a-f]{64}",expected) is None: emit("unknown","private_file_invalid",identity=identity)
      digest=hashlib.sha256(); remaining=size
      while remaining:
       block=source.read(min(65536,remaining))
       if not block: emit("unknown","private_truncated",identity=identity)
       digest.update(block); remaining-=len(block)
      if source.read(1): emit("unknown","private_grew",identity=identity)
      if digest.hexdigest()!=expected: emit("unknown","private_hash_mismatch",identity=identity)
   finally: os.close(directory)
   emit("complete",None,identity=identity,receipt=receipt)
  emit("unknown",receipt.get("reason","worker_unknown"),identity=identity)
 try:
  fields=pathlib.Path(f"/proc/{pid}/stat").read_text(encoding="ascii").rsplit(")",1)[1].split()
  live=fields[0]!="Z" and int(fields[19])==ticks
 except (OSError,ValueError,IndexError): live=False
 emit("running" if live else "unknown",None if live else "missing_worker_receipt",identity=identity)
except FileNotFoundError: emit("unknown","missing_job_or_intent")
except (OSError,ValueError,TypeError,KeyError): emit("unknown","status_unavailable")'''


def start(root: Path | str, host: str, device: str, correlation_id: str, artifact_id: str,
          cli_stage_correlation_id: str, expected_owner: str, expected_revision: int) -> dict[str, Any]:
    if not isinstance(correlation_id, str) or not _UUID.fullmatch(correlation_id):
        raise ValueError("Android document correlation must be a UUID")
    if host != "archlinux" or device != "api29":
        raise ValueError("Android 48 MiB document scenario is limited to owned API29")
    if not isinstance(expected_owner, str) or not _UUID.fullmatch(expected_owner) or type(expected_revision) is not int or expected_revision < 0:
        raise ValueError("Android document owner guard is invalid")
    if not isinstance(cli_stage_correlation_id, str) or not _UUID.fullmatch(cli_stage_correlation_id):
        raise ValueError("Android document CLI stage correlation is invalid")
    config = ssh_transport.load_config(root)
    if host not in config.hosts or device not in config.hosts[host].android_devices or config.hosts[host].fixture_transfer_root is None:
        raise ValueError("Android document fixture is not configured")
    if ssh_transport.connection_host(config, host).password is not None:
        raise ValueError("Android document route requires a private key")
    profile = android_observation._profile(config.hosts[host].android_devices[device])
    if profile["api"] != 29:
        raise ValueError("Android document fixture API is not 29")
    artifact = native_artifact_registry.verify_artifact(root, artifact_id)
    if artifact.get("verification") != "verified" or artifact["artifact"].get("platform") != "android" or artifact["artifact"].get("artifactKind") != "apk":
        raise ValueError("Android document APK is not verified")
    source_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if artifact["artifact"].get("sourceSha") != source_sha:
        raise ValueError("Android document APK is not current source")
    android_package_install._inspect_apk(root, Path(artifact["location"]["localPath"]))
    package_hash = artifact["artifact"]["sha256"]
    cli_stage = android_cli_stage.status(root, cli_stage_correlation_id)
    if not cli_stage.get("ok") or cli_stage.get("state") != "published" or cli_stage.get("sourceSha") != source_sha:
        raise ValueError("Android document CLI stage is not verified for current source")
    cli_path = cli_stage.get("receipt", {}).get("cliPath")
    if not isinstance(cli_path, str) or not cli_path.startswith(str(config.hosts[host].fixture_transfer_root) + "/android-cli-stage-" + cli_stage_correlation_id + "/tree/"):
        raise ValueError("Android document CLI path is not stage-bound")
    public_argv = ssh_transport.build_ssh_argv(config, host, 60, command=("python3", "-I", "-B", "-c",
        "exec(" + repr(_PUBLIC_PREFLIGHT) + ")", profile["adb"], cli_path, profile["serial"], expected_owner, str(expected_revision)))
    try:
        public_code, public_output = android_observation._run_probe(public_argv, 60)
        public = json.loads(public_output.decode("utf-8", "strict")) if public_code == 0 else None
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
        public = None
    if not isinstance(public, dict) or public.get("ready") is not True:
        raise ValueError("Android document current-source public owner is not idle and OFF")
    heap_argv = ssh_transport.build_ssh_argv(config, host, 30, command=("python3", "-I", "-B", "-c",
        "exec(" + repr(_HEAP_PROBE) + ")", profile["adb"], profile["serial"], profile["expectedAvd"]))
    try:
        heap_code, heap_output = android_observation._run_probe(heap_argv, 30)
        heap = json.loads(heap_output.decode("utf-8", "strict")) if heap_code == 0 else None
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
        heap = None
    if not isinstance(heap, dict) or heap.get("ready") is not True:
        raise ValueError("Android document 48 MiB heap and device preflight failed")
    remote_root = config.hosts[host].fixture_transfer_root
    intent = {"host": host, "device": device, "correlationId": correlation_id, "artifactId": artifact_id,
              "packageSha256": package_hash, "expectedOwner": expected_owner, "expectedRevision": expected_revision,
              "expectedAvd": profile["expectedAvd"], "api": profile["api"], "fixtureRoot": str(remote_root),
              "fixtureSha256": _FIXTURE_SHA, "fixtureSize": _FIXTURE_SIZE,
              "cliStageCorrelationId": cli_stage_correlation_id,
              "cliManifestSha256": cli_stage["receipt"]["manifestSha256"],
              "cliDesktopJarSha256": cli_stage["receipt"]["desktopJarSha256"],
              "cliPath": cli_path}
    args = [profile["adb"], cli_path, profile["serial"], profile["expectedAvd"], str(profile["api"]),
            str(remote_root), correlation_id, package_hash, expected_owner, str(expected_revision), _FIXTURE_SHA, str(_FIXTURE_SIZE)]
    encoded = base64.urlsafe_b64encode(_worker(_REMOTE, args).encode()).decode("ascii")
    argv = ssh_transport.build_ssh_argv(config, host, 60, command=("python3", "-I", "-B", "-c", "exec(" + repr(_SUBMIT) + ")",
        str(remote_root), correlation_id, json.dumps(intent, sort_keys=True, separators=(",", ":")), encoded))
    _reserve(root, intent)
    try:
        code, output = android_observation._run_probe(argv, 60)
        observed = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
        if isinstance(observed, dict) and observed.get("state") == "submitted" and observed.get("correlationId") == correlation_id:
            return {"ok": True, "state": "submitted", "correlationId": correlation_id, "identity": observed.get("identity"), "replayAllowed": False}
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
        pass
    return {"ok": False, "state": "unknown", "correlationId": correlation_id, "replayAllowed": False}


def status(root: Path | str, correlation_id: str) -> dict[str, Any]:
    if not isinstance(correlation_id, str) or not _UUID.fullmatch(correlation_id):
        raise ValueError("Android document correlation must be a UUID")
    intent = _load(root, correlation_id)
    if intent is None:
        return {"ok": False, "state": "unknown", "reason": "missing_local_intent", "correlationId": correlation_id, "replayAllowed": False}
    config = ssh_transport.load_config(root)
    if intent["host"] not in config.hosts or ssh_transport.connection_host(config, intent["host"]).password is not None:
        return {"ok": False, "state": "unknown", "reason": "route_unavailable", "correlationId": correlation_id, "replayAllowed": False}
    remote_root = config.hosts[intent["host"]].fixture_transfer_root
    if remote_root is None or str(remote_root) != intent.get("fixtureRoot"):
        return {"ok": False, "state": "unknown", "reason": "fixture_root_changed", "correlationId": correlation_id, "replayAllowed": False}
    argv = ssh_transport.build_ssh_argv(config, intent["host"], 30, command=("python3", "-I", "-B", "-c", "exec(" + repr(_STATUS) + ")",
        str(remote_root), correlation_id, json.dumps(intent, sort_keys=True, separators=(",", ":"))))
    try:
        code, output = android_observation._run_probe(argv, 30)
        observed = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
        if isinstance(observed, dict) and observed.get("correlationId") == correlation_id and observed.get("state") in {"running", "complete", "unknown"}:
            return {"ok": observed["state"] in {"running", "complete"}, **observed, "replayAllowed": False}
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
        pass
    return {"ok": False, "state": "unknown", "reason": "transport_or_receipt_unknown", "correlationId": correlation_id, "replayAllowed": False}


def collect(root: Path | str, correlation_id: str) -> dict[str, Any]:
    observed = status(root, correlation_id)
    if observed.get("state") != "complete": return observed
    intent = _load(root, correlation_id)
    receipt = observed.get("receipt")
    value = receipt.get("result") if isinstance(receipt, dict) else None
    if (not isinstance(intent, dict) or not isinstance(value, dict) or value.get("state") != "complete" or
            value.get("sourcePackageSha256") != intent.get("packageSha256") or
            value.get("device") != {"uid": "2000", "api": 29, "avd": intent.get("expectedAvd"), "heap": "48m"} or
            value.get("opening", {}).get("controllerId") != intent.get("expectedOwner") or
            value.get("opening", {}).get("revision") != intent.get("expectedRevision") or
            value.get("fixture") != {"sha256": _FIXTURE_SHA, "bytes": _FIXTURE_SIZE, "domainCount": _DOMAIN_COUNT} or
            value.get("fullRead") is not True or value.get("newRequestNoop") is not True or
            value.get("coldRead") is not True or value.get("restore", {}).get("openingRulesRestored") is not True or
            value.get("restore", {}).get("runtimeOff") is not True):
        return {"ok": False, "state": "unknown", "reason": "terminal_binding_invalid", "correlationId": correlation_id, "replayAllowed": False}
    stage = android_cli_stage.status(root, intent["cliStageCorrelationId"])
    if (not stage.get("ok") or stage.get("state") != "published" or
            stage.get("receipt", {}).get("manifestSha256") != intent.get("cliManifestSha256") or
            stage.get("receipt", {}).get("desktopJarSha256") != intent.get("cliDesktopJarSha256") or
            stage.get("receipt", {}).get("cliPath") != intent.get("cliPath")):
        return {"ok": False, "state": "unknown", "reason": "cli_stage_changed", "correlationId": correlation_id, "replayAllowed": False}
    released = _release_device(root, intent["host"], intent["device"], correlation_id)
    return {"ok": released, "state": "complete", "correlationId": correlation_id, "result": value,
            "identity": observed.get("identity"), "replayAllowed": False,
            "leaseReleased": released, "evidenceClass": "native-document-acceptance"}

"""One journaled public restore of an uncertain API29 document acceptance run.

The original unknown journal and its device lease remain evidence.  A separate
recovery correlation permits exactly one restore attempt.  Only a later exact
readback may release the original lease.
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
    from . import (android_admission_readback, android_cli_stage, android_document_acceptance,
                   android_observation, android_package_install, android_public_inspect,
                   native_artifact_registry, ssh_transport)
except ImportError:  # pragma: no cover
    import android_admission_readback, android_cli_stage, android_document_acceptance
    import android_observation, android_package_install, android_public_inspect
    import native_artifact_registry, ssh_transport


_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


def _journal(root: Path | str, correlation: str) -> Path:
    return Path(root).resolve() / ".rag_index" / "android-document-recovery-jobs" / (correlation + ".json")


def _reservation(root: Path | str, unknown: str) -> Path:
    return _journal(root, unknown).with_name("unknown-" + unknown + ".json")


def _private_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("Android recovery journal directory is not private")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        out.flush(); os.fsync(out.fileno())
    directory = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(directory)
    finally: os.close(directory)


def _private_read(path: Path, expected_key: str, expected_value: str) -> dict[str, Any] | None:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                return None
            raw = source.read(8193)
        if len(raw) > 8192: return None
        value = json.loads(raw)
        return value if isinstance(value, dict) and value.get(expected_key) == expected_value else None
    except (OSError, ValueError):
        return None


def _load(root: Path | str, correlation: str) -> dict[str, Any] | None:
    return _private_read(_journal(root, correlation), "correlationId", correlation)


def _reserve(root: Path | str, intent: dict[str, Any]) -> None:
    # Reservation is intentionally permanent, including a local failure: no
    # automatic second import can follow an uncertain first submission.
    _private_write(_reservation(root, intent["unknownDocumentCorrelationId"]),
                   {"unknownDocumentCorrelationId": intent["unknownDocumentCorrelationId"],
                    "recoveryCorrelationId": intent["correlationId"]})
    _private_write(_journal(root, intent["correlationId"]), intent)


def _readback(root: Path | str, correlation: str, host: str, device: str,
              package_hash: str, owner: str, revision: int) -> dict[str, Any]:
    value = android_admission_readback.async_collect(root, correlation)
    result = value.get("result") if value.get("ok") and value.get("state") == "complete" else None
    intent = android_admission_readback._load_async_intent(root, correlation)
    if (not isinstance(result, dict) or not isinstance(intent, dict) or
            intent.get("host") != host or intent.get("device") != device or
            result.get("package", {}).get("baseSha256") != package_hash or
            result.get("guard", {}).get("controllerId") != owner or
            result.get("guard", {}).get("configurationRevision") != revision or
            result.get("device", {}).get("uid") != "2000" or
            result.get("device", {}).get("api") != 29):
        raise ValueError("Android recovery readback guard changed")
    backup = result.get("backup", {})
    if (not isinstance(backup.get("sha256"), str) or not _SHA.fullmatch(backup["sha256"]) or
            type(backup.get("size")) is not int or not 0 < backup["size"] <= 67_108_864):
        raise ValueError("Android recovery backup is invalid")
    return result


_REMOTE = android_observation._canonical_cli_environment_source() + r'''
import hashlib,json,os,pathlib,stat,subprocess,sys
adb,cli,serial,avd,root,recovery,unknown,current_readback,package_hash,owner,revision,opening_hash,opening_size,current_hash,current_size=sys.argv[1:]
def fail(reason):
 print(json.dumps({"state":"unknown","reason":reason},separators=(",",":"))); raise SystemExit(0)
def invoke(args,timeout=60,limit=16777216,env=None):
 try: done=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout,env=env,check=False)
 except (OSError,subprocess.TimeoutExpired): fail("command_outcome_unknown")
 if done.returncode or len(done.stdout)>limit: fail("command_failed")
 try: return done.stdout.decode("utf-8","strict").strip()
 except UnicodeError: fail("command_encoding")
def shell(*words): return invoke([adb,"-s",serial,"shell","-T",*words],timeout=20,limit=2048)
def public(*words,timeout=300,limit=16777216):
 raw=invoke([cli,"--json","--android","--serial",serial,"--timeout-seconds",str(timeout),*words],timeout=timeout+15,limit=limit,env=environment)
 try: value=json.loads(raw)
 except ValueError: fail("public_result_invalid")
 if not isinstance(value,dict): fail("public_result_invalid")
 return value
def final(value,who,reason):
 if value.get("ok") is not True or value.get("final") is not True or value.get("code")!="OK" or value.get("controllerId")!=who: fail(reason)
def private(path,size,sha):
 fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
 with os.fdopen(fd,"rb") as source:
  info=os.fstat(source.fileno())
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size!=int(size): fail("preserved_file_unsafe")
  raw=source.read(int(size)+1)
 if len(raw)!=int(size) or hashlib.sha256(raw).hexdigest()!=sha: fail("preserved_file_changed")
 try: value=json.loads(raw)
 except ValueError: fail("preserved_file_invalid")
 if value.get("type")!="vpn_control_routing_rules" or value.get("version")!=7 or not isinstance(value.get("rules"),dict): fail("preserved_file_invalid")
 return value
if shell("id","-u")!="2000" or shell("getprop","ro.build.version.sdk")!="29" or {x for x in (shell("getprop","ro.kernel.qemu.avd_name"),shell("getprop","ro.boot.qemu.avd_name")) if x}!={avd} or shell("getprop","ro.product.cpu.abi")!="x86_64": fail("device_changed")
if shell("getprop","dalvik.vm.heapsize").lower()!="48m": fail("heap_changed")
paths=[x.removeprefix("package:") for x in shell("pm","path","com.kardinal.vpncontrol").splitlines() if x.startswith("package:") and x.endswith("/base.apk")]
if len(paths)!=1 or not paths[0].startswith("/data/app/"): fail("package_path_changed")
pair=shell("sha256sum",paths[0]).split()
if len(pair)!=2 or pair!=[package_hash,paths[0]]: fail("package_changed")
environment=public_cli_environment(adb,pathlib.Path(cli))
base=pathlib.Path(root); binfo=base.lstat()
if not stat.S_ISDIR(binfo.st_mode) or binfo.st_uid!=os.getuid() or stat.S_IMODE(binfo.st_mode)!=0o700: fail("private_root_unsafe")
os.umask(0o077)
old=base/("android-document-job-"+unknown); info=old.lstat()
if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: fail("unknown_job_unsafe")
original=old/"opening-routing.json"; opening=private(original,opening_size,opening_hash)
readback=base/("android-readback-"+current_readback)
rinfo=readback.lstat()
if not stat.S_ISDIR(rinfo.st_mode) or rinfo.st_uid!=os.getuid() or stat.S_IMODE(rinfo.st_mode)!=0o700: fail("current_readback_unsafe")
current=private(readback/"routing.json",current_size,current_hash)
status=public("status",timeout=30,limit=16384); final(status,owner,"owner_changed")
if status.get("configurationRevision")!=int(revision) or status.get("data",{}).get("runtimeRunning") is not False or status.get("data",{}).get("runtimeObservation")!="stopped": fail("runtime_changed")
operations=public("operations","list",timeout=30,limit=16384); final(operations,owner,"operations_changed")
entries=operations.get("data",{}).get("operations")
if operations.get("configurationRevision")!=int(revision) or not isinstance(entries,list) or any(not isinstance(x,dict) or x.get("final") is not True for x in entries): fail("operations_nonterminal")
before=public("routing","show",timeout=300)
final(before,owner,"current_read_failed")
if before.get("configurationRevision")!=int(revision) or before.get("data",{}).get("routing",{}).get("rules")!=current["rules"]: fail("current_read_mismatch")
job=base/("android-document-recovery-job-"+recovery); info=job.lstat()
if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: fail("recovery_job_unsafe")
marker=job/"phase.json"
def phase(name):
 temporary=job/"phase.json.tmp"
 with temporary.open("x",encoding="utf-8") as output: json.dump({"phase":name},output); output.flush(); os.fsync(output.fileno())
 os.replace(temporary,marker)
phase("public_import_submitted")
restored=public("--controller-id",owner,"--if-revision",revision,"routing","import","--input",str(original),timeout=300,limit=16384)
final(restored,owner,"restore_not_final")
operation_id=restored.get("operationId")
if operation_id:
 phase("retained_wait_submitted")
 waited=public("--controller-id",owner,"operations","wait",operation_id,timeout=300,limit=16384)
 final(waited,owner,"retained_wait_failed")
 if waited.get("operationId")!=operation_id: fail("retained_operation_changed")
phase("public_read_submitted")
read=public("routing","show",timeout=300); final(read,owner,"restored_read_failed")
if read.get("data",{}).get("routing",{}).get("rules")!=opening["rules"] or read.get("configurationRevision",-1)<=int(revision): fail("restored_rules_mismatch")
phase("private_export_submitted")
export=job/"restored-routing.json"
saved=public("routing","export","--output",str(export),timeout=300,limit=16384); final(saved,owner,"restored_export_failed")
exported=private(export,export.stat().st_size,hashlib.sha256(export.read_bytes()).hexdigest())
if exported.get("rules")!=opening["rules"]: fail("restored_export_mismatch")
last=public("status",timeout=30,limit=16384); final(last,owner,"closing_status_invalid")
if last.get("data",{}).get("runtimeRunning") is not False or last.get("data",{}).get("runtimeObservation")!="stopped": fail("closing_runtime_changed")
phase("complete")
print(json.dumps({"state":"complete","sourcePackageSha256":package_hash,"opening":{"sha256":opening_hash,"size":int(opening_size)},"current":{"sha256":current_hash,"size":int(current_size),"revision":int(revision)},"restore":{"controllerId":owner,"revision":read["configurationRevision"],"operationId":operation_id,"rulesRestored":True,"runtimeOff":True,"exportSha256":hashlib.sha256(export.read_bytes()).hexdigest(),"exportSize":export.stat().st_size},"replayAllowed":False},separators=(",",":")))
'''

_PRESERVED_PREFLIGHT = r'''import hashlib,json,os,pathlib,stat,sys
root,unknown,opening_readback,current,opening_hash,opening_size,current_hash,current_size=sys.argv[1:]
def observe(directory_name,name,sha=None,size=None):
 try:
  directory=pathlib.Path(root)/directory_name; info=directory.lstat()
  if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: return {"state":"unsafe_directory"},None
  fd=os.open(directory/name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
  with os.fdopen(fd,"rb") as source:
   info=os.fstat(source.fileno())
   if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or not 0<info.st_size<=67108864: return {"state":"unsafe_file"},None
   raw=source.read(info.st_size+1)
  if len(raw)!=info.st_size: return {"state":"changed_file"},None
  observed={"state":"verified_file","sha256":hashlib.sha256(raw).hexdigest(),"size":info.st_size}
  if sha is not None: observed["matchesExpected"]=observed["sha256"]==sha and observed["size"]==int(size)
  try: document=json.loads(raw)
  except (ValueError,UnicodeError): document=None
  valid=isinstance(document,dict) and document.get("type")=="vpn_control_routing_rules" and document.get("version")==7 and isinstance(document.get("rules"),dict)
  observed["validDocument"]=valid
  return observed,document if valid else None
 except FileNotFoundError: return {"state":"missing"},None
 except (OSError,ValueError): return {"state":"unavailable"},None
base=pathlib.Path(root)
try:
 info=base.lstat(); ready=stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700
except OSError: ready=False
opening_export,export_doc=observe("android-document-job-"+unknown,"opening-routing.json") if ready else ({"state":"unsafe_root"},None)
opening_backup,backup_doc=observe("android-readback-"+opening_readback,"routing.json",opening_hash,opening_size) if ready else ({"state":"unsafe_root"},None)
current_file,current_doc=observe("android-readback-"+current,"routing.json",current_hash,current_size) if ready else ({"state":"unsafe_root"},None)
semantic=export_doc is not None and backup_doc is not None and {k:v for k,v in export_doc.items() if k!="exported_at"}=={k:v for k,v in backup_doc.items() if k!="exported_at"}
ready=ready and opening_export.get("size")==239 and opening_backup.get("matchesExpected") is True and current_file.get("matchesExpected") is True and semantic
print(json.dumps({"ready":ready,"openingExport":opening_export,"openingReadback":opening_backup,"current":current_file,"semanticMatch":semantic},separators=(",",":")))'''

_ORIGINAL_TERMINAL = r'''import errno,json,os,pathlib,stat,sys
root,correlation,expected_json,pid_text,ticks_text=sys.argv[1:]
def private(directory,name,limit):
 fd=os.open(directory/name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
 with os.fdopen(fd,"rb") as source:
  info=os.fstat(source.fileno())
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1: raise ValueError("unsafe")
  raw=source.read(limit+1)
 if len(raw)>limit: raise ValueError("oversized")
 return json.loads(raw)
ready=False
try:
 job=pathlib.Path(root)/("android-document-job-"+correlation); info=job.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: raise ValueError("job_unsafe")
 intent=private(job,"intent.json",8192)
 identity=private(job,"identity.json",1024)
 result=private(job,"result.json",16384)
 pid=int(pid_text); ticks=int(ticks_text)
 if intent!=json.loads(expected_json) or identity.get("pid")!=pid or identity.get("startTicks")!=ticks: raise ValueError("identity_changed")
 if result.get("state")!="unknown" or result.get("reason")!="command_failed": raise ValueError("not_terminal_failure")
 try:
  fields=pathlib.Path(f"/proc/{pid}/stat").read_text(encoding="ascii").rsplit(")",1)[1].split()
  live=fields[0]!="Z" and int(fields[19])==ticks
 except FileNotFoundError: live=False
 except OSError as error:
  if error.errno!=errno.ESRCH: raise
  live=False
 ready=not live
except (OSError,ValueError,TypeError,KeyError,IndexError): pass
print(json.dumps({"ready":ready},separators=(",",":")))'''

_CLOSING_SEMANTIC = r'''import hashlib,json,os,pathlib,stat,sys
root,opening,closing,opening_hash,opening_size,closing_hash,closing_size=sys.argv[1:]
def document(correlation,sha,size):
 directory=pathlib.Path(root)/("android-readback-"+correlation); info=directory.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: raise ValueError("directory_unsafe")
 fd=os.open(directory/"routing.json",os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
 with os.fdopen(fd,"rb") as source:
  info=os.fstat(source.fileno())
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size!=int(size): raise ValueError("file_unsafe")
  raw=source.read(int(size)+1)
 if len(raw)!=int(size) or hashlib.sha256(raw).hexdigest()!=sha: raise ValueError("file_changed")
 value=json.loads(raw)
 if not isinstance(value,dict) or value.get("type")!="vpn_control_routing_rules" or value.get("version")!=7 or not isinstance(value.get("rules"),dict): raise ValueError("document_invalid")
 return {k:v for k,v in value.items() if k!="exported_at"}
same=False; canonical=None
try:
 base=pathlib.Path(root); info=base.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: raise ValueError("root_unsafe")
 first=document(opening,opening_hash,opening_size)
 last=document(closing,closing_hash,closing_size)
 same=first==last
 if same: canonical=hashlib.sha256(json.dumps(first,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
except (OSError,ValueError,TypeError): pass
print(json.dumps({"same":same,"canonicalSha256":canonical},separators=(",",":")))'''

_SUBMIT = android_admission_readback._ASYNC_SUBMIT.replace("android-readback-job-", "android-document-recovery-job-")
_STATUS = r'''import hashlib,json,os,pathlib,re,stat,sys
root,correlation,expected_json=sys.argv[1:]
def emit(state,reason=None,**extra):
 print(json.dumps({"state":state,"reason":reason,"correlationId":correlation,**extra},separators=(",",":"))); raise SystemExit(0)
job=pathlib.Path(root)/("android-document-recovery-job-"+correlation)
try:
 info=job.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: emit("unknown","unsafe_job")
 def private(name,limit=16384):
  path=job/name; fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
  with os.fdopen(fd,"rb") as source:
   info=os.fstat(source.fileno())
   if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1: emit("unknown","unsafe_"+name)
   raw=source.read(limit+1)
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
   if value.get("state")!="complete" or value.get("sourcePackageSha256")!=intent.get("packageSha256") or value.get("opening")!={"sha256":intent.get("openingExportSha256"),"size":intent.get("openingExportSize")} or value.get("current")!={"sha256":intent.get("currentBackupSha256"),"size":intent.get("currentBackupSize"),"revision":intent.get("expectedRevision")}: emit("unknown","terminal_binding_invalid",identity=identity)
   restored=value.get("restore")
   if not isinstance(restored,dict) or restored.get("controllerId")!=intent.get("expectedOwner") or restored.get("rulesRestored") is not True or restored.get("runtimeOff") is not True: emit("unknown","terminal_shape_invalid",identity=identity)
   path=job/"restored-routing.json"; fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
   with os.fdopen(fd,"rb") as source:
    info=os.fstat(source.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size!=restored.get("exportSize") or not 0<info.st_size<=67108864: emit("unknown","restored_export_unsafe",identity=identity)
    digest=hashlib.sha256()
    while block:=source.read(65536): digest.update(block)
   if digest.hexdigest()!=restored.get("exportSha256"): emit("unknown","restored_export_changed",identity=identity)
   emit("complete",None,identity=identity,receipt=receipt)
  try: phase=private("phase.json",1024).get("phase")
  except FileNotFoundError: phase=None
  emit("unknown",receipt.get("reason","worker_unknown"),identity=identity,phase=phase)
 try:
  fields=pathlib.Path(f"/proc/{pid}/stat").read_text(encoding="ascii").rsplit(")",1)[1].split()
  live=fields[0]!="Z" and int(fields[19])==ticks
 except (OSError,ValueError,IndexError): live=False
 emit("running" if live else "unknown",None if live else "missing_worker_receipt",identity=identity)
except FileNotFoundError: emit("unknown","missing_job_or_intent")
except (OSError,ValueError,TypeError,KeyError): emit("unknown","status_unavailable")'''


def start(root: Path | str, host: str, device: str, recovery_correlation_id: str,
          unknown_document_correlation_id: str, opening_readback_correlation_id: str,
          current_readback_correlation_id: str, artifact_id: str,
          cli_stage_correlation_id: str, expected_owner: str, expected_revision: int) -> dict[str, Any]:
    values = (recovery_correlation_id, unknown_document_correlation_id,
              opening_readback_correlation_id, current_readback_correlation_id,
              cli_stage_correlation_id, expected_owner)
    if any(not isinstance(value, str) or not _UUID.fullmatch(value) for value in values) or len(set(values)) != len(values):
        raise ValueError("Android recovery correlations and owner must be distinct UUIDs")
    if host != "archlinux" or device != "api29" or type(expected_revision) is not int or expected_revision < 0:
        raise ValueError("Android recovery requires owned API29 and exact revision")
    old = android_document_acceptance._load(root, unknown_document_correlation_id)
    observed = android_document_acceptance.status(root, unknown_document_correlation_id)
    if (not isinstance(old, dict) or old.get("host") != host or old.get("device") != device or
            old.get("expectedOwner") != expected_owner or
            type(old.get("expectedRevision")) is not int or
            old.get("expectedRevision") >= expected_revision or observed.get("state") != "unknown" or
            observed.get("reason") != "command_failed"):
        raise ValueError("Android recovery requires the exact unknown document job")
    identity = observed.get("identity")
    if (not isinstance(identity, dict) or type(identity.get("pid")) is not int or
            type(identity.get("startTicks")) is not int or identity["pid"] <= 0 or identity["startTicks"] <= 0):
        raise ValueError("Android recovery requires exact original worker identity")
    lease = android_document_acceptance._lease(root, host, device, unknown_document_correlation_id)
    if _private_read(lease, "correlationId", unknown_document_correlation_id) != {
            "host": host, "device": device, "correlationId": unknown_document_correlation_id}:
        raise ValueError("Android recovery requires the exact unknown document lease")
    config = ssh_transport.load_config(root)
    if host not in config.hosts or device not in config.hosts[host].android_devices or config.hosts[host].fixture_transfer_root is None:
        raise ValueError("Android recovery fixture is not configured")
    if ssh_transport.connection_host(config, host).password is not None:
        raise ValueError("Android recovery requires a private key route")
    profile = android_observation._profile(config.hosts[host].android_devices[device])
    if profile["api"] != 29: raise ValueError("Android recovery API changed")
    remote_root = config.hosts[host].fixture_transfer_root
    terminal_argv = ssh_transport.build_ssh_argv(config, host, 30, command=("python3", "-I", "-B", "-c",
        "exec(" + repr(_ORIGINAL_TERMINAL) + ")", str(remote_root), unknown_document_correlation_id,
        json.dumps(old, sort_keys=True, separators=(",", ":")), str(identity["pid"]), str(identity["startTicks"])))
    try:
        terminal_code, terminal_output = android_observation._run_probe(terminal_argv, 30)
        terminal = json.loads(terminal_output.decode("utf-8", "strict")) if terminal_code == 0 else None
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
        terminal = None
    if not isinstance(terminal, dict) or terminal.get("ready") is not True:
        raise ValueError("Android recovery original worker is not proven terminal")
    artifact = native_artifact_registry.verify_artifact(root, artifact_id)
    if (artifact.get("verification") != "verified" or artifact["artifact"].get("platform") != "android" or
            artifact["artifact"].get("artifactKind") not in {"apk", "native-fixture-apk"}):
        raise ValueError("Android recovery APK is not verified")
    source_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if artifact["artifact"].get("sourceSha") != source_sha:
        raise ValueError("Android recovery APK is not current source")
    android_package_install._inspect_apk(root, Path(artifact["location"]["localPath"]))
    package_hash = artifact["artifact"]["sha256"]
    if old.get("packageSha256") != package_hash or old.get("cliStageCorrelationId") != cli_stage_correlation_id:
        raise ValueError("Android recovery source differs from unknown job")
    stage = android_cli_stage.status(root, cli_stage_correlation_id)
    if not stage.get("ok") or stage.get("state") != "published" or stage.get("sourceSha") != source_sha:
        raise ValueError("Android recovery CLI stage is not current source")
    cli_path = stage.get("receipt", {}).get("cliPath")
    if cli_path != old.get("cliPath") or not isinstance(cli_path, str) or not cli_path.startswith(str(remote_root) + "/android-cli-stage-" + cli_stage_correlation_id + "/tree/"):
        raise ValueError("Android recovery CLI path changed")
    opening = _readback(root, opening_readback_correlation_id, host, device, package_hash, expected_owner, old["expectedRevision"])
    current = _readback(root, current_readback_correlation_id, host, device, package_hash, expected_owner, expected_revision)
    opening_backup, current_backup = opening["backup"], current["backup"]
    if (opening_backup["size"] != 239 or opening_backup["size"] >= current_backup["size"] or
            opening_backup["sha256"] == current_backup["sha256"] or
            current_backup["size"] < 11_000_000):
        raise ValueError("Android recovery current routing does not match committed large import")
    preserved_argv = ssh_transport.build_ssh_argv(config, host, 30, command=("python3", "-I", "-B", "-c",
        "exec(" + repr(_PRESERVED_PREFLIGHT) + ")", str(remote_root), unknown_document_correlation_id,
        opening_readback_correlation_id, current_readback_correlation_id,
        opening_backup["sha256"], str(opening_backup["size"]),
        current_backup["sha256"], str(current_backup["size"])))
    try:
        preserved_code, preserved_output = android_observation._run_probe(preserved_argv, 30)
        preserved = json.loads(preserved_output.decode("utf-8", "strict")) if preserved_code == 0 else None
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
        preserved = None
    if not isinstance(preserved, dict) or preserved.get("ready") is not True:
        diagnostic = {key: preserved.get(key) for key in ("openingExport", "openingReadback", "current", "semanticMatch")} if isinstance(preserved, dict) else {}
        raise ValueError("Android recovery preserved private bytes are not exact: " +
                         json.dumps(diagnostic, sort_keys=True, separators=(",", ":")))
    opening_export = preserved["openingExport"]
    if (not isinstance(opening_export.get("sha256"), str) or not _SHA.fullmatch(opening_export["sha256"]) or
            opening_export.get("size") != 239):
        raise ValueError("Android recovery opening export identity is invalid")
    public = android_public_inspect.inspect(root, host, device, recovery_correlation_id,
                                             package_hash, expected_owner, expected_revision)
    result = public.get("result", {})
    if (not public.get("ok") or public.get("outcome") != "admitted" or
            result.get("runtime", {}).get("running") is not False or
            result.get("runtime", {}).get("observation") != "stopped"):
        raise ValueError("Android recovery owner/runtime preflight failed")
    intent = {"host": host, "device": device, "correlationId": recovery_correlation_id,
              "unknownDocumentCorrelationId": unknown_document_correlation_id,
              "openingReadbackCorrelationId": opening_readback_correlation_id,
              "currentReadbackCorrelationId": current_readback_correlation_id,
              "artifactId": artifact_id, "packageSha256": package_hash,
              "expectedOwner": expected_owner, "expectedRevision": expected_revision,
              "openingRevision": old["expectedRevision"],
              "openingBackupSha256": opening_backup["sha256"], "openingBackupSize": opening_backup["size"],
              "openingExportSha256": opening_export["sha256"], "openingExportSize": opening_export["size"],
              "currentBackupSha256": current_backup["sha256"], "currentBackupSize": current_backup["size"],
              "cliStageCorrelationId": cli_stage_correlation_id, "cliPath": cli_path,
              "cliManifestSha256": stage["receipt"]["manifestSha256"],
              "expectedAvd": profile["expectedAvd"], "fixtureRoot": str(remote_root)}
    args = [profile["adb"], cli_path, profile["serial"], profile["expectedAvd"], str(remote_root),
            recovery_correlation_id, unknown_document_correlation_id, current_readback_correlation_id, package_hash, expected_owner,
            str(expected_revision), opening_export["sha256"], str(opening_export["size"]),
            current_backup["sha256"], str(current_backup["size"])]
    encoded = base64.urlsafe_b64encode(android_document_acceptance._worker(_REMOTE, args).encode()).decode("ascii")
    argv = ssh_transport.build_ssh_argv(config, host, 60, command=("python3", "-I", "-B", "-c", "exec(" + repr(_SUBMIT) + ")",
        str(remote_root), recovery_correlation_id, json.dumps(intent, sort_keys=True, separators=(",", ":")), encoded))
    _reserve(root, intent)
    try:
        code, output = android_observation._run_probe(argv, 60)
        value = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
        if isinstance(value, dict) and value.get("state") == "submitted" and value.get("correlationId") == recovery_correlation_id:
            return {"ok": True, "state": "submitted", "correlationId": recovery_correlation_id,
                    "identity": value.get("identity"), "replayAllowed": False}
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
        pass
    return {"ok": False, "state": "unknown", "correlationId": recovery_correlation_id, "replayAllowed": False}


def status(root: Path | str, recovery_correlation_id: str) -> dict[str, Any]:
    if not isinstance(recovery_correlation_id, str) or not _UUID.fullmatch(recovery_correlation_id):
        raise ValueError("Android recovery correlation must be a UUID")
    intent = _load(root, recovery_correlation_id)
    if intent is None:
        return {"ok": False, "state": "unknown", "reason": "missing_local_intent",
                "correlationId": recovery_correlation_id, "replayAllowed": False}
    config = ssh_transport.load_config(root)
    host = intent["host"]
    if host not in config.hosts or ssh_transport.connection_host(config, host).password is not None:
        return {"ok": False, "state": "unknown", "reason": "route_unavailable",
                "correlationId": recovery_correlation_id, "replayAllowed": False}
    root_remote = config.hosts[host].fixture_transfer_root
    if root_remote is None or str(root_remote) != intent.get("fixtureRoot"):
        return {"ok": False, "state": "unknown", "reason": "fixture_root_changed",
                "correlationId": recovery_correlation_id, "replayAllowed": False}
    argv = ssh_transport.build_ssh_argv(config, host, 30, command=("python3", "-I", "-B", "-c", "exec(" + repr(_STATUS) + ")",
        str(root_remote), recovery_correlation_id, json.dumps(intent, sort_keys=True, separators=(",", ":"))))
    try:
        code, output = android_observation._run_probe(argv, 30)
        value = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
        if isinstance(value, dict) and value.get("correlationId") == recovery_correlation_id and value.get("state") in {"running", "complete", "unknown"}:
            return {"ok": value["state"] in {"running", "complete"}, **value, "replayAllowed": False}
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
        pass
    return {"ok": False, "state": "unknown", "reason": "transport_or_receipt_unknown",
            "correlationId": recovery_correlation_id, "replayAllowed": False}


def collect(root: Path | str, recovery_correlation_id: str) -> dict[str, Any]:
    observed = status(root, recovery_correlation_id)
    if observed.get("state") != "complete": return observed
    intent = _load(root, recovery_correlation_id)
    receipt = observed.get("receipt")
    result = receipt.get("result") if isinstance(receipt, dict) else None
    if (not isinstance(intent, dict) or not isinstance(result, dict) or result.get("state") != "complete" or
            result.get("sourcePackageSha256") != intent.get("packageSha256") or
            result.get("opening") != {"sha256": intent.get("openingExportSha256"), "size": intent.get("openingExportSize")} or
            result.get("current") != {"sha256": intent.get("currentBackupSha256"), "size": intent.get("currentBackupSize"), "revision": intent.get("expectedRevision")} or
            result.get("restore", {}).get("controllerId") != intent.get("expectedOwner") or
            result.get("restore", {}).get("rulesRestored") is not True or
            result.get("restore", {}).get("runtimeOff") is not True):
        return {"ok": False, "state": "unknown", "reason": "terminal_binding_invalid",
                "correlationId": recovery_correlation_id, "replayAllowed": False}
    return {"ok": True, "state": "complete", "correlationId": recovery_correlation_id,
            "result": result, "identity": observed.get("identity"), "leaseReleased": False,
            "replayAllowed": False}


def finalize(root: Path | str, recovery_correlation_id: str, closing_readback_correlation_id: str,
             expected_owner: str, expected_revision: int) -> dict[str, Any]:
    if (not isinstance(closing_readback_correlation_id, str) or not _UUID.fullmatch(closing_readback_correlation_id) or
            not isinstance(expected_owner, str) or not _UUID.fullmatch(expected_owner) or
            type(expected_revision) is not int or expected_revision < 0):
        raise ValueError("Android recovery closing guard is invalid")
    completed = collect(root, recovery_correlation_id)
    if not completed.get("ok") or completed.get("state") != "complete": return completed
    intent = _load(root, recovery_correlation_id)
    result = completed["result"]
    if (result["restore"]["controllerId"] != expected_owner or result["restore"]["revision"] != expected_revision or
            closing_readback_correlation_id in {intent["openingReadbackCorrelationId"], intent["currentReadbackCorrelationId"]}):
        return {"ok": False, "state": "unknown", "reason": "closing_guard_mismatch",
                "correlationId": recovery_correlation_id, "replayAllowed": False}
    try:
        lease = android_document_acceptance._lease(root, intent["host"], intent["device"], intent["unknownDocumentCorrelationId"])
        if _private_read(lease, "correlationId", intent["unknownDocumentCorrelationId"]) != {
                "host": intent["host"], "device": intent["device"],
                "correlationId": intent["unknownDocumentCorrelationId"]}:
            raise ValueError("Android recovery original lease changed")
        closing = _readback(root, closing_readback_correlation_id, intent["host"], intent["device"],
                            intent["packageSha256"], expected_owner, expected_revision)
        backup = closing["backup"]
        if backup["size"] != 239:
            raise ValueError("Android recovery closing routing size differs from opening")
        fresh = android_admission_readback.readback_status(
            root, intent["host"], intent["device"], closing_readback_correlation_id)
        live = fresh.get("result") if fresh.get("ok") and fresh.get("outcome") == "observed" else None
        if (not isinstance(live, dict) or live.get("deviceIdentity") is not True or
                live.get("controllerId") != expected_owner or
                live.get("configurationRevision") != expected_revision or
                live.get("stage") != "backup_present" or
                not isinstance(live.get("backup"), dict) or
                live["backup"].get("sha256") != backup["sha256"] or
                live["backup"].get("size") != backup["size"] or
                live["backup"].get("formatValid") is not True):
            raise ValueError("Android recovery fresh closing readback changed")
        config = ssh_transport.load_config(root)
        remote_root = config.hosts[intent["host"]].fixture_transfer_root
        if remote_root is None or str(remote_root) != intent["fixtureRoot"]:
            raise ValueError("Android recovery fixture root changed")
        semantic_argv = ssh_transport.build_ssh_argv(config, intent["host"], 30, command=("python3", "-I", "-B", "-c",
            "exec(" + repr(_CLOSING_SEMANTIC) + ")", str(remote_root), intent["openingReadbackCorrelationId"],
            closing_readback_correlation_id, intent["openingBackupSha256"], str(intent["openingBackupSize"]),
            backup["sha256"], str(backup["size"])))
        semantic_code, semantic_output = android_observation._run_probe(semantic_argv, 30)
        semantic = json.loads(semantic_output.decode("utf-8", "strict")) if semantic_code == 0 else None
        if not isinstance(semantic, dict) or semantic.get("same") is not True or not isinstance(semantic.get("canonicalSha256"), str) or not _SHA.fullmatch(semantic["canonicalSha256"]):
            raise ValueError("Android recovery closing persistent routing differs from opening")
        public = android_public_inspect.inspect(root, intent["host"], intent["device"], recovery_correlation_id,
                                                 intent["packageSha256"], expected_owner, expected_revision)
        runtime = public.get("result", {}).get("runtime", {})
        if not public.get("ok") or runtime.get("running") is not False or runtime.get("observation") != "stopped":
            raise ValueError("Android recovery closing runtime changed")
        released = android_document_acceptance._release_device(root, intent["host"], intent["device"], intent["unknownDocumentCorrelationId"])
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError, KeyError):
        return {"ok": False, "state": "unknown", "reason": "closing_readback_unverified",
                "correlationId": recovery_correlation_id, "replayAllowed": False}
    return {"ok": released, "state": "complete" if released else "unknown", "correlationId": recovery_correlation_id,
            "closingReadbackCorrelationId": closing_readback_correlation_id, "leaseReleased": released,
            "persistentRulesSha256": semantic["canonicalSha256"] if released else None,
            "replayAllowed": False}

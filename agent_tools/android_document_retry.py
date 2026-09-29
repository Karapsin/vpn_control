"""One source-bound API29 large-document retry using the public document provider.

This campaign is separate from the completed CLI document scenario.  It creates
two different provider transfers containing byte-identical requests with one
UUID, and never resubmits either transfer after an uncertain outcome.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any

try:
    from . import (android_admission_readback, android_cli_stage, android_document_acceptance,
                   android_document_recovery, android_public_inspect,
                   android_installer_dispatch,
                   android_observation, android_package_install, native_artifact_registry,
                   ssh_transport)
except ImportError:  # pragma: no cover
    import android_admission_readback, android_cli_stage, android_document_acceptance
    import android_document_recovery, android_public_inspect
    import android_installer_dispatch
    import android_observation, android_package_install, native_artifact_registry, ssh_transport


_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FIXTURE_SHA = android_document_acceptance._FIXTURE_SHA
_FIXTURE_SIZE = android_document_acceptance._FIXTURE_SIZE


def _request_bytes(request_id: str, owner: str, revision: int, input_text: str) -> bytes:
    value = {"schemaVersion": 1, "requestId": request_id, "controllerId": owner,
             "ifRevision": revision, "interactive": False, "asynchronous": False,
             "command": {"operation": "routing.import", "arguments": {"input": input_text}}}
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _fixture_text() -> str:
    prefix = "." + "a" * 60 + "." + "b" * 60 + "." + "c" * 60 + ".example.test"
    fixture = {"type": "vpn_control_routing_rules", "version": 7,
               "rules": {"ignore_rules": False, "block_quic_udp_443": False,
                         "proxy_packages": [],
                         "direct_domain_suffixes": [f"d{i:05d}" + prefix for i in range(56000)]}}
    text = json.dumps(fixture)
    encoded = text.encode()
    if len(encoded) != _FIXTURE_SIZE or hashlib.sha256(encoded).hexdigest() != _FIXTURE_SHA:
        raise ValueError("Android retry fixed fixture identity changed")
    return text


def _test_intent() -> dict[str, Any]:
    return {"packageSha256": "a" * 64, "expectedOwner": "owner-id", "expectedRevision": 1,
            "backupSha256": "b" * 64, "fixtureSha256": _FIXTURE_SHA,
            "fixtureSize": _FIXTURE_SIZE, "expectedAvd": "api29", "requestId": "request-id"}


def _test_result(intent: dict[str, Any]) -> dict[str, Any]:
    first = {"requestId": intent["requestId"], "operationId": "operation-id", "revision": 2}
    return {"state": "complete", "sourcePackageSha256": intent["packageSha256"],
            "device": {"uid": "2000", "api": 29, "avd": intent["expectedAvd"], "heap": "48m"},
            "opening": {"controllerId": intent["expectedOwner"], "revision": intent["expectedRevision"],
                        "backupSha256": intent["backupSha256"]},
            "fixture": {"sha256": intent["fixtureSha256"], "bytes": intent["fixtureSize"], "domainCount": 56000},
            "first": first, "retry": dict(first), "conflictingRetryRejected": True,
            "fullRead": True, "singleOperation": True,
            "restore": {"openingRulesRestored": True, "runtimeOff": True}}


def _terminal_valid(intent: dict[str, Any], value: dict[str, Any]) -> bool:
    try:
        first, retry = value["first"], value["retry"]
        return (value.get("state") == "complete" and
                value.get("sourcePackageSha256") == intent.get("packageSha256") and
                value.get("device") == {"uid": "2000", "api": 29, "avd": intent.get("expectedAvd"), "heap": "48m"} and
                value.get("opening") == {"controllerId": intent.get("expectedOwner"),
                                         "revision": intent.get("expectedRevision"),
                                         "backupSha256": intent.get("backupSha256")} and
                value.get("fixture") == {"sha256": intent.get("fixtureSha256"),
                                         "bytes": intent.get("fixtureSize"), "domainCount": 56000} and
                isinstance(first, dict) and isinstance(retry, dict) and first == retry and
                first.get("requestId") == intent.get("requestId") and
                isinstance(first.get("operationId"), str) and bool(first["operationId"]) and
                type(first.get("revision")) is int and first["revision"] > intent.get("expectedRevision", -1) and
                value.get("conflictingRetryRejected") is True and value.get("fullRead") is True and
                value.get("singleOperation") is True and
                value.get("restore") == {"openingRulesRestored": True, "runtimeOff": True})
    except (KeyError, TypeError, ValueError):
        return False


def _collect_release_allowed(observed: dict[str, Any]) -> bool:
    return observed.get("state") == "complete" and observed.get("terminalValidated") is True


def _opening_valid(opening: dict[str, Any], opening_intent: dict[str, Any],
                   host: str, device: str, package_hash: str, expected_owner: str,
                   expected_revision: int, expected_backup_sha256: str,
                   expected_avd: str, remote_root: Path, correlation_id: str) -> bool:
    result = opening.get("result")
    if not isinstance(result, dict) or not isinstance(opening_intent, dict):
        return False
    return (opening.get("ok") is True and opening.get("state") == "complete" and
            opening_intent.get("host") == host and opening_intent.get("device") == device and
            result.get("package", {}).get("baseSha256") == package_hash and
            result.get("guard", {}).get("controllerId") == expected_owner and
            result.get("guard", {}).get("configurationRevision") == expected_revision and
            result.get("guard", {}).get("backupSha256") == expected_backup_sha256 and
            result.get("backup", {}).get("sha256") == expected_backup_sha256 and
            result.get("backup", {}).get("size") == 239 and
            result.get("backup", {}).get("path") == str(remote_root / ("android-readback-" + correlation_id) / "routing.json") and
            result.get("device", {}).get("uid") == "2000" and
            result.get("device", {}).get("api") == 29 and
            result.get("device", {}).get("avd") == expected_avd and
            result.get("reverseInventory") == [])


def _journal(root: Path | str, correlation: str) -> Path:
    return Path(root).resolve() / ".rag_index" / "android-document-retry-jobs" / (correlation + ".json")


def _save(root: Path | str, intent: dict[str, Any]) -> None:
    path = _journal(root, intent["correlationId"])
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700:
        raise ValueError("Android document retry journal directory is not private")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(json.dumps(intent, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        out.flush(); os.fsync(out.fileno())
    directory = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(directory)
    finally: os.close(directory)


def _load(root: Path | str, correlation: str) -> dict[str, Any] | None:
    try:
        fd = os.open(_journal(root, correlation), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                return None
            raw = source.read(8193)
        value = json.loads(raw) if len(raw) <= 8192 else None
        return value if isinstance(value, dict) and value.get("correlationId") == correlation else None
    except (OSError, ValueError, TypeError):
        return None


def _claim_shared(root: Path | str, host: str, device: str, correlation_id: str) -> dict[str, Any]:
    android_installer_dispatch._claim_local(Path(root).resolve(), host, device, correlation_id,
                                            "android-document-retry")
    return android_installer_dispatch.remote_shared_lease(root, host, device, correlation_id,
                                                           "android-document-retry", "claim")


def _recovery_original_valid(old: dict[str, Any] | None, observed: dict[str, Any],
                             host: str, device: str, owner: str, current_revision: int,
                             unknown_correlation_id: str) -> bool:
    if not isinstance(old, dict):
        return False
    identity = observed.get("identity")
    return (old.get("correlationId") == unknown_correlation_id and old.get("host") == host and
            old.get("device") == device and old.get("expectedOwner") == owner and
            type(old.get("expectedRevision")) is int and old["expectedRevision"] < current_revision and
            observed.get("state") == "unknown" and isinstance(observed.get("reason"), str) and
            bool(observed["reason"]) and isinstance(identity, dict) and
            type(identity.get("pid")) is int and identity["pid"] > 0 and
            type(identity.get("startTicks")) is int and identity["startTicks"] > 0)


def _recovery_sources() -> tuple[str, str, str]:
    old_name = '"android-document-job-"'
    new_name = '"android-document-retry-job-"'
    remote = android_document_recovery._REMOTE.replace(old_name, new_name)
    preserved = android_document_recovery._PRESERVED_PREFLIGHT.replace(old_name, new_name)
    terminal = android_document_recovery._ORIGINAL_TERMINAL.replace(old_name, new_name)
    original_check = 'result.get("reason")!="command_failed"'
    terminal = terminal.replace(original_check,
        '(not isinstance(result.get("reason"),str) or not result.get("reason"))')
    if (old_name in remote or old_name in preserved or old_name in terminal or
            new_name not in remote or new_name not in preserved or new_name not in terminal or
            original_check in terminal):
        raise RuntimeError("Android retry recovery source binding changed")
    return remote, preserved, terminal


def _closing_semantic_source() -> str:
    original = "same=first==last"
    replacement = 'same=json.dumps(first,sort_keys=True,separators=(",",":"),ensure_ascii=False)==json.dumps(last,sort_keys=True,separators=(",",":"),ensure_ascii=False)'
    source = android_document_recovery._CLOSING_SEMANTIC
    if source.count(original) != 1:
        raise RuntimeError("Android retry closing semantic source changed")
    return source.replace(original, replacement)


_RECOVERY_CURRENT_PROOF = r'''import hashlib,json,os,pathlib,stat,sys
root,unknown,current,fixture_sha,fixture_size,current_sha,current_size=sys.argv[1:]
def document(directory_name,name,sha,size):
 directory=pathlib.Path(root)/directory_name; info=directory.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: raise ValueError("unsafe_directory")
 descriptor=os.open(directory,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0))
 try:
  fd=os.open(name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0),dir_fd=descriptor)
  with os.fdopen(fd,"rb") as source:
   info=os.fstat(source.fileno())
   if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size!=int(size): raise ValueError("unsafe_file")
   raw=source.read(int(size)+1)
 finally: os.close(descriptor)
 if len(raw)!=int(size) or hashlib.sha256(raw).hexdigest()!=sha: raise ValueError("changed_file")
 value=json.loads(raw)
 if value.get("type")!="vpn_control_routing_rules" or value.get("version")!=7 or not isinstance(value.get("rules"),dict): raise ValueError("invalid_document")
 return value
ready=False
try:
 base=pathlib.Path(root); info=base.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: raise ValueError("unsafe_root")
 fixture=document("android-document-retry-job-"+unknown,"routing-v7-56000.json",fixture_sha,fixture_size)
 observed=document("android-readback-"+current,"routing.json",current_sha,current_size)
 ready=json.dumps(fixture["rules"],sort_keys=True,separators=(",",":"),ensure_ascii=False)==json.dumps(observed["rules"],sort_keys=True,separators=(",",":"),ensure_ascii=False)
except (OSError,ValueError,TypeError,KeyError): pass
print(json.dumps({"ready":ready},separators=(",",":")))'''


_REMOTE = android_observation._canonical_cli_environment_source() + r'''
import base64,hashlib,json,os,pathlib,re,stat,subprocess,sys,time,uuid
os.umask(0o077)
adb,cli,serial,avd,root,correlation,package_hash,owner,revision,backup_path,backup_hash,fixture_hash,fixture_size,request_id=sys.argv[1:]
job=pathlib.Path(root)/("android-document-retry-job-"+correlation)
URI="content://com.kardinal.vpncontrol.control"
environment=public_cli_environment(adb,pathlib.Path(cli))
def fail(reason):
 print(json.dumps({"state":"unknown","reason":reason},separators=(",",":"))); raise SystemExit(0)
def invoke(args,timeout=60,limit=16777216,input=None,env=None,allow_stderr=False):
 try: done=subprocess.run(args,input=input,stdin=subprocess.DEVNULL if input is None else None,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,env=env,check=False)
 except (OSError,subprocess.TimeoutExpired): fail("command_outcome_unknown")
 if done.returncode or len(done.stdout)>limit or len(done.stderr)>65536 or (done.stderr and not allow_stderr): fail("command_failed")
 try: return done.stdout.decode("utf-8","strict").strip()
 except UnicodeError: fail("command_encoding")
def shell(*words): return invoke([adb,"-s",serial,"shell","-T",*words],timeout=20,limit=4096)
def public(*words,timeout=300,limit=16777216):
 raw=invoke([cli,"--json","--android","--serial",serial,"--timeout-seconds",str(timeout),*words],timeout=timeout+15,limit=limit,env=environment,allow_stderr=True)
 try: value=json.loads(raw)
 except ValueError: fail("public_result_invalid")
 if not isinstance(value,dict): fail("public_result_invalid")
 return value
def final(value,who,reason):
 if value.get("ok") is not True or value.get("final") is not True or value.get("code")!="OK" or value.get("controllerId")!=who: fail(reason)
def same_rules(left,right):
 return isinstance(left,dict) and isinstance(right,dict) and json.dumps(left,sort_keys=True,separators=(",",":"),ensure_ascii=False)==json.dumps(right,sort_keys=True,separators=(",",":"),ensure_ascii=False)
def phase(name):
 temporary=job/"phase.json.tmp"; marker=job/"phase.json"
 with temporary.open("x",encoding="utf-8") as output: json.dump({"phase":name},output); output.flush(); os.fsync(output.fileno())
 os.replace(temporary,marker); directory=os.open(job,os.O_RDONLY); os.fsync(directory); os.close(directory)
def bundle(raw):
 match=re.fullmatch(r"Result: Bundle\[\{([^{}\r\n]*)}]\s*",raw)
 if not match: fail("provider_bundle_invalid")
 if not match.group(1): return {}
 fields={}
 for item in match.group(1).split(", "):
  if "=" not in item: fail("provider_bundle_invalid")
  key,value=item.split("=",1)
  if not key or key in fields: fail("provider_bundle_invalid")
  fields[key]=value
 return fields
def call(method,arg):
 return bundle(invoke([adb,"-s",serial,"shell","-T","content","call","--uri",URI,"--method",method,"--arg",arg],timeout=30,limit=2048))
def safe_file(path,expected,size):
 fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
 with os.fdopen(fd,"rb") as source:
  info=os.fstat(source.fileno())
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size!=int(size): fail("private_file_unsafe")
  raw=source.read(int(size)+1)
 if len(raw)!=int(size) or hashlib.sha256(raw).hexdigest()!=expected: fail("private_file_changed")
 return raw
def shared_lease():
 lease=pathlib.Path(root)/( "android-native-device-api29.lease")
 fd=os.open(lease,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
 with os.fdopen(fd,"rb") as source:
  info=os.fstat(source.fileno()); raw=source.read(1025)
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or len(raw)>1024: fail("shared_lease_unsafe")
 try: value=json.loads(raw)
 except ValueError: fail("shared_lease_invalid")
 if value!={"owner":"android-document-retry","host":"archlinux","device":"api29","correlationId":correlation}: fail("shared_lease_changed")
def request(text):
 return json.dumps({"schemaVersion":1,"requestId":request_id,"controllerId":owner,"ifRevision":int(revision),"interactive":False,"asynchronous":False,"command":{"operation":"routing.import","arguments":{"input":text}}},ensure_ascii=False,separators=(",",":"),allow_nan=False).encode("utf-8")
def transfer(label,payload):
 context=str(uuid.uuid4()); begun=call("document-begin",context)
 if set(begun)!={"id","controllerId","chunkBytes"} or begun["controllerId"]!=owner or not re.fullmatch(r"[0-9a-f-]{36}",begun["id"]): fail("begin_invalid")
 transfer_id=begun["id"]
 try: chunk_size=int(begun["chunkBytes"])
 except ValueError: fail("chunk_size_invalid")
 if not 1<=chunk_size<=65536: fail("chunk_size_invalid")
 identity=job/("transfer-"+label+".json")
 with identity.open("x",encoding="utf-8") as out:
  json.dump({"requestId":request_id,"controllerId":owner,"transferId":transfer_id,"payloadSha256":hashlib.sha256(payload).hexdigest()},out); out.flush(); os.fsync(out.fileno())
 directory=os.open(job,os.O_RDONLY); os.fsync(directory); os.close(directory)
 for offset in range(0,len(payload),chunk_size):
  raw=invoke([adb,"-s",serial,"shell","-T","content","write","--uri",URI+"/document-uploads/"+transfer_id+"/"+str(offset)],timeout=30,limit=1024,input=payload[offset:offset+chunk_size])
  if raw: fail("upload_reply_invalid")
 digest=hashlib.sha256(payload).hexdigest()
 sealed=call("document-seal",transfer_id+":"+str(len(payload))+":"+digest)
 if set(sealed)!={"id","byteCount","sha256","chunkBytes"} or sealed["id"]!=transfer_id or sealed["byteCount"]!=str(len(payload)) or sealed["sha256"]!=digest: fail("seal_invalid")
 shared_lease(); phase(label+"_submit")
 state=call("document-submit",transfer_id)
 deadline=time.monotonic()+360
 while state.get("state") in ("pending","sealed"):
  if time.monotonic()>=deadline: fail("document_outcome_unknown")
  time.sleep(.1); state=call("document-status",transfer_id)
 if state!={"state":"complete"}: fail("document_outcome_unknown")
 descriptor=call("document-result",transfer_id)
 if set(descriptor)!={"id","byteCount","sha256","chunkBytes"} or not re.fullmatch(r"[0-9a-f]{64}",descriptor["sha256"]): fail("result_descriptor_invalid")
 try: count=int(descriptor["byteCount"]); read_size=int(descriptor["chunkBytes"])
 except ValueError: fail("result_descriptor_invalid")
 if not 0<count<=65536 or not 1<=read_size<=65536: fail("result_size_invalid")
 output=bytearray()
 while len(output)<count:
  length=min(read_size,count-len(output)); chunk=call("document-read",transfer_id+":"+str(len(output))+":"+str(length))
  if set(chunk)!={"id","offset","data"} or chunk["id"]!=descriptor["id"] or chunk["offset"]!=str(len(output)): fail("result_chunk_invalid")
  try: data=base64.b64decode(chunk["data"],validate=True)
  except ValueError: fail("result_chunk_invalid")
  if len(data)!=length or base64.b64encode(data).decode()!=chunk["data"]: fail("result_chunk_invalid")
  output.extend(data)
 if hashlib.sha256(output).hexdigest()!=descriptor["sha256"]: fail("result_hash_invalid")
 try: result=json.loads(output)
 except (ValueError,UnicodeError): fail("result_json_invalid")
 if not isinstance(result,dict) or result.get("controllerId")!=owner or result.get("requestId")!=request_id or type(result.get("final")) is not bool: fail("result_identity_invalid")
 discarded=call("document-discard",transfer_id)
 if discarded: fail("discard_unknown")
 return result
def settle(value,label):
 if value.get("ok") is True and value.get("final") is True and value.get("code")=="OK": return value.get("operationId"),value.get("configurationRevision")
 operation=value.get("operationId")
 if value.get("code") not in ("ACCEPTED","TIMEOUT") or value.get("final") is not False or not isinstance(operation,str) or not re.fullmatch(r"[0-9a-f-]{36}",operation): fail(label+"_not_recoverable")
 phase(label+"_wait")
 waited=public("--controller-id",owner,"operations","wait",operation,timeout=300,limit=16384)
 final(waited,owner,label+"_wait_failed")
 if waited.get("operationId")!=operation: fail(label+"_operation_changed")
 return operation,waited.get("configurationRevision")
if shell("id","-u")!="2000" or shell("getprop","ro.build.version.sdk")!="29" or {x for x in (shell("getprop","ro.kernel.qemu.avd_name"),shell("getprop","ro.boot.qemu.avd_name")) if x}!={avd} or shell("getprop","ro.product.cpu.abi")!="x86_64" or shell("getprop","dalvik.vm.heapsize").lower()!="48m": fail("device_changed")
paths=[x.removeprefix("package:") for x in shell("pm","path","com.kardinal.vpncontrol").splitlines() if x.startswith("package:") and x.endswith("/base.apk")]
if len(paths)!=1 or not paths[0].startswith("/data/app/") or shell("sha256sum",paths[0]).split()!=[package_hash,paths[0]]: fail("package_changed")
base=pathlib.Path(root); info=base.lstat(); jinfo=job.lstat()
if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700 or not stat.S_ISDIR(jinfo.st_mode) or jinfo.st_uid!=os.getuid() or stat.S_IMODE(jinfo.st_mode)!=0o700: fail("private_root_unsafe")
opening_raw=safe_file(backup_path,backup_hash,239)
shared_lease()
try: opening=json.loads(opening_raw)
except ValueError: fail("opening_invalid")
if opening.get("type")!="vpn_control_routing_rules" or opening.get("version")!=7 or not isinstance(opening.get("rules"),dict): fail("opening_invalid")
original=job/"opening-routing.json"
with original.open("xb") as out: out.write(opening_raw); out.flush(); os.fsync(out.fileno())
directory=os.open(job,os.O_RDONLY); os.fsync(directory); os.close(directory)
status=public("status",timeout=30,limit=16384); final(status,owner,"opening_status_changed")
if status.get("configurationRevision")!=int(revision) or status.get("data",{}).get("runtimeRunning") is not False or status.get("data",{}).get("runtimeObservation")!="stopped": fail("opening_guard_changed")
rules={"ignore_rules":False,"block_quic_udp_443":False,"proxy_packages":[],"direct_domain_suffixes":["d%05d"%i+"."+"a"*60+"."+"b"*60+"."+"c"*60+".example.test" for i in range(56000)]}
fixture=json.dumps({"type":"vpn_control_routing_rules","version":7,"rules":rules}).encode()
if len(fixture)!=int(fixture_size) or hashlib.sha256(fixture).hexdigest()!=fixture_hash: fail("fixture_mismatch")
target=job/"routing-v7-56000.json"
with target.open("xb") as out: out.write(fixture); out.flush(); os.fsync(out.fileno())
payload=request(fixture.decode())
phase("first_upload")
first=transfer("first",payload)
first_id,first_revision=settle(first,"first")
if not isinstance(first_id,str) or not first_id or type(first_revision) is not int or first_revision<=int(revision): fail("first_identity_invalid")
phase("retry_upload")
retry=transfer("retry",payload)
retry_id,retry_revision=settle(retry,"retry")
if retry_id!=first_id or retry_revision!=first_revision: fail("same_request_replayed")
phase("conflict_upload")
conflict=transfer("conflict",request(opening_raw.decode()))
if conflict.get("ok") is not False or conflict.get("code")!="CONFLICT" or conflict.get("configurationRevision")!=first_revision: fail("conflict_not_rejected")
read=public("routing","show",timeout=300); final(read,owner,"full_read_invalid")
if read.get("configurationRevision")!=first_revision or not same_rules(read.get("data",{}).get("routing",{}).get("rules"),rules): fail("full_read_mismatch")
history=public("operations","list",timeout=30,limit=16384); final(history,owner,"history_invalid")
entries=history.get("data",{}).get("operations")
if not isinstance(entries,list) or sum(isinstance(x,dict) and x.get("id")==first_id for x in entries)!=1: fail("duplicate_operation")
phase("restore_submit")
shared_lease()
restored=public("--controller-id",owner,"--if-revision",str(first_revision),"routing","import","--input",str(original),timeout=300,limit=16384); final(restored,owner,"restore_failed")
closing=public("routing","show",timeout=300); final(closing,owner,"closing_read_failed")
if not same_rules(closing.get("data",{}).get("routing",{}).get("rules"),opening["rules"]): fail("restore_mismatch")
off=public("status",timeout=30,limit=16384); final(off,owner,"closing_status_failed")
if off.get("data",{}).get("runtimeRunning") is not False or off.get("data",{}).get("runtimeObservation")!="stopped" or shell("sha256sum",paths[0]).split()!=[package_hash,paths[0]]: fail("closing_guard_changed")
print(json.dumps({"state":"complete","sourcePackageSha256":package_hash,"device":{"uid":"2000","api":29,"avd":avd,"heap":"48m"},"opening":{"controllerId":owner,"revision":int(revision),"backupSha256":backup_hash},"fixture":{"sha256":fixture_hash,"bytes":int(fixture_size),"domainCount":56000},"first":{"requestId":request_id,"operationId":first_id,"revision":first_revision},"retry":{"requestId":request_id,"operationId":retry_id,"revision":retry_revision},"conflictingRetryRejected":True,"fullRead":True,"singleOperation":True,"restore":{"openingRulesRestored":True,"runtimeOff":True}},separators=(",",":")))
'''


_SUBMIT = android_admission_readback._ASYNC_SUBMIT.replace("android-readback-job-", "android-document-retry-job-")
_STATUS = r'''import hashlib,json,os,pathlib,re,stat,sys
root,correlation,expected_json=sys.argv[1:]
def emit(state,reason=None,**extra):
 print(json.dumps({"state":state,"reason":reason,"correlationId":correlation,**extra},separators=(",",":"))); raise SystemExit(0)
job=pathlib.Path(root)/( "android-document-retry-job-"+correlation)
try:
 info=job.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: emit("unknown","unsafe_job")
 directory=os.open(job,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0))
 def private(name,limit=16384):
  fd=os.open(name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0),dir_fd=directory)
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
  value=receipt.get("result")
  if receipt.get("state")=="complete" and isinstance(value,dict):
   first=value.get("first"); retry=value.get("retry")
   valid=(value.get("state")=="complete" and value.get("sourcePackageSha256")==intent.get("packageSha256") and
    value.get("device")=={"uid":"2000","api":29,"avd":intent.get("expectedAvd"),"heap":"48m"} and
    value.get("opening")=={"controllerId":intent.get("expectedOwner"),"revision":intent.get("expectedRevision"),"backupSha256":intent.get("backupSha256")} and
    value.get("fixture")=={"sha256":intent.get("fixtureSha256"),"bytes":intent.get("fixtureSize"),"domainCount":56000} and
    isinstance(first,dict) and first==retry and first.get("requestId")==intent.get("requestId") and
    isinstance(first.get("operationId"),str) and bool(first["operationId"]) and type(first.get("revision")) is int and first["revision"]>intent.get("expectedRevision",-1) and
    value.get("conflictingRetryRejected") is True and value.get("fullRead") is True and value.get("singleOperation") is True and
    value.get("restore")=={"openingRulesRestored":True,"runtimeOff":True})
   if not valid: emit("unknown","terminal_binding_invalid",identity=identity)
   for name,expected,size in (("opening-routing.json",intent.get("backupSha256"),239),("routing-v7-56000.json",intent.get("fixtureSha256"),intent.get("fixtureSize"))):
    fd=os.open(name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0),dir_fd=directory)
    with os.fdopen(fd,"rb") as source:
     info=os.fstat(source.fileno())
     if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size!=size or not isinstance(expected,str) or not re.fullmatch(r"[0-9a-f]{64}",expected): emit("unknown","private_file_invalid",identity=identity)
     digest=hashlib.sha256()
     while True:
      block=source.read(65536)
      if not block: break
      digest.update(block)
     if digest.hexdigest()!=expected: emit("unknown","private_file_changed",identity=identity)
   transfers=[private("transfer-"+name+".json",1024) for name in ("first","retry","conflict")]
   expected_hashes=[item.get("payloadSha256") for item in transfers]
   transfer_ids=[item.get("transferId") for item in transfers]
   if (any(not isinstance(item,dict) or item.get("requestId")!=intent.get("requestId") or item.get("controllerId")!=intent.get("expectedOwner") for item in transfers) or
       any(not isinstance(item,str) or not re.fullmatch(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}",item) for item in transfer_ids) or
       len(set(transfer_ids))!=3 or
       any(not isinstance(item,str) or not re.fullmatch(r"[0-9a-f]{64}",item) for item in expected_hashes) or
       expected_hashes[0]!=intent.get("requestSha256") or expected_hashes[0]!=expected_hashes[1] or expected_hashes[0]==expected_hashes[2]):
    emit("unknown","transfer_identity_invalid",identity=identity)
   emit("complete",None,identity=identity,receipt=receipt)
  try: phase=private("phase.json",1024).get("phase")
  except FileNotFoundError: phase=None
  allowed={"first_upload","first_submit","first_wait","retry_upload","retry_submit","retry_wait","conflict_upload","conflict_submit","restore_submit"}
  if phase is not None and phase not in allowed: emit("unknown","phase_invalid",identity=identity)
  emit("unknown",receipt.get("reason","worker_unknown"),identity=identity,phase=phase)
 try:
  fields=pathlib.Path(f"/proc/{pid}/stat").read_text(encoding="ascii").rsplit(")",1)[1].split()
  live=fields[0]!="Z" and int(fields[19])==ticks
 except (OSError,ValueError,IndexError): live=False
 emit("running" if live else "unknown",None if live else "missing_worker_receipt",identity=identity)
except FileNotFoundError: emit("unknown","missing_job_or_intent")
except (OSError,ValueError,TypeError,KeyError): emit("unknown","status_unavailable")'''


def start(root: Path | str, host: str, device: str, correlation_id: str, artifact_id: str,
          cli_stage_correlation_id: str, opening_readback_correlation_id: str,
          expected_backup_sha256: str, expected_owner: str, expected_revision: int) -> dict[str, Any]:
    if host != "archlinux" or device != "api29" or not all(isinstance(v, str) and _UUID.fullmatch(v)
            for v in (correlation_id, cli_stage_correlation_id, opening_readback_correlation_id, expected_owner)):
        raise ValueError("Android document retry requires exact owned API29 identities")
    if type(expected_revision) is not int or expected_revision < 0 or not isinstance(expected_backup_sha256, str) or not _SHA.fullmatch(expected_backup_sha256):
        raise ValueError("Android document retry owner and backup guard is invalid")
    config = ssh_transport.load_config(root)
    if host not in config.hosts or device not in config.hosts[host].android_devices or config.hosts[host].fixture_transfer_root is None or ssh_transport.connection_host(config, host).password is not None:
        raise ValueError("Android document retry route is not configured")
    profile = android_observation._profile(config.hosts[host].android_devices[device])
    if profile["api"] != 29:
        raise ValueError("Android document retry requires API29")
    artifact = native_artifact_registry.verify_artifact(root, artifact_id)
    if (artifact.get("verification") != "verified" or artifact["artifact"].get("platform") != "android" or
            artifact["artifact"].get("artifactKind") not in {"apk", "native-fixture-apk"}):
        raise ValueError("Android document retry APK is not verified")
    source_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if artifact["artifact"].get("sourceSha") != source_sha:
        raise ValueError("Android document retry APK is not current source")
    android_package_install._inspect_apk(root, Path(artifact["location"]["localPath"]))
    package_hash = artifact["artifact"]["sha256"]
    stage = android_cli_stage.status(root, cli_stage_correlation_id)
    if not stage.get("ok") or stage.get("state") != "published" or stage.get("sourceSha") != source_sha:
        raise ValueError("Android document retry CLI stage is not current source")
    cli_path = stage.get("receipt", {}).get("cliPath")
    remote_root = config.hosts[host].fixture_transfer_root
    if not isinstance(cli_path, str) or not cli_path.startswith(str(remote_root) + "/android-cli-stage-" + cli_stage_correlation_id + "/tree/"):
        raise ValueError("Android document retry CLI path is not stage-bound")
    opening = android_admission_readback.async_collect(root, opening_readback_correlation_id)
    opening_intent = android_admission_readback._load_async_intent(root, opening_readback_correlation_id)
    if not _opening_valid(opening, opening_intent, host, device, package_hash, expected_owner,
                          expected_revision, expected_backup_sha256, profile["expectedAvd"],
                          remote_root, opening_readback_correlation_id):
        raise ValueError("Android document retry opening readback changed")
    result = opening["result"]
    backup_path = result["backup"]["path"]
    if backup_path != str(remote_root / ("android-readback-" + opening_readback_correlation_id) / "routing.json"):
        raise ValueError("Android document retry backup path is not private")
    public_argv = ssh_transport.build_ssh_argv(config, host, 60, command=("python3", "-I", "-B", "-c",
        "exec(" + repr(android_document_acceptance._PUBLIC_PREFLIGHT) + ")", profile["adb"], cli_path, profile["serial"], expected_owner, str(expected_revision)))
    heap_argv = ssh_transport.build_ssh_argv(config, host, 30, command=("python3", "-I", "-B", "-c",
        "exec(" + repr(android_document_acceptance._HEAP_PROBE) + ")", profile["adb"], profile["serial"], profile["expectedAvd"]))
    for argv, timeout in ((public_argv, 60), (heap_argv, 30)):
        try:
            code, output = android_observation._run_probe(argv, timeout)
            probe = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
        except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
            probe = None
        if not isinstance(probe, dict) or probe.get("ready") is not True:
            raise ValueError("Android document retry public owner or 48 MiB heap is not admitted")
    import uuid
    request_id = str(uuid.uuid4())
    request_sha = hashlib.sha256(_request_bytes(request_id, expected_owner, expected_revision,
                                                _fixture_text())).hexdigest()
    intent = {"host": host, "device": device, "correlationId": correlation_id, "artifactId": artifact_id,
              "packageSha256": package_hash, "sourceSha": source_sha, "expectedOwner": expected_owner,
              "expectedRevision": expected_revision, "backupSha256": expected_backup_sha256,
              "openingReadbackCorrelationId": opening_readback_correlation_id,
              "expectedAvd": profile["expectedAvd"], "fixtureRoot": str(remote_root),
              "fixtureSha256": _FIXTURE_SHA, "fixtureSize": _FIXTURE_SIZE, "requestId": request_id,
              "requestSha256": request_sha,
              "cliStageCorrelationId": cli_stage_correlation_id,
              "cliManifestSha256": stage["receipt"]["manifestSha256"],
              "cliDesktopJarSha256": stage["receipt"]["desktopJarSha256"], "cliPath": cli_path}
    args = [profile["adb"], cli_path, profile["serial"], profile["expectedAvd"], str(remote_root),
            correlation_id, package_hash, expected_owner, str(expected_revision), backup_path,
            expected_backup_sha256, _FIXTURE_SHA, str(_FIXTURE_SIZE), request_id]
    worker = android_document_acceptance._worker(_REMOTE, args)
    encoded = base64.urlsafe_b64encode(worker.encode()).decode("ascii")
    argv = ssh_transport.build_ssh_argv(config, host, 60, command=("python3", "-I", "-B", "-c",
        "exec(" + repr(_SUBMIT) + ")", str(remote_root), correlation_id,
        json.dumps(intent, sort_keys=True, separators=(",", ":")), encoded))
    _save(root, intent)
    android_document_acceptance._claim_device(root, host, device, correlation_id)
    try:
        shared = _claim_shared(root, host, device, correlation_id)
    except FileExistsError:
        android_document_acceptance._release_device(root, host, device, correlation_id)
        raise
    if shared.get("state") != "claimed":
        return {"ok": False, "state": "unknown", "reason": "shared_remote_lease_unknown",
                "correlationId": correlation_id, "replayAllowed": False}
    try:
        code, output = android_observation._run_probe(argv, 60)
        observed = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
        if isinstance(observed, dict) and observed.get("state") == "submitted" and observed.get("correlationId") == correlation_id:
            return {"ok": True, "state": "submitted", "correlationId": correlation_id,
                    "identity": observed.get("identity"), "replayAllowed": False}
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
        pass
    return {"ok": False, "state": "unknown", "correlationId": correlation_id, "replayAllowed": False}


def status(root: Path | str, correlation_id: str) -> dict[str, Any]:
    if not isinstance(correlation_id, str) or not _UUID.fullmatch(correlation_id):
        raise ValueError("Android document retry correlation must be a UUID")
    intent = _load(root, correlation_id)
    if intent is None:
        return {"ok": False, "state": "unknown", "reason": "missing_local_intent", "correlationId": correlation_id, "replayAllowed": False}
    config = ssh_transport.load_config(root)
    if intent["host"] not in config.hosts or ssh_transport.connection_host(config, intent["host"]).password is not None:
        return {"ok": False, "state": "unknown", "reason": "route_unavailable", "correlationId": correlation_id, "replayAllowed": False}
    remote_root = config.hosts[intent["host"]].fixture_transfer_root
    if remote_root is None or str(remote_root) != intent.get("fixtureRoot"):
        return {"ok": False, "state": "unknown", "reason": "fixture_root_changed", "correlationId": correlation_id, "replayAllowed": False}
    argv = ssh_transport.build_ssh_argv(config, intent["host"], 30, command=("python3", "-I", "-B", "-c",
        "exec(" + repr(_STATUS) + ")", str(remote_root), correlation_id,
        json.dumps(intent, sort_keys=True, separators=(",", ":"))))
    try:
        code, output = android_observation._run_probe(argv, 30)
        observed = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
        if isinstance(observed, dict) and observed.get("correlationId") == correlation_id and observed.get("state") in {"running", "complete", "unknown"}:
            return {"ok": observed["state"] in {"running", "complete"}, **observed, "replayAllowed": False}
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
        pass
    return {"ok": False, "state": "unknown", "reason": "transport_or_receipt_unknown",
            "correlationId": correlation_id, "replayAllowed": False}


def collect(root: Path | str, correlation_id: str) -> dict[str, Any]:
    observed = status(root, correlation_id)
    if observed.get("state") != "complete":
        return observed
    intent = _load(root, correlation_id)
    receipt = observed.get("receipt")
    value = receipt.get("result") if isinstance(receipt, dict) else None
    if not isinstance(intent, dict) or not isinstance(value, dict) or not _terminal_valid(intent, value):
        return {"ok": False, "state": "unknown", "reason": "terminal_binding_invalid",
                "correlationId": correlation_id, "replayAllowed": False}
    stage = android_cli_stage.status(root, intent["cliStageCorrelationId"])
    if (not stage.get("ok") or stage.get("state") != "published" or stage.get("sourceSha") != intent.get("sourceSha") or
            stage.get("receipt", {}).get("manifestSha256") != intent.get("cliManifestSha256") or
            stage.get("receipt", {}).get("desktopJarSha256") != intent.get("cliDesktopJarSha256") or
            stage.get("receipt", {}).get("cliPath") != intent.get("cliPath")):
        return {"ok": False, "state": "unknown", "reason": "cli_stage_changed",
                "correlationId": correlation_id, "replayAllowed": False}
    validated = {"state": "complete", "terminalValidated": True}
    remote = android_installer_dispatch.remote_shared_lease(root, intent["host"], intent["device"],
                                                             correlation_id, "android-document-retry", "release")
    if remote.get("state") != "released":
        return {"ok": False, "state": "unknown", "reason": "shared_remote_lease_not_released",
                "correlationId": correlation_id, "replayAllowed": False}
    document_released = _collect_release_allowed(validated) and android_document_acceptance._release_device(
        root, intent["host"], intent["device"], correlation_id)
    shared_released = android_installer_dispatch._release_local(Path(root).resolve(), intent["host"],
        intent["device"], correlation_id, "android-document-retry") if document_released else False
    released = document_released and shared_released
    return {"ok": released, "state": "complete", "correlationId": correlation_id, "result": value,
            "identity": observed.get("identity"), "replayAllowed": False, "leaseReleased": released,
            "evidenceClass": "native-document-retry"}


def recovery_start(root: Path | str, host: str, device: str, recovery_correlation_id: str,
                   unknown_retry_correlation_id: str, opening_readback_correlation_id: str,
                   current_readback_correlation_id: str, artifact_id: str,
                   cli_stage_correlation_id: str, expected_owner: str,
                   expected_revision: int) -> dict[str, Any]:
    """Restore one proven terminal unknown import; retain original leases until finalize."""
    values = (recovery_correlation_id, unknown_retry_correlation_id, opening_readback_correlation_id,
              current_readback_correlation_id, cli_stage_correlation_id, expected_owner)
    if (host != "archlinux" or device != "api29" or type(expected_revision) is not int or expected_revision < 0 or
            any(not isinstance(value, str) or not _UUID.fullmatch(value) for value in values) or
            len(set(values)) != len(values)):
        raise ValueError("Android retry recovery requires distinct exact API29 identities")
    old = _load(root, unknown_retry_correlation_id)
    observed = status(root, unknown_retry_correlation_id)
    if not _recovery_original_valid(old, observed, host, device, expected_owner,
                                    expected_revision, unknown_retry_correlation_id):
        raise ValueError("Android retry recovery original outcome is not terminal unknown")
    assert old is not None
    identity = observed["identity"]
    lease = android_document_acceptance._lease(root, host, device, unknown_retry_correlation_id)
    if android_document_recovery._private_read(lease, "correlationId", unknown_retry_correlation_id) != {
            "host": host, "device": device, "correlationId": unknown_retry_correlation_id}:
        raise ValueError("Android retry recovery original document lease changed")
    config = ssh_transport.load_config(root)
    if (host not in config.hosts or device not in config.hosts[host].android_devices or
            config.hosts[host].fixture_transfer_root is None or
            ssh_transport.connection_host(config, host).password is not None):
        raise ValueError("Android retry recovery fixture route changed")
    profile = android_observation._profile(config.hosts[host].android_devices[device])
    if profile["api"] != 29:
        raise ValueError("Android retry recovery API changed")
    remote_root = config.hosts[host].fixture_transfer_root
    shared = android_installer_dispatch.remote_shared_lease(root, host, device, unknown_retry_correlation_id,
                                                             "android-document-retry", "status")
    if shared.get("state") != "claimed":
        raise ValueError("Android retry recovery shared lease changed")
    recovery_remote, recovery_preserved, recovery_terminal = _recovery_sources()
    terminal_argv = ssh_transport.build_ssh_argv(config, host, 30, command=("python3", "-I", "-B", "-c",
        "exec(" + repr(recovery_terminal) + ")", str(remote_root), unknown_retry_correlation_id,
        json.dumps(old, sort_keys=True, separators=(",", ":")), str(identity["pid"]), str(identity["startTicks"])))
    try:
        code, output = android_observation._run_probe(terminal_argv, 30)
        terminal = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
        terminal = None
    if not isinstance(terminal, dict) or terminal.get("ready") is not True:
        raise ValueError("Android retry recovery original worker is not proven stopped")
    artifact = native_artifact_registry.verify_artifact(root, artifact_id)
    if (artifact.get("verification") != "verified" or artifact["artifact"].get("platform") != "android" or
            artifact["artifact"].get("artifactKind") not in {"apk", "native-fixture-apk"}):
        raise ValueError("Android retry recovery APK is not verified")
    source_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True,
                                timeout=10, check=True).stdout.strip()
    if artifact["artifact"].get("sourceSha") != source_sha:
        raise ValueError("Android retry recovery APK is not current source")
    android_package_install._inspect_apk(root, Path(artifact["location"]["localPath"]))
    package_hash = artifact["artifact"]["sha256"]
    if (old.get("packageSha256") != package_hash or old.get("cliStageCorrelationId") != cli_stage_correlation_id or
            old.get("openingReadbackCorrelationId") != opening_readback_correlation_id):
        raise ValueError("Android retry recovery source differs from original job")
    stage = android_cli_stage.status(root, cli_stage_correlation_id)
    if not stage.get("ok") or stage.get("state") != "published" or stage.get("sourceSha") != source_sha:
        raise ValueError("Android retry recovery CLI stage changed")
    cli_path = stage.get("receipt", {}).get("cliPath")
    if cli_path != old.get("cliPath") or not isinstance(cli_path, str) or not cli_path.startswith(
            str(remote_root) + "/android-cli-stage-" + cli_stage_correlation_id + "/tree/"):
        raise ValueError("Android retry recovery CLI path changed")
    opening = android_document_recovery._readback(root, opening_readback_correlation_id, host, device,
                                                   package_hash, expected_owner, old["expectedRevision"])
    current = android_document_recovery._readback(root, current_readback_correlation_id, host, device,
                                                   package_hash, expected_owner, expected_revision)
    opening_backup, current_backup = opening["backup"], current["backup"]
    if (opening_backup["sha256"] != old.get("backupSha256") or opening_backup["size"] != 239 or
            current_backup["size"] < 11_000_000 or current_backup["sha256"] == opening_backup["sha256"]):
        raise ValueError("Android retry recovery current routing is not the large committed import")
    preserved_argv = ssh_transport.build_ssh_argv(config, host, 30, command=("python3", "-I", "-B", "-c",
        "exec(" + repr(recovery_preserved) + ")", str(remote_root), unknown_retry_correlation_id,
        opening_readback_correlation_id, current_readback_correlation_id,
        opening_backup["sha256"], str(opening_backup["size"]), current_backup["sha256"], str(current_backup["size"])))
    try:
        code, output = android_observation._run_probe(preserved_argv, 30)
        preserved = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
        preserved = None
    if not isinstance(preserved, dict) or preserved.get("ready") is not True:
        raise ValueError("Android retry recovery preserved routing is not exact")
    current_argv = ssh_transport.build_ssh_argv(config, host, 30, command=("python3", "-I", "-B", "-c",
        "exec(" + repr(_RECOVERY_CURRENT_PROOF) + ")", str(remote_root), unknown_retry_correlation_id,
        current_readback_correlation_id, _FIXTURE_SHA, str(_FIXTURE_SIZE),
        current_backup["sha256"], str(current_backup["size"])))
    try:
        code, output = android_observation._run_probe(current_argv, 30)
        current_proof = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
        current_proof = None
    if not isinstance(current_proof, dict) or current_proof.get("ready") is not True:
        raise ValueError("Android retry recovery current routing is not the exact fixture")
    opening_export = preserved["openingExport"]
    public = android_public_inspect.inspect(root, host, device, recovery_correlation_id,
                                             package_hash, expected_owner, expected_revision)
    result = public.get("result", {})
    if (public.get("ok") is not True or public.get("outcome") != "admitted" or
            result.get("runtime", {}).get("running") is not False or
            result.get("runtime", {}).get("observation") != "stopped"):
        raise ValueError("Android retry recovery owner/runtime preflight failed")
    intent = {"host": host, "device": device, "correlationId": recovery_correlation_id,
              "unknownDocumentCorrelationId": unknown_retry_correlation_id,
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
            recovery_correlation_id, unknown_retry_correlation_id, current_readback_correlation_id,
            package_hash, expected_owner, str(expected_revision), opening_export["sha256"],
            str(opening_export["size"]), current_backup["sha256"], str(current_backup["size"])]
    worker = android_document_acceptance._worker(recovery_remote, args)
    encoded = base64.urlsafe_b64encode(worker.encode()).decode("ascii")
    argv = ssh_transport.build_ssh_argv(config, host, 60, command=("python3", "-I", "-B", "-c",
        "exec(" + repr(android_document_recovery._SUBMIT) + ")", str(remote_root), recovery_correlation_id,
        json.dumps(intent, sort_keys=True, separators=(",", ":")), encoded))
    android_document_recovery._reserve(root, intent)
    try:
        code, output = android_observation._run_probe(argv, 60)
        value = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
        if isinstance(value, dict) and value.get("state") == "submitted" and value.get("correlationId") == recovery_correlation_id:
            return {"ok": True, "state": "submitted", "correlationId": recovery_correlation_id,
                    "identity": value.get("identity"), "replayAllowed": False}
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
        pass
    return {"ok": False, "state": "unknown", "correlationId": recovery_correlation_id,
            "replayAllowed": False}


def recovery_status(root: Path | str, recovery_correlation_id: str) -> dict[str, Any]:
    return android_document_recovery.status(root, recovery_correlation_id)


def recovery_collect(root: Path | str, recovery_correlation_id: str) -> dict[str, Any]:
    return android_document_recovery.collect(root, recovery_correlation_id)


def _release_recovery_leases(root: Path | str, host: str, device: str,
                             old_correlation: str) -> bool:
    remote = android_installer_dispatch.remote_shared_lease(root, host, device, old_correlation,
                                                             "android-document-retry", "release")
    if remote.get("state") != "released":
        return False
    if not android_document_acceptance._release_device(root, host, device, old_correlation):
        return False
    if android_installer_dispatch._release_local(Path(root).resolve(), host, device,
                                                  old_correlation, "android-document-retry"):
        return True
    with android_installer_dispatch._shared_lock(Path(root).resolve(), host, device) as path:
        try: path.lstat()
        except FileNotFoundError: return True
    return False


def recovery_finalize(root: Path | str, recovery_correlation_id: str,
                      closing_readback_correlation_id: str, expected_owner: str,
                      expected_revision: int) -> dict[str, Any]:
    """Verify a fresh persistent close, then durably record proof before releasing leases."""
    if (not isinstance(recovery_correlation_id, str) or not _UUID.fullmatch(recovery_correlation_id) or
            not isinstance(closing_readback_correlation_id, str) or not _UUID.fullmatch(closing_readback_correlation_id) or
            not isinstance(expected_owner, str) or not _UUID.fullmatch(expected_owner) or
            type(expected_revision) is not int or expected_revision < 0):
        raise ValueError("Android retry recovery closing guard is invalid")
    completed = recovery_collect(root, recovery_correlation_id)
    intent = android_document_recovery._load(root, recovery_correlation_id)
    result = completed.get("result")
    if (not completed.get("ok") or completed.get("state") != "complete" or not isinstance(intent, dict) or
            not isinstance(result, dict) or result.get("restore", {}).get("controllerId") != expected_owner or
            result.get("restore", {}).get("revision") != expected_revision or
            closing_readback_correlation_id in {intent.get("openingReadbackCorrelationId"),
                                                intent.get("currentReadbackCorrelationId")}):
        return {"ok": False, "state": "unknown", "reason": "closing_guard_mismatch",
                "correlationId": recovery_correlation_id, "replayAllowed": False}
    old_correlation = intent["unknownDocumentCorrelationId"]
    marker = {"correlationId": recovery_correlation_id,
              "closingReadbackCorrelationId": closing_readback_correlation_id,
              "expectedOwner": expected_owner, "expectedRevision": expected_revision,
              "unknownRetryCorrelationId": old_correlation}
    previous = _load(root, recovery_correlation_id)
    if previous is not None and any(previous.get(key) != value for key, value in marker.items()):
        return {"ok": False, "state": "unknown", "reason": "closing_proof_changed",
                "correlationId": recovery_correlation_id, "replayAllowed": False}
    original_lease = android_document_acceptance._lease(root, intent["host"], intent["device"], old_correlation)
    if previous is None and android_document_recovery._private_read(original_lease, "correlationId", old_correlation) != {
            "host": intent["host"], "device": intent["device"], "correlationId": old_correlation}:
        return {"ok": False, "state": "unknown", "reason": "original_lease_changed",
                "correlationId": recovery_correlation_id, "replayAllowed": False}
    try:
        closing = android_document_recovery._readback(root, closing_readback_correlation_id,
            intent["host"], intent["device"], intent["packageSha256"], expected_owner, expected_revision)
        backup = closing["backup"]
        if backup["size"] != 239:
            raise ValueError("Closing routing size changed")
        fresh = android_admission_readback.readback_status(root, intent["host"], intent["device"],
                                                            closing_readback_correlation_id)
        live = fresh.get("result") if fresh.get("ok") and fresh.get("outcome") == "observed" else None
        if (not isinstance(live, dict) or live.get("deviceIdentity") is not True or
                live.get("controllerId") != expected_owner or
                live.get("configurationRevision") != expected_revision or
                live.get("stage") != "backup_present" or
                live.get("backup", {}).get("sha256") != backup["sha256"] or
                live.get("backup", {}).get("size") != backup["size"] or
                live.get("backup", {}).get("formatValid") is not True):
            raise ValueError("Closing owner/readback changed")
        config = ssh_transport.load_config(root)
        remote_root = config.hosts[intent["host"]].fixture_transfer_root
        if remote_root is None or str(remote_root) != intent["fixtureRoot"]:
            raise ValueError("Closing fixture root changed")
        semantic_argv = ssh_transport.build_ssh_argv(config, intent["host"], 30, command=("python3", "-I", "-B", "-c",
            "exec(" + repr(_closing_semantic_source()) + ")", str(remote_root),
            intent["openingReadbackCorrelationId"], closing_readback_correlation_id,
            intent["openingBackupSha256"], str(intent["openingBackupSize"]),
            backup["sha256"], str(backup["size"])))
        code, output = android_observation._run_probe(semantic_argv, 30)
        semantic = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
        if (not isinstance(semantic, dict) or semantic.get("same") is not True or
                not isinstance(semantic.get("canonicalSha256"), str) or
                not _SHA.fullmatch(semantic["canonicalSha256"])):
            raise ValueError("Closing routing differs from opening")
        public = android_public_inspect.inspect(root, intent["host"], intent["device"],
            recovery_correlation_id, intent["packageSha256"], expected_owner, expected_revision)
        runtime = public.get("result", {}).get("runtime", {})
        if (not public.get("ok") or public.get("outcome") != "admitted" or
                runtime.get("running") is not False or runtime.get("observation") != "stopped"):
            raise ValueError("Closing public runtime changed")
        marker["persistentRulesSha256"] = semantic["canonicalSha256"]
        if previous is None:
            _save(root, marker)
        elif previous != marker:
            raise ValueError("Closing proof marker changed")
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError, KeyError, TypeError):
        return {"ok": False, "state": "unknown", "reason": "closing_readback_unverified",
                "correlationId": recovery_correlation_id, "replayAllowed": False}
    shared_released = _release_recovery_leases(root, intent["host"], intent["device"], old_correlation)
    return {"ok": shared_released, "state": "complete" if shared_released else "unknown",
            "reason": None if shared_released else "shared_local_lease_not_released",
            "correlationId": recovery_correlation_id,
            "closingReadbackCorrelationId": closing_readback_correlation_id,
            "leaseReleased": shared_released,
            "persistentRulesSha256": marker["persistentRulesSha256"] if shared_released else None,
            "replayAllowed": False}

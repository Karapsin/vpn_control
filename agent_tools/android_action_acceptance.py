"""One guarded public-provider same-request routing case on the owned API29 AVD.

The fixture transport uses explicit request UUIDs.  A result lost after a
provider write stays unknown and retains the local device lease.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
import re
import subprocess
from typing import Any

try:
    from . import (android_admission_readback, android_document_acceptance,
                   android_observation, android_package_install,
                   android_public_inspect, native_artifact_registry, ssh_transport)
except ImportError:
    import android_admission_readback
    import android_document_acceptance
    import android_observation
    import android_package_install
    import android_public_inspect
    import native_artifact_registry
    import ssh_transport


_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_SHA = re.compile(r"[0-9a-f]{64}")


def _request(request_id: str, owner: str, revision: int, input_text: str) -> dict[str, Any]:
    return {"schemaVersion": 1, "requestId": request_id, "controllerId": owner,
            "ifRevision": revision, "interactive": False, "asynchronous": False,
            "command": {"operation": "routing.import", "arguments": {"input": input_text}}}


_FIXTURE_SOURCE = (Path(__file__).resolve().parents[1] / "scripts" / "integration" /
                   "android_public_control_fixture.py").read_text(encoding="utf-8")
_REMOTE = _FIXTURE_SOURCE + r'''
import hashlib,json,os,pathlib,stat,sys,uuid
adb,serial,avd,api,root,correlation,package_hash,owner,revision,backup_path,backup_hash=sys.argv[1:]
def fail(reason):
 print(json.dumps({"state":"unknown","reason":reason},separators=(",",":"))); raise SystemExit(0)
def probe(*words):
 try: done=subprocess.run([adb,"-s",serial,"shell","-T",*words],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=25,check=False)
 except (OSError,subprocess.TimeoutExpired): fail("device_probe_unknown")
 if done.returncode or len(done.stdout)>4096: fail("device_probe_failed")
 try: return done.stdout.decode("utf-8","strict").strip()
 except UnicodeError: fail("device_probe_encoding")
if probe("id","-u")!="2000" or probe("getprop","ro.build.version.sdk")!=api or {v for v in (probe("getprop","ro.kernel.qemu.avd_name"),probe("getprop","ro.boot.qemu.avd_name")) if v}!={avd} or probe("getprop","ro.product.cpu.abi")!="x86_64": fail("device_changed")
paths=[p.removeprefix("package:") for p in probe("pm","path","com.kardinal.vpncontrol").splitlines() if p.startswith("package:") and p.endswith("/base.apk")]
if len(paths)!=1 or not paths[0].startswith("/data/app/"): fail("package_path_changed")
pair=probe("sha256sum",paths[0]).split()
if len(pair)!=2 or pair[0]!=package_hash or pair[1]!=paths[0]: fail("package_changed")
job=pathlib.Path(root)/("android-document-job-"+correlation)
try:
 root_info=pathlib.Path(root).lstat(); job_info=job.lstat()
except OSError: fail("job_missing")
if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid!=os.getuid() or stat.S_IMODE(root_info.st_mode)!=0o700 or not stat.S_ISDIR(job_info.st_mode) or job_info.st_uid!=os.getuid() or stat.S_IMODE(job_info.st_mode)!=0o700: fail("job_unsafe")
try:
 fd=os.open(backup_path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
 with os.fdopen(fd,"rb") as source:
  info=os.fstat(source.fileno())
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size!=239: fail("backup_unsafe")
  opening_bytes=source.read(240)
 if len(opening_bytes)!=239 or hashlib.sha256(opening_bytes).hexdigest()!=backup_hash: fail("backup_changed")
 opening=json.loads(opening_bytes)
except (OSError,ValueError,UnicodeError): fail("backup_unknown")
if opening.get("type")!="vpn_control_routing_rules" or opening.get("version")!=7 or not isinstance(opening.get("rules"),dict): fail("backup_invalid")
try:
 runner=AdbPublicRunner(adb,serial,timeout_seconds=60)
 identity=runner.attest()
 client=AndroidPublicControlFixture(runner,identity,poll_seconds=.1,timeout_seconds=90)
except (FixtureProtocolError,OSError,subprocess.TimeoutExpired): fail("provider_attestation_unknown")
def request(operation,args,request_id,revision=None):
 return {"schemaVersion":1,"requestId":request_id,"controllerId":owner,"ifRevision":revision,"interactive":False,"asynchronous":False,"command":{"operation":operation,"arguments":args}}
def exchange(value,phase):
 marker=job/"phase.json"; temporary=job/"phase.json.tmp"
 payload=json.dumps({"phase":phase},separators=(",",":")).encode()+b"\n"
 try:
  fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
  with os.fdopen(fd,"wb") as out: out.write(payload); out.flush(); os.fsync(out.fileno())
  os.replace(temporary,marker)
  directory=os.open(job,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0))
  try: os.fsync(directory)
  finally: os.close(directory)
 except OSError: fail("phase_journal_failed")
 def retain(transfer):
  record=job/("transfer-"+phase+".json")
  payload=json.dumps({"requestId":transfer.request_id,"controllerId":transfer.controller_id,"transferId":transfer.transfer_id},separators=(",",":")).encode()+b"\n"
  fd=os.open(record,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
  with os.fdopen(fd,"wb") as out: out.write(payload); out.flush(); os.fsync(out.fileno())
  directory=os.open(job,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0)); os.fsync(directory); os.close(directory)
 try:
  response=client.exchange(value,retain_transfer=retain)
  result=response.result
  response.cleanup()
  return result
 except (FixtureOutcomeUnknown,FixtureProtocolError,OSError,subprocess.TimeoutExpired): fail("public_outcome_unknown")
def final(value,request_id,expected_revision=None):
 if not isinstance(value,dict) or value.get("ok") is not True or value.get("final") is not True or value.get("code")!="OK" or value.get("controllerId")!=owner or value.get("requestId")!=request_id or (expected_revision is not None and value.get("configurationRevision")!=expected_revision): fail("public_result_invalid")
opening_status_id=str(uuid.uuid4()); status=exchange(request("status",{},opening_status_id),"opening_status")
final(status,opening_status_id,int(revision))
if status.get("data",{}).get("runtimeRunning") is not False or status.get("data",{}).get("runtimeObservation")!="stopped": fail("runtime_not_off")
history_id=str(uuid.uuid4()); history=exchange(request("operations.list",{},history_id),"opening_history")
final(history,history_id,int(revision))
entries=history.get("data",{}).get("operations")
if not isinstance(entries,list) or any(not isinstance(x,dict) or x.get("controllerId")!=owner or not isinstance(x.get("id"),str) or not x["id"] or x.get("final") is not True or x.get("phase") not in ("succeeded","failed","cancelled") or not isinstance(x.get("code"),str) for x in entries): fail("history_not_terminal")
rules=dict(opening["rules"])
domains=rules.get("direct_domain_suffixes")
if not isinstance(domains,list) or domains: fail("opening_rules_not_empty")
rules["direct_domain_suffixes"]=["same-request.acceptance.example.test"]
changed=json.dumps({"type":"vpn_control_routing_rules","version":7,"rules":rules},separators=(",",":"),ensure_ascii=False)
original=json.dumps(opening,separators=(",",":"),ensure_ascii=False)
request_id=str(uuid.uuid4())
mutation=request("routing.import",{"input":changed},request_id,int(revision))
first=exchange(mutation,"first_import")
final(first,request_id)
operation_id=first.get("operationId"); new_revision=first.get("configurationRevision")
if not isinstance(operation_id,str) or not operation_id or type(new_revision) is not int or new_revision<=int(revision): fail("first_commit_invalid")
retry=exchange(mutation,"same_request_retry")
final(retry,request_id,new_revision)
if retry.get("operationId")!=operation_id: fail("same_request_replayed")
different=request("routing.import",{"input":original},request_id,int(revision))
conflict=exchange(different,"conflicting_request")
if conflict.get("controllerId")!=owner or conflict.get("requestId")!=request_id or conflict.get("code")!="CONFLICT" or conflict.get("ok") is not False or conflict.get("final") is not True or conflict.get("configurationRevision")!=new_revision: fail("conflicting_retry_not_rejected")
read_id=str(uuid.uuid4()); read=exchange(request("routing.show",{},read_id),"changed_read")
final(read,read_id,new_revision)
if read.get("data",{}).get("routing",{}).get("rules")!=rules: fail("changed_read_mismatch")
restore_id=str(uuid.uuid4()); restored=exchange(request("routing.import",{"input":original},restore_id,new_revision),"restore_import")
final(restored,restore_id)
closing_revision=restored.get("configurationRevision")
if type(closing_revision) is not int or closing_revision<=new_revision: fail("restore_revision_invalid")
closing_id=str(uuid.uuid4()); closing=exchange(request("routing.show",{},closing_id),"closing_read")
final(closing,closing_id,closing_revision)
if closing.get("data",{}).get("routing",{}).get("rules")!=opening["rules"]: fail("restore_mismatch")
off_id=str(uuid.uuid4()); off=exchange(request("status",{},off_id),"closing_status")
final(off,off_id,closing_revision)
if off.get("data",{}).get("runtimeRunning") is not False or off.get("data",{}).get("runtimeObservation")!="stopped": fail("runtime_changed")
if probe("sha256sum",paths[0]).split()!=[package_hash,paths[0]]: fail("closing_package_changed")
print(json.dumps({"state":"complete","sourcePackageSha256":package_hash,"device":{"uid":"2000","api":int(api),"avd":avd},"opening":{"owner":owner,"revision":int(revision),"backupSha256":backup_hash},"first":{"operationId":operation_id,"revision":new_revision},"sameRequestRetry":True,"conflictingRetryRejected":True,"changedRead":True,"restore":{"openingRulesRestored":True,"runtimeOff":True,"revision":closing_revision}},separators=(",",":")))
'''

_SUBMIT = android_document_acceptance._SUBMIT
_STATUS = r'''import json,os,pathlib,stat,sys
root,correlation,expected_json=sys.argv[1:]
def emit(state,reason=None,**extra):
 print(json.dumps({"state":state,"reason":reason,"correlationId":correlation,**extra},separators=(",",":"))); raise SystemExit(0)
job=pathlib.Path(root)/("android-document-job-"+correlation)
try:
 info=job.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: emit("unknown","unsafe_job")
 def private(name,limit=16384):
  fd=os.open(job/name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
  with os.fdopen(fd,"rb") as source:
   info=os.fstat(source.fileno())
   if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1: emit("unknown","unsafe_file")
   raw=source.read(limit+1)
  if len(raw)>limit: emit("unknown","oversized_file")
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
   if value.get("state")!="complete" or value.get("sourcePackageSha256")!=intent.get("packageSha256") or value.get("device")!={"uid":"2000","api":intent.get("api"),"avd":intent.get("expectedAvd")} or value.get("opening")!={"owner":intent.get("expectedOwner"),"revision":intent.get("expectedRevision"),"backupSha256":intent.get("backupSha256")} or value.get("sameRequestRetry") is not True or value.get("conflictingRetryRejected") is not True or value.get("changedRead") is not True or value.get("restore",{}).get("openingRulesRestored") is not True or value.get("restore",{}).get("runtimeOff") is not True: emit("unknown","terminal_binding_invalid",identity=identity)
   emit("complete",None,identity=identity,receipt=receipt)
  try: phase=private("phase.json",1024).get("phase")
  except FileNotFoundError: phase=None
  if phase is not None and phase not in {"opening_status","opening_history","first_import","same_request_retry","conflicting_request","changed_read","restore_import","closing_read","closing_status"}: emit("unknown","phase_invalid",identity=identity)
  emit("unknown",receipt.get("reason","worker_unknown"),identity=identity,phase=phase)
 try:
  fields=pathlib.Path(f"/proc/{pid}/stat").read_text(encoding="ascii").rsplit(")",1)[1].split()
  live=fields[0]!="Z" and int(fields[19])==ticks
 except FileNotFoundError: live=False
 except (OSError,ValueError,IndexError): emit("unknown","worker_identity_unavailable",identity=identity)
 emit("running" if live else "unknown",None if live else "missing_worker_receipt",identity=identity)
except FileNotFoundError: emit("unknown","missing_job_or_intent")
except (OSError,ValueError,TypeError,KeyError): emit("unknown","status_unavailable")'''


def start(root: Path | str, host: str, device: str, correlation_id: str, artifact_id: str,
          backup_correlation_id: str, expected_backup_sha256: str, expected_owner: str,
          expected_revision: int) -> dict[str, Any]:
    if host != "archlinux" or device != "api29" or not all(isinstance(v, str) and _UUID.fullmatch(v) for v in
        (correlation_id, backup_correlation_id, expected_owner)) or not isinstance(expected_backup_sha256, str) or not _SHA.fullmatch(expected_backup_sha256) or type(expected_revision) is not int or expected_revision < 0:
        raise ValueError("Android same-request fixture guards are invalid")
    config = ssh_transport.load_config(root)
    if host not in config.hosts or device not in config.hosts[host].android_devices or config.hosts[host].fixture_transfer_root is None or ssh_transport.connection_host(config, host).password is not None:
        raise ValueError("Android same-request fixture route is unavailable")
    profile = android_observation._profile(config.hosts[host].android_devices[device])
    if profile["api"] != 29:
        raise ValueError("Android same-request fixture requires API29")
    artifact = native_artifact_registry.verify_artifact(root, artifact_id)
    if artifact.get("verification") != "verified" or artifact.get("artifact", {}).get("platform") != "android" or artifact["artifact"].get("artifactKind") not in {"apk", "native-fixture-apk"}:
        raise ValueError("Android same-request APK is not verified")
    source_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if artifact["artifact"].get("sourceSha") != source_sha:
        raise ValueError("Android same-request APK is not current source")
    android_package_install._inspect_apk(root, Path(artifact["location"]["localPath"]))
    package_hash = artifact["artifact"]["sha256"]
    opening = android_admission_readback.async_collect(root, backup_correlation_id)
    observed = opening.get("result", {})
    if (opening.get("state") != "complete" or opening.get("ok") is not True or
            observed.get("package", {}).get("baseSha256") != package_hash or
            observed.get("backup", {}).get("sha256") != expected_backup_sha256 or
            observed.get("backup", {}).get("size") != 239 or
            observed.get("guard", {}).get("controllerId") != expected_owner or
            observed.get("guard", {}).get("configurationRevision") != expected_revision):
        raise ValueError("Android same-request opening readback is not admitted")
    live = android_admission_readback.readback_status(root, host, device, backup_correlation_id, timeout_seconds=30)
    if (not live.get("ok") or live.get("result", {}).get("stage") != "backup_present" or
            live["result"].get("controllerId") != expected_owner or
            live["result"].get("configurationRevision") != expected_revision or
            live["result"].get("backup", {}).get("sha256") != expected_backup_sha256):
        raise ValueError("Android same-request live opening backup changed")
    public = android_public_inspect.inspect(root, host, device, correlation_id, package_hash,
                                            expected_owner, expected_revision)
    if public.get("outcome") != "admitted" or public.get("result", {}).get("runtime", {}).get("running") is not False:
        raise ValueError("Android same-request owner/runtime is not admitted")
    remote_root = config.hosts[host].fixture_transfer_root
    intent = {"host": host, "device": device, "correlationId": correlation_id,
              "artifactId": artifact_id, "packageSha256": package_hash,
              "backupCorrelationId": backup_correlation_id, "backupSha256": expected_backup_sha256,
              "expectedOwner": expected_owner, "expectedRevision": expected_revision,
              "expectedAvd": profile["expectedAvd"], "api": 29, "fixtureRoot": str(remote_root)}
    backup_path = remote_root / ("android-readback-" + backup_correlation_id) / "routing.json"
    args = [profile["adb"], profile["serial"], profile["expectedAvd"], "29", str(remote_root),
            correlation_id, package_hash, expected_owner, str(expected_revision),
            str(backup_path), expected_backup_sha256]
    worker = android_document_acceptance._worker(_REMOTE, args)
    encoded = base64.urlsafe_b64encode(worker.encode()).decode("ascii")
    argv = ssh_transport.build_ssh_argv(config, host, 60, command=("python3", "-I", "-B", "-c",
        "exec(" + repr(_SUBMIT) + ")", str(remote_root), correlation_id,
        json.dumps(intent, sort_keys=True, separators=(",", ":")), encoded))
    android_document_acceptance._reserve(root, intent)
    try:
        code, output = android_observation._run_probe(argv, 60)
        value = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
        if isinstance(value, dict) and value.get("state") == "submitted" and value.get("correlationId") == correlation_id:
            return {"ok": True, "state": "submitted", "correlationId": correlation_id,
                    "identity": value.get("identity"), "replayAllowed": False}
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
        pass
    return {"ok": False, "state": "unknown", "correlationId": correlation_id, "replayAllowed": False}


def status(root: Path | str, correlation_id: str) -> dict[str, Any]:
    if not isinstance(correlation_id, str) or not _UUID.fullmatch(correlation_id):
        raise ValueError("Android same-request correlation must be a UUID")
    intent = android_document_acceptance._load(root, correlation_id)
    if intent is None or intent.get("device") != "api29":
        return {"ok": False, "state": "unknown", "reason": "missing_local_intent",
                "correlationId": correlation_id, "replayAllowed": False}
    config = ssh_transport.load_config(root)
    if intent["host"] not in config.hosts or ssh_transport.connection_host(config, intent["host"]).password is not None:
        return {"ok": False, "state": "unknown", "reason": "route_unavailable",
                "correlationId": correlation_id, "replayAllowed": False}
    remote_root = config.hosts[intent["host"]].fixture_transfer_root
    if str(remote_root) != intent.get("fixtureRoot"):
        return {"ok": False, "state": "unknown", "reason": "fixture_root_changed",
                "correlationId": correlation_id, "replayAllowed": False}
    argv = ssh_transport.build_ssh_argv(config, intent["host"], 30, command=("python3", "-I", "-B", "-c",
        "exec(" + repr(_STATUS) + ")", str(remote_root), correlation_id,
        json.dumps(intent, sort_keys=True, separators=(",", ":"))))
    try:
        code, output = android_observation._run_probe(argv, 30)
        value = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
        if isinstance(value, dict) and value.get("correlationId") == correlation_id and value.get("state") in {"running", "complete", "unknown"}:
            return {"ok": value["state"] in {"running", "complete"}, **value, "replayAllowed": False}
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
        pass
    return {"ok": False, "state": "unknown", "reason": "transport_or_receipt_unknown",
            "correlationId": correlation_id, "replayAllowed": False}


def collect(root: Path | str, correlation_id: str) -> dict[str, Any]:
    observed = status(root, correlation_id)
    if observed.get("state") != "complete":
        return observed
    intent = android_document_acceptance._load(root, correlation_id)
    receipt = observed.get("receipt")
    value = receipt.get("result") if isinstance(receipt, dict) else None
    if not isinstance(intent, dict) or not isinstance(value, dict) or value.get("state") != "complete":
        return {"ok": False, "state": "unknown", "reason": "terminal_binding_invalid",
                "correlationId": correlation_id, "replayAllowed": False}
    closing = value.get("restore", {})
    current_revision = closing.get("revision")
    if type(current_revision) is not int or current_revision <= intent["expectedRevision"]:
        return {"ok": False, "state": "unknown", "reason": "closing_revision_invalid",
                "correlationId": correlation_id, "replayAllowed": False}
    public = android_public_inspect.inspect(root, intent["host"], intent["device"], correlation_id,
        intent["packageSha256"], intent["expectedOwner"], current_revision)
    if public.get("outcome") != "admitted" or public.get("result", {}).get("runtime", {}).get("running") is not False:
        return {"ok": False, "state": "unknown", "reason": "closing_owner_unknown",
                "correlationId": correlation_id, "replayAllowed": False}
    released = android_document_acceptance._release_device(root, intent["host"], intent["device"], correlation_id)
    return {"ok": released, "state": "complete", "correlationId": correlation_id,
            "result": value, "identity": observed.get("identity"), "leaseReleased": released,
            "replayAllowed": False, "evidenceClass": "native-android-action"}

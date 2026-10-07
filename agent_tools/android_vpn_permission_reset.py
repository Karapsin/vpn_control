"""One-shot, API29-only reset of the disposable app's VPN-consent AppOp.

This is intentionally not an app permission grant.  It invokes exactly the
platform's revocation transition (ACTIVATE_VPN -> ignore) after a complete,
source-bound public-state admission.  A later ordinary interactive consent flow
is the only supported way to restore permission.
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
                   android_endpoint_admission, android_observation, android_package_install,
                   android_public_inspect, native_artifact_registry, ssh_transport)
except ImportError:  # pragma: no cover
    import android_admission_readback
    import android_cli_stage
    import android_document_acceptance
    import android_endpoint_admission
    import android_observation
    import android_package_install
    import android_public_inspect
    import native_artifact_registry
    import ssh_transport

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_PACKAGE = "com.kardinal.vpncontrol"
_HOST = "archlinux"
_DEVICE = "api29"
_API = 29
_USER = "0"
_OP = "ACTIVATE_VPN"
_MODE = "ignore"
_GROUP = ".rag_index/android-vpn-permission-reset"

_SUBMIT = android_admission_readback._ASYNC_SUBMIT.replace("android-readback-job-", "android-vpn-permission-reset-")


def _journal(root: Path | str, correlation: str) -> Path:
    if not isinstance(correlation, str) or not _UUID.fullmatch(correlation):
        raise ValueError("Android permission-reset correlation must be canonical UUID")
    return Path(root).resolve() / _GROUP / (correlation + ".json")


def _save(root: Path | str, intent: dict[str, Any]) -> None:
    path = _journal(root, intent["correlationId"])
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode) or parent.st_uid != os.getuid()
            or stat.S_IMODE(parent.st_mode) != 0o700):
        raise ValueError("Android permission-reset journal is unsafe")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(json.dumps(intent, sort_keys=True, separators=(",", ":")).encode() + b"\n")
            out.flush(); os.fsync(out.fileno())
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try: os.fsync(directory)
        finally: os.close(directory)
    except Exception:
        try: os.close(fd)
        except OSError: pass
        raise


def _load(root: Path | str, correlation: str) -> dict[str, Any] | None:
    try: path = _journal(root, correlation)
    except ValueError: return None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_nlink != 1 or not 0 < info.st_size <= 8192): return None
            raw = source.read(8193)
        if len(raw) != info.st_size: return None
        value = json.loads(raw)
        return value if isinstance(value, dict) and value.get("correlationId") == correlation else None
    except (OSError, UnicodeError, ValueError, TypeError):
        return None


def _endpoint_lease_active(root: Path | str) -> bool:
    """Fail closed while endpoint admission holds the same device lease."""
    path = Path(root).resolve() / ".rag_index/android-native-device-leases/lease-archlinux-api29.json"
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or not 0 < info.st_size <= 1024):
        return True
    # Any existing record, including malformed bytes, is an active or unknown
    # claim.  Reset never closes, overwrites, or bypasses it.
    return True


def _claim_reset_lease(root: Path | str, correlation: str) -> None:
    """Atomically claim the shared device lease after all read-only admission."""
    root_path = Path(root).resolve()
    with android_endpoint_admission._shared_device_lease(root_path, _HOST, _DEVICE) as lease:
        try:
            lease.lstat()
        except FileNotFoundError:
            fd = os.open(lease, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as out:
                out.write(json.dumps({"owner": "android-vpn-permission-reset", "correlationId": correlation,
                                      "device": _DEVICE, "host": _HOST}, sort_keys=True, separators=(",", ":")).encode() + b"\n")
                out.flush(); os.fsync(out.fileno())
            directory = os.open(lease.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try: os.fsync(directory)
            finally: os.close(directory)
            return
        raise ValueError("Android permission-reset device lease became active")


_REMOTE = (android_observation._canonical_cli_environment_source() + "\nCLI_STAGE_STATUS=" + repr(android_cli_stage._STATUS) + "\n" + r'''
import hashlib,json,os,pathlib,re,stat,subprocess,sys
adb,cli,serial,avd,root,correlation,package_sha,owner,revision,readback_correlation,backup_sha,stage_correlation,stage_manifest,stage_rpm,stage_launcher,stage_jar=sys.argv[1:]
def emit(state,reason=None,**extra):
 print(json.dumps({"state":state,"reason":reason,**extra},separators=(",",":"))); raise SystemExit(0)
def run(argv,timeout=60,limit=65536,env=None,allowed=(0,)):
 try: done=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout,env=env,check=False)
 except (OSError,subprocess.TimeoutExpired): emit("unknown","command_outcome_unknown")
 if done.returncode not in allowed or len(done.stdout)>limit: emit("unknown","command_failed")
 try: return done.stdout.decode("utf-8","strict").strip()
 except UnicodeError: emit("unknown","command_encoding")
def shell(*words,timeout=60,limit=65536,allowed=(0,)):
 return run([adb,"-s",serial,"shell","-T",*words],timeout,limit,None,allowed)
def phase(name):
 if name not in {"opening","opening_routing_exported","intent_durable","pre_effect_verified","appop_reset_submitted","closing_routing_exported","closing"}: emit("unknown","phase_invalid")
 tmp=job/"phase.tmp"; target=job/"phase.json"
 try:
  fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
  with os.fdopen(fd,"wb") as out: out.write(json.dumps({"phase":name},separators=(",",":" )).encode()+b"\n"); out.flush(); os.fsync(out.fileno())
  os.replace(tmp,target); d=os.open(job,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)); os.fsync(d); os.close(d)
 except OSError: emit("unknown","phase_journal_failed")
def public(*words,timeout=60,allowed=(0,)):
 raw=run([cli,"--json","--android","--serial",serial,"--timeout-seconds",str(timeout),*words],timeout+15,65536,env,allowed=allowed)
 try: value=json.loads(raw)
 except ValueError: emit("unknown","public_result_invalid")
 return value if isinstance(value,dict) else emit("unknown","public_result_invalid")
def status_and_ops(where):
 status=public("status",timeout=30); ops=public("operations","list",timeout=30)
 base=lambda v: v.get("ok") is True and v.get("final") is True and v.get("code")=="OK" and v.get("controllerId")==owner and v.get("configurationRevision")==int(revision)
 if not base(status) or not base(ops): emit("unknown",where+"_owner_or_revision_changed")
 data=status.get("data"); history=ops.get("data",{}).get("operations")
 if not isinstance(data,dict) or data.get("runtimeRunning") is not False or data.get("runtimeObservation")!="stopped": emit("unknown",where+"_runtime_not_off")
 if not isinstance(history,list) or any(not isinstance(x,dict) or x.get("controllerId")!=owner or x.get("final") is not True or x.get("phase") not in ("succeeded","failed","cancelled") for x in history): emit("unknown",where+"_operations_active_or_unknown")
def routing_hash(phase_name,filename,expected_backup=None):
 target=job/filename
 value=public("routing","export","--output",str(target),timeout=300)
 if value.get("ok") is not True or value.get("final") is not True or value.get("code")!="OK" or value.get("controllerId")!=owner or value.get("configurationRevision")!=int(revision): emit("unknown",phase_name+"_routing_export_failed")
 try:
  info=target.lstat()
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or not 0<info.st_size<=67108864: emit("unknown",phase_name+"_routing_export_unsafe")
  raw=target.read_bytes()
  if expected_backup is not None and hashlib.sha256(raw).hexdigest()!=expected_backup: emit("unknown",phase_name+"_backup_hash_changed")
  document=json.loads(raw); rules=document.get("rules") if isinstance(document,dict) else None
  if document.get("type")!="vpn_control_routing_rules" or document.get("version")!=7 or not isinstance(rules,dict): emit("unknown",phase_name+"_routing_export_invalid")
  return hashlib.sha256(json.dumps(rules,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()).hexdigest()
 except (OSError,UnicodeError,ValueError,TypeError): emit("unknown",phase_name+"_routing_export_invalid")
def diag(where,required):
 raw=run([cli,"--android","--serial",serial,"--timeout-seconds","90","diagnostics","export","--output","-"],105,1048576,env)
 fields={}; sections=0; active=False
 for line in raw.splitlines():
  if line=="[runtime]": sections+=1; active=True; continue
  if line.startswith("[") and line.endswith("]"): active=False; continue
  if active and "=" in line:
   k,v=line.split("=",1)
   if k in ("mode","vpn_permission_granted","is_vpn_running"):
    if k in fields: emit("unknown",where+"_diagnostics_ambiguous")
    fields[k]=v
 if sections!=1 or fields!=required: emit("unknown",where+"_diagnostics_changed")
def appop():
 raw=shell("cmd","appops","get","--user","0","com.kardinal.vpncontrol","ACTIVATE_VPN")
 lines=[x.strip() for x in raw.splitlines() if x.strip()]
 # Exact sole operation record.  We deliberately do not parse timestamps or
 # accept another UID/package/op record in a bounded census.
 if len(lines)!=1 or not re.fullmatch(r"ACTIVATE_VPN: (allow|ignore)",lines[0]): emit("unknown","appop_census_unknown")
 return lines[0].split(": ",1)[1]
if shell("id","-u")!="2000" or shell("getprop","ro.build.version.sdk")!="29" or {x for x in (shell("getprop","ro.kernel.qemu.avd_name"),shell("getprop","ro.boot.qemu.avd_name")) if x}!={avd} or shell("getprop","ro.product.cpu.abi")!="x86_64": emit("unknown","device_changed")
paths=[x[8:] for x in shell("pm","path","com.kardinal.vpncontrol").splitlines() if x.startswith("package:") and x.endswith("/base.apk")]
if len(paths)!=1 or not paths[0].startswith("/data/app/"): emit("unknown","package_path_changed")
pair=shell("sha256sum",paths[0]).split()
if pair!=[package_sha,paths[0]]: emit("unknown","package_changed")
env=public_cli_environment(adb,pathlib.Path(cli))
base=pathlib.Path(root); job=base/("android-vpn-permission-reset-"+correlation)
try:
 info=job.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: emit("unknown","job_unsafe")
except OSError: emit("unknown","job_missing")
phase("opening"); status_and_ops("opening"); diag("opening",{"mode":"VPN","vpn_permission_granted":"true","is_vpn_running":"false"})
phase("opening_routing_exported")
# The retained admission export anchors the semantic rules while omitting only generated metadata.
admitted=base/("android-readback-"+readback_correlation)/"routing.json"
try:
 info=admitted.lstat()
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or not 0<info.st_size<=67108864: emit("unknown","admitted_backup_unsafe")
 raw=admitted.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=backup_sha: emit("unknown","admitted_backup_hash_changed")
 document=json.loads(raw); admitted_rules=document.get("rules") if isinstance(document,dict) else None
 if document.get("type")!="vpn_control_routing_rules" or document.get("version")!=7 or not isinstance(admitted_rules,dict): emit("unknown","admitted_backup_invalid")
 admitted_routing=hashlib.sha256(json.dumps(admitted_rules,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()).hexdigest()
except (OSError,UnicodeError,ValueError,TypeError): emit("unknown","admitted_backup_invalid")
opening_routing=routing_hash("opening","opening-routing.json")
if opening_routing!=admitted_routing: emit("unknown","opening_routing_not_admitted")
if appop()!="allow": emit("unknown","opening_appop_not_allow")
# The submit wrapper has durably written intent.json before this worker starts;
# write a second local remote marker immediately before the single mutation.
phase("intent_durable")
try:
 fd=os.open(job/"mutation-intent.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
 with os.fdopen(fd,"wb") as out: out.write(b'{"user":"0","package":"com.kardinal.vpncontrol","op":"ACTIVATE_VPN","mode":"ignore"}\n'); out.flush(); os.fsync(out.fileno())
 d=os.open(job,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)); os.fsync(d); os.close(d)
except OSError: emit("unknown","mutation_intent_journal_failed")
# Bind the staged CLI tree again immediately before the sole AppOp effect.
def stage_current():
 try:
  raw=run(["python3","-I","-B","-c","exec("+repr(CLI_STAGE_STATUS)+")",root,stage_correlation,stage_manifest],60,65536)
  value=json.loads(raw)
 except (ValueError,TypeError): emit("unknown","pre_effect_cli_stage_invalid")
 receipt=value.get("receipt") if isinstance(value,dict) else None
 if not isinstance(value,dict) or value.get("state")!="published" or value.get("correlationId")!=stage_correlation or not isinstance(receipt,dict) or receipt.get("manifestSha256")!=stage_manifest or receipt.get("rpmSha256")!=stage_rpm or receipt.get("launcherSha256")!=stage_launcher or receipt.get("desktopJarSha256")!=stage_jar or receipt.get("cliPath")!=cli: emit("unknown","pre_effect_cli_stage_changed")
stage_current()
# Re-observe every mutable public/native predicate *after* intent fsync and immediately before effect.
phase("pre_effect_verified"); status_and_ops("pre_effect"); diag("pre_effect",{"mode":"VPN","vpn_permission_granted":"true","is_vpn_running":"false"})
if routing_hash("pre_effect","pre-effect-routing.json")!=admitted_routing or appop()!="allow": emit("unknown","pre_effect_admission_changed")
phase("appop_reset_submitted")
# Sole state-changing native action.  No --uid, default, reset, grant, or allow.
shell("cmd","appops","set","--user","0","com.kardinal.vpncontrol","ACTIVATE_VPN","ignore")
if appop()!="ignore": emit("unknown","closing_appop_not_ignore")
phase("closing"); status_and_ops("closing")
phase("closing_routing_exported")
if routing_hash("closing","closing-routing.json")!=admitted_routing: emit("unknown","closing_routing_changed")
diag("closing",{"mode":"VPN","vpn_permission_granted":"false","is_vpn_running":"false"})
if shell("sha256sum",paths[0]).split()!=[package_sha,paths[0]]: emit("unknown","closing_package_changed")
print(json.dumps({"state":"complete","api":29,"package":"com.kardinal.vpncontrol","appOp":"ACTIVATE_VPN","mode":"ignore","runtimeOff":True,"permissionAbsent":True,"owner":owner,"revision":int(revision)},separators=(",",":")))
''')

_STATUS = r'''
import json,os,pathlib,stat,sys
root,correlation,expected=sys.argv[1:]
def emit(state,reason=None,**extra): print(json.dumps({"state":state,"reason":reason,"correlationId":correlation,**extra},separators=(",",":"))); raise SystemExit(0)
job=pathlib.Path(root)/("android-vpn-permission-reset-"+correlation)
def private(name,limit=4096):
 try:
  fd=os.open(job/name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
  with os.fdopen(fd,"rb") as source:
   info=os.fstat(source.fileno())
   if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or not 0<info.st_size<=limit: emit("unknown","unsafe_remote_record")
   raw=source.read(limit+1)
  if len(raw)!=info.st_size: emit("unknown","remote_record_changed")
  return json.loads(raw)
 except FileNotFoundError: return None
 except (OSError,UnicodeError,ValueError,TypeError): emit("unknown","remote_record_unavailable")
try:
 info=job.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: emit("unknown","unsafe_job")
 intent=private("intent.json",8192)
 if intent!=json.loads(expected): emit("unknown","intent_mismatch")
 identity=private("identity.json",1024)
 if not isinstance(identity,dict) or type(identity.get("pid")) is not int or type(identity.get("startTicks")) is not int: emit("unknown","identity_invalid")
 receipt=private("result.json",8192)
 if receipt is None: emit("unknown","missing_worker_receipt",identity=identity)
 result=receipt.get("result") if isinstance(receipt,dict) else None
 needed={"state":"complete","api":29,"package":"com.kardinal.vpncontrol","appOp":"ACTIVATE_VPN","mode":"ignore","runtimeOff":True,"permissionAbsent":True,"owner":json.loads(expected)["expectedOwner"],"revision":json.loads(expected)["expectedRevision"]}
 if (receipt.get("state")!="complete" or result!=needed or type(result.get("api")) is not int or type(result.get("revision")) is not int or result.get("runtimeOff") is not True or result.get("permissionAbsent") is not True): emit("unknown","terminal_binding_invalid",identity=identity)
 emit("complete",identity=identity,receipt=receipt)
except SystemExit: raise
except (OSError,KeyError,TypeError,ValueError): emit("unknown","status_unavailable")
'''


def _public_preflight(root: Path | str, host: str, profile: dict[str, Any], cli: str,
                      owner: str, revision: int) -> bool:
    """Read-only owner/runtime/operation admission; failures are not reset attempts."""
    script = android_observation._canonical_cli_environment_source() + r'''
import json,pathlib,subprocess,sys
adb,cli,serial,owner,revision=sys.argv[1:]
try:
 env=public_cli_environment(adb,pathlib.Path(cli))
 def call(*words):
  done=subprocess.run([cli,"--json","--android","--serial",serial,"--timeout-seconds","30",*words],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=45,env=env,check=False)
  return json.loads(done.stdout) if done.returncode==0 and len(done.stdout)<=65536 else None
 status=call("status"); ops=call("operations","list")
 valid=lambda v:isinstance(v,dict) and v.get("ok") is True and v.get("final") is True and v.get("code")=="OK" and v.get("controllerId")==owner and v.get("configurationRevision")==int(revision)
 history=ops.get("data",{}).get("operations") if isinstance(ops,dict) else None
 ready=valid(status) and valid(ops) and isinstance(status.get("data"),dict) and status["data"].get("runtimeRunning") is False and status["data"].get("runtimeObservation")=="stopped" and isinstance(history,list) and all(isinstance(x,dict) and x.get("controllerId")==owner and x.get("final") is True and x.get("phase") in ("succeeded","failed","cancelled") for x in history)
except (OSError,ValueError,TypeError,UnicodeError,RuntimeError,subprocess.TimeoutExpired): ready=False
print(json.dumps({"ready":ready},separators=(",",":")))'''
    config = ssh_transport.load_config(root)
    argv = ssh_transport.build_ssh_argv(config, host, 60, command=("python3", "-I", "-B", "-c", "exec(" + repr(script) + ")", profile["adb"], cli, profile["serial"], owner, str(revision)))
    try:
        code, output = android_observation._run_probe(argv, 60)
        return code == 0 and json.loads(output.decode("utf-8", "strict")) == {"ready": True}
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
        return False


def start(root: Path | str, correlation_id: str, artifact_id: str, cli_stage_correlation_id: str,
          opening_readback_correlation_id: str, expected_backup_sha256: str,
          expected_owner: str, expected_revision: int) -> dict[str, Any]:
    """Submit the one-shot reset.  Every input is an existing bounded receipt ID."""
    if (not all(isinstance(v, str) and _UUID.fullmatch(v) for v in (correlation_id, cli_stage_correlation_id,
            opening_readback_correlation_id, expected_owner)) or not isinstance(artifact_id, str)
            or not isinstance(expected_backup_sha256, str) or not _SHA.fullmatch(expected_backup_sha256)
            or type(expected_revision) is not int or expected_revision < 0):
        raise ValueError("Android permission-reset inputs are invalid")
    root_path = Path(root)
    if _load(root_path, correlation_id) is not None:
        return {"ok": False, "state": "unknown", "reason": "existing_intent_no_replay", "correlationId": correlation_id, "replayAllowed": False}
    if _endpoint_lease_active(root_path):
        return {"ok": False, "state": "blocked", "reason": "endpoint_lease_active", "correlationId": correlation_id, "replayAllowed": False}
    config = ssh_transport.load_config(root_path)
    if (_HOST not in config.hosts or _DEVICE not in config.hosts[_HOST].android_devices or
            config.hosts[_HOST].fixture_transfer_root is None or ssh_transport.connection_host(config, _HOST).password is not None):
        raise ValueError("Android permission-reset route is unavailable")
    profile = android_observation._profile(config.hosts[_HOST].android_devices[_DEVICE])
    if profile.get("api") != _API:
        raise ValueError("Android permission-reset requires API29")
    artifact = native_artifact_registry.verify_artifact(root_path, artifact_id)
    source_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root_path, capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if (artifact.get("verification") != "verified" or artifact.get("artifact", {}).get("platform") != "android" or
            artifact["artifact"].get("artifactKind") not in {"apk", "native-fixture-apk"} or artifact["artifact"].get("sourceSha") != source_sha):
        raise ValueError("Android permission-reset APK is not exact source")
    android_package_install._inspect_apk(root_path, Path(artifact["location"]["localPath"]))
    package_sha = artifact["artifact"]["sha256"]
    stage = android_cli_stage.status(root_path, cli_stage_correlation_id)
    cli = stage.get("receipt", {}).get("cliPath")
    remote_root = config.hosts[_HOST].fixture_transfer_root
    if (stage.get("state") != "published" or not stage.get("ok") or stage.get("sourceSha") != source_sha or
            not isinstance(cli, str) or not cli.startswith(str(remote_root) + "/android-cli-stage-" + cli_stage_correlation_id + "/tree/")):
        raise ValueError("Android permission-reset CLI stage is not source-bound")
    opening = android_admission_readback.async_collect(root_path, opening_readback_correlation_id)
    observed = opening.get("result", {})
    if (opening.get("state") != "complete" or opening.get("ok") is not True or
            observed.get("package", {}).get("baseSha256") != package_sha or observed.get("backup", {}).get("sha256") != expected_backup_sha256 or
            observed.get("backup", {}).get("rulesValid") is not True or observed.get("guard", {}).get("controllerId") != expected_owner or observed.get("guard", {}).get("configurationRevision") != expected_revision or
            observed.get("device", {}).get("api") != _API):
        raise ValueError("Android permission-reset opening readback is not admitted")
    live = android_admission_readback.readback_status(root_path, _HOST, _DEVICE, opening_readback_correlation_id, timeout_seconds=30)
    if (not live.get("ok") or live.get("result", {}).get("stage") != "backup_present" or
            live["result"].get("controllerId") != expected_owner or live["result"].get("configurationRevision") != expected_revision or
            live["result"].get("backup", {}).get("sha256") != expected_backup_sha256 or
            live["result"].get("backup", {}).get("rulesValid") is not True):
        raise ValueError("Android permission-reset full routing readback changed")
    if not _public_preflight(root_path, _HOST, profile, cli, expected_owner, expected_revision):
        raise ValueError("Android permission-reset public owner/runtime/operations admission failed")
    public = android_public_inspect.inspect(root_path, _HOST, _DEVICE, correlation_id, package_sha, expected_owner, expected_revision)
    if public.get("outcome") != "admitted" or public.get("result", {}).get("runtime", {}).get("running") is not False:
        raise ValueError("Android permission-reset public state is not admitted")
    intent = {"schema": 1, "host": _HOST, "device": _DEVICE, "correlationId": correlation_id, "api": _API,
              "package": _PACKAGE, "appOp": _OP, "mode": _MODE, "artifactId": artifact_id, "packageSha256": package_sha,
              "cliStageCorrelationId": cli_stage_correlation_id, "cliPath": cli, "cliManifestSha256": stage["receipt"]["manifestSha256"], "cliRpmSha256": stage["receipt"]["rpmSha256"], "cliLauncherSha256": stage["receipt"]["launcherSha256"], "cliDesktopJarSha256": stage["receipt"]["desktopJarSha256"], "openingReadbackCorrelationId": opening_readback_correlation_id,
              "backupSha256": expected_backup_sha256, "expectedOwner": expected_owner, "expectedRevision": expected_revision,
              "expectedAvd": profile["expectedAvd"], "fixtureRoot": str(remote_root), "sourceSha": source_sha}
    args = [profile["adb"], cli, profile["serial"], profile["expectedAvd"], str(remote_root), correlation_id, package_sha, expected_owner, str(expected_revision), opening_readback_correlation_id, expected_backup_sha256, cli_stage_correlation_id, stage["receipt"]["manifestSha256"], stage["receipt"]["rpmSha256"], stage["receipt"]["launcherSha256"], stage["receipt"]["desktopJarSha256"]]
    worker = android_document_acceptance._worker(_REMOTE, args)
    encoded = base64.urlsafe_b64encode(worker.encode()).decode("ascii")
    argv = ssh_transport.build_ssh_argv(config, _HOST, 60, command=("python3", "-I", "-B", "-c", "exec(" + repr(_SUBMIT) + ")", str(remote_root), correlation_id, json.dumps(intent, sort_keys=True, separators=(",", ":")), encoded))
    # Recheck the complete staged CLI receipt immediately before durable intent/effect.
    current_stage = android_cli_stage.status(root_path, cli_stage_correlation_id)
    if (current_stage.get("state") != "published" or not current_stage.get("ok") or current_stage.get("sourceSha") != source_sha or
            current_stage.get("receipt", {}).get("cliPath") != cli or current_stage.get("receipt", {}).get("manifestSha256") != stage.get("receipt", {}).get("manifestSha256") or
            current_stage.get("receipt", {}).get("desktopJarSha256") != stage.get("receipt", {}).get("desktopJarSha256") or current_stage.get("receipt", {}).get("rpmSha256") != stage.get("receipt", {}).get("rpmSha256") or current_stage.get("receipt", {}).get("launcherSha256") != stage.get("receipt", {}).get("launcherSha256")):
        raise ValueError("Android permission-reset CLI stage changed before effect")
    _save(root_path, intent)  # durable local intent precedes the one async native job
    # The claim is deliberately never removed by status or submit failure.
    # Unknown native outcome retains it for a later explicit review/collection.
    _claim_reset_lease(root_path, correlation_id)
    try:
        code, output = android_observation._run_probe(argv, 60)
        value = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
        if isinstance(value, dict) and value.get("state") == "submitted" and value.get("correlationId") == correlation_id:
            return {"ok": True, "state": "submitted", "correlationId": correlation_id, "identity": value.get("identity"), "replayAllowed": False}
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
        pass
    return {"ok": False, "state": "unknown", "reason": "submit_unknown", "correlationId": correlation_id, "replayAllowed": False}


def status(root: Path | str, correlation_id: str) -> dict[str, Any]:
    intent = _load(root, correlation_id)
    if intent is None:
        return {"ok": False, "state": "unknown", "reason": "missing_local_intent", "correlationId": correlation_id, "replayAllowed": False}
    if intent.get("host") != _HOST or intent.get("device") != _DEVICE or intent.get("api") != _API:
        return {"ok": False, "state": "unknown", "reason": "intent_invalid", "correlationId": correlation_id, "replayAllowed": False}
    config = ssh_transport.load_config(root)
    if _HOST not in config.hosts or ssh_transport.connection_host(config, _HOST).password is not None or str(config.hosts[_HOST].fixture_transfer_root) != intent.get("fixtureRoot"):
        return {"ok": False, "state": "unknown", "reason": "route_unavailable", "correlationId": correlation_id, "replayAllowed": False}
    argv = ssh_transport.build_ssh_argv(config, _HOST, 30, command=("python3", "-I", "-B", "-c", "exec(" + repr(_STATUS) + ")", str(config.hosts[_HOST].fixture_transfer_root), correlation_id, json.dumps(intent, sort_keys=True, separators=(",", ":"))))
    try:
        code, output = android_observation._run_probe(argv, 30)
        value = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
        if isinstance(value, dict) and value.get("correlationId") == correlation_id and value.get("state") in {"complete", "unknown"}:
            return {"ok": value["state"] == "complete", **value, "replayAllowed": False}
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
        pass
    return {"ok": False, "state": "unknown", "reason": "transport_or_receipt_unknown", "correlationId": correlation_id, "replayAllowed": False}

# Fresh post-terminal proof for collection. It has no `appops set` or product action.
_COLLECT = android_observation._canonical_cli_environment_source() + r'''
import hashlib,json,os,pathlib,stat,subprocess,sys
adb,cli,serial,avd,root,correlation,package_sha,owner,revision,readback_correlation,backup_sha=sys.argv[1:]
def fail(reason): print(json.dumps({"state":"unknown","reason":reason},separators=(",",":"))); raise SystemExit(0)
def run(argv,timeout=60,limit=1048576,env=None):
 try: done=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout,env=env,check=False)
 except (OSError,subprocess.TimeoutExpired): fail("collect_command_unknown")
 if done.returncode or len(done.stdout)>limit: fail("collect_command_failed")
 try: return done.stdout.decode("utf-8","strict").strip()
 except UnicodeError: fail("collect_encoding")
def shell(*words): return run([adb,"-s",serial,"shell","-T",*words])
if shell("id","-u")!="2000" or shell("getprop","ro.build.version.sdk")!="29" or {x for x in (shell("getprop","ro.kernel.qemu.avd_name"),shell("getprop","ro.boot.qemu.avd_name")) if x}!={avd} or shell("getprop","ro.product.cpu.abi")!="x86_64": fail("collect_device_changed")
env=public_cli_environment(adb,pathlib.Path(cli))
def public(*words,timeout=60):
 try: value=json.loads(run([cli,"--json","--android","--serial",serial,"--timeout-seconds",str(timeout),*words],timeout+15,65536,env))
 except ValueError: fail("collect_public_invalid")
 return value if isinstance(value,dict) else fail("collect_public_invalid")
def fixed(value): return value.get("ok") is True and value.get("final") is True and value.get("code")=="OK" and value.get("controllerId")==owner and value.get("configurationRevision")==int(revision)
def private_bytes(path,limit=67108864):
 try:
  info=path.lstat()
  if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or not 0<info.st_size<=limit: fail("collect_private_file_unsafe")
  fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
  try:
   before=os.fstat(fd); raw=os.read(fd,limit+1); after=os.fstat(fd)
  finally: os.close(fd)
  if len(raw)!=before.st_size or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns) or (info.st_dev,info.st_ino)!=(before.st_dev,before.st_ino): fail("collect_private_file_changed")
  return raw
 except OSError: fail("collect_private_file_unavailable")
status=public("status",timeout=30); ops=public("operations","list",timeout=30)
if not fixed(status) or not fixed(ops) or status.get("data",{}).get("runtimeRunning") is not False or status.get("data",{}).get("runtimeObservation")!="stopped": fail("collect_owner_or_runtime_changed")
history=ops.get("data",{}).get("operations")
if not isinstance(history,list) or any(not isinstance(x,dict) or x.get("controllerId")!=owner or x.get("final") is not True or x.get("phase") not in ("succeeded","failed","cancelled") for x in history): fail("collect_operations_active_or_unknown")
raw=run([cli,"--android","--serial",serial,"--timeout-seconds","90","diagnostics","export","--output","-"],105,1048576,env)
if "[runtime]" not in raw or raw.count("vpn_permission_granted=false")!=1 or raw.count("is_vpn_running=false")!=1 or raw.count("mode=VPN")!=1: fail("collect_permission_or_runtime_changed")
if shell("cmd","appops","get","--user","0","com.kardinal.vpncontrol","ACTIVATE_VPN")!="ACTIVATE_VPN: ignore": fail("collect_appop_changed")
paths=[x[8:] for x in shell("pm","path","com.kardinal.vpncontrol").splitlines() if x.startswith("package:") and x.endswith("/base.apk")]
if len(paths)!=1 or shell("sha256sum",paths[0]).split()!=[package_sha,paths[0]]: fail("collect_package_changed")
job=pathlib.Path(root)/("android-vpn-permission-reset-"+correlation); target=job/"collect-routing.json"
value=public("routing","export","--output",str(target),timeout=300)
if not fixed(value): fail("collect_routing_export_failed")
try:
 raw=private_bytes(target); doc=json.loads(raw); rules=doc.get("rules") if isinstance(doc,dict) else None
 if doc.get("type")!="vpn_control_routing_rules" or doc.get("version")!=7 or not isinstance(rules,dict): fail("collect_routing_invalid")
 admitted=private_bytes(pathlib.Path(root)/("android-readback-"+readback_correlation)/"routing.json")
 if hashlib.sha256(admitted).hexdigest()!=backup_sha: fail("collect_admitted_backup_changed")
 source=json.loads(admitted); source_rules=source.get("rules") if isinstance(source,dict) else None
 if not isinstance(source_rules,dict) or json.dumps(rules,sort_keys=True,separators=(",",":"))!=json.dumps(source_rules,sort_keys=True,separators=(",",":")): fail("collect_routing_changed")
except (OSError,UnicodeError,ValueError,TypeError): fail("collect_routing_invalid")
print(json.dumps({"state":"complete"},separators=(",",":")))
'''


def _release_reset_lease(root: Path | str, correlation: str) -> bool:
    """Remove only this exact terminal owner's shared lease."""
    root_path = Path(root).resolve()
    expected = {"owner": "android-vpn-permission-reset", "correlationId": correlation, "device": _DEVICE, "host": _HOST}
    try:
        with android_endpoint_admission._shared_device_lease(root_path, _HOST, _DEVICE) as lease:
            fd = os.open(lease, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                info = os.fstat(fd); raw = os.read(fd, 2048)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or
                        info.st_nlink != 1 or len(raw) != info.st_size or json.loads(raw) != expected): return False
                after = os.fstat(fd)
                now = lease.lstat()
                fingerprint = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
                if ((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != fingerprint or
                        (now.st_dev, now.st_ino, now.st_size, now.st_mtime_ns) != fingerprint or
                        not stat.S_ISREG(now.st_mode) or now.st_uid != os.getuid() or stat.S_IMODE(now.st_mode) != 0o600 or now.st_nlink != 1): return False
                lease.unlink(); directory = os.open(lease.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try: os.fsync(directory)
                finally: os.close(directory)
                return True
            finally: os.close(fd)
    except (OSError, UnicodeError, ValueError, TypeError): return False


def collect(root: Path | str, correlation_id: str) -> dict[str, Any]:
    """Freshly prove postconditions, then release only the exact reset lease."""
    observed = status(root, correlation_id)
    if observed.get("state") != "complete": return observed
    intent = _load(root, correlation_id)
    if not isinstance(intent, dict):
        return {"ok": False, "state": "unknown", "reason": "missing_local_intent", "correlationId": correlation_id, "replayAllowed": False}
    config = ssh_transport.load_config(root)
    stage = android_cli_stage.status(root, intent["cliStageCorrelationId"])
    if (stage.get("state") != "published" or not stage.get("ok") or stage.get("sourceSha") != intent.get("sourceSha") or stage.get("receipt", {}).get("cliPath") != intent.get("cliPath") or stage.get("receipt", {}).get("manifestSha256") != intent.get("cliManifestSha256") or stage.get("receipt", {}).get("rpmSha256") != intent.get("cliRpmSha256") or stage.get("receipt", {}).get("launcherSha256") != intent.get("cliLauncherSha256") or stage.get("receipt", {}).get("desktopJarSha256") != intent.get("cliDesktopJarSha256")):
        return {"ok": False, "state": "unknown", "reason": "cli_stage_changed", "correlationId": correlation_id, "replayAllowed": False}
    profile = android_observation._profile(config.hosts[_HOST].android_devices[_DEVICE])
    argv = ssh_transport.build_ssh_argv(config, _HOST, 360, command=("python3", "-I", "-B", "-c", "exec(" + repr(_COLLECT) + ")", profile["adb"], intent["cliPath"], profile["serial"], intent["expectedAvd"], str(config.hosts[_HOST].fixture_transfer_root), correlation_id, intent["packageSha256"], intent["expectedOwner"], str(intent["expectedRevision"]), intent["openingReadbackCorrelationId"], intent["backupSha256"]))
    try:
        code, output = android_observation._run_probe(argv, 360)
        value = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError): value = None
    if value != {"state": "complete"}:
        return {"ok": False, "state": "unknown", "reason": "fresh_postcondition_unknown", "correlationId": correlation_id, "replayAllowed": False}
    if not _release_reset_lease(root, correlation_id):
        return {"ok": False, "state": "unknown", "reason": "lease_release_unconfirmed", "correlationId": correlation_id, "replayAllowed": False}
    return {"ok": True, "state": "complete", "correlationId": correlation_id, "leaseReleased": True, "replayAllowed": False}

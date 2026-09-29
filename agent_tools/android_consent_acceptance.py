"""Guarded public Android VPN consent denial on a disposable owned emulator."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import re
import subprocess
from typing import Any
import xml.etree.ElementTree as ET

try:
    from . import (android_admission_readback, android_cli_stage, android_document_acceptance,
                   android_observation, android_package_install, android_public_inspect,
                   native_artifact_registry, ssh_transport)
except ImportError:
    import android_admission_readback
    import android_cli_stage
    import android_document_acceptance
    import android_observation
    import android_package_install
    import android_public_inspect
    import native_artifact_registry
    import ssh_transport


_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_SHA = re.compile(r"[0-9a-f]{64}")
_BOUNDS = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")


def _diagnostic_consent_state(raw: str) -> bool:
    """Admit only an unambiguous VPN runtime block with absent permission."""
    if not isinstance(raw, str) or len(raw) > 1_048_576:
        return False
    sections: list[list[str]] = []
    in_runtime = False
    for line in raw.splitlines():
        if line == "[runtime]":
            sections.append([])
            in_runtime = True
        elif line.startswith("[") and line.endswith("]"):
            in_runtime = False
        elif in_runtime:
            sections[-1].append(line)
    if len(sections) != 1:
        return False
    required = {"mode": "VPN", "vpn_permission_granted": "false", "is_vpn_running": "false"}
    for key, value in required.items():
        matches = [line for line in sections[0] if line.startswith(key + "=")]
        if matches != [key + "=" + value]:
            return False
    return True


def _cancel_button(xml: str) -> tuple[int, int] | None:
    """Find the Cancel control in exactly one system VPN permission dialog."""
    if not isinstance(xml, str) or len(xml) > 1_048_576:
        return None
    try:
        tree = ET.fromstring(xml)
    except ET.ParseError:
        return None
    if tree.tag != "hierarchy":
        return None
    nodes = list(tree.iter("node"))
    roots = [node for node in nodes if node.attrib.get("package") == "com.android.vpndialogs"]
    if not roots or any(node.attrib.get("package") not in {"com.android.vpndialogs", None} for node in nodes):
        return None
    titles = [node for node in nodes if node.attrib.get("resource-id") == "android:id/alertTitle" and
              node.attrib.get("package") == "com.android.vpndialogs" and
              node.attrib.get("text") == "Connection request"]
    warnings = [node for node in nodes if node.attrib.get("resource-id") == "com.android.vpndialogs:id/warning" and
                node.attrib.get("package") == "com.android.vpndialogs"]
    buttons = [node for node in nodes if node.attrib.get("resource-id") == "android:id/button2" and
               node.attrib.get("package") == "com.android.vpndialogs" and
               node.attrib.get("text") == "Cancel" and node.attrib.get("enabled") == "true"]
    if (len(titles) != 1 or len(warnings) != 1 or len(buttons) != 1 or
            not warnings[0].attrib.get("text", "").startswith(
                "VPN Control wants to set up a VPN connection that allows it to monitor network traffic.")):
        return None
    bounds = _BOUNDS.fullmatch(buttons[0].attrib.get("bounds", ""))
    if bounds is None:
        return None
    left, top, right, bottom = map(int, bounds.groups())
    if not (0 <= left < right <= 4096 and 0 <= top < bottom <= 4096):
        return None
    return ((left + right) // 2, (top + bottom) // 2)


_CLI_ENV = android_observation._canonical_cli_environment_source()
_REMOTE = _CLI_ENV + r'''import hashlib,json,os,pathlib,re,stat,subprocess,sys,time,uuid,xml.etree.ElementTree as ET
adb,cli,serial,avd,api,root,correlation,package_hash,owner,revision=sys.argv[1:]
def fail(reason):
 print(json.dumps({"state":"unknown","reason":reason},separators=(",",":"))); raise SystemExit(0)
try: environment=public_cli_environment(adb,pathlib.Path(cli))
except (OSError,ValueError,RuntimeError): fail("cli_environment_unknown")
def invoke(args,timeout=60,limit=65536,allowed=(0,)):
 try: done=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout,env=environment,check=False)
 except (OSError,subprocess.TimeoutExpired): fail("command_outcome_unknown")
 if done.returncode not in allowed or len(done.stdout)>limit: fail("command_failed")
 try: return done.stdout.decode("utf-8","strict").strip()
 except UnicodeError: fail("command_encoding")
def shell(*words,timeout=60,limit=65536,allowed=(0,)):
 return invoke([adb,"-s",serial,"shell","-T",*words],timeout,limit,allowed)
def mark(phase):
 if phase not in {"opening_diagnostics","opening_status","noninteractive_on_submitted","noninteractive_diagnostics","noninteractive_status","noninteractive_prompt_checked","interactive_on_submitted","prompt_observed","cancel_submitted","operation_wait_submitted","closing_diagnostics","closing_status"}: fail("phase_invalid")
 temporary=job/"phase.json.tmp"; final=job/"phase.json"
 payload=json.dumps({"phase":phase},separators=(",",":")).encode()+b"\n"
 try:
  fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
  with os.fdopen(fd,"wb") as output: output.write(payload); output.flush(); os.fsync(output.fileno())
  os.replace(temporary,final)
  directory=os.open(job,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0)); os.fsync(directory); os.close(directory)
 except OSError: fail("phase_journal_failed")
def cli_json(phase,*words,timeout=120,allowed=(0,)):
 mark(phase)
 raw=invoke([cli,"--json","--android","--serial",serial,"--timeout-seconds",str(timeout),*words],timeout+15,16384,allowed)
 try: value=json.loads(raw)
 except ValueError: fail("public_result_invalid")
 if not isinstance(value,dict): fail("public_result_invalid")
 return value
def diagnostics(phase):
 mark(phase)
 raw=invoke([cli,"--android","--serial",serial,"--timeout-seconds","90","diagnostics","export","--output","-"],105,1048576)
 lines=raw.splitlines(); in_runtime=False; fields={}; sections=0
 for line in lines:
  if line=="[runtime]":
   sections+=1; in_runtime=True; continue
  if line.startswith("[") and line.endswith("]"):
   in_runtime=False; continue
  if in_runtime and "=" in line:
   key,value=line.split("=",1)
   if key in ("mode","vpn_permission_granted","is_vpn_running"):
    if key in fields: fail("diagnostic_ambiguous")
    fields[key]=value
 if sections!=1 or fields!={"mode":"VPN","vpn_permission_granted":"false","is_vpn_running":"false"}: fail("consent_not_absent")
if shell("id","-u")!="2000" or shell("getprop","ro.build.version.sdk")!=api or {v for v in (shell("getprop","ro.kernel.qemu.avd_name"),shell("getprop","ro.boot.qemu.avd_name")) if v}!={avd} or shell("getprop","ro.product.cpu.abi")!="x86_64": fail("device_changed")
paths=[p.removeprefix("package:") for p in shell("pm","path","com.kardinal.vpncontrol").splitlines() if p.startswith("package:") and p.endswith("/base.apk")]
if len(paths)!=1 or not paths[0].startswith("/data/app/"): fail("package_path_changed")
pair=shell("sha256sum",paths[0]).split()
if len(pair)!=2 or pair[0]!=package_hash or pair[1]!=paths[0]: fail("package_changed")
job=pathlib.Path(root)/("android-document-job-"+correlation)
try: rinfo=pathlib.Path(root).lstat(); jinfo=job.lstat()
except OSError: fail("job_missing")
if not stat.S_ISDIR(rinfo.st_mode) or rinfo.st_uid!=os.getuid() or stat.S_IMODE(rinfo.st_mode)!=0o700 or not stat.S_ISDIR(jinfo.st_mode) or jinfo.st_uid!=os.getuid() or stat.S_IMODE(jinfo.st_mode)!=0o700: fail("job_unsafe")
diagnostics("opening_diagnostics")
opening=cli_json("opening_status","status",timeout=30)
if opening.get("ok") is not True or opening.get("final") is not True or opening.get("code")!="OK" or opening.get("controllerId")!=owner or opening.get("configurationRevision")!=int(revision) or opening.get("data",{}).get("runtimeRunning") is not False or opening.get("data",{}).get("runtimeObservation")!="stopped": fail("opening_owner_changed")
headless=cli_json("noninteractive_on_submitted","on",timeout=30,allowed=(1,))
if headless.get("ok") is not False or headless.get("final") is not True or headless.get("code")!="INTERACTION_REQUIRED" or headless.get("controllerId")!=owner or headless.get("configurationRevision")!=int(revision): fail("noninteractive_rejection_unknown")
diagnostics("noninteractive_diagnostics")
unchanged=cli_json("noninteractive_status","status",timeout=30)
if unchanged.get("ok") is not True or unchanged.get("final") is not True or unchanged.get("code")!="OK" or unchanged.get("controllerId")!=owner or unchanged.get("configurationRevision")!=int(revision) or unchanged.get("data",{}).get("runtimeRunning") is not False or unchanged.get("data",{}).get("runtimeObservation")!="stopped": fail("noninteractive_state_changed")
headless_ui="/sdcard/android-consent-headless-"+correlation+".xml"
mark("noninteractive_prompt_checked")
shell("uiautomator","dump",headless_ui,timeout=45)
headless_xml=shell("cat",headless_ui,timeout=30,limit=1048576)
shell("rm",headless_ui,timeout=15)
try: headless_tree=ET.fromstring(headless_xml)
except ET.ParseError: fail("noninteractive_ui_unknown")
if headless_tree.tag!="hierarchy" or any(x.attrib.get("package")=="com.android.vpndialogs" for x in headless_tree.iter("node")): fail("noninteractive_prompt_visible")
accepted=cli_json("interactive_on_submitted","--interactive","--async","on",timeout=120)
operation_id=accepted.get("operationId")
if accepted.get("ok") is not True or accepted.get("code")!="ACCEPTED" or accepted.get("final") is not False or accepted.get("controllerId")!=owner or not isinstance(operation_id,str) or re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",operation_id) is None: fail("on_not_accepted")
try:
 fd=os.open(job/"operation.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
 with os.fdopen(fd,"wb") as output:
  output.write(json.dumps({"operationId":operation_id,"controllerId":owner},separators=(",",":")).encode()+b"\n")
  output.flush(); os.fsync(output.fileno())
 directory=os.open(job,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0)); os.fsync(directory); os.close(directory)
except OSError: fail("operation_journal_failed")
ui_path="/sdcard/android-consent-"+correlation+".xml"
mark("prompt_observed")
shell("uiautomator","dump",ui_path,timeout=45)
xml=shell("cat",ui_path,timeout=30,limit=1048576)
shell("rm",ui_path,timeout=15)
try: tree=ET.fromstring(xml)
except ET.ParseError: fail("prompt_invalid")
nodes=list(tree.iter("node"))
titles=[x for x in nodes if x.attrib.get("package")=="com.android.vpndialogs" and x.attrib.get("resource-id")=="android:id/alertTitle" and x.attrib.get("text")=="Connection request"]
warnings=[x for x in nodes if x.attrib.get("package")=="com.android.vpndialogs" and x.attrib.get("resource-id")=="com.android.vpndialogs:id/warning"]
buttons=[x for x in nodes if x.attrib.get("package")=="com.android.vpndialogs" and x.attrib.get("resource-id")=="android:id/button2" and x.attrib.get("text")=="Cancel" and x.attrib.get("enabled")=="true"]
if tree.tag!="hierarchy" or len(titles)!=1 or len(warnings)!=1 or len(buttons)!=1 or not warnings[0].attrib.get("text","").startswith("VPN Control wants to set up a VPN connection that allows it to monitor network traffic.") or any(x.attrib.get("package") not in ("com.android.vpndialogs",None) for x in nodes): fail("prompt_not_owned")
bounds=re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]",buttons[0].attrib.get("bounds",""))
if bounds is None: fail("cancel_bounds_unknown")
left,top,right,bottom=map(int,bounds.groups())
if not (0<=left<right<=4096 and 0<=top<bottom<=4096): fail("cancel_bounds_invalid")
mark("cancel_submitted")
shell("input","tap",str((left+right)//2),str((top+bottom)//2),timeout=30)
waited=cli_json("operation_wait_submitted","--controller-id",owner,"operations","wait",operation_id,timeout=120,allowed=(1,))
if waited.get("controllerId")!=owner or waited.get("operationId")!=operation_id or waited.get("code")!="PERMISSION_DENIED" or waited.get("ok") is not False or waited.get("final") is not True: fail("denial_result_unknown")
diagnostics("closing_diagnostics")
closed=cli_json("closing_status","status",timeout=30)
if closed.get("ok") is not True or closed.get("final") is not True or closed.get("code")!="OK" or closed.get("controllerId")!=owner or closed.get("configurationRevision")!=int(revision) or closed.get("data",{}).get("runtimeRunning") is not False or closed.get("data",{}).get("runtimeObservation")!="stopped": fail("closing_runtime_unknown")
if shell("sha256sum",paths[0]).split()!=[package_hash,paths[0]]: fail("closing_package_changed")
print(json.dumps({"state":"complete","sourcePackageSha256":package_hash,"device":{"uid":"2000","api":int(api),"avd":avd},"opening":{"owner":owner,"revision":int(revision)},"operationId":operation_id,"noninteractiveRejected":True,"consentDenied":True,"runtimeOff":True,"permissionStillAbsent":True},separators=(",",":")))
'''

_PREFLIGHT = _CLI_ENV + r'''import json,subprocess,sys
adb,cli,serial=sys.argv[1:]
code="diagnostics_unavailable"
try:
 environment=public_cli_environment(adb,Path(cli))
 done=subprocess.run([cli,"--android","--serial",serial,"--timeout-seconds","45","diagnostics","export","--output","-"],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=55,env=environment,check=False)
 raw=done.stdout.decode("utf-8","strict") if done.returncode==0 and len(done.stdout)<=1048576 else ""
 fields={}; runtime=False; sections=0
 for line in raw.splitlines():
  if line=="[runtime]": sections+=1; runtime=True; continue
  if runtime and line.startswith("[") and line.endswith("]"): runtime=False
  if runtime and "=" in line:
   key,value=line.split("=",1)
   if key in ("mode","vpn_permission_granted","is_vpn_running"):
    if key in fields: fields[key]="duplicate"
    else: fields[key]=value
 if sections!=1 or "duplicate" in fields.values(): code="ambiguous_runtime"
 elif fields.get("mode")=="PROXY_ONLY": code="mode_not_vpn"
 elif fields.get("mode")!="VPN": code="diagnostics_unavailable"
 elif fields.get("is_vpn_running")=="true": code="runtime_running"
 elif fields.get("vpn_permission_granted")=="true": code="permission_granted"
 elif fields=={"mode":"VPN","vpn_permission_granted":"false","is_vpn_running":"false"}: code="ready"
 else: code="diagnostics_unavailable"
except (OSError,subprocess.TimeoutExpired,UnicodeError,ValueError,RuntimeError): pass
print(json.dumps({"ready":code=="ready","code":code},separators=(",",":")))'''

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
   opening=value.get("opening")
   operation=private("operation.json",1024)
   if value.get("state")!="complete" or value.get("sourcePackageSha256")!=intent.get("packageSha256") or value.get("device")!={"uid":"2000","api":intent.get("api"),"avd":intent.get("expectedAvd")} or opening!={"owner":intent.get("expectedOwner"),"revision":intent.get("expectedRevision")} or not isinstance(value.get("operationId"),str) or operation!={"operationId":value.get("operationId"),"controllerId":intent.get("expectedOwner")} or value.get("consentDenied") is not True or value.get("runtimeOff") is not True or value.get("permissionStillAbsent") is not True or intent.get("scenarioVersion")==2 and value.get("noninteractiveRejected") is not True: emit("unknown","terminal_binding_invalid",identity=identity)
   emit("complete",None,identity=identity,receipt=receipt)
  try: phase=private("phase.json",1024).get("phase")
  except FileNotFoundError: phase=None
  if phase is not None and phase not in {"opening_diagnostics","opening_status","noninteractive_on_submitted","noninteractive_diagnostics","noninteractive_status","noninteractive_prompt_checked","interactive_on_submitted","prompt_observed","cancel_submitted","operation_wait_submitted","closing_diagnostics","closing_status"}: emit("unknown","phase_invalid",identity=identity)
  emit("unknown",receipt.get("reason","worker_unknown"),identity=identity,phase=phase)
 try:
  fields=pathlib.Path(f"/proc/{pid}/stat").read_text(encoding="ascii").rsplit(")",1)[1].split()
  live=fields[0]!="Z" and int(fields[19])==ticks
 except FileNotFoundError: live=False
 except (OSError,ValueError,IndexError): emit("unknown","worker_identity_unavailable",identity=identity)
 emit("running" if live else "unknown",None if live else "missing_worker_receipt",identity=identity)
except FileNotFoundError: emit("unknown","missing_job_or_intent")
except (OSError,ValueError,TypeError,KeyError): emit("unknown","status_unavailable")'''


def preflight(root: Path | str, host: str, device: str, cli_stage_correlation_id: str) -> dict[str, Any]:
    """Classify consent readiness on the owned AVD without journaling an action."""
    if (host != "archlinux" or device not in {"api29", "api35"} or
            not isinstance(cli_stage_correlation_id, str) or not _UUID.fullmatch(cli_stage_correlation_id)):
        raise ValueError("Android consent preflight requires a configured device and CLI stage UUID")
    config = ssh_transport.load_config(root)
    if (host not in config.hosts or device not in config.hosts[host].android_devices or
            config.hosts[host].fixture_transfer_root is None or
            ssh_transport.connection_host(config, host).password is not None):
        raise ValueError("Android consent preflight route is unavailable")
    profile = android_observation._profile(config.hosts[host].android_devices[device])
    source_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root,
                                capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    stage = android_cli_stage.status(root, cli_stage_correlation_id)
    if stage.get("state") != "published" or stage.get("sourceSha") != source_sha or not stage.get("ok"):
        raise ValueError("Android consent preflight CLI stage is not current source")
    cli_path = stage.get("receipt", {}).get("cliPath")
    remote_root = config.hosts[host].fixture_transfer_root
    if not isinstance(cli_path, str) or not cli_path.startswith(
            str(remote_root) + "/android-cli-stage-" + cli_stage_correlation_id + "/tree/"):
        raise ValueError("Android consent preflight CLI path is not stage-bound")
    observed = android_observation.observe(root, host, config.hosts[host].android_devices[device], 30)
    if observed.get("available") is not True or observed.get("ownerConsistency") != "consistent":
        return {"ok": False, "state": "unknown", "code": "device_unknown", "host": host,
                "deviceAlias": device, "sourceSha": source_sha, "productAction": False}
    argv = ssh_transport.build_ssh_argv(config, host, 60, command=("python3", "-I", "-B", "-c",
        "exec(" + repr(_PREFLIGHT) + ")", profile["adb"], cli_path, profile["serial"]))
    try:
        exit_code, output = android_observation._run_probe(argv, 60)
        result = json.loads(output.decode("utf-8", "strict")) if exit_code == 0 else None
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
        result = None
    code = result.get("code") if isinstance(result, dict) else None
    if code not in {"ready", "permission_granted", "runtime_running", "mode_not_vpn",
                    "ambiguous_runtime", "diagnostics_unavailable"} or result.get("ready") is not (code == "ready"):
        code = "probe_unknown"
    state = "ready" if code == "ready" else ("unknown" if code in {
        "probe_unknown", "diagnostics_unavailable", "ambiguous_runtime"} else "blocked")
    return {"ok": state == "ready", "state": state, "code": code, "host": host,
            "deviceAlias": device, "sourceSha": source_sha, "productAction": False}


def start(root: Path | str, host: str, device: str, correlation_id: str, artifact_id: str,
          cli_stage_correlation_id: str, opening_readback_correlation_id: str,
          expected_backup_sha256: str, expected_owner: str, expected_revision: int) -> dict[str, Any]:
    if (host != "archlinux" or device not in {"api29", "api35"} or
            not all(isinstance(v, str) and _UUID.fullmatch(v) for v in
                    (correlation_id, cli_stage_correlation_id, opening_readback_correlation_id, expected_owner)) or
            not isinstance(expected_backup_sha256, str) or not _SHA.fullmatch(expected_backup_sha256) or
            type(expected_revision) is not int or expected_revision < 0):
        raise ValueError("Android consent fixture guards are invalid")
    config = ssh_transport.load_config(root)
    if host not in config.hosts or device not in config.hosts[host].android_devices or config.hosts[host].fixture_transfer_root is None or ssh_transport.connection_host(config, host).password is not None:
        raise ValueError("Android consent fixture route is unavailable")
    profile = android_observation._profile(config.hosts[host].android_devices[device])
    artifact = native_artifact_registry.verify_artifact(root, artifact_id)
    if artifact.get("verification") != "verified" or artifact.get("artifact", {}).get("platform") != "android" or artifact["artifact"].get("artifactKind") not in {"apk", "native-fixture-apk"}:
        raise ValueError("Android consent APK is not verified")
    source_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if artifact["artifact"].get("sourceSha") != source_sha:
        raise ValueError("Android consent APK is not current source")
    android_package_install._inspect_apk(root, Path(artifact["location"]["localPath"]))
    package_hash = artifact["artifact"]["sha256"]
    stage = android_cli_stage.status(root, cli_stage_correlation_id)
    if stage.get("state") != "published" or stage.get("sourceSha") != source_sha or not stage.get("ok"):
        raise ValueError("Android consent CLI stage is not current source")
    cli_path = stage.get("receipt", {}).get("cliPath")
    remote_root = config.hosts[host].fixture_transfer_root
    if not isinstance(cli_path, str) or not cli_path.startswith(str(remote_root) + "/android-cli-stage-" + cli_stage_correlation_id + "/tree/"):
        raise ValueError("Android consent CLI path is not stage-bound")
    opening = android_admission_readback.async_collect(root, opening_readback_correlation_id)
    observed = opening.get("result", {})
    if (opening.get("state") != "complete" or opening.get("ok") is not True or
            observed.get("package", {}).get("baseSha256") != package_hash or
            observed.get("backup", {}).get("sha256") != expected_backup_sha256 or
            observed.get("guard", {}).get("controllerId") != expected_owner or
            observed.get("guard", {}).get("configurationRevision") != expected_revision or
            observed.get("device", {}).get("api") != profile["api"]):
        raise ValueError("Android consent opening backup is not admitted")
    live = android_admission_readback.readback_status(root, host, device, opening_readback_correlation_id, timeout_seconds=30)
    if (not live.get("ok") or live.get("result", {}).get("stage") != "backup_present" or
            live["result"].get("controllerId") != expected_owner or
            live["result"].get("configurationRevision") != expected_revision or
            live["result"].get("backup", {}).get("sha256") != expected_backup_sha256):
        raise ValueError("Android consent live backup changed")
    public = android_public_inspect.inspect(root, host, device, correlation_id, package_hash,
                                            expected_owner, expected_revision)
    if public.get("outcome") != "admitted" or public.get("result", {}).get("runtime", {}).get("running") is not False:
        raise ValueError("Android consent owner/runtime is not admitted")
    preflight_argv = ssh_transport.build_ssh_argv(config, host, 60, command=("python3", "-I", "-B", "-c",
        "exec(" + repr(_PREFLIGHT) + ")", profile["adb"], cli_path, profile["serial"]))
    try:
        preflight_code, preflight_output = android_observation._run_probe(preflight_argv, 60)
        preflight = json.loads(preflight_output.decode("utf-8", "strict")) if preflight_code == 0 else None
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
        preflight = None
    if not isinstance(preflight, dict) or preflight.get("ready") is not True or preflight.get("code") != "ready":
        reason = preflight.get("code") if isinstance(preflight, dict) and preflight.get("code") in {
            "permission_granted", "runtime_running", "mode_not_vpn", "ambiguous_runtime",
            "diagnostics_unavailable"} else "probe_unknown"
        raise ValueError("Android consent permission is not freshly absent in VPN mode: " + reason)
    intent = {"host": host, "device": device, "correlationId": correlation_id,
              "scenarioVersion": 2,
              "artifactId": artifact_id, "packageSha256": package_hash,
              "cliStageCorrelationId": cli_stage_correlation_id,
              "cliManifestSha256": stage["receipt"]["manifestSha256"],
              "cliDesktopJarSha256": stage["receipt"]["desktopJarSha256"],
              "cliPath": cli_path, "openingReadbackCorrelationId": opening_readback_correlation_id,
              "backupSha256": expected_backup_sha256, "expectedOwner": expected_owner,
              "expectedRevision": expected_revision, "expectedAvd": profile["expectedAvd"],
              "api": profile["api"], "fixtureRoot": str(remote_root)}
    args = [profile["adb"], cli_path, profile["serial"], profile["expectedAvd"],
            str(profile["api"]), str(remote_root), correlation_id, package_hash,
            expected_owner, str(expected_revision)]
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
        raise ValueError("Android consent correlation must be a UUID")
    intent = android_document_acceptance._load(root, correlation_id)
    if intent is None or intent.get("device") not in {"api29", "api35"}:
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
    stage = android_cli_stage.status(root, intent["cliStageCorrelationId"])
    if (stage.get("state") != "published" or not stage.get("ok") or
            stage.get("receipt", {}).get("manifestSha256") != intent["cliManifestSha256"] or
            stage.get("receipt", {}).get("desktopJarSha256") != intent["cliDesktopJarSha256"] or
            stage.get("receipt", {}).get("cliPath") != intent["cliPath"]):
        return {"ok": False, "state": "unknown", "reason": "cli_stage_changed",
                "correlationId": correlation_id, "replayAllowed": False}
    public = android_public_inspect.inspect(root, intent["host"], intent["device"], correlation_id,
        intent["packageSha256"], intent["expectedOwner"], intent["expectedRevision"])
    if public.get("outcome") != "admitted" or public.get("result", {}).get("runtime", {}).get("running") is not False:
        return {"ok": False, "state": "unknown", "reason": "closing_owner_unknown",
                "correlationId": correlation_id, "replayAllowed": False}
    released = android_document_acceptance._release_device(root, intent["host"], intent["device"], correlation_id)
    return {"ok": released, "state": "complete", "correlationId": correlation_id,
            "result": value, "identity": observed.get("identity"), "leaseReleased": released,
            "replayAllowed": False, "evidenceClass": "native-android-consent-denial"}

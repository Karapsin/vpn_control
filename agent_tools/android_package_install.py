"""Durable, exact-correlation installation of an admitted Android fixture APK.

The public action is `adb install -r` from UID 2000.  No caller-supplied command,
remote path, or retry is accepted.  An uncertain job is observed, never replayed.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any

try:
    from . import android_admission_readback, android_observation, native_artifact_registry, ssh_transfer, ssh_transport
except ImportError:  # pragma: no cover
    import android_admission_readback, android_observation, native_artifact_registry, ssh_transfer, ssh_transport


_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_PACKAGE = "com.kardinal.vpncontrol"


def _version_identity(package: dict[str, Any]) -> tuple[int, int, int]:
    version = package.get("version")
    code = package.get("code")
    if not isinstance(version, str) or not re.fullmatch(r"[1-9][0-9]?\.(?:0|[1-9][0-9]?)\.(?:0|[1-9][0-9]?)", version):
        raise ValueError("Android APK version is not canonical")
    values = tuple(int(part) for part in version.split("."))
    if values[0] > 19 or values[1] > 19 or values[2] > 19 or type(code) is not int or code != ((values[0]*20+values[1])*20+values[2])*20:
        raise ValueError("Android APK version code does not match product version")
    return values


def _journal(root: Path | str, correlation: str) -> Path:
    return Path(root).resolve() / ".rag_index" / "android-install-jobs" / (correlation + ".json")


def _device_lease(root: Path | str, host: str, device: str) -> Path:
    if not re.fullmatch(r"[a-zA-Z0-9_-]+", host) or not re.fullmatch(r"[a-zA-Z0-9_-]+", device):
        raise ValueError("Android install host or device alias is invalid")
    return _journal(root, "unused").parent / ("lease-" + host + "-" + device + ".json")


def _claim_device(root: Path | str, host: str, device: str, correlation: str) -> None:
    path = _device_lease(root, host, device)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("Android install lease directory is not private")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(json.dumps({"host":host,"device":device,"correlationId":correlation},
                             sort_keys=True,separators=(",", ":")).encode()+b"\n")
        out.flush(); os.fsync(out.fileno())
    directory=os.open(path.parent,os.O_RDONLY)
    try: os.fsync(directory)
    finally: os.close(directory)


def _save(root: Path | str, intent: dict[str, Any]) -> None:
    path = _journal(root, intent["correlationId"])
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700:
        raise ValueError("Android install journal is not private")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(json.dumps(intent, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        out.flush(); os.fsync(out.fileno())
    directory = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(directory)
    finally: os.close(directory)


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


def _build_tools(root: Path | str) -> tuple[Path, Path]:
    match = re.search(r"(?m)^sdk\.dir=(.+)$", (Path(root) / "local.properties").read_text(encoding="utf-8"))
    if not match: raise ValueError("Android SDK path is unavailable")
    base = Path(match.group(1).strip()) / "build-tools"
    candidates = sorted((path for path in base.iterdir() if path.is_dir() and (path / "aapt").is_file() and
                         (path / "apksigner").is_file()), reverse=True)
    if not candidates: raise ValueError("Android APK inspection tools are unavailable")
    return candidates[0] / "aapt", candidates[0] / "apksigner"


def _inspect_apk(root: Path | str, apk: Path) -> dict[str, Any]:
    aapt, signer = _build_tools(root)
    badging = subprocess.run([str(aapt), "dump", "badging", str(apk)], capture_output=True,
                            timeout=30, check=True).stdout.decode("utf-8", "strict")
    signature = subprocess.run([str(signer), "verify", "--print-certs", str(apk)], capture_output=True,
                              timeout=30, check=True).stdout.decode("utf-8", "strict")
    package = re.search(r"(?m)^package: name='([^']+)' versionCode='([0-9]+)' versionName='([^']+)'", badging)
    abi = re.search(r"(?m)^native-code: '([^']+)'$", badging)
    certs = re.findall(r"(?m)^Signer #([0-9]+) certificate SHA-256 digest: ([0-9a-f]{64})$", signature)
    signer_ids = set(re.findall(r"(?m)^Signer #([0-9]+) certificate ", signature))
    if (not package or package.group(1) != _PACKAGE or not abi or abi.group(1) != "x86_64" or
            "application-debuggable" in badging or len(certs) != 1 or certs[0][0] != "1" or
            signer_ids != {"1"}):
        raise ValueError("Android APK identity is not an admitted nondebuggable x86_64 package")
    result={"package":package.group(1),"code":int(package.group(2)),"version":package.group(3),
            "abi":"x86_64","signerSha256":certs[0][1],"debuggable":False}
    _version_identity(result)
    return result


def _remote_source() -> str:
    helper = android_observation._canonical_cli_environment_source()
    return helper + r'''
import hashlib,json,os,pathlib,re,stat,subprocess,sys,time
adb,cli,serial,avd,api,root,correlation,stage_path,stage_hash,old_hash,target_hash,old_owner,old_revision,backup_path,backup_hash,target_code,target_version=sys.argv[1:]
def fail(reason):
 print(json.dumps({"state":"unknown","reason":reason},separators=(",",":"))); raise SystemExit(0)
def run(args,timeout=30,env=None,max_bytes=1048576):
 try: done=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout,env=env,check=False)
 except (OSError,subprocess.TimeoutExpired): fail("command_unavailable")
 if done.returncode or len(done.stdout)>max_bytes: fail("command_failed")
 return done.stdout.decode("utf-8","strict").strip()
def shell(*words): return run([adb,"-s",serial,"shell","-T",*words])
def public(*words):
 value=json.loads(run([cli,"--json","--android","--serial",serial,"--timeout-seconds","30",*words],env=environment))
 if not isinstance(value,dict) or value.get("ok") is not True or value.get("final") is not True or value.get("code")!="OK": fail("public_unavailable")
 return value
def base():
 paths=[line.removeprefix("package:") for line in shell("pm","path","com.kardinal.vpncontrol").splitlines() if line.startswith("package:") and line.endswith("/base.apk")]
 if len(paths)!=1 or not paths[0].startswith("/data/app/"): fail("installed_path_invalid")
 digest=shell("sha256sum",paths[0]).split()
 if len(digest)!=2 or digest[1]!=paths[0] or not re.fullmatch(r"[0-9a-f]{64}",digest[0]): fail("installed_hash_invalid")
 return digest[0]
if shell("id","-u")!="2000" or shell("getprop","ro.build.version.sdk")!=api or {x for x in (shell("getprop","ro.kernel.qemu.avd_name"),shell("getprop","ro.boot.qemu.avd_name")) if x}!={avd} or shell("getprop","ro.product.cpu.abi")!="x86_64": fail("device_identity")
if base()!=old_hash: fail("preinstall_package_changed")
environment=public_cli_environment(adb,pathlib.Path(cli))
private_root=pathlib.Path(root); root_info=private_root.lstat()
if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid!=os.getuid() or stat.S_IMODE(root_info.st_mode)!=0o700: fail("private_root_invalid")
for path,expected,size_limit in ((pathlib.Path(backup_path),backup_hash,67108864),(pathlib.Path(stage_path),stage_hash,67108864)):
 if not path.is_relative_to(private_root): fail("input_outside_root")
 ancestor=path.parent
 while ancestor!=private_root:
  ancestor_info=ancestor.lstat()
  if not stat.S_ISDIR(ancestor_info.st_mode) or ancestor_info.st_uid!=os.getuid() or stat.S_IMODE(ancestor_info.st_mode)!=0o700: fail("private_input_ancestor_invalid")
  ancestor=ancestor.parent
 info=path.lstat(); parent=path.parent.lstat()
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=os.getuid() or stat.S_IMODE(parent.st_mode)!=0o700 or not 0<info.st_size<=size_limit: fail("private_input_invalid")
 digest=hashlib.sha256()
 with path.open("rb") as source:
  while block:=source.read(65536): digest.update(block)
 if digest.hexdigest()!=expected: fail("input_hash_changed")
opening=json.loads(pathlib.Path(backup_path).read_text(encoding="utf-8"))
if opening.get("type")!="vpn_control_routing_rules" or opening.get("version")!=7 or not isinstance(opening.get("rules"),dict): fail("opening_routing_invalid")
status=public("status"); data=status.get("data")
if status.get("controllerId")!=old_owner or status.get("configurationRevision")!=int(old_revision) or not isinstance(data,dict) or data.get("runtimeRunning") is not False or data.get("runtimeObservation")!="stopped": fail("preinstall_owner_or_runtime_changed")
ops=public("operations","list")
entries=ops.get("data",{}).get("operations") if isinstance(ops.get("data"),dict) else None
if ops.get("controllerId")!=old_owner or ops.get("configurationRevision")!=int(old_revision) or not isinstance(entries,list) or any(not isinstance(e,dict) or e.get("final") is not True for e in entries): fail("preinstall_history_changed")
try: installed=run([adb,"-s",serial,"install","-r",stage_path],timeout=240,max_bytes=4096)
except Exception: fail("install_outcome_unknown")
if installed.splitlines() not in (["Success"],["Performing Streamed Install","Success"],["Performing Push Install","Success"]): fail("install_result_unknown")
if shell("id","-u")!="2000" or shell("getprop","ro.build.version.sdk")!=api or {x for x in (shell("getprop","ro.kernel.qemu.avd_name"),shell("getprop","ro.boot.qemu.avd_name")) if x}!={avd} or shell("getprop","ro.product.cpu.abi")!="x86_64": fail("postinstall_device_identity")
if base()!=target_hash: fail("postinstall_hash_unknown")
package=shell("dumpsys","package","com.kardinal.vpncontrol")
versions=set(re.findall(r"(?:^|\s)versionName=([^\s]+)",package)); codes=set(re.findall(r"(?:^|\s)versionCode=([0-9]+)(?=\s|$)",package))
if versions!={target_version} or codes!={target_code} or "DEBUGGABLE" in package: fail("postinstall_package_unknown")
last=None
for attempt in range(3):
 try:
  observed=subprocess.run([cli,"--json","--android","--serial",serial,"--timeout-seconds","15","status"],
      stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=15,env=environment,check=False)
  if observed.returncode==0 and len(observed.stdout)<=16384:
   last=json.loads(observed.stdout)
   if isinstance(last,dict) and last.get("ok") is True and last.get("final") is True and last.get("code")=="OK" and isinstance(last.get("controllerId"),str) and last["controllerId"]!=old_owner and type(last.get("configurationRevision")) is int and isinstance(last.get("data"),dict) and last["data"].get("runtimeRunning") is False and last["data"].get("runtimeObservation")=="stopped": break
 except (OSError,subprocess.TimeoutExpired,ValueError,UnicodeError): pass
 time.sleep(1)
if not isinstance(last,dict) or not isinstance(last.get("controllerId"),str) or not last["controllerId"] or last["controllerId"]==old_owner or not isinstance(last.get("data"),dict) or last["data"].get("runtimeRunning") is not False or last["data"].get("runtimeObservation")!="stopped": fail("postinstall_owner_unknown")
post_ops=public("operations","list")
post_entries=post_ops.get("data",{}).get("operations") if isinstance(post_ops.get("data"),dict) else None
if post_ops.get("controllerId")!=last["controllerId"] or post_ops.get("configurationRevision")!=last["configurationRevision"] or not isinstance(post_entries,list) or any(not isinstance(e,dict) or e.get("final") is not True for e in post_entries): fail("postinstall_history_unknown")
job=pathlib.Path(root)/("android-install-job-"+correlation)
job_info=job.lstat()
if not stat.S_ISDIR(job_info.st_mode) or job_info.st_uid!=os.getuid() or stat.S_IMODE(job_info.st_mode)!=0o700: fail("postinstall_job_unsafe")
post_path=job/"postinstall-routing.json"
if post_path.exists(): fail("postinstall_export_exists")
os.umask(0o077)
export=json.loads(run([cli,"--json","--android","--serial",serial,"--timeout-seconds","300","routing","export","--output",str(post_path),"--format","json"],timeout=300,env=environment,max_bytes=16384))
export_data=export.get("data") if isinstance(export,dict) else None
if not isinstance(export,dict) or export.get("ok") is not True or export.get("final") is not True or export.get("code")!="OK" or export.get("controllerId")!=last["controllerId"] or export.get("configurationRevision")!=last["configurationRevision"] or not isinstance(export_data,dict) or export_data.get("format")!="json" or type(export_data.get("bytes")) is not int: fail("postinstall_export_envelope")
post_info=post_path.lstat()
if not stat.S_ISREG(post_info.st_mode) or post_info.st_uid!=os.getuid() or stat.S_IMODE(post_info.st_mode)!=0o600 or not 0<post_info.st_size<=67108864 or post_info.st_size!=export_data["bytes"]: fail("postinstall_export_private_bytes")
post_bytes=post_path.read_bytes()
if len(post_bytes)!=post_info.st_size: fail("postinstall_export_changed")
after=json.loads(post_bytes.decode("utf-8","strict"))
if not isinstance(after,dict) or after.get("type")!="vpn_control_routing_rules" or after.get("version")!=7 or not isinstance(after.get("rules"),dict) or after["rules"]!=opening["rules"]: fail("postinstall_routing_changed")
closing=public("status"); closing_ops=public("operations","list")
closing_entries=closing_ops.get("data",{}).get("operations") if isinstance(closing_ops.get("data"),dict) else None
if closing.get("controllerId")!=last["controllerId"] or closing.get("configurationRevision")!=last["configurationRevision"] or not isinstance(closing.get("data"),dict) or closing["data"].get("runtimeRunning") is not False or closing["data"].get("runtimeObservation")!="stopped" or closing_ops.get("controllerId")!=last["controllerId"] or closing_ops.get("configurationRevision")!=last["configurationRevision"] or not isinstance(closing_entries,list) or any(not isinstance(e,dict) or e.get("final") is not True for e in closing_entries): fail("postinstall_guard_changed")
post_hash=hashlib.sha256(post_bytes).hexdigest()
print(json.dumps({"state":"complete","package":{"baseSha256":target_hash,"version":target_version,"code":int(target_code),"debuggable":False},"owner":{"controllerId":last["controllerId"],"configurationRevision":last["configurationRevision"],"runtimeObservation":"stopped","terminalHistory":True},"device":{"uid":"2000","api":int(api),"avd":avd},"before":{"baseSha256":old_hash,"controllerId":old_owner,"configurationRevision":int(old_revision)},"backupSha256":backup_hash,"postInstallRouting":"verified","postRouting":{"path":str(post_path),"sha256":post_hash,"size":len(post_bytes),"matchesOpeningRules":True},"mutationAllowed":False},separators=(",",":")))
'''


_SUBMIT = android_admission_readback._ASYNC_SUBMIT.replace("android-readback-job-", "android-install-job-")


def _worker_source(source: str, args: list[str]) -> str:
    # Install (240s), export (300s), and bounded owner/status reads can all
    # consume their budgets.  Keep the accepted operation alive long enough
    # to publish a terminal receipt; a timeout still remains truthful unknown.
    return r'''import json,os,pathlib,subprocess,sys,time
job=pathlib.Path(sys.argv[1])
while not (job/"release").exists(): time.sleep(.02)
command=''' + repr(["python3", "-I", "-B", "-c", "exec(" + repr(source) + ")", *args]) + r'''
try:
 done=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,timeout=900,check=False)
 if done.returncode or len(done.stdout)>16384: result={"state":"unknown","reason":"worker_failed"}
 else:
  value=json.loads(done.stdout)
  complete=value.get("state")=="complete"
  result={"state":"complete" if complete else "unknown",
          "result":value if complete else None,
          "reason":None if complete else value.get("reason","install_unknown")}
except (OSError,subprocess.TimeoutExpired,ValueError,UnicodeError): result={"state":"unknown","reason":"worker_unknown"}
path=job/"result.json"; temporary=job/"result.json.tmp"
payload=json.dumps(result,sort_keys=True,separators=(",",":")).encode()+b"\n"
fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
with os.fdopen(fd,"wb") as out: out.write(payload); out.flush(); os.fsync(out.fileno())
os.replace(temporary,path)
directory=os.open(job,os.O_RDONLY); os.fsync(directory); os.close(directory)
'''


_STATUS = r'''import hashlib,json,os,pathlib,stat,sys
root,correlation,expected_json=sys.argv[1:]
def emit(state,reason=None,**extra): print(json.dumps({"state":state,"reason":reason,"correlationId":correlation,**extra},separators=(",",":"))); raise SystemExit(0)
job=pathlib.Path(root)/("android-install-job-"+correlation)
try:
 info=job.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: emit("unknown","unsafe_job")
 def read(name):
  fd=os.open(job/name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)); info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600: emit("unknown","unsafe_"+name)
  with os.fdopen(fd,"rb") as inp: raw=inp.read(16385)
  if len(raw)>16384: emit("unknown","oversized_"+name)
  return json.loads(raw)
 if read("intent.json")!=json.loads(expected_json): emit("unknown","intent_mismatch")
 identity=read("identity.json"); pid=identity.get("pid"); ticks=identity.get("startTicks")
 if type(pid) is not int or type(ticks) is not int or pid<=0 or ticks<=0: emit("unknown","identity_invalid")
 try: result=read("result.json")
 except FileNotFoundError: result=None
 if result is not None:
  if result.get("state")=="complete" and isinstance(result.get("result"),dict):
   value=result["result"]; post=value.get("postRouting"); intent=read("intent.json")
   if value.get("state")!="complete" or value.get("postInstallRouting")!="verified" or not isinstance(post,dict) or post.get("matchesOpeningRules") is not True: emit("unknown","postrouting_receipt_invalid",identity=identity)
   expected_post=job/"postinstall-routing.json"
   expected_opening=pathlib.Path(root)/("android-readback-"+intent["backupCorrelationId"])/"routing.json"
   if post.get("path")!=str(expected_post) or not isinstance(post.get("sha256"),str) or len(post["sha256"])!=64 or type(post.get("size")) is not int or not 0<post["size"]<=67108864 or value.get("backupSha256")!=intent.get("backupSha256"): emit("unknown","postrouting_binding_invalid",identity=identity)
   def verify(path,digest,size=None):
    pinfo=path.parent.lstat(); info=path.lstat()
    if not stat.S_ISDIR(pinfo.st_mode) or pinfo.st_uid!=os.getuid() or stat.S_IMODE(pinfo.st_mode)!=0o700 or not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or not 0<info.st_size<=67108864 or (size is not None and info.st_size!=size): return False
    sha=hashlib.sha256(); fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
    with os.fdopen(fd,"rb") as inp:
     while block:=inp.read(65536): sha.update(block)
    return sha.hexdigest()==digest
   if not verify(expected_opening,intent["backupSha256"]) or not verify(expected_post,post["sha256"],post["size"]): emit("unknown","postrouting_bytes_invalid",identity=identity)
   emit("complete",None,identity=identity,receipt=result)
  emit("unknown",result.get("reason","worker_unknown"),identity=identity)
 try:
  fields=pathlib.Path(f"/proc/{pid}/stat").read_text(encoding="ascii").rsplit(")",1)[1].split()
  live=fields[0]!="Z" and int(fields[19])==ticks
 except (OSError,ValueError,IndexError): live=False
 emit("running" if live else "unknown",None if live else "missing_worker_receipt",identity=identity)
except (OSError,ValueError,TypeError,KeyError): emit("unknown","status_unavailable")'''


def start(root: Path | str, host: str, device: str, correlation_id: str, artifact_id: str,
          stage_identity: dict[str, Any], backup_correlation_id: str, expected_backup_sha256: str,
          expected_old_base_sha256: str, expected_owner: str, expected_revision: int) -> dict[str, Any]:
    """Admit exact package/stage/backup then journal before one detached install."""
    if not all(isinstance(value,str) and _UUID.fullmatch(value) for value in (correlation_id,backup_correlation_id)):
        raise ValueError("Android install requires UUID correlations")
    if not all(isinstance(value,str) and _SHA.fullmatch(value) for value in (expected_backup_sha256,expected_old_base_sha256)):
        raise ValueError("Android install requires exact SHA-256 values")
    if not isinstance(expected_owner,str) or not expected_owner or type(expected_revision) is not int or expected_revision<0:
        raise ValueError("Android install requires exact prior owner and revision")
    config=ssh_transport.load_config(root)
    if host not in config.hosts or device not in config.hosts[host].android_devices or config.hosts[host].fixture_transfer_root is None:
        raise ValueError("Unknown configured Android fixture")
    if ssh_transport.connection_host(config,host).password is not None:
        raise ValueError("Android install requires a private key route")
    profile=android_observation._profile(config.hosts[host].android_devices[device])
    verified=native_artifact_registry.verify_artifact(root,artifact_id)
    if verified.get("verification")!="verified" or verified["artifact"].get("platform")!="android" or verified["artifact"].get("artifactKind")!="apk":
        raise ValueError("Android APK artifact is not verified")
    artifact=verified["artifact"]; apk=Path(verified["location"]["localPath"])
    source_sha=subprocess.run(["git","rev-parse","HEAD"],cwd=root,capture_output=True,text=True,
                              timeout=10,check=True).stdout.strip()
    if artifact.get("sourceSha")!=source_sha:
        raise ValueError("Android APK source does not match current checkout")
    package=_inspect_apk(root,apk)
    previous=native_artifact_registry.verify_artifact(root,"sha256-"+expected_old_base_sha256)
    previous_package=_inspect_apk(root,Path(previous["location"]["localPath"])) if previous.get("verification")=="verified" else None
    if (previous_package is None or previous_package["signerSha256"]!=package["signerSha256"] or
            _version_identity(previous_package)>=_version_identity(package)):
        raise ValueError("Android upgrade signer is not compatible with installed package")
    stage=ssh_transfer.android_apk_stage_status(root,host,stage_identity,timeout_seconds=30)
    if (stage.get("state")!="published" or stage.get("destinationHashes",{}).get("app-nativeFixture.apk")!=artifact["sha256"] or
            stage.get("destinationSizes",{}).get("app-nativeFixture.apk")!=artifact["size"] or
            stage_identity.get("environment")!=device):
        raise ValueError("Android staged APK does not match verified artifact")
    backup=android_admission_readback.readback_status(root,host,device,backup_correlation_id,timeout_seconds=30)
    observed=backup.get("result",{})
    if (not backup.get("ok") or observed.get("stage")!="backup_present" or not observed.get("deviceIdentity") or
            observed.get("controllerId")!=expected_owner or observed.get("configurationRevision")!=expected_revision or
            observed.get("backup",{}).get("sha256")!=expected_backup_sha256 or
            observed.get("backup",{}).get("formatValid") is not True):
        raise ValueError("Android opening owner or private routing backup changed")
    opening=android_admission_readback.async_collect(root,backup_correlation_id)
    opening_result=opening.get("result",{})
    if (not opening.get("ok") or opening_result.get("package",{}).get("baseSha256")!=expected_old_base_sha256 or
            opening_result.get("guard",{}).get("controllerId")!=expected_owner or
            opening_result.get("guard",{}).get("configurationRevision")!=expected_revision or
            opening_result.get("backup",{}).get("sha256")!=expected_backup_sha256):
        raise ValueError("Android opening readback receipt does not match current owner and package")
    remote_root=config.hosts[host].fixture_transfer_root
    stage_path=remote_root/stage_identity["environment"]/stage_identity["owner"]/stage_identity["correlationId"]/"app-nativeFixture.apk"
    backup_path=remote_root/("android-readback-"+backup_correlation_id)/"routing.json"
    intent={"host":host,"device":device,"correlationId":correlation_id,"artifactId":artifact_id,
            "targetSha256":artifact["sha256"],"targetSize":artifact["size"],"package":package,
            "stageIdentity":stage_identity,"backupCorrelationId":backup_correlation_id,"backupSha256":expected_backup_sha256,
            "oldBaseSha256":expected_old_base_sha256,"oldOwner":expected_owner,"oldRevision":expected_revision,
            "expectedAvd":profile["expectedAvd"],"api":profile["api"],"fixtureRoot":str(remote_root)}
    args=[profile["adb"],profile["cli"],profile["serial"],profile["expectedAvd"],str(profile["api"]),
          str(remote_root),correlation_id,str(stage_path),artifact["sha256"],expected_old_base_sha256,artifact["sha256"],
          expected_owner,str(expected_revision),str(backup_path),expected_backup_sha256,
          str(package["code"]),package["version"]]
    import base64
    encoded=base64.urlsafe_b64encode(_worker_source(_remote_source(),args).encode()).decode("ascii")
    argv=ssh_transport.build_ssh_argv(config,host,60,command=("python3","-I","-B","-c","exec("+repr(_SUBMIT)+")",
        str(remote_root),correlation_id,json.dumps(intent,sort_keys=True,separators=(",",":")),encoded))
    _claim_device(root,host,device,correlation_id)
    _save(root,intent)
    try:
        code,output=android_observation._run_probe(argv,60)
        value=json.loads(output.decode("utf-8","strict")) if code==0 else None
        if isinstance(value,dict) and value.get("state")=="submitted" and value.get("correlationId")==correlation_id:
            return {"ok":True,"state":"submitted","correlationId":correlation_id,"identity":value.get("identity"),"replayAllowed":False}
    except (OSError,RuntimeError,TimeoutError,UnicodeError,ValueError): pass
    return {"ok":False,"state":"unknown","correlationId":correlation_id,"replayAllowed":False}


def status(root: Path | str, correlation_id: str) -> dict[str, Any]:
    if not isinstance(correlation_id,str) or not _UUID.fullmatch(correlation_id): raise ValueError("Android install status requires UUID correlation")
    intent=_load(root,correlation_id)
    if intent is None: return {"ok":False,"state":"unknown","reason":"missing_local_intent","correlationId":correlation_id,"replayAllowed":False}
    config=ssh_transport.load_config(root); host=intent["host"]
    if host not in config.hosts or ssh_transport.connection_host(config,host).password is not None:
        return {"ok":False,"state":"unknown","reason":"route_unavailable","correlationId":correlation_id,"replayAllowed":False}
    remote_root=config.hosts[host].fixture_transfer_root
    if remote_root is None or str(remote_root)!=intent.get("fixtureRoot"):
        return {"ok":False,"state":"unknown","reason":"fixture_root_changed","correlationId":correlation_id,"replayAllowed":False}
    argv=ssh_transport.build_ssh_argv(config,host,30,command=("python3","-I","-B","-c","exec("+repr(_STATUS)+")",
        str(remote_root),correlation_id,json.dumps(intent,sort_keys=True,separators=(",",":"))))
    try:
        code,output=android_observation._run_probe(argv,30)
        value=json.loads(output.decode("utf-8","strict")) if code==0 else None
        if isinstance(value,dict) and value.get("correlationId")==correlation_id and value.get("state") in {"running","complete","unknown"}:
            return {"ok":value["state"]=="complete",**value,"replayAllowed":False}
    except (OSError,RuntimeError,TimeoutError,UnicodeError,ValueError): pass
    return {"ok":False,"state":"unknown","reason":"transport_or_receipt_unknown","correlationId":correlation_id,"replayAllowed":False}


def collect(root: Path | str, correlation_id: str) -> dict[str, Any]:
    observed=status(root,correlation_id)
    if observed.get("state")!="complete": return {**observed,"ok":False}
    intent=_load(root,correlation_id); receipt=observed.get("receipt")
    value=receipt.get("result") if isinstance(receipt,dict) else None
    package=value.get("package") if isinstance(value,dict) else None
    owner=value.get("owner") if isinstance(value,dict) else None
    device=value.get("device") if isinstance(value,dict) else None
    before=value.get("before") if isinstance(value,dict) else None
    post=value.get("postRouting") if isinstance(value,dict) else None
    if (not isinstance(intent,dict) or not isinstance(package,dict) or not isinstance(owner,dict) or
            not isinstance(device,dict) or not isinstance(before,dict) or not isinstance(post,dict) or value.get("state")!="complete" or
            package.get("baseSha256")!=intent.get("targetSha256") or package.get("version")!=intent.get("package",{}).get("version") or
            package.get("code")!=intent.get("package",{}).get("code") or package.get("debuggable") is not False or
            device.get("uid")!="2000" or device.get("api")!=intent.get("api") or device.get("avd")!=intent.get("expectedAvd") or
            before.get("baseSha256")!=intent.get("oldBaseSha256") or before.get("controllerId")!=intent.get("oldOwner") or
            before.get("configurationRevision")!=intent.get("oldRevision") or value.get("backupSha256")!=intent.get("backupSha256") or
            not isinstance(owner.get("controllerId"),str) or not owner["controllerId"] or
            type(owner.get("configurationRevision")) is not int or owner["configurationRevision"]<0 or
            owner.get("runtimeObservation")!="stopped" or owner.get("terminalHistory") is not True or
            value.get("postInstallRouting")!="verified" or value.get("mutationAllowed") is not False or
            post.get("path")!=intent.get("fixtureRoot")+"/android-install-job-"+correlation_id+"/postinstall-routing.json" or
            not isinstance(post.get("sha256"),str) or not _SHA.fullmatch(post["sha256"]) or
            type(post.get("size")) is not int or not 0<post["size"]<=67_108_864 or
            post.get("matchesOpeningRules") is not True):
        return {"ok":False,"state":"unknown","reason":"invalid_terminal_receipt","correlationId":correlation_id,"replayAllowed":False}
    return {"ok":True,"state":"complete","correlationId":correlation_id,"result":value,"identity":observed.get("identity"),
            "replayAllowed":False,"admissionReady":False,"nextRequired":"fresh_post_install_mutation_guard"}

"""Bounded, read-only native Android public CLI comparison probe."""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

try:
    from . import android_observation, ssh_transport
except ImportError:  # pragma: no cover
    import android_observation, ssh_transport


_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


def _remote_source() -> str:
    return android_observation._canonical_cli_environment_source() + r'''
import hashlib,json,os,re,subprocess,sys
adb,cli,serial,avd,api,base_hash,owner,revision=sys.argv[1:]
def fail(reason): print(json.dumps({"admitted":False,"reason":reason},separators=(",",":"))); raise SystemExit(0)
def run(args,env=None,max_bytes=65536):
 try: done=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=25,env=env,check=False)
 except (OSError,subprocess.TimeoutExpired): fail("command_unavailable")
 if done.returncode or len(done.stdout)>max_bytes: fail("command_failed")
 return done.stdout.decode("utf-8","strict").strip()
def shell(*words): return run([adb,"-s",serial,"shell","-T",*words],max_bytes=1048576)
if shell("id","-u")!="2000" or shell("getprop","ro.build.version.sdk")!=api or {x for x in (shell("getprop","ro.kernel.qemu.avd_name"),shell("getprop","ro.boot.qemu.avd_name")) if x}!={avd} or shell("getprop","ro.product.cpu.abi")!="x86_64": fail("device_identity")
paths=[line.removeprefix("package:") for line in shell("pm","path","com.kardinal.vpncontrol").splitlines() if line.startswith("package:") and line.endswith("/base.apk")]
if len(paths)!=1 or not paths[0].startswith("/data/app/"): fail("package_path")
digest=shell("sha256sum",paths[0]).split()
if len(digest)!=2 or digest[0]!=base_hash or digest[1]!=paths[0]: fail("package_changed")
environment=public_cli_environment(adb,__import__("pathlib").Path(cli))
def public(*words):
 value=json.loads(run([cli,"--json","--android","--serial",serial,"--timeout-seconds","25",*words],env=environment))
 if not isinstance(value,dict) or value.get("ok") is not True or value.get("final") is not True or value.get("code")!="OK" or value.get("controllerId")!=owner or value.get("configurationRevision")!=int(revision) or not isinstance(value.get("data"),dict): fail("owner_or_response_changed")
 return value["data"]
opening=public("status")
if opening.get("runtimeObservation") not in ("stopped","running") or type(opening.get("runtimeRunning")) is not bool: fail("runtime_observation_unknown")
snapshots={}
for name,command in (("stats",("stats",)),("source",("source","show")),("settings",("settings","show"))):
 data=public(*command)
 canonical=json.dumps(data,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")
 snapshots[name]={"sha256":hashlib.sha256(canonical).hexdigest(),"keys":sorted(data.keys())}
 if name=="source":
  mode=data.get("mode")
  if mode not in ("current-locations","subscription","all"): fail("source_mode_invalid")
  snapshots[name]["mode"]=mode
  selected=data.get("subscriptionId")
  if selected is not None and not isinstance(selected,str): fail("source_selection_invalid")
  snapshots[name]["selectionState"]="none" if selected is None else "empty" if selected=="" else "selected"
operations=public("operations","list")
entries=operations.get("operations")
if not isinstance(entries,list) or any(not isinstance(item,dict) or item.get("final") is not True for item in entries): fail("operation_history_unknown")
closing=public("status")
if closing.get("runtimeRunning")!=opening.get("runtimeRunning") or closing.get("runtimeObservation")!=opening.get("runtimeObservation"): fail("runtime_changed")
print(json.dumps({"admitted":True,"controllerId":owner,"configurationRevision":int(revision),
 "device":{"uid":"2000","api":int(api),"avd":avd},"packageSha256":base_hash,
 "runtime":{"running":opening["runtimeRunning"],"observation":opening["runtimeObservation"]},
 "snapshots":snapshots,"operationCount":len(entries)},separators=(",",":")))
'''


def inspect(root: Path | str, host: str, device: str, correlation_id: str,
            expected_base_sha256: str, expected_owner: str, expected_revision: int,
            timeout_seconds: int = 60) -> dict[str, Any]:
    if not isinstance(correlation_id,str) or not _UUID.fullmatch(correlation_id):
        raise ValueError("Android public inspect requires UUID correlation")
    if not isinstance(expected_base_sha256,str) or not _SHA.fullmatch(expected_base_sha256):
        raise ValueError("Android public inspect requires exact package hash")
    if not isinstance(expected_owner,str) or not expected_owner or type(expected_revision) is not int or expected_revision<0:
        raise ValueError("Android public inspect requires exact owner and revision")
    if isinstance(timeout_seconds,bool) or not isinstance(timeout_seconds,int) or not 1<=timeout_seconds<=60:
        raise ValueError("Android public inspect timeout must be 1..60 seconds")
    config=ssh_transport.load_config(root)
    if host not in config.hosts or device not in config.hosts[host].android_devices:
        raise ValueError("Unknown configured Android device")
    if ssh_transport.connection_host(config,host).password is not None:
        raise ValueError("Android public inspect requires a private key route")
    profile=android_observation._profile(config.hosts[host].android_devices[device])
    argv=ssh_transport.build_ssh_argv(config,host,timeout_seconds,command=("python3","-I","-B","-c",
        "exec("+repr(_remote_source())+")",profile["adb"],profile["cli"],profile["serial"],profile["expectedAvd"],
        str(profile["api"]),expected_base_sha256,expected_owner,str(expected_revision)))
    try:
        code,output=android_observation._run_probe(argv,timeout_seconds)
        if code==255:
            connectivity=ssh_transport.probe(root,host,timeout_seconds)
            if not connectivity.ok:
                response={"ok":False,"outcome":"unknown","reason":connectivity.status.value,
                          "correlationId":correlation_id,"nativeMutationAllowed":False,"replayAllowed":False}
                if (connectivity.status is ssh_transport.ProbeStatus.AUTHENTICATION_FAILED and
                        config.hosts[host].transport=="nested"):
                    response["recoveryHint"]={"tool":"ssh_workflow","action":"connection-recover","host":host}
                return response
        value=json.loads(output.decode("utf-8","strict")) if code==0 else None
        if isinstance(value,dict) and value.get("admitted") is True and value.get("controllerId")==expected_owner and value.get("configurationRevision")==expected_revision and value.get("packageSha256")==expected_base_sha256:
            return {"ok":True,"outcome":"admitted","correlationId":correlation_id,"host":host,"deviceAlias":device,
                    "result":value,"nativeMutationAllowed":False,"replayAllowed":False}
        reason=value.get("reason") if isinstance(value,dict) and isinstance(value.get("reason"),str) else "response_unknown"
    except (OSError,RuntimeError,TimeoutError,UnicodeError,ValueError): reason="transport_or_observation_unknown"
    return {"ok":False,"outcome":"unknown","reason":reason,"correlationId":correlation_id,
            "nativeMutationAllowed":False,"replayAllowed":False}

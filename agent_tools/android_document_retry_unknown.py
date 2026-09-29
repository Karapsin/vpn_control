"""Fixed diagnosis and exact no-effect closure for one unknown Android retry.

Neither action replays a document request.  The private terminal job, device
owner/history, and semantically equal routing must all agree before release.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
from typing import Any

try:
    from . import (android_admission_readback, android_cli_stage, android_document_acceptance,
                   android_document_recovery, android_document_retry, android_installer_dispatch,
                   android_observation, android_public_inspect, ssh_transport)
except ImportError:  # pragma: no cover
    import android_admission_readback, android_cli_stage, android_document_acceptance
    import android_document_recovery, android_document_retry, android_installer_dispatch
    import android_observation, android_public_inspect, ssh_transport


_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_PROOF_KEYS = ("terminal", "preEffect", "openingReadback", "currentReadback", "sameRules",
               "sameHistory", "publicOff", "sharedLease", "documentLease")


def _no_effect_valid(proof: dict[str, Any]) -> bool:
    return isinstance(proof, dict) and all(proof.get(key) is True for key in _PROOF_KEYS)


_PRE_EFFECT = r'''import json,os,pathlib,stat,sys
root,correlation,expected_json,pid_text,ticks_text=sys.argv[1:]
ready=False; stage="unavailable"
try:
 base=pathlib.Path(root); binfo=base.lstat()
 if not stat.S_ISDIR(binfo.st_mode) or binfo.st_uid!=os.getuid() or stat.S_IMODE(binfo.st_mode)!=0o700: raise ValueError("root")
 job=base/("android-document-retry-job-"+correlation); info=job.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: raise ValueError("job")
 directory=os.open(job,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0))
 def private(name,limit):
  fd=os.open(name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0),dir_fd=directory)
  with os.fdopen(fd,"rb") as source:
   info=os.fstat(source.fileno()); raw=source.read(limit+1)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or len(raw)>limit: raise ValueError("private")
  return json.loads(raw)
 intent=private("intent.json",8192)
 identity=private("identity.json",1024)
 result=private("result.json",16384)
 if json.dumps(intent,sort_keys=True,separators=(",",":"))!=json.dumps(json.loads(expected_json),sort_keys=True,separators=(",",":")) or json.dumps(identity,sort_keys=True,separators=(",",":"))!=json.dumps({"pid":int(pid_text),"startTicks":int(ticks_text)},sort_keys=True,separators=(",",":")) or result.get("state")!="unknown" or not isinstance(result.get("reason"),str) or not result["reason"]: raise ValueError("identity")
 names=os.listdir(directory)
 if any(name.startswith("transfer-") or name.startswith("phase.json") for name in names):
  stage="transfer_or_phase_present"
 else:
  stage="before_first_upload"; ready=True
 os.close(directory)
except (OSError,ValueError,TypeError,KeyError): pass
print(json.dumps({"ready":ready,"stage":stage},separators=(",",":")))'''


_COMMAND_PROBE = android_observation._canonical_cli_environment_source() + r'''import json,pathlib,subprocess,sys
adb,cli,serial,owner,revision,package_hash=sys.argv[1:]
environment=public_cli_environment(adb,pathlib.Path(cli))
def run(name,args,env=None):
 try: done=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8,env=env,check=False)
 except (OSError,subprocess.TimeoutExpired): return {"name":name,"outcome":"unavailable","stderrNonempty":None}
 if len(done.stdout)>65536 or len(done.stderr)>65536: return {"name":name,"outcome":"oversized","stderrNonempty":None}
 value={"name":name,"outcome":"exit_zero" if done.returncode==0 else "exit_nonzero","stderrNonempty":bool(done.stderr)}
 if name=="uid": value["expectedValue"]=done.stdout.strip()==b"2000"
 if name=="status" and done.returncode==0:
  try:
   parsed=json.loads(done.stdout)
   value["bound"]=parsed.get("ok") is True and parsed.get("controllerId")==owner and parsed.get("configurationRevision")==int(revision)
  except (ValueError,UnicodeError): value["bound"]=False
 return value
commands=[]
for name,words in (("uid",("id","-u")),("api",("getprop","ro.build.version.sdk")),
 ("avd",("getprop","ro.kernel.qemu.avd_name")),("abi",("getprop","ro.product.cpu.abi")),
 ("heap",("getprop","dalvik.vm.heapsize")),("package",("pm","path","com.kardinal.vpncontrol"))):
 commands.append(run(name,[adb,"-s",serial,"shell","-T",*words]))
commands.append(run("status",[cli,"--json","--android","--serial",serial,"--timeout-seconds","30","status"],environment))
print(json.dumps({"commands":commands},separators=(",",":")))'''


def _remote_json(root: Path | str, host: str, source: str, args: tuple[str, ...], timeout: int = 30) -> dict[str, Any] | None:
    config = ssh_transport.load_config(root)
    argv = ssh_transport.build_ssh_argv(config, host, timeout, command=("python3", "-I", "-B", "-c",
        "exec(" + repr(source) + ")", *args))
    try:
        code, output = android_observation._run_probe(argv, timeout)
        value = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
        return value if isinstance(value, dict) else None
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
        return None


def _marker_path(root: Path | str, correlation_id: str) -> Path:
    return Path(root).resolve() / ".rag_index" / "android-document-retry-noeffect" / (correlation_id + ".json")


def _read_marker(root: Path | str, correlation_id: str) -> dict[str, Any] | None:
    return android_document_recovery._private_read(_marker_path(root, correlation_id), "correlationId", correlation_id)


def _write_marker(root: Path | str, value: dict[str, Any]) -> None:
    path = _marker_path(root, value["correlationId"])
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("Android no-effect proof journal directory is unsafe")
    android_document_recovery._private_write(path, value)


def diagnose(root: Path | str, unknown_correlation_id: str,
             opening_readback_correlation_id: str,
             current_readback_correlation_id: str,
             *, command_probe: bool = True) -> dict[str, Any]:
    if (not all(isinstance(value, str) and _UUID.fullmatch(value) for value in
            (unknown_correlation_id, opening_readback_correlation_id, current_readback_correlation_id)) or
            len({unknown_correlation_id, opening_readback_correlation_id, current_readback_correlation_id}) != 3):
        raise ValueError("Android retry diagnosis requires distinct exact correlations")
    old = android_document_retry._load(root, unknown_correlation_id)
    if not isinstance(old, dict) or old.get("openingReadbackCorrelationId") != opening_readback_correlation_id:
        return {"ok": False, "state": "unknown", "reason": "original_intent_changed",
                "correlationId": unknown_correlation_id, "replayAllowed": False}
    host, device = old.get("host"), old.get("device")
    if host != "archlinux" or device != "api29":
        return {"ok": False, "state": "unknown", "reason": "environment_changed",
                "correlationId": unknown_correlation_id, "replayAllowed": False}
    config = ssh_transport.load_config(root)
    if (host not in config.hosts or device not in config.hosts[host].android_devices or
            ssh_transport.connection_host(config, host).password is not None or
            config.hosts[host].fixture_transfer_root is None):
        return {"ok": False, "state": "unknown", "reason": "route_changed",
                "correlationId": unknown_correlation_id, "replayAllowed": False}
    profile = android_observation._profile(config.hosts[host].android_devices[device])
    remote_root = config.hosts[host].fixture_transfer_root
    original = android_document_retry.status(root, unknown_correlation_id)
    identity = original.get("identity")
    valid_identity = (original.get("state") == "unknown" and isinstance(identity, dict) and
                      type(identity.get("pid")) is int and identity["pid"] > 0 and
                      type(identity.get("startTicks")) is int and identity["startTicks"] > 0)
    proof: dict[str, bool] = {key: False for key in _PROOF_KEYS}
    terminal = None
    pre_effect = None
    if valid_identity:
        terminal_source = android_document_retry._recovery_sources()[2]
        args = (str(remote_root), unknown_correlation_id,
                json.dumps(old, sort_keys=True, separators=(",", ":")),
                str(identity["pid"]), str(identity["startTicks"]))
        terminal = _remote_json(root, host, terminal_source, args)
        proof["terminal"] = isinstance(terminal, dict) and terminal.get("ready") is True
        pre_effect = _remote_json(root, host, _PRE_EFFECT, args)
        proof["preEffect"] = isinstance(pre_effect, dict) and pre_effect.get("ready") is True
    local_lease = android_document_acceptance._lease(root, host, device, unknown_correlation_id)
    proof["documentLease"] = android_document_recovery._private_read(local_lease, "correlationId", unknown_correlation_id) == {
        "host": host, "device": device, "correlationId": unknown_correlation_id}
    expected_shared = android_installer_dispatch._lease_value("android-document-retry", host, device,
                                                                unknown_correlation_id)
    try:
        local_shared = android_installer_dispatch._shared_directory(Path(root).resolve()) / ("lease-" + host + "-" + device + ".json")
        local_value = json.loads(android_installer_dispatch.android_installer_target._private_file(local_shared, 1024))
    except (OSError, ValueError, TypeError):
        local_value = None
    remote_shared = android_installer_dispatch.remote_shared_lease(root, host, device,
        unknown_correlation_id, "android-document-retry", "status")
    proof["sharedLease"] = local_value == expected_shared and remote_shared.get("state") == "claimed"
    package_hash, owner, revision = old.get("packageSha256"), old.get("expectedOwner"), old.get("expectedRevision")
    opening = android_admission_readback.async_collect(root, opening_readback_correlation_id)
    opening_intent = android_admission_readback._load_async_intent(root, opening_readback_correlation_id)
    proof["openingReadback"] = android_document_retry._opening_valid(opening, opening_intent, host, device,
        package_hash, owner, revision, old.get("backupSha256"), profile["expectedAvd"], remote_root,
        opening_readback_correlation_id)
    current = android_admission_readback.async_collect(root, current_readback_correlation_id)
    current_intent = android_admission_readback._load_async_intent(root, current_readback_correlation_id)
    current_result = current.get("result") if current.get("ok") and current.get("state") == "complete" else None
    current_backup_sha = current_result.get("backup", {}).get("sha256") if isinstance(current_result, dict) else None
    proof["currentReadback"] = (isinstance(current_backup_sha, str) and _SHA.fullmatch(current_backup_sha) is not None and
        android_document_retry._opening_valid(current, current_intent, host, device,
            package_hash, owner, revision, current_backup_sha, profile["expectedAvd"], remote_root,
            current_readback_correlation_id))
    opening_result = opening.get("result") if proof["openingReadback"] else None
    proof["sameHistory"] = (proof["openingReadback"] and proof["currentReadback"] and
        type(opening_result.get("operationCount")) is int and
        opening_result["operationCount"] == current_result.get("operationCount"))
    semantic = None
    if proof["openingReadback"] and proof["currentReadback"]:
        opening_backup = opening_result["backup"]
        current_backup = current_result["backup"]
        semantic = _remote_json(root, host, android_document_retry._closing_semantic_source(),
            (str(remote_root), opening_readback_correlation_id, current_readback_correlation_id,
             opening_backup["sha256"], str(opening_backup["size"]),
             current_backup["sha256"], str(current_backup["size"])))
        proof["sameRules"] = (isinstance(semantic, dict) and semantic.get("same") is True and
            isinstance(semantic.get("canonicalSha256"), str) and
            _SHA.fullmatch(semantic["canonicalSha256"]) is not None)
    public = android_public_inspect.inspect(root, host, device, unknown_correlation_id,
                                            package_hash, owner, revision)
    runtime = public.get("result", {}).get("runtime", {})
    proof["publicOff"] = (public.get("ok") is True and public.get("outcome") == "admitted" and
                          runtime.get("running") is False and runtime.get("observation") == "stopped")
    command = None
    if command_probe:
        command = _remote_json(root, host, _COMMAND_PROBE,
            (profile["adb"], old["cliPath"], profile["serial"], owner, str(revision), package_hash), 60)
    ready = _no_effect_valid(proof)
    return {"ok": True, "state": "observed", "correlationId": unknown_correlation_id,
            "noEffectProven": ready, "proof": proof,
            "stage": pre_effect.get("stage") if isinstance(pre_effect, dict) else "unavailable",
            "routingCanonicalSha256": semantic.get("canonicalSha256") if proof["sameRules"] else None,
            "openingOperationCount": opening_result.get("operationCount") if proof["openingReadback"] else None,
            "currentOperationCount": current_result.get("operationCount") if proof["currentReadback"] else None,
            "commandCategories": command.get("commands") if isinstance(command, dict) else None,
            "replayAllowed": False}


def close(root: Path | str, unknown_correlation_id: str,
          opening_readback_correlation_id: str,
          current_readback_correlation_id: str) -> dict[str, Any]:
    """Release an exact unknown lease only after durable, fresh no-effect proof."""
    observed = diagnose(root, unknown_correlation_id, opening_readback_correlation_id,
                        current_readback_correlation_id, command_probe=False)
    old = android_document_retry._load(root, unknown_correlation_id)
    if not isinstance(old, dict) or observed.get("state") != "observed":
        return {"ok": False, "state": "unknown", "reason": "diagnosis_unavailable",
                "correlationId": unknown_correlation_id, "replayAllowed": False}
    proof = observed.get("proof")
    marker = {"correlationId": unknown_correlation_id,
              "openingReadbackCorrelationId": opening_readback_correlation_id,
              "currentReadbackCorrelationId": current_readback_correlation_id,
              "expectedOwner": old.get("expectedOwner"),
              "expectedRevision": old.get("expectedRevision"),
              "packageSha256": old.get("packageSha256"),
              "routingCanonicalSha256": observed.get("routingCanonicalSha256"),
              "operationCount": observed.get("currentOperationCount")}
    previous = _read_marker(root, unknown_correlation_id)
    stable = (isinstance(proof, dict) and all(proof.get(key) is True for key in _PROOF_KEYS
              if key not in {"sharedLease", "documentLease"}) and
              isinstance(marker["routingCanonicalSha256"], str) and
              _SHA.fullmatch(marker["routingCanonicalSha256"]) is not None and
              type(marker["operationCount"]) is int)
    if previous is None:
        if not _no_effect_valid(proof) or not stable:
            return {"ok": False, "state": "unknown", "reason": "no_effect_not_proven",
                    "correlationId": unknown_correlation_id, "replayAllowed": False}
        try:
            _write_marker(root, marker)
        except (OSError, ValueError):
            return {"ok": False, "state": "unknown", "reason": "proof_journal_unknown",
                    "correlationId": unknown_correlation_id, "replayAllowed": False}
    elif previous != marker or not stable:
        return {"ok": False, "state": "unknown", "reason": "proof_marker_changed",
                "correlationId": unknown_correlation_id, "replayAllowed": False}
    released = android_document_retry._release_recovery_leases(root, old["host"], old["device"],
                                                                 unknown_correlation_id)
    return {"ok": released, "state": "closed" if released else "unknown",
            "reason": None if released else "lease_release_unknown",
            "correlationId": unknown_correlation_id,
            "currentReadbackCorrelationId": current_readback_correlation_id,
            "leaseReleased": released, "replayAllowed": False}

"""Fixed read-only Android package/control admission with a private routing backup.

The product actions are reads.  The backup is written only in the configured
private fixture root; an uncertain SSH result preserves that directory for
inspection and never retries a product mutation.
"""
from __future__ import annotations

import ast
import base64
import json
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import time
from typing import Any, Mapping

try:
    from . import android_observation, ssh_transport
except ImportError:  # standalone MCP loader
    import android_observation
    import ssh_transport


_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_PREFLIGHT_STAGES = ("uid", "api", "kernel_avd", "boot_avd", "abi", "package",
                     "package_path", "base_hash", "reverse", "status", "operations", "routing")


def _run_stream_probe(argv: list[str], timeout_seconds: int) -> tuple[int | None, list[dict[str, Any]], bool]:
    """Keep bounded completed stage events even if the SSH observer times out."""
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL)
    assert process.stdout is not None
    lines: list[dict[str, Any]] = []
    pending = bytearray()
    deadline = time.monotonic() + timeout_seconds + 1
    timed_out = False
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            ready, _, _ = select.select([process.stdout], [], [], remaining)
            if not ready: continue
            chunk = os.read(process.stdout.fileno(), 4096)
            if not chunk: break
            pending.extend(chunk)
            if len(pending) > 16_384: raise RuntimeError("oversized_stage_output")
            while b"\n" in pending:
                line, _, rest = pending.partition(b"\n")
                pending = bytearray(rest)
                try:
                    event = json.loads(line.decode("utf-8", "strict"))
                except (UnicodeError, ValueError) as error:
                    raise RuntimeError("malformed_stage_event") from error
                if (not isinstance(event, dict) or set(event) - {"stage", "ok", "elapsedMs", "summary"} or
                        event.get("stage") not in _PREFLIGHT_STAGES or
                        not isinstance(event.get("ok"), bool) or
                        isinstance(event.get("elapsedMs"), bool) or
                        not isinstance(event.get("elapsedMs"), int) or event["elapsedMs"] < 0 or
                        len(lines) >= len(_PREFLIGHT_STAGES) or
                        event["stage"] != _PREFLIGHT_STAGES[len(lines)]):
                    raise RuntimeError("malformed_stage_event")
                lines.append(event)
                if not event["ok"]: return None, lines, False
        return process.poll(), lines, timed_out
    finally:
        if process.poll() is None: process.kill()
        process.wait()
        process.stdout.close()


def _remote_preflight() -> str:
    helper = android_observation._canonical_cli_environment_source()
    return helper + r'''
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

adb, cli, serial, expected_avd, expected_api, timeout_text = sys.argv[1:]
step_timeout = min(12, int(timeout_text))
started = time.monotonic()
def emit(stage, ok, summary=None):
    event = {"stage":stage,"ok":ok,"elapsedMs":int((time.monotonic()-started)*1000)}
    if summary is not None: event["summary"] = summary
    print(json.dumps(event, separators=(",",":")), flush=True)
    if not ok: raise SystemExit(0)
def invoke(argv, env=None, limit=67108864, command_timeout=None):
    try:
        done = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=command_timeout or step_timeout, check=False, env=env)
        if done.returncode or len(done.stdout) > limit: return None
        return done.stdout.decode("utf-8", "strict").strip()
    except (OSError, subprocess.TimeoutExpired, UnicodeError): return None
def shell(*words): return invoke([adb,"-s",serial,"shell","-T",*words], limit=1048576)
uid = shell("id","-u")
emit("uid", uid == "2000")
api = shell("getprop","ro.build.version.sdk")
emit("api", api == expected_api)
kernel = shell("getprop","ro.kernel.qemu.avd_name")
emit("kernel_avd", kernel is not None)
boot = shell("getprop","ro.boot.qemu.avd_name")
emit("boot_avd", boot is not None and {name for name in (kernel,boot) if name} == {expected_avd})
abi = shell("getprop","ro.product.cpu.abi")
emit("abi", abi is not None and bool(re.fullmatch(r"[A-Za-z0-9_.-]+",abi)), abi)
package = shell("dumpsys","package","com.kardinal.vpncontrol")
versions = re.findall(r"(?:^|\s)versionName=([^\s]+)",package or "")
codes = re.findall(r"(?:^|\s)versionCode=([0-9]+)(?=\s|$)",package or "")
emit("package", package is not None and "DEBUGGABLE" not in package and
    len(set(versions)) == len(set(codes)) == 1,
    {"version":versions[0],"code":int(codes[0]),"debuggable":False} if len(set(versions)) == len(set(codes)) == 1 else None)
paths = shell("pm","path","com.kardinal.vpncontrol")
bases = [line.removeprefix("package:") for line in (paths or "").splitlines()
         if line.startswith("package:") and line.endswith("/base.apk")]
emit("package_path",len(bases)==1 and bases[0].startswith("/data/app/"))
hashed = shell("sha256sum",bases[0])
fields = (hashed or "").split()
emit("base_hash",len(fields)==2 and bool(re.fullmatch(r"[0-9a-f]{64}",fields[0])) and fields[1]==bases[0],
     fields[0] if len(fields)==2 and re.fullmatch(r"[0-9a-f]{64}",fields[0]) else None)
reverse = invoke([adb,"-s",serial,"reverse","--list"],limit=16384)
emit("reverse",reverse is not None, {"lineCount":len(reverse.splitlines())} if reverse is not None else None)
try: environment = public_cli_environment(adb,Path(cli))
except (OSError,RuntimeError,ValueError): environment = None
def public(*words):
    if environment is None: return None
    command_timeout = min(30,int(timeout_text)) if words == ("routing","show") else step_timeout
    raw = invoke([cli,"--json","--android","--serial",serial,"--timeout-seconds",timeout_text,*words],
                 environment,command_timeout=command_timeout)
    try: return json.loads(raw) if raw is not None else None
    except ValueError: return None
status = public("status")
owner = status.get("controllerId") if isinstance(status,dict) else None
revision = status.get("configurationRevision") if isinstance(status,dict) else None
valid_status = isinstance(status,dict) and status.get("ok") is True and status.get("final") is True and status.get("code")=="OK" and isinstance(owner,str) and bool(owner) and type(revision) is int and revision>=0
emit("status",valid_status,{"controllerId":owner,"configurationRevision":revision} if valid_status else None)
operations = public("operations","list")
entries = operations.get("data",{}).get("operations") if isinstance(operations,dict) else None
valid_ops = isinstance(operations,dict) and operations.get("ok") is True and operations.get("final") is True and operations.get("code")=="OK" and operations.get("controllerId")==owner and operations.get("configurationRevision")==revision and isinstance(entries,list) and all(isinstance(e,dict) and e.get("final") is True for e in entries)
emit("operations",valid_ops,{"count":len(entries)} if valid_ops else None)
routing = public("routing","show")
data = routing.get("data") if isinstance(routing,dict) else None
valid_routing = isinstance(routing,dict) and routing.get("ok") is True and routing.get("final") is True and routing.get("code")=="OK" and routing.get("controllerId")==owner and routing.get("configurationRevision")==revision and isinstance(data,dict) and isinstance(data.get("routing"),dict)
emit("routing",valid_routing,{"ownerStable":True} if valid_routing else None)
'''


def preflight(root: Path | str, host: str, device: str, correlation_id: str,
              timeout_seconds: int = 60) -> dict[str, Any]:
    """Return bounded read-only stage evidence; a timeout retains completed steps."""
    if not isinstance(correlation_id, str) or not _UUID.fullmatch(correlation_id):
        raise ValueError("Android preflight requires a UUID correlation")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 60:
        raise ValueError("Android preflight timeout must be 1..60 seconds")
    config = ssh_transport.load_config(root)
    if host not in config.hosts or device not in config.hosts[host].android_devices:
        raise ValueError("Unknown configured Android device")
    if ssh_transport.connection_host(config, host).password is not None:
        raise ValueError("Android preflight requires a private key route")
    profile = android_observation._profile(config.hosts[host].android_devices[device])
    argv = ssh_transport.build_ssh_argv(config, host, timeout_seconds,
        command=("python3", "-c", "exec(" + repr(_remote_preflight()) + ")",
                 profile["adb"], profile["cli"], profile["serial"], profile["expectedAvd"],
                 str(profile["api"]), str(timeout_seconds)))
    try:
        code, stages, timed_out = _run_stream_probe(argv, timeout_seconds)
    except (OSError, RuntimeError, TimeoutError):
        code, stages, timed_out = None, [], True
    complete = code == 0 and len(stages) == len(_PREFLIGHT_STAGES) and all(stage["ok"] for stage in stages)
    return {"ok":complete,"outcome":"admitted" if complete else "unknown" if timed_out or code is None else "rejected",
            "correlationId":correlation_id,"host":host,"deviceAlias":device,
            "completedStages":stages,"lastStage":stages[-1]["stage"] if stages else None,
            "timedOut":timed_out,"replayAllowed":False,"nativeMutationAllowed":False}


def _guard_source() -> str:
    """Ship the canonical pure preflight guard, rather than a diverging copy."""
    path = Path(__file__).resolve().parents[1] / "scripts" / "android_fixture_preflight.py"
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    names = {"require_terminal_operation_history", "admission_export_guard"}
    functions = [ast.get_source_segment(source, item) for item in tree.body
                 if isinstance(item, ast.FunctionDef) and item.name in names]
    if len(functions) != len(names) or any(not item for item in functions):
        raise RuntimeError("Canonical Android admission guards are unavailable")
    return "from collections.abc import Mapping\nimport re\n" + "\n\n".join(functions) + "\n"


def _remote_probe() -> str:
    helper = android_observation._canonical_cli_environment_source()
    guard = _guard_source()
    return helper + guard + r'''
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

adb, cli, serial, expected_avd, expected_api, root, correlation, expected_hash, timeout_text = sys.argv[1:]
timeout = int(timeout_text)
def read(argv, env=None, *, max_bytes=67108864, command_timeout=None):
    try:
        done = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=command_timeout or timeout, env=env, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("command_unavailable")
    if done.returncode or len(done.stdout) > max_bytes:
        raise RuntimeError("command_failed")
    return done.stdout.decode("utf-8", "strict").strip()
def shell(*words): return read([adb, "-s", serial, "shell", "-T", *words], max_bytes=1048576)
def public(*words, max_bytes=67108864):
    return read([cli, "--json", "--android", "--serial", serial,
        "--timeout-seconds", timeout_text, *words], environment, max_bytes=max_bytes)
def envelope(*words):
    value = json.loads(public(*words))
    if not isinstance(value, dict): raise RuntimeError("invalid_envelope")
    return value
def fail(reason):
    print(json.dumps({"admitted":False,"reason":reason}, separators=(",",":")))
    raise SystemExit(0)

uid = shell("id", "-u")
api = shell("getprop", "ro.build.version.sdk")
avds = {name for name in (shell("getprop", "ro.kernel.qemu.avd_name"),
                         shell("getprop", "ro.boot.qemu.avd_name")) if name}
abi = shell("getprop", "ro.product.cpu.abi")
if uid != "2000" or api != expected_api or avds != {expected_avd} or not re.fullmatch(r"[A-Za-z0-9_.-]+", abi):
    fail("device_identity")
package = shell("dumpsys", "package", "com.kardinal.vpncontrol")
versions = re.findall(r"(?:^|\s)versionName=([^\s]+)", package)
codes = re.findall(r"(?:^|\s)versionCode=([0-9]+)(?=\s|$)", package)
if "DEBUGGABLE" in package or len(set(versions)) != 1 or len(set(codes)) != 1:
    fail("package_identity")
paths = [line.removeprefix("package:") for line in shell("pm", "path", "com.kardinal.vpncontrol").splitlines()
         if line.startswith("package:") and line.endswith("/base.apk")]
if len(paths) != 1 or not paths[0].startswith("/data/app/"):
    fail("package_path")
base_hash = shell("sha256sum", paths[0]).split()
if len(base_hash) != 2 or not re.fullmatch(r"[0-9a-f]{64}", base_hash[0]) or base_hash[1] != paths[0]:
    fail("package_hash")
if expected_hash and base_hash[0] != expected_hash:
    fail("artifact_mismatch")
reverse = read([adb, "-s", serial, "reverse", "--list"], max_bytes=16384)
reverse_lines = reverse.splitlines()
seen_ports = set()
for line in reverse_lines:
    fields = line.split()
    if (len(fields) != 3 or fields[0] != serial or
            not all(re.fullmatch(r"tcp:[1-9][0-9]{0,4}", field) for field in fields[1:]) or
            not all(1 <= int(field[4:]) <= 65535 for field in fields[1:]) or
            fields[1] in seen_ports):
        fail("reverse_inventory")
    seen_ports.add(fields[1])
environment = public_cli_environment(adb, Path(cli))
status = envelope("status")
operations = envelope("operations", "list")

parent = Path(root)
metadata = parent.lstat()
if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
    fail("private_root")
directory = parent / ("android-readback-" + correlation)
directory.mkdir(mode=0o700)
backup_path = directory / "routing.json"
os.umask(0o077)
stage = "export_command"
try:
    export = read([cli, "--json", "--android", "--serial", serial, "--timeout-seconds", "300",
        "routing", "export", "--output", str(backup_path), "--format", "json"],
        environment, max_bytes=16384, command_timeout=300)
    stage = "export_response"
    export_response = json.loads(export)
    export_data = export_response.get("data") if isinstance(export_response, dict) else None
    if (not isinstance(export_response, dict) or export_response.get("ok") is not True or
            export_response.get("final") is not True or export_response.get("code") != "OK" or
            export_response.get("controllerId") != status.get("controllerId") or
            export_response.get("configurationRevision") != status.get("configurationRevision") or
            not isinstance(export_data, dict) or export_data.get("format") != "json" or
            type(export_data.get("bytes")) is not int or export_data["bytes"] <= 0):
        raise RuntimeError("export_response_invalid")
    stage = "backup_privacy"
    file_metadata = backup_path.lstat()
    if not stat.S_ISREG(file_metadata.st_mode) or file_metadata.st_uid != os.getuid() or stat.S_IMODE(file_metadata.st_mode) != 0o600:
        raise RuntimeError("backup_not_private")
    stage = "backup_size"
    if not 0 < file_metadata.st_size <= 67108864: raise RuntimeError("backup_size")
    stage = "backup_bytes"
    with backup_path.open("rb") as handle: payload = handle.read(67108865)
    if len(payload) != file_metadata.st_size or len(payload) != export_data["bytes"]: raise RuntimeError("backup_changed")
    stage = "backup_document"
    document = json.loads(payload.decode("utf-8", "strict"))
    if not isinstance(document, dict): raise RuntimeError("backup_document")
    rules = document.get("rules")
    rules_valid = (isinstance(rules, dict) and
        isinstance(rules.get("ignore_rules"), bool) and
        isinstance(rules.get("block_quic_udp_443"), bool) and
        isinstance(rules.get("proxy_packages"), list) and
        all(isinstance(item, str) for item in rules["proxy_packages"]) and
        isinstance(rules.get("direct_domain_suffixes"), list) and
        all(isinstance(item, str) for item in rules["direct_domain_suffixes"]))
    backup = {"path":str(backup_path), "sha256":hashlib.sha256(payload).hexdigest(),
        "size":len(payload), "type":document.get("type"), "version":document.get("version"),
        "rulesValid":rules_valid}
    stage = "closing_status"
    closing_status = envelope("status")
    stage = "guard"
    guard = admission_export_guard(status, operations, closing_status, backup)
except Exception:
    # Retain any partial backup and correlation.  The caller must inspect it;
    # it must never silently become an admitted snapshot.
    fail("readback_" + stage + "_unknown")

print(json.dumps({"admitted":True,"device":{"uid":uid,"api":int(api),"avd":expected_avd,"abi":abi},
    "package":{"name":"com.kardinal.vpncontrol","version":versions[0],"code":int(codes[0]),
        "debuggable":False,"baseSha256":base_hash[0]},
    "reverseInventory":reverse_lines,
    "operationCount":len(operations["data"]["operations"]),
    "guard":guard,"backup":backup}, separators=(",",":")))
'''


def readback(root: Path | str, host: str, device: str, correlation_id: str,
             expected_base_sha256: str | None = None, timeout_seconds: int = 45) -> dict[str, Any]:
    """Observe a configured AVD and retain one exclusive private full routing export."""
    if not isinstance(correlation_id, str) or not _UUID.fullmatch(correlation_id):
        raise ValueError("Android readback requires a UUID correlation")
    if expected_base_sha256 is not None and (not isinstance(expected_base_sha256, str) or not _SHA.fullmatch(expected_base_sha256)):
        raise ValueError("Expected APK hash must be a lowercase SHA-256")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 60:
        raise ValueError("Android readback timeout must be 1..60 seconds")
    config = ssh_transport.load_config(root)
    if host not in config.hosts or device not in config.hosts[host].android_devices:
        raise ValueError("Unknown configured Android device")
    configured = config.hosts[host]
    connection = ssh_transport.connection_host(config, host)
    if connection.password is not None or configured.fixture_transfer_root is None:
        raise ValueError("Android readback requires a private key route and fixture root")
    profile = android_observation._profile(configured.android_devices[device])
    argv = ssh_transport.build_ssh_argv(config, host, timeout_seconds,
        command=("python3", "-c", "exec(" + repr(_remote_probe()) + ")",
            profile["adb"], profile["cli"], profile["serial"], profile["expectedAvd"],
            str(profile["api"]), str(configured.fixture_transfer_root), correlation_id,
            expected_base_sha256 or "", str(timeout_seconds)))
    try:
        code, output = android_observation._run_probe(argv, timeout_seconds)
        if code: raise RuntimeError("transport_failed")
        result = json.loads(output.decode("utf-8", "strict"))
        if not isinstance(result, dict) or result.get("admitted") is not True:
            reason = result.get("reason") if isinstance(result, dict) else "malformed_result"
            return {"ok":False,"outcome":"unknown","reason":reason,"correlationId":correlation_id,
                    "replayAllowed":False}
        if (not isinstance(result.get("guard"), dict) or not isinstance(result.get("backup"), dict) or
                result["guard"].get("backupSha256") != result["backup"].get("sha256") or
                result["guard"].get("backupSize") != result["backup"].get("size")):
            raise ValueError("malformed_result")
        return {"ok":True,"outcome":"admitted","correlationId":correlation_id,
                "host":host,"deviceAlias":device,"result":result,"replayAllowed":False}
    except (TimeoutError, RuntimeError, UnicodeError, json.JSONDecodeError, ValueError):
        return {"ok":False,"outcome":"unknown","reason":"transport_or_result_unknown",
                "correlationId":correlation_id,"replayAllowed":False}


def _remote_status() -> str:
    helper = android_observation._canonical_cli_environment_source()
    return helper + r'''
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

adb, cli, serial, expected_avd, expected_api, root, correlation, timeout_text = sys.argv[1:]
timeout = int(timeout_text)
def read(argv):
    try:
        done = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired): return None
    if done.returncode or len(done.stdout) > 32768: return None
    try: return done.stdout.decode("utf-8", "strict").strip()
    except UnicodeError: return None
def shell(*words): return read([adb,"-s",serial,"shell","-T",*words])
uid = shell("id","-u")
api = shell("getprop","ro.build.version.sdk")
avds = {name for name in (shell("getprop","ro.kernel.qemu.avd_name"),
                         shell("getprop","ro.boot.qemu.avd_name")) if name}
device_ok = uid == "2000" and api == expected_api and avds == {expected_avd}
owner = None
revision = None
if device_ok:
    try:
        env = public_cli_environment(adb, Path(cli))
        done = subprocess.run([cli,"--json","--android","--serial",serial,"--timeout-seconds",timeout_text,"status"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=timeout, check=False, env=env)
        value = json.loads(done.stdout) if done.returncode == 0 and len(done.stdout) <= 32768 else None
        if (isinstance(value,dict) and value.get("ok") is True and value.get("final") is True and
                value.get("code") == "OK" and isinstance(value.get("controllerId"),str)):
            owner = value["controllerId"]
            if type(value.get("configurationRevision")) is int and value["configurationRevision"]>=0:
                revision = value["configurationRevision"]
    except (OSError, subprocess.TimeoutExpired, ValueError): pass
parent = Path(root)
directory = parent / ("android-readback-" + correlation)
state = "absent"
backup = None
try:
    parent_stat = parent.lstat()
    if not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid != os.getuid() or stat.S_IMODE(parent_stat.st_mode) != 0o700:
        state = "unsafe_root"
    else:
        try: directory_stat = directory.lstat()
        except FileNotFoundError: directory_stat = None
        if directory_stat is not None:
            if (not stat.S_ISDIR(directory_stat.st_mode) or directory_stat.st_uid != os.getuid() or
                    stat.S_IMODE(directory_stat.st_mode) != 0o700):
                state = "unsafe_directory"
            else:
                state = "directory_present"
                path = directory / "routing.json"
                try: file_stat = path.lstat()
                except FileNotFoundError: file_stat = None
                if file_stat is not None:
                    if (not stat.S_ISREG(file_stat.st_mode) or file_stat.st_uid != os.getuid() or
                            stat.S_IMODE(file_stat.st_mode) != 0o600 or
                            not 0 < file_stat.st_size <= 67108864):
                        state = "unsafe_backup"
                    else:
                        with path.open("rb") as handle: payload = handle.read(67108865)
                        if len(payload) != file_stat.st_size:
                            state = "changed_backup"
                        else:
                            state = "backup_present"
                            backup = {"path":str(path),"sha256":hashlib.sha256(payload).hexdigest(),"size":len(payload)}
                            try:
                                document=json.loads(payload.decode("utf-8","strict"))
                                rules=document.get("rules") if isinstance(document,dict) else None
                                valid=(isinstance(document,dict) and document.get("type")=="vpn_control_routing_rules" and
                                    document.get("version")==7 and isinstance(rules,dict) and
                                    isinstance(rules.get("ignore_rules"),bool) and
                                    isinstance(rules.get("block_quic_udp_443"),bool) and
                                    isinstance(rules.get("proxy_packages"),list) and
                                    all(isinstance(item,str) for item in rules["proxy_packages"]) and
                                    isinstance(rules.get("direct_domain_suffixes"),list) and
                                    all(isinstance(item,str) for item in rules["direct_domain_suffixes"]))
                                backup["formatValid"]=valid
                                backup["domainCount"]=len(rules["direct_domain_suffixes"]) if valid else None
                            except (UnicodeError,ValueError): backup["formatValid"]=False
except (OSError, ValueError):
    state = "observation_unknown"
print(json.dumps({"deviceIdentity":device_ok,"controllerId":owner,"configurationRevision":revision,
    "stage":state,"backup":backup}, separators=(",",":")))
'''


def readback_status(root: Path | str, host: str, device: str, correlation_id: str,
                    timeout_seconds: int = 45) -> dict[str, Any]:
    """Inspect one retained readback correlation without invoking a product write."""
    if not isinstance(correlation_id, str) or not _UUID.fullmatch(correlation_id):
        raise ValueError("Android readback status requires a UUID correlation")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 60:
        raise ValueError("Android readback status timeout must be 1..60 seconds")
    config = ssh_transport.load_config(root)
    if host not in config.hosts or device not in config.hosts[host].android_devices:
        raise ValueError("Unknown configured Android device")
    configured = config.hosts[host]
    connection = ssh_transport.connection_host(config, host)
    if connection.password is not None or configured.fixture_transfer_root is None:
        raise ValueError("Android readback status requires a private key route and fixture root")
    profile = android_observation._profile(configured.android_devices[device])
    argv = ssh_transport.build_ssh_argv(config, host, timeout_seconds,
        command=("python3", "-c", "exec(" + repr(_remote_status()) + ")",
            profile["adb"], profile["cli"], profile["serial"], profile["expectedAvd"],
            str(profile["api"]), str(configured.fixture_transfer_root), correlation_id,
            str(timeout_seconds)))
    try:
        code, output = android_observation._run_probe(argv, timeout_seconds)
        if code: raise RuntimeError("transport_failed")
        value = json.loads(output.decode("utf-8", "strict"))
        if (not isinstance(value, dict) or set(value) != {"deviceIdentity", "controllerId", "configurationRevision", "stage", "backup"} or
                not isinstance(value["deviceIdentity"], bool) or
                (value["controllerId"] is not None and not isinstance(value["controllerId"], str)) or
                (value["configurationRevision"] is not None and
                 (type(value["configurationRevision"]) is not int or value["configurationRevision"] < 0)) or
                value["stage"] not in {"absent", "unsafe_root", "unsafe_directory", "directory_present",
                    "unsafe_backup", "changed_backup", "backup_present", "observation_unknown"}):
            raise ValueError("malformed_status")
        return {"ok":True, "admissionReady":False,
                "outcome":"observed", "host":host,"deviceAlias":device,"correlationId":correlation_id,
                "result":value,"replayAllowed":False}
    except (TimeoutError, RuntimeError, UnicodeError, json.JSONDecodeError, ValueError):
        return {"ok":False,"outcome":"unknown","reason":"transport_or_status_unknown",
                "correlationId":correlation_id,"replayAllowed":False}


_ASYNC_SUBMIT = r'''
import base64,json,os,pathlib,stat,subprocess,sys
root,correlation,intent_json,worker_encoded=sys.argv[1:]
worker_source=base64.urlsafe_b64decode(worker_encoded.encode("ascii")).decode("utf-8","strict")
parent=pathlib.Path(root); pinfo=parent.lstat()
if not stat.S_ISDIR(pinfo.st_mode) or pinfo.st_uid!=os.getuid() or stat.S_IMODE(pinfo.st_mode)!=0o700: raise SystemExit(2)
job=parent/("android-readback-job-"+correlation)
job.mkdir(mode=0o700)
def durable(name,value):
 path=job/name; payload=json.dumps(value,sort_keys=True,separators=(",",":")).encode()+b"\n"
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
 with os.fdopen(fd,"wb") as out: out.write(payload); out.flush(); os.fsync(out.fileno())
 directory=os.open(job,os.O_RDONLY); os.fsync(directory); os.close(directory)
intent=json.loads(intent_json)
durable("intent.json",intent)
worker=job/"worker.py"
fd=os.open(worker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
with os.fdopen(fd,"w",encoding="utf-8") as out: out.write(worker_source); out.flush(); os.fsync(out.fileno())
process=subprocess.Popen([sys.executable,"-I","-B",str(worker),str(job)],stdin=subprocess.DEVNULL,
 stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
try: ticks=int(pathlib.Path(f"/proc/{process.pid}/stat").read_text(encoding="ascii").rsplit(")",1)[1].split()[19])
except (OSError,ValueError,IndexError):
 try:
  process.kill(); process.wait(timeout=3)
  print(json.dumps({"state":"unknown","correlationId":correlation,"reason":"identity_unavailable","cleanupConfirmed":True},separators=(",",":")))
 except (OSError,subprocess.TimeoutExpired):
  print(json.dumps({"state":"unknown","correlationId":correlation,"reason":"identity_unavailable","cleanupConfirmed":False},separators=(",",":")))
 raise SystemExit(0)
identity={"pid":process.pid,"startTicks":ticks}
try: durable("identity.json",identity)
except (OSError,ValueError):
 try:
  process.kill(); process.wait(timeout=3)
  print(json.dumps({"state":"unknown","correlationId":correlation,"reason":"identity_write_failed","cleanupConfirmed":True},separators=(",",":")))
 except (OSError,subprocess.TimeoutExpired):
  print(json.dumps({"state":"unknown","correlationId":correlation,"reason":"identity_write_failed","cleanupConfirmed":False},separators=(",",":")))
 raise SystemExit(0)
(job/"release").touch(exist_ok=False)
directory=os.open(job,os.O_RDONLY); os.fsync(directory); os.close(directory)
print(json.dumps({"state":"submitted","correlationId":correlation,"identity":identity},separators=(",",":")))
'''


def _async_worker_source(probe_source: str, args: list[str]) -> str:
    """Create the fixed detached worker; result publication is atomic and private."""
    return r'''import json,os,pathlib,subprocess,sys,time
job=pathlib.Path(sys.argv[1])
while not (job/"release").exists(): time.sleep(.02)
command=''' + repr(["python3", "-I", "-B", "-c", "exec(" + repr(probe_source) + ")", *args]) + r'''
try:
 done=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,timeout=420,check=False)
 if done.returncode or len(done.stdout)>16384: result={"state":"unknown","reason":"worker_failed"}
 else:
  value=json.loads(done.stdout)
  result={"state":"complete" if value.get("admitted") is True else "unknown",
          "result":value if value.get("admitted") is True else None,
          "reason":None if value.get("admitted") is True else value.get("reason","readback_failed")}
except (OSError,subprocess.TimeoutExpired,ValueError,UnicodeError): result={"state":"unknown","reason":"worker_unknown"}
path=job/"result.json"
temporary=job/"result.json.tmp"
payload=json.dumps(result,sort_keys=True,separators=(",",":")).encode()+b"\n"
fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
with os.fdopen(fd,"wb") as out: out.write(payload); out.flush(); os.fsync(out.fileno())
os.replace(temporary,path)
directory=os.open(job,os.O_RDONLY); os.fsync(directory); os.close(directory)
'''


_ASYNC_STATUS = r'''
import hashlib,json,os,pathlib,re,stat,sys
root,correlation,expected_json=sys.argv[1:]
def result(state,reason=None,**extra):
 print(json.dumps({"state":state,"reason":reason,"correlationId":correlation,**extra},separators=(",",":")))
 raise SystemExit(0)
job=pathlib.Path(root)/("android-readback-job-"+correlation)
try:
 info=job.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: result("unknown","unsafe_job")
 def private(name):
  path=job/name; fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)); meta=os.fstat(fd)
  if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.getuid() or stat.S_IMODE(meta.st_mode)!=0o600: result("unknown","unsafe_"+name)
  raw=os.read(fd,16385); os.close(fd)
  if len(raw)>16384: result("unknown","oversized_"+name)
  return json.loads(raw)
 intent=private("intent.json")
 if intent!=json.loads(expected_json): result("unknown","intent_mismatch")
 if intent.get("fixtureRoot")!=root: result("unknown","fixture_root_mismatch")
 identity=private("identity.json")
 pid=identity.get("pid"); ticks=identity.get("startTicks")
 if type(pid) is not int or type(ticks) is not int or pid<=0 or ticks<=0: result("unknown","identity_invalid")
 try: receipt=private("result.json")
 except FileNotFoundError: receipt=None
 if receipt is not None:
  if receipt.get("state")=="complete" and isinstance(receipt.get("result"),dict):
   value=receipt["result"]; guard=value.get("guard"); backup=value.get("backup")
   package=value.get("package"); device=value.get("device")
   if (value.get("admitted") is not True or not isinstance(guard,dict) or
       not isinstance(backup,dict) or not isinstance(package,dict) or not isinstance(device,dict) or
       package.get("baseSha256")!=intent.get("expectedBaseSha256") or
       device.get("uid")!="2000" or device.get("avd")!=intent.get("expectedAvd") or
       device.get("api")!=intent.get("api") or
       not isinstance(guard.get("controllerId"),str) or not guard["controllerId"] or
       type(guard.get("configurationRevision")) is not int or guard["configurationRevision"]<0 or
       not isinstance(backup.get("sha256"),str) or
       re.fullmatch(r"[0-9a-f]{64}",backup["sha256"]) is None or
       guard.get("backupSha256")!=backup["sha256"] or
       type(backup.get("size")) is not int or not 0<backup["size"]<=67108864 or
       guard.get("backupSize")!=backup["size"] or
       backup.get("type")!="vpn_control_routing_rules" or backup.get("version")!=7 or
       backup.get("rulesValid") is not True): result("unknown","terminal_binding_invalid",identity=identity)
   path=pathlib.Path(root)/("android-readback-"+correlation)/"routing.json"
   if backup.get("path")!=str(path): result("unknown","backup_path_mismatch",identity=identity)
   parent_info=path.parent.lstat(); file_info=path.lstat()
   if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid!=os.getuid() or
       stat.S_IMODE(parent_info.st_mode)!=0o700 or not stat.S_ISREG(file_info.st_mode) or
       file_info.st_uid!=os.getuid() or stat.S_IMODE(file_info.st_mode)!=0o600 or
       file_info.st_size!=backup["size"]): result("unknown","backup_private_bytes_invalid",identity=identity)
   digest=hashlib.sha256()
   fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
   with os.fdopen(fd,"rb") as content:
    remaining=backup["size"]
    while remaining:
     block=content.read(min(65536,remaining))
     if not block: result("unknown","backup_truncated",identity=identity)
     digest.update(block); remaining-=len(block)
    if content.read(1): result("unknown","backup_grew",identity=identity)
   if digest.hexdigest()!=backup["sha256"]: result("unknown","backup_hash_mismatch",identity=identity)
   result("complete",None,identity=identity,receipt=receipt)
  result("unknown",receipt.get("reason","worker_unknown"),identity=identity)
 try:
  fields=pathlib.Path(f"/proc/{pid}/stat").read_text(encoding="ascii").rsplit(")",1)[1].split()
  running=fields[0]!="Z" and int(fields[19])==ticks
 except (OSError,ValueError,IndexError): running=False
 result("running" if running else "unknown",None if running else "missing_worker_receipt",identity=identity)
except FileNotFoundError: result("unknown","missing_job_or_intent")
except (OSError,ValueError,TypeError,KeyError): result("unknown","status_unavailable")
'''


def _async_journal(root: Path | str, correlation_id: str) -> Path:
    return Path(root).resolve() / ".rag_index" / "android-admission-jobs" / (correlation_id + ".json")


def _save_async_intent(root: Path | str, intent: dict[str, Any]) -> None:
    path = _async_journal(root, intent["correlationId"])
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.parent.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ValueError("Android async journal is not private")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(json.dumps(intent, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        out.flush(); os.fsync(out.fileno())
    directory = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(directory)
    finally: os.close(directory)


def _load_async_intent(root: Path | str, correlation_id: str) -> dict[str, Any] | None:
    path = _async_journal(root, correlation_id)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
                return None
            payload = source.read(8193)
        if len(payload) > 8192: return None
        value = json.loads(payload)
        return value if isinstance(value, dict) and value.get("correlationId") == correlation_id else None
    except (OSError, ValueError):
        return None


def async_start(root: Path | str, host: str, device: str, correlation_id: str,
                expected_base_sha256: str) -> dict[str, Any]:
    """Journal one fixed Android export before a detached remote submission."""
    if not isinstance(correlation_id, str) or not _UUID.fullmatch(correlation_id):
        raise ValueError("Android async readback requires a UUID correlation")
    if not isinstance(expected_base_sha256, str) or not _SHA.fullmatch(expected_base_sha256):
        raise ValueError("Android async readback requires an exact base APK hash")
    config = ssh_transport.load_config(root)
    if host not in config.hosts or device not in config.hosts[host].android_devices:
        raise ValueError("Unknown configured Android device")
    configured = config.hosts[host]
    if ssh_transport.connection_host(config, host).password is not None or configured.fixture_transfer_root is None:
        raise ValueError("Android async readback requires a private key route and fixture root")
    profile = android_observation._profile(configured.android_devices[device])
    intent = {"host":host,"device":device,"correlationId":correlation_id,
              "expectedBaseSha256":expected_base_sha256,"serial":profile["serial"],
              "expectedAvd":profile["expectedAvd"],"api":profile["api"],
              "fixtureRoot":str(configured.fixture_transfer_root)}
    _save_async_intent(root, intent)
    args = [profile["adb"], profile["cli"], profile["serial"], profile["expectedAvd"],
            str(profile["api"]), str(configured.fixture_transfer_root), correlation_id,
            expected_base_sha256, "60"]
    encoded_worker = base64.urlsafe_b64encode(_async_worker_source(_remote_probe(), args).encode("utf-8")).decode("ascii")
    argv = ssh_transport.build_ssh_argv(config, host, 60,
        command=("python3", "-I", "-B", "-c", "exec(" + repr(_ASYNC_SUBMIT) + ")",
                 str(configured.fixture_transfer_root), correlation_id,
                 json.dumps(intent, sort_keys=True, separators=(",", ":")),
                 encoded_worker))
    try:
        code, output = android_observation._run_probe(argv, 60)
        value = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
        if isinstance(value, dict) and value.get("state") == "submitted" and value.get("correlationId") == correlation_id:
            return {"ok":True,"state":"submitted","correlationId":correlation_id,
                    "identity":value.get("identity"),"replayAllowed":False}
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
        pass
    return {"ok":False,"state":"unknown","correlationId":correlation_id,"replayAllowed":False}


def async_status(root: Path | str, correlation_id: str) -> dict[str, Any]:
    """Observe only the job named by the durable local intent; never relaunch."""
    if not isinstance(correlation_id, str) or not _UUID.fullmatch(correlation_id):
        raise ValueError("Android async status requires a UUID correlation")
    intent = _load_async_intent(root, correlation_id)
    if intent is None:
        return {"ok":False,"state":"unknown","reason":"missing_local_intent",
                "correlationId":correlation_id,"replayAllowed":False}
    config = ssh_transport.load_config(root)
    host = intent["host"]
    if host not in config.hosts or ssh_transport.connection_host(config, host).password is not None:
        return {"ok":False,"state":"unknown","reason":"route_unavailable",
                "correlationId":correlation_id,"replayAllowed":False}
    fixture_root = config.hosts[host].fixture_transfer_root
    if fixture_root is None:
        return {"ok":False,"state":"unknown","reason":"fixture_root_unavailable",
                "correlationId":correlation_id,"replayAllowed":False}
    argv = ssh_transport.build_ssh_argv(config, host, 30,
        command=("python3", "-I", "-B", "-c", "exec(" + repr(_ASYNC_STATUS) + ")",
                 str(fixture_root), correlation_id,
                 json.dumps(intent, sort_keys=True, separators=(",", ":"))))
    try:
        code, output = android_observation._run_probe(argv, 30)
        value = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
        if (isinstance(value, dict) and value.get("correlationId") == correlation_id and
                value.get("state") in {"running", "complete", "unknown"}):
            return {"ok":value["state"] == "complete", **value, "replayAllowed":False}
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
        pass
    return {"ok":False,"state":"unknown","reason":"transport_or_receipt_unknown",
            "correlationId":correlation_id,"replayAllowed":False}


def async_collect(root: Path | str, correlation_id: str) -> dict[str, Any]:
    """Collect a terminal exact-correlation receipt without creating work."""
    observed = async_status(root, correlation_id)
    if observed.get("state") != "complete":
        return {**observed, "ok":False}
    receipt = observed.get("receipt")
    result = receipt.get("result") if isinstance(receipt, dict) else None
    intent = _load_async_intent(root, correlation_id)
    guard = result.get("guard") if isinstance(result, dict) else None
    backup = result.get("backup") if isinstance(result, dict) else None
    package = result.get("package") if isinstance(result, dict) else None
    device = result.get("device") if isinstance(result, dict) else None
    if (not isinstance(intent, dict) or not isinstance(result, dict) or result.get("admitted") is not True or
            not isinstance(guard, dict) or not isinstance(backup, dict) or
            not isinstance(package, dict) or not isinstance(device, dict) or
            package.get("baseSha256") != intent.get("expectedBaseSha256") or
            device.get("uid") != "2000" or device.get("avd") != intent.get("expectedAvd") or
            device.get("api") != intent.get("api") or
            not isinstance(guard.get("controllerId"), str) or not guard["controllerId"] or
            type(guard.get("configurationRevision")) is not int or guard["configurationRevision"] < 0 or
            not isinstance(backup.get("sha256"), str) or not _SHA.fullmatch(backup["sha256"]) or
            guard.get("backupSha256") != backup["sha256"] or
            type(backup.get("size")) is not int or not 0 < backup["size"] <= 67_108_864 or
            guard.get("backupSize") != backup["size"] or
            not isinstance(intent.get("fixtureRoot"), str) or
            backup.get("path") != intent["fixtureRoot"] + "/android-readback-" + correlation_id + "/routing.json" or
            backup.get("type") != "vpn_control_routing_rules" or backup.get("version") != 7 or
            backup.get("rulesValid") is not True):
        return {"ok":False,"state":"unknown","reason":"invalid_terminal_receipt",
                "correlationId":correlation_id,"replayAllowed":False}
    return {"ok":True,"state":"complete","correlationId":correlation_id,
            "result":result,"identity":observed.get("identity"),"replayAllowed":False}

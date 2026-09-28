"""Fixed read-only Android package/control admission with a private routing backup.

The product actions are reads.  The backup is written only in the configured
private fixture root; an uncertain SSH result preserves that directory for
inspection and never retries a product mutation.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path
import re
from typing import Any, Mapping

try:
    from . import android_observation, ssh_transport
except ImportError:  # standalone MCP loader
    import android_observation
    import ssh_transport


_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")


def _guard_source() -> str:
    """Ship the canonical pure preflight guard, rather than a diverging copy."""
    path = Path(__file__).resolve().parents[1] / "scripts" / "android_fixture_preflight.py"
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    names = {"require_terminal_operation_history", "admission_readback_guard"}
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
def read(argv, env=None, *, max_bytes=67108864):
    try:
        done = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=timeout, env=env, check=False)
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
routing = envelope("routing", "show")

parent = Path(root)
metadata = parent.lstat()
if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
    fail("private_root")
directory = parent / ("android-readback-" + correlation)
directory.mkdir(mode=0o700)
backup_path = directory / "routing.json"
os.umask(0o077)
try:
    export = read([cli, "--android", "--serial", serial, "--timeout-seconds", timeout_text,
        "routing", "export", "--output", str(backup_path), "--format", "json"],
        environment, max_bytes=16384)
    if export: raise RuntimeError("unexpected_export_stdout")
    file_metadata = backup_path.lstat()
    if not stat.S_ISREG(file_metadata.st_mode) or file_metadata.st_uid != os.getuid() or stat.S_IMODE(file_metadata.st_mode) != 0o600:
        raise RuntimeError("backup_not_private")
    if not 0 < file_metadata.st_size <= 67108864: raise RuntimeError("backup_size")
    with backup_path.open("rb") as handle: payload = handle.read(67108865)
    if len(payload) != file_metadata.st_size: raise RuntimeError("backup_changed")
    document = json.loads(payload.decode("utf-8", "strict"))
    if not isinstance(document, dict): raise RuntimeError("backup_document")
    show = routing.get("data", {}).get("routing")
    backup = {"path":str(backup_path), "sha256":hashlib.sha256(payload).hexdigest(),
        "size":len(payload), "type":document.get("type"), "version":document.get("version"),
        "rulesType":"object" if isinstance(document.get("rules"), dict) else "invalid",
        "matchesReadback":isinstance(show, dict) and document.get("rules") == show.get("rules")}
    guard = admission_readback_guard(status, operations, routing, backup)
except Exception:
    # Retain any partial backup and correlation.  The caller must inspect it;
    # it must never silently become an admitted snapshot.
    fail("readback_or_backup_unknown")

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
except (OSError, ValueError):
    state = "observation_unknown"
print(json.dumps({"deviceIdentity":device_ok,"controllerId":owner,"stage":state,"backup":backup}, separators=(",",":")))
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
        if (not isinstance(value, dict) or set(value) != {"deviceIdentity", "controllerId", "stage", "backup"} or
                not isinstance(value["deviceIdentity"], bool) or
                (value["controllerId"] is not None and not isinstance(value["controllerId"], str)) or
                value["stage"] not in {"absent", "unsafe_root", "unsafe_directory", "directory_present",
                    "unsafe_backup", "changed_backup", "backup_present", "observation_unknown"}):
            raise ValueError("malformed_status")
        return {"ok":True, "admissionReady":False,
                "outcome":"observed", "host":host,"deviceAlias":device,"correlationId":correlation_id,
                "result":value,"replayAllowed":False}
    except (TimeoutError, RuntimeError, UnicodeError, json.JSONDecodeError, ValueError):
        return {"ok":False,"outcome":"unknown","reason":"transport_or_status_unknown",
                "correlationId":correlation_id,"replayAllowed":False}

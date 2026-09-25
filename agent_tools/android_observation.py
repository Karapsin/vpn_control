"""Bounded, read-only Android state observation over an approved SSH route.

This deliberately has no Android lifecycle operations: it cannot boot, stop,
root, install, refresh, or otherwise change an emulator.  It is intended for
diagnosing an already observed native failure when the transport is available.
"""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path, PurePosixPath
import re
import select
import subprocess
import time
from typing import Any, Mapping

try:
    from . import ssh_transport
except ImportError:  # pragma: no cover - standalone MCP loader
    import ssh_transport


MAX_OUTPUT_BYTES = 16_384
_SERIAL = re.compile(r"^emulator-[0-9]{4}$")
_AVD = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. -]{0,127}$")
_PROXY_FIELDS = ("http_proxy", "global_http_proxy_host", "global_http_proxy_port",
                 "global_http_proxy_pac", "global_http_proxy_exclusion_list")


class AndroidObservationError(ValueError):
    """The caller supplied an unsafe Android observation profile."""


def _remote_path(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
        raise AndroidObservationError(f"Android profile {name} is invalid.")
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts or path == PurePosixPath("/"):
        raise AndroidObservationError(f"Android profile {name} must be an absolute remote POSIX path.")
    return str(path)


def _profile(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"adb", "cli", "serial", "expectedAvd", "api"}:
        raise AndroidObservationError("Android profile has unsupported or missing fields.")
    serial = value["serial"]
    avd = value["expectedAvd"]
    api = value["api"]
    if not isinstance(serial, str) or not _SERIAL.fullmatch(serial):
        raise AndroidObservationError("Android profile serial must be an emulator-#### serial.")
    if not isinstance(avd, str) or not _AVD.fullmatch(avd):
        raise AndroidObservationError("Android profile expectedAvd is invalid.")
    if isinstance(api, bool) or not isinstance(api, int) or api not in (29, 35):
        raise AndroidObservationError("Android profile api must be 29 or 35.")
    cli = _remote_path(value["cli"], "cli")
    if cli.lower().endswith(".py"):
        raise AndroidObservationError("Android profile cli must name a packaged CLI executable.")
    return {"adb": _remote_path(value["adb"], "adb"), "cli": cli,
            "serial": serial, "expectedAvd": avd, "api": api}


def _canonical_cli_environment_source() -> str:
    """Extract the reviewed helper instead of carrying a stale second copy."""
    source_path = Path(__file__).resolve().parents[1] / "scripts" / "android_no_update_tls_preflight.py"
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(source_path))
    function = next((node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name == "public_cli_environment"), None)
    if function is None:
        raise RuntimeError("Canonical Android CLI environment helper is unavailable.")
    segment = ast.get_source_segment(source, function)
    if not segment:
        raise RuntimeError("Canonical Android CLI environment helper cannot be extracted.")
    # These are the helper's declared standard-library dependencies.  Keeping
    # this list tiny makes the remotely executed observer auditable.
    return "import os\nimport shutil\nfrom pathlib import Path\n" + segment + "\n"


def _remote_probe() -> str:
    helper = _canonical_cli_environment_source()
    return helper + r'''
import json
import re
import select
import subprocess
import sys
import time

adb, cli, serial, expected_avd, expected_api, timeout = sys.argv[1:]
timeout = int(timeout)
def invoke(argv, env=None, accept_failure=False):
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=env)
    except OSError:
        return None
    try:
        chunks = []; received = 0; deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0: return None
            ready, _, _ = select.select([process.stdout], [], [], remaining)
            if ready:
                chunk = os.read(process.stdout.fileno(), min(1024, 8193 - received))
                if chunk:
                    chunks.append(chunk); received += len(chunk)
                    if received > 8192: return None
                    continue
                if process.poll() is not None:
                    if process.returncode and not accept_failure: return None
                    return b"".join(chunks).decode("utf-8").strip()
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    finally:
        if process.poll() is None: process.kill()
        process.wait()
        process.stdout.close()
def adb_shell(*words):
    return invoke([adb, "-s", serial, "shell", *words])
uid = adb_shell("id", "-u")
sdk = adb_shell("getprop", "ro.build.version.sdk")
kernel_avd = adb_shell("getprop", "ro.kernel.qemu.avd_name")
boot_avd = adb_shell("getprop", "ro.boot.qemu.avd_name")
proxy = {name: adb_shell("settings", "get", "global", name) for name in ''' + repr(_PROXY_FIELDS) + r'''}
def redact_proxy(value):
    # Preserve only known diagnostic-safe values.  A global setting can carry a
    # URI with credentials, so arbitrary values become a category, never text.
    if value is None: return {"state": "unknown"}
    value = value.strip()
    if not value: return {"state": "unset"}
    if value == "null": return {"state": "null", "value": value}
    if value == ":0": return {"state": "disabled", "value": value}
    if re.fullmatch(r"(?:127\.0\.0\.1|localhost):[1-9][0-9]{0,4}", value) or re.fullmatch(r"\[::1\]:[1-9][0-9]{0,4}", value):
        return {"state": "loopback", "value": value}
    return {"state": "set"}
proxy = {name: redact_proxy(value) for name, value in proxy.items()}
baseline = {"uid": uid, "sdk": sdk, "kernelAvd": kernel_avd, "bootAvd": boot_avd, "proxy": proxy}
# Match the canonical fixture admission policy: API 29 may not expose the
# secondary boot property, while two populated properties must agree.
avd_identities = {value for value in (kernel_avd, boot_avd) if value}
if uid != "2000" or sdk != str(expected_api) or len(avd_identities) != 1 or expected_avd not in avd_identities:
    print(json.dumps({"baseline": baseline, "admitted": False}, separators=(",", ":")))
    raise SystemExit(0)
environment = public_cli_environment(adb, Path(cli))
status = invoke([cli, "--json", "--android", "--serial", serial, "--timeout-seconds", str(timeout), "status"], environment, True)
operations = invoke([cli, "--json", "--android", "--serial", serial, "--timeout-seconds", str(timeout), "operations", "list"], environment, True)
def summary(raw, operations_list=False):
    try:
        item = json.loads(raw)
        if not isinstance(item, dict): raise ValueError
        data = item.get("data")
        if not isinstance(item.get("ok"), bool) or not isinstance(item.get("code"), str) or not isinstance(item.get("final"), bool) or not isinstance(item.get("controllerId"), str) or not item["controllerId"] or item.get("operationId") is not None and not isinstance(item.get("operationId"), str): raise ValueError
        result = {key: item.get(key) for key in ("ok", "code", "final", "controllerId", "operationId")}
        if operations_list:
            if not isinstance(data, dict) or not isinstance(data.get("operations"), list): raise ValueError
            result["operationCount"] = len(data["operations"])
        return result
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
print(json.dumps({"baseline": baseline, "admitted": True, "status": summary(status),
                  "operations": summary(operations, True)}, separators=(",", ":")))
'''


def _run_probe(argv: list[str], timeout_seconds: int) -> tuple[int, bytes]:
    """Run one SSH observer, retaining at most MAX_OUTPUT_BYTES."""
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError as exc:
        raise RuntimeError("transport_unavailable") from exc
    assert process.stdout is not None
    chunks: list[bytes] = []; received = 0; deadline = time.monotonic() + timeout_seconds + 1
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise TimeoutError
            ready, _, _ = select.select([process.stdout], [], [], remaining)
            if ready:
                chunk = os.read(process.stdout.fileno(), min(1024, MAX_OUTPUT_BYTES + 1 - received))
                if chunk:
                    chunks.append(chunk); received += len(chunk)
                    if received > MAX_OUTPUT_BYTES: raise RuntimeError("oversized_output")
                    continue
                if process.poll() is not None: return process.returncode, b"".join(chunks)
    finally:
        if process.poll() is None: process.kill()
        process.wait()
        process.stdout.close()


def _unknown(reason: str) -> dict[str, Any]:
    return {"available": False, "outcome": "unknown", "reason": reason,
            "baseline": None, "ownerConsistency": "unknown", "status": None, "operations": None}


def _result(returncode: int, output: bytes) -> dict[str, Any]:
    if returncode: return _unknown("transport_failed")
    try:
        item = json.loads(output.decode("utf-8"))
        baseline = item["baseline"]
        if not isinstance(item, dict) or not isinstance(baseline, dict) or set(baseline) != {"uid", "sdk", "kernelAvd", "bootAvd", "proxy"}:
            raise ValueError
        proxy = baseline["proxy"]
        if not isinstance(proxy, dict) or set(proxy) != set(_PROXY_FIELDS): raise ValueError
        if not all(isinstance(value, str) for value in [baseline["uid"], baseline["sdk"], baseline["kernelAvd"], baseline["bootAvd"]]): raise ValueError
        for value in proxy.values():
            if not isinstance(value, dict) or set(value) - {"state", "value"} or not isinstance(value.get("state"), str): raise ValueError
            if value["state"] not in {"unknown", "unset", "null", "disabled", "loopback", "set"}: raise ValueError
            if "value" in value and not isinstance(value["value"], str): raise ValueError
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        return _unknown("malformed_observation")
    if item.get("admitted") is not True:
        return {"available": False, "outcome": "unavailable", "reason": "device_admission_failed", "baseline": baseline,
                "ownerConsistency": "unknown", "status": None, "operations": None}
    status, operations = item.get("status"), item.get("operations")
    summary_fields = {"ok", "code", "final", "controllerId", "operationId"}
    operation_fields = summary_fields | {"operationCount"}
    def valid_summary(value: Any, fields: set[str]) -> bool:
        return (isinstance(value, dict) and set(value) == fields and isinstance(value.get("ok"), bool)
                and isinstance(value.get("code"), str) and isinstance(value.get("final"), bool)
                and isinstance(value.get("controllerId"), str) and bool(value["controllerId"])
                and (value.get("operationId") is None or isinstance(value.get("operationId"), str))
                and ("operationCount" not in value or isinstance(value["operationCount"], int)
                     and not isinstance(value["operationCount"], bool) and value["operationCount"] >= 0))
    if not valid_summary(status, summary_fields) or not valid_summary(operations, operation_fields):
        return {"available": False, "outcome": "unknown", "reason": "cli_observation_failed", "baseline": baseline,
                "ownerConsistency": "unknown", "status": None, "operations": None}
    left, right = status.get("controllerId"), operations.get("controllerId")
    owner = "consistent" if isinstance(left, str) and left and left == right else "unknown"
    if status.get("ok") is not True or operations.get("ok") is not True:
        return {"available": False, "outcome": "unavailable", "reason": "cli_unsuccessful", "baseline": baseline,
                "ownerConsistency": owner, "status": status, "operations": operations}
    return {"available": owner == "consistent", "outcome": "available" if owner == "consistent" else "unknown",
            "reason": "ok" if owner == "consistent" else "owner_replaced", "baseline": baseline,
            "ownerConsistency": owner, "status": status, "operations": operations}


def observe(root: Path | str, host: str, device_profile: Mapping[str, Any], timeout_seconds: int = 30) -> dict[str, Any]:
    """Observe one admitted emulator once; every uncertain outcome remains unknown."""
    profile = _profile(device_profile)
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 60:
        raise AndroidObservationError("Android observation timeout must be between 1 and 60 seconds.")
    try:
        config = ssh_transport.load_config(root)
        if host not in config.hosts: raise AndroidObservationError("Unknown VM host alias.")
        connection = ssh_transport.connection_host(config, host)
        if connection.password is not None: raise AndroidObservationError("Android observation requires key or agent SSH authentication.")
        argv = ssh_transport.build_ssh_argv(config, host, timeout_seconds,
            command=("python3", "-c", "exec(" + repr(_remote_probe()) + ")", profile["adb"], profile["cli"], profile["serial"], profile["expectedAvd"], str(profile["api"]), str(timeout_seconds)))
        code, output = _run_probe(argv, timeout_seconds)
        return _result(code, output)
    except (ssh_transport.SshConfigError, AndroidObservationError):
        raise
    except TimeoutError:
        return _unknown("timeout")
    except RuntimeError as exc:
        return _unknown(str(exc) if str(exc) in {"transport_unavailable", "oversized_output"} else "transport_failed")

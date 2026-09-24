"""Recover the one verified API29 stale loopback proxy without replaying writes.

Android 10 observes the deprecated ``http_proxy`` setting. Writing ``:0`` invokes
ProxyTracker's clear-and-broadcast path; deleting the stored host/port fields
alone leaves its in-memory proxy in place. This helper admits only a configured
owned emulator, a stopped app, absent stored proxy fields, and fresh independent
NetworkMonitor evidence for the caller's exact task-owned loopback port.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import uuid
from typing import Any, Mapping

try:
    from . import android_observation, ssh_transport
except ImportError:  # pragma: no cover - standalone MCP loader
    import android_observation
    import ssh_transport


_FIELDS = (
    "http_proxy", "global_http_proxy_host", "global_http_proxy_port",
    "global_proxy_pac_url", "global_http_proxy_exclusion_list",
)
_CLEARED = (":0", "", "0", "", "")
_BASELINE = ("null",) * 5
_RELATIVE = Path(".rag_index") / "android-proxy-recovery"
_LOG_LIMIT = 12000
_EVIDENCE_AGE_SECONDS = 600


class AndroidProxyRecoveryError(ValueError):
    """The request or private evidence store is unsafe."""


def _identity(root: Path | str, host: str, device: str, expected_port: int,
              correlation_id: str) -> tuple[Path, dict[str, Any], Mapping[str, Any]]:
    if not isinstance(host, str) or not host or not isinstance(device, str) or not device:
        raise AndroidProxyRecoveryError("Configured host and device aliases are required.")
    try:
        correlation_id = str(uuid.UUID(correlation_id))
    except (ValueError, AttributeError, TypeError) as error:
        raise AndroidProxyRecoveryError("Recovery correlation must be a UUID.") from error
    if isinstance(expected_port, bool) or not isinstance(expected_port, int) or not 1 <= expected_port <= 65535:
        raise AndroidProxyRecoveryError("Expected loopback port is invalid.")
    config = ssh_transport.load_config(root)
    target = config.hosts.get(host)
    if target is None or device not in target.android_devices:
        raise AndroidProxyRecoveryError("Configured Android device is unavailable.")
    profile = android_observation._profile(target.android_devices[device])
    if profile["api"] != 29:
        raise AndroidProxyRecoveryError("Recovery is limited to a configured API29 emulator.")
    root_path = Path(root).resolve(strict=True)
    return root_path, {"host": host, "device": device, "expectedPort": expected_port,
                       "correlationId": correlation_id, "serial": profile["serial"],
                       "expectedAvd": profile["expectedAvd"]}, profile


def _private_directory(root: Path) -> Path:
    if os.name != "posix":
        raise AndroidProxyRecoveryError("Private recovery evidence requires POSIX ownership checks.")
    base = root / ".rag_index"
    directory = root / _RELATIVE
    for path in (base, directory):
        if path.exists() or path.is_symlink():
            metadata = path.lstat()
            if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
                raise AndroidProxyRecoveryError("Recovery evidence directory is not private.")
        else:
            path.mkdir(mode=0o700)
    return directory


def _write_new(path: Path, value: Mapping[str, Any]) -> None:
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as file:
        file.write(encoded)
        file.flush()
        os.fsync(file.fileno())
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _read(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.getuid() or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise AndroidProxyRecoveryError("Recovery evidence file is not private.")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AndroidProxyRecoveryError("Recovery evidence is malformed.")
    return value


def _invoke(root: Path, host: str, profile: Mapping[str, Any], directory: Path,
            label: str, words: list[str], timeout: int = 30) -> tuple[int | None, str, str]:
    """Record complete SSH streams before interpreting a command outcome."""
    config = ssh_transport.load_config(root)
    argv = ssh_transport.build_ssh_argv(config, host, min(timeout, 60), command=words)
    try:
        process = subprocess.run(argv, capture_output=True, timeout=timeout + 5)
        status: int | None = process.returncode
        stdout = process.stdout.decode("utf-8", "replace")
        stderr = process.stderr.decode("utf-8", "replace")
    except subprocess.TimeoutExpired as error:
        status = None
        stdout = (error.stdout or b"").decode("utf-8", "replace")
        stderr = (error.stderr or b"").decode("utf-8", "replace")
    except OSError as error:
        status, stdout, stderr = None, "", f"{type(error).__name__}: {error}"
    _write_new(directory / f"{time.time_ns()}-{uuid.uuid4().hex}-{label}.json", {
        "label": label, "exitCode": status, "stdout": stdout, "stderr": stderr,
        "atEpoch": time.time(),
    })
    return status, stdout, stderr


def _adb(root: Path, host: str, profile: Mapping[str, Any], directory: Path,
         label: str, *args: str, timeout: int = 30) -> tuple[int | None, str]:
    code, output, _ = _invoke(root, host, profile, directory, label,
                              [profile["adb"], "-s", profile["serial"], *args], timeout)
    return code, output.strip()


def _cli(root: Path, host: str, profile: Mapping[str, Any], directory: Path,
         label: str, *args: str) -> tuple[int | None, dict[str, Any] | None]:
    path = str(Path(profile["adb"]).parent)
    command = ["env", f"PATH={path}:/usr/local/bin:/usr/bin:/bin", profile["cli"],
               "--json", "--android", "--serial", profile["serial"], "--timeout-seconds", "30", *args]
    code, output, _ = _invoke(root, host, profile, directory, label, command, 35)
    try:
        value = json.loads(output)
    except (TypeError, ValueError):
        return code, None
    return code, value if isinstance(value, dict) else None


def _stored(root: Path, host: str, profile: Mapping[str, Any], directory: Path,
            prefix: str) -> tuple[str, ...] | None:
    values = []
    for field in _FIELDS:
        code, value = _adb(root, host, profile, directory, f"{prefix}-{field}",
                           "shell", "settings", "get", "global", field)
        if code != 0:
            return None
        values.append(value)
    return tuple(values)


def _admission(root: Path, host: str, profile: Mapping[str, Any], directory: Path,
               prefix: str) -> tuple[str | None, str]:
    for key, expected in (("id", "2000"), ("getprop ro.build.version.sdk", "29")):
        args = ("shell", "id", "-u") if key == "id" else ("shell", "getprop", "ro.build.version.sdk")
        code, value = _adb(root, host, profile, directory, f"{prefix}-{key.split()[0]}", *args)
        if code != 0 or value != expected:
            return None, "device_admission_failed"
    avds = []
    for key in ("ro.kernel.qemu.avd_name", "ro.boot.qemu.avd_name"):
        code, value = _adb(root, host, profile, directory, f"{prefix}-{key.split('.')[-1]}",
                           "shell", "getprop", key)
        if code != 0:
            return None, "device_admission_failed"
        if value:
            avds.append(value)
    if set(avds) != {profile["expectedAvd"]}:
        return None, "device_admission_failed"
    code, status = _cli(root, host, profile, directory, f"{prefix}-status", "status")
    if code != 0 or not isinstance(status, dict) or status.get("ok") is not True or status.get("final") is not True:
        return None, "status_unknown"
    data = status.get("data")
    if not isinstance(data, dict) or data.get("runtimeRunning") is not False or data.get("runtimeObservation") != "stopped":
        return None, "runtime_not_stopped"
    code, operations = _cli(root, host, profile, directory, f"{prefix}-operations", "operations", "list")
    if code != 0 or not isinstance(operations, dict) or operations.get("ok") is not True or operations.get("final") is not True or operations.get("controllerId") != status.get("controllerId"):
        return None, "operations_unknown"
    listed = operations.get("data", {}).get("operations") if isinstance(operations.get("data"), dict) else None
    if not isinstance(listed, list) or any(not isinstance(item, dict) or item.get("final") is not True for item in listed):
        return None, "active_or_unknown_operation"
    owner = status.get("controllerId")
    if not isinstance(owner, str) or not owner:
        return None, "owner_unknown"
    return owner, "ok"


def _log_epoch(line: str) -> float | None:
    try:
        return float(line.split(" ", 1)[0])
    except (ValueError, IndexError):
        return None


def _network_evidence(log: str, expected_port: int, *, after: float | None = None) -> bool:
    endpoint = f"/127.0.0.1:{expected_port}"
    for line in log.splitlines():
        when = _log_epoch(line)
        if when is None or after is not None and when <= after:
            continue
        if after is None and when < time.time() - _EVIDENCE_AGE_SECONDS:
            continue
        if "NetworkMonitor/" in line and "Failed to connect to " + endpoint in line:
            return True
    return False


def _clear_evidence(log: str, started: float, expected_port: int) -> tuple[bool, bool]:
    broadcast = None
    for line in log.splitlines():
        when = _log_epoch(line)
        if when is None or when < started - 1:
            continue
        if "ProxyTracker: sending Proxy Broadcast for [] 0 xl=" in line:
            broadcast = when
    if broadcast is None:
        return False, False
    successes = [line for line in log.splitlines()
                 if (_log_epoch(line) or 0) > broadcast and "NetworkMonitor/" in line
                 and ("PROBE_HTTP " in line or "PROBE_HTTPS " in line) and "ret=204" in line]
    stale = _network_evidence(log, expected_port, after=broadcast)
    return True, bool(successes) and not stale


def _result(identity: Mapping[str, Any], state: str, reason: str,
            directory: Path) -> dict[str, Any]:
    return {"ok": state == "complete", "state": state, "reason": reason,
            "identity": dict(identity), "evidencePath": str(directory)}


def recover_owned_stale_proxy(root: Path | str, host: str, device: str,
                              expected_port: int, correlation_id: str) -> dict[str, Any]:
    """Clear a verified stale task proxy once; retrying a correlation only observes."""
    root_path, identity, profile = _identity(root, host, device, expected_port, correlation_id)
    directory = _private_directory(root_path) / identity["correlationId"]
    if directory.exists():
        return observe_recovery(root_path, host, device, identity)
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        return observe_recovery(root_path, host, device, identity)
    if _stored(root_path, host, profile, directory, "before") != _BASELINE:
        return _result(identity, "rejected", "configured_or_unknown_proxy", directory)
    owner, reason = _admission(root_path, host, profile, directory, "before")
    if owner is None:
        return _result(identity, "rejected", reason, directory)
    code, log = _adb(root_path, host, profile, directory, "before-logcat", "logcat", "-d", "-v", "epoch", "-t", str(_LOG_LIMIT))
    if code != 0 or not _network_evidence(log, expected_port):
        return _result(identity, "rejected", "stale_endpoint_unverified", directory)
    intent = {"schemaVersion": 1, **identity, "owner": owner, "state": "prepared"}
    _write_new(directory / "intent.json", intent)
    # A second observation narrows the interval between admission and the one write.
    if _stored(root_path, host, profile, directory, "prewrite") != _BASELINE:
        return _result(identity, "rejected", "proxy_changed_before_write", directory)
    repeat_owner, reason = _admission(root_path, host, profile, directory, "prewrite")
    if repeat_owner != owner:
        return _result(identity, "rejected", reason if repeat_owner is None else "owner_changed", directory)
    started = time.time()
    _write_new(directory / "write-intent.json", {"atEpoch": started, **identity})
    code, _ = _adb(root_path, host, profile, directory, "clear-observer", "shell", "settings", "put", "global", "http_proxy", ":0")
    if code != 0:
        return _result(identity, "unknown", "clear_write_uncertain", directory)
    if _stored(root_path, host, profile, directory, "cleared") != _CLEARED:
        return _result(identity, "unknown", "clear_state_unverified", directory)
    effective = False
    for index in range(12):
        code, log = _adb(root_path, host, profile, directory, f"verify-logcat-{index}",
                         "logcat", "-d", "-v", "epoch", "-t", str(_LOG_LIMIT))
        if code is None or code != 0:
            return _result(identity, "unknown", "effective_state_unknown", directory)
        broadcast, effective = _clear_evidence(log, started, expected_port)
        if effective:
            break
        if not broadcast and index == 11:
            return _result(identity, "unknown", "clear_broadcast_unverified", directory)
        time.sleep(2)
    if not effective:
        return _result(identity, "unknown", "network_probe_unverified", directory)
    # Restore only the exact representation introduced by ProxyTracker's clear.
    for field, expected in zip(_FIELDS, _CLEARED):
        code, current = _adb(root_path, host, profile, directory, "prerestore-" + field,
                             "shell", "settings", "get", "global", field)
        if code != 0 or current != expected:
            return _result(identity, "unknown", "concurrent_proxy_change", directory)
        code, _ = _adb(root_path, host, profile, directory, "restore-" + field,
                       "shell", "settings", "delete", "global", field)
        if code != 0:
            return _result(identity, "unknown", "restore_uncertain", directory)
    if _stored(root_path, host, profile, directory, "final") != _BASELINE:
        return _result(identity, "unknown", "final_proxy_unverified", directory)
    repeat_owner, reason = _admission(root_path, host, profile, directory, "final")
    if repeat_owner != owner:
        return _result(identity, "unknown", reason if repeat_owner is None else "owner_changed", directory)
    _write_new(directory / "complete.json", {"schemaVersion": 1, **identity, "owner": owner,
                                              "state": "complete", "clearAtEpoch": started})
    return _result(identity, "complete", "effective_proxy_cleared", directory)


def observe_recovery(root: Path | str, host: str, device: str,
                     identity: Mapping[str, Any]) -> dict[str, Any]:
    """Read a prior correlation and current settings; never reissue a write."""
    if not isinstance(identity, Mapping) or set(identity) != {"host", "device", "expectedPort", "correlationId", "serial", "expectedAvd"}:
        raise AndroidProxyRecoveryError("Recovery identity is invalid.")
    root_path, expected, profile = _identity(root, host, device, identity["expectedPort"], identity["correlationId"])
    if dict(identity) != expected:
        raise AndroidProxyRecoveryError("Recovery identity does not match configured device.")
    directory = _private_directory(root_path) / expected["correlationId"]
    if not directory.is_dir() or directory.is_symlink():
        return _result(expected, "unknown", "intent_missing", directory)
    complete = directory / "complete.json"
    if complete.exists():
        value = _read(complete)
        if all(value.get(key) == val for key, val in expected.items()):
            return _result(expected, "complete", "durable_receipt", directory)
    if not (directory / "write-intent.json").exists():
        return _result(expected, "rejected" if (directory / "intent.json").exists() else "unknown",
                       "write_not_started" if (directory / "intent.json").exists() else "preflight_pending_or_rejected", directory)
    current = _stored(root_path, host, profile, directory, "observe")
    if current == _BASELINE:
        return _result(expected, "unknown", "stored_clear_observed_without_terminal_receipt", directory)
    if current == _CLEARED:
        return _result(expected, "unknown", "clear_applied_restoration_pending", directory)
    return _result(expected, "unknown", "effective_or_concurrent_state_unknown", directory)

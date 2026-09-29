"""Bounded, read-only observation of the fixed Arch ``ai_loop`` installation.

The observer deliberately does not accept a path, command, configuration, or job
identifier.  It runs one fixed Python probe through the configured ``archlinux``
SSH route.  The probe only emits categorical installation/activity data plus an
optional, strict safe-projection file.  It never reads ai_loop's normal config,
prompts, credentials, logs, or job data.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import select
import subprocess
import time
from typing import Any
import re

try:
    from . import ssh_transport
except ImportError:  # pragma: no cover - standalone MCP loader
    import ssh_transport


HOST = "archlinux"
MAX_OUTPUT_BYTES = 16_384
SAFE_PROJECTION_PATH = ".local/state/ai_loop/observer-v1.json"
_PROVIDERS = {"openai", "anthropic", "local", "other"}
_SAFE_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_VERSION = re.compile(r"^[0-9]+(?:\.[0-9A-Za-z._-]+)+$")
_SECRET = re.compile(r"(?:secret|token|password|api[_-]?key|bearer|sk-)", re.IGNORECASE)


class ArchAiLoopObservationError(ValueError):
    """The fixed observer cannot safely use the configured SSH route."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate observation field.")
        result[key] = value
    return result


def _remote_probe() -> str:
    """Return the fixed remote source without accepting remote user input."""
    return r'''
import json
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import time

SAFE_PROJECTION_PATH = Path.home() / ".local/state/ai_loop/observer-v1.json"
PROVIDERS = {"openai", "anthropic", "local", "other"}
SAFE_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
VERSION = re.compile(r"\b[0-9]+(?:\.[0-9A-Za-z._-]+)+\b")
SECRET = re.compile(r"(?:secret|token|password|api[_-]?key|bearer|sk-)", re.I)

def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError
        result[key] = value
    return result

def bounded(argv, allow_failure=True):
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C", "AI_LOOP_OFFLINE": "1", "NO_COLOR": "1"})
    except OSError:
        return None
    try:
        chunks = []; received = 0; deadline = time.monotonic() + 5
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0: return None
            ready, _, _ = select.select([process.stdout], [], [], remaining)
            if ready:
                chunk = os.read(process.stdout.fileno(), min(512, 4097 - received))
                if chunk:
                    chunks.append(chunk); received += len(chunk)
                    if received > 4096: return None
                    continue
                if process.poll() is not None:
                    if process.returncode and not allow_failure: return None
                    return b"".join(chunks).decode("utf-8", "replace").strip()
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    finally:
        if process.poll() is None: process.kill()
        process.wait()
        process.stdout.close()

def state(argv, active="active"):
    value = bounded(argv)
    if value is None: return "unknown"
    return active if value == active else "inactive"

def package_state():
    for name in ("ai_loop", "ai-loop"):
        value = bounded(["/usr/bin/pacman", "-Q", name])
        if value:
            match = VERSION.search(value)
            return {"state": "installed", "version": match.group(0) if match else None}
    return {"state": "absent", "version": None}

def executable_state():
    executable = next((str(path) for path in (Path("/usr/local/bin/ai_loop"), Path("/usr/local/bin/ai-loop"), Path("/usr/bin/ai_loop"), Path("/usr/bin/ai-loop")) if path.is_file() and os.access(path, os.X_OK)), None)
    # Do not execute an unknown local binary, including its conventional version
    # flag.  Package metadata is the only source of a reported version.
    return {"state": "present" if executable else "absent", "version": None}

def projection():
    try:
        metadata = os.lstat(SAFE_PROJECTION_PATH)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) not in (0o600, 0o640):
            return {"state": "rejected"}
        raw = SAFE_PROJECTION_PATH.read_bytes()
        if len(raw) > 4096: return {"state": "rejected"}
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
        fields = {"schemaVersion", "provider", "model", "budget", "metrics"}
        budget_fields = {"maxInputTokens", "maxOutputTokens", "maxIterations", "maxConcurrency", "timeoutSeconds"}
        metric_fields = {"window", "completedRuns", "failedRuns", "inputTokens", "outputTokens"}
        if not isinstance(value, dict) or set(value) != fields or value.get("schemaVersion") != 1:
            raise ValueError
        provider, model = value["provider"], value["model"]
        if provider not in PROVIDERS or not isinstance(model, str) or not SAFE_TEXT.fullmatch(model) or SECRET.search(model):
            raise ValueError
        budget, metrics = value["budget"], value["metrics"]
        if not isinstance(budget, dict) or set(budget) != budget_fields or not isinstance(metrics, dict) or set(metrics) != metric_fields:
            raise ValueError
        if not isinstance(metrics["window"], str) or metrics["window"] not in {"last_24h", "last_7d", "last_30d"}:
            raise ValueError
        numbers = list(budget.values()) + [metrics[key] for key in metric_fields - {"window"}]
        if any(type(item) is not int or item < 0 or item > 1_000_000_000 for item in numbers):
            raise ValueError
        return {"state": "available", "provider": provider, "model": model, "budget": budget, "metrics": metrics}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return {"state": "rejected"} if SAFE_PROJECTION_PATH.exists() else {"state": "absent"}

def process_state():
    observed = []
    for name in ("ai_loop", "ai-loop"):
        value = bounded(["/usr/bin/pgrep", "-cx", name])
        if value is None:
            continue
        if not re.fullmatch(r"[0-9]+", value):
            return "unknown"
        observed.append(int(value))
    if not observed:
        return "unknown"
    return "running" if any(observed) else "not_running"

installation = package_state()
executable = executable_state()
print(json.dumps({
    "schemaVersion": 1,
    "installation": {"package": installation["state"], "executable": executable["state"], "version": installation["version"]},
    "activity": {
        "userService": state(["/usr/bin/systemctl", "--user", "is-active", "ai_loop.service"]),
        "systemService": state(["/usr/bin/systemctl", "is-active", "ai_loop.service"]),
        "process": process_state()
    },
    "safeProjection": projection()
}, separators=(",", ":")))
'''


def _run_probe(argv: list[str], timeout_seconds: int) -> tuple[int, bytes]:
    """Run a single fixed SSH observation and keep a bounded stdout envelope."""
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError as exc:
        raise RuntimeError("transport_unavailable") from exc
    assert process.stdout is not None
    chunks: list[bytes] = []
    received = 0
    deadline = time.monotonic() + timeout_seconds + 1
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            ready, _, _ = select.select([process.stdout], [], [], remaining)
            if ready:
                chunk = os.read(process.stdout.fileno(), min(1024, MAX_OUTPUT_BYTES + 1 - received))
                if chunk:
                    chunks.append(chunk)
                    received += len(chunk)
                    if received > MAX_OUTPUT_BYTES:
                        raise RuntimeError("oversized_output")
                    continue
                if process.poll() is not None:
                    return process.returncode, b"".join(chunks)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()


def _unknown(reason: str) -> dict[str, Any]:
    return {"available": False, "outcome": "unknown", "reason": reason,
            "installation": None, "activity": None, "safeProjection": None}


def _valid_count(value: Any) -> bool:
    return type(value) is int and 0 <= value <= 1_000_000_000


def _result(returncode: int, output: bytes) -> dict[str, Any]:
    if returncode:
        return _unknown("transport_failed")
    try:
        value = json.loads(output.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
        if not isinstance(value, dict) or set(value) != {"schemaVersion", "installation", "activity", "safeProjection"} or value["schemaVersion"] != 1:
            raise ValueError
        installation, activity, projection = value["installation"], value["activity"], value["safeProjection"]
        if not isinstance(installation, dict) or set(installation) != {"package", "executable", "version"}:
            raise ValueError
        if installation["package"] not in {"installed", "absent"} or installation["executable"] not in {"present", "absent"}:
            raise ValueError
        if installation["version"] is not None and (not isinstance(installation["version"], str) or not _VERSION.fullmatch(installation["version"]) or _SECRET.search(installation["version"])):
            raise ValueError
        if not isinstance(activity, dict) or set(activity) != {"userService", "systemService", "process"}:
            raise ValueError
        if activity["userService"] not in {"active", "inactive", "unknown"} or activity["systemService"] not in {"active", "inactive", "unknown"} or activity["process"] not in {"running", "not_running", "unknown"}:
            raise ValueError
        if not isinstance(projection, dict) or projection.get("state") not in {"absent", "rejected", "available"}:
            raise ValueError
        if projection["state"] in {"absent", "rejected"} and set(projection) != {"state"}:
            raise ValueError
        if projection["state"] == "available":
            fields = {"state", "provider", "model", "budget", "metrics"}
            budget_fields = {"maxInputTokens", "maxOutputTokens", "maxIterations", "maxConcurrency", "timeoutSeconds"}
            metric_fields = {"window", "completedRuns", "failedRuns", "inputTokens", "outputTokens"}
            if (set(projection) != fields or projection["provider"] not in _PROVIDERS
                    or not isinstance(projection["model"], str)
                    or not _SAFE_TEXT.fullmatch(projection["model"])
                    or _SECRET.search(projection["model"])):
                raise ValueError
            if not isinstance(projection["budget"], dict) or set(projection["budget"]) != budget_fields or not isinstance(projection["metrics"], dict) or set(projection["metrics"]) != metric_fields:
                raise ValueError
            if not all(_valid_count(item) for item in projection["budget"].values()):
                raise ValueError
            if projection["metrics"].get("window") not in {"last_24h", "last_7d", "last_30d"} or not all(_valid_count(projection["metrics"][key]) for key in metric_fields - {"window"}):
                raise ValueError
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        return _unknown("malformed_observation")
    return {"available": True, "outcome": "available", "reason": "ok", "installation": installation,
            "activity": activity, "safeProjection": projection}


def observe(root: Path | str, timeout_seconds: int = 15) -> dict[str, Any]:
    """Observe only the configured Arch host; uncertainty stays unknown."""
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 60:
        raise ArchAiLoopObservationError("ai_loop observation timeout must be between 1 and 60 seconds.")
    try:
        config = ssh_transport.load_config(root)
        if HOST not in config.hosts:
            raise ArchAiLoopObservationError("Configured archlinux host is unavailable.")
        if ssh_transport.connection_host(config, HOST).password is not None:
            raise ArchAiLoopObservationError("ai_loop observation requires key or agent SSH authentication.")
        argv = ssh_transport.build_ssh_argv(config, HOST, timeout_seconds,
            command=("/usr/bin/python3", "-c", "exec(" + repr(_remote_probe()) + ")"))
        return _result(*_run_probe(argv, timeout_seconds))
    except (ssh_transport.SshConfigError, ArchAiLoopObservationError):
        raise
    except TimeoutError:
        return _unknown("timeout")
    except RuntimeError as exc:
        return _unknown(str(exc) if str(exc) in {"transport_unavailable", "oversized_output"} else "transport_failed")

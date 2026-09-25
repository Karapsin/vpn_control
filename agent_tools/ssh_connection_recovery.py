"""Fail-closed recovery for a missing nested SSH control master.

This module intentionally has no generic remote-command interface.  It can only
check the configured nested control socket and, when that socket is confirmed
absent, start one isolated replacement master using the nested profile's
already-private credential.  A local intent receipt prevents a retry from
starting another master after an interrupted observation.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tempfile
import threading
import time
from typing import Any
from uuid import uuid4

try:
    from . import ssh_transport
except ImportError:  # pragma: no cover - supports direct script loading in tests.
    import ssh_transport  # type: ignore


DEFAULT_TIMEOUT_SECONDS = 30
MAX_TIMEOUT_SECONDS = 60
_INTENT_DIRECTORY = ".rag_index/ssh-recovery"
_ABSENT_SOCKET_MARKERS = ("no such file or directory", "control socket connect")
_MAX_CAPTURE_CHARS = 8_192
_MAX_REMOTE_SOCKET_BYTES = 85


class RecoveryError(ValueError):
    """The requested recovery cannot safely proceed."""


def _intent_path(root: Path, host: str, target: ssh_transport.SshHost) -> Path:
    identity = json.dumps(_identity(target), sort_keys=True).encode("utf-8")
    digest = hashlib.sha256(identity).hexdigest()
    return root / _INTENT_DIRECTORY / f"{host}-{digest}.json"


def _recovery_socket_path(target: ssh_transport.SshHost, correlation_id: str) -> tuple[PurePosixPath, PurePosixPath] | None:
    assert target.remote_control_path
    directory = target.remote_control_path.parent / f"r-{correlation_id[:16]}"
    control_path = directory / "m"
    try:
        valid = len(str(control_path).encode("utf-8")) <= _MAX_REMOTE_SOCKET_BYTES
    except UnicodeError:
        valid = False
    return (directory, control_path) if valid else None


def _identity(target: ssh_transport.SshHost) -> dict[str, str]:
    assert target.gateway and target.remote_host_alias and target.remote_control_path
    return {"targetHost": target.host, "gateway": target.gateway, "remoteHostAlias": target.remote_host_alias,
            "configuredControlPath": str(target.remote_control_path)}


def _read_intent(root: Path, host: str, target: ssh_transport.SshHost) -> dict[str, str] | None:
    path = _intent_path(root, host, target)
    legacy = False
    if not path.exists():
        path = root / _INTENT_DIRECTORY / f"{host}.json"
        legacy = True
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError):
        raise RecoveryError("Existing SSH recovery intent cannot be read safely.") from None
    required = {"schemaVersion", "host", "correlationId", "state", "controlPath", *(_identity(target))}
    if not isinstance(value, dict) or set(value) != required:
        raise RecoveryError("Existing SSH recovery intent has an unsupported format.")
    if not all(isinstance(value.get(key), str) and value[key] for key in ("correlationId", "state", "controlPath")):
        raise RecoveryError("Existing SSH recovery intent is incomplete.")
    identity = _identity(target)
    if value.get("schemaVersion") != 1 or value.get("host") != host or any(
            value.get(key) != expected for key, expected in identity.items() if key != "configuredControlPath"):
        raise RecoveryError("Existing SSH recovery intent does not match this host.")
    if value.get("configuredControlPath") != identity["configuredControlPath"]:
        # A completed legacy recovery remains immutable history after the user
        # adopts a new configured socket. Unknown legacy outcomes stay blocked.
        if legacy and value.get("state") == "ready":
            return None
        raise RecoveryError("Existing SSH recovery intent does not match this host.")
    return {key: value[key] for key in required if key != "schemaVersion"}


def _intent_value(host: str, target: ssh_transport.SshHost, correlation_id: str, state: str, control_path: str) -> dict[str, str | int]:
    return {"schemaVersion": 1, "host": host, "correlationId": correlation_id,
            "state": state, "controlPath": control_path, **_identity(target)}


def _create_intent(root: Path, host: str, target: ssh_transport.SshHost, correlation_id: str, control_path: str) -> None:
    directory = _intent_path(root, host, target).parent
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        if not directory.is_dir() or directory.is_symlink():
            raise RecoveryError("SSH recovery intent directory is unsafe.")
        path = _intent_path(root, host, target)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=True) as handle:
            json.dump(_intent_value(host, target, correlation_id, "pending", control_path), handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        raise
    except OSError as error:
        raise RecoveryError("SSH recovery intent cannot be stored safely.") from error


def _update_intent(root: Path, host: str, target: ssh_transport.SshHost, correlation_id: str, state: str, control_path: str) -> None:
    directory = _intent_path(root, host, target).parent
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=f".{host}.", suffix=".tmp", dir=directory)
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=True) as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(_intent_value(host, target, correlation_id, state, control_path), handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, _intent_path(root, host, target))
    except OSError as error:
        raise RecoveryError("SSH recovery intent cannot be updated safely.") from error


def _bounded_run(argv: list[str], timeout_seconds: int, *, input_text: str | None = None,
                 environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[str] | None:
    """Run SSH with fixed-size output retention so diagnostics cannot grow unbounded."""
    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
    except OSError:
        return None
    captured: dict[str, list[str]] = {"stdout": [], "stderr": []}

    def drain(name: str, stream: Any) -> None:
        try:
            for chunk in iter(lambda: stream.read(1024), ""):
                remaining = _MAX_CAPTURE_CHARS - sum(map(len, captured[name]))
                if remaining > 0:
                    captured[name].append(chunk[:remaining])
        except (OSError, ValueError):
            pass

    readers = [threading.Thread(target=drain, args=(name, stream), daemon=True)
               for name, stream in (("stdout", process.stdout), ("stderr", process.stderr))]
    for reader in readers:
        reader.start()
    incomplete_capture = False
    try:
        if input_text is not None:
            assert process.stdin is not None
            process.stdin.write(input_text)
            process.stdin.close()
        process.wait(timeout=timeout_seconds + 1)
    except (OSError, subprocess.TimeoutExpired):
        process.kill()
        process.wait()
        return None
    finally:
        deadline = time.monotonic() + 1
        for reader in readers:
            reader.join(timeout=max(0, deadline - time.monotonic()))
            incomplete_capture |= reader.is_alive()
        if incomplete_capture:
            for stream in (process.stdout, process.stderr):
                stream.close()
            for reader in readers:
                reader.join(timeout=0.1)
        else:
            for stream in (process.stdout, process.stderr):
                stream.close()
    if incomplete_capture:
        return None
    return subprocess.CompletedProcess(argv, process.returncode, "".join(captured["stdout"]), "".join(captured["stderr"]))


def _gateway_run(config: ssh_transport.SshConfig, target: ssh_transport.SshHost, command: tuple[str, ...], timeout_seconds: int,
                 *, input_text: str | None = None) -> subprocess.CompletedProcess[str] | None:
    assert target.gateway
    gateway = ssh_transport.connection_host(config, target.gateway)
    argv = ssh_transport.build_ssh_argv(config, target.gateway, timeout_seconds, command=command)
    if gateway.password is None:
        return _bounded_run(argv, timeout_seconds, input_text=input_text)
    try:
        with tempfile.TemporaryDirectory(prefix="vpn-control-askpass-") as directory:
            _, environment = ssh_transport._askpass_environment(gateway.password, Path(directory))
            return _bounded_run(argv, timeout_seconds, input_text=input_text, environment=environment)
    except OSError:
        return None


def _socket_state(config: ssh_transport.SshConfig, target: ssh_transport.SshHost, control_path: PurePosixPath, timeout_seconds: int) -> str:
    assert target.remote_host_alias
    completed = _gateway_run(config, target, ("ssh", "-S", str(control_path), "-O", "check", target.remote_host_alias), timeout_seconds)
    if completed is None:
        return "unknown"
    if completed.returncode == 0:
        return "ready"
    output = (completed.stdout + completed.stderr).lower()
    return "absent" if all(marker in output for marker in _ABSENT_SOCKET_MARKERS) else "unknown"


# The script is deliberately fixed code.  The only stdin payload is JSON carrying
# the private nested-key passphrase; it is never placed in argv or environment.
_REMOTE_RECOVERY_SCRIPT = r'''
import json, os, subprocess, sys, tempfile
profile = sys.argv[1]
timeout = int(sys.argv[2])
directory = sys.argv[3]
control_path = sys.argv[4]
secret = json.loads(sys.stdin.read())
passphrase = secret.get("passphrase")
if not isinstance(passphrase, str) or not passphrase:
    print(json.dumps({"state": "credential_unavailable"}))
    raise SystemExit(2)
try:
    os.mkdir(directory, 0o700)
except FileExistsError:
    print(json.dumps({"state": "directory_exists", "control_path": control_path}))
    raise SystemExit(4)
password_path = os.path.join(directory, "askpass-password")
helper_path = os.path.join(directory, "askpass")
try:
    descriptor = os.open(password_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(passphrase)
    with open(helper_path, "w", encoding="utf-8") as handle:
        handle.write("#!/bin/sh\ncat \"$VPN_CONTROL_SSH_PASSWORD_FILE\"\n")
    os.chmod(helper_path, 0o700)
    resolved = subprocess.run(["ssh", "-G", profile], capture_output=True, text=True, timeout=timeout, check=False)
    known_hosts = next((line.split(" ", 1)[1] for line in resolved.stdout.splitlines()
                        if line.startswith("userknownhostsfile ")), None)
    if resolved.returncode != 0 or not known_hosts:
        print(json.dumps({"state": "config_unavailable", "control_path": control_path}))
        raise SystemExit(3)
    environment = os.environ.copy()
    environment.update({"SSH_ASKPASS": helper_path, "SSH_ASKPASS_REQUIRE": "force",
                        "DISPLAY": environment.get("DISPLAY", "vpn-control-askpass"),
                        "VPN_CONTROL_SSH_PASSWORD_FILE": password_path})
    command = ["ssh", "-M", "-N", "-f", "-S", control_path,
               "-o", "ControlMaster=yes", "-o", "ControlPersist=3600",
               "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + known_hosts,
               "-o", "IdentitiesOnly=yes", "-o", "BatchMode=no",
               "-o", "NumberOfPasswordPrompts=1", "-o", "ConnectTimeout=" + str(timeout), profile]
    created = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False, env=environment)
    checked = subprocess.run(["ssh", "-S", control_path, "-O", "check", profile], capture_output=True, text=True, timeout=timeout, check=False)
    print(json.dumps({"state": "ready" if created.returncode == 0 and checked.returncode == 0 else "unknown",
                      "control_path": control_path}))
finally:
    for path in (password_path, helper_path):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
'''.strip()


def _remote_command(target: ssh_transport.SshHost, timeout_seconds: int,
                    control_directory: PurePosixPath, control_path: str) -> tuple[str, ...]:
    """Encode fixed multiline code as one control-character-free argv value."""
    assert target.remote_host_alias
    return ("python3", "-c", f"exec({_REMOTE_RECOVERY_SCRIPT!r})", target.remote_host_alias,
            str(timeout_seconds), str(control_directory), control_path)


def recover(root: Path | str, host: str, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Recover one configured nested control master without replacing unknown state."""
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        return {"ok": False, "state": "invalid_timeout"}
    try:
        config = ssh_transport.load_config(root)
        target = config.hosts.get(host)
        if target is None or target.transport != "nested" or not target.gateway or not target.remote_control_path or not target.remote_host_alias:
            return {"ok": False, "state": "unsupported_host"}
        configured = _socket_state(config, target, target.remote_control_path, timeout_seconds)
        if configured == "ready":
            return {"ok": True, "state": "configured_master_ready"}
        if configured != "absent":
            return {"ok": False, "state": "configured_master_unknown"}
        intent = _read_intent(Path(root).resolve(), host, target)
        if intent is not None:
            recovered = _socket_state(config, target, PurePosixPath(intent["controlPath"]), timeout_seconds)
            if recovered == "ready":
                return {"ok": True, "state": "recovery_master_ready"}
            return {"ok": False, "state": "recovery_intent_pending"}
        if target.password is None:
            return {"ok": False, "state": "nested_credential_unavailable"}
        correlation_id = uuid4().hex
        recovery_socket = _recovery_socket_path(target, correlation_id)
        if recovery_socket is None:
            return {"ok": False, "state": "recovery_socket_path_too_long"}
        control_directory, remote_socket = recovery_socket
        control_path = str(remote_socket)
        try:
            _create_intent(Path(root).resolve(), host, target, correlation_id, control_path)
        except FileExistsError:
            return {"ok": False, "state": "recovery_intent_pending"}
        request = json.dumps({"passphrase": target.password})
        completed = _gateway_run(config, target, _remote_command(target, timeout_seconds, control_directory, control_path),
                                 timeout_seconds, input_text=request)
        if completed is None:
            return {"ok": False, "state": "recovery_intent_pending"}
        try:
            response = json.loads(completed.stdout)
            reported_path = response["control_path"]
            state = response["state"]
            if not isinstance(reported_path, str) or not PurePosixPath(reported_path).is_absolute() or state not in {"ready", "unknown", "config_unavailable"}:
                raise ValueError
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            return {"ok": False, "state": "recovery_intent_pending"}
        if control_path != reported_path:
            return {"ok": False, "state": "recovery_intent_pending"}
        _update_intent(Path(root).resolve(), host, target, correlation_id, state, control_path)
        return {"ok": state == "ready", "state": "recovery_master_ready" if state == "ready" else "recovery_intent_pending"}
    except (ssh_transport.SshConfigError, RecoveryError):
        return {"ok": False, "state": "recovery_unavailable"}

"""Fail-closed, CP117-only nested loopback VNC forwarding.

This is deliberately narrower than a general SSH forwarding interface.  It can
only bridge the configured ``archlinux`` nested control master to the owned
Windows VM's loopback VNC port.  A durable local intent retains the exact local
master identity before any network side effect, so an uncertain open is never
replayed and close can address only a forward this module created.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import hashlib
import platform
import socket
import subprocess
import tempfile
import time
from typing import Any
from uuid import uuid4

try:
    from . import ssh_connection_recovery, ssh_transport
except ImportError:  # pragma: no cover - direct module loading in tests.
    import ssh_connection_recovery  # type: ignore
    import ssh_transport  # type: ignore


HOST = "archlinux"
LOCAL_PORT = 45909
REMOTE_VNC_PORT = 5909
TIMEOUT_SECONDS = 20
_INTENT_DIRECTORY = ".rag_index/ssh-forward"
_CONTROL_ROOT = Path("/private/tmp") if platform.system() == "Darwin" else Path(tempfile.gettempdir())
_MAX_UNIX_SOCKET_BYTES = 104
_OPENSSH_SOCKET_SUFFIX_RESERVE = 16


class ForwardError(ValueError):
    """The requested fixed forward cannot safely proceed."""


def _intent_path(root: Path) -> Path:
    return root / _INTENT_DIRECTORY / f"{HOST}.json"


def _process_generation(pid: int) -> str | None:
    """Return a platform-native process generation marker, never PID alone."""
    if platform.system() == "Darwin":
        # libproc's start timeval distinguishes a reused PID even when ``ps``
        # renders both processes in the same second.
        import ctypes

        class ProcBsdInfo(ctypes.Structure):
            _fields_ = [("flags", ctypes.c_uint32), ("status", ctypes.c_uint32),
                       ("xstatus", ctypes.c_uint32), ("pid", ctypes.c_uint32),
                       ("ppid", ctypes.c_uint32), ("uid", ctypes.c_uint32), ("gid", ctypes.c_uint32),
                       ("ruid", ctypes.c_uint32), ("rgid", ctypes.c_uint32), ("svuid", ctypes.c_uint32),
                       ("svgid", ctypes.c_uint32), ("reserved", ctypes.c_uint32),
                       ("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32),
                       ("nfiles", ctypes.c_uint32), ("pgid", ctypes.c_uint32), ("pjobc", ctypes.c_uint32),
                       ("tdev", ctypes.c_uint32), ("tpgid", ctypes.c_uint32), ("nice", ctypes.c_int32),
                       ("startSeconds", ctypes.c_uint64), ("startMicroseconds", ctypes.c_uint64)]
        try:
            info = ProcBsdInfo()
            received = ctypes.CDLL("/usr/lib/libproc.dylib").proc_pidinfo(
                pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
            if received != ctypes.sizeof(info) or info.pid != pid or not info.startSeconds:
                return None
            return f"darwin:{info.startSeconds}:{info.startMicroseconds}"
        except (OSError, AttributeError):
            return None
    try:
        fields = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").rsplit(") ", 1)[1].split()
        return f"linux:{fields[19]}"
    except (FileNotFoundError, IndexError, OSError):
        return None


def _process_command_matches(pid: int, control_path: str) -> bool:
    """Require the recorded SSH control socket and fixed loopback argument."""
    try:
        completed = subprocess.run(["ps", "-p", str(pid), "-o", "command="], text=True,
                                   capture_output=True, timeout=2, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    command = completed.stdout.strip()
    return (completed.returncode == 0 and command and control_path in command and
            "-M" in command and "-N" in command and
            f"127.0.0.1:{LOCAL_PORT}:127.0.0.1:{LOCAL_PORT}" in command)


def _control_directory() -> tuple[Path, Path]:
    """Reserve a short, owner-private directory before an SSH command is sent."""
    directory = Path(tempfile.mkdtemp(prefix="vcf-", dir=_CONTROL_ROOT))
    metadata = directory.stat()
    if directory.is_symlink() or metadata.st_uid != os.getuid() or (metadata.st_mode & 0o777) != 0o700:
        raise ForwardError("SSH forward control directory is unsafe.")
    socket_path = directory / "m"
    if len(os.fsencode(socket_path)) + _OPENSSH_SOCKET_SUFFIX_RESERVE > _MAX_UNIX_SOCKET_BYTES:
        raise ForwardError("SSH forward control socket path is too long.")
    return directory, socket_path


def _identity(target: ssh_transport.SshHost, local_socket: str, pid: int, start_ticks: str,
              correlation_id: str, state: str, local_directory: str, remote_master_identity: str) -> dict[str, Any]:
    assert target.gateway and target.remote_host_alias and target.remote_control_path
    return {
        "schemaVersion": 1,
        "host": HOST,
        "correlationId": correlation_id,
        "state": state,
        "gateway": target.gateway,
        "remoteHostAlias": target.remote_host_alias,
        "remoteControlPath": str(target.remote_control_path),
        "localPort": LOCAL_PORT,
        "remotePort": REMOTE_VNC_PORT,
        "remoteMasterIdentity": remote_master_identity,
        "localControlDirectory": local_directory,
        "localControlPath": local_socket,
        "pid": pid,
        "startTicks": start_ticks,
    }


def _read_intent(root: Path, target: ssh_transport.SshHost) -> dict[str, Any] | None:
    try:
        value = json.loads(_intent_path(root).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as error:
        raise ForwardError("Existing SSH forward intent cannot be read safely.") from error
    required = {"schemaVersion", "host", "correlationId", "state", "gateway", "remoteHostAlias",
                "remoteControlPath", "localPort", "remotePort", "remoteMasterIdentity", "localControlDirectory",
                "localControlPath", "pid", "startTicks"}
    if not isinstance(value, dict) or set(value) != required:
        raise ForwardError("Existing SSH forward intent has an unsupported format.")
    expected = {"schemaVersion": 1, "host": HOST, "gateway": target.gateway,
                "remoteHostAlias": target.remote_host_alias, "remoteControlPath": str(target.remote_control_path),
                "localPort": LOCAL_PORT, "remotePort": REMOTE_VNC_PORT}
    if any(value.get(key) != expected_value for key, expected_value in expected.items()):
        raise ForwardError("Existing SSH forward intent does not match the configured route.")
    if (not isinstance(value["correlationId"], str) or not value["correlationId"] or
            value["state"] not in {"pending", "remote_created", "local_pending", "ready", "closing", "closed"} or
            not isinstance(value["localControlPath"], str) or not isinstance(value["localControlDirectory"], str) or
            not isinstance(value["remoteMasterIdentity"], str) or len(value["remoteMasterIdentity"]) != 64 or
            isinstance(value["pid"], bool) or not isinstance(value["pid"], int) or value["pid"] < 0 or
            not isinstance(value["startTicks"], str) or not value["startTicks"]):
        raise ForwardError("Existing SSH forward intent is incomplete.")
    return value


def _write_intent(root: Path, value: dict[str, Any]) -> None:
    path = _intent_path(root)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise ForwardError("SSH forward intent directory is unsafe.")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", closefd=True) as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def _replace_intent(root: Path, value: dict[str, Any]) -> None:
    path = _intent_path(root)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        with open(temporary, "x", encoding="utf-8") as stream:
            os.chmod(temporary, 0o600)
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError as error:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise ForwardError("SSH forward intent cannot be updated safely.") from error


def _port_is_free() -> bool:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", LOCAL_PORT))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def _port_is_ready(port: int = LOCAL_PORT) -> bool:
    """Prove the fixed listener reaches a VNC server, not just an SSH accept."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1) as probe:
            probe.settimeout(1)
            banner = b""
            while len(banner) < 12:
                chunk = probe.recv(12 - len(banner))
                if not chunk:
                    return False
                banner += chunk
            return (banner[:4] == b"RFB " and banner[4:7].isdigit() and
                    banner[7:8] == b"." and banner[8:11].isdigit() and banner[11:] == b"\n")
    except OSError:
        return False


def _remote_forward_command(target: ssh_transport.SshHost, action: str) -> tuple[str, ...]:
    assert target.remote_control_path and target.remote_host_alias
    if action not in {"forward", "cancel"}:
        raise ValueError("unsupported fixed forwarding action")
    return ("ssh", "-S", str(target.remote_control_path), "-O", action, "-L",
            f"127.0.0.1:{LOCAL_PORT}:127.0.0.1:{REMOTE_VNC_PORT}", target.remote_host_alias)


def _local_argv(config: ssh_transport.SshConfig, target: ssh_transport.SshHost, control_path: str,
                operation: str) -> list[str]:
    """Use the transport builder for fixed gateway authentication arguments."""
    assert target.gateway
    base = ssh_transport.build_ssh_argv(config, target.gateway, TIMEOUT_SECONDS, command=("true",))
    gateway_host = base[-2]
    options = base[:-2]
    if operation == "open":
        return [*options, "-M", "-N", "-S", control_path, "-o", "ControlMaster=yes",
                "-o", "ControlPersist=no", "-o", "ExitOnForwardFailure=yes", "-L",
                f"127.0.0.1:{LOCAL_PORT}:127.0.0.1:{LOCAL_PORT}", gateway_host]
    if operation == "close":
        return [*options, "-S", control_path, "-O", "exit", gateway_host]
    if operation == "check":
        return [*options, "-S", control_path, "-O", "check", gateway_host]
    raise ValueError("unsupported fixed local action")


def _remote_result(config: ssh_transport.SshConfig, target: ssh_transport.SshHost, action: str) -> bool | None:
    result = ssh_connection_recovery._gateway_run(config, target, _remote_forward_command(target, action), TIMEOUT_SECONDS)
    return None if result is None else result.returncode == 0


def _remote_master_identity(config: ssh_transport.SshConfig, target: ssh_transport.SshHost) -> str | None:
    assert target.remote_control_path and target.remote_host_alias
    command = ("ssh", "-S", str(target.remote_control_path), "-O", "check", target.remote_host_alias)
    result = ssh_connection_recovery._gateway_run(config, target, command, TIMEOUT_SECONDS)
    if result is None or result.returncode != 0:
        return None
    # The remote control master's own check output is a bounded identity witness;
    # retain only its digest, never private topology or command text.
    payload = (result.stdout + "\n" + result.stderr).encode("utf-8", errors="replace")
    return hashlib.sha256(payload).hexdigest() if payload else None


def _local_control_ready(config: ssh_transport.SshConfig, target: ssh_transport.SshHost, control_path: str) -> bool:
    try:
        result = subprocess.run(_local_argv(config, target, control_path, "check"), stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True,
                                timeout=TIMEOUT_SECONDS, check=False)
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _owned(intent: dict[str, Any]) -> bool:
    return (intent["pid"] > 0 and _process_generation(intent["pid"]) == intent["startTicks"] and
            _process_command_matches(intent["pid"], intent["localControlPath"]))


def status(root: Path | str, host: str = HOST) -> dict[str, Any]:
    """Observe a previously recorded forward; this never opens, retries, or kills it."""
    if host != HOST:
        return {"ok": False, "state": "unsupported_host"}
    # This coordinator records ownership through POSIX uid/mode checks and Unix
    # control sockets.  Do not pretend Windows ACLs provide the same admission.
    if os.name != "posix":
        return {"ok": False, "state": "unsupported_platform"}
    try:
        config = ssh_transport.load_config(root)
        target = config.hosts.get(host)
        if target is None or target.transport != "nested" or not target.gateway or not target.remote_control_path or not target.remote_host_alias:
            return {"ok": False, "state": "unsupported_host"}
        intent = _read_intent(Path(root).resolve(), target)
        if intent is None:
            return {"ok": False, "state": "not_open"}
        if intent["state"] == "closed":
            return {"ok": True, "state": "closed", "correlationId": intent["correlationId"]}
        if not _owned(intent):
            return {"ok": False, "state": "owner_unknown", "correlationId": intent["correlationId"]}
        return {"ok": intent["state"] == "ready" and _local_control_ready(config, target, intent["localControlPath"]) and _port_is_ready(), "state": intent["state"],
                "correlationId": intent["correlationId"], "localPort": LOCAL_PORT}
    except (ForwardError, ssh_transport.SshConfigError):
        return {"ok": False, "state": "unavailable"}


def open_forward(root: Path | str, host: str = HOST) -> dict[str, Any]:
    """Create one owned fixed forward; uncertain outcomes retain a pending intent."""
    if host != HOST:
        return {"ok": False, "state": "unsupported_host"}
    if os.name != "posix":
        return {"ok": False, "state": "unsupported_platform"}
    try:
        root_path = Path(root).resolve()
        config = ssh_transport.load_config(root_path)
        target = config.hosts.get(host)
        if target is None or target.transport != "nested" or not target.gateway or not target.remote_control_path or not target.remote_host_alias:
            return {"ok": False, "state": "unsupported_host"}
        if _read_intent(root_path, target) is not None:
            return {"ok": False, "state": "intent_exists"}
        if not _port_is_free():
            return {"ok": False, "state": "local_port_occupied"}
        remote_master_identity = _remote_master_identity(config, target)
        if remote_master_identity is None:
            return {"ok": False, "state": "remote_master_unknown"}
        correlation_id = uuid4().hex
        control_directory, control_socket = _control_directory()
        control_path = str(control_socket)
        # Record an impossible PID first.  It makes a response loss non-replayable
        # before either remote or local forwarding command is submitted.
        pending = _identity(target, control_path, 0, "pending", correlation_id, "pending",
                            str(control_directory), remote_master_identity)
        _write_intent(root_path, pending)
        remote = _remote_result(config, target, "forward")
        if remote is not True:
            return {"ok": False, "state": "remote_forward_pending", "correlationId": correlation_id}
        # A successful control command is the only observation that proves the
        # remote listener is ours. Persist it before local process creation so a
        # local launch failure can cancel exactly this listener later.
        remote_created = {**pending, "state": "remote_created"}
        _replace_intent(root_path, remote_created)
        try:
            process = subprocess.Popen(_local_argv(config, target, control_path, "open"), stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
        except OSError:
            return {"ok": False, "state": "local_forward_pending", "correlationId": correlation_id}
        ticks = _process_generation(process.pid)
        if ticks is None:
            return {"ok": False, "state": "local_forward_pending", "correlationId": correlation_id}
        pending = _identity(target, control_path, process.pid, ticks, correlation_id, "local_pending",
                            str(control_directory), remote_master_identity)
        _replace_intent(root_path, pending)
        deadline = time.monotonic() + TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if not _owned(pending):
                return {"ok": False, "state": "local_forward_pending", "correlationId": correlation_id}
            if _local_control_ready(config, target, control_path) and _port_is_ready():
                ready = {**pending, "state": "ready"}
                _replace_intent(root_path, ready)
                return {"ok": True, "state": "ready", "correlationId": correlation_id, "localPort": LOCAL_PORT}
            time.sleep(0.1)
        return {"ok": False, "state": "local_forward_pending", "correlationId": correlation_id}
    except (ForwardError, OSError, ssh_transport.SshConfigError):
        return {"ok": False, "state": "unavailable"}


def close(root: Path | str, identity: dict[str, Any], host: str = HOST) -> dict[str, Any]:
    """Close only a live forward that matches the caller's captured identity."""
    if host != HOST or not isinstance(identity, dict):
        return {"ok": False, "state": "unsupported_host"}
    if os.name != "posix":
        return {"ok": False, "state": "unsupported_platform"}
    try:
        root_path = Path(root).resolve()
        config = ssh_transport.load_config(root_path)
        target = config.hosts.get(host)
        if target is None or target.transport != "nested" or not target.gateway or not target.remote_control_path or not target.remote_host_alias:
            return {"ok": False, "state": "unsupported_host"}
        intent = _read_intent(root_path, target)
        if intent is None or identity.get("correlationId") != intent["correlationId"]:
            return {"ok": False, "state": "identity_mismatch"}
        if intent["state"] == "closed":
            return {"ok": True, "state": "closed", "correlationId": intent["correlationId"]}
        # A submission without a response might have reached the remote master.
        # It is never safe to cancel by matching port alone in that case.
        if intent["state"] == "pending":
            return {"ok": False, "state": "close_pending", "correlationId": intent["correlationId"]}
        if intent["state"] == "remote_created":
            if _remote_master_identity(config, target) != intent["remoteMasterIdentity"]:
                return {"ok": False, "state": "close_pending", "correlationId": intent["correlationId"]}
            remote = _remote_result(config, target, "cancel")
            if remote is not True:
                return {"ok": False, "state": "close_pending", "correlationId": intent["correlationId"]}
            _replace_intent(root_path, {**intent, "state": "closed"})
            return {"ok": True, "state": "closed", "correlationId": intent["correlationId"]}
        if intent["state"] != "ready":
            return {"ok": False, "state": "close_pending", "correlationId": intent["correlationId"]}
        if not _owned(intent):
            return {"ok": False, "state": "owner_unknown"}
        closing = {**intent, "state": "closing"}
        _replace_intent(root_path, closing)
        local = subprocess.run(_local_argv(config, target, intent["localControlPath"], "close"), stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True, timeout=TIMEOUT_SECONDS, check=False)
        if local.returncode != 0:
            return {"ok": False, "state": "close_pending", "correlationId": intent["correlationId"]}
        if _remote_master_identity(config, target) != intent["remoteMasterIdentity"]:
            # A replacement master can own the same socket pathname.  Never
            # issue its matching-port cancel merely because our local leg ended.
            return {"ok": False, "state": "close_pending", "correlationId": intent["correlationId"]}
        remote = _remote_result(config, target, "cancel")
        if remote is not True:
            return {"ok": False, "state": "close_pending", "correlationId": intent["correlationId"]}
        _replace_intent(root_path, {**intent, "state": "closed"})
        return {"ok": True, "state": "closed", "correlationId": intent["correlationId"]}
    except (ForwardError, OSError, subprocess.TimeoutExpired, ssh_transport.SshConfigError):
        return {"ok": False, "state": "close_pending"}

"""One source-bound, local-only adoption of an observed nested SSH socket.

Only the two fixed recovery observations can contact the host. Immutable pending
and terminal records fence replacement, including ambiguous/crashed attempts.

Inventory adoption holds the private config.lock cooperative flock. Every writer
sharing this ownership must acquire that lock. Snapshot guards detect observed
external drift, but POSIX rename is not an atomic compare-and-swap against
arbitrary external writers that ignore the ownership lock.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
from uuid import uuid4

try:
    from . import ssh_connection_recovery as recovery, ssh_transport
    from .private_inventory_lock import (
        Directory as _Directory, Snapshot as _Snapshot, PresentedPath as _PresentedPath,
        InventoryLock as _ConfigLock, lock_directory as _receipt_directory,
    )
except ImportError:  # CLI/MCP server may import tools as top-level modules.
    import ssh_connection_recovery as recovery
    import ssh_transport
    from private_inventory_lock import (
        Directory as _Directory, Snapshot as _Snapshot, PresentedPath as _PresentedPath,
        InventoryLock as _ConfigLock, lock_directory as _receipt_directory,
    )

_RECEIPTS = ".rag_index/ssh-recovery-adoption"


def _unknown() -> dict[str, object]:
    return {"state": "unknown", "nextAction": "inspect-recovery", "replayAllowed": False}


def _json(body: bytes) -> dict:
    value = json.loads(body.decode("utf-8"), object_pairs_hook=ssh_transport._reject_duplicate_keys)
    if not isinstance(value, dict):
        raise ValueError("unsupported private object")
    return value


def _validate_candidate(body: bytes, root: Path | None = None) -> ssh_transport.SshConfig:
    """Actual strict schema/graph loader sees only the pinned candidate bytes."""
    _json(body)
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary).resolve()
        with _Directory(path) as directory:
            fd = os.open(ssh_transport.CONFIG_FILENAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory.fd)
            with os.fdopen(fd, "wb") as stream:
                stream.write(body); stream.flush(); os.fsync(stream.fileno())
            with _Snapshot(directory, ssh_transport.CONFIG_FILENAME) as candidate:
                if candidate.body != body:
                    raise ValueError("candidate bytes changed")
                candidate.guard()
                config = ssh_transport.load_config(path)
                candidate.guard()
    return ssh_transport.SshConfig(root=root or path, hosts=config.hosts)


def _read_inventory(root: Path) -> tuple[Path, bytes, os.stat_result]:
    """Compatibility read: the adoption path retains its snapshot throughout."""
    with _Directory(root) as directory, _Snapshot(directory, ssh_transport.CONFIG_FILENAME) as snapshot:
        return root / ssh_transport.CONFIG_FILENAME, snapshot.body, os.fstat(snapshot.fd)


def _route_sha(body: bytes, config: ssh_transport.SshConfig, host: str) -> str:
    raw = _json(body)
    route = {entry.alias: raw["hosts"][entry.alias] for entry in ssh_transport._route_hosts(config.hosts, host)}
    return hashlib.sha256(json.dumps(route, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _route_key(host: str, old: str, adopted: str, correlation: str, route_sha: str) -> str:
    return hashlib.sha256(json.dumps([host, old, adopted, correlation, route_sha],
                                    separators=(",", ":")).encode()).hexdigest()


def _receipt_path(root: Path, key: str, kind: str) -> Path:
    return root / _RECEIPTS / (key + "." + kind + ".json")




def _exists(directory: _Directory, name: str) -> bool:
    directory.guard()
    try:
        os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _intent_fenced(directory: _Directory, host: str, old: str, new: str, correlation: str) -> bool:
    # Previously consumed intents cannot become fresh merely because route
    # bytes changed. Keep legacy four-field fences effective as well.
    legacy = hashlib.sha256(json.dumps([host, old, new, correlation], separators=(",", ":")).encode()).hexdigest()
    if any(_exists(directory, legacy + "." + kind + ".json") for kind in ("pending", "adopted")):
        return True
    names = os.listdir(directory.fd)
    if len(names) > 4096:
        raise ValueError("unbounded receipt history")
    for name in names:
        if name == _ConfigLock.name:
            continue
        if not re.fullmatch(r"[0-9a-f]{64}\.(pending|adopted)\.json", name):
            raise ValueError("unsupported receipt history")
        with _Snapshot(directory, name) as receipt:
            value = _json(receipt.body)
            if all(value.get(field) == expected for field, expected in (
                    ("host", host), ("oldControlPath", old), ("controlPath", new), ("correlationId", correlation))):
                return True
            receipt.guard()
    directory.guard()
    return False


def _encode(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _write_receipt(directory: _Directory, name: str, value: dict) -> dict:
    directory.guard()
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory.fd)
    with os.fdopen(fd, "wb") as stream:
        stream.write(_encode(value))
        stream.flush(); os.fsync(stream.fileno())
    directory.guard()
    os.fsync(directory.fd)
    directory.guard()
    with _Snapshot(directory, name) as receipt:
        if receipt.body != _encode(value):
            raise ValueError("receipt bytes changed")
        receipt.guard()
        return receipt.pin()


def _create_receipt(root: Path, host: str, old: str, adopted: str, intent: dict, kind: str) -> None:
    """Compatibility constructor for explicit local fixture fences."""
    if kind not in {"pending", "adopted"}:
        raise ValueError("unsupported receipt")
    presented = _PresentedPath(Path(root).absolute())
    with _Directory(presented.canonical) as directory, _Snapshot(directory, ssh_transport.CONFIG_FILENAME) as source:
        config = _validate_candidate(source.body, presented.canonical)
        key = _route_key(host, old, adopted, intent["correlationId"], _route_sha(source.body, config, host))
        with _receipt_directory(directory) as receipts:
            _write_receipt(receipts, key + "." + kind + ".json", {"schemaVersion": 1, "state": kind})


def _intent(source: _Snapshot, host: str, target: ssh_transport.SshHost) -> dict:
    value = _json(source.body)
    identity = recovery._identity(target)
    required = {"schemaVersion", "host", "correlationId", "state", "controlPath", *identity}
    if (set(value) != required or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1
            or value["host"] != host or value["state"] != "ready"
            or any(value[key] != expected for key, expected in identity.items())
            or not isinstance(value["correlationId"], str) or not re.fullmatch(r"[0-9a-f]{32}", value["correlationId"])):
        raise ValueError("intent does not match route")
    expected = recovery._recovery_socket_path(target, value["correlationId"])
    if expected is None or value["controlPath"] != str(expected[1]) or value["controlPath"] == str(target.remote_control_path):
        raise ValueError("intent socket does not match correlation")
    return value


def adopt(root: Path | str, host: str, timeout: int = 5) -> dict[str, object]:
    if os.name != "posix" or type(timeout) is not int or not 1 <= timeout <= 60 or not isinstance(host, str) or not ssh_transport._ALIAS_RE.fullmatch(host):
        return _unknown()
    temporary = None
    try:
        presented = _PresentedPath(Path(root).absolute())
        root_path = presented.canonical
        with _Directory(root_path) as directory, _Snapshot(directory, ssh_transport.CONFIG_FILENAME) as source, \
                _receipt_directory(directory) as receipts, _ConfigLock(receipts) as ownership:
            # Never load the changing named inventory: validate and use exactly
            # the strict snapshot, including every gateway and private field.
            presented.guard(); ownership.guard(); source.guard()
            config = _validate_candidate(source.body, root_path)
            presented.guard(); ownership.guard(); source.guard()
            target = config.hosts.get(host)
            if target is None or target.transport != "nested" or target.remote_control_path is None:
                return _unknown()
            intent_path = recovery._intent_path(root_path, host, target)
            with _Directory(intent_path.parent) as intent_directory, _Snapshot(intent_directory, intent_path.name) as intent_source:
                intent = _intent(intent_source, host, target)
                old, new = str(target.remote_control_path), intent["controlPath"]
                route_sha = _route_sha(source.body, config, host)
                key = _route_key(host, old, new, intent["correlationId"], route_sha)
                pending_name, terminal_name = key + ".pending.json", key + ".adopted.json"
                if (_exists(receipts, pending_name) or _exists(receipts, terminal_name)
                        or _intent_fenced(receipts, host, old, new, intent["correlationId"])):
                    return _unknown()
                def guards():
                    presented.guard(); ownership.guard(); intent_source.guard(); receipts.guard(); source.guard()
                guards()
                if recovery._socket_state(config, target, target.remote_control_path, timeout) != "absent":
                    return _unknown()
                guards()
                if recovery._socket_state(config, target, PurePosixPath(new), timeout) != "ready":
                    return _unknown()
                guards()
                raw = _json(source.body)
                raw["hosts"][host]["remoteControlPath"] = new
                encoded = (json.dumps(raw, sort_keys=True, separators=(",", ":")) + "\n").encode()
                _validate_candidate(encoded, root_path)
                guards()
                value = {"schemaVersion": 1, "host": host, "oldControlPath": old,
                         "controlPath": new, "correlationId": intent["correlationId"],
                         "routeSha256": route_sha, "source": source.pin(), "intent": intent_source.pin(),
                         "ownershipLock": ownership.pin()}
                # No replacement is attempted until both file AND directory
                # fsync completed. A failure leaves the create-only barrier.
                pending_value = {**value, "state": "pending"}
                pending_pin = _write_receipt(receipts, pending_name, pending_value)
                with _Snapshot(receipts, pending_name) as pending:
                    if pending.pin() != pending_pin or pending.body != _encode(pending_value):
                        raise ValueError("pending generation changed")
                    guards(); pending.guard()
                    if _exists(receipts, terminal_name):
                        return _unknown()
                    temporary = ".ssh-adopt-" + uuid4().hex
                    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory.fd)
                    try:
                        with os.fdopen(fd, "wb") as stream:
                            stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
                        with _Snapshot(directory, temporary) as candidate:
                            if candidate.body != encoded:
                                raise ValueError("replacement candidate changed")
                            _validate_candidate(candidate.body, root_path)
                            if _exists(receipts, terminal_name):
                                return _unknown()
                            replace_fd = directory.fd
                            # All admission reads precede this final guard group.
                            # Source is last; no unrelated call precedes replace.
                            presented.guard(); ownership.guard(); receipts.guard()
                            intent_source.guard(); pending.guard(); candidate.guard()
                            source.guard()
                            os.replace(temporary, ssh_transport.CONFIG_FILENAME,
                                       src_dir_fd=replace_fd, dst_dir_fd=replace_fd)
                            temporary = None
                            os.fsync(directory.fd)
                        with _Snapshot(directory, ssh_transport.CONFIG_FILENAME) as adopted:
                            if adopted.body != encoded:
                                raise ValueError("adopted bytes changed")
                            _validate_candidate(adopted.body, root_path)
                            presented.guard(); ownership.guard(); adopted.guard(); intent_source.guard(); pending.guard()
                            terminal_value = {**value, "state": "adopted", "adopted": adopted.pin()}
                            terminal_pin = _write_receipt(receipts, terminal_name, terminal_value)
                            with _Snapshot(receipts, terminal_name) as terminal:
                                if terminal.pin() != terminal_pin or terminal.body != _encode(terminal_value):
                                    raise ValueError("terminal generation changed")
                                terminal.guard()
                                presented.guard(); ownership.guard(); adopted.guard(); intent_source.guard(); pending.guard()
                    finally:
                        if temporary is not None:
                            os.unlink(temporary, dir_fd=directory.fd)
                            temporary = None
                return {"state": "ready", "nextAction": "configured-probe", "replayAllowed": False}
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, ssh_transport.SshConfigError, recovery.RecoveryError):
        return _unknown()

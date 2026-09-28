"""One bounded, durable mode repair for a verified Tart macOS fixture pair.

The GitHub artifact transport restores the captured DMGs with owner-write bits.
The fixture HTTPS server requires immutable local copies. This route verifies both
guest files before changing only their modes. A lost mutation response is never
replayed; status performs a read-only guest observation instead.
"""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
from typing import Any, Callable, Mapping
from uuid import UUID


VM_NAME = "vpn-control-boot-control53"
BASE_NAME = "vpn-control-2.1.19.dmg"
TARGET_NAME = "vpn-control-2.2.0.dmg"
TIMEOUT_SECONDS = 120
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")

# Fixed Python is argv data to Tart; no shell, credentials, arbitrary guest path,
# package execution, or request-controlled interpreter code crosses this route.
_GUEST_CODE = r'''
import hashlib,json,os,stat,sys
mode,root,base_sha,base_size,target_sha,target_size=sys.argv[1:]
def directory(path):
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for leaf in path.strip('/').split('/'):
            if not leaf or leaf in ('.','..'): raise ValueError('unsafe directory')
            other=os.open(leaf,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd); fd=other
        return fd
    except BaseException:
        os.close(fd); raise
def checked(label,name,digest,size):
    parent=directory(root+'/pair/packages/'+label)
    try:
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
        try:
            before=os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or before.st_size!=int(size):
                raise ValueError('unsafe fixture file')
            if stat.S_IMODE(before.st_mode) not in (0o444,0o644): raise ValueError('unsafe fixture mode')
            h=hashlib.sha256()
            while True:
                chunk=os.read(fd,1024*1024)
                if not chunk: break
                h.update(chunk)
            if h.hexdigest()!=digest: raise ValueError('fixture digest mismatch')
            at=os.stat(name,dir_fd=parent,follow_symlinks=False)
            if (at.st_dev,at.st_ino)!=(before.st_dev,before.st_ino): raise ValueError('fixture replacement')
            return parent,fd,before,h.hexdigest()
        except BaseException:
            os.close(fd); raise
    except BaseException:
        os.close(parent); raise
handles=[]
try:
    handles.append(('base',checked('base','vpn-control-2.1.19.dmg',base_sha,base_size)))
    handles.append(('target',checked('target','vpn-control-2.2.0.dmg',target_sha,target_size)))
    if mode=='mutate':
        for _,(_,fd,_,_) in handles: os.fchmod(fd,0o444)
    elif mode!='inspect': raise ValueError('unsupported mode')
    output={}
    for label,(parent,fd,before,digest) in handles:
        after=os.fstat(fd)
        name='vpn-control-2.1.19.dmg' if label=='base' else 'vpn-control-2.2.0.dmg'
        at=os.stat(name,dir_fd=parent,follow_symlinks=False)
        if (after.st_dev,after.st_ino)!=(before.st_dev,before.st_ino) or (at.st_dev,at.st_ino)!=(before.st_dev,before.st_ino):
            raise ValueError('fixture replacement')
        output[label]={'sha256':digest,'sizeBytes':after.st_size,'mode':stat.S_IMODE(after.st_mode)}
    print(json.dumps(output,sort_keys=True,separators=(',',':')))
finally:
    for _,(parent,fd,_,_) in handles:
        os.close(fd); os.close(parent)
'''


def _canonical_uuid(value: Any) -> str:
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError("correlationId must be a canonical UUID")
    return value


def _request(value: Mapping[str, Any]) -> dict[str, Any]:
    required = {"correlationId", "sourceSha", "guestRoot", "baseSha256", "baseSizeBytes",
                "targetSha256", "targetSizeBytes"}
    if not isinstance(value, Mapping) or set(value) != required:
        raise ValueError("fixture stage request has unsupported fields")
    result = dict(value)
    result["correlationId"] = _canonical_uuid(result["correlationId"])
    source = result["sourceSha"]
    if not isinstance(source, str) or not _HEX40.fullmatch(source):
        raise ValueError("sourceSha must be a full lowercase commit SHA")
    if result["guestRoot"] != f"/Users/admin/macos-parity{source[:7]}":
        raise ValueError("guest fixture root is not bound to sourceSha")
    for label in ("base", "target"):
        digest, size = result[f"{label}Sha256"], result[f"{label}SizeBytes"]
        if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
            raise ValueError(f"{label} digest is invalid")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise ValueError(f"{label} size is invalid")
    return result


def _directory(root: Path) -> Path:
    path = Path(root).resolve() / ".rag_index" / "macos-fixture-guest-stage"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
        raise ValueError("fixture stage state directory is unsafe")
    return path


def _read(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise ValueError("fixture stage state file is unsafe")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
        return json.load(stream)


def _save(path: Path, record: Mapping[str, Any]) -> None:
    temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(record, stream, sort_keys=True, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _command(request: Mapping[str, Any], mode: str) -> list[str]:
    return ["tart", "exec", VM_NAME, "/usr/bin/python3", "-c", _GUEST_CODE, mode,
            request["guestRoot"], request["baseSha256"], str(request["baseSizeBytes"]),
            request["targetSha256"], str(request["targetSizeBytes"])]


def _verified(stdout: str, request: Mapping[str, Any]) -> dict[str, Any] | None:
    try:
        value = json.loads(stdout)
    except (ValueError, TypeError):
        return None
    if not isinstance(value, dict) or set(value) != {"base", "target"}:
        return None
    for label in ("base", "target"):
        item = value[label]
        if not isinstance(item, dict) or item != {
            "sha256": request[f"{label}Sha256"], "sizeBytes": request[f"{label}SizeBytes"], "mode": 0o444
        }:
            return None
    return value


def _run(request: Mapping[str, Any], mode: str, runner: Callable[..., Any]) -> dict[str, Any] | None:
    try:
        completed = runner(_command(request, mode), capture_output=True, text=True, timeout=TIMEOUT_SECONDS,
                           check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return _verified(completed.stdout, request) if completed.returncode == 0 else None


def _public(record: Mapping[str, Any]) -> dict[str, Any]:
    result = {"ok": record["state"] == "complete", "state": record["state"],
              "correlationId": record["request"]["correlationId"],
              "sourceSha": record["request"]["sourceSha"], "vmName": VM_NAME,
              "replayAllowed": False}
    if record["state"] == "complete":
        result["observation"] = record["observation"]
    return result


def _lock(directory: Path):
    path = directory / "lock"
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        os.close(descriptor)
        raise ValueError("fixture stage lock is unsafe")
    return os.fdopen(descriptor, "r+", encoding="utf-8")


def start(root: str | Path, inputs: Mapping[str, Any], *, runner: Callable[..., Any] = subprocess.run) -> dict[str, Any]:
    request = _request(inputs)
    directory = _directory(Path(root))
    with _lock(directory) as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        path = directory / (request["correlationId"] + ".json")
        record = _read(path)
        if record is not None:
            if record["request"] != request:
                raise ValueError("correlationId is bound to different fixture inputs")
            return _public(record)
        record = {"state": "unknown", "request": request, "observation": None}
        _save(path, record)  # Persist uncertainty before the only mutation call.
        observed = _run(request, "mutate", runner)
        if observed is not None:
            record = {**record, "state": "complete", "observation": observed}
            _save(path, record)
        return _public(record)


def status(root: str | Path, inputs: Mapping[str, Any], *, runner: Callable[..., Any] = subprocess.run) -> dict[str, Any]:
    if not isinstance(inputs, Mapping) or set(inputs) != {"correlationId"}:
        raise ValueError("status requires only correlationId")
    correlation = _canonical_uuid(inputs["correlationId"])
    directory = _directory(Path(root))
    with _lock(directory) as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        path = directory / (correlation + ".json")
        record = _read(path)
        if record is None:
            raise ValueError("fixture stage correlation is unknown")
        if record["state"] != "complete":
            observed = _run(record["request"], "inspect", runner)
            if observed is not None:
                record = {**record, "state": "complete", "observation": observed}
                _save(path, record)
        return _public(record)


def collect(root: str | Path, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(inputs, Mapping) or set(inputs) != {"correlationId"}:
        raise ValueError("collect requires only correlationId")
    correlation = _canonical_uuid(inputs["correlationId"])
    record = _read(_directory(Path(root)) / (correlation + ".json"))
    if record is None:
        raise ValueError("fixture stage correlation is unknown")
    return _public(record)

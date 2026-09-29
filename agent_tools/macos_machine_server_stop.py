"""One-shot stop of the fixed, source-bound Tart Mac fixture HTTPS server.

The host journal is written before a guest signal can be sent. A lost response
remains unknown; status only reads the guest's final receipt and fresh kernel
state. No caller-controlled guest path, command, or PID is accepted outside the
exact campaign binding.
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
from typing import Any, Mapping, Protocol

from .macos_machine_receipts import (MacReceiptError, ReceiptBinding,
                                     read_guest_candidate, validate_server_stop, _uuid)
from .macos_machine_kernel_observer import observe_server_generation
from .macos_machine_tart_readonly import TartReadOnlyProvider
from . import macos_machine_acceptance as acceptance
from .macos_machine_acceptance import VM_NAME


_SOURCE = re.compile(r"[0-9a-f]{40}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_START = re.compile(r"darwin:[1-9][0-9]*:[0-9]{1,6}\Z")
_FIELDS = {"schemaVersion", "sourceSha", "correlationId", "scenario", "jobId",
           "operationId", "bootSessionUuid", "reservationId", "fixtureReceiptArtifactId",
           "serverInstanceId", "serverPid", "serverProcessStartIdentity", "readySha256"}

# This is fixed source, not caller-provided Python. It creates the private
# guest intent before sending the only signal. It deliberately does not remove
# a stale intent, even if the target is now absent.
_GUEST_STOP = r'''import ctypes,hashlib,json,os,pathlib,signal,socket,stat,sys,uuid
request=json.loads(sys.argv[1]);source=request['sourceSha'];correlation=request['correlationId']
if len(source)!=40 or any(c not in '0123456789abcdef' for c in source):raise ValueError('source')
if str(uuid.UUID(correlation))!=correlation:raise ValueError('correlation')
root=pathlib.Path('/Users/admin/macos-parity'+source[:7])
path=root/'state'/'acceptance-evidence'/correlation
parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
try:
 for index,part in enumerate(path.parts[1:]):
  child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
  info=os.fstat(child)
  if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0,501) or info.st_mode&0o022 or (index>=3 and (info.st_uid!=501 or stat.S_IMODE(info.st_mode)!=0o700)):
   os.close(child);raise ValueError('ancestor')
  os.close(parent);parent=child
 fd=os.open('server-ready.json',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
 try:
  before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode) or before.st_uid!=501 or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1 or not 0<before.st_size<=16384:raise ValueError('ready')
  raw=os.read(fd,16385);after=os.fstat(fd);now=os.stat('server-ready.json',dir_fd=parent,follow_symlinks=False)
  fields=('st_dev','st_ino','st_size','st_mtime_ns','st_uid','st_mode','st_nlink')
  if len(raw)!=before.st_size or tuple(getattr(before,k) for k in fields)!=tuple(getattr(after,k) for k in fields) or tuple(getattr(before,k) for k in fields)!=tuple(getattr(now,k) for k in fields):raise ValueError('ready changed')
 finally:os.close(fd)
 ready=json.loads(raw);pid=request['serverPid'];start=request['serverProcessStartIdentity'];port=ready.get('port')
 if hashlib.sha256(raw).hexdigest()!=request['readySha256'] or ready.get('serverInstanceId')!=request['serverInstanceId'] or ready.get('serverPid')!=pid or ready.get('serverProcessStartIdentity')!=start or request['fixtureReceiptArtifactId']!='sha256-'+str(ready.get('fixtureReceiptSha256')) or type(pid)!=int or pid<=0 or type(port)!=int or not 0<port<65536:raise ValueError('ready identity')
 class Info(ctypes.Structure):
  _fields_=[('flags',ctypes.c_uint32),('status',ctypes.c_uint32),('xstatus',ctypes.c_uint32),('pid',ctypes.c_uint32),('ppid',ctypes.c_uint32),('uid',ctypes.c_uint32),('gid',ctypes.c_uint32),('ruid',ctypes.c_uint32),('rgid',ctypes.c_uint32),('svuid',ctypes.c_uint32),('svgid',ctypes.c_uint32),('rfu_1',ctypes.c_uint32),('comm',ctypes.c_char*16),('name',ctypes.c_char*32),('nfiles',ctypes.c_uint32),('pgid',ctypes.c_uint32),('pjobc',ctypes.c_uint32),('tdev',ctypes.c_uint32),('tpgid',ctypes.c_uint32),('nice',ctypes.c_int32),('startsec',ctypes.c_uint64),('startusec',ctypes.c_uint64)]
 lib=ctypes.CDLL('/usr/lib/libproc.dylib',use_errno=True);fn=lib.proc_pidinfo
 fn.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_int];fn.restype=ctypes.c_int
 info=Info();size=fn(pid,3,0,ctypes.byref(info),ctypes.sizeof(info))
 if size!=ctypes.sizeof(info) or info.pid!=pid or 'darwin:'+str(info.startsec)+':'+str(info.startusec)!=start or info.uid!=501:raise ValueError('process generation')
 connection=socket.create_connection(('127.0.0.1',port),timeout=0.5);connection.close()
 try:os.stat('server-stop-intent.json',dir_fd=parent,follow_symlinks=False)
 except FileNotFoundError:pass
 else:raise ValueError('stop already requested')
 intent={**request,'stopRequestCount':1,'port':port}
 data=(json.dumps(intent,sort_keys=True,separators=(',',':'))+'\n').encode()
 fd=os.open('server-stop-intent.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
 try:
  if os.fstat(fd).st_uid!=501:raise ValueError('intent owner')
  if os.write(fd,data)!=len(data):raise ValueError('intent write incomplete')
  os.fsync(fd)
 finally:os.close(fd)
 os.fsync(parent)
 info=Info();size=fn(pid,3,0,ctypes.byref(info),ctypes.sizeof(info))
 if size!=ctypes.sizeof(info) or info.pid!=pid or 'darwin:'+str(info.startsec)+':'+str(info.startusec)!=start or info.uid!=501:raise ValueError('process changed before signal')
 os.kill(pid,signal.SIGTERM)
 print(json.dumps({'stopRequestCount':1,'serverPid':pid,'serverProcessStartIdentity':start}))
finally:os.close(parent)
'''


def _request(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _FIELDS or type(value.get("schemaVersion")) is not int or value["schemaVersion"] != 1:
        raise MacReceiptError("Mac server stop request fields are invalid.")
    result = dict(value)
    binding = ReceiptBinding(*(result[key] for key in (
        "sourceSha", "correlationId", "scenario", "jobId", "operationId",
        "bootSessionUuid", "reservationId", "fixtureReceiptArtifactId")))
    binding.validate()
    if not _SOURCE.fullmatch(result["sourceSha"]) or \
            not _SHA.fullmatch(str(result["readySha256"])) or \
            type(result["serverPid"]) is not int or result["serverPid"] <= 0 or \
            not _START.fullmatch(str(result["serverProcessStartIdentity"])):
        raise MacReceiptError("Mac server stop identity is invalid.")
    _uuid(result["serverInstanceId"])
    return result


def _trusted_campaign(root: Path, request: Mapping[str, Any]) -> None:
    """A stop cannot invent a new campaign around a same-prefix guest path."""
    group = acceptance._private_group(root)
    prior = acceptance._read(group / (request["correlationId"] + ".json"))
    if not isinstance(prior, dict) or prior.get("state") not in {"unknown", "complete"} or \
            prior.get("operationId") != request["operationId"] or \
            prior.get("jobId") != request["jobId"] or \
            not isinstance(prior.get("request"), dict) or \
            not isinstance(prior.get("admission"), dict):
        raise MacReceiptError("Trusted Mac machine campaign is unavailable for server stop.")
    expected_request = {"sourceSha": "sourceSha", "correlationId": "correlationId",
                        "scenario": "scenario", "fixtureReceiptArtifactId": "fixtureReceiptArtifactId"}
    if any(prior["request"].get(name) != request[field]
           for name, field in expected_request.items()) or \
            prior["admission"].get("bootSessionUuid") != request["bootSessionUuid"] or \
            prior["admission"].get("reservationId") != request["reservationId"]:
        raise MacReceiptError("Mac server stop does not match the accepted full-source campaign.")


class Boundary(Protocol):
    def request_stop(self, request: Mapping[str, Any]) -> None: ...
    def observe_stop(self, request: Mapping[str, Any]) -> Mapping[str, Any] | None: ...


class TartBoundary:
    def __init__(self, *, runner=subprocess.run):
        self.runner = runner

    def request_stop(self, request: Mapping[str, Any]) -> None:
        TartReadOnlyProvider(runner=self.runner)._require_running()
        result = self.runner(["tart", "exec", VM_NAME, "/usr/bin/python3", "-c", _GUEST_STOP,
                              json.dumps(request, sort_keys=True, separators=(",", ":"))],
                             capture_output=True, text=True, timeout=30, check=False)
        if result.returncode != 0:
            raise MacReceiptError("Mac fixture stop signal is unconfirmed.")

    def observe_stop(self, request: Mapping[str, Any]) -> Mapping[str, Any] | None:
        try:
            receipt = read_guest_candidate(request["sourceSha"], request["correlationId"],
                                           "server-stop", runner=self.runner)
            observed = observe_server_generation(request["sourceSha"], request["correlationId"],
                expected_ready_sha256=request["readySha256"],
                expected_instance_id=request["serverInstanceId"], expected_pid=request["serverPid"],
                expected_start=request["serverProcessStartIdentity"], runner=self.runner)
            binding = ReceiptBinding(*(request[key] for key in (
                "sourceSha", "correlationId", "scenario", "jobId", "operationId",
                "bootSessionUuid", "reservationId", "fixtureReceiptArtifactId")))
            validate_server_stop(receipt, binding,
                expected_instance_id=request["serverInstanceId"], expected_pid=request["serverPid"],
                expected_start=request["serverProcessStartIdentity"],
                expected_ready_sha256=request["readySha256"],
                fresh_pid_generation_absent=not observed["pidGenerationAlive"],
                fresh_listener_absent=not observed["listenerOpen"])
            return receipt
        except (MacReceiptError, OSError, ValueError):
            return None


def _directory(root: Path) -> Path:
    root = root.resolve(strict=True)
    parent = root / ".rag_index"
    parent.mkdir(mode=0o700, exist_ok=True)
    path = parent / "macos-machine-server-stop"
    path.mkdir(mode=0o700, exist_ok=True)
    for node in (parent, path):
        info = node.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise MacReceiptError("Mac server stop journal directory is unsafe.")
    return path


def _read(path: Path) -> dict[str, Any] | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "r", encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 16384:
            raise MacReceiptError("Mac server stop journal is unsafe.")
        value = json.load(stream)
    if not isinstance(value, dict):
        raise MacReceiptError("Mac server stop journal is invalid.")
    return value


def _save(path: Path, record: Mapping[str, Any]) -> None:
    temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(record, stream, sort_keys=True, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)


def _public(record: Mapping[str, Any]) -> dict[str, Any]:
    request = record["request"]
    result = {"state": record["state"], "sourceSha": request["sourceSha"],
              "correlationId": request["correlationId"], "serverInstanceId": request["serverInstanceId"],
              "replayAllowed": False}
    if record["state"] == "complete":
        result["receipt"] = record["receipt"]
    return result


def _lock(directory: Path):
    fd = os.open(directory / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        os.close(fd)
        raise MacReceiptError("Mac server stop lock is unsafe.")
    return os.fdopen(fd, "r+")


def start(root: Path, inputs: Mapping[str, Any], boundary: Boundary | None = None) -> dict[str, Any]:
    request = _request(inputs)
    _trusted_campaign(root, request)
    boundary = boundary or TartBoundary()
    directory = _directory(root)
    with _lock(directory) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        path = directory / (request["correlationId"] + ".json")
        record = _read(path)
        if record is not None:
            if record.get("request") != request:
                raise MacReceiptError("Mac server stop correlation is already bound.")
            return _public(record)
        others = list(directory.glob("*.json"))
        if len(others) > 128:
            raise MacReceiptError("Mac server stop journal is unbounded.")
        for other in others:
            previous = _read(other)
            if previous is None or previous.get("state") != "complete":
                raise MacReceiptError("A prior Mac fixture server stop remains unknown.")
        record = {"schemaVersion": 1, "request": request, "state": "unknown", "receipt": None}
        _save(path, record)
        try:
            boundary.request_stop(request)
        except Exception:
            pass  # Lost execution result is permanently uncertain, never replayed.
        return _public(record)


def status(root: Path, correlation_id: str, boundary: Boundary | None = None) -> dict[str, Any]:
    correlation = _uuid(correlation_id)
    boundary = boundary or TartBoundary()
    directory = _directory(root)
    with _lock(directory) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        path = directory / (correlation + ".json")
        record = _read(path)
        if record is None:
            raise MacReceiptError("Mac server stop correlation is unknown.")
        try:
            receipt = boundary.observe_stop(record["request"])
        except Exception:
            receipt = None
        if receipt is None:
            # Keep the historical receipt, but never reuse it as a current
            # stop claim after a changed guest generation or reopened port.
            return _public({**record, "state": "unknown", "receipt": None})
        if record.get("state") != "complete" or record.get("receipt") != receipt:
            record = {**record, "state": "complete", "receipt": dict(receipt)}
            _save(path, record)
        return _public(record)


def collect(root: Path, correlation_id: str) -> dict[str, Any]:
    record = _read(_directory(root) / (_uuid(correlation_id) + ".json"))
    if record is None:
        raise MacReceiptError("Mac server stop correlation is unknown.")
    result = _public(record)
    if result["state"] == "complete":
        result["state"] = "historical-receipt"
        result["currentState"] = "unverified"
    return result

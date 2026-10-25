"""One-shot download of a pinned VirtIO ISO into a private Arch fixture root.

The destination is new and distinct from all historical Windows guests. A
local intent precedes the remote request; an uncertain result is observed via
status and never retried.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Mapping

try:
    from . import ssh_transport
except ImportError:  # fixed MCP CLI fallback
    import ssh_transport  # type: ignore[no-redef]


HOST = "archlinux"
URL = "https://github.com/microsoft/openvmm-deps/releases/download/virtio-iso-v1/virtio-win-0.1.285.iso"
SHA256 = "e14cf2b94492c3e925f0070ba7fdfedeb2048c91eea9c5a5afb30232a3976331"
SIZE = 789645312
ROOT = "/home/kardinal/vpn-control-windows-baseline-20260929"
DEST = ROOT + "/runtime/virtio-win-0.1.285.iso"
_UUID = re.compile(r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$")

_REMOTE = r'''import hashlib,json,os,stat,sys,urllib.error,urllib.request
URL=__URL__
EXPECTED=__SHA__
SIZE=__SIZE__
ROOT=__ROOT__
DEST=__DEST__
CORR=__CORR__
MODE=__MODE__
def check_parent(path,mode):
 info=os.lstat(path)
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=mode:raise ValueError('unsafe-directory')
def file_hash(path):
 fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
 try:
  before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid() or stat.S_IMODE(before.st_mode)!=0o400 or before.st_nlink!=1:raise ValueError('unsafe-file')
  h=hashlib.sha256();size=0
  while True:
   chunk=os.read(fd,1048576)
   if not chunk:break
   size+=len(chunk)
   if size>SIZE:raise ValueError('oversize')
   h.update(chunk)
  after=os.fstat(fd);name=os.stat(path,follow_symlinks=False)
  fields=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
  if not all(getattr(before,x)==getattr(after,x)==getattr(name,x) for x in fields):raise ValueError('changed-file')
  return size,h.hexdigest()
 finally:os.close(fd)
def status():
 if not os.path.isdir(ROOT):return 'absent'
 check_parent(ROOT,0o700)
 runtime=os.path.join(ROOT,'runtime')
 if not os.path.isdir(runtime):return 'absent'
 check_parent(runtime,0o700)
 part=os.path.join(runtime,'.download-'+CORR+'.part')
 if not os.path.lexists(DEST):
  return 'partial' if os.path.lexists(part) else 'absent'
 if os.path.lexists(part):return 'linked-partial'
 size,digest=file_hash(DEST)
 return 'verified' if size==SIZE and digest==EXPECTED else 'mismatch'
def partial_info():
 part=os.path.join(ROOT,'runtime','.download-'+CORR+'.part')
 if not os.path.lexists(part):return None,None
 info=os.lstat(part)
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode) not in (0o600,0o400) or info.st_nlink not in (1,2):raise ValueError('unsafe-partial')
 return info.st_size,info.st_mtime_ns
try:
 current=status()
 if MODE=='start' and current=='absent':
  if not os.path.exists(ROOT):os.mkdir(ROOT,0o700)
  check_parent(ROOT,0o700)
  runtime=os.path.join(ROOT,'runtime')
  if not os.path.exists(runtime):os.mkdir(runtime,0o700)
  check_parent(runtime,0o700)
  part=os.path.join(runtime,'.download-'+CORR+'.part')
  fd=os.open(part,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  try:
   request=urllib.request.Request(URL,headers={'User-Agent':'vpn-control-baseline-fetch/1'})
   with urllib.request.urlopen(request,timeout=30) as response:
    h=hashlib.sha256();size=0
    while True:
     chunk=response.read(1048576)
     if not chunk:break
     size+=len(chunk)
     if size>SIZE:raise ValueError('oversize')
     view=memoryview(chunk)
     while view:view=view[os.write(fd,view):]
     h.update(chunk)
   os.fchmod(fd,0o400)
   os.fsync(fd)
  finally:os.close(fd)
  if size!=SIZE or h.hexdigest()!=EXPECTED:raise ValueError('digest-mismatch')
  os.link(part,DEST,follow_symlinks=False)
  os.unlink(part)
  dfd=os.open(runtime,os.O_RDONLY|os.O_DIRECTORY);os.fsync(dfd);os.close(dfd)
  current=status()
 partial_size,partial_mtime=partial_info()
 print(json.dumps({'schemaVersion':1,'host':'archlinux','correlationId':CORR,
                   'state':current,'sha256':EXPECTED if current=='verified' else None,
                   'sizeBytes':SIZE if current=='verified' else None,
                   'partialSizeBytes':partial_size,'partialMtimeNs':partial_mtime},separators=(',',':')))
except (OSError,ValueError,urllib.error.URLError):
 print(json.dumps({'schemaVersion':1,'host':'archlinux','correlationId':CORR,'state':'unknown',
                   'sha256':None,'sizeBytes':None,'partialSizeBytes':None,'partialMtimeNs':None}))
'''


def _validate(correlation_id: str, host: str, timeout_seconds: int) -> None:
    if (host != HOST or not isinstance(correlation_id, str) or not _UUID.fullmatch(correlation_id)
            or type(timeout_seconds) is not int or not 30 <= timeout_seconds <= 300):
        raise ValueError("Windows driver fetch requires fixed host, canonical correlation and bounded timeout")


def _journal(root: str | Path, correlation_id: str, *, create: bool) -> Path:
    directory = Path(root).resolve() / ".rag_index" / "windows-vm-driver-fetch"
    if create:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = os.lstat(directory)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("Windows driver fetch journal directory is unsafe")
    return directory / "intent.json"


def _save_intent(path: Path, correlation_id: str) -> None:
    payload = json.dumps({"schemaVersion": 1, "correlationId": correlation_id,
                          "host": HOST, "url": URL, "sha256": SHA256, "sizeBytes": SIZE,
                          "destination": DEST}, sort_keys=True).encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _read_intent(path: Path, correlation_id: str) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("Windows driver fetch intent is unsafe")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            value = json.load(stream)
    finally:
        if fd >= 0:
            os.close(fd)
    if value != {"schemaVersion": 1, "correlationId": correlation_id, "host": HOST,
                 "url": URL, "sha256": SHA256, "sizeBytes": SIZE, "destination": DEST}:
        raise ValueError("Windows driver fetch intent changed")


def _remote(root: str | Path, host: str, correlation_id: str, mode: str, timeout_seconds: int) -> dict[str, Any]:
    program = (_REMOTE.replace("__URL__", repr(URL)).replace("__SHA__", repr(SHA256))
               .replace("__SIZE__", repr(SIZE)).replace("__ROOT__", repr(ROOT))
               .replace("__DEST__", repr(DEST)).replace("__CORR__", repr(correlation_id))
               .replace("__MODE__", repr(mode)))
    config = ssh_transport.load_config(root)
    if host not in config.hosts or ssh_transport.connection_host(config, host).password is not None:
        raise ValueError("Configured Arch transport is unavailable")
    command = ("python3", "-c", "exec(" + repr(program) + ")")
    argv = ssh_transport.build_ssh_argv(config, host, min(timeout_seconds, 30), command=command)
    completed = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               timeout=timeout_seconds, check=False)
    if completed.returncode != 0 or len(completed.stdout) > 2048:
        raise ValueError("Windows driver fetch transport is unknown")
    value = json.loads(completed.stdout)
    if (not isinstance(value, Mapping) or set(value) != {"schemaVersion", "host", "correlationId", "state", "sha256", "sizeBytes", "partialSizeBytes", "partialMtimeNs"}
            or value["schemaVersion"] != 1 or value["host"] != HOST or value["correlationId"] != correlation_id
            or value["state"] not in ("verified", "absent", "partial", "linked-partial", "mismatch", "unknown")):
        raise ValueError("Windows driver fetch response is invalid")
    if ((value["partialSizeBytes"] is None) != (value["partialMtimeNs"] is None)
            or value["partialSizeBytes"] is not None and
            (type(value["partialSizeBytes"]) is not int or not 0 <= value["partialSizeBytes"] <= SIZE or
             type(value["partialMtimeNs"]) is not int or value["partialMtimeNs"] < 1)):
        raise ValueError("Windows driver fetch partial evidence is invalid")
    if value["state"] == "verified" and (value["sha256"] != SHA256 or value["sizeBytes"] != SIZE):
        raise ValueError("Windows driver fetch verified identity changed")
    return dict(value)


def start(root: str | Path, *, host: str, correlation_id: str, timeout_seconds: int = 300) -> dict[str, Any]:
    _validate(correlation_id, host, timeout_seconds)
    path = _journal(root, correlation_id, create=True)
    try:
        _save_intent(path, correlation_id)
    except FileExistsError as error:
        raise ValueError("Windows driver fetch intent already exists; use exact status") from error
    try:
        result = _remote(root, host, correlation_id, "start", timeout_seconds)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        result = {"state": "unknown"}
    return {"correlationId": correlation_id, "state": result["state"],
            "sha256": result.get("sha256"), "sizeBytes": result.get("sizeBytes"),
            "partialSizeBytes": result.get("partialSizeBytes"),
            "partialMtimeNs": result.get("partialMtimeNs"),
            "destination": DEST if result["state"] == "verified" else None,
            "replayAllowed": False, "nativeActionAllowed": False}


def status(root: str | Path, *, host: str, correlation_id: str, timeout_seconds: int = 120) -> dict[str, Any]:
    _validate(correlation_id, host, timeout_seconds)
    _read_intent(_journal(root, correlation_id, create=False), correlation_id)
    try:
        result = _remote(root, host, correlation_id, "status", timeout_seconds)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        result = {"state": "unknown"}
    return {"correlationId": correlation_id, "state": result["state"],
            "sha256": result.get("sha256"), "sizeBytes": result.get("sizeBytes"),
            "partialSizeBytes": result.get("partialSizeBytes"),
            "partialMtimeNs": result.get("partialMtimeNs"),
            "destination": DEST if result["state"] == "verified" else None,
            "replayAllowed": False, "nativeActionAllowed": False}

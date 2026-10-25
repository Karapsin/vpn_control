"""Read the one historical Python installer source for the CP117 fixture.

The installer itself is never transferred, executed, or exposed through this
module.  The only remote operation is an SSH read of a fixed Arch path, and
the public result deliberately contains no filesystem information.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
from typing import Any, Mapping

from . import ssh_transport


HOST = "archlinux"
SOURCE = "/home/kardinal/vpn-control-windows-msi-native-20260907/transfer/checkpoint58-python/python-3.13.15-amd64.exe"
SIZE_BYTES = 29_452_944
SHA256 = "edec09c4853aeae9ac36efb8c9f95b6b8e2fee65eee56d9767a8b7c69c574403"

_UNKNOWN = {"state": "unknown", "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False}

# The path, expected size, and digest are constants in this program.  In
# particular, none are SSH argv or public MCP input.  Opening through an fd
# and comparing its identity to lstat closes the usual replacement race.
_REMOTE = r'''import hashlib,json,os,stat
PATH=''' + repr(SOURCE) + r'''
SIZE=''' + repr(SIZE_BYTES) + r'''
SHA=''' + repr(SHA256) + r'''
def out(v): print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 info=os.lstat(PATH)
 if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
     or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600
     or info.st_size!=SIZE): raise ValueError()
 fd=os.open(PATH,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
 try:
  opened=os.fstat(fd)
  if (not stat.S_ISREG(opened.st_mode) or opened.st_uid!=os.geteuid()
      or stat.S_IMODE(opened.st_mode)!=0o600
      or (opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns)
         !=(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns)): raise ValueError()
  digest=hashlib.sha256()
  remaining=SIZE
  with os.fdopen(fd,'rb',closefd=False) as stream:
   while remaining:
    block=stream.read(min(131072,remaining))
    if not block: raise ValueError()
    digest.update(block);remaining-=len(block)
   if stream.read(1): raise ValueError()
  after=os.fstat(fd)
  if ((after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)
      !=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns)): raise ValueError()
 finally: os.close(fd)
 out({'state':'present'} if digest.hexdigest()==SHA else {'state':'absent-or-mismatch'})
except Exception: out({'state':'absent-or-mismatch'})
'''


def _request(value: Mapping[str, Any]) -> int:
    if (not isinstance(value, Mapping) or set(value) != {"host", "timeoutSeconds"}
            or value.get("host") != HOST or type(value.get("timeoutSeconds")) is not int
            or not 10 <= value["timeoutSeconds"] <= 60):
        raise ValueError("Python source probe requires its fixed Arch host and bounded timeout.")
    return value["timeoutSeconds"]


def _result(state: str) -> dict[str, Any]:
    if state not in {"present", "absent-or-mismatch", "unknown"}:
        return dict(_UNKNOWN)
    return {"state": state, "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False}


def _public(raw: bytes | None) -> dict[str, Any]:
    if raw is None:
        return _result("unknown")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return _result("unknown")
    if not isinstance(value, dict) or set(value) != {"state"}:
        return _result("unknown")
    return _result(value["state"])


def observe(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Observe the fixed CP95 source without a transfer or a guest action."""
    timeout = _request(value)
    try:
        config = ssh_transport.load_config(Path(root).resolve(strict=True))
        if HOST not in config.hosts or ssh_transport.connection_host(config, HOST).password is not None:
            return _result("unknown")
        command = ("python3", "-c", "exec(" + repr(_REMOTE) + ")")
        argv = ssh_transport.build_ssh_argv(config, HOST, min(timeout, 30), command=command)
        completed = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired, ssh_transport.SshConfigError):
        return _result("unknown")
    if completed.returncode != 0 or not 0 < len(completed.stdout) <= 256:
        return _result("unknown")
    return _public(completed.stdout)

"""Read-only admission facts for a separate Secure Boot and TPM Windows clone.

This preflight never creates a clone, variable store, TPM state, or reservation.
The running source is deliberately a blocker until a reviewed stopped source
and a separate clone reservation exist.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Mapping

from . import ssh_transport


HOST = "archlinux"
OWNER_PID = 3369984
OWNER_TICKS = 45177745
BASELINE_RESERVATION = "env-fc3b3308d6a07175d1e4e08330f7f3aa"
SOURCE = "/home/kardinal/vpn-control-windows-baseline-20260929/guest/disk.qcow2"
QMP = "/home/kardinal/vpn-control-windows-baseline-20260929/guest/qmp.sock"
CLONE_ROOT = "/home/kardinal/vpn-control-windows-secureboot-clone-20260929"
CODE = "/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd"
CODE_SHA256 = "cc150d941d4f1d39e596dedc545384a66ccfb3c9ba5cf9bc3a54d8d427d4d88f"
VARS = "/usr/share/edk2/x64/OVMF_VARS.4m.fd"
VARS_SHA256 = "5d2ac383371b408398accee7ec27c8c09ea5b74a0de0ceea6513388b15be5d1e"
MEMORY_KIB = 6 * 1024 * 1024
HEADROOM_KIB = 8 * 1024 * 1024
MIN_DISK_KIB = 30 * 1024 * 1024
_HASH = re.compile(r"[0-9a-f]{64}\Z")

_REMOTE = r'''import hashlib,json,os,shutil,stat,subprocess,time
PID=3369984;TICKS=45177745
SOURCE='/home/kardinal/vpn-control-windows-baseline-20260929/guest/disk.qcow2'
QMP='/home/kardinal/vpn-control-windows-baseline-20260929/guest/qmp.sock'
CLONE='/home/kardinal/vpn-control-windows-secureboot-clone-20260929'
CODE='/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd'
CODE_HASH='cc150d941d4f1d39e596dedc545384a66ccfb3c9ba5cf9bc3a54d8d427d4d88f'
VARS='/usr/share/edk2/x64/OVMF_VARS.4m.fd'
VARS_HASH='5d2ac383371b408398accee7ec27c8c09ea5b74a0de0ceea6513388b15be5d1e'
def ticks(pid):
 try:
  with open('/proc/%d/stat'%pid) as f:raw=f.read()
  return int(raw.rsplit(')',1)[1].split()[19])
 except (OSError,ValueError,IndexError):return None
def owner():
 if ticks(PID)!=TICKS:raise ValueError()
 with open('/proc/%d/cmdline'%PID,'rb') as f:raw=f.read(32769)
 if not raw or len(raw)>32768:raise ValueError()
 argv=[os.fsdecode(x) for x in raw.rstrip(b'\0').split(b'\0')]
 if os.path.basename(argv[0])!='qemu-system-x86_64':raise ValueError()
 if 'file='+SOURCE+',if=virtio,format=qcow2' not in argv:raise ValueError()
 if 'unix:'+QMP+',server=on,wait=off' not in argv:raise ValueError()
 disk=os.stat(SOURCE,follow_symlinks=False)
 if not stat.S_ISREG(disk.st_mode) or disk.st_uid!=os.geteuid() or disk.st_nlink!=1:raise ValueError()
 with open('/proc/net/unix') as f:unix=f.read(131073)
 if len(unix)>131072:raise ValueError()
 sockets=[line.split()[6] for line in unix.splitlines()[1:] if len(line.split())>=8 and line.split()[-1]==QMP]
 if len(sockets)!=1:raise ValueError()
 qmp_link='socket:['+sockets[0]+']'
 owned=False;qmp_owned=False
 for fd in os.listdir('/proc/%d/fd'%PID):
  path='/proc/%d/fd/%s'%(PID,fd)
  try:
   link=os.readlink(path)
   if link==qmp_link:qmp_owned=True
   if link==SOURCE:
    held=os.stat(path)
    if (held.st_dev,held.st_ino)==(disk.st_dev,disk.st_ino):owned=True
  except OSError:continue
 if not owned or not qmp_owned or ticks(PID)!=TICKS:raise ValueError()
 return (disk.st_dev,disk.st_ino)
def source_holders(identity):
 holders=[]
 proc=os.listdir('/proc')
 if len(proc)>8192:raise ValueError()
 for entry in proc:
  if not entry.isdigit():continue
  pid=int(entry);before=ticks(pid)
  if before is None:continue
  try:
   for fd in os.listdir('/proc/%d/fd'%pid):
    try:info=os.stat('/proc/%d/fd/%s'%(pid,fd))
    except FileNotFoundError:continue
    if (info.st_dev,info.st_ino)==identity:
     holders.append((pid,before));break
  except FileNotFoundError:continue
  except PermissionError:raise ValueError()
  if ticks(pid)!=before:raise ValueError()
 return sorted(holders)
def digest(path,expected):
 if os.path.realpath(path)!=path:raise ValueError()
 fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
 try:
  first=os.fstat(fd)
  if not stat.S_ISREG(first.st_mode) or not 0<first.st_size<=33554432:raise ValueError()
  hash=hashlib.sha256();remaining=first.st_size
  while remaining:
   block=os.read(fd,min(131072,remaining))
   if not block:raise ValueError()
   hash.update(block);remaining-=len(block)
  if os.read(fd,1):raise ValueError()
  last=os.fstat(fd);name=os.stat(path,follow_symlinks=False)
  fields=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
  if any(getattr(first,k)!=getattr(last,k) or getattr(first,k)!=getattr(name,k) for k in fields):raise ValueError()
  if hash.hexdigest()!=expected:raise ValueError()
  return first.st_size
 finally:os.close(fd)
def binary(name):
 path='/usr/bin/'+name
 if not os.path.exists(path):return False
 info=os.stat(path,follow_symlinks=False)
 return stat.S_ISREG(info.st_mode) and info.st_size>0 and os.access(path,os.X_OK)
def package(name):
 if not binary('pacman'):raise ValueError()
 run=subprocess.run(['/usr/bin/pacman','-Q',name],capture_output=True,timeout=5,check=False)
 if len(run.stdout)>256 or len(run.stderr)>256:raise ValueError()
 parts=run.stdout.decode('utf-8').strip().split()
 return len(parts)==2 and parts[0]==name and run.returncode==0
stage='owner'
try:
 identity=owner();stage='source-holders';holders=source_holders(identity)
 if holders!=[(PID,TICKS)]:raise ValueError()
 stage='firmware'
 code_size=digest(CODE,CODE_HASH);vars_size=digest(VARS,VARS_HASH)
 stage='components'
 installed={name:binary(name) for name in ('qemu-system-x86_64','swtpm','swtpm_setup','virt-fw-vars')}
 packages={name:package(name) for name in ('edk2-ovmf','swtpm','virt-firmware')}
 stage='resources'
 with open('/proc/meminfo') as f:memory=f.read(8192)
 available=next(int(line.split()[1]) for line in memory.splitlines() if line.startswith('MemAvailable:'))
 free=shutil.disk_usage('/home/kardinal').free//1024
 if ticks(PID)!=TICKS:raise ValueError()
 print(json.dumps({'schemaVersion':1,'host':'archlinux','ownerPid':PID,'ownerStartTicks':TICKS,
   'sourceDisk':SOURCE,'cloneRoot':CLONE,'sourceHolders':[{'pid':p,'startTicks':t} for p,t in holders],
   'cloneRootAbsent':not os.path.lexists(CLONE),'codeSha256':CODE_HASH,'codeSizeBytes':code_size,
   'varsSha256':VARS_HASH,'varsSizeBytes':vars_size,'binaries':installed,'packages':packages,
   'kvmAvailable':os.path.exists('/dev/kvm'),'availableMemoryKiB':available,'freeDiskKiB':free},separators=(',',':')))
except Exception:
 print(json.dumps({'schemaVersion':1,'host':'archlinux','ownerPid':PID,'ownerStartTicks':TICKS,
                   'state':'unknown','failurePhase':stage}))
'''


def _request(value: Mapping[str, Any]) -> int:
    if (not isinstance(value, Mapping) or set(value) != {"host", "ownerPid", "ownerStartTicks", "baselineReservationId", "timeoutSeconds"}
            or value.get("host") != HOST or type(value.get("ownerPid")) is not int or value["ownerPid"] != OWNER_PID
            or type(value.get("ownerStartTicks")) is not int or value["ownerStartTicks"] != OWNER_TICKS
            or value.get("baselineReservationId") != BASELINE_RESERVATION
            or type(value.get("timeoutSeconds")) is not int or not 10 <= value["timeoutSeconds"] <= 60):
        raise ValueError("Secure Boot clone preflight requires exact Arch source and reservation pins.")
    return value["timeoutSeconds"]


def _baseline_reservation(root: Path) -> bool:
    path = root / ".rag_index/native-environments/reservations.json"
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_mode & 0o077 or before.st_size > 1048576:
            return False
        raw = os.read(descriptor, before.st_size + 1)
        after = os.fstat(descriptor)
        if len(raw) != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            return False
        state = json.loads(raw)
        records = state.get("reservations") if isinstance(state, dict) and state.get("version") == 1 else None
        if not isinstance(records, list):
            return False
        matching = [item for item in records if isinstance(item, dict) and item.get("id") == BASELINE_RESERVATION]
        return len(matching) == 1 and all(matching[0].get(key) == expected for key, expected in {
            "hostAlias": HOST, "environment": "windows-vm-baseline-20260929", "operator": "windows-baseline",
            "requestedMemoryBytes": MEMORY_KIB * 1024, "allocationState": "pending"}.items())
    except (OSError, ValueError, TypeError):
        return False
    finally:
        os.close(descriptor)


def classify(value: Mapping[str, Any], *, baseline_reservation_pinned: bool) -> dict[str, Any]:
    unknown = {"state": "unknown", "nativeActionAllowed": False}
    if (isinstance(value, Mapping) and set(value) == {"schemaVersion", "host", "ownerPid", "ownerStartTicks", "state", "failurePhase"}
            and value.get("schemaVersion") == 1 and value.get("host") == HOST
            and value.get("ownerPid") == OWNER_PID and value.get("ownerStartTicks") == OWNER_TICKS
            and value.get("state") == "unknown"
            and value.get("failurePhase") in {"owner", "source-holders", "firmware", "components", "resources"}):
        return {**unknown, "failurePhase": value["failurePhase"]}
    required = {"schemaVersion", "host", "ownerPid", "ownerStartTicks", "sourceDisk", "cloneRoot",
                "sourceHolders", "cloneRootAbsent", "codeSha256", "codeSizeBytes", "varsSha256",
                "varsSizeBytes", "binaries", "packages", "kvmAvailable", "availableMemoryKiB", "freeDiskKiB"}
    if (not isinstance(value, Mapping) or set(value) != required or value.get("schemaVersion") != 1
            or value.get("host") != HOST or value.get("ownerPid") != OWNER_PID
            or value.get("ownerStartTicks") != OWNER_TICKS or value.get("sourceDisk") != SOURCE
            or value.get("cloneRoot") != CLONE_ROOT
            or value.get("sourceHolders") != [{"pid": OWNER_PID, "startTicks": OWNER_TICKS}]
            or type(value.get("cloneRootAbsent")) is not bool
            or value.get("codeSha256") != CODE_SHA256 or value.get("varsSha256") != VARS_SHA256
            or type(value.get("codeSizeBytes")) is not int or not 0 < value["codeSizeBytes"] <= 33554432
            or type(value.get("varsSizeBytes")) is not int or not 0 < value["varsSizeBytes"] <= 33554432
            or type(value.get("kvmAvailable")) is not bool
            or type(value.get("availableMemoryKiB")) is not int or value["availableMemoryKiB"] < 0
            or type(value.get("freeDiskKiB")) is not int or value["freeDiskKiB"] < 0):
        return unknown
    binaries, packages = value["binaries"], value["packages"]
    if (not isinstance(binaries, Mapping) or set(binaries) != {"qemu-system-x86_64", "swtpm", "swtpm_setup", "virt-fw-vars"}
            or any(type(x) is not bool for x in binaries.values())
            or not isinstance(packages, Mapping) or set(packages) != {"edk2-ovmf", "swtpm", "virt-firmware"}
            or any(type(x) is not bool for x in packages.values())):
        return unknown
    missing = []
    if not baseline_reservation_pinned: missing.append("baseline-reservation-unverified")
    if not value["cloneRootAbsent"]: missing.append("clone-root-exists")
    if not binaries["virt-fw-vars"] or not packages["virt-firmware"]: missing.append("virt-fw-vars-unavailable")
    if not binaries["swtpm"] or not binaries["swtpm_setup"] or not packages["swtpm"]: missing.append("swtpm-unavailable")
    if not binaries["qemu-system-x86_64"] or not packages["edk2-ovmf"] or not value["kvmAvailable"]: missing.append("host-components-unavailable")
    if value["availableMemoryKiB"] < MEMORY_KIB + HEADROOM_KIB: missing.append("memory-headroom")
    if value["freeDiskKiB"] < MIN_DISK_KIB: missing.append("disk-headroom")
    missing.extend(("source-running", "clone-reservation-absent", "enrolled-clone-vars-absent"))
    return {"state": "blocked", "host": HOST, "sourceDisk": SOURCE, "cloneRoot": CLONE_ROOT,
            "ownerPid": OWNER_PID, "ownerStartTicks": OWNER_TICKS, "baselineReservationPinned": baseline_reservation_pinned,
            "firmwareCode": CODE, "firmwareCodeSha256": CODE_SHA256,
            "varsTemplate": VARS, "varsTemplateSha256": VARS_SHA256,
            "availableMemoryKiB": value["availableMemoryKiB"], "freeDiskKiB": value["freeDiskKiB"],
            "missing": missing, "safeNextAction": "prepare-reviewed-stopped-source-and-clone-reservation",
            "nativeActionAllowed": False}


def preflight(root: str | Path, value: Mapping[str, Any]) -> dict[str, Any]:
    timeout = _request(value)
    repository = Path(root).resolve(strict=True)
    try:
        reservation = _baseline_reservation(repository)
    except OSError:
        reservation = False
    config = ssh_transport.load_config(repository)
    if HOST not in config.hosts or ssh_transport.connection_host(config, HOST).password is not None:
        raise ValueError("Configured Arch transport is unavailable.")
    command = ("python3", "-c", "exec(" + repr(_REMOTE) + ")")
    argv = ssh_transport.build_ssh_argv(config, HOST, min(timeout, 30), command=command)
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {"state": "unknown", "nativeActionAllowed": False}
    if result.returncode or not 0 < len(result.stdout) <= 8192:
        return {"state": "unknown", "nativeActionAllowed": False}
    try:
        payload = json.loads(result.stdout)
    except (TypeError, ValueError):
        return {"state": "unknown", "nativeActionAllowed": False}
    return classify(payload, baseline_reservation_pinned=reservation)

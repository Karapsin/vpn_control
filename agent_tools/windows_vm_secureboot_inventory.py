"""Read-only, generation-bound TPM and OVMF inventory for the disposable Windows VM."""
from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping

from . import ssh_transport


HOST = "archlinux"
PID = 3369984
START_TICKS = 45177745
GUEST = "/home/kardinal/vpn-control-windows-baseline-20260929/guest"
DISK = GUEST + "/disk.qcow2"
QMP = GUEST + "/qmp.sock"
_HASH = re.compile(r"[0-9a-f]{64}\Z")

_REMOTE = r'''import hashlib,json,os,re,shutil,stat,subprocess,time
PID=3369984;TICKS=45177745
GUEST='/home/kardinal/vpn-control-windows-baseline-20260929/guest'
DISK=GUEST+'/disk.qcow2';QMP=GUEST+'/qmp.sock'
ROOTS=('/usr/share/edk2/x64','/usr/share/OVMF','/usr/share/qemu')
NAMES=('swtpm','swtpm_setup','virt-fw-vars','qemu-system-x86_64')
def ticks():
 try:
  with open('/proc/%d/stat'%PID) as stream:raw=stream.read()
  return int(raw[raw.rfind(')')+2:].split()[19])
 except (OSError,ValueError,IndexError):return None
def generation():
 if ticks()!=TICKS:raise ValueError()
 with open('/proc/%d/cmdline'%PID,'rb') as stream:argv=stream.read().split(b'\0')
 if not argv or os.path.basename(os.fsdecode(argv[0]))!='qemu-system-x86_64':raise ValueError()
 args=[os.fsdecode(item) for item in argv if item]
 if not any(DISK in item for item in args):raise ValueError()
 disk=os.stat(DISK);owned=False
 for name in os.listdir('/proc/%d/fd'%PID):
  path='/proc/%d/fd/%s'%(PID,name)
  try:
   if os.readlink(path)==DISK:
    held=os.stat(path)
    if (held.st_dev,held.st_ino)==(disk.st_dev,disk.st_ino):owned=True
  except OSError:continue
 if not owned:raise ValueError()
 sockets=[]
 with open('/proc/net/unix') as stream:
  for line in stream:
   parts=line.split()
   if len(parts)>=8 and parts[-1]==QMP:sockets.append(parts[6])
 if len(sockets)!=1:raise ValueError()
 qmp='socket:['+sockets[0]+']'
 if not any(os.readlink('/proc/%d/fd/%s'%(PID,name))==qmp for name in os.listdir('/proc/%d/fd'%PID) if os.path.lexists('/proc/%d/fd/%s'%(PID,name))):raise ValueError()
 if ticks()!=TICKS:raise ValueError()
 return args
def option(args,name):
 return [args[i+1] for i in range(len(args)-1) if args[i]==name]
def pflash(args):
 paths=[]
 for value in option(args,'-drive'):
  fields=dict(item.split('=',1) for item in value.split(',') if '=' in item)
  if fields.get('if')=='pflash' and 'file' in fields:paths.append(fields['file'])
 return paths
def tpm_graph(args):
 chars={}
 for value in option(args,'-chardev'):
  fields=dict(item.split('=',1) for item in value.split(',') if '=' in item)
  if value.startswith('socket,') and fields.get('id') and fields.get('path','').startswith(GUEST+'/'):
   chars[fields['id']]=fields['path']
 tpms={}
 for value in option(args,'-tpmdev'):
  fields=dict(item.split('=',1) for item in value.split(',') if '=' in item)
  if value.startswith('emulator,') and fields.get('id') and fields.get('chardev') in chars:
   tpms[fields['id']]=fields['chardev']
 for value in option(args,'-device'):
  fields=dict(item.split('=',1) for item in value.split(',') if '=' in item)
  if value.startswith(('tpm-tis,','tpm-crb,')) and fields.get('tpmdev') in tpms:return True
 return False
def file_info(path):
 actual=os.path.realpath(path)
 if not any(actual.startswith(allowed+'/') for allowed in ROOTS):raise ValueError()
 fd=os.open(actual,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
 h=hashlib.sha256()
 with os.fdopen(fd,'rb') as stream:
  before=os.fstat(stream.fileno())
  if not stat.S_ISREG(before.st_mode) or not 0<before.st_size<=33554432:raise ValueError()
  remaining=before.st_size
  while remaining:
   block=stream.read(min(131072,remaining))
   if not block:raise ValueError()
   h.update(block);remaining-=len(block)
  if stream.read(1):raise ValueError()
  after=os.fstat(stream.fileno())
 if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):raise ValueError()
 if not os.path.samefile(path,actual):raise ValueError()
 return {'path':path,'sizeBytes':before.st_size,'sha256':h.hexdigest()}
def output(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
try:
 args=generation();firmware_paths=pflash(args)
 code=next((path for path in firmware_paths if 'CODE' in os.path.basename(path).upper()),None)
 variables=next((path for path in firmware_paths if 'VARS' in os.path.basename(path).upper()),None)
 current_tpm=tpm_graph(args)
 secure_code=bool(code and re.search(r'(secboot|secure)',os.path.basename(code),re.I))
 binaries=[]
 for name in NAMES:
  path='/usr/bin/'+name
  if os.path.exists(path):
   info=os.stat(path)
   if stat.S_ISREG(info.st_mode) and info.st_size>0 and os.access(path,os.X_OK):
    binaries.append({'name':name,'path':os.path.realpath(path),'sizeBytes':info.st_size})
 firmware=[]
 for root in ROOTS:
  if not os.path.isdir(root):continue
  names=sorted(os.listdir(root))
  if len(names)>256:raise ValueError()
  for name in names:
   if not (name.lower().endswith('.fd') and ('ovmf' in name.lower() or 'secboot' in name.lower())):continue
   path=os.path.join(root,name)
   if os.path.isfile(path):firmware.append(file_info(path))
   if len(firmware)>64:raise ValueError()
 packages=[]
 if os.path.exists('/usr/bin/pacman'):
  package_manager=os.stat('/usr/bin/pacman')
  if not stat.S_ISREG(package_manager.st_mode) or not os.access('/usr/bin/pacman',os.X_OK):raise ValueError()
  result=subprocess.run(['/usr/bin/pacman','-Q','edk2-ovmf','swtpm','virt-firmware'],capture_output=True,timeout=10,check=False)
  if len(result.stdout)>4096:raise ValueError()
  for line in result.stdout.decode('utf-8').splitlines():
   parts=line.split()
   if len(parts)==2 and parts[0] in ('edk2-ovmf','swtpm','virt-firmware'):
    packages.append({'name':parts[0],'version':parts[1]})
 generation()
 output({'schemaVersion':1,'host':'archlinux','qemuPid':PID,'startTicks':TICKS,
         'diskOwned':True,'qmpSocketOwned':True,'currentTpmDevice':current_tpm,
         'currentSecureFirmware':secure_code,'firmwareCodePath':code,
         'firmwareVarsPath':variables,'components':{'binaries':binaries,
         'firmware':firmware,'packages':packages}})
except Exception:output({'schemaVersion':1,'host':'archlinux','qemuPid':PID,'startTicks':TICKS,'state':'unknown'})
'''


def _request(value: Mapping[str, Any]) -> int:
    if (not isinstance(value, Mapping) or set(value) != {"host", "qemuPid", "startTicks", "timeoutSeconds"}
            or value.get("host") != HOST or type(value.get("qemuPid")) is not int or value["qemuPid"] != PID
            or type(value.get("startTicks")) is not int or value["startTicks"] != START_TICKS
            or type(value.get("timeoutSeconds")) is not int or not 10 <= value["timeoutSeconds"] <= 60):
        raise ValueError("Secure Boot inventory requires exact Arch VM generation and bounded timeout.")
    return value["timeoutSeconds"]


def classify(value: Mapping[str, Any]) -> dict[str, Any]:
    unknown = {"state": "unknown", "nativeActionAllowed": False}
    if (not isinstance(value, Mapping) or set(value) != {"schemaVersion", "host", "qemuPid", "startTicks",
            "diskOwned", "qmpSocketOwned", "currentTpmDevice", "currentSecureFirmware",
            "firmwareCodePath", "firmwareVarsPath", "components"}
            or value.get("schemaVersion") != 1 or value.get("host") != HOST
            or type(value.get("qemuPid")) is not int or value["qemuPid"] != PID
            or type(value.get("startTicks")) is not int or value["startTicks"] != START_TICKS
            or value.get("diskOwned") is not True or value.get("qmpSocketOwned") is not True
            or type(value.get("currentTpmDevice")) is not bool
            or type(value.get("currentSecureFirmware")) is not bool):
        return unknown
    for key in ("firmwareCodePath", "firmwareVarsPath"):
        item = value[key]
        if item is not None and (not isinstance(item, str) or len(item) > 256 or not item.startswith("/")):
            return unknown
    components = value["components"]
    if not isinstance(components, Mapping) or set(components) != {"binaries", "firmware", "packages"}:
        return unknown
    binaries, firmware, packages = (components[key] for key in ("binaries", "firmware", "packages"))
    if not isinstance(binaries, list) or len(binaries) > 8 or not isinstance(firmware, list) or len(firmware) > 64 or not isinstance(packages, list) or len(packages) > 8:
        return unknown
    if any(not isinstance(item, Mapping) or set(item) != {"name", "path", "sizeBytes"}
           or item["name"] not in {"swtpm", "swtpm_setup", "virt-fw-vars", "qemu-system-x86_64"}
           or not isinstance(item["path"], str) or not item["path"].startswith("/")
           or type(item["sizeBytes"]) is not int or item["sizeBytes"] <= 0 for item in binaries):
        return unknown
    if any(not isinstance(item, Mapping) or set(item) != {"path", "sizeBytes", "sha256"}
           or not isinstance(item["path"], str) or not item["path"].startswith(("/usr/share/edk2/x64/", "/usr/share/OVMF/", "/usr/share/qemu/"))
           or type(item["sizeBytes"]) is not int or not 0 < item["sizeBytes"] <= 33554432
           or not isinstance(item["sha256"], str) or not _HASH.fullmatch(item["sha256"])
           for item in firmware):
        return unknown
    if any(not isinstance(item, Mapping) or set(item) != {"name", "version"}
           or item["name"] not in {"edk2-ovmf", "swtpm", "virt-firmware"}
           or not isinstance(item["version"], str) or not 0 < len(item["version"]) <= 128
           for item in packages):
        return unknown
    missing = []
    if not value["currentTpmDevice"]: missing.append("tpm2")
    if not value["currentSecureFirmware"]: missing.append("secure-boot-firmware")
    return {"state": "observed", "host": HOST, "qemuPid": PID, "startTicks": START_TICKS,
            "currentTpmDevice": value["currentTpmDevice"],
            "currentSecureFirmware": value["currentSecureFirmware"],
            "currentGuestMeetsRequirements": False if missing else None,
            "missingCurrentDevices": missing,
            "firmwareCodePath": value["firmwareCodePath"],
            "firmwareVarsPath": value["firmwareVarsPath"], "components": dict(components),
            "safeNextAction": "prepare-stopped-secureboot-tpm-clone" if missing else "verify-guest-requirements",
            "nativeActionAllowed": False}


def observe(root: str | Path, value: Mapping[str, Any]) -> dict[str, Any]:
    timeout = _request(value)
    config = ssh_transport.load_config(Path(root).resolve(strict=True))
    if HOST not in config.hosts or ssh_transport.connection_host(config, HOST).password is not None:
        raise ValueError("Configured Arch transport is unavailable.")
    command = ("python3", "-c", "exec(" + repr(_REMOTE) + ")")
    argv = ssh_transport.build_ssh_argv(config, HOST, min(timeout, 30), command=command)
    try:
        completed = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {"state": "unknown", "nativeActionAllowed": False}
    if completed.returncode != 0 or not 0 < len(completed.stdout) <= 32768:
        return {"state": "unknown", "nativeActionAllowed": False}
    try: payload = json.loads(completed.stdout)
    except (TypeError, ValueError): return {"state": "unknown", "nativeActionAllowed": False}
    return classify(payload)

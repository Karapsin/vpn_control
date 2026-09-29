"""Fixed read-only Arch-host QEMU process and holder census.

The census reports process generations, allocated memory and observed file or
socket descriptors. It assigns a task role only when the fixed Windows setup
receipts on both coordinator and host bind the same PID, disk inode and QMP FD.
Other QEMUs remain unattributed; this route cannot park or stop any process.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Mapping

from . import ssh_transport, windows_vm_fresh_setup


_HOST = "archlinux"
_MAX_OUTPUT = 65536
_DISK = windows_vm_fresh_setup.GUEST + "/disk.qcow2"
_QMP = windows_vm_fresh_setup.GUEST + "/qmp.sock"
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")


_REMOTE = r'''import json,os,pwd,re,stat,sys,time
if pwd.getpwuid(os.geteuid()).pw_name!='kardinal':raise SystemExit(21)
GUEST=__GUEST__;DISK=GUEST+'/disk.qcow2';QMP=GUEST+'/qmp.sock'
WIN=__WIN__;DRV=__DRV__;MEM=6144;VNC=5927
MAX_QEMU=16;MAX_FD=8192
def ticks(pid):
 try:return int(open('/proc/%d/stat'%pid,encoding='ascii').read().rsplit(')',1)[1].split()[19])
 except (OSError,ValueError,IndexError):return None
def private(path,limit):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  s=os.fstat(fd);base=os.stat(GUEST,follow_symlinks=False)
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=base.st_uid or stat.S_IMODE(s.st_mode)!=0o600 or s.st_size<1 or s.st_size>limit:raise ValueError()
  raw=os.read(fd,s.st_size+1)
  if len(raw)!=s.st_size:raise ValueError()
  return json.loads(raw)
 finally:os.close(fd)
def baseline():
 try:
  parent=os.lstat(os.path.dirname(GUEST));g=os.lstat(GUEST)
  if not stat.S_ISDIR(parent.st_mode) or stat.S_IMODE(parent.st_mode)!=0o700 or not stat.S_ISDIR(g.st_mode) or stat.S_IMODE(g.st_mode)!=0o700:raise ValueError()
  intent=private(GUEST+'/intent.json',2048);started=private(GUEST+'/started.json',512)
  d=os.stat(DISK,follow_symlinks=False)
  if not stat.S_ISREG(d.st_mode) or intent.get('schemaVersion')!=1 or intent.get('windowsSha256')!=WIN or intent.get('driverSha256')!=DRV or intent.get('memoryMiB')!=MEM or intent.get('vncPort')!=VNC or type(started.get('pid'))!=int or type(started.get('startTicks'))!=int or not isinstance(intent.get('correlationId'),str):raise ValueError()
  return {'correlationId':intent['correlationId'],'pid':started['pid'],'startTicks':started['startTicks'],'diskDevice':d.st_dev,'diskInode':d.st_ino}
 except (OSError,ValueError,TypeError):return None
def sockets():
 unix={}
 with open('/proc/net/unix',encoding='ascii') as f:
  for line in f:
   p=line.split()
   if len(p)>=8 and p[6].isdigit():unix[int(p[6])]=p[7]
 tcp={}
 for name in ('tcp','tcp6'):
  with open('/proc/net/'+name,encoding='ascii') as f:
   next(f)
   for line in f:
    p=line.split()
    if len(p)>=10 and p[3]=='0A' and p[9].isdigit():
     try:
      address,port=p[1].split(':')
      bind='127.0.0.1' if name=='tcp' and address=='0100007F' else '::1' if name=='tcp6' and address=='00000000000000000000000001000000' else 'other'
      tcp[int(p[9])]=(int(port,16),bind)
     except (ValueError,IndexError):raise ValueError('tcp-table')
 return unix,tcp
def memory(argv):
 if argv.count('-m')!=1:return None
 i=argv.index('-m')
 if i+1>=len(argv):return None
 value=argv[i+1].removeprefix('size=')
 m=re.fullmatch(r'([1-9][0-9]{0,5})([MmGg]?)',value)
 if not m:return None
 amount=int(m.group(1))*(1024 if m.group(2).lower()=='g' else 1)
 return amount if 128<=amount<=65536 else None
def memory_diagnostic(value):
 if not isinstance(value,str) or len(value)>48:return None
 pattern=r'(?:size=)?[1-9][0-9]{0,5}[MmGg]?(?:,(?:slots=[1-9][0-9]{0,3}|maxmem=[1-9][0-9]{0,6}[MmGg]?))*'
 return value if re.fullmatch(pattern,value) else None
def disk_path(link,dev,ino):
 if not link.startswith('/home/kardinal/') or not link.endswith(('.qcow2','.img','.raw')) or '\x00' in link:return None
 try:
  s=os.stat(link,follow_symlinks=False)
  return link if stat.S_ISREG(s.st_mode) and (s.st_dev,s.st_ino)==(dev,ino) else None
 except OSError:return None
def proc_visible():
 try:
  if open('/proc/1/comm',encoding='ascii').read(128).strip()!='systemd':return False
  if os.readlink('/proc/1/ns/pid')!=os.readlink('/proc/self/ns/pid'):return False
  mounts=[]
  with open('/proc/self/mountinfo',encoding='ascii') as f:
   for line in f:
    before,after=line.strip().split(' - ',1)
    fields=before.split();tail=after.split()
    if len(fields)>=6 and fields[4]=='/proc':mounts.append((fields,tail))
  if len(mounts)!=1:return False
  fields,tail=mounts[0]
  if len(tail)<3 or tail[0]!='proc':return False
  options=set((fields[5]+','+tail[2]).split(','))
  return 'subset=pid' not in options and not any(
   option.startswith('hidepid=') and option!='hidepid=0' for option in options)
 except (OSError,ValueError,IndexError):return False
def scan(unix,tcp):
 complete=proc_visible();items=[]
 entries=[item for item in os.listdir('/proc') if item.isdecimal()]
 if len(entries)>8192:raise ValueError('proc-count')
 for item in entries:
  pid=int(item)
  try:comm=open('/proc/%d/comm'%pid,encoding='ascii').read(128).strip()
  except FileNotFoundError:
   if os.path.exists('/proc/%d'%pid):complete=False
   continue
  except OSError:complete=False;continue
  if not comm.startswith('qemu-system-'):continue
  if len(items)>=MAX_QEMU:complete=False;break
  before=ticks(pid)
  if before is None:complete=False;items.append({'pid':pid,'state':'unknown','reason':'start-unreadable'});continue
  try:
   exe=os.path.basename(os.readlink('/proc/%d/exe'%pid))
   raw=open('/proc/%d/cmdline'%pid,'rb').read(32769)
   if not 0<len(raw)<=32768:raise ValueError('cmdline-size')
   argv=[p.decode('utf-8','replace') for p in raw.split(b'\0') if p]
   memory_arg=None
   if argv.count('-m')==1 and argv.index('-m')+1<len(argv):
    memory_arg=memory_diagnostic(argv[argv.index('-m')+1])
   names=os.listdir('/proc/%d/fd'%pid)
   if len(names)>MAX_FD:raise ValueError('fd-count')
   disks=[];qmps=[];listeners=[]
   for fd in names:
    path='/proc/%d/fd/%s'%(pid,fd)
    link=os.readlink(path);s=os.stat(path)
    if stat.S_ISREG(s.st_mode) and link.endswith(('.qcow2','.img','.raw')):
     disks.append({'device':s.st_dev,'inode':s.st_ino,'path':disk_path(link,s.st_dev,s.st_ino)})
    m=re.fullmatch(r'socket:\[([0-9]+)\]',link)
    if m:
     inode=int(m.group(1))
     if inode in unix:
      q=unix[inode]
      if q.startswith('/home/kardinal/') and q.endswith('/qmp.sock'):qmps.append({'inode':inode,'path':q})
     if inode in tcp:listeners.append({'inode':inode,'port':tcp[inode][0],'bindAddress':tcp[inode][1]})
   if len(disks)>32 or len(qmps)>16 or len(listeners)>32:raise ValueError('descriptor-count')
   if ticks(pid)!=before:raise ValueError('generation-changed')
   mem=memory(argv)
   if mem is None:raise ValueError('memory-unknown'+(':'+memory_arg if memory_arg else ''))
   items.append({'pid':pid,'startTicks':before,'state':'observed','exe':exe,
    'allocatedMemoryMiB':mem,'disks':sorted(disks,key=lambda x:(x['device'],x['inode'],x['path'] or '')),
    'qmpSockets':sorted(qmps,key=lambda x:x['inode']),'tcpListeners':sorted(listeners,key=lambda x:x['inode'])})
  except (OSError,ValueError) as error:
   complete=False;items.append({'pid':pid,'startTicks':before,'state':'unknown','reason':str(error)[:64]})
 return complete,sorted(items,key=lambda x:x['pid'])
try:
 unix,tcp=sockets();complete,items=scan(unix,tcp)
 print(json.dumps({'schemaVersion':1,'host':'archlinux','censusComplete':complete,
  'observedAtUnixMs':int(time.time()*1000),'processes':items,
  'windowsBaselineReceipt':baseline()},sort_keys=True,separators=(',',':')))
except (OSError,ValueError) as error:
 print(json.dumps({'schemaVersion':1,'host':'archlinux','censusComplete':False,
  'observedAtUnixMs':int(time.time()*1000),'processes':[],
  'windowsBaselineReceipt':None,'reason':type(error).__name__},sort_keys=True,separators=(',',':')))
'''


def _read_local_claim(root: Path) -> dict[str, str] | None:
    try:
        path = windows_vm_fresh_setup._intent(root, create=False)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                    stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 2048):
                return None
            raw = os.read(fd, info.st_size + 1)
            if len(raw) != info.st_size:
                return None
            value = json.loads(raw)
        finally:
            os.close(fd)
        correlation = value.get("correlationId")
        if not isinstance(correlation, str) or _UUID.fullmatch(correlation) is None or \
                value != windows_vm_fresh_setup._payload(correlation):
            return None
        return {"correlationId": correlation}
    except (OSError, ValueError, TypeError, AttributeError):
        return None


def classify(raw: Mapping[str, Any], *, local_claim: Mapping[str, Any] | None) -> dict[str, Any]:
    if (not isinstance(raw, Mapping) or raw.get("schemaVersion") != 1 or
            raw.get("host") != _HOST or not isinstance(raw.get("processes"), list) or
            len(raw["processes"]) > 16 or type(raw.get("censusComplete")) is not bool):
        raise ValueError("Arch QEMU census envelope is invalid")
    receipt = raw.get("windowsBaselineReceipt")
    processes: list[dict[str, Any]] = []
    complete = raw["censusComplete"]
    seen: set[int] = set()
    for item in raw["processes"]:
        if not isinstance(item, Mapping) or type(item.get("pid")) is not int or item["pid"] <= 0 or item["pid"] in seen:
            raise ValueError("Arch QEMU process identity is invalid")
        seen.add(item["pid"])
        if item.get("state") != "observed":
            complete = False
            reason = item.get("reason")
            if not isinstance(reason, str) or re.fullmatch(r"[A-Za-z0-9:,=+.-]{1,64}", reason) is None:
                reason = "unreadable"
            processes.append({"pid": item["pid"], "startTicks": item.get("startTicks"),
                              "state": "unknown", "reason": reason, "claimedRole": "unknown"})
            continue
        required = {"pid", "startTicks", "state", "exe", "allocatedMemoryMiB", "disks", "qmpSockets", "tcpListeners"}
        if (set(item) != required or type(item.get("startTicks")) is not int or item["startTicks"] <= 0 or
                item.get("exe") not in ("qemu-system-x86_64", "qemu-system-aarch64") or
                type(item.get("allocatedMemoryMiB")) is not int or not 128 <= item["allocatedMemoryMiB"] <= 65536 or
                not isinstance(item.get("disks"), list) or len(item["disks"]) > 32 or
                not isinstance(item.get("qmpSockets"), list) or len(item["qmpSockets"]) > 16 or
                not isinstance(item.get("tcpListeners"), list) or len(item["tcpListeners"]) > 32):
            raise ValueError("Arch QEMU process facts are invalid")
        for disk in item["disks"]:
            if (not isinstance(disk, Mapping) or set(disk) != {"path", "device", "inode"} or
                    type(disk["device"]) is not int or type(disk["inode"]) is not int or
                    disk["device"] <= 0 or disk["inode"] <= 0 or
                    (disk["path"] is not None and
                     (not isinstance(disk["path"], str) or not disk["path"].startswith("/home/kardinal/") or
                      not disk["path"].endswith((".qcow2", ".img", ".raw"))))):
                raise ValueError("Arch QEMU disk facts are invalid")
        for key, suffix in (("qmpSockets", "/qmp.sock"), ("tcpListeners", None)):
            for socket in item[key]:
                fields = {"inode", "path"} if suffix else {"inode", "port", "bindAddress"}
                if (not isinstance(socket, Mapping) or set(socket) != fields or
                        type(socket["inode"]) is not int or socket["inode"] <= 0 or
                        (suffix and (not isinstance(socket["path"], str) or
                                     not socket["path"].startswith("/home/kardinal/") or
                                     not socket["path"].endswith(suffix))) or
                        (not suffix and (type(socket["port"]) is not int or not 1 <= socket["port"] <= 65535 or
                                         socket["bindAddress"] not in ("127.0.0.1", "::1", "other")))):
                    raise ValueError("Arch QEMU socket facts are invalid")
        claimed = "unknown"
        if (isinstance(local_claim, Mapping) and set(local_claim) == {"correlationId"} and
                isinstance(receipt, Mapping) and set(receipt) ==
                {"correlationId", "pid", "startTicks", "diskDevice", "diskInode"} and
                receipt.get("correlationId") == local_claim["correlationId"] and
                item["pid"] == receipt.get("pid") and item["startTicks"] == receipt.get("startTicks") and
                item["allocatedMemoryMiB"] == windows_vm_fresh_setup.MEMORY_MIB and
                any(disk == {"path": _DISK, "device": receipt.get("diskDevice"),
                             "inode": receipt.get("diskInode")} for disk in item["disks"]) and
                any(socket.get("path") == _QMP for socket in item["qmpSockets"]) and
                any(socket["port"] == windows_vm_fresh_setup.VNC_PORT and
                    socket["bindAddress"] == "127.0.0.1" for socket in item["tcpListeners"])):
            claimed = "windows-baseline"
        processes.append({**item, "claimedRole": claimed})
    return {"state": "observed" if complete else "unknown", "host": _HOST,
            "inventoryComplete": complete, "nativeActionAllowed": False,
            "observedAtUnixMs": raw.get("observedAtUnixMs"),
            "processes": processes, "runningQemuCount": len(processes),
            "runningQemuMemoryMiB": sum(item.get("allocatedMemoryMiB", 0) for item in processes
                                        if item["state"] == "observed")}


def observe(root: Path | str, request: Mapping[str, Any], *, runner=None) -> dict[str, Any]:
    if (not isinstance(request, Mapping) or set(request) != {"host", "timeoutSeconds"} or
            request.get("host") != _HOST or type(request.get("timeoutSeconds")) is not int or
            not 1 <= request["timeoutSeconds"] <= 30):
        raise ValueError("Arch QEMU census requires fixed host and bounded timeout")
    root = Path(root).resolve(strict=True)
    config = ssh_transport.load_config(root)
    if (_HOST not in config.hosts or
            ssh_transport.connection_host(config, _HOST).password is not None or
            ssh_transport.connection_host(config, _HOST).user != "kardinal"):
        raise ValueError("Fixed Arch SSH transport is unavailable")
    script = (_REMOTE.replace("__GUEST__", repr(windows_vm_fresh_setup.GUEST))
             .replace("__WIN__", repr(windows_vm_fresh_setup.WINDOWS_SHA256))
             .replace("__DRV__", repr(windows_vm_fresh_setup.DRIVER_SHA256)))
    encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
    fixed_command = f"import base64;exec(base64.b64decode('{encoded}'))"
    argv = ssh_transport.build_ssh_argv(config, _HOST, request["timeoutSeconds"],
                                         command=("python3", "-I", "-B", "-c", fixed_command))
    invoke = runner or subprocess.run
    try:
        response = invoke(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          timeout=request["timeoutSeconds"] + 1, check=False)
        if response.returncode != 0 or len(response.stdout) > _MAX_OUTPUT:
            raise ValueError("Arch QEMU census response is unavailable")
        raw = json.loads(response.stdout)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        raise ValueError("Arch QEMU census response is unavailable") from error
    return classify(raw, local_claim=_read_local_claim(root))

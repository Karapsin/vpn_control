"""One-shot independent blank Windows VM with Secure Boot and software TPM.

The fixed sources are official installation media and read-only OVMF firmware.
No live VM disk is an input. Preflight is read-only; start journals locally and
remotely before creating a private blank disk, VARS, TPM state, or VM process.
Any uncertain start is observed by exact status and is never replayed.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Mapping

from . import native_environment, ssh_transport


HOST = "archlinux"
ROOT = "/home/kardinal/vpn-control-windows-secureboot-fresh-20260929"
GUEST = ROOT + "/guest"
WINDOWS_ISO = "/home/kardinal/vpn-control-windows-native-20260907/windows-x64.iso"
WINDOWS_SIZE = 7092807680
WINDOWS_SHA256 = "a61adeab895ef5a4db436e0a7011c92a2ff17bb0357f58b13bbc4062e535e7b9"
DRIVER_ISO = "/home/kardinal/vpn-control-windows-baseline-20260929/runtime/virtio-win-0.1.285.iso"
DRIVER_SIZE = 789645312
DRIVER_SHA256 = "e14cf2b94492c3e925f0070ba7fdfedeb2048c91eea9c5a5afb30232a3976331"
CODE = "/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd"
CODE_SHA256 = "cc150d941d4f1d39e596dedc545384a66ccfb3c9ba5cf9bc3a54d8d427d4d88f"
VARS_TEMPLATE = "/usr/share/edk2/x64/OVMF_VARS.4m.fd"
VARS_SHA256 = "5d2ac383371b408398accee7ec27c8c09ea5b74a0de0ceea6513388b15be5d1e"
MEMORY_MIB = 6144
HEADROOM_KIB = 8 * 1024 * 1024
MIN_DISK_KIB = 30 * 1024 * 1024
VNC_PORT = 5928
ENVIRONMENT = "windows-vm-secureboot-fresh-20260929"
OPERATOR = "windows-secureboot-fresh"
UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")

_REMOTE = r'''import hashlib,json,os,shutil,stat,struct,subprocess,sys,time,uuid
ROOT=__ROOT__;GUEST=__GUEST__;CORR=__CORR__;MODE=__MODE__
WIN=__WIN__;WIN_SIZE=__WIN_SIZE__;WIN_HASH=__WIN_HASH__
DRV=__DRV__;DRV_SIZE=__DRV_SIZE__;DRV_HASH=__DRV_HASH__
CODE=__CODE__;CODE_HASH=__CODE_HASH__;VARS=__VARS__;VARS_HASH=__VARS_HASH__
MEM=__MEM__;HEADROOM=__HEADROOM__;MIN_DISK=__MIN_DISK__;PORT=__PORT__
DISK=GUEST+'/disk.qcow2';NEW_VARS=GUEST+'/uefi-vars.fd';TPM=GUEST+'/tpm'
TPM_SOCKET=TPM+'/swtpm.sock';QMP=GUEST+'/qmp.sock'
def emit(state,reason=None,**extra):
 print(json.dumps({'schemaVersion':1,'correlationId':CORR,'state':state,'reason':reason,
                   'nativeActionAllowed':False,**extra},separators=(',',':')))
def private_dir(path):
 info=os.lstat(path)
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
def private_file(path):
 info=os.lstat(path)
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:raise ValueError()
 return info
def digest(path,size,expected,owner,limit):
 if os.path.realpath(path)!=path:raise ValueError()
 fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
 try:
  first=os.fstat(fd)
  if not stat.S_ISREG(first.st_mode) or first.st_size!=size or first.st_size>limit or (owner and first.st_uid!=os.geteuid()):raise ValueError()
  hash=hashlib.sha256();remaining=first.st_size
  while remaining:
   block=os.read(fd,min(1048576,remaining))
   if not block:raise ValueError()
   hash.update(block);remaining-=len(block)
  if os.read(fd,1):raise ValueError()
  last=os.fstat(fd);name=os.stat(path,follow_symlinks=False)
  fields=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
  if any(getattr(first,k)!=getattr(last,k) or getattr(first,k)!=getattr(name,k) for k in fields):raise ValueError()
  if hash.hexdigest()!=expected:raise ValueError()
  return first
 finally:os.close(fd)
def binary(name):
 path='/usr/bin/'+name
 info=os.stat(path,follow_symlinks=False)
 if not stat.S_ISREG(info.st_mode) or info.st_size<1 or not os.access(path,os.X_OK):raise ValueError()
 return path
def package_installed(name,version=None):
 pacman=binary('pacman')
 run=subprocess.run([pacman,'-Q',name],capture_output=True,timeout=5,check=False)
 if len(run.stdout)>256 or len(run.stderr)>256:raise ValueError()
 parts=run.stdout.decode().split()
 if run.returncode!=0 or len(parts)!=2 or parts[0]!=name or (version and parts[1]!=version):return False
 integrity=subprocess.run([pacman,'-Qkk',name],capture_output=True,timeout=10,check=False)
 return integrity.returncode==0 and len(integrity.stdout)<=8192 and len(integrity.stderr)<=8192
def port_free():
 needle='%04X'%PORT
 for path in ('/proc/net/tcp','/proc/net/tcp6'):
  with open(path) as f:rows=f.read(1048577)
  if len(rows)>1048576:raise ValueError()
  for line in rows.splitlines()[1:]:
   cols=line.split()
   if len(cols)>=4 and cols[1].rsplit(':',1)[-1].upper()==needle and cols[3]=='0A':return False
 return True
def prerequisites():
 if os.path.lexists(ROOT):return 'guest-root-exists',None,None
 if not os.path.isfile('/usr/bin/virt-fw-vars'):return 'virt-fw-vars-unavailable',None,None
 for name in ('qemu-system-x86_64','qemu-img','swtpm','swtpm_setup','virt-fw-vars'):binary(name)
 if not package_installed('virt-firmware','26.9-1'):return 'virt-fw-vars-unavailable',None,None
 if not package_installed('edk2-ovmf','202608-1') or not package_installed('swtpm','0.10.2-1'):
  return 'host-components-unavailable',None,None
 if not package_installed('qemu-system-x86') or not package_installed('qemu-img'):
  return 'host-components-unavailable',None,None
 if not os.path.exists('/dev/kvm'):return 'kvm-unavailable',None,None
 if not port_free():return 'vnc-port-owned',None,None
 digest(CODE,3653632,CODE_HASH,False,33554432)
 template=digest(VARS,540672,VARS_HASH,False,33554432)
 digest(WIN,WIN_SIZE,WIN_HASH,True,8*1024*1024*1024)
 digest(DRV,DRV_SIZE,DRV_HASH,True,1024*1024*1024)
 with open('/proc/meminfo') as f:memory=f.read(8192)
 available=next(int(line.split()[1]) for line in memory.splitlines() if line.startswith('MemAvailable:'))
 free=shutil.disk_usage('/home/kardinal').free//1024
 if available<MEM*1024+HEADROOM:return 'memory-headroom',available,free
 if free<MIN_DISK:return 'disk-headroom',available,free
 return None,available,free
def write_json(path,value):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 try:os.write(fd,json.dumps(value,sort_keys=True,separators=(',',':')).encode());os.fsync(fd)
 finally:os.close(fd)
 parent=os.path.dirname(path)
 dfd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0))
 try:os.fsync(dfd)
 finally:os.close(dfd)
def read_json(path):
 private_file(path)
 with open(path,encoding='utf-8') as f:return json.load(f)
MS_OWNER=uuid.UUID('77fa9abd-0359-4d32-bd60-28f4e78f784b')
X509=uuid.UUID('a5c059a1-94e4-4aa7-87b5-ab155c2bf072')
# SHA256 of DER certificates in virt-firmware v26.9's microsoft.com resources.
MICROSOFT={
 'PK':{'2f569e8edaf9657dc4951c29598725255c7f821472db71374211fe44d082546f'},
 'KEK':{'a1117f516a32cefcba3f2d1ace10a87972fd6bbe8fe0d0b996e09e65d802a503',
        '3cd3f0309edae228767a976dd40d9f4affc4fbd5218f2e8cc3c9dd97e8ac6f9d'},
 'db':{'e8e95f0733a55e8bad7be0a1413ee23c51fcea64b3c8fa6a786935fddcc71961',
       '076f1fea90ac29155ebf77c17682f75f1fdd1be196da302dc8461e350a9ae330'}}
def cert_fingerprints(hexdata):
 blob=bytes.fromhex(hexdata)
 if not 28<len(blob)<=65536:raise ValueError()
 found=[];pos=0
 while pos<len(blob):
  if len(blob)-pos<28 or uuid.UUID(bytes_le=blob[pos:pos+16])!=X509:raise ValueError()
  total,header,stride=struct.unpack_from('<LLL',blob,pos+16)
  if not 28<=total<=len(blob)-pos or header!=0 or stride<=16 or (total-28)%stride:raise ValueError()
  for offset in range(pos+28,pos+total,stride):
   if uuid.UUID(bytes_le=blob[offset:offset+16])!=MS_OWNER:raise ValueError()
   found.append(hashlib.sha256(blob[offset+16:offset+stride]).hexdigest())
  pos+=total
 if not found or len(found)!=len(set(found)):raise ValueError()
 return set(found)
def enrolled_vars(path):
 private_file(path)
 run=subprocess.run(['/usr/bin/virt-fw-vars','--input',path,'--output-json','-'],
                    stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                    timeout=15,check=False)
 if run.returncode or not 0<len(run.stdout)<=262144:raise ValueError()
 value=json.loads(run.stdout)
 if not isinstance(value,dict) or value.get('version')!=2 or not isinstance(value.get('variables'),list):raise ValueError()
 variables={}
 for item in value['variables']:
  if not isinstance(item,dict) or not isinstance(item.get('name'),str) or not isinstance(item.get('data'),str):raise ValueError()
  if item['name'] in variables:raise ValueError()
  variables[item['name']]=item['data']
 if any(cert_fingerprints(variables.get(name,''))!=expected for name,expected in MICROSOFT.items()):raise ValueError()
 if variables.get('SecureBootEnable')!='01' or variables.get('CustomMode')!='00':raise ValueError()
 return True
def ticks(pid):
 try:
  with open('/proc/%d/stat'%pid) as f:raw=f.read()
  return int(raw.rsplit(')',1)[1].split()[19])
 except (OSError,ValueError,IndexError):return None
def args(pid):
 with open('/proc/%d/cmdline'%pid,'rb') as f:raw=f.read(32769)
 if not raw or len(raw)>32768:raise ValueError()
 return [os.fsdecode(x) for x in raw.rstrip(b'\0').split(b'\0')]
def owned_disk(pid):
 disk=private_file(DISK)
 for name in os.listdir('/proc/%d/fd'%pid):
  path='/proc/%d/fd/%s'%(pid,name)
  try:
   if os.readlink(path)==DISK:
    held=os.stat(path)
    if (held.st_dev,held.st_ino)==(disk.st_dev,disk.st_ino):return True
  except OSError:continue
 return False
def socket_owned(pid,socket_path):
 with open('/proc/net/unix') as f:raw=f.read(131073)
 if len(raw)>131072:raise ValueError()
 matches=[line.split()[6] for line in raw.splitlines()[1:] if len(line.split())>=8 and line.split()[-1]==socket_path]
 if len(matches)!=1:return False
 link='socket:['+matches[0]+']'
 return any(os.readlink('/proc/%d/fd/%s'%(pid,name))==link for name in os.listdir('/proc/%d/fd'%pid))
def executable(pid,path):
 return os.readlink('/proc/%d/exe'%pid)==os.path.realpath(path)
def swtpm_args():
 return ['/usr/bin/swtpm','socket','--tpm2','--tpmstate','dir='+TPM,
         '--ctrl','type=unixio,path='+TPM_SOCKET]
def qemu_args():
 return ['/usr/bin/qemu-system-x86_64','-name','vpn-control-windows-secureboot-fresh-20260929',
         '-machine','q35,smm=on','-accel','kvm','-cpu','host','-smp','4','-m',str(MEM),
         '-global','driver=cfi.pflash01,property=secure,value=on',
         '-drive','if=pflash,format=raw,readonly=on,file='+CODE,
         '-drive','if=pflash,format=raw,file='+NEW_VARS,
         '-drive','file='+DISK+',if=virtio,format=qcow2',
         '-drive','file='+WIN+',media=cdrom,readonly=on',
         '-drive','file='+DRV+',media=cdrom,readonly=on',
         '-chardev','socket,id=chrtpm,path='+TPM_SOCKET,
         '-tpmdev','emulator,id=tpm0,chardev=chrtpm','-device','tpm-tis,tpmdev=tpm0',
         '-netdev','user,id=net0','-device','virtio-net-pci,netdev=net0',
         '-boot','order=d,menu=off','-display','none','-vnc','127.0.0.1:'+str(PORT-5900),
         '-monitor','none','-qmp','unix:'+QMP+',server=on,wait=off']
def state():
 if not os.path.lexists(ROOT):return 'absent'
 private_dir(ROOT);private_dir(GUEST);private_dir(TPM)
 intent=read_json(GUEST+'/intent.json')
 if intent!={'schemaVersion':1,'correlationId':CORR,'windowsSha256':WIN_HASH,
            'driverSha256':DRV_HASH,'codeSha256':CODE_HASH,'varsTemplateSha256':VARS_HASH,
            'disk':DISK,'vars':NEW_VARS,'tpmSocket':TPM_SOCKET,'memoryMiB':MEM,'vncPort':PORT}:return 'unknown'
 if not os.path.lexists(GUEST+'/qemu-started.json') or not os.path.lexists(GUEST+'/swtpm-started.json'):return 'partial-unknown'
 q=read_json(GUEST+'/qemu-started.json');t=read_json(GUEST+'/swtpm-started.json')
 if set(q)!={'pid','startTicks'} or set(t)!={'pid','startTicks'}:return 'unknown'
 if any(type(x)!=int or x<1 for x in (*q.values(),*t.values())):return 'unknown'
 if ticks(q['pid'])!=q['startTicks'] or ticks(t['pid'])!=t['startTicks']:return 'partial-unknown'
 qa=args(q['pid']);ta=args(t['pid'])
 if (qa!=qemu_args() or ta!=swtpm_args() or not executable(q['pid'],'/usr/bin/qemu-system-x86_64')
     or not executable(t['pid'],'/usr/bin/swtpm')):return 'unknown'
 if not owned_disk(q['pid']) or not socket_owned(q['pid'],QMP):return 'unknown'
 enrolled_vars(NEW_VARS)
 socket=os.lstat(TPM_SOCKET)
 if not stat.S_ISSOCK(socket.st_mode) or socket.st_uid!=os.geteuid() or not socket_owned(t['pid'],TPM_SOCKET):return 'unknown'
 if ticks(q['pid'])!=q['startTicks'] or ticks(t['pid'])!=t['startTicks']:return 'unknown'
 return 'running-observed'
try:
 if MODE=='status':emit(state())
 elif MODE=='preflight':
  reason,available,free=prerequisites()
  emit('blocked' if reason else 'ready',reason,availableMemoryKiB=available,freeDiskKiB=free,
       windowsSha256=WIN_HASH,driverSha256=DRV_HASH,codeSha256=CODE_HASH,varsTemplateSha256=VARS_HASH,
       vncPort=PORT)
 elif MODE=='start':
  reason,available,free=prerequisites()
  if reason:emit('blocked',reason)
  else:
   os.umask(0o077)
   os.mkdir(ROOT,0o700);private_dir(ROOT)
   os.mkdir(GUEST,0o700);private_dir(GUEST)
   os.mkdir(TPM,0o700);private_dir(TPM)
   intent={'schemaVersion':1,'correlationId':CORR,'windowsSha256':WIN_HASH,
           'driverSha256':DRV_HASH,'codeSha256':CODE_HASH,'varsTemplateSha256':VARS_HASH,
           'disk':DISK,'vars':NEW_VARS,'tpmSocket':TPM_SOCKET,'memoryMiB':MEM,'vncPort':PORT}
   write_json(GUEST+'/intent.json',intent)
   temp_vars=GUEST+'/vars.create.fd'
   run=subprocess.run(['/usr/bin/virt-fw-vars','--input',VARS,'--output',temp_vars,
                       '--enroll-microsoft','--microsoft-db','win11','--microsoft-kek','all','--secure-boot'],
                      stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=60,check=True)
   created=private_file(temp_vars)
   if created.st_size!=540672:raise ValueError()
   with open(temp_vars,'rb') as f:content=f.read(540673)
   if len(content)!=540672 or hashlib.sha256(content).hexdigest()==VARS_HASH:raise ValueError()
   enrolled_vars(temp_vars)
   os.link(temp_vars,NEW_VARS,follow_symlinks=False);os.unlink(temp_vars)
   private_file(NEW_VARS)
   temp_disk=GUEST+'/disk.create.qcow2'
   fd=os.open(temp_disk,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
   claimed=os.fstat(fd);os.close(fd)
   subprocess.run(['/usr/bin/qemu-img','create','-f','qcow2',temp_disk,'96G'],
                  stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=60,check=True)
   made=private_file(temp_disk)
   if (made.st_dev,made.st_ino)!=(claimed.st_dev,claimed.st_ino):raise ValueError()
   info=subprocess.run(['/usr/bin/qemu-img','info','--output=json',temp_disk],capture_output=True,timeout=15,check=True)
   if len(info.stdout)>16384:raise ValueError()
   image=json.loads(info.stdout)
   if image.get('format')!='qcow2' or image.get('virtual-size')!=96*1024*1024*1024 or image.get('backing-filename'):raise ValueError()
   os.link(temp_disk,DISK,follow_symlinks=False);os.unlink(temp_disk)
   private_file(DISK)
   tpm_log=os.open(GUEST+'/swtpm.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
   try:
    tproc=subprocess.Popen(swtpm_args(),
                           stdin=subprocess.DEVNULL,stdout=tpm_log,stderr=tpm_log,
                           start_new_session=True,close_fds=True)
   finally:os.close(tpm_log)
   tt=None
   for _ in range(50):
    tt=ticks(tproc.pid)
    if tt is not None and os.path.exists(TPM_SOCKET):break
    time.sleep(.1)
   if tt is None or not os.path.exists(TPM_SOCKET):raise ValueError()
   write_json(GUEST+'/swtpm-started.json',{'pid':tproc.pid,'startTicks':tt})
   qlog=os.open(GUEST+'/qemu.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
   try:qproc=subprocess.Popen(qemu_args(),stdin=subprocess.DEVNULL,stdout=qlog,stderr=qlog,start_new_session=True,close_fds=True)
   finally:os.close(qlog)
   qt=None
   for _ in range(50):
    qt=ticks(qproc.pid)
    if qt is not None and os.path.exists(QMP):break
    time.sleep(.1)
   if qt is None or not os.path.exists(QMP):raise ValueError()
   write_json(GUEST+'/qemu-started.json',{'pid':qproc.pid,'startTicks':qt})
   emit(state())
 else:emit('unknown','invalid-mode')
except Exception:
 emit('unknown','effect-or-observation-unknown')
'''


def _validate(host: str, correlation_id: str, timeout_seconds: int) -> None:
    if (host != HOST or not isinstance(correlation_id, str) or UUID.fullmatch(correlation_id) is None
            or type(timeout_seconds) is not int or not 30 <= timeout_seconds <= 300):
        raise ValueError("Secure Boot fresh VM requires fixed host, canonical correlation and bounded timeout.")


def _intent(root: str | Path, *, create: bool) -> Path:
    base = Path(root).resolve(strict=True) / ".rag_index"
    directory = base / "windows-vm-secureboot-fresh"
    if create:
        base.mkdir(mode=0o700, exist_ok=True)
        directory.mkdir(mode=0o700, exist_ok=True)
    for path in (base, directory):
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("Secure Boot fresh VM journal is unsafe.")
    return directory / "intent.json"


def _payload(correlation_id: str) -> dict[str, Any]:
    return {"schemaVersion": 1, "host": HOST, "correlationId": correlation_id,
            "guest": GUEST, "windowsSha256": WINDOWS_SHA256, "driverSha256": DRIVER_SHA256,
            "codeSha256": CODE_SHA256, "varsTemplateSha256": VARS_SHA256,
            "memoryMiB": MEMORY_MIB, "vncPort": VNC_PORT}


def _save(path: Path, correlation_id: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, json.dumps(_payload(correlation_id), sort_keys=True).encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _read(path: Path, correlation_id: str) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("Secure Boot fresh VM intent is unsafe.")
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            fd = -1
            value = json.load(stream)
    finally:
        if fd >= 0:
            os.close(fd)
    if value != _payload(correlation_id):
        raise ValueError("Secure Boot fresh VM intent changed.")


def _program(correlation_id: str, mode: str) -> str:
    values = {"ROOT": ROOT, "GUEST": GUEST, "CORR": correlation_id, "MODE": mode,
              "WIN": WINDOWS_ISO, "WIN_SIZE": WINDOWS_SIZE, "WIN_HASH": WINDOWS_SHA256,
              "DRV": DRIVER_ISO, "DRV_SIZE": DRIVER_SIZE, "DRV_HASH": DRIVER_SHA256,
              "CODE": CODE, "CODE_HASH": CODE_SHA256, "VARS": VARS_TEMPLATE,
              "VARS_HASH": VARS_SHA256, "MEM": MEMORY_MIB, "HEADROOM": HEADROOM_KIB,
              "MIN_DISK": MIN_DISK_KIB, "PORT": VNC_PORT}
    program = _REMOTE
    for key, value in values.items():
        program = program.replace("__" + key + "__", repr(value))
    return program


def _remote(root: str | Path, correlation_id: str, mode: str, timeout_seconds: int) -> dict[str, Any]:
    config = ssh_transport.load_config(Path(root).resolve(strict=True))
    if HOST not in config.hosts or ssh_transport.connection_host(config, HOST).password is not None:
        raise ValueError("Configured Arch transport is unavailable.")
    argv = ssh_transport.build_ssh_argv(config, HOST, min(timeout_seconds, 30),
                                        command=("python3", "-c", "exec(" + repr(_program(correlation_id, mode)) + ")"))
    completed = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, timeout=timeout_seconds, check=False)
    if completed.returncode or not 0 < len(completed.stdout) <= 2048:
        raise ValueError("Secure Boot fresh VM transport is unknown.")
    value = json.loads(completed.stdout)
    if (not isinstance(value, Mapping) or value.get("schemaVersion") != 1
            or value.get("correlationId") != correlation_id or value.get("nativeActionAllowed") is not False
            or value.get("state") not in {"ready", "blocked", "absent", "partial-unknown", "running-observed", "unknown"}
            or value.get("reason") not in {None, "guest-root-exists", "virt-fw-vars-unavailable",
                                            "host-components-unavailable", "kvm-unavailable", "vnc-port-owned",
                                            "memory-headroom", "disk-headroom", "invalid-mode",
                                            "effect-or-observation-unknown"}):
        raise ValueError("Secure Boot fresh VM response is invalid.")
    return dict(value)


def preflight(root: str | Path, *, host: str, correlation_id: str, timeout_seconds: int = 180) -> dict[str, Any]:
    _validate(host, correlation_id, timeout_seconds)
    try:
        return _remote(root, correlation_id, "preflight", timeout_seconds)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return {"state": "unknown", "nativeActionAllowed": False}


def start(root: str | Path, *, host: str, correlation_id: str,
          reservation_request: Mapping[str, Any], timeout_seconds: int = 300) -> dict[str, Any]:
    _validate(host, correlation_id, timeout_seconds)
    if (not isinstance(reservation_request, Mapping) or reservation_request.get("hostAlias") != HOST
            or reservation_request.get("environment") != ENVIRONMENT
            or reservation_request.get("operator") != OPERATOR
            or reservation_request.get("requestedMemoryBytes") != MEMORY_MIB * 1024 * 1024
            or reservation_request.get("allocationState") != "pending"
            or not isinstance(reservation_request.get("reservationIdentity"), Mapping)):
        raise ValueError("Secure Boot fresh VM needs a separate exact pending reservation.")
    path = _intent(root, create=True)
    try:
        _save(path, correlation_id)
    except FileExistsError as error:
        raise ValueError("Secure Boot fresh VM intent exists; use exact status.") from error
    admitted = native_environment.reserve_environment(root, reservation_request)
    if (admitted.get("state") != "reserved" or admitted.get("identity") != reservation_request["reservationIdentity"]
            or admitted.get("reservation", {}).get("allocationState") != "pending"):
        raise ValueError("Secure Boot fresh VM host reservation was not admitted.")
    try:
        result = _remote(root, correlation_id, "start", timeout_seconds)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        result = {"state": "unknown", "reason": "transport-unknown"}
    return {"correlationId": correlation_id, "state": result["state"], "reason": result.get("reason"),
            "guest": GUEST, "vncPort": VNC_PORT, "replayAllowed": False, "nativeActionAllowed": False}


def status(root: str | Path, *, host: str, correlation_id: str, timeout_seconds: int = 60) -> dict[str, Any]:
    _validate(host, correlation_id, timeout_seconds)
    _read(_intent(root, create=False), correlation_id)
    try:
        result = _remote(root, correlation_id, "status", timeout_seconds)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        result = {"state": "unknown", "reason": "transport-unknown"}
    return {"correlationId": correlation_id, "state": result["state"], "reason": result.get("reason"),
            "guest": GUEST, "vncPort": VNC_PORT, "replayAllowed": False, "nativeActionAllowed": False}

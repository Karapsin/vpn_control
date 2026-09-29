"""One-shot, source-bound Windows setup VM on the Arch test host.

The VM uses a new blank disk and stops at the vendor setup boundary.  No
answer file, product key, account, or license interaction is supplied here.
An intent is durable before any remote write; an uncertain start is observed
through status and is never replayed.
"""
from __future__ import annotations

import json
import base64
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import zlib
from typing import Any, Mapping

try:
    from . import native_environment, ssh_transport
except ImportError:
    import native_environment  # type: ignore[no-redef]
    import ssh_transport  # type: ignore[no-redef]


HOST = "archlinux"
ROOT = "/home/kardinal/vpn-control-windows-baseline-20260929"
GUEST = ROOT + "/guest"
WINDOWS_ISO = "/home/kardinal/vpn-control-windows-native-20260907/windows-x64.iso"
WINDOWS_SHA256 = "a61adeab895ef5a4db436e0a7011c92a2ff17bb0357f58b13bbc4062e535e7b9"
WINDOWS_SIZE = 7092807680
DRIVER_ISO = ROOT + "/runtime/virtio-win-0.1.285.iso"
DRIVER_SHA256 = "e14cf2b94492c3e925f0070ba7fdfedeb2048c91eea9c5a5afb30232a3976331"
DRIVER_SIZE = 789645312
MEMORY_MIB = 6144
HEADROOM_KIB = 8 * 1024 * 1024
MIN_DISK_KIB = 30 * 1024 * 1024
VNC_PORT = 5927
ENVIRONMENT = "windows-vm-baseline-20260929"
OPERATOR = "windows-baseline"
UUID = re.compile(r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$")

_REMOTE = r'''import base64,hashlib,json,os,shutil,socket,stat,subprocess,sys,time,zlib
ROOT=__ROOT__;GUEST=__GUEST__;CORR=__CORR__;MODE=__MODE__
WIN=__WIN__;WIN_HASH=__WIN_HASH__;WIN_SIZE=__WIN_SIZE__
DRV=__DRV__;DRV_HASH=__DRV_HASH__;DRV_SIZE=__DRV_SIZE__
PORT=__PORT__;MEM=__MEM__;HEADROOM=__HEADROOM__;MIN_DISK=__MIN_DISK__
def fail(reason):
 print(json.dumps({'schemaVersion':1,'correlationId':CORR,'state':'blocked','reason':reason,'nativeActionAllowed':False},separators=(',',':')));sys.exit(0)
def private_dir(path):
 s=os.lstat(path)
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o700:raise ValueError('unsafe-directory')
def media(path,size,digest):
 fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 try:
  a=os.fstat(fd)
  if not stat.S_ISREG(a.st_mode) or a.st_size!=size or a.st_uid!=os.geteuid():raise ValueError('unsafe-media')
  h=hashlib.sha256()
  while True:
   chunk=os.read(fd,1048576)
   if not chunk:break
   h.update(chunk)
  b=os.fstat(fd);c=os.stat(path,follow_symlinks=False)
  keys=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
  if any(getattr(a,k)!=getattr(b,k) or getattr(a,k)!=getattr(c,k) for k in keys) or h.hexdigest()!=digest:raise ValueError('media-mismatch')
 finally:os.close(fd)
def ticks(pid):
 try:
  with open('/proc/%d/stat'%pid) as f:return int(f.read().rsplit(')',1)[1].split()[19])
 except (OSError,ValueError,IndexError):return None
def qemu_claim(pid):
 before=ticks(pid)
 if before is None:return 'gone',None
 try:
  comm=open('/proc/%d/comm'%pid).read().strip()
 except OSError:return 'uncertain',None
 if not comm.startswith('qemu-system-'):return 'other',None
 try:
  exe=os.path.basename(os.readlink('/proc/%d/exe'%pid))
  argv=open('/proc/%d/cmdline'%pid,'rb').read().split(b'\0')
  disk_arg=b'file='+(GUEST+'/disk.qcow2').encode()+b',if=virtio,format=qcow2'
  qmp_arg=b'unix:'+(GUEST+'/qmp.sock').encode()+b',server=on,wait=off'
  if exe!='qemu-system-x86_64' or disk_arg not in argv or qmp_arg not in argv:
   return ('other',None) if ticks(pid)==before else ('uncertain',None)
  fd_names=os.listdir('/proc/%d/fd'%pid)
  disk=os.stat(GUEST+'/disk.qcow2',follow_symlinks=False)
  with open('/proc/net/unix') as f:unix=f.read().splitlines()
  sockets=[line.split()[6] for line in unix[1:] if len(line.split())>=8 and line.split()[-1]==GUEST+'/qmp.sock']
  links={item:os.readlink('/proc/%d/fd/'%pid+item) for item in fd_names}
  disk_owned=False
  for item,link in links.items():
   if link==GUEST+'/disk.qcow2':
    held=os.stat('/proc/%d/fd/'%pid+item)
    if held.st_dev==disk.st_dev and held.st_ino==disk.st_ino:disk_owned=True
 except (OSError,IndexError):return 'uncertain',None
 after=ticks(pid)
 if after!=before:return 'uncertain',None
 if not stat.S_ISREG(disk.st_mode) or not disk_owned or len(sockets)!=1 or 'socket:['+sockets[0]+']' not in links.values():return 'uncertain',None
 return 'match',before
def running():
 path=GUEST+'/started.json'
 started=None
 if os.path.isfile(path):
  with open(path) as f:started=json.load(f)
  if type(started.get('pid'))!=int or type(started.get('startTicks'))!=int:return 'unknown'
 proc=[item for item in os.listdir('/proc') if item.isdigit()]
 if len(proc)>8192:return 'unknown'
 matches=[];uncertain=False
 for item in proc:
  state,generation=qemu_claim(int(item))
  if state=='match':matches.append((int(item),generation))
  if state=='uncertain':uncertain=True
 if uncertain or len(matches)>1:return 'unknown'
 if started is None:return 'running-unrecorded-observed' if len(matches)==1 else 'unknown'
 if matches==[(started['pid'],started['startTicks'])]:return 'running-observed'
 if matches:return 'unknown'
 return 'stopped-observed' if ticks(started['pid']) is None else 'unknown'
def availability():
 private_dir(ROOT);private_dir(ROOT+'/runtime')
 media(WIN,WIN_SIZE,WIN_HASH);media(DRV,DRV_SIZE,DRV_HASH)
 if not os.path.exists('/dev/kvm'):raise ValueError('kvm-unavailable')
 if not shutil.which('qemu-img') or not shutil.which('qemu-system-x86_64'):raise ValueError('qemu-unavailable')
 firmware=None
 for code,variables in (('/usr/share/edk2/x64/OVMF_CODE.4m.fd','/usr/share/edk2/x64/OVMF_VARS.4m.fd'),('/usr/share/OVMF/OVMF_CODE_4M.fd','/usr/share/OVMF/OVMF_VARS_4M.fd')):
  if os.path.isfile(code) and os.path.isfile(variables):firmware=(code,variables);break
 if firmware is None:raise ValueError('ovmf-unavailable')
 with open('/proc/meminfo') as f:lines=f.read().splitlines()
 available=next(int(line.split()[1]) for line in lines if line.startswith('MemAvailable:'))
 if available < MEM*1024+HEADROOM:raise ValueError('memory-headroom')
 free=shutil.disk_usage(ROOT).free//1024
 if free<MIN_DISK:raise ValueError('disk-headroom')
 sock=socket.socket()
 try:sock.bind(('127.0.0.1',PORT))
 except OSError:raise ValueError('vnc-port-owned')
 finally:sock.close()
 return firmware,available,free
def screen_receipt(capture):
 if running()!='running-observed':raise ValueError('vm-identity-unknown')
 path=GUEST+'/screen-'+CORR+'.ppm'
 if capture:
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  claimed=os.fstat(fd);os.close(fd)
  sock=socket.socket(socket.AF_UNIX);sock.settimeout(15)
  try:
   sock.connect(GUEST+'/qmp.sock')
   stream=sock.makefile('rwb',buffering=0)
   def receive():
    for _ in range(32):
     line=stream.readline(65537)
     if not line or len(line)>65536:raise ValueError('qmp-response-unknown')
     value=json.loads(line)
     if 'return' in value:return value
     if 'error' in value:raise ValueError('qmp-error')
    raise ValueError('qmp-response-unknown')
   greeting=json.loads(stream.readline(65537))
   if 'QMP' not in greeting:raise ValueError('qmp-greeting-unknown')
   stream.write(b'{"execute":"qmp_capabilities"}\r\n');receive()
   stream.write(json.dumps({'execute':'screendump','arguments':{'filename':path}}).encode()+b'\r\n');receive()
  finally:sock.close()
 fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 try:
  before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid() or not 64<=before.st_size<=8388608:raise ValueError('screen-unsafe')
  if capture and (before.st_ino!=claimed.st_ino or before.st_dev!=claimed.st_dev):raise ValueError('screen-claim-changed')
  data=b''
  while len(data)<=8388608:
   chunk=os.read(fd,1048576)
   if not chunk:break
   data+=chunk
  after=os.fstat(fd);name=os.stat(path,follow_symlinks=False)
  keys=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
  if len(data)!=before.st_size or any(getattr(before,k)!=getattr(after,k) or getattr(before,k)!=getattr(name,k) for k in keys):raise ValueError('screen-changed')
 finally:os.close(fd)
 header=data.split(b'\n',3)
 if len(header)<4 or header[0]!=b'P6' or header[2]!=b'255':raise ValueError('screen-format')
 width,height=[int(item) for item in header[1].split()]
 if not 320<=width<=3840 or not 240<=height<=2160 or len(header[3])!=width*height*3:raise ValueError('screen-dimensions')
 if running()!='running-observed':raise ValueError('vm-changed-during-capture')
 return {'schemaVersion':1,'correlationId':CORR,'state':'observed','reason':None,'nativeActionAllowed':False,
         'width':width,'height':height,'frameSizeBytes':len(data),'frameSha256':hashlib.sha256(data).hexdigest(),
         'frameBase64':base64.b64encode(zlib.compress(data,6)).decode()}
try:
 if MODE=='status':
  if not os.path.lexists(GUEST):state='absent'
  else:
   private_dir(GUEST)
   path=GUEST+'/intent.json'
   if not os.path.isfile(path):state='unknown'
   else:
    with open(path) as f:intent=json.load(f)
    state=running() if intent.get('correlationId')==CORR and intent.get('windowsSha256')==WIN_HASH and intent.get('driverSha256')==DRV_HASH else 'unknown'
  print(json.dumps({'schemaVersion':1,'correlationId':CORR,'state':state,'reason':None,'nativeActionAllowed':False},separators=(',',':')))
 elif MODE in ('screen-start','screen-status'):
  private_dir(GUEST)
  with open(GUEST+'/intent.json') as f:intent=json.load(f)
  if intent.get('correlationId')!=CORR or intent.get('windowsSha256')!=WIN_HASH or intent.get('driverSha256')!=DRV_HASH:raise ValueError('wrong-vm-intent')
  print(json.dumps(screen_receipt(MODE=='screen-start'),separators=(',',':')))
 elif MODE=='preflight':
  if os.path.lexists(GUEST):fail('guest-root-exists')
  firmware,available,free=availability()
  print(json.dumps({'schemaVersion':1,'correlationId':CORR,'state':'ready','reason':None,'nativeActionAllowed':False,'availableMemoryKiB':available,'freeDiskKiB':free,'firmware':firmware[0],'vncPort':PORT,'windowsSha256':WIN_HASH,'driverSha256':DRV_HASH},separators=(',',':')))
 elif MODE=='start':
  if os.path.lexists(GUEST):fail('guest-root-exists')
  firmware,available,free=availability()
  os.mkdir(GUEST,0o700);private_dir(GUEST)
  record={'schemaVersion':1,'correlationId':CORR,'windowsSha256':WIN_HASH,'driverSha256':DRV_HASH,'windowsIso':WIN,'driverIso':DRV,'memoryMiB':MEM,'vncPort':PORT,'firmware':firmware[0]}
  fd=os.open(GUEST+'/intent.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  try:os.write(fd,json.dumps(record,sort_keys=True).encode());os.fsync(fd)
  finally:os.close(fd)
  dfd=os.open(GUEST,os.O_RDONLY|os.O_DIRECTORY);os.fsync(dfd);os.close(dfd)
  src=os.open(firmware[1],os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
  dest=os.open(GUEST+'/uefi-vars.fd',os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  try:
   while True:
    chunk=os.read(src,1048576)
    if not chunk:break
    view=memoryview(chunk)
    while view:view=view[os.write(dest,view):]
   os.fsync(dest)
  finally:os.close(src);os.close(dest)
  temp=GUEST+'/disk.create.qcow2'
  fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  claimed=os.fstat(fd);os.close(fd)
  subprocess.run(['qemu-img','create','-f','qcow2',temp,'96G'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
  completed=os.lstat(temp)
  if not stat.S_ISREG(completed.st_mode) or completed.st_dev!=claimed.st_dev or completed.st_ino!=claimed.st_ino:raise ValueError('disk-claim-changed')
  os.link(temp,GUEST+'/disk.qcow2',follow_symlinks=False)
  os.unlink(temp)
  dfd=os.open(GUEST,os.O_RDONLY|os.O_DIRECTORY);os.fsync(dfd);os.close(dfd)
  args=['qemu-system-x86_64','-name','vpn-control-windows-setup-20260929','-machine','q35','-accel','kvm','-cpu','host','-smp','4','-m',str(MEM),
        '-drive','if=pflash,format=raw,readonly=on,file='+firmware[0],'-drive','if=pflash,format=raw,file='+GUEST+'/uefi-vars.fd',
        '-drive','file='+GUEST+'/disk.qcow2,if=virtio,format=qcow2','-drive','file='+WIN+',media=cdrom,readonly=on',
        '-drive','file='+DRV+',media=cdrom,readonly=on','-netdev','user,id=net0','-device','virtio-net-pci,netdev=net0',
        '-display','none','-vnc','127.0.0.1:'+str(PORT-5900),'-monitor','none','-qmp','unix:'+GUEST+'/qmp.sock,server=on,wait=off']
  log=os.open(GUEST+'/qemu.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  try:p=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True,close_fds=True)
  finally:os.close(log)
  for _ in range(50):
   t=ticks(p.pid)
   if t is not None:break
   time.sleep(.1)
  if t is None:raise ValueError('qemu-start-unknown')
  fd=os.open(GUEST+'/started.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  try:os.write(fd,json.dumps({'pid':p.pid,'startTicks':t}).encode());os.fsync(fd)
  finally:os.close(fd)
  dfd=os.open(GUEST,os.O_RDONLY|os.O_DIRECTORY);os.fsync(dfd);os.close(dfd)
  print(json.dumps({'schemaVersion':1,'correlationId':CORR,'state':running(),'reason':None,'nativeActionAllowed':False},separators=(',',':')))
 else:fail('invalid-mode')
except (OSError,ValueError,subprocess.SubprocessError,StopIteration) as error:
 print(json.dumps({'schemaVersion':1,'correlationId':CORR,'state':'unknown','reason':type(error).__name__,'nativeActionAllowed':False},separators=(',',':')))
'''

_PROBE_REMOTE = r'''import json,os,stat,subprocess
ROOT=__ROOT__;PROBE=ROOT+'/qemu-img-create-probe';CORR=__CORR__;MODE=__MODE__
def private(path):
 s=os.lstat(path)
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o700:raise ValueError('unsafe-directory')
def state():
 if not os.path.lexists(PROBE):return 'absent'
 private(PROBE)
 with open(PROBE+'/intent.json') as f:intent=json.load(f)
 if intent!={'schemaVersion':1,'correlationId':CORR}:return 'unknown'
 final=PROBE+'/disk.qcow2';temp=PROBE+'/disk.create.qcow2'
 if os.path.lexists(temp):return 'partial'
 if not os.path.lexists(final):return 'unknown'
 info=os.lstat(final)
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1:return 'unknown'
 result=subprocess.run(['qemu-img','info','--output=json',final],capture_output=True,timeout=15,check=True)
 image=json.loads(result.stdout)
 return 'verified' if image.get('format')=='qcow2' and image.get('virtual-size')==8388608 and not image.get('backing-filename') else 'unknown'
try:
 if MODE=='start':
  private(ROOT)
  if os.path.lexists(PROBE):raise ValueError('probe-exists')
  os.mkdir(PROBE,0o700);private(PROBE)
  fd=os.open(PROBE+'/intent.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  try:os.write(fd,json.dumps({'schemaVersion':1,'correlationId':CORR}).encode());os.fsync(fd)
  finally:os.close(fd)
  dfd=os.open(PROBE,os.O_RDONLY|os.O_DIRECTORY);os.fsync(dfd);os.close(dfd)
  temp=PROBE+'/disk.create.qcow2'
  fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  claimed=os.fstat(fd);os.close(fd)
  subprocess.run(['qemu-img','create','-f','qcow2',temp,'8M'],check=True,capture_output=True,timeout=30)
  built=os.lstat(temp)
  if not stat.S_ISREG(built.st_mode) or built.st_dev!=claimed.st_dev or built.st_ino!=claimed.st_ino:raise ValueError('claim-changed')
  os.link(temp,PROBE+'/disk.qcow2',follow_symlinks=False)
  os.unlink(temp)
  dfd=os.open(PROBE,os.O_RDONLY|os.O_DIRECTORY);os.fsync(dfd);os.close(dfd)
 elif MODE!='status':raise ValueError('invalid-mode')
 print(json.dumps({'schemaVersion':1,'correlationId':CORR,'state':state(),'nativeActionAllowed':False},separators=(',',':')))
except (OSError,ValueError,subprocess.SubprocessError):
 print(json.dumps({'schemaVersion':1,'correlationId':CORR,'state':'unknown','nativeActionAllowed':False},separators=(',',':')))
'''


def _validate(host: str, correlation_id: str, timeout_seconds: int) -> None:
    if (host != HOST or not isinstance(correlation_id, str) or not UUID.fullmatch(correlation_id)
            or type(timeout_seconds) is not int or not 30 <= timeout_seconds <= 300):
        raise ValueError("Windows fresh setup requires fixed host, canonical correlation and bounded timeout")


def _intent(root: str | Path, *, create: bool) -> Path:
    base = Path(root).resolve() / ".rag_index"
    directory = base / "windows-vm-fresh-setup"
    if create:
        base.mkdir(mode=0o700, exist_ok=True)
        directory.mkdir(mode=0o700, exist_ok=True)
    for path in (base, directory):
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("Windows fresh setup journal is unsafe")
    return directory / "intent.json"


def _payload(correlation_id: str) -> dict[str, Any]:
    return {"schemaVersion": 1, "host": HOST, "correlationId": correlation_id,
            "guest": GUEST, "windowsSha256": WINDOWS_SHA256, "driverSha256": DRIVER_SHA256,
            "memoryMiB": MEMORY_MIB, "vncPort": VNC_PORT}


def _save(path: Path, correlation_id: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, json.dumps(_payload(correlation_id), sort_keys=True).encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    dfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _read(path: Path, correlation_id: str) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("Windows fresh setup intent is unsafe")
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            fd = -1
            value = json.load(stream)
    finally:
        if fd >= 0:
            os.close(fd)
    if value != _payload(correlation_id):
        raise ValueError("Windows fresh setup intent changed")


def _program(correlation_id: str, mode: str) -> str:
    substitutions = {"ROOT": ROOT, "GUEST": GUEST, "CORR": correlation_id, "MODE": mode,
                     "WIN": WINDOWS_ISO, "WIN_HASH": WINDOWS_SHA256, "WIN_SIZE": WINDOWS_SIZE,
                     "DRV": DRIVER_ISO, "DRV_HASH": DRIVER_SHA256, "DRV_SIZE": DRIVER_SIZE,
                     "PORT": VNC_PORT, "MEM": MEMORY_MIB, "HEADROOM": HEADROOM_KIB, "MIN_DISK": MIN_DISK_KIB}
    program = _REMOTE
    for key, value in substitutions.items():
        program = program.replace("__" + key + "__", repr(value))
    return program


def _remote(root: str | Path, host: str, correlation_id: str, mode: str, timeout_seconds: int) -> dict[str, Any]:
    program = _program(correlation_id, mode)
    config = ssh_transport.load_config(root)
    if host not in config.hosts or ssh_transport.connection_host(config, host).password is not None:
        raise ValueError("Configured Arch transport is unavailable")
    argv = ssh_transport.build_ssh_argv(config, host, min(timeout_seconds, 30),
                                        command=("python3", "-c", "exec(" + repr(program) + ")"))
    completed = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               timeout=timeout_seconds, check=False)
    if completed.returncode != 0 or len(completed.stdout) > 2048:
        raise ValueError("Windows fresh setup transport is unknown")
    value = json.loads(completed.stdout)
    if (not isinstance(value, Mapping) or value.get("schemaVersion") != 1
            or value.get("correlationId") != correlation_id
            or value.get("state") not in ("ready", "blocked", "absent", "running-observed", "running-unrecorded-observed", "stopped-observed", "unknown")
            or value.get("nativeActionAllowed") is not False):
        raise ValueError("Windows fresh setup response is invalid")
    return dict(value)


def _screen_remote(root: str | Path, host: str, correlation_id: str, mode: str, timeout_seconds: int) -> dict[str, Any]:
    config = ssh_transport.load_config(root)
    if host not in config.hosts or ssh_transport.connection_host(config, host).password is not None:
        raise ValueError("Configured Arch transport is unavailable")
    argv = ssh_transport.build_ssh_argv(config, host, min(timeout_seconds, 30),
                                        command=("python3", "-c", "exec(" + repr(_program(correlation_id, mode)) + ")"))
    completed = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               timeout=timeout_seconds, check=False)
    if completed.returncode != 0 or len(completed.stdout) > 13_000_000:
        raise ValueError("Windows screen transport is unknown")
    value = json.loads(completed.stdout)
    if (not isinstance(value, Mapping) or value.get("schemaVersion") != 1
            or value.get("correlationId") != correlation_id or value.get("nativeActionAllowed") is not False):
        raise ValueError("Windows screen response is invalid")
    if value.get("state") == "unknown":
        return {"state": "unknown"}
    if (value.get("state") != "observed" or type(value.get("width")) is not int
            or not 320 <= value["width"] <= 3840 or type(value.get("height")) is not int
            or not 240 <= value["height"] <= 2160 or type(value.get("frameSizeBytes")) is not int
            or not 64 <= value["frameSizeBytes"] <= 8_388_608
            or not isinstance(value.get("frameSha256"), str)
            or not isinstance(value.get("frameBase64"), str)):
        raise ValueError("Windows screen frame is invalid")
    packed = base64.b64decode(value["frameBase64"], validate=True)
    decompressor = zlib.decompressobj()
    frame = decompressor.decompress(packed, 8_388_609)
    frame += decompressor.flush(8_388_609 - len(frame))
    if (not decompressor.eof or decompressor.unused_data or len(frame) != value["frameSizeBytes"]
            or hashlib.sha256(frame).hexdigest() != value["frameSha256"]):
        raise ValueError("Windows screen frame digest changed")
    header = frame.split(b"\n", 3)
    if (len(header) != 4 or header[0] != b"P6" or header[2] != b"255"
            or header[1] != f"{value['width']} {value['height']}".encode()
            or len(header[3]) != value["width"] * value["height"] * 3):
        raise ValueError("Windows screen frame dimensions changed")
    return {"state": "observed", "frame": frame, "sha256": value["frameSha256"],
            "width": value["width"], "height": value["height"]}


def preflight(root: str | Path, *, host: str, correlation_id: str, timeout_seconds: int = 180) -> dict[str, Any]:
    _validate(host, correlation_id, timeout_seconds)
    return _remote(root, host, correlation_id, "preflight", timeout_seconds)


def start(root: str | Path, *, host: str, correlation_id: str,
          reservation_request: Mapping[str, Any], timeout_seconds: int = 300) -> dict[str, Any]:
    _validate(host, correlation_id, timeout_seconds)
    if (not isinstance(reservation_request, Mapping)
            or reservation_request.get("hostAlias") != HOST
            or reservation_request.get("environment") != ENVIRONMENT
            or reservation_request.get("operator") != OPERATOR
            or reservation_request.get("requestedMemoryBytes") != MEMORY_MIB * 1024 * 1024
            or reservation_request.get("allocationState") != "pending"
            or not isinstance(reservation_request.get("reservationIdentity"), Mapping)):
        raise ValueError("Windows fresh setup requires exact pending host reservation")
    path = _intent(root, create=True)
    try:
        _save(path, correlation_id)
    except FileExistsError as error:
        raise ValueError("Windows fresh setup intent exists; use exact status") from error
    admitted = native_environment.reserve_environment(root, reservation_request)
    if (admitted.get("state") != "reserved" or admitted.get("identity") != reservation_request["reservationIdentity"]
            or admitted.get("reservation", {}).get("allocationState") != "pending"):
        raise ValueError("Windows fresh setup host reservation was not admitted")
    try:
        result = _remote(root, host, correlation_id, "start", timeout_seconds)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        result = {"state": "unknown", "reason": "transport-unknown"}
    return {"correlationId": correlation_id, "state": result["state"], "reason": result.get("reason"),
            "guest": GUEST, "vncPort": VNC_PORT, "replayAllowed": False, "nativeActionAllowed": False}


def status(root: str | Path, *, host: str, correlation_id: str, timeout_seconds: int = 60) -> dict[str, Any]:
    _validate(host, correlation_id, timeout_seconds)
    _read(_intent(root, create=False), correlation_id)
    try:
        result = _remote(root, host, correlation_id, "status", timeout_seconds)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        result = {"state": "unknown", "reason": "transport-unknown"}
    return {"correlationId": correlation_id, "state": result["state"], "reason": result.get("reason"),
            "guest": GUEST, "vncPort": VNC_PORT, "replayAllowed": False, "nativeActionAllowed": False}


def _probe_remote(root: str | Path, host: str, correlation_id: str, mode: str, timeout_seconds: int) -> dict[str, Any]:
    program = (_PROBE_REMOTE.replace("__ROOT__", repr(ROOT))
               .replace("__CORR__", repr(correlation_id)).replace("__MODE__", repr(mode)))
    config = ssh_transport.load_config(root)
    if host not in config.hosts or ssh_transport.connection_host(config, host).password is not None:
        raise ValueError("Configured Arch transport is unavailable")
    argv = ssh_transport.build_ssh_argv(config, host, min(timeout_seconds, 30),
                                        command=("python3", "-c", "exec(" + repr(program) + ")"))
    completed = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               timeout=timeout_seconds, check=False)
    if completed.returncode != 0 or len(completed.stdout) > 512:
        raise ValueError("Windows disk probe transport is unknown")
    value = json.loads(completed.stdout)
    if (not isinstance(value, Mapping) or value.get("schemaVersion") != 1
            or value.get("correlationId") != correlation_id or value.get("nativeActionAllowed") is not False
            or value.get("state") not in ("absent", "partial", "verified", "unknown")):
        raise ValueError("Windows disk probe response is invalid")
    return dict(value)


def _probe_intent(root: str | Path, *, create: bool) -> Path:
    base = Path(root).resolve() / ".rag_index"
    directory = base / "windows-vm-disk-probe"
    if create:
        base.mkdir(mode=0o700, exist_ok=True)
        directory.mkdir(mode=0o700, exist_ok=True)
    for path in (base, directory):
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("Windows disk probe journal is unsafe")
    return directory / "intent.json"


def probe_start(root: str | Path, *, host: str, correlation_id: str, timeout_seconds: int = 60) -> dict[str, Any]:
    _validate(host, correlation_id, timeout_seconds)
    path = _probe_intent(root, create=True)
    _save(path, correlation_id)
    try:
        result = _probe_remote(root, host, correlation_id, "start", timeout_seconds)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        result = {"state": "unknown"}
    return {"correlationId": correlation_id, "state": result["state"], "replayAllowed": False,
            "nativeActionAllowed": False}


def probe_status(root: str | Path, *, host: str, correlation_id: str, timeout_seconds: int = 60) -> dict[str, Any]:
    _validate(host, correlation_id, timeout_seconds)
    _read(_probe_intent(root, create=False), correlation_id)
    try:
        result = _probe_remote(root, host, correlation_id, "status", timeout_seconds)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        result = {"state": "unknown"}
    return {"correlationId": correlation_id, "state": result["state"], "replayAllowed": False,
            "nativeActionAllowed": False}


def _screen_intent(root: str | Path, *, create: bool) -> Path:
    base = Path(root).resolve() / ".rag_index"
    directory = base / "windows-vm-setup-screen"
    if create:
        base.mkdir(mode=0o700, exist_ok=True)
        directory.mkdir(mode=0o700, exist_ok=True)
    for path in (base, directory):
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("Windows screen journal is unsafe")
    return directory / "intent.json"


def _screen_result(path: Path, correlation_id: str, value: Mapping[str, Any]) -> dict[str, Any]:
    if value.get("state") != "observed":
        return {"correlationId": correlation_id, "state": "unknown", "replayAllowed": False,
                "nativeActionAllowed": False}
    frame_path = path.parent / ("frame-" + correlation_id + ".ppm")
    frame = value["frame"]
    try:
        fd = os.open(frame_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        fd = os.open(frame_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise ValueError("Windows screen local frame is unsafe")
            existing = bytearray()
            while len(existing) <= 8_388_608:
                chunk = os.read(fd, 1_048_576)
                if not chunk:
                    break
                existing.extend(chunk)
            if existing != frame:
                raise ValueError("Windows screen local frame changed")
        finally:
            os.close(fd)
    else:
        try:
            view = memoryview(frame)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
    return {"correlationId": correlation_id, "state": "observed", "width": value["width"],
            "height": value["height"], "frameSha256": value["sha256"],
            "framePath": str(frame_path), "replayAllowed": False, "nativeActionAllowed": False}


def screen_start(root: str | Path, *, host: str, correlation_id: str, timeout_seconds: int = 60) -> dict[str, Any]:
    _validate(host, correlation_id, timeout_seconds)
    path = _screen_intent(root, create=True)
    _save(path, correlation_id)
    try:
        value = _screen_remote(root, host, correlation_id, "screen-start", timeout_seconds)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError, zlib.error):
        value = {"state": "unknown"}
    return _screen_result(path, correlation_id, value)


def screen_status(root: str | Path, *, host: str, correlation_id: str, timeout_seconds: int = 60) -> dict[str, Any]:
    _validate(host, correlation_id, timeout_seconds)
    path = _screen_intent(root, create=False)
    _read(path, correlation_id)
    try:
        value = _screen_remote(root, host, correlation_id, "screen-status", timeout_seconds)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError, zlib.error):
        value = {"state": "unknown"}
    return _screen_result(path, correlation_id, value)

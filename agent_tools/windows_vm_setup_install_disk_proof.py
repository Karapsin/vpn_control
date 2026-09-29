"""Read-only proof that Windows Setup can reach only its blank disposable disk."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
from typing import Any, Mapping

try:
    from . import windows_vm_optical_boot as boot
    from . import windows_vm_setup_keyboard_next as keyboard
except ImportError:
    import windows_vm_optical_boot as boot  # type: ignore[no-redef]
    import windows_vm_setup_keyboard_next as keyboard  # type: ignore[no-redef]


KEYBOARD_CORRELATION = "7f9ac4d6-b2b6-4018-8b35-c8476b2aec6d"
INSTALL_FRAME_SHA256 = "787bc4fbce9764e08f909a339f4f16b4253c67a40f449ae34210bed0f1ee4e58"

_REMOTE = r'''
INSTALL_FRAME_SHA=__INSTALL_FRAME_SHA__;FIRST_BLANK_CORR=__FIRST_BLANK_CORR__
PHASE='source'
def disk_metadata():
 fd=os.open(DISK,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 try:
  a=os.fstat(fd)
  if (not stat.S_ISREG(a.st_mode) or a.st_uid!=os.geteuid() or a.st_nlink!=1
      or stat.S_IMODE(a.st_mode)!=0o600 or not 104<=a.st_size<=96*1024**3):
   raise ValueError('disk-unsafe')
  header=os.pread(fd,104,0)
  if len(header)!=104 or header[:4]!=b'QFI\xfb':raise ValueError('disk-header')
  version=struct.unpack_from('>I',header,4)[0]
  backing=struct.unpack_from('>Q',header,8)[0];backing_size=struct.unpack_from('>I',header,16)[0]
  cluster_bits=struct.unpack_from('>I',header,20)[0];virtual=struct.unpack_from('>Q',header,24)[0]
  crypt=struct.unpack_from('>I',header,32)[0];l1_size=struct.unpack_from('>I',header,36)[0]
  l1_offset=struct.unpack_from('>Q',header,40)[0];snapshots=struct.unpack_from('>I',header,60)[0]
  if (version not in (2,3) or backing or backing_size or not 9<=cluster_bits<=21
      or virtual!=96*1024**3 or crypt or snapshots or not 0<l1_size<=4096
      or l1_offset<104 or l1_offset+l1_size*8>a.st_size):raise ValueError('disk-provenance-changed')
  table=os.pread(fd,l1_size*8,l1_offset)
  b=os.fstat(fd);named=os.stat(DISK,follow_symlinks=False)
  keys=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
  if (len(table)!=l1_size*8 or any(getattr(a,k)!=getattr(b,k) or getattr(a,k)!=getattr(named,k) for k in keys)):
   raise ValueError('disk-provenance-changed')
  allocated=sum(bool(struct.unpack_from('>Q',table,i*8)[0]) for i in range(l1_size))
  return {'device':a.st_dev,'inode':a.st_ino,'virtualSizeBytes':virtual,
          'allocatedL1Entries':allocated,'backingFile':False,'snapshots':0}
 finally:os.close(fd)
def live_blocks(blocks):
 if not isinstance(blocks,list) or not 1<=len(blocks)<=16:raise ValueError('qmp-block-census')
 allowed={DISK,ISO,DRIVER}
 guest=read(GUEST+'/intent.json')
 allowed.add(guest['firmware']);allowed.add(GUEST+'/uefi-vars.fd')
 attached=[];writable=[]
 for block in blocks:
  if not isinstance(block,dict):raise ValueError('qmp-block-census')
  inserted=block.get('inserted')
  if inserted is None:continue
  if not isinstance(inserted,dict):raise ValueError('qmp-block-census')
  path=inserted.get('file');ro=inserted.get('ro')
  image=inserted.get('image')
  if (not isinstance(path,str) or path not in allowed or type(ro) is not bool
      or inserted.get('backing_file') or inserted.get('backing_file_depth',0)
      or (image is not None and (not isinstance(image,dict) or image.get('backing-image')))):
   raise ValueError('qmp-foreign-block')
  if path in attached:raise ValueError('qmp-duplicate-block')
  attached.append(path)
  if not ro:writable.append(path)
  if path in (ISO,DRIVER,guest['firmware']) and not ro:raise ValueError('qmp-writable-media')
 if attached.count(DISK)!=1 or writable.count(DISK)!=1 or any(path not in (DISK,GUEST+'/uefi-vars.fd') for path in writable):
  raise ValueError('qmp-install-target')
 return {'attachedBlockCount':len(attached),'writableAttached':writable}
def install_disk_proof():
 global PHASE
 owner,media,disk,previous=keyboard_source()
 prior=keyboard_status(owner,media,disk)
 if prior.get('state')!='after-observed' or prior.get('frame',{}).get('sha256')!=INSTALL_FRAME_SHA:
  raise ValueError('install-option-frame-not-sealed')
 PHASE='provenance'
 original=read(GUEST+'/optical-boot-intent.json')
 if (original.get('correlationId')!=FIRST_BLANK_CORR or original.get('owner')!=owner
     or original.get('blankDisk')!=disk):raise ValueError('blank-receipt-changed')
 current=disk_metadata()
 if ((current['device'],current['inode'],current['virtualSizeBytes'])!=
     (disk['device'],disk['inode'],disk['virtualSizeBytes'])):raise ValueError('disk-identity-changed')
 guest=read(GUEST+'/intent.json')
 firmware=guest['firmware']
 if not isinstance(firmware,str) or not firmware.startswith('/usr/share/'):
  raise ValueError('firmware-path')
 expected=[b'-name',b'vpn-control-windows-setup-20260929',b'-machine',b'q35',b'-accel',b'kvm',
           b'-cpu',b'host',b'-smp',b'4',b'-m',b'6144',
           b'-drive',('if=pflash,format=raw,readonly=on,file='+firmware).encode(),
           b'-drive',('if=pflash,format=raw,file='+GUEST+'/uefi-vars.fd').encode(),
           b'-drive',('file='+DISK+',if=virtio,format=qcow2').encode(),
           b'-drive',('file='+ISO+',media=cdrom,readonly=on').encode(),
           b'-drive',('file='+DRIVER+',media=cdrom,readonly=on').encode(),
           b'-netdev',b'user,id=net0',b'-device',b'virtio-net-pci,netdev=net0',
           b'-display',b'none',b'-vnc',b'127.0.0.1:27',b'-monitor',b'none',
           b'-qmp',('unix:'+QMP+',server=on,wait=off').encode()]
 PHASE='argv'
 pid=owner['qemuPid'];generation=owner['qemuStartTicks']
 argv=open('/proc/%d/cmdline'%pid,'rb').read().split(b'\0')
 if argv[-1:]==[b'']:argv.pop()
 if argv[1:]!=expected or ticks(pid)!=generation:raise ValueError('qemu-device-topology')
 PHASE='vars'
 vars_path=GUEST+'/uefi-vars.fd';vars_stat=os.stat(vars_path,follow_symlinks=False)
 if (not stat.S_ISREG(vars_stat.st_mode) or vars_stat.st_uid!=os.geteuid() or vars_stat.st_nlink!=1
     or stat.S_IMODE(vars_stat.st_mode)!=0o600 or vars_stat.st_size==0):raise ValueError('uefi-vars-unsafe')
 vars_held=False
 for fd in os.listdir('/proc/%d/fd'%pid):
  link=os.readlink('/proc/%d/fd/'%pid+fd)
  if link==vars_path:
   held=os.stat('/proc/%d/fd/'%pid+fd)
   vars_held=(held.st_dev,held.st_ino)==(vars_stat.st_dev,vars_stat.st_ino)
 if not vars_held:raise ValueError('uefi-vars-not-held')
 PHASE='qmp'
 sock,command=qmp_open(owner)
 try:topology=live_blocks(command('query-block'))
 finally:sock.close()
 PHASE='post'
 if claim()!=owner or disk_metadata()!=current or not same_media(media):
  raise ValueError('install-disk-proof-changed')
 return {'schemaVersion':1,'state':'ready','owner':owner,'setupFrameSha256':INSTALL_FRAME_SHA,
         'installDisk':current,'historicalBlankCorrelationId':FIRST_BLANK_CORR,
         'historicalBlankDisk':disk,'driveCount':5,'attachedBlockCount':topology['attachedBlockCount'],
         'writableAttached':topology['writableAttached'],
         'guestWritableTargets':['task-owned-blank-qcow2','task-owned-uefi-vars'],
         'otherGuestOrHostDiskWritable':False,'nativeActionAllowed':False}
try:
 print(json.dumps(install_disk_proof(),separators=(',',':')))
except Exception as error:
 allowed={'install-option-frame-not-sealed','blank-receipt-changed','disk-identity-changed',
          'disk-provenance-changed','disk-unsafe','disk-header','firmware-path',
          'qemu-device-topology','uefi-vars-unsafe','uefi-vars-not-held',
          'qmp-block-census','qmp-foreign-block','qmp-duplicate-block',
          'qmp-writable-media','qmp-install-target','install-disk-proof-changed'}
 reason=str(error) if isinstance(error,ValueError) and str(error) in allowed else type(error).__name__
 print(json.dumps({'schemaVersion':1,'state':'unknown','phase':PHASE,'reason':reason,
                   'nativeActionAllowed':False}))
'''


def _program(expected_owner: Mapping[str, int]) -> str:
    base = keyboard._program("status", KEYBOARD_CORRELATION, expected_owner)
    prefix = base.split("\ntry:\n owner,media,disk,old=keyboard_source()", 1)[0]
    if prefix == base:
        raise ValueError("Windows keyboard Next source has no fixed boundary")
    prefix = prefix.replace("SETUP_FRAME_SHA", "KEYBOARD_SETUP_FRAME_SHA")
    return (prefix + _REMOTE.replace("__INSTALL_FRAME_SHA__", repr(INSTALL_FRAME_SHA256))
            .replace("__FIRST_BLANK_CORR__", repr(boot.FIRST_CORRELATION)))


def preflight(root: str | Path, *, host: str, timeout_seconds: int = 90) -> dict[str, Any]:
    if host != boot.HOST or type(timeout_seconds) is not int or not 30 <= timeout_seconds <= 300:
        raise ValueError("Windows install disk proof needs fixed Arch host and bounded timeout")
    previous = keyboard.status(root, host=host, next_correlation_id=KEYBOARD_CORRELATION,
                               timeout_seconds=timeout_seconds)
    if (previous.get("state") != "after-observed" or previous.get("frame", {}).get("sha256") != INSTALL_FRAME_SHA256
            or not isinstance(previous.get("owner"), Mapping)):
        raise ValueError("Windows install option frame is not sealed")
    config = boot.ssh_transport.load_config(root)
    if (boot.HOST not in config.hosts
            or boot.ssh_transport.connection_host(config, boot.HOST).password is not None):
        raise ValueError("Configured Arch transport is unavailable")
    program = _program(previous["owner"])
    argv = boot.ssh_transport.build_ssh_argv(config, boot.HOST, min(timeout_seconds, 30),
                                              command=("python3", "-c", "exec(" + repr(program) + ")"))
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=timeout_seconds, check=False)
    if result.returncode != 0 or len(result.stdout) > 4096:
        raise ValueError("Windows install disk proof transport is unknown")
    value = json.loads(result.stdout)
    if (not isinstance(value, dict) or value.get("schemaVersion") != 1
            or value.get("state") not in ("ready", "unknown")
            or value.get("nativeActionAllowed") is not False):
        raise ValueError("Windows install disk proof response is invalid")
    if value["state"] == "unknown":
        if (value.get("phase") not in ("source", "provenance", "argv", "vars", "qmp", "post")
                or not isinstance(value.get("reason"), str)
                or not 1 <= len(value["reason"]) <= 64):
            raise ValueError("Windows install disk proof diagnostic is invalid")
    if value["state"] == "ready":
        if (value.get("owner") != previous["owner"]
                or value.get("setupFrameSha256") != INSTALL_FRAME_SHA256
                or not isinstance(value.get("installDisk"), dict)
                or value["installDisk"].get("device") != previous["owner"]["diskDevice"]
                or value["installDisk"].get("inode") != previous["owner"]["diskInode"]
                or value["installDisk"].get("virtualSizeBytes") != 96 * 1024**3
                or type(value["installDisk"].get("allocatedL1Entries")) is not int
                or not 0 <= value["installDisk"]["allocatedL1Entries"] <= 4096
                or value["installDisk"].get("backingFile") is not False
                or value["installDisk"].get("snapshots") != 0
                or value.get("historicalBlankCorrelationId") != boot.FIRST_CORRELATION
                or value.get("historicalBlankDisk") != {"device": previous["owner"]["diskDevice"],
                                                           "inode": previous["owner"]["diskInode"],
                                                           "virtualSizeBytes": 96 * 1024**3,
                                                           "allocatedGuestClusters": 0}
                or value.get("driveCount") != 5
                or type(value.get("attachedBlockCount")) is not int
                or not 1 <= value["attachedBlockCount"] <= 5
                or not isinstance(value.get("writableAttached"), list)
                or not all(isinstance(path, str) for path in value["writableAttached"])
                or len(set(value["writableAttached"])) != len(value["writableAttached"])
                or set(value["writableAttached"]) not in ({boot.setup.GUEST + "/disk.qcow2"},
                                                           {boot.setup.GUEST + "/disk.qcow2",
                                                            boot.setup.GUEST + "/uefi-vars.fd"})
                or value.get("guestWritableTargets") != ["task-owned-blank-qcow2", "task-owned-uefi-vars"]
                or value.get("otherGuestOrHostDiskWritable") is not False):
            raise ValueError("Windows install disk proof is incomplete")
    return {**value, "replayAllowed": False}

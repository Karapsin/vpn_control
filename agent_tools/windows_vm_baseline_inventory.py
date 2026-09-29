"""Bounded read-only inventory of Windows qcow2 candidates on the Arch host.

This never admits capture, clone, shutdown, or installer work. A source can be
labelled ``stopped-observed`` only after a complete all-process descriptor
census; an incomplete census leaves it unknown. In particular a disk used by
CP117 cannot become a baseline merely because its path exists.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
from typing import Any, Mapping

try:
    from . import ssh_transport
except ImportError:  # direct tool fallback
    import ssh_transport  # type: ignore[no-redef]


_HOST = "archlinux"
_MAX_OUTPUT = 32768
_MEDIA_PATHS = {
    "windows-x64": "/home/kardinal/vpn-control-windows-native-20260907/windows-x64.iso",
    "virtio-win": "/home/kardinal/vpn-control-windows-native-20260907/virtio-win.iso",
}

_REMOTE = r'''import json,os,stat,subprocess,sys,time
ROOT='/home/kardinal'
MAX_ENTRIES=4096
def ticks(pid):
 try:return int(open('/proc/%d/stat'%pid,encoding='ascii').read().rsplit(')',1)[1].split()[19])
 except (OSError,ValueError,IndexError):return None
def safe_file(path):
 try:
  current='/'
  for part in path.strip('/').split('/'):
   current=os.path.join(current,part)
   if stat.S_ISLNK(os.lstat(current).st_mode):return None
  info=os.stat(path,follow_symlinks=False)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.stat(ROOT).st_uid or info.st_nlink!=1:return None
  return (info.st_dev,info.st_ino,info.st_size)
 except OSError:return None
def candidates():
 found=[];count=0;complete=True
 def failed(_):
  nonlocal complete
  complete=False
 try:tops=os.listdir(ROOT)
 except OSError:return [],False
 if len(tops)>MAX_ENTRIES:return [],False
 for top in tops:
  if not any(token in top.lower() for token in ('windows','win11','win10','cp117','cp95')):continue
  start=os.path.join(ROOT,top)
  if os.path.islink(start) or not os.path.isdir(start):continue
  for base,dirs,files in os.walk(start,followlinks=False,onerror=failed):
   depth=base[len(start):].count(os.sep)
   dirs[:]=[d for d in dirs if not os.path.islink(os.path.join(base,d)) and not d.startswith('.')]
   if depth>=3:dirs[:]=[]
   count+=len(dirs)+len(files)
   if count>MAX_ENTRIES:complete=False;break
   for name in files:
    if not name.endswith('.qcow2'):continue
    path=os.path.join(base,name)
    info=safe_file(path)
    if info:found.append((path,info))
    else:complete=False
  if not complete:break
 return found,complete
def media():
 found=[];count=0;complete=True
 try:tops=os.listdir(ROOT)
 except OSError:return [],False
 if len(tops)>MAX_ENTRIES:return [],False
 for top in tops:
  if top!='Downloads' and not any(token in top.lower() for token in ('windows','win11','win10')):continue
  start=os.path.join(ROOT,top)
  if os.path.islink(start) or not os.path.isdir(start):continue
  def failed(_):
   nonlocal complete
   complete=False
  for base,dirs,files in os.walk(start,followlinks=False,onerror=failed):
   depth=base[len(start):].count(os.sep)
   dirs[:]=[d for d in dirs if not os.path.islink(os.path.join(base,d)) and not d.startswith('.')]
   if depth>=3:dirs[:]=[]
   count+=len(dirs)+len(files)
   if count>MAX_ENTRIES:complete=False;break
   for name in files:
    if not name.lower().endswith('.iso'):continue
    path=os.path.join(base,name);info=safe_file(path)
    if info:found.append({'path':path,'sizeBytes':info[2]})
    else:complete=False
  if not complete:break
 return found,complete
def qemu():
 result=[];complete=True
 try:entries=os.listdir('/proc')
 except OSError:return [],False
 for entry in entries:
  if not entry.isdigit():continue
  pid=int(entry)
  try:name=open('/proc/%d/comm'%pid,encoding='ascii').read().strip()
  except FileNotFoundError:continue
  except (OSError,UnicodeError):complete=False;continue
  if not name.startswith('qemu-system-'):continue
  before=ticks(pid)
  if before is None:complete=False;continue
  try:
   fds=[]
   for fd in os.listdir('/proc/%d/fd'%pid):
    try:info=os.stat('/proc/%d/fd/%s'%(pid,fd));fds.append((info.st_dev,info.st_ino))
    except FileNotFoundError:continue
   raw=open('/proc/%d/cmdline'%pid,'rb').read(32769)
   if not raw or len(raw)>32768:complete=False;continue
   argv=[x.decode('utf-8') for x in raw.rstrip(b'\0').split(b'\0')]
  except (OSError,UnicodeError):complete=False;continue
  if ticks(pid)!=before:complete=False;continue
  result.append((pid,before,set(fds),argv))
 return result,complete
def all_holders(inodes):
 result={key:[] for key in inodes};complete=True
 try:entries=os.listdir('/proc')
 except OSError:return result,False
 for entry in entries:
  if not entry.isdigit():continue
  pid=int(entry);before=ticks(pid)
  if before is None:
   if os.path.exists('/proc/%d'%pid):complete=False
   continue
  try:
   for fd in os.listdir('/proc/%d/fd'%pid):
    try:info=os.stat('/proc/%d/fd/%s'%(pid,fd))
    except FileNotFoundError:continue
    for key,identity in inodes.items():
     if (info.st_dev,info.st_ino)==identity:result[key].append({'pid':pid,'startTicks':before})
  except FileNotFoundError:continue
  except OSError:complete=False;continue
  if ticks(pid)!=before:complete=False
 return result,complete
def image(path):
 try:
  run=subprocess.run(('qemu-img','info','--output=json',path),stdout=subprocess.PIPE,
                     stderr=subprocess.DEVNULL,timeout=5,check=False)
  if run.returncode or len(run.stdout)>16384:return None
  value=json.loads(run.stdout)
  if not isinstance(value,dict) or value.get('format')!='qcow2':return None
  return {'format':'qcow2','backingFile':value.get('backing-filename'),
          'virtualSizeBytes':value.get('virtual-size')}
 except (OSError,subprocess.TimeoutExpired,ValueError):return None
if sys.platform!='linux':print(json.dumps({'schemaVersion':1,'host':'archlinux','error':'unsupported'}));raise SystemExit
try:
 disks,paths_complete=candidates();media_items,media_complete=media();processes,process_complete=qemu()
 images={path:image(path) for path,info in disks}
 allheld,holders_complete=all_holders({path:(dev,ino) for path,(dev,ino,size) in disks})
 items=[]
 for path,(dev,ino,size) in disks:
  holders=[{'pid':pid,'startTicks':start} for pid,start,fds,argv in processes if (dev,ino) in fds]
  argv_users=[{'pid':pid,'startTicks':start} for pid,start,fds,argv in processes if path in argv or any(a.startswith('file='+path+',') for a in argv)]
  everyone=allheld[path]
  items.append({'path':path,'sizeBytes':size,'image':images[path],'holders':holders,'argvUsers':argv_users,
                'allProcessHolders':everyone,'noQemuObserved':not holders and not argv_users,
                'sourceState':'unknown'})
 for pid,start,fds,argv in processes:
  if ticks(pid)!=start:process_complete=False
 if paths_complete and process_complete and holders_complete:
  for item in items:
   if item['image'] is not None and not item['allProcessHolders'] and not item['argvUsers']:
    item['sourceState']='stopped-observed'
 print(json.dumps({'schemaVersion':1,'host':'archlinux','observedAtUnixMs':time.time_ns()//1000000,
  'pathsComplete':paths_complete,'processesComplete':process_complete,
  'holderCensusComplete':holders_complete,'candidates':items,
  'mediaComplete':media_complete,'mediaCandidates':media_items},separators=(',',':')))
except (OSError,ValueError,UnicodeError):
 print(json.dumps({'schemaVersion':1,'host':'archlinux','error':'observer-failed'}))
'''

_MEDIA_HASH_REMOTE = r'''import hashlib,json,os,stat,time
PATHS={'windows-x64':'/home/kardinal/vpn-control-windows-native-20260907/windows-x64.iso',
       'virtio-win':'/home/kardinal/vpn-control-windows-native-20260907/virtio-win.iso'}
def one(path):
 current='/'
 for part in path.strip('/').split('/'):
  current=os.path.join(current,part)
  if stat.S_ISLNK(os.lstat(current).st_mode):raise ValueError()
 fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
 try:
  before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid() or before.st_nlink!=1:raise ValueError()
  digest=hashlib.sha256()
  while True:
   chunk=os.read(fd,1048576)
   if not chunk:break
   digest.update(chunk)
  after=os.fstat(fd);name=os.stat(path,follow_symlinks=False)
  fields=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
  stable=all(getattr(before,x)==getattr(after,x)==getattr(name,x) for x in fields)
  return {'path':path,'sizeBytes':before.st_size,'sha256':digest.hexdigest(),'stable':stable}
 finally:os.close(fd)
try:
 print(json.dumps({'schemaVersion':1,'host':'archlinux','observedAtUnixMs':time.time_ns()//1000000,
                   'media':{key:one(path) for key,path in PATHS.items()}},separators=(',',':')))
except (OSError,ValueError):
 print(json.dumps({'schemaVersion':1,'host':'archlinux','error':'media-unavailable'}))
'''


def classify(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or value.get("schemaVersion") != 1 or value.get("host") != _HOST:
        raise ValueError("Windows baseline inventory envelope is invalid")
    candidates = value.get("candidates")
    complete = (value.get("pathsComplete") is True and value.get("processesComplete") is True
                and value.get("holderCensusComplete") is True)
    if not isinstance(candidates, list) or len(candidates) > 64:
        complete = False
        candidates = []
    public = []
    for item in candidates:
        if not isinstance(item, Mapping) or set(item) != {"path", "sizeBytes", "image", "holders", "argvUsers", "allProcessHolders", "noQemuObserved", "sourceState"}:
            complete = False
            continue
        path = item["path"]
        holders = item["holders"]
        users = item["argvUsers"]
        everyone = item["allProcessHolders"]
        image = item["image"]
        if (not isinstance(path, str) or not path.startswith("/home/kardinal/")
                or type(item["sizeBytes"]) is not int or item["sizeBytes"] < 1
                or not isinstance(holders, list) or not isinstance(users, list) or not isinstance(everyone, list)
                or item["noQemuObserved"] is not (not holders and not users)
                or item["sourceState"] not in ("unknown", "stopped-observed")
                or item["sourceState"] == "stopped-observed" and
                    (value.get("holderCensusComplete") is not True or
                     value.get("processesComplete") is not True or
                     value.get("pathsComplete") is not True or everyone or users or image is None)):
            complete = False
            continue
        if (not isinstance(image, Mapping) or set(image) != {"format", "backingFile", "virtualSizeBytes"}
                or image["format"] != "qcow2"
                or image["backingFile"] is not None and not isinstance(image["backingFile"], str)
                or type(image["virtualSizeBytes"]) is not int or image["virtualSizeBytes"] < 1):
            complete = False
        for holder in holders + users + everyone:
            if (not isinstance(holder, Mapping) or set(holder) != {"pid", "startTicks"}
                    or any(type(holder[k]) is not int or holder[k] < 1 for k in ("pid", "startTicks"))):
                complete = False
        public.append(dict(item))
    media = value.get("mediaCandidates")
    media_complete = value.get("mediaComplete") is True
    if not isinstance(media, list) or len(media) > 64:
        media_complete = False
        media = []
    for item in media:
        if (not isinstance(item, Mapping) or set(item) != {"path", "sizeBytes"}
                or not isinstance(item["path"], str) or not item["path"].startswith("/home/kardinal/")
                or type(item["sizeBytes"]) is not int or item["sizeBytes"] < 1):
            media_complete = False
    media = [dict(item) for item in media if isinstance(item, Mapping)]
    return {"inventoryComplete": complete, "nativeActionAllowed": False,
            "observedAtUnixMs": value.get("observedAtUnixMs"), "candidates": public,
            "pathsComplete": value.get("pathsComplete") is True,
            "processesComplete": value.get("processesComplete") is True,
            "holderCensusComplete": value.get("holderCensusComplete") is True,
            "mediaComplete": media_complete, "mediaCandidates": media,
            "reason": "observed" if complete else "incomplete_or_conflicting_inventory"}


def observe(root: str | Path, host_alias: str, timeout_seconds: int = 20) -> dict[str, Any]:
    if host_alias != _HOST or type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 30:
        raise ValueError("Only bounded Arch Windows baseline inventory is supported")
    config = ssh_transport.load_config(root)
    target = config.hosts.get(host_alias)
    if target is None or ssh_transport.connection_host(config, host_alias).password is not None:
        raise ValueError("Configured Arch transport is unavailable")
    command = ("python3", "-c", "exec(" + repr(_REMOTE) + ")")
    argv = ssh_transport.build_ssh_argv(config, host_alias, timeout_seconds, command=command)
    try:
        completed = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   timeout=timeout_seconds + 1, check=False)
        if completed.returncode != 0 or len(completed.stdout) > _MAX_OUTPUT:
            raise ValueError("Read-only Windows baseline inventory is unavailable")
        value = json.loads(completed.stdout)
        return classify(value)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        raise ValueError("Read-only Windows baseline inventory is unavailable") from error


def media_fingerprint(root: str | Path, host_alias: str, timeout_seconds: int = 180) -> dict[str, Any]:
    """Hash only the two fixed existing media files; this does not prove publisher identity."""
    if host_alias != _HOST or type(timeout_seconds) is not int or not 30 <= timeout_seconds <= 240:
        raise ValueError("Only bounded Arch Windows media fingerprint is supported")
    config = ssh_transport.load_config(root)
    target = config.hosts.get(host_alias)
    if target is None or ssh_transport.connection_host(config, host_alias).password is not None:
        raise ValueError("Configured Arch transport is unavailable")
    command = ("python3", "-c", "exec(" + repr(_MEDIA_HASH_REMOTE) + ")")
    argv = ssh_transport.build_ssh_argv(config, host_alias, 30, command=command)
    try:
        completed = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   timeout=timeout_seconds, check=False)
        if completed.returncode != 0 or len(completed.stdout) > 4096:
            raise ValueError("Read-only Windows media fingerprint is unavailable")
        value = json.loads(completed.stdout)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        raise ValueError("Read-only Windows media fingerprint is unavailable") from error
    media = value.get("media") if isinstance(value, Mapping) else None
    if (not isinstance(value, Mapping) or value.get("schemaVersion") != 1 or value.get("host") != _HOST
            or not isinstance(media, Mapping) or set(media) != set(_MEDIA_PATHS)):
        raise ValueError("Read-only Windows media fingerprint is incomplete")
    for key, item in media.items():
        if (not isinstance(item, Mapping) or set(item) != {"path", "sizeBytes", "sha256", "stable"}
                or item["path"] != _MEDIA_PATHS[key]
                or type(item["sizeBytes"]) is not int or item["sizeBytes"] < 1
                or not isinstance(item["sha256"], str) or len(item["sha256"]) != 64
                or any(c not in "0123456789abcdef" for c in item["sha256"])
                or item["stable"] is not True):
            raise ValueError("Read-only Windows media fingerprint is unstable")
    return {"mediaFingerprintComplete": True, "nativeActionAllowed": False,
            "observedAtUnixMs": value.get("observedAtUnixMs"), "media": dict(media)}

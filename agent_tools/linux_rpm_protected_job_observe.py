"""Read-only, bounded inventory of Fedora's protected public installer jobs.

This diagnoses a blocked RPM base preflight. It never changes a protected job,
promotes an uncertain receipt to success, or admits an RPM installation.
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any, Mapping

from . import native_rpm_public_install_ssh, ssh_transport


_HOST = "fedora2328"
_HASH = re.compile(r"[0-9a-f]{16}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_PHASE = re.compile(r"[A-Z_]{1,32}\Z")
_KINDS = {"directory", "regular", "symlink", "other", "unreadable"}
_GUARDS = {"gate-linux", "reservation-linux"}
_ROOT_STATES = {"absent", "readable", "unsafe-root", "unsafe-entry", "receipt-untrusted",
                "unreadable", "changed", "entry-bound", "privilege-unavailable"}


_COMMON = r'''import hashlib,json,os,re,stat,sys,uuid
ROOT='/var/lib/vpn-control-install-jobs'
LIMIT=32
def result(state,rootState,entries=(),entryCount=0,truncated=False):
 return {'state':state,'rootState':rootState,'entries':list(entries),'entryCount':entryCount,
  'truncated':truncated,'observerUid':os.geteuid()}
def name_hash(name):return hashlib.sha256(name.encode('utf-8','surrogateescape')).hexdigest()[:16]
def kind(mode):
 if stat.S_ISDIR(mode):return 'directory'
 if stat.S_ISREG(mode):return 'regular'
 if stat.S_ISLNK(mode):return 'symlink'
 return 'other'
def canonical_job(name):
 try:return str(uuid.UUID(name))==name
 except (ValueError,TypeError,AttributeError):return False
def same(a,b):return (a.st_dev,a.st_ino,a.st_mode,a.st_uid)==(b.st_dev,b.st_ino,b.st_mode,b.st_uid)
def mounted_at(path):
 if path!=ROOT and not path.startswith(ROOT+'/'):return False
 # A bind mount may share st_dev, so compare the fixed protected root and its children
 # with kernel mount points as well as checking inode/device identity.
 with open('/proc/self/mountinfo','rb') as stream:raw=stream.read(1048577)
 if len(raw)>1048576:raise OSError('mountinfo-bound')
 for line in raw.splitlines():
  fields=line.split(b' ')
  if len(fields)<5:raise OSError('mountinfo-malformed')
  mount=re.sub(rb'\\([0-7]{3})',lambda m:bytes((int(m.group(1),8),)),fields[4])
  if mount==os.fsencode(path):return True
 return False
def open_root(root):
 if root==ROOT:
  fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
  try:
   for component in ('var','lib','vpn-control-install-jobs'):
    next_fd=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
    os.close(fd);fd=next_fd
   return fd
  except BaseException:os.close(fd);raise
 return os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
def lock_held(root,info):
 if root!=ROOT:return False
 with open('/proc/locks','rb') as stream:raw=stream.read(1048577)
 if len(raw)>1048576:raise OSError('locks-bound')
 expected=(os.major(info.st_dev),os.minor(info.st_dev),info.st_ino)
 for line in raw.splitlines():
  fields=line.split()
  locations=[part for part in fields if re.fullmatch(rb'[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9]+',part)]
  if len(locations)!=1:raise OSError('locks-malformed')
  major,minor,inode=locations[0].split(b':')
  if (int(major,16),int(minor,16),int(inode,10))==expected:return True
 return False
def guard(root_fd,name,expected_uid,expected_info):
 flags=os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW
 fd=os.open(name,flags,dir_fd=root_fd)
 try:
  before=os.fstat(fd)
  if (not same(before,expected_info) or before.st_dev!=os.fstat(root_fd).st_dev or
      not stat.S_ISREG(before.st_mode) or before.st_uid!=expected_uid or
      before.st_nlink!=1 or before.st_mode&(stat.S_IWGRP|stat.S_IWOTH)):return 'untrusted',None
  wanted=17 if name=='gate-linux' else 0
  if before.st_size!=wanted:return 'untrusted',None
  raw=os.read(fd,18)
  after=os.fstat(fd)
  if (not same(before,after) or before.st_size!=after.st_size or before.st_mtime_ns!=after.st_mtime_ns or
      before.st_ctime_ns!=after.st_ctime_ns or len(raw)!=wanted):return 'untrusted',None
  if name=='gate-linux':
   if any(value!=0 for i,value in enumerate(raw) if i!=8) or raw[8] not in (0,1):return 'untrusted',None
   return 'trusted',bool(raw[8])
  return 'trusted',None
 finally:os.close(fd)
def receipt(root_fd,root,job_id,expected_uid,expected_info,root_dev):
 if mounted_at(root+'/'+job_id+'/status.json'):return 'untrusted',None
 flags=os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0)
 fd=os.open(job_id,flags,dir_fd=root_fd)
 try:
  parent=os.fstat(fd)
  if ((parent.st_dev,parent.st_ino)!=(expected_info.st_dev,expected_info.st_ino) or
      parent.st_dev!=root_dev or not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=expected_uid or
      parent.st_mode&(stat.S_IWGRP|stat.S_IWOTH)):return 'untrusted',None
  try:leaf=os.open('status.json',os.O_RDONLY|os.O_NONBLOCK|getattr(os,'O_NOFOLLOW',0),dir_fd=fd)
  except FileNotFoundError:return 'missing',None
  try:
   before=os.fstat(leaf)
   if (before.st_dev!=root_dev or not stat.S_ISREG(before.st_mode) or before.st_uid!=expected_uid or before.st_nlink!=1 or
       before.st_mode&(stat.S_IWGRP|stat.S_IWOTH) or before.st_size>4096):return 'untrusted',None
   raw=os.read(leaf,4097)
   after=os.fstat(leaf)
   identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
   if len(raw)!=before.st_size or identity(before)!=identity(after):return 'untrusted',None
   def no_duplicates(pairs):
    value={}
    for key,item in pairs:
     if key in value:raise ValueError('duplicate-key')
     value[key]=item
    return value
   value=json.loads(raw,object_pairs_hook=no_duplicates)
   phase=value.get('phase') if isinstance(value,dict) else None
   code=value.get('code') if isinstance(value,dict) else None
   sequence=value.get('sequence') if isinstance(value,dict) else None
   phases=('PREPARING','AUTHORIZED','WAITING_FOR_EXIT','INSTALLING','SUCCEEDED','FAILED','CANCELLED')
   codes=('OK','ACCEPTED','INVALID_ARGUMENT','NOT_FOUND','AMBIGUOUS_LOCATION','READ_ONLY_SOURCE',
    'BUSY','CONFLICT','UNSUPPORTED','INTERACTION_REQUIRED','PERMISSION_DENIED','PERSISTENCE_FAILED',
    'RUNTIME_FAILED','CANCELLED','TIMEOUT','OUTCOME_UNKNOWN','UNAVAILABLE','INCOMPATIBLE_PROTOCOL')
   if (not isinstance(value,dict) or set(value)!=set(('version','jobId','sequence','phase','code')) or
       type(value.get('version')) is not int or value['version']!=1 or value.get('jobId')!=job_id or
       type(sequence) is not int or sequence<0 or sequence>100000 or phase not in phases or
       code not in codes or
       (phase=='SUCCEEDED' and code!='OK') or (phase=='CANCELLED' and code!='CANCELLED') or
       (phase=='FAILED' and code in ('OK','ACCEPTED','CANCELLED')) or
       (phase not in ('FAILED','CANCELLED') and code!='OK')):
    return 'untrusted',None
   return ('terminal' if phase in ('SUCCEEDED','FAILED','CANCELLED') else 'active'),phase
  finally:os.close(leaf)
 finally:os.close(fd)
def scan(root,expected_uid):
 if os.geteuid()!=expected_uid:return result('unknown','privilege-unavailable')
 try:before=os.lstat(root)
 except FileNotFoundError:return result('observed','absent')
 except OSError:return result('unknown','unreadable')
 if not stat.S_ISDIR(before.st_mode) or before.st_uid!=expected_uid or before.st_mode&(stat.S_IWGRP|stat.S_IWOTH):
  return result('unknown','unsafe-root')
 entries=[];unsafe=False;receipt_bad=False;truncated=False
 try:
  if mounted_at(root):return result('unknown','unsafe-root')
  root_fd=open_root(root)
  try:
   pinned=os.fstat(root_fd)
   if not same(before,pinned):return result('unknown','changed')
   if root==ROOT and pinned.st_dev!=os.stat('/var/lib').st_dev:return result('unknown','unsafe-root')
   with os.scandir(root_fd) as listing:
    for item in listing:
     if len(entries)==LIMIT:truncated=True;break
     row={'nameHash':name_hash(item.name)}
     try:info=item.stat(follow_symlinks=False)
     except OSError:
      row['kind']='unreadable';entries.append(row);unsafe=True;continue
     row['kind']=kind(info.st_mode)
     if item.name in ('reservation-linux','gate-linux'):
      row['guardName']=item.name
      try:
       if info.st_dev!=pinned.st_dev or mounted_at(root+'/'+item.name):raise OSError('mount-boundary')
       guard_state,pending=guard(root_fd,item.name,expected_uid,info)
      except OSError:guard_state,pending='untrusted',None
      row['guardState']=guard_state
      if pending is not None:row['gatePending']=pending
      if guard_state=='trusted' and item.name=='reservation-linux':
       try:row['reservationLocked']=lock_held(root,info)
       except OSError:row['guardState']='untrusted';guard_state='untrusted'
      if guard_state!='trusted':unsafe=True
     elif row['kind']!='directory' or not canonical_job(item.name) or info.st_uid!=expected_uid or info.st_dev!=pinned.st_dev or info.st_mode&(stat.S_IWGRP|stat.S_IWOTH) or mounted_at(root+'/'+item.name):
      unsafe=True
     else:
      row['jobId']=item.name
      try:receipt_state,phase=receipt(root_fd,root,item.name,expected_uid,info,pinned.st_dev)
      except (OSError,ValueError,UnicodeError):receipt_state,phase='untrusted',None
      row['receiptState']=receipt_state
      if phase is not None:row['phase']=phase
      if receipt_state=='untrusted':receipt_bad=True
     entries.append(row)
   after=os.fstat(root_fd)
   path_after=os.lstat(root)
  finally:os.close(root_fd)
 except OSError:return result('unknown','unreadable',entries,len(entries),truncated)
 entries.sort(key=lambda row:(row.get('jobId',''),row['nameHash']))
 if (before.st_dev,before.st_ino,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_mtime_ns,after.st_ctime_ns) or not same(after,path_after):
  return result('unknown','changed',entries,len(entries),truncated)
 if truncated:return result('unknown','entry-bound',entries,LIMIT+1,True)
 root_state='unsafe-entry' if unsafe else 'receipt-untrusted' if receipt_bad else 'readable'
 return result('unknown' if unsafe or receipt_bad else 'observed',root_state,entries,len(entries))
'''

_PROGRAM = _COMMON + r'''if os.geteuid()!=0:
 value=result('unknown','privilege-unavailable')
else:value=scan(ROOT,0)
print(json.dumps(value,separators=(',',':')))
'''


def _driver(root: Path):
    return native_rpm_public_install_ssh.RpmPublicInstallSshDriver(root, timeout_seconds=20)


def _validated(raw: Any) -> dict[str, Any]:
    if (not isinstance(raw, Mapping) or raw.get("observerUid") != 0 or raw.get("state") not in {"observed", "unknown"}
            or raw.get("rootState") not in _ROOT_STATES or type(raw.get("entryCount")) is not int
            or not 0 <= raw["entryCount"] <= 33 or type(raw.get("truncated")) is not bool
            or not isinstance(raw.get("entries"), list) or len(raw["entries"]) > 32
            or (raw["truncated"] and raw["entryCount"] != 33)
            or (not raw["truncated"] and raw["entryCount"] != len(raw["entries"]))):
        return {"state": "unknown", "rootState": "unreadable", "entryCount": 0,
                "entries": [], "truncated": False}
    entries = []
    for row in raw["entries"]:
        if (not isinstance(row, Mapping) or row.get("kind") not in _KINDS or
                not isinstance(row.get("nameHash"), str) or not _HASH.fullmatch(row["nameHash"])):
            return {"state": "unknown", "rootState": "unreadable", "entryCount": 0,
                    "entries": [], "truncated": False}
        entry = {"kind": row["kind"], "nameHash": row["nameHash"]}
        if "guardName" in row:
            if (row["guardName"] not in _GUARDS or
                    row.get("guardState") not in {"trusted", "untrusted"} or
                    (row["guardState"] == "trusted" and row["kind"] != "regular") or
                    ("reservationLocked" in row and (row["guardName"] != "reservation-linux" or
                                                       type(row["reservationLocked"]) is not bool)) or
                    (row["guardName"] == "reservation-linux" and row["guardState"] == "trusted" and
                     type(row.get("reservationLocked")) is not bool) or
                    ("gatePending" in row and (row["guardName"] != "gate-linux" or
                                             type(row["gatePending"]) is not bool))):
                return {"state": "unknown", "rootState": "unreadable", "entryCount": 0,
                        "entries": [], "truncated": False}
            entry.update(guardName=row["guardName"], guardState=row["guardState"])
            if "gatePending" in row:
                entry["gatePending"] = row["gatePending"]
            if "reservationLocked" in row:
                entry["reservationLocked"] = row["reservationLocked"]
        if "jobId" in row:
            if (row["kind"] != "directory" or not isinstance(row["jobId"], str) or
                    not _UUID.fullmatch(row["jobId"]) or row.get("receiptState") not in {"missing", "active", "terminal", "untrusted"}):
                return {"state": "unknown", "rootState": "unreadable", "entryCount": 0,
                        "entries": [], "truncated": False}
            entry.update(jobId=row["jobId"], receiptState=row["receiptState"])
            if "phase" in row:
                if not isinstance(row["phase"], str) or not _PHASE.fullmatch(row["phase"]):
                    return {"state": "unknown", "rootState": "unreadable", "entryCount": 0,
                            "entries": [], "truncated": False}
                entry["phase"] = row["phase"]
        entries.append(entry)
    if (raw["state"] == "observed" and raw["rootState"] not in {"absent", "readable"}) or (raw["truncated"] and raw["state"] != "unknown"):
        return {"state": "unknown", "rootState": "unreadable", "entryCount": 0,
                "entries": [], "truncated": False}
    return {"state": raw["state"], "rootState": raw["rootState"],
            "entryCount": raw["entryCount"], "entries": entries, "truncated": raw["truncated"]}


def observe(root: Path | str, request: Mapping[str, Any]) -> dict[str, Any]:
    """Inspect only Fedora's fixed protected job root through passwordless sudo."""
    if (not isinstance(request, Mapping) or set(request) != {"host", "environment"} or
            request.get("host") != _HOST or request.get("environment") != _HOST):
        raise ValueError("Protected RPM job observation requires exact Fedora guest")
    root = Path(root).resolve(strict=True)
    config = ssh_transport.load_config(root)
    host = config.hosts.get(_HOST)
    if host is None or host.user != "vpnfixture":
        return {"state": "unknown", "rootState": "unreadable", "entryCount": 0,
                "entries": [], "truncated": False, "admissionReady": False,
                "reason": "guest-config-unavailable"}
    try:
        raw = _driver(root)._remote(config, _HOST, _PROGRAM, (), privileged=True, diagnostic=True)
    except Exception:
        raw = None
    return {"host": _HOST, "environment": _HOST, "evidenceScope": "fixed-protected-job-inventory-only",
            "admissionReady": False,
            **_validated(raw)}

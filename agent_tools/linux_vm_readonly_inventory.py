"""Read-only inventory of two historical, disposable Linux package VMs.

The caller chooses no path, PID, port, command, or guest. This is an observation,
never VM or installer admission. An incomplete census stays unknown.
"""
from __future__ import annotations

import json
import inspect
import os
from pathlib import Path
import re
import shlex
import subprocess
import time
from typing import Any, Mapping

try:
    from . import native_environment, ssh_transport
except ImportError:  # pragma: no cover - direct MCP fallback
    import native_environment  # type: ignore[no-redef]
    import ssh_transport  # type: ignore[no-redef]


_MIN_DISK_BYTES = 10 << 30
_MAX_OUTPUT_BYTES = 16384
_HOST = "archlinux"


def _final_generation_stability(guests, tick_reader):
    """Recheck all guests after the last potentially slow guest probe."""
    for guest in guests.values():
        guest["generationStable"] = all(
            tick_reader(match["pid"]) == match["startTicks"]
            for match in guest["matchingQemu"]
        )

_GUEST_PROGRAM = r'''import json,os,subprocess
def ticks(pid):
 try: return int(open('/proc/%s/stat'%pid,encoding='ascii').read().rsplit(')',1)[1].split()[19])
 except (OSError,ValueError,IndexError): return None
app=0; runtime=0; complete=True
try: entries=os.listdir('/proc')
except OSError: entries=[]; complete=False
for item in entries:
 if not item.isdigit(): continue
 if int(item) in (os.getpid(),os.getppid()): continue
 before=ticks(item)
 if before is None:
  if os.path.exists('/proc/%s'%item): complete=False
  continue
 try: raw=open('/proc/%s/cmdline'%item,'rb').read(8193)
 except OSError: complete=False; continue
 if len(raw)>8192: complete=False; continue
 argv=raw.rstrip(b'\0').split(b'\0') if raw else []
 if any(b'/opt/vpn-control/' in arg for arg in argv): app+=1
 if any(b'/sing-box' in arg for arg in argv): runtime+=1
 if ticks(item)!=before: complete=False
phases=[]
try:
 base='/var/lib/vpn-control-install-jobs'
 for name in os.listdir(base) if os.path.isdir(base) else []:
  path=os.path.join(base,name,'status.json')
  try: data=json.load(open(path,encoding='utf-8'))
  except (OSError,ValueError): complete=False; continue
  phase=data.get('phase')
  if phase not in ('SUCCEEDED','FAILED','CANCELLED'): complete=False
  phases.append(phase)
except OSError: complete=False
print(json.dumps({'complete':complete,'appProcesses':app,'runtimeProcesses':runtime,
 'jobCount':len(phases),'activeJobs':sum(x not in ('SUCCEEDED','FAILED','CANCELLED') for x in phases)},separators=(',',':')))
'''

_REMOTE_PROGRAM = r'''import json,os,socket,stat,subprocess,sys,time
__FINAL_RECHECK__
SPECS={'ubuntu2307':('/home/kardinal/vpn-control-install-vm-9540bc92',2307),
       'arch2317':('/home/kardinal/vpn-control-install-vm-20260907-201b-arch',2317)}
GUEST=__GUEST_LITERAL__
def ticks(pid):
 try: return int(open('/proc/%d/stat'%pid,encoding='ascii').read().rsplit(')',1)[1].split()[19])
 except (OSError,ValueError,IndexError): return None
def safe(path,kind):
 cur='/'
 try:
  for part in path.strip('/').split('/'):
   cur=os.path.join(cur,part); mode=os.lstat(cur).st_mode
   if stat.S_ISLNK(mode): return False
  return (stat.S_ISDIR if kind=='dir' else stat.S_ISREG if kind=='file' else stat.S_ISSOCK)(mode)
 except OSError: return False
def listeners(port):
 result=[]
 for table in ('/proc/net/tcp','/proc/net/tcp6'):
  try: lines=open(table,encoding='ascii').readlines()[1:]
  except OSError: return None
  for line in lines:
   fields=line.split()
   if len(fields)<10: return None
   try: address,number=fields[1].split(':')
   except ValueError: return None
   if int(number,16)==port and fields[3]=='0A': result.append(int(fields[9]))
 return result
def qmp_socket(path):
 try: lines=open('/proc/net/unix',encoding='ascii').readlines()[1:]
 except OSError: return None
 result=[]
 for line in lines:
  fields=line.split()
  if len(fields)<7: return None
  if len(fields)>7 and fields[7]==path:
   try: result.append(int(fields[6]))
   except ValueError: return None
 return result
def guest_probe(root,port):
 key=os.path.join(root,'client-key'); known=os.path.join(root,'known-hosts')
 if not safe(key,'file') or not safe(known,'file'): return 'unknown',None
 command=['ssh','-p',str(port),'-i',key,'-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes',
          '-o','UserKnownHostsFile='+known,'-o','BatchMode=yes','-o','ConnectTimeout=3',
          'vpnfixture@127.0.0.1','sudo -n python3 -c '+__GUEST_ARG__]
 try: run=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=6,check=False)
 except (OSError,subprocess.TimeoutExpired): return 'unknown',None
 if run.returncode or len(run.stdout)>4096: return 'unknown',None
 try: data=json.loads(run.stdout)
 except (ValueError,UnicodeError): return 'unknown',None
 if set(data)!={'complete','appProcesses','runtimeProcesses','jobCount','activeJobs'} or data['complete'] is not True: return 'unknown',None
 if any(type(data[k]) is not int or data[k]<0 for k in ('appProcesses','runtimeProcesses','jobCount','activeJobs')): return 'unknown',None
 if data['activeJobs']!=0: return 'unknown',data
 return ('observed-off-no-active-jobs' if data['runtimeProcesses']==0 else 'observed-runtime-active-no-jobs'),data
if sys.platform!='linux': print(json.dumps({'schemaVersion':1,'host':'archlinux','error':'unsupported'})); raise SystemExit(0)
try:
 fs=os.statvfs('/home/kardinal'); disk=fs.f_bavail*fs.f_frsize
 entries=os.listdir('/proc'); process_complete=True; processes=[]
 for entry in entries:
  if not entry.isdigit(): continue
  pid=int(entry)
  try: name=open('/proc/%d/comm'%pid,encoding='ascii').read().strip()
  except FileNotFoundError: continue
  except (OSError,UnicodeError): process_complete=False; continue
  if not name.startswith('qemu-system-'): continue
  before=ticks(pid)
  if before is None: process_complete=False; continue
  try:
   raw=open('/proc/%d/cmdline'%pid,'rb').read(32769)
   if not raw or len(raw)>32768: process_complete=False; continue
   argv=[x.decode('utf-8') for x in raw.rstrip(b'\0').split(b'\0')]
   fdnames=os.listdir('/proc/%d/fd'%pid)
   held=set(); sockets=set()
   for fd in fdnames:
    try: info=os.stat('/proc/%d/fd/%s'%(pid,fd))
    except FileNotFoundError: continue
    held.add((info.st_dev,info.st_ino))
    try: link=os.readlink('/proc/%d/fd/%s'%(pid,fd))
    except FileNotFoundError: continue
    if link.startswith('socket:[') and link.endswith(']'):
     try: sockets.add(int(link[8:-1]))
     except ValueError: process_complete=False
  except (OSError,UnicodeError): process_complete=False; continue
  if ticks(pid)!=before: process_complete=False; continue
  processes.append((pid,before,argv,held,sockets))
 guests={}
 for label,(root,port) in SPECS.items():
  diskpath=os.path.join(root,'task.qcow2'); qmp=os.path.join(root,'qmp.sock')
  tree=safe(root,'dir')
  if tree:
   info=os.lstat(root); tree=info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o700
  disk_safe=safe(diskpath,'file') if tree else False
  diskid=None
  if disk_safe:
   info=os.stat(diskpath,follow_symlinks=False)
   disk_safe=info.st_uid==os.geteuid() and info.st_nlink==1
   if disk_safe: diskid=(info.st_dev,info.st_ino)
  matches=[]; held=[]; port_claims=[]; qmp_claims=[]
  for pid,generation,argv,fds,sockets in processes:
   joined='\0'.join(argv)
   if any(arg==diskpath or arg.startswith('file='+diskpath+',') for arg in argv):
    matches.append({'pid':pid,'startTicks':generation})
   if diskid is not None and diskid in fds: held.append(pid)
   if 'hostfwd=tcp:127.0.0.1:%d-:22'%port in joined: port_claims.append(pid)
   if 'unix:'+qmp+',server=on,wait=off' in joined: qmp_claims.append(pid)
  qmp_present=os.path.lexists(qmp)
  qmp_safe=safe(qmp,'socket') if qmp_present else True
  port_sockets=listeners(port); qmp_sockets=qmp_socket(qmp)
  port_owners=[pid for pid,_,_,_,sockets in processes if port_sockets is not None and set(port_sockets)&sockets]
  qmp_owners=[pid for pid,_,_,_,sockets in processes if qmp_sockets is not None and set(qmp_sockets)&sockets]
  count=None if port_sockets is None else len(port_sockets)
  state='running' if matches or held or qmp_present or (count or 0)>0 else 'stopped'
  probe,facts=guest_probe(root,port) if state=='running' and len(matches)==1 and held==[matches[0]['pid']] else ('not-running',None) if state=='stopped' else ('unknown',None)
  guests[label]={'state':state,'treeSafe':tree,'diskSafe':disk_safe,'diskHeldBy':held,
   'portListeners':count,'portClaimPids':port_claims,'qmpPresent':qmp_present,'qmpSafe':qmp_safe,
   'qmpClaimPids':qmp_claims,'portOwnerPids':port_owners,'qmpOwnerPids':qmp_owners,
   'socketInventoryComplete':port_sockets is not None and qmp_sockets is not None,
   'generationStable':False,'matchingQemu':matches,'guestProbe':probe,'guestFacts':facts}
 _final_generation_stability(guests,ticks)
 print(json.dumps({'schemaVersion':1,'host':'archlinux','observedAtUnixMs':time.time_ns()//1000000,
  'diskAvailableBytes':disk,'processInventoryComplete':process_complete,'portsComplete':all(x['portListeners'] is not None for x in guests.values()),
  'guests':guests},separators=(',',':')))
except (OSError,ValueError,UnicodeError) as error:
 print(json.dumps({'schemaVersion':1,'host':'archlinux','error':'observer-failed'},separators=(',',':')))
'''.replace("__FINAL_RECHECK__", inspect.getsource(_final_generation_stability)).replace(
    "__GUEST_LITERAL__", repr(_GUEST_PROGRAM)).replace(
    "__GUEST_ARG__", repr(shlex.quote("exec(" + repr(_GUEST_PROGRAM) + ")")))


def classify(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Keep any absent, ambiguous, or active evidence out of admission."""
    if not isinstance(payload, Mapping) or payload.get("schemaVersion") != 1 or payload.get("host") != _HOST:
        raise ValueError("Linux VM inventory envelope is invalid")
    guests = payload.get("guests")
    if not isinstance(guests, dict) or set(guests) != {"ubuntu2307", "arch2317"}:
        return {"inventoryComplete": False, "nativeActionAllowed": False, "reason": "incomplete_inventory"}
    complete = (payload.get("processInventoryComplete") is True and payload.get("portsComplete") is True
                and type(payload.get("diskAvailableBytes")) is int and payload["diskAvailableBytes"] >= _MIN_DISK_BYTES)
    for guest in guests.values():
        if not isinstance(guest, Mapping) or guest.get("treeSafe") is not True or guest.get("diskSafe") is not True:
            complete = False
            continue
        state = guest.get("state")
        matches = guest.get("matchingQemu")
        held = guest.get("diskHeldBy")
        port = guest.get("portListeners")
        if not isinstance(matches, list) or not isinstance(held, list) or type(port) is not int or port < 0:
            complete = False
            continue
        if (any(not isinstance(item, Mapping) or set(item) != {"pid", "startTicks"}
                or type(item.get("pid")) is not int or item["pid"] < 1
                or type(item.get("startTicks")) is not int or item["startTicks"] < 1
                for item in matches)
                or any(type(pid) is not int or pid < 1 for pid in held)):
            complete = False
            continue
        if guest.get("socketInventoryComplete") is not True or guest.get("generationStable") is not True:
            complete = False
        if state == "stopped":
            if (matches or held or port or guest.get("portClaimPids", []) != [] or guest.get("qmpClaimPids", []) != []
                    or guest.get("portOwnerPids", []) != [] or guest.get("qmpOwnerPids", []) != []
                    or guest.get("qmpPresent") is not False or guest.get("guestProbe") != "not-running"
                    or guest.get("guestFacts") is not None):
                complete = False
        elif state == "running":
            facts = guest.get("guestFacts")
            if (len(matches) != 1 or len(held) != 1 or held[0] != matches[0]["pid"]
                    or port != 1 or guest.get("qmpPresent") is not True or guest.get("qmpSafe") is not True
                    or guest.get("portClaimPids") != [matches[0]["pid"]]
                    or guest.get("qmpClaimPids") != [matches[0]["pid"]]
                    or guest.get("portOwnerPids") != [matches[0]["pid"]]
                    or guest.get("qmpOwnerPids") != [matches[0]["pid"]]
                    or guest.get("guestProbe") not in {"observed-off-no-active-jobs", "observed-runtime-active-no-jobs"}
                    or not isinstance(facts, Mapping) or facts.get("complete") is not True
                    or any(type(facts.get(key)) is not int or facts[key] < 0 for key in
                           ("appProcesses", "runtimeProcesses", "jobCount", "activeJobs"))
                    or facts.get("activeJobs") != 0):
                complete = False
        else:
            complete = False
    return {"inventoryComplete": complete, "nativeActionAllowed": False,
            "reason": "observed" if complete else "incomplete_or_conflicting_inventory",
            "observedAtUnixMs": payload.get("observedAtUnixMs"),
            "diskAvailableBytes": payload.get("diskAvailableBytes"), "guests": guests}


def _run_fixed(root: str | Path, host_alias: str, timeout_seconds: int) -> bytes:
    config = ssh_transport.load_config(root)
    target = config.hosts.get(host_alias)
    if target is None or ssh_transport.connection_host(config, host_alias).password is not None:
        raise ValueError("Configured read-only Arch transport is unavailable")
    command = ("python3", "-c", "exec(" + repr(_REMOTE_PROGRAM) + ")")
    argv = ssh_transport.build_ssh_argv(config, host_alias, timeout_seconds, command=command)
    completed = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               timeout=timeout_seconds + 1, check=False)
    if completed.returncode != 0 or len(completed.stdout) > _MAX_OUTPUT_BYTES:
        raise ValueError("Read-only Linux VM inventory is unavailable")
    return completed.stdout


def _reservations(root: str | Path) -> dict[str, int]:
    """Read the existing private journal without creating a lock or changing it."""
    directory, path = native_environment._root_paths(root)
    native_environment._require_private(directory, directory=True)
    state = native_environment._load(path)
    records = state["reservations"]
    if any(not isinstance(item, Mapping) or item.get("hostAlias") is None or
           item.get("allocationState") not in {"pending", "running"} or
           type(item.get("requestedMemoryBytes")) is not int or item["requestedMemoryBytes"] < 1
           for item in records):
        raise ValueError("Reservation journal is incomplete")
    selected = [item for item in records if item["hostAlias"] == _HOST]
    return {"pendingCount": sum(item["allocationState"] == "pending" for item in selected),
            "runningCount": sum(item["allocationState"] == "running" for item in selected),
            "reservedMemoryBytes": sum(item["requestedMemoryBytes"] for item in selected)}


def observe(root: str | Path, host_alias: str, timeout_seconds: int = 20) -> dict[str, Any]:
    if host_alias != _HOST or type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 30:
        raise ValueError("Only bounded Arch Linux VM inventory is supported")
    try:
        raw = _run_fixed(root, host_alias, timeout_seconds)
        payload = json.loads(raw)
        if not isinstance(payload, dict) or len(raw) > _MAX_OUTPUT_BYTES:
            raise ValueError("Inventory output is invalid")
        result = classify(payload)
        result["reservations"] = _reservations(root)
        return result
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired):
        return {"inventoryComplete": False, "nativeActionAllowed": False,
                "reason": "observer_unavailable", "observedAtUnixMs": time.time_ns() // 1_000_000}

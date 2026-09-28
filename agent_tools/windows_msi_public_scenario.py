"""Bounded observation of one Windows protected pre-install job.

This is deliberately read-only. A separate durable native scenario must submit
the public update; an unknown or terminal job is never replayed here.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
from typing import Any
import uuid

try:
    from . import ssh_transport, windows_credential_probe_ssh
except ImportError:  # pragma: no cover - CLI fallback
    import ssh_transport  # type: ignore[no-redef]
    import windows_credential_probe_ssh  # type: ignore[no-redef]


_JOB = re.compile(r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$")
_CODE = re.compile(r"^[A-Z_]{1,40}$")
_PHASES = {"Preparing", "Authorized", "WaitingForExit", "Installing", "Succeeded", "Failed", "Cancelled"}
_STAGES = {"EXCLUSIVE_ADMISSION", "INVENTORY", "READINESS"}
_KINDS = {"OTHER", "WIN32_API", "IDENTITY"}


class WindowsMsiPreinstallStatusError(ValueError):
    pass


# The remote code accepts only a configured socket, process generation, and
# validated UUID. It can issue only QGA read commands against two fixed leaves.
_REMOTE_OBSERVE = r'''import base64,json,os,secrets,socket,stat,sys,time
sock,pid,ticks,job=sys.argv[1:]
def out(v): print(json.dumps(v,separators=(",",":"),sort_keys=True))
def live():
 s=os.lstat(sock)
 if not stat.S_ISSOCK(s.st_mode): return False
 raw=open('/proc/%s/stat'%pid,'rb').read().split()
 if len(raw)<22 or raw[21].decode()!=ticks: return False
 inodes=set()
 for name in os.listdir('/proc/%s/fd'%pid):
  try:
   link=os.readlink('/proc/%s/fd/%s'%(pid,name))
   if link.startswith('socket:[') and link.endswith(']'): inodes.add(link[8:-1].encode())
  except OSError: pass
 for line in open('/proc/net/unix','rb'):
  fields=line.split()
  if len(fields)==8 and fields[6] in inodes and fields[7]==os.fsencode(sock): return True
 return False
def exchange(command,args):
 c=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); c.settimeout(5)
 try:
  c.connect(sock); sid=secrets.randbits(63)
  c.sendall(b'\xff'+json.dumps({'execute':'guest-sync-delimited','arguments':{'id':sid}},separators=(',',':')).encode()+b'\n')
  seen=0
  while True:
   byte=c.recv(1); seen+=1
   if not byte or seen>8192: raise ValueError()
   if byte==b'\xff': break
  def line():
   raw=bytearray()
   while len(raw)<8192:
    x=c.recv(1)
    if not x: raise ValueError()
    if x==b'\n': return json.loads(raw)
    raw.extend(x)
   raise ValueError()
  if line().get('return')!=sid: raise ValueError()
  c.sendall(json.dumps({'execute':command,'arguments':args},separators=(',',':')).encode()+b'\n')
  return line()
 finally: c.close()
def read_leaf(leaf):
 path='C:\\ProgramData\\vpn-control-install-jobs\\'+job+'\\'+leaf
 opened=exchange('guest-file-open',{'path':path,'mode':'rb'})
 if 'return' not in opened: return None
 handle=opened['return']
 try:
  raw=bytearray()
  for attempt in range(16):
   response=exchange('guest-file-read',{'handle':handle,'count':4096-len(raw)})
   if 'return' not in response: raise ValueError()
   value=response['return']; part=base64.b64decode(value['buf-b64'],validate=True)
   if len(part)>4096-len(raw) or value.get('count')!=len(part): raise ValueError()
   raw.extend(part)
   if value.get('eof') is True or not part: return json.loads(raw)
   if len(raw)==4096: raise ValueError()
  raise ValueError()
 finally: exchange('guest-file-close',{'handle':handle})
stage='binding'
try:
 if not live(): out({'state':'unknown','reason':'guest-binding'}); raise SystemExit(0)
 stage='status'
 status=read_leaf('status.json')
 if status is None: out({'state':'unknown','reason':'status-unavailable'}); raise SystemExit(0)
 stage='diagnostic'
 diagnostic=read_leaf('preinstall-diagnostic.json')
 out({'state':'observed','status':status,'diagnostic':diagnostic})
except Exception: out({'state':'unknown','reason':stage+'-unavailable'})
'''


def _parse(raw: bytes | None, job_id: str) -> dict[str, Any]:
    if raw is None or len(raw) > 8192:
        return {"state": "unknown", "jobId": job_id}
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"state": "unknown", "jobId": job_id}
    if not isinstance(value, dict) or value.get("state") != "observed":
        return {"state": "unknown", "jobId": job_id}
    status, diagnostic = value.get("status"), value.get("diagnostic")
    if (not isinstance(status, dict) or status.get("version") != 1 or status.get("jobId") != job_id
            or type(status.get("sequence")) is not int or status["sequence"] < 0
            or status.get("phase") not in _PHASES or not isinstance(status.get("code"), str)
            or not _CODE.fullmatch(status["code"])):
        return {"state": "unknown", "jobId": job_id}
    result: dict[str, Any] = {"state": "observed", "jobId": job_id, "phase": status["phase"],
                              "code": status["code"], "sequence": status["sequence"]}
    if diagnostic is None:
        result["diagnostic"] = "absent-or-unreadable"
    elif (isinstance(diagnostic, dict) and set(diagnostic) == {"version", "stage", "kind"}
          and diagnostic["version"] == 1 and diagnostic["stage"] in _STAGES
          and diagnostic["kind"] in _KINDS):
        result["diagnostic"] = {"stage": diagnostic["stage"], "kind": diagnostic["kind"]}
    else:
        return {"state": "unknown", "jobId": job_id}
    return result


def preinstall_status(root: Path | str, host: str, job_id: str, timeout_seconds: int = 15) -> dict[str, Any]:
    """Read fixed enum diagnostic and exact protected receipt for one job."""
    if not isinstance(job_id, str) or not _JOB.fullmatch(job_id):
        raise WindowsMsiPreinstallStatusError("Protected job ID must be a canonical lowercase UUID.")
    uuid.UUID(job_id)
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 30:
        raise WindowsMsiPreinstallStatusError("Observation timeout must be 1 through 30 seconds.")
    try:
        config = ssh_transport.load_config(root)
        target = config.hosts[host]
        environment, socket, pid, ticks, _, _, _ = windows_credential_probe_ssh._descriptor(target)
        if host != "archlinux" or environment != "windows-cp117":
            raise WindowsMsiPreinstallStatusError("Windows MSI observer is bound to the owned CP117 guest.")
        command = windows_credential_probe_ssh._remote_command(_REMOTE_OBSERVE, socket, str(pid), str(ticks), job_id)
        argv = ssh_transport.build_ssh_argv(config, host, timeout_seconds, command=command)
        completed = subprocess.run(argv, capture_output=True, timeout=timeout_seconds + 1, check=False)
        raw = completed.stdout if completed.returncode == 0 else None
    except (KeyError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise WindowsMsiPreinstallStatusError("Configured Windows guest observation is unavailable.") from error
    return _parse(raw, job_id)

"""One-shot public quit of the exact approved, disconnected Fedora fixture owner.

The local and guest intents precede the public command. An uncertain result is
observed by correlation; neither start nor status ever retries the quit.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import uuid
from typing import Any, Mapping

from . import native_rpm_public_install_ssh, ssh_transport


APPROVAL = "explicit-user-approved-disposable-owner-quit"
_HOST = "fedora2328"
_GROUP = "linux-owner-public-quit"
_APPROVED_PID = 18367
_APPROVED_TICKS = 2078693
_APPROVED_CONTROLLER = "1780cc81-65a6-4284-a424-2178b94e2690"


class LinuxOwnerPublicQuitError(ValueError):
    pass


_COMMON = r'''import json,os,pwd,stat,subprocess,sys,time
ACCOUNT='vpnfixture';LAUNCHER='/opt/vpn-control/bin/vpn-control'
APPROVAL='explicit-user-approved-disposable-owner-quit'
APPROVED_PID=18367;APPROVED_TICKS=2078693;APPROVED_CONTROLLER='1780cc81-65a6-4284-a424-2178b94e2690'
def output(state,reason=None,**fields):
 value={'state':state,**fields}
 if reason is not None:value['reason']=reason
 print(json.dumps(value,separators=(',',':')))
def generation(pid):
 try:
  parts=open('/proc/%d/stat'%pid,encoding='ascii').read().rsplit(')',1)[1].split()
  return (parts[0],int(parts[19]))
 except FileNotFoundError:
  try:os.stat('/proc/%d'%pid)
  except FileNotFoundError:return 'missing'
  except OSError:return 'unknown'
  return 'unknown'
 except (OSError,ValueError,IndexError):return 'unknown'
def same_owner(intent):
 observed=generation(intent['pid'])
 if observed=='unknown':return None
 if observed=='missing':return False
 return observed[1]==intent['startTicks']
def public_status(intent):
 if intent.get('approval')!=APPROVAL:return None,'approval-unavailable'
 if (intent.get('pid')!=APPROVED_PID or intent.get('startTicks')!=APPROVED_TICKS or
     intent.get('controllerId')!=APPROVED_CONTROLLER):return None,'approval-owner-mismatch'
 if os.geteuid()!=pwd.getpwnam(ACCOUNT).pw_uid:return None,'wrong-guest-user'
 if same_owner(intent) is not True:return None,'owner-generation-changed'
 try:
  raw=open('/proc/%d/cmdline'%intent['pid'],'rb').read(8193)
  if not raw or len(raw)>8192:return None,'owner-command-unavailable'
  argv=[part.decode('utf-8') for part in raw.split(b'\0') if part]
  if not argv or os.path.realpath(argv[0])!=LAUNCHER:return None,'owner-launcher-mismatch'
  positions=[n for n,part in enumerate(argv) if part=='--state-dir']
  if len(positions)!=1 or positions[0]+1>=len(argv):return None,'state-directory-unavailable'
  workspace=argv[positions[0]+1]
  if not os.path.isabs(workspace) or '..' in workspace.split('/') or '\x00' in workspace:return None,'state-directory-unsafe'
  if not any(part in ('serve','--headless-controller') for part in argv):return None,'owner-role-mismatch'
  args=[LAUNCHER,'--state-dir',workspace,'--json','--controller-id',intent['controllerId'],'status']
  response=subprocess.run(args,capture_output=True,text=True,timeout=15)
  if response.returncode!=0 or len(response.stdout)>65536:return None,'public-status-unavailable'
  value=json.loads(response.stdout)
  data=value.get('data')
  if (value.get('ok') is not True or value.get('final') is not True or value.get('code')!='OK'
      or value.get('controllerId')!=intent['controllerId'] or not isinstance(data,dict)):
   return None,'public-status-invalid'
  if data.get('runtimeRunning') is not False or data.get('runtimeId') is not None or data.get('activeLocationId') is not None or data.get('activeMode') is not None:
   return None,'active-runtime'
  if same_owner(intent) is not True:return None,'owner-generation-changed'
  return workspace,None
 except Exception:return None,'owner-observation-unavailable'
def directory(create):
 account=pwd.getpwnam(ACCOUNT);home=account.pw_dir
 info=os.lstat(home)
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=account.pw_uid or info.st_mode & (stat.S_IWGRP|stat.S_IWOTH):raise ValueError('unsafe-home')
 root=os.path.join(home,'.vpn-control-agent-owner-quit')
 if create:
  try:os.mkdir(root,0o700)
  except FileExistsError:pass
 try:info=os.lstat(root)
 except FileNotFoundError:return None
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=account.pw_uid or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('unsafe-job-root')
 return root
def record(path,value):
 data=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
 fd=os.open(os.path.dirname(path),os.O_RDONLY)
 try:os.fsync(fd)
 finally:os.close(fd)
def read(path):
 fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 with os.fdopen(fd,'rb') as stream:
  info=os.fstat(stream.fileno())
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>4096:raise ValueError('unsafe-record')
  return json.loads(stream.read())
'''

_PREFLIGHT = _COMMON + r'''intent=json.loads(sys.argv[1])
workspace,reason=public_status(intent)
if reason:output('blocked' if reason=='active-runtime' else 'unknown',reason)
else:output('ready',pid=intent['pid'],startTicks=intent['startTicks'],controllerId=intent['controllerId'])
'''

_SUBMIT = _COMMON + r'''intent=json.loads(sys.argv[1])
workspace,reason=public_status(intent)
if reason:output('blocked' if reason=='active-runtime' else 'unknown',reason);raise SystemExit(0)
try:
 root=directory(True);job=os.path.join(root,intent['correlationId']);os.mkdir(job,0o700)
 record(os.path.join(job,'intent.json'),intent)
except FileExistsError:output('unknown','correlation-exists');raise SystemExit(0)
except Exception:output('unknown','guest-intent-unavailable');raise SystemExit(0)
# The durable intent may take time to sync; check the owner and runtime again
# immediately before the public command, and record a no-effect block on drift.
workspace,reason=public_status(intent)
if reason:
 try:record(os.path.join(job,'receipt.json'),{'correlationId':intent['correlationId'],
  'pid':intent['pid'],'startTicks':intent['startTicks'],'controllerId':intent['controllerId'],
  'exitCode':None,'publicAccepted':False,'blockedReason':reason})
 except Exception:output('unknown','guest-receipt-unavailable');raise SystemExit(0)
 output('blocked',reason,correlationId=intent['correlationId']);raise SystemExit(0)
# This is the only effect. The owner and controller are pinned by public_status,
# and the public client will not bootstrap an absent owner for quit.
try:
 response=subprocess.run([LAUNCHER,'--state-dir',workspace,'--json','--controller-id',intent['controllerId'],'quit'],
  capture_output=True,text=True,timeout=30)
 code=response.returncode
 value=json.loads(response.stdout) if len(response.stdout)<=65536 else None
 accepted=(code==0 and isinstance(value,dict) and value.get('ok') is True and
  value.get('final') is True and value.get('code')=='OK' and value.get('controllerId')==intent['controllerId'])
except Exception:
 code=None;accepted=False
try:record(os.path.join(job,'receipt.json'),{'correlationId':intent['correlationId'],
 'pid':intent['pid'],'startTicks':intent['startTicks'],'controllerId':intent['controllerId'],
 'exitCode':code,'publicAccepted':accepted})
except Exception:output('unknown','guest-receipt-unavailable');raise SystemExit(0)
output('submitted',correlationId=intent['correlationId'])
'''

_STATUS = _COMMON + r'''intent=json.loads(sys.argv[1])
try:
 root=directory(False)
 if root is None:raise ValueError('missing-root')
 job=os.path.join(root,intent['correlationId']);info=os.lstat(job)
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('unsafe-job')
 if read(os.path.join(job,'intent.json'))!=intent:raise ValueError('intent-mismatch')
 receipt=read(os.path.join(job,'receipt.json'))
 if (receipt.get('correlationId')!=intent['correlationId'] or receipt.get('pid')!=intent['pid']
  or receipt.get('startTicks')!=intent['startTicks'] or receipt.get('controllerId')!=intent['controllerId']):raise ValueError('receipt-mismatch')
 if (receipt.get('blockedReason') in ('active-runtime','owner-generation-changed','public-status-unavailable',
      'public-status-invalid','owner-observation-unavailable','owner-command-unavailable','owner-launcher-mismatch',
      'state-directory-unavailable','state-directory-unsafe','owner-role-mismatch','wrong-guest-user',
      'approval-unavailable','approval-owner-mismatch') and receipt.get('publicAccepted') is False and receipt.get('exitCode') is None):
  output('blocked',receipt['blockedReason'],correlationId=intent['correlationId'])
 elif type(receipt.get('exitCode')) is not int or receipt.get('publicAccepted') is not True:
  output('failed',correlationId=intent['correlationId'],exitCode=receipt.get('exitCode'))
 else:
  owner=same_owner(intent)
  if owner is None:output('unknown','owner-generation-unreadable',correlationId=intent['correlationId'])
  elif owner:output('pending',correlationId=intent['correlationId'],reason='owner-still-exiting')
  else:output('terminal',correlationId=intent['correlationId'],result='passed',exitCode=0,
   ownerGenerationGone=True,pid=intent['pid'],startTicks=intent['startTicks'],controllerId=intent['controllerId'])
except FileNotFoundError:output('unknown','guest-receipt-missing',correlationId=intent['correlationId'])
except Exception:output('unknown','guest-status-unavailable',correlationId=intent['correlationId'])
'''


def _request(value: Mapping[str, Any]) -> dict[str, Any]:
    fields = {"host", "environment", "pid", "startTicks", "controllerId", "approval", "correlationId"}
    if (not isinstance(value, Mapping) or set(value) != fields or value.get("host") != _HOST or
            value.get("environment") != _HOST or type(value.get("pid")) is not int or value["pid"] != _APPROVED_PID or
            type(value.get("startTicks")) is not int or value["startTicks"] != _APPROVED_TICKS or
            not isinstance(value.get("controllerId"), str) or not 0 < len(value["controllerId"]) <= 128 or
            value["controllerId"] != _APPROVED_CONTROLLER or
            value.get("approval") != APPROVAL):
        raise LinuxOwnerPublicQuitError("Exact approved Fedora owner identity is required")
    try:
        if str(uuid.UUID(value["controllerId"])) != value["controllerId"]:
            raise ValueError()
        if str(uuid.UUID(value["correlationId"])) != value["correlationId"]:
            raise ValueError()
    except (ValueError, TypeError, AttributeError) as error:
        raise LinuxOwnerPublicQuitError("Invalid owner or correlation identity") from error
    return dict(value)


def _correlation(value: Mapping[str, Any]) -> str:
    if not isinstance(value, Mapping) or set(value) != {"correlationId"}:
        raise LinuxOwnerPublicQuitError("Status requires correlationId only")
    try:
        correlation = value["correlationId"]
        if str(uuid.UUID(correlation)) != correlation:
            raise ValueError()
        return correlation
    except (ValueError, TypeError, AttributeError) as error:
        raise LinuxOwnerPublicQuitError("Invalid correlationId") from error


def _journal(root: Path, correlation: str, create=False) -> Path | None:
    directory = root / ".rag_index" / _GROUP
    if create:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not directory.exists():
        return None
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise LinuxOwnerPublicQuitError("Owner quit journal is unsafe")
    return directory / (correlation + ".json")


def _write(path: Path, value: Mapping[str, Any]) -> None:
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _read(path: Path) -> dict[str, Any]:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 4096):
            raise LinuxOwnerPublicQuitError("Owner quit journal is unsafe")
        return _request(json.loads(stream.read()))


def _driver(root: Path):
    return native_rpm_public_install_ssh.RpmPublicInstallSshDriver(root, timeout_seconds=60)


def _config(root: Path):
    config = ssh_transport.load_config(root)
    host = config.hosts.get(_HOST)
    if host is None or host.user != "vpnfixture":
        raise LinuxOwnerPublicQuitError("Fedora fixture account is not configured")
    return config


def _unknown(correlation: str, reason: str) -> dict[str, Any]:
    return {"state": "unknown", "correlationId": correlation, "reason": reason, "replayAllowed": False}


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Submit once after a fresh guest-side runtime-off observation."""
    request = _request(value)
    root = Path(root).resolve(strict=True)
    path = _journal(root, request["correlationId"])
    if path is not None and (path.exists() or path.is_symlink()):
        if _read(path) != request:
            raise LinuxOwnerPublicQuitError("Correlation already binds another owner")
        return _unknown(request["correlationId"], "existing-intent")
    config = _config(root)
    driver = _driver(root)
    argument = json.dumps(request, sort_keys=True, separators=(",", ":"))
    observed = driver._remote(config, _HOST, _PREFLIGHT, (argument,), diagnostic=True)
    if not isinstance(observed, Mapping) or observed.get("state") != "ready":
        return {"state": "blocked" if isinstance(observed, Mapping) and observed.get("state") == "blocked" else "unknown",
                "correlationId": request["correlationId"],
                "reason": observed.get("reason", "owner-preflight-unavailable") if isinstance(observed, Mapping) else "owner-preflight-unavailable",
                "replayAllowed": False}
    if (observed.get("pid") != request["pid"] or observed.get("startTicks") != request["startTicks"] or
            observed.get("controllerId") != request["controllerId"]):
        return _unknown(request["correlationId"], "owner-preflight-mismatch")
    path = _journal(root, request["correlationId"], create=True)
    try:
        _write(path, request)
    except FileExistsError as error:
        raise LinuxOwnerPublicQuitError("Correlation intent already exists") from error
    try:
        submitted = driver._remote(config, _HOST, _SUBMIT, (argument,), diagnostic=True)
    except Exception:
        return _unknown(request["correlationId"], "quit-response-uncertain")
    if isinstance(submitted, Mapping) and submitted.get("state") == "blocked" and submitted.get("correlationId") == request["correlationId"]:
        return {"state": "blocked", "correlationId": request["correlationId"],
                "reason": submitted.get("reason", "owner-drift"), "replayAllowed": False}
    if not isinstance(submitted, Mapping) or submitted.get("state") != "submitted" or submitted.get("correlationId") != request["correlationId"]:
        return _unknown(request["correlationId"], "quit-response-uncertain")
    return {"state": "submitted", "correlationId": request["correlationId"], "replayAllowed": False}


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read the original guest receipt and exact process generation, never submit."""
    correlation = _correlation(value)
    root = Path(root).resolve(strict=True)
    path = _journal(root, correlation)
    if path is None or not path.exists():
        return _unknown(correlation, "missing-intent")
    request = _read(path)
    try:
        observed = _driver(root)._remote(_config(root), _HOST, _STATUS,
                                         (json.dumps(request, sort_keys=True, separators=(",", ":")),), diagnostic=True)
    except Exception:
        return _unknown(correlation, "guest-status-unavailable")
    if not isinstance(observed, Mapping) or observed.get("correlationId") != correlation:
        return _unknown(correlation, "guest-status-invalid")
    state = observed.get("state")
    if state == "terminal" and (observed.get("result") == "passed" and observed.get("exitCode") == 0 and
                                observed.get("ownerGenerationGone") is True and observed.get("pid") == request["pid"] and
                                observed.get("startTicks") == request["startTicks"] and
                                observed.get("controllerId") == request["controllerId"]):
        return {"state": "terminal", "result": "passed", "correlationId": correlation,
                "pid": request["pid"], "startTicks": request["startTicks"],
                "controllerId": request["controllerId"], "exitCode": 0,
                "ownerGenerationGone": True, "replayAllowed": False}
    if state in {"pending", "failed", "blocked"}:
        return {"state": state, "correlationId": correlation,
                "reason": observed.get("reason", "public-quit-not-complete"), "replayAllowed": False}
    return _unknown(correlation, "guest-status-invalid")


def collect(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Return a verified terminal observation only; no native effect."""
    return status(root, value)

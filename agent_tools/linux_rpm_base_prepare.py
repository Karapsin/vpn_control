"""Journaled, fixed preparation of one source-matched RPM base on Fedora2328.

This is a disposable-guest action. It never stops an owner, VPN, package manager,
or installer. An active or unreadable process blocks submission.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
from typing import Any, Mapping

from . import native_artifact_registry, native_rpm_public_install_ssh, ssh_transport
from scripts.version_metadata import parse_version


_SHA = re.compile(r"[0-9a-f]{40}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ARTIFACT = re.compile(r"sha256-[0-9a-f]{64}\Z")
_NEVRA = re.compile(r"vpn-control-[0-9]+\.[0-9]+\.[0-9]+-1\.x86_64\Z")
_ROOT = "/var/lib/vpn-control-rpm-base-prep"
_MAX_RPM = 1024 * 1024 * 1024


class LinuxRpmBasePrepareError(ValueError):
    pass


_COMMON = r'''import hashlib,json,os,pwd,stat,subprocess,sys,time
ROOT='/var/lib/vpn-control-rpm-base-prep'
FMT='%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}'
def result(state,reason=None,**extra):
 value={'state':state,**extra}
 if reason is not None:value['reason']=reason
 return value
def nevra(args):
 p=subprocess.run(args,capture_output=True,text=True,timeout=30)
 return p.stdout.strip() if p.returncode==0 and not p.stderr else None
def inspect(expected):
 if os.geteuid()!=0:return result('unknown','privilege-unavailable')
 try: uid=pwd.getpwnam('vpnfixture').pw_uid
 except KeyError:return result('unknown','fixture-account-missing')
 if uid<=0:return result('unknown','fixture-account-invalid')
 current=nevra(['rpm','-q','--qf',FMT,'vpn-control'])
 if current!=expected:return result('blocked','current-nevra-mismatch',currentNevra=current)
 try:
  entries=[p for p in os.scandir('/proc') if p.name.isdecimal()]
  if len(entries)>4096:return result('unknown','process-bound')
  active=[];active_total=0
  for entry in entries:
   if int(entry.name)==os.getpid():continue
   try:
    lines=open(entry.path+'/status',encoding='ascii').read().splitlines()
    row=[line.split()[1:] for line in lines if line.startswith('Uid:')]
    if len(row)!=1 or len(row[0])!=4:return result('unknown','process-uid-unreadable')
    uids={int(value) for value in row[0]}
    target_user=uid in uids
    if not target_user and 0 not in uids:continue
    raw=open(entry.path+'/cmdline','rb').read(65537)
    if len(raw)>65536:return result('unknown','process-command-bound')
   except FileNotFoundError:
    if not os.path.exists(entry.path):continue
    return result('unknown','process-changed')
   except (OSError,ValueError):return result('unknown','process-unreadable')
   argv=[word.decode('utf-8','replace') for word in raw.split(b'\0') if word]
   if not argv:continue
   executable=os.path.basename(argv[0])
   if executable in ('vpn-control','sing-box','rpm','dnf','dnf5','packagekitd') or (target_user and executable in ('java','javaw') and any(
      part.startswith('/opt/vpn-control/') or 'com.kardinal.vpncontrol' in part for part in argv)):
    try: ticks=int(open(entry.path+'/stat',encoding='ascii').read().rsplit(')',1)[1].split()[19])
    except (OSError,ValueError,IndexError):return result('unknown','active-process-identity-unreadable')
    if ticks<=0:return result('unknown','active-process-identity-invalid')
    active_total+=1
    if len(active)<8:active.append({'pid':int(entry.name),'startTicks':ticks,'executable':executable})
  if active_total:return result('blocked','active-runtime',activeProcessCount=active_total,activeProcesses=active)
  protected='/var/lib/vpn-control-install-jobs'
  if os.path.lexists(protected):
   info=os.stat(protected,follow_symlinks=False)
   if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0:return result('unknown','protected-job-root-unsafe')
   for entry in os.scandir(protected):
    if not entry.is_dir(follow_symlinks=False):return result('unknown','protected-job-unsafe')
    path=entry.path+'/status.json'
    if not os.path.isfile(path):return result('blocked','pending-installer')
    value=json.load(open(path,encoding='utf-8'))
    if value.get('phase') not in ('SUCCEEDED','FAILED','CANCELLED'):return result('blocked','pending-installer')
 except (OSError,ValueError,KeyError):return result('unknown','guest-observation-unavailable')
 return result('ready',currentNevra=current)
def durable(path,value):
 tmp=path+'.tmp'; fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'wb') as stream:
  stream.write((json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode());stream.flush();os.fsync(stream.fileno())
 os.replace(tmp,path); fd=os.open(os.path.dirname(path),os.O_RDONLY);os.fsync(fd);os.close(fd)
'''

_PREFLIGHT = _COMMON + r'''expected=sys.argv[1]
try: observed=inspect(expected)
except Exception as error: observed=result('unknown','observer-exception-'+type(error).__name__)
print(json.dumps(observed,separators=(',',':')))
'''

_WORKER = _COMMON + r'''job=sys.argv[1]
intent=json.load(open(job+'/intent.json',encoding='utf-8'))
while not os.path.exists(job+'/release'):time.sleep(.02)
pre=inspect(intent['expectedCurrentNevra'])
if pre.get('state')!='ready':
 durable(job+'/receipt.json',{'state':'blocked','correlationId':intent['correlationId'],'reason':pre.get('reason','preflight-unknown')})
 raise SystemExit(1)
with open(job+'/rpm.stdout','xb') as out,open(job+'/rpm.stderr','xb') as err:
 command=subprocess.run(['rpm','-Uvh','--',job+'/base.rpm'],stdout=out,stderr=err)
current=nevra(['rpm','-q','--qf',FMT,'vpn-control'])
verify=subprocess.run(['rpm','-V','vpn-control'],capture_output=True,timeout=30) if current==intent['expectedBaseNevra'] else None
passed=(command.returncode==0 and current==intent['expectedBaseNevra'] and verify is not None
 and verify.returncode==0 and not verify.stdout and not verify.stderr)
durable(job+'/receipt.json',{'state':'terminal','correlationId':intent['correlationId'],
 'sourceSha':intent['sourceSha'],'baseArtifactId':intent['baseArtifactId'],
 'expectedBaseNevra':intent['expectedBaseNevra'],'observedNevra':current,
 'exitCode':command.returncode,'rpmVerifyClean':bool(passed),'result':'passed' if passed else 'failed'})
'''

_SUBMIT = _COMMON + r'''metadata,size,digest=sys.argv[1:]
intent=json.loads(metadata);size=int(size)
pre=inspect(intent['expectedCurrentNevra'])
if pre.get('state')!='ready':print(json.dumps(pre,separators=(',',':')));raise SystemExit(0)
if not 0<size<=1073741824 or digest!=intent['baseArtifactId'].removeprefix('sha256-'):
 print(json.dumps(result('unknown','payload-identity-invalid'),separators=(',',':')));raise SystemExit(0)
os.umask(0o077)
os.makedirs(ROOT,mode=0o700,exist_ok=True)
info=os.stat(ROOT,follow_symlinks=False)
if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:
 print(json.dumps(result('unknown','job-root-unsafe'),separators=(',',':')));raise SystemExit(0)
job=ROOT+'/'+intent['correlationId']
try:os.mkdir(job,0o700)
except FileExistsError:
 print(json.dumps(result('unknown','correlation-exists'),separators=(',',':')));raise SystemExit(0)
durable(job+'/intent.json',intent)
fd=os.open(job+'/base.rpm',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o400);h=hashlib.sha256();remaining=size
with os.fdopen(fd,'wb') as out:
 while remaining:
  chunk=sys.stdin.buffer.read(min(65536,remaining))
  if not chunk:print(json.dumps(result('unknown','payload-interrupted'),separators=(',',':')));raise SystemExit(0)
  out.write(chunk);h.update(chunk);remaining-=len(chunk)
 out.flush();os.fsync(out.fileno())
if h.hexdigest()!=digest:
 print(json.dumps(result('unknown','payload-hash-mismatch'),separators=(',',':')));raise SystemExit(0)
header=nevra(['rpm','-qp','--qf',FMT,job+'/base.rpm'])
if header!=intent['expectedBaseNevra']:
 print(json.dumps(result('unknown','rpm-header-mismatch'),separators=(',',':')));raise SystemExit(0)
pre=inspect(intent['expectedCurrentNevra'])
if pre.get('state')!='ready':print(json.dumps(pre,separators=(',',':')));raise SystemExit(0)
worker=job+'/worker.py';fd=os.open(worker,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w') as out:out.write(WORKER_CODE);out.flush();os.fsync(out.fileno())
process=subprocess.Popen([sys.executable,'-I','-B',worker,job],stdin=subprocess.DEVNULL,
 stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
try: ticks=int(open('/proc/%d/stat'%process.pid,encoding='ascii').read().rsplit(')',1)[1].split()[19])
except Exception:
 print(json.dumps(result('unknown','worker-generation-unavailable'),separators=(',',':')));raise SystemExit(0)
intent['identity']={'pid':process.pid,'startTicks':ticks};durable(job+'/intent.json',intent)
fd=os.open(job+'/release',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
print(json.dumps(result('submitted',correlationId=intent['correlationId']),separators=(',',':')))
'''.replace('WORKER_CODE', repr(_WORKER))

_STATUS = _COMMON + r'''intent=json.loads(sys.argv[1]);job=ROOT+'/'+intent['correlationId']
try:
 info=os.stat(job,follow_symlinks=False)
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 saved=json.load(open(job+'/intent.json',encoding='utf-8'))
 if any(saved.get(key)!=intent[key] for key in intent):raise ValueError()
 identity=saved.get('identity')
 if not isinstance(identity,dict) or type(identity.get('pid')) is not int or type(identity.get('startTicks')) is not int:raise ValueError()
 try:receipt=json.load(open(job+'/receipt.json',encoding='utf-8'))
 except FileNotFoundError:receipt=None
 if receipt is not None:
  if receipt.get('correlationId')!=intent['correlationId']:raise ValueError()
  if receipt.get('state')=='blocked':print(json.dumps(receipt,separators=(',',':')));raise SystemExit(0)
  if receipt.get('state')!='terminal' or any(receipt.get(key)!=intent[key] for key in ('sourceSha','baseArtifactId','expectedBaseNevra')):raise ValueError()
  if receipt.get('result')=='passed':
   current=nevra(['rpm','-q','--qf',FMT,'vpn-control'])
   verify=subprocess.run(['rpm','-V','vpn-control'],capture_output=True,timeout=30)
   if current!=intent['expectedBaseNevra'] or verify.returncode or verify.stdout or verify.stderr:raise ValueError()
  print(json.dumps(receipt,separators=(',',':')));raise SystemExit(0)
 parts=open('/proc/%d/stat'%identity['pid'],encoding='ascii').read().rsplit(')',1)[1].split()
 if parts[0]=='Z' or int(parts[19])!=identity['startTicks']:raise ValueError()
 print(json.dumps(result('running',correlationId=intent['correlationId']),separators=(',',':')))
except Exception:print(json.dumps(result('unknown',correlationId=intent['correlationId']),separators=(',',':')))
'''

_OWNER_OBSERVE = r'''import json,os,pwd,subprocess,sys
pid=int(sys.argv[1]);expected_ticks=int(sys.argv[2])
def unknown(reason):
 print(json.dumps({'state':'unknown','reason':reason},separators=(',',':')));raise SystemExit(0)
if os.geteuid()!=pwd.getpwnam('vpnfixture').pw_uid or pid<=0 or expected_ticks<=0:unknown('wrong-owner')
def ticks():
 try:return int(open('/proc/%d/stat'%pid,encoding='ascii').read().rsplit(')',1)[1].split()[19])
 except Exception:return None
if ticks()!=expected_ticks:unknown('owner-generation-changed')
try:
 raw=open('/proc/%d/cmdline'%pid,'rb').read(8193)
 if not raw or len(raw)>8192:unknown('owner-command-unavailable')
 argv=[part.decode('utf-8') for part in raw.split(b'\0') if part]
 if not argv or os.path.realpath(argv[0])!='/opt/vpn-control/bin/vpn-control':unknown('owner-launcher-mismatch')
 positions=[n for n,part in enumerate(argv) if part=='--state-dir']
 if len(positions)!=1 or positions[0]+1>=len(argv):unknown('state-directory-unavailable')
 workspace=argv[positions[0]+1]
 if not os.path.isabs(workspace) or '..' in workspace.split('/') or '\x00' in workspace:unknown('state-directory-unsafe')
 if not any(part in ('serve','--headless-controller') for part in argv):unknown('owner-role-mismatch')
 args=['/opt/vpn-control/bin/vpn-control','--state-dir',workspace,'--json','status']
 observed=subprocess.run(args,capture_output=True,text=True,timeout=15)
 if observed.returncode!=0 or len(observed.stdout)>65536:unknown('public-status-unavailable')
 value=json.loads(observed.stdout)
 data=value.get('data')
 if value.get('ok') is not True or not isinstance(data,dict) or type(data.get('runtimeRunning')) is not bool:unknown('public-status-invalid')
 fields=('selectedLocationId','activeLocationId','configuredMode','activeMode','runtimeId')
 if any(data.get(field) is not None and (not isinstance(data[field],str) or len(data[field])>128) for field in fields):unknown('public-status-invalid')
 controller=value.get('controllerId')
 if not isinstance(controller,str) or len(controller)>128:unknown('public-status-invalid')
 if ticks()!=expected_ticks:unknown('owner-generation-changed')
 print(json.dumps({'state':'observed','pid':pid,'startTicks':expected_ticks,'controllerId':controller,
  'runtimeRunning':data['runtimeRunning'],**{field:data.get(field) for field in fields},
  'trafficInterruptionRisk':'possible' if data['runtimeRunning'] else 'no-app-runtime',
  'controlSessionRisk':'unknown'},separators=(',',':')))
except Exception:unknown('owner-observation-unavailable')
'''


def _request(value: Mapping[str, Any]) -> dict[str, str]:
    fields = {"host", "environment", "baseArtifactId", "sourceSha", "sourceFingerprint",
              "expectedCurrentNevra", "expectedBaseNevra", "correlationId"}
    if not isinstance(value, Mapping) or set(value) != fields or value.get("host") != "fedora2328" or value.get("environment") != "fedora2328":
        raise LinuxRpmBasePrepareError("Fedora RPM base preparation requires exact fields and environment")
    for field, pattern in (("baseArtifactId", _ARTIFACT), ("sourceSha", _SHA),
                           ("sourceFingerprint", _HASH), ("expectedCurrentNevra", _NEVRA),
                           ("expectedBaseNevra", _NEVRA)):
        if not isinstance(value[field], str) or not pattern.fullmatch(value[field]):
            raise LinuxRpmBasePrepareError(f"Invalid {field}")
    try:
        if str(uuid.UUID(value["correlationId"])) != value["correlationId"]:
            raise ValueError()
    except (ValueError, TypeError, AttributeError) as error:
        raise LinuxRpmBasePrepareError("Invalid correlationId") from error
    current = value["expectedCurrentNevra"].removeprefix("vpn-control-").split("-", 1)[0]
    target = value["expectedBaseNevra"].removeprefix("vpn-control-").split("-", 1)[0]
    if parse_version(current) >= parse_version(target):
        raise LinuxRpmBasePrepareError("Base RPM must be newer than installed version")
    return dict(value)


def _admitted(root: Path, request: Mapping[str, str]):
    verified = native_artifact_registry.verify_artifact(root, request["baseArtifactId"])
    artifact = verified.get("artifact")
    location = verified.get("location")
    if (verified.get("verification") != "verified" or not isinstance(artifact, Mapping)
            or artifact.get("platform") != "linux" or artifact.get("artifactKind") != "package"
            or artifact.get("sourceSha") != request["sourceSha"]
            or artifact.get("sourceFingerprint") != request["sourceFingerprint"]
            or not isinstance(location, Mapping) or not isinstance(location.get("localPath"), str)):
        raise LinuxRpmBasePrepareError("Base RPM is not a verified registered source artifact")
    package = Path(location["localPath"])
    info = package.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or not 0 < info.st_size <= _MAX_RPM:
        raise LinuxRpmBasePrepareError("Base RPM path is unsafe")
    config = ssh_transport.load_config(root)
    host = config.hosts.get("fedora2328")
    if host is None or host.user != "vpnfixture":
        raise LinuxRpmBasePrepareError("Fedora guest account is not configured")
    return package, config


def _driver(root):
    return native_rpm_public_install_ssh.RpmPublicInstallSshDriver(root, timeout_seconds=60)


def _journal(root, correlation, create=False):
    directory = Path(root) / ".rag_index" / "linux-rpm-base-prepare"
    if create:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not directory.exists():
        return None
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise LinuxRpmBasePrepareError("Base preparation journal is unsafe")
    return directory / (correlation + ".json")


def _save(path, request):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write((json.dumps(request, sort_keys=True, separators=(",", ":")) + "\n").encode())
        out.flush(); os.fsync(out.fileno())
    fd = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)


def _read(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 4096:
            raise LinuxRpmBasePrepareError("Base preparation journal is unsafe")
        value = json.loads(source.read())
    return _request(value)


def _unknown(correlation, reason):
    return {"state": "unknown", "correlationId": correlation, "reason": reason, "replayAllowed": False}


def preflight(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read only the current disposable guest state before any base submission."""
    if (not isinstance(value, Mapping) or set(value) !=
            {"host", "environment", "expectedCurrentNevra"} or
            value.get("host") != "fedora2328" or value.get("environment") != "fedora2328" or
            not isinstance(value.get("expectedCurrentNevra"), str) or
            not _NEVRA.fullmatch(value["expectedCurrentNevra"])):
        raise LinuxRpmBasePrepareError("Fedora base preflight requires exact guest and current NEVRA")
    root = Path(root).resolve(strict=True)
    config = ssh_transport.load_config(root)
    host = config.hosts.get("fedora2328")
    if host is None or host.user != "vpnfixture":
        return {"state": "unknown", "reason": "guest-config-unavailable"}
    try:
        observed = _driver(root)._remote(config, "fedora2328", _PREFLIGHT,
                                         (value["expectedCurrentNevra"],), privileged=True,
                                         diagnostic=True)
    except Exception as error:
        observed = {"state": "unknown", "reason": "local-observer-exception-" + type(error).__name__}
    if not isinstance(observed, Mapping) or observed.get("state") not in {"ready", "blocked"}:
        return {"state": "unknown", "reason": observed.get("reason", "guest-observation-unavailable")
                if isinstance(observed, Mapping) else "guest-observation-unavailable"}
    result = {"state": observed["state"], "host": "fedora2328", "environment": "fedora2328"}
    if observed["state"] == "ready" and observed.get("currentNevra") == value["expectedCurrentNevra"]:
        result["currentNevra"] = value["expectedCurrentNevra"]
    else:
        result["state"] = "blocked"
        result["reason"] = observed.get("reason", "guest-not-idle")
        if isinstance(observed.get("currentNevra"), str) and _NEVRA.fullmatch(observed["currentNevra"]):
            result["currentNevra"] = observed["currentNevra"]
        if (observed.get("reason") == "active-runtime" and
                type(observed.get("activeProcessCount")) is int and
                0 < observed["activeProcessCount"] <= 4096 and
                isinstance(observed.get("activeProcesses"), list) and
                len(observed["activeProcesses"]) <= 8 and
                all(isinstance(item, Mapping) and set(item) == {"pid", "startTicks", "executable"}
                    and type(item["pid"]) is int and item["pid"] > 0
                    and type(item["startTicks"]) is int and item["startTicks"] > 0
                    and item["executable"] in {"vpn-control", "sing-box", "rpm", "dnf", "dnf5", "packagekitd", "java", "javaw"}
                    for item in observed["activeProcesses"])):
            result["activeProcessCount"] = observed["activeProcessCount"]
            result["activeProcesses"] = observed["activeProcesses"]
    return result


def observe_owner(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read the one pinned installed owner through its public no-startup status."""
    if (not isinstance(value, Mapping) or set(value) != {"host", "environment", "pid", "startTicks"}
            or value.get("host") != "fedora2328" or value.get("environment") != "fedora2328"
            or type(value.get("pid")) is not int or value["pid"] <= 0
            or type(value.get("startTicks")) is not int or value["startTicks"] <= 0):
        raise LinuxRpmBasePrepareError("Owner observation requires exact Fedora PID generation")
    root = Path(root).resolve(strict=True)
    config = ssh_transport.load_config(root)
    host = config.hosts.get("fedora2328")
    if host is None or host.user != "vpnfixture":
        return {"state": "unknown", "reason": "guest-config-unavailable"}
    try:
        observed = _driver(root)._remote(config, "fedora2328", _OWNER_OBSERVE,
                                         (str(value["pid"]), str(value["startTicks"])), diagnostic=True)
    except Exception as error:
        observed = {"state": "unknown", "reason": "local-owner-exception-" + type(error).__name__}
    if not isinstance(observed, Mapping) or observed.get("state") != "observed":
        return {"state": "unknown", "reason": observed.get("reason", "owner-observation-unavailable")
                if isinstance(observed, Mapping) else "owner-observation-unavailable"}
    fields = {"pid", "startTicks", "controllerId", "runtimeRunning", "selectedLocationId",
              "activeLocationId", "configuredMode", "activeMode", "runtimeId",
              "trafficInterruptionRisk", "controlSessionRisk"}
    if (not fields <= set(observed) or observed["pid"] != value["pid"] or
            observed["startTicks"] != value["startTicks"] or
            type(observed["runtimeRunning"]) is not bool or
            observed["trafficInterruptionRisk"] != ("possible" if observed["runtimeRunning"] else "no-app-runtime") or
            observed["controlSessionRisk"] != "unknown"):
        return {"state": "unknown", "reason": "owner-observation-invalid"}
    return {"state": "observed", "host": "fedora2328", "environment": "fedora2328",
            **{field: observed[field] for field in fields}}


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    root = Path(root).resolve(strict=True)
    request = _request(value)
    path = _journal(root, request["correlationId"])
    if path is not None and (path.exists() or path.is_symlink()):
        if _read(path) != request:
            raise LinuxRpmBasePrepareError("Correlation already binds another base preparation")
        return _unknown(request["correlationId"], "existing-intent")
    package, config = _admitted(root, request)
    driver = _driver(root)
    pre = driver._remote(config, "fedora2328", _PREFLIGHT, (request["expectedCurrentNevra"],), privileged=True)
    if not isinstance(pre, Mapping) or pre.get("state") not in {"ready", "blocked"}:
        return _unknown(request["correlationId"], "preflight-unknown")
    if pre["state"] == "blocked":
        return {"state": "blocked", "correlationId": request["correlationId"],
                "reason": pre.get("reason", "guest-not-idle"), "replayAllowed": False}
    if pre.get("currentNevra") != request["expectedCurrentNevra"]:
        return _unknown(request["correlationId"], "preflight-nevra-mismatch")
    path = _journal(root, request["correlationId"], create=True)
    try: _save(path, request)
    except FileExistsError as error:
        raise LinuxRpmBasePrepareError("Correlation intent already exists") from error
    size = package.stat().st_size
    digest_state = hashlib.sha256()
    with package.open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            digest_state.update(chunk)
    digest = digest_state.hexdigest()
    if digest != request["baseArtifactId"].removeprefix("sha256-"):
        return _unknown(request["correlationId"], "registered-rpm-changed")
    try:
        remote = driver._remote(config, "fedora2328", _SUBMIT,
                                (json.dumps(request, sort_keys=True, separators=(",", ":")), str(size), digest),
                                package, privileged=True)
    except Exception:
        return _unknown(request["correlationId"], "submission-uncertain")
    if not isinstance(remote, Mapping) or remote.get("state") != "submitted" or remote.get("correlationId") != request["correlationId"]:
        return _unknown(request["correlationId"], "submission-uncertain")
    return {"state": "submitted", "correlationId": request["correlationId"], "replayAllowed": False}


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"correlationId"}:
        raise LinuxRpmBasePrepareError("Base preparation status requires correlationId only")
    correlation = value["correlationId"]
    try:
        if str(uuid.UUID(correlation)) != correlation: raise ValueError()
    except (ValueError, TypeError, AttributeError) as error:
        raise LinuxRpmBasePrepareError("Invalid correlationId") from error
    root = Path(root).resolve(strict=True)
    path = _journal(root, correlation)
    if path is None or not path.exists():
        return _unknown(correlation, "missing-intent")
    request = _read(path)
    config = ssh_transport.load_config(root)
    host = config.hosts.get("fedora2328")
    if host is None or host.user != "vpnfixture":
        return _unknown(correlation, "guest-config-unavailable")
    try:
        remote = _driver(root)._remote(config, "fedora2328", _STATUS,
                                       (json.dumps(request, sort_keys=True, separators=(",", ":")),), privileged=True)
    except Exception:
        return _unknown(correlation, "remote-status-unavailable")
    if not isinstance(remote, Mapping) or remote.get("correlationId") != correlation or remote.get("state") not in {"running", "terminal", "blocked"}:
        return _unknown(correlation, "remote-status-unavailable")
    result = {"state": remote["state"], "correlationId": correlation, "sourceSha": request["sourceSha"],
              "baseArtifactId": request["baseArtifactId"], "replayAllowed": False}
    if remote["state"] == "terminal":
        if (remote.get("result") not in {"passed", "failed"} or type(remote.get("exitCode")) is not int
                or remote.get("expectedBaseNevra") != request["expectedBaseNevra"]):
            return _unknown(correlation, "terminal-receipt-invalid")
        result.update(result=remote["result"], exitCode=remote["exitCode"],
                      observedNevra=remote.get("observedNevra"), rpmVerifyClean=remote.get("rpmVerifyClean") is True)
    elif remote["state"] == "blocked":
        result["reason"] = remote.get("reason", "guest-not-idle")
    return result

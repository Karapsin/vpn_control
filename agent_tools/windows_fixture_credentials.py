"""Private CP117 fixture TLS credential boundary.

Only the fixed, owner-private credential sibling may hold this short-lived
material. Public inputs never contain a path, certificate, key, password, or
arbitrary observation. Native dispatch remains subject to independent review
and explicit MCP integration; importing this module does not launch a guest.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import fcntl
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import stat
import time
import uuid
from typing import Any, Mapping

from . import windows_cp117_lease as lease
from . import windows_msi_base_prepare as base
from . import windows_msi_public_scenario as public
from . import windows_update_fixture_stage as stage
from . import windows_credential_probe_ssh as transport


class WindowsFixtureCredentialsError(ValueError):
    pass


_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_SID = re.compile(r"S-1-5-21-(?:[0-9]+-){3}[0-9]+\Z")
_GUEST_ROOT = r"C:\Users\vpncp117\AppData\Local\VpnControl"
_ALIAS = "vpn-control-fixture-github"
_GROUP = ".rag_index/windows-fixture-credentials"
_CLEANUP_GROUP = ".rag_index/windows-fixture-credentials-cleanup"
_ABORT_GROUP = ".rag_index/windows-fixture-credentials-abort"


_REMOTE_START = base._QGA + lease.remote_role_guard() + r'''import fcntl,struct,time
root,env,corr,lease_id,stage_corr,sock,pid,ticks,sid,source,fingerprint,receipt_id,base_id,target_id=sys.argv[1:]
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
try:
 if env!='windows-cp117' or not live(sock,pid,ticks):raise ValueError()
 require_campaign_role(root,env,lease_id,'credentials',corr,source,receipt_id,base_id,target_id,sock,pid,ticks)
 parent=os.path.join(root,env);group=os.path.join(parent,'windows-fixture-credentials')
 for path in (root,parent,group):
  if not os.path.exists(path):
   os.mkdir(path,0o700)
   parentfd=os.open(os.path.dirname(path),os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(parentfd);os.close(parentfd)
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 lock=os.open(os.path.join(group,'.environment.lock'),os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
 try:
  fcntl.flock(lock,fcntl.LOCK_EX)
  if any(name.endswith('.json') for name in os.listdir(group)):raise FileExistsError()
  stage=os.path.join(group,corr);os.mkdir(stage,0o700)
  parentfd=os.open(group,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(parentfd);os.close(parentfd)
 finally:os.close(lock)
 length=struct.unpack('>I',sys.stdin.buffer.read(4))[0]
 if not 0<length<=1048576:raise ValueError()
 payload=json.loads(sys.stdin.buffer.read(length))
 if sys.stdin.buffer.read(1) or set(payload)!={'binding','provisionId','fileSha256','peerCertificateSha256','setupCommand','finalizeCommand','files'}:raise ValueError()
 expected={'leaseId':lease_id,'stageCorrelationId':stage_corr,'sourceSha':source,'sourceFingerprint':fingerprint,
  'fixtureReceiptArtifactId':receipt_id,'baseMsiArtifactId':base_id,'targetMsiArtifactId':target_id,
  'socketPath':sock,'qemuPid':int(pid),'startTicks':int(ticks),'originalSid':sid,'sessionId':1,'limited':True}
 if payload['binding']!=expected or not isinstance(payload['provisionId'],str) or len(payload['provisionId'])!=36:raise ValueError()
 names=('certificate','privateKey','trustStore')
 if set(payload['files'])!=set(names) or set(payload['fileSha256'])!=set(names):raise ValueError()
 files={name:base64.b64decode(payload['files'][name],validate=True) for name in names}
 if any(not 0<len(files[name])<=262144 or hashlib.sha256(files[name]).hexdigest()!=payload['fileSha256'][name] for name in names):raise ValueError()
 if any(not isinstance(payload[name],str) or len(payload[name])>30000 for name in ('setupCommand','finalizeCommand')):raise ValueError()
 binding={'binding':expected,'provisionId':payload['provisionId'],'fileSha256':payload['fileSha256'],
  'peerCertificateSha256':payload['peerCertificateSha256']}
 path=os.path.join(stage,'binding.json')
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'w',encoding='utf-8') as stream:json.dump(binding,stream,separators=(',',':'));stream.flush();os.fsync(stream.fileno())
 parentfd=os.open(stage,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(parentfd);os.close(parentfd)
 def execute(encoded):
  task=call(sock,'guest-exec',{'path':'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})
  for i in range(60):
   result=call(sock,'guest-exec-status',{'pid':task['pid']})
   if result.get('exited') is True:
    if result.get('exitcode')!=0:raise ValueError()
    return
   time.sleep(.2)
  raise ValueError()
 execute(payload['setupCommand'])
 guest='C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-update-credentials-'+stage_corr
 paths={'certificate':guest+'\\server-cert.pem','privateKey':guest+'\\server-key.pem','trustStore':guest+'\\fixture-trust.p12'}
 for name in names:
  handle=call(sock,'guest-file-open',{'path':paths[name],'mode':'wb'})
  try:
   raw=files[name];offset=0
   while offset<len(raw):
    part=raw[offset:offset+49152];written=call(sock,'guest-file-write',{'handle':handle,'buf-b64':base64.b64encode(part).decode()})['count']
    if type(written) is not int or written!=len(part):raise ValueError()
    offset+=written
   call(sock,'guest-file-flush',{'handle':handle})
  finally:call(sock,'guest-file-close',{'handle':handle})
 execute(payload['finalizeCommand'])
 out({'state':'submitted','correlationId':corr})
except Exception:out({'state':'unknown','correlationId':corr})
'''


_REMOTE_STATUS = base._QGA + r'''import time
root,env,corr,lease_id,stage_corr,sock,pid,ticks,sid,source,fingerprint,receipt_id,base_id,target_id,provision_id,cert_hash,key_hash,trust_hash,leaf_hash,observe_encoded=sys.argv[1:]
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
try:
 if env!='windows-cp117' or not live(sock,pid,ticks):raise ValueError()
 group=os.path.join(root,env,'windows-fixture-credentials');journal=os.path.join(group,corr)
 for path in (root,os.path.join(root,env),group,journal):
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 path=os.path.join(journal,'binding.json');info=os.lstat(path)
 if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>4096:raise ValueError()
 value=json.load(open(path,encoding='utf-8'))
 expected={'binding':{'leaseId':lease_id,'stageCorrelationId':stage_corr,'sourceSha':source,
  'sourceFingerprint':fingerprint,'fixtureReceiptArtifactId':receipt_id,'baseMsiArtifactId':base_id,
  'targetMsiArtifactId':target_id,'socketPath':sock,'qemuPid':int(pid),'startTicks':int(ticks),
  'originalSid':sid,'sessionId':1,'limited':True},'provisionId':provision_id,
  'fileSha256':{'certificate':cert_hash,'privateKey':key_hash,'trustStore':trust_hash},
  'peerCertificateSha256':leaf_hash}
 if value!=expected:raise ValueError()
 if len(observe_encoded)>30000:raise ValueError()
 task=call(sock,'guest-exec',{'path':'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',observe_encoded],'capture-output':True})
 for i in range(40):
  result=call(sock,'guest-exec-status',{'pid':task['pid']})
  if result.get('exited') is True:break
  time.sleep(.2)
 else:raise ValueError()
 if result.get('exitcode')!=0 or result.get('out-truncated') is not False or result.get('err-truncated') is not False:raise ValueError()
 stdout=base64.b64decode(result.get('out-data',''),validate=True)
 if not 0<len(stdout)<=16384:raise ValueError()
 fresh=json.loads(decode(stdout))
 guest='C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-update-credentials-'+stage_corr
 raw=read(sock,guest+'\\provenance.json',16384)
 if raw is None or not 0<len(raw)<=12000:raise ValueError()
 provenance=json.loads(decode(raw))
 out({'state':'observed','correlationId':corr,'provenance':provenance,'fresh':fresh,
  'provenanceSha256':hashlib.sha256(raw).hexdigest()})
except Exception:out({'state':'unknown','correlationId':corr})
'''


_REMOTE_CLEANUP_START = base._QGA + lease.remote_role_guard() + r'''import time
root,env,corr,lease_id,stage_corr,provision_corr,sock,pid,ticks,sid,source,receipt_id,base_id,target_id,role,encoded=sys.argv[1:]
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
try:
 if env!='windows-cp117' or role not in ('credentials','credentials-cleanup') or not live(sock,pid,ticks) or len(encoded)>30000:raise ValueError()
 require_campaign_role(root,env,lease_id,role,corr,source,receipt_id,base_id,target_id,sock,pid,ticks)
 parent=os.path.join(root,env);group=os.path.join(parent,'windows-fixture-credentials-'+('abort' if role=='credentials' else 'cleanup'))
 for path in (root,parent,group):
  if not os.path.exists(path):
   os.mkdir(path,0o700)
   parentfd=os.open(os.path.dirname(path),os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(parentfd);os.close(parentfd)
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 journal=os.path.join(group,corr);os.mkdir(journal,0o700)
 parentfd=os.open(group,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(parentfd);os.close(parentfd)
 binding={'leaseId':lease_id,'stageCorrelationId':stage_corr,'provisionCorrelationId':provision_corr,
  'socketPath':sock,'qemuPid':int(pid),'startTicks':int(ticks),'sourceSha':source,'originalSid':sid}
 path=os.path.join(journal,'binding.json');fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'w',encoding='utf-8') as stream:json.dump(binding,stream,separators=(',',':'));stream.flush();os.fsync(stream.fileno())
 parentfd=os.open(journal,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(parentfd);os.close(parentfd)
 task=call(sock,'guest-exec',{'path':'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})
 fd=os.open(os.path.join(journal,'dispatch.json'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'w',encoding='utf-8') as stream:json.dump({'pid':task['pid']},stream);stream.flush();os.fsync(stream.fileno())
 parentfd=os.open(journal,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(parentfd);os.close(parentfd)
 out({'state':'submitted','correlationId':corr})
except Exception:out({'state':'unknown','correlationId':corr})
'''


_REMOTE_CLEANUP_STATUS = base._QGA + r'''import time
root,env,corr,lease_id,stage_corr,provision_corr,sock,pid,ticks,sid,source,role,encoded=sys.argv[1:]
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
try:
 if env!='windows-cp117' or role not in ('credentials','credentials-cleanup') or not live(sock,pid,ticks) or len(encoded)>30000:raise ValueError()
 journal=os.path.join(root,env,'windows-fixture-credentials-'+('abort' if role=='credentials' else 'cleanup'),corr)
 for path in (root,os.path.join(root,env),os.path.dirname(journal),journal):
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 binding_path=os.path.join(journal,'binding.json');info=os.lstat(binding_path)
 if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError()
 expected={'leaseId':lease_id,'stageCorrelationId':stage_corr,'provisionCorrelationId':provision_corr,
  'socketPath':sock,'qemuPid':int(pid),'startTicks':int(ticks),'sourceSha':source,'originalSid':sid}
 if json.load(open(binding_path,encoding='utf-8'))!=expected:raise ValueError()
 observe=call(sock,'guest-exec',{'path':'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})
 for i in range(40):
  result=call(sock,'guest-exec-status',{'pid':observe['pid']})
  if result.get('exited') is True:break
  time.sleep(.2)
 else:raise ValueError()
 if result.get('exitcode')!=0 or result.get('out-truncated') is not False:raise ValueError()
 raw=base64.b64decode(result.get('out-data',''),validate=True)
 if len(raw)>4096:raise ValueError()
 receipt=json.loads(decode(raw))
 out({'state':'observed','correlationId':corr,'receipt':receipt})
except Exception:out({'state':'unknown','correlationId':corr})
'''


def _request(value: Mapping[str, Any]) -> dict[str, str]:
    fields = {"host", "leaseId", "stageCorrelationId", "correlationId"}
    if (not isinstance(value, Mapping) or set(value) != fields or value.get("host") != "archlinux"
            or not all(_canonical(value.get(name)) for name in
                       ("leaseId", "stageCorrelationId", "correlationId"))
            or len({value["leaseId"], value["stageCorrelationId"], value["correlationId"]}) != 3):
        raise WindowsFixtureCredentialsError("Credential provision requires exact CP117 correlations.")
    return dict(value)


def _journal(root: Path) -> Path:
    directory = root / _GROUP
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink()
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise WindowsFixtureCredentialsError("Credential journal is unsafe.")
    parent = os.open(directory.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return directory


def _prior_intents_closed(root: Path, directory: Path, reader: Any) -> bool:
    """Retain history; only a closed exact campaign permits the next intent."""
    for path in directory.iterdir():
        if path.suffix != ".json":
            continue
        if not _canonical(path.stem):
            return False
        prior = reader(root, path.stem)
        if prior is None or lease.inspect(root, prior["request"]["leaseId"]).get("state") != "closed":
            return False
    return True


def _read_intent(root: Path, correlation_id: str) -> dict[str, Any] | None:
    path = root / _GROUP / (correlation_id + ".json")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 8192):
            raise WindowsFixtureCredentialsError("Credential intent is unsafe.")
        try:
            value = json.load(stream)
        except (TypeError, ValueError) as error:
            raise WindowsFixtureCredentialsError("Credential intent is invalid.") from error
    if (not isinstance(value, dict) or set(value) != {"schemaVersion", "request", "binding", "provisionId",
                                                    "fileSha256", "peerCertificateSha256",
                                                    "certificateValidFromUtc", "certificateValidUntilUtc"}
            or value["schemaVersion"] != 1 or _request(value["request"])["correlationId"] != correlation_id
            or not _canonical(value["provisionId"])
            or not isinstance(value["binding"], dict)
            or value["binding"].get("leaseId") != value["request"]["leaseId"]
            or value["binding"].get("stageCorrelationId") != value["request"]["stageCorrelationId"]
            or not isinstance(value["fileSha256"], dict)
            or set(value["fileSha256"]) != {"certificate", "privateKey", "trustStore"}
            or any(not isinstance(digest, str) or not _HASH.fullmatch(digest)
                   for digest in value["fileSha256"].values())
            or not isinstance(value["peerCertificateSha256"], str)
            or not _HASH.fullmatch(value["peerCertificateSha256"])
            or type(value["certificateValidFromUtc"]) is not int
            or type(value["certificateValidUntilUtc"]) is not int
            or value["certificateValidUntilUtc"] <= value["certificateValidFromUtc"]):
        raise WindowsFixtureCredentialsError("Credential intent is invalid.")
    return value


def _reserve(root: Path, record: Mapping[str, Any]) -> None:
    directory = _journal(root)
    fd = os.open(directory / ".environment.lock", os.O_RDWR | os.O_CREAT |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise WindowsFixtureCredentialsError("Credential journal lock is unsafe.")
        fcntl.flock(fd, fcntl.LOCK_EX)
        if not _prior_intents_closed(root, directory, _read_intent):
            raise WindowsFixtureCredentialsError("An existing credential intent needs readback or cleanup.")
        raw = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if len(raw) > 8192:
            raise WindowsFixtureCredentialsError("Credential intent is too large.")
        path = directory / (record["request"]["correlationId"] + ".json")
        output = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(output, "wb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        parent = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        os.close(fd)


def _cleanup_intent(root: Path, correlation_id: str, *, group: str = _CLEANUP_GROUP) -> dict[str, Any] | None:
    path = root / group / (correlation_id + ".json")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 8192):
            raise WindowsFixtureCredentialsError("Credential cleanup intent is unsafe.")
        try:
            value = json.load(stream)
        except (ValueError, TypeError) as error:
            raise WindowsFixtureCredentialsError("Credential cleanup intent is invalid.") from error
    if (not isinstance(value, dict) or set(value) != {"schemaVersion", "request", "binding", "provisionCorrelationId"}
            or value["schemaVersion"] != 1 or _request(value["request"])["correlationId"] != correlation_id
            or not _canonical(value["provisionCorrelationId"])
            or not isinstance(value["binding"], dict)
            or value["binding"].get("leaseId") != value["request"]["leaseId"]
            or value["binding"].get("stageCorrelationId") != value["request"]["stageCorrelationId"]):
        raise WindowsFixtureCredentialsError("Credential cleanup intent is invalid.")
    return value


def _reserve_cleanup(root: Path, record: Mapping[str, Any], *, group: str = _CLEANUP_GROUP) -> None:
    directory = root / group
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink()
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise WindowsFixtureCredentialsError("Credential cleanup journal is unsafe.")
    parent = os.open(directory.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    fd = os.open(directory / ".environment.lock", os.O_RDWR | os.O_CREAT |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise WindowsFixtureCredentialsError("Credential cleanup lock is unsafe.")
        fcntl.flock(fd, fcntl.LOCK_EX)
        if not _prior_intents_closed(root, directory,
                                     lambda parent, corr: _cleanup_intent(parent, corr, group=group)):
            raise WindowsFixtureCredentialsError("An existing credential cleanup needs readback.")
        raw = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if len(raw) > 8192:
            raise WindowsFixtureCredentialsError("Credential cleanup intent is too large.")
        path = directory / (record["request"]["correlationId"] + ".json")
        output = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(output, "wb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        parent = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        os.close(fd)


def _dispatch(root: Path, request: Mapping[str, str], binding: Mapping[str, Any],
              material: Mapping[str, Any], provision_id: str) -> bytes | None:
    config, target, _ = base._descriptor(root)
    paths = _fixed_paths(request["stageCorrelationId"])
    setup = base64.b64encode(_guest_setup_script(paths, binding["originalSid"]).encode("utf-16le")).decode("ascii")
    finalize = base64.b64encode(_guest_finalize_script(binding, material, paths, provision_id,
                                                         request["correlationId"]).encode("utf-16le")).decode("ascii")
    payload = {"binding": dict(binding), "provisionId": provision_id,
               "fileSha256": material["fileSha256"],
               "peerCertificateSha256": material["peerCertificateSha256"],
               "setupCommand": setup, "finalizeCommand": finalize,
               "files": {name: base64.b64encode(material[name]).decode("ascii")
                         for name in ("certificate", "privateKey", "trustStore")}}
    argv = transport._remote_command(_REMOTE_START, str(target.fixture_transfer_root), "windows-cp117",
        request["correlationId"], request["leaseId"], request["stageCorrelationId"],
        binding["socketPath"], str(binding["qemuPid"]), str(binding["startTicks"]),
        binding["originalSid"], binding["sourceSha"], binding["sourceFingerprint"],
        binding["fixtureReceiptArtifactId"], binding["baseMsiArtifactId"],
        binding["targetMsiArtifactId"])
    return transport._run_ssh(config, "archlinux", argv, transport._remote_payload(payload), 120)


def _remote_observe(root: Path, request: Mapping[str, str], binding: Mapping[str, Any],
                    record: Mapping[str, Any]) -> dict[str, Any]:
    config, target, _ = base._descriptor(root)
    paths = _fixed_paths(request["stageCorrelationId"])
    encoded = base64.b64encode(_guest_observe_script(paths, request["correlationId"]).encode("utf-16le")).decode("ascii")
    if len(encoded) > 30000:
        raise WindowsFixtureCredentialsError("Credential observer is too large.")
    hashes = record["fileSha256"]
    command = transport._remote_command(_REMOTE_STATUS, str(target.fixture_transfer_root), "windows-cp117",
        request["correlationId"], request["leaseId"], request["stageCorrelationId"],
        binding["socketPath"], str(binding["qemuPid"]), str(binding["startTicks"]),
        binding["originalSid"], binding["sourceSha"], binding["sourceFingerprint"],
        binding["fixtureReceiptArtifactId"], binding["baseMsiArtifactId"],
        binding["targetMsiArtifactId"], record["provisionId"], hashes["certificate"],
        hashes["privateKey"], hashes["trustStore"], record["peerCertificateSha256"], encoded)
    raw = transport._run_ssh(config, "archlinux", command, None, 30)
    try:
        response = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError):
        response = None
    if (not isinstance(response, dict) or set(response) != {"state", "correlationId", "provenance",
                                                             "fresh", "provenanceSha256"}
            or response["state"] != "observed" or response["correlationId"] != request["correlationId"]
            or not isinstance(response["provenanceSha256"], str)
            or not _HASH.fullmatch(response["provenanceSha256"])):
        raise WindowsFixtureCredentialsError("FIXTURE_CREDENTIAL_PROVENANCE_READBACK_UNAVAILABLE")
    fresh = response["fresh"]
    if (not isinstance(fresh, dict) or set(fresh) != {"schemaVersion", "taskState", "taskLastResult",
                                                "fileSha256", "acls", "provenanceAcl"}
            or fresh["schemaVersion"] != 1 or fresh["taskState"] != "Ready"
            or fresh["taskLastResult"] != 0 or fresh["fileSha256"] != record["fileSha256"]
            or not _valid_acl(fresh["provenanceAcl"], paths["directory"] + r"\provenance.json",
                              binding["originalSid"], directory=False)):
        raise WindowsFixtureCredentialsError("Credential owner task or live files are unverified.")
    provenance = response["provenance"]
    if not isinstance(provenance, dict) or provenance.get("acls") != fresh["acls"]:
        raise WindowsFixtureCredentialsError("Credential ACL changed after owner readback.")
    observed = dict(provenance, fileSha256=fresh["fileSha256"], acls=fresh["acls"])
    _validate_observation(binding, observed, now=int(time.time()))
    if (observed["provisionId"] != record["provisionId"]
            or observed["fileSha256"] != record["fileSha256"]
            or observed["peerCertificateSha256"] != record["peerCertificateSha256"]
            or observed["certificateValidFromUtc"] != record["certificateValidFromUtc"]
            or observed["certificateValidUntilUtc"] != record["certificateValidUntilUtc"]):
        raise WindowsFixtureCredentialsError("Credential generation changed.")
    return {"observation": observed, "provenanceSha256": response["provenanceSha256"]}


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Reserve once, claim the credentials lease role, then submit fixed QGA transfer."""
    request = _request(value)
    root = Path(root).resolve(strict=True)
    corr = request["correlationId"]
    prior = _read_intent(root, corr)
    if prior is not None:
        if prior["request"] != request:
            raise WindowsFixtureCredentialsError("Credential correlation binds another campaign.")
        return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
    binding = _binding(root, request["leaseId"], request["stageCorrelationId"])
    material = _generate_material()
    provision_id = str(uuid.uuid4())
    record = {"schemaVersion": 1, "request": request, "binding": binding,
              "provisionId": provision_id, "fileSha256": material["fileSha256"],
              "peerCertificateSha256": material["peerCertificateSha256"],
              "certificateValidFromUtc": material["certificateValidFromUtc"],
              "certificateValidUntilUtc": material["certificateValidUntilUtc"]}
    _reserve(root, record)
    config, target, _ = base._descriptor(root)
    claimed = lease.claim_role(root, request["leaseId"], "credentials", corr,
                               base._campaign_remote(config, target))
    if claimed.get("state") != "role-active":
        return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
    raw = _dispatch(root, request, binding, material, provision_id)
    try:
        result = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError):
        result = None
    if not isinstance(result, dict) or result != {"state": "submitted", "correlationId": corr}:
        return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
    return {"state": "submitted", "correlationId": corr, "replayAllowed": False}


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"correlationId"} or not _canonical(value["correlationId"]):
        raise WindowsFixtureCredentialsError("Credential status requires exact correlation.")
    root = Path(root).resolve(strict=True); corr = value["correlationId"]
    unknown = {"state": "unknown", "correlationId": corr, "replayAllowed": False}
    record = _read_intent(root, corr)
    if record is None:
        return unknown
    request = record["request"]
    try:
        try:
            binding = _binding(root, request["leaseId"], request["stageCorrelationId"],
                               require_credentials="ready")
            already_ready = True
        except WindowsFixtureCredentialsError:
            binding = _binding(root, request["leaseId"], request["stageCorrelationId"],
                               provision_correlation_id=corr, require_credentials="absent")
            already_ready = False
        if binding != record["binding"]:
            return unknown
        observed = _remote_observe(root, request, binding, record)
        if not already_ready:
            config, target, _ = base._descriptor(root)
            finished = lease.finish_role(root, request["leaseId"], "credentials", corr,
                                         observed["provenanceSha256"], "succeeded",
                                         base._campaign_remote(config, target))
            if finished.get("state") != "active":
                return unknown
    except (ValueError, OSError, KeyError):
        return unknown
    return {"state": "ready", "correlationId": corr,
            "peerCertificateSha256": observed["observation"]["peerCertificateSha256"],
            "trustStoreSha256": observed["observation"]["fileSha256"]["trustStore"],
            "replayAllowed": False}


def collect(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Exact readback only; a lost submit response is never replayed."""
    return status(root, value)


def _provision_record(root: Path, binding: Mapping[str, Any]) -> dict[str, Any]:
    try:
        names = [path.stem for path in (root / _GROUP).iterdir() if path.suffix == ".json"]
    except FileNotFoundError as error:
        raise WindowsFixtureCredentialsError("Fixture credential intent is unavailable.") from error
    if any(not _canonical(name) for name in names):
        raise WindowsFixtureCredentialsError("Fixture credential intent is ambiguous.")
    matched = [record for name in names if (record := _read_intent(root, name)) is not None
               and record["binding"] == binding]
    if len(matched) != 1:
        raise WindowsFixtureCredentialsError("Fixture credential intent changed.")
    return matched[0]


def _dispatch_cleanup(root: Path, request: Mapping[str, str], binding: Mapping[str, Any],
                      provision_correlation_id: str, *, abort: bool = False) -> bytes | None:
    config, target, _ = base._descriptor(root)
    paths = _fixed_paths(request["stageCorrelationId"])
    script = (_guest_abort_script(paths, provision_correlation_id, binding["originalSid"])
              if abort else _guest_cleanup_script(paths, provision_correlation_id))
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    if len(encoded) > 30000:
        raise WindowsFixtureCredentialsError("Credential cleanup is too large.")
    command = transport._remote_command(_REMOTE_CLEANUP_START, str(target.fixture_transfer_root),
        "windows-cp117", request["correlationId"], request["leaseId"],
        request["stageCorrelationId"], provision_correlation_id,
        binding["socketPath"], str(binding["qemuPid"]), str(binding["startTicks"]),
        binding["originalSid"], binding["sourceSha"], binding["fixtureReceiptArtifactId"],
        binding["baseMsiArtifactId"], binding["targetMsiArtifactId"],
        "credentials" if abort else "credentials-cleanup", encoded)
    return transport._run_ssh(config, "archlinux", command, None, 60)


def cleanup_start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    request = _request(value); root = Path(root).resolve(strict=True); corr = request["correlationId"]
    prior = _cleanup_intent(root, corr)
    if prior is not None:
        if prior["request"] != request:
            raise WindowsFixtureCredentialsError("Cleanup correlation binds another campaign.")
        return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
    binding = _binding(root, request["leaseId"], request["stageCorrelationId"],
                       require_credentials="ready")
    campaign = lease.inspect(root, request["leaseId"])
    if campaign.get("state") != "active" or campaign.get("role") is not None or campaign.get("server") != "stopped":
        raise WindowsFixtureCredentialsError("Fixture server must be terminal before credential cleanup.")
    provision = _provision_record(root, binding)
    if corr == provision["request"]["correlationId"]:
        raise WindowsFixtureCredentialsError("Cleanup correlation must be fresh.")
    record = {"schemaVersion": 1, "request": request, "binding": binding,
              "provisionCorrelationId": provision["request"]["correlationId"]}
    _reserve_cleanup(root, record)
    config, target, _ = base._descriptor(root)
    claimed = lease.claim_role(root, request["leaseId"], "credentials-cleanup", corr,
                               base._campaign_remote(config, target))
    if claimed.get("state") != "role-active":
        return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
    raw = _dispatch_cleanup(root, request, binding, record["provisionCorrelationId"])
    try:
        response = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError):
        response = None
    if response != {"state": "submitted", "correlationId": corr}:
        return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
    return {"state": "submitted", "correlationId": corr, "replayAllowed": False}


def _observe_cleanup(root: Path, request: Mapping[str, str], binding: Mapping[str, Any],
                     provision_correlation_id: str, *, abort: bool = False) -> dict[str, Any]:
    config, target, _ = base._descriptor(root)
    paths = _fixed_paths(request["stageCorrelationId"])
    script = _guest_cleanup_observe_script(paths, provision_correlation_id, request["stageCorrelationId"])
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    command = transport._remote_command(_REMOTE_CLEANUP_STATUS, str(target.fixture_transfer_root),
        "windows-cp117", request["correlationId"], request["leaseId"],
        request["stageCorrelationId"], provision_correlation_id,
        binding["socketPath"], str(binding["qemuPid"]), str(binding["startTicks"]),
        binding["originalSid"], binding["sourceSha"],
        "credentials" if abort else "credentials-cleanup", encoded)
    raw = transport._run_ssh(config, "archlinux", command, None, 30)
    try:
        response = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError):
        response = None
    if (not isinstance(response, dict) or response.get("correlationId") != request["correlationId"]
            or response.get("state") not in {"running", "observed"}):
        raise WindowsFixtureCredentialsError("Credential cleanup readback is unavailable.")
    if response["state"] == "running":
        return {"state": "running"}
    receipt = response.get("receipt")
    if receipt != {"schemaVersion": 1, "credentialDirectoryAbsent": True, "taskAbsent": True,
                   "stagePresent": True, "stageCorrelationId": request["stageCorrelationId"]}:
        raise WindowsFixtureCredentialsError("Credential cleanup is not complete.")
    return {"state": "observed", "receiptSha256": hashlib.sha256(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}


def cleanup_status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"correlationId"} or not _canonical(value["correlationId"]):
        raise WindowsFixtureCredentialsError("Credential cleanup status requires exact correlation.")
    root = Path(root).resolve(strict=True); corr = value["correlationId"]
    unknown = {"state": "unknown", "correlationId": corr, "replayAllowed": False}
    record = _cleanup_intent(root, corr)
    if record is None:
        return unknown
    request = record["request"]
    try:
        try:
            binding = _binding(root, request["leaseId"], request["stageCorrelationId"],
                               require_credentials="cleaned")
            already_cleaned = True
        except WindowsFixtureCredentialsError:
            binding = _binding(root, request["leaseId"], request["stageCorrelationId"],
                               cleanup_correlation_id=corr, require_credentials="ready")
            already_cleaned = False
        if binding != record["binding"]:
            return unknown
        observation = _observe_cleanup(root, request, binding, record["provisionCorrelationId"])
        if observation["state"] == "running":
            return {"state": "running", "correlationId": corr, "replayAllowed": False}
        if not already_cleaned:
            config, target, _ = base._descriptor(root)
            finished = lease.finish_role(root, request["leaseId"], "credentials-cleanup", corr,
                                         observation["receiptSha256"], "succeeded",
                                         base._campaign_remote(config, target))
            if finished.get("state") != "active":
                return unknown
    except (ValueError, OSError, KeyError):
        return unknown
    return {"state": "cleaned", "correlationId": corr,
            "cleanupReceiptSha256": observation["receiptSha256"], "replayAllowed": False}


def cleanup_collect(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    return cleanup_status(root, value)


def abort_start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """One-shot cleanup for a partial or uncertain provision, under its held role."""
    if not isinstance(value, Mapping) or set(value) != {"correlationId"} or not _canonical(value["correlationId"]):
        raise WindowsFixtureCredentialsError("Credential abort requires exact provision correlation.")
    root = Path(root).resolve(strict=True); corr = value["correlationId"]
    prior = _cleanup_intent(root, corr, group=_ABORT_GROUP)
    if prior is not None:
        return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
    provision = _read_intent(root, corr)
    if provision is None:
        raise WindowsFixtureCredentialsError("Credential provision intent is absent.")
    request = provision["request"]
    binding = _binding(root, request["leaseId"], request["stageCorrelationId"],
                       provision_correlation_id=corr, require_credentials="absent")
    campaign = lease.inspect(root, request["leaseId"])
    if (campaign.get("state") != "role-active" or campaign.get("role") != "credentials"
            or campaign.get("server") != "stopped" or binding != provision["binding"]):
        raise WindowsFixtureCredentialsError("Credential provision role is not held for abort.")
    record = {"schemaVersion": 1, "request": request, "binding": binding,
              "provisionCorrelationId": corr}
    _reserve_cleanup(root, record, group=_ABORT_GROUP)
    raw = _dispatch_cleanup(root, request, binding, corr, abort=True)
    try:
        response = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError):
        response = None
    if response != {"state": "submitted", "correlationId": corr}:
        return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
    return {"state": "submitted", "correlationId": corr, "replayAllowed": False}


def abort_status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"correlationId"} or not _canonical(value["correlationId"]):
        raise WindowsFixtureCredentialsError("Credential abort status requires exact correlation.")
    root = Path(root).resolve(strict=True); corr = value["correlationId"]
    unknown = {"state": "unknown", "correlationId": corr, "replayAllowed": False}
    record = _cleanup_intent(root, corr, group=_ABORT_GROUP)
    if record is None:
        return unknown
    request = record["request"]
    try:
        binding = _binding(root, request["leaseId"], request["stageCorrelationId"],
                           provision_correlation_id=corr, require_credentials="absent")
        if binding != record["binding"]:
            return unknown
        campaign = lease.inspect(root, request["leaseId"])
        if campaign.get("state") == "role-active" and campaign.get("role") == "credentials":
            finish = True
        elif campaign.get("state") == "active" and campaign.get("role") is None:
            finish = False
        else:
            return unknown
        observation = _observe_cleanup(root, request, binding, corr, abort=True)
        if observation["state"] == "running":
            return {"state": "running", "correlationId": corr, "replayAllowed": False}
        if finish:
            config, target, _ = base._descriptor(root)
            result = lease.finish_role(root, request["leaseId"], "credentials", corr,
                                       observation["receiptSha256"], "failed-cleaned",
                                       base._campaign_remote(config, target))
            if result.get("state") != "active":
                return unknown
    except (ValueError, OSError, KeyError):
        return unknown
    return {"state": "aborted-cleaned", "correlationId": corr,
            "cleanupReceiptSha256": observation["receiptSha256"], "replayAllowed": False}


def abort_collect(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    return abort_status(root, value)


def _canonical(value: Any) -> bool:
    return isinstance(value, str) and bool(_UUID.fullmatch(value)) and str(uuid.UUID(value)) == value


def _fixed_paths(stage_correlation_id: str) -> dict[str, str]:
    if not _canonical(stage_correlation_id):
        raise WindowsFixtureCredentialsError("Fixture stage correlation is invalid.")
    parent = _GUEST_ROOT + r"\mcp-update-credentials-" + stage_correlation_id
    return {"directory": parent, "certificate": parent + r"\server-cert.pem",
            "privateKey": parent + r"\server-key.pem",
            "trustStore": parent + r"\fixture-trust.p12"}


def _generate_material(*, now: datetime | None = None) -> dict[str, Any]:
    """Generate one short-lived leaf and JVM trust anchor in memory.

    The private key must be passed only over the fixed SSH/QGA stdin path. It
    must never enter argv, a local journal, an MCP response, or a system store.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import pkcs12
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except ImportError as error:
        raise WindowsFixtureCredentialsError("FIXTURE_CRYPTOGRAPHY_UNAVAILABLE") from error
    instant = now or datetime.now(timezone.utc)
    if instant.tzinfo is None:
        raise WindowsFixtureCredentialsError("Fixture certificate time is invalid.")
    instant = instant.astimezone(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "github.com")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(instant - timedelta(minutes=5))
            .not_valid_after(instant + timedelta(hours=24))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("github.com")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    key_bytes = key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption())
    trust_bytes = pkcs12.serialize_java_truststore(
        [pkcs12.PKCS12Certificate(cert, _ALIAS.encode("ascii"))],
        serialization.NoEncryption())
    parsed_trust = pkcs12.load_pkcs12(trust_bytes, password=None)
    if (not trust_bytes or key.public_key() != cert.public_key()
            or parsed_trust.key is not None or parsed_trust.cert is not None
            or len(parsed_trust.additional_certs) != 1
            or parsed_trust.additional_certs[0].certificate != cert):
        raise WindowsFixtureCredentialsError("Fixture certificate generation failed.")
    return {"certificate": cert_bytes, "privateKey": key_bytes, "trustStore": trust_bytes,
            "fileSha256": {name: hashlib.sha256(data).hexdigest() for name, data in
                           (("certificate", cert_bytes), ("privateKey", key_bytes),
                            ("trustStore", trust_bytes))},
            "peerCertificateSha256": hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
            "certificateValidFromUtc": int(cert.not_valid_before_utc.timestamp()),
            "certificateValidUntilUtc": int(cert.not_valid_after_utc.timestamp())}


def _ps_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _guest_fixed_ancestor_guard(path: str) -> str:
    """Check each fixed component before traversing the next one in the guest."""
    fixed = PureWindowsPath(path)
    root = PureWindowsPath(_GUEST_ROOT)
    if fixed != root and root not in fixed.parents:
        raise WindowsFixtureCredentialsError("Credential guard path is outside the fixed guest root.")
    components = list(reversed(fixed.parents)) + [fixed]
    return "".join(
        "$ancestor=Get-Item -LiteralPath " + _ps_literal(str(component)) + " -Force -ErrorAction Stop\n"
        "if(-not $ancestor.PSIsContainer -or ($ancestor.Attributes -band "
        "[IO.FileAttributes]::ReparsePoint) -ne 0){throw 'UNSAFE_ANCESTOR'}\n"
        for component in components
    )


def _guest_setup_script(paths: Mapping[str, str], sid: str) -> str:
    """SYSTEM creates a protected sibling; exact-source server-state stays empty."""
    return r'''$ErrorActionPreference='Stop'
$root=@ROOT@;$sid=@SID@
@ANCESTORS@
$allowed=@('S-1-5-18','S-1-5-32-544',$sid)
if([IO.Directory]::Exists($root) -or [IO.File]::Exists($root)){throw 'EXISTING_CREDENTIALS'}
$security=New-Object Security.AccessControl.DirectorySecurity
$security.SetAccessRuleProtection($true,$false)
$inherit=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
foreach($allowedSid in $allowed){
 $rule=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($allowedSid),
  [Security.AccessControl.FileSystemRights]::FullControl,$inherit,[Security.AccessControl.PropagationFlags]::None,
  [Security.AccessControl.AccessControlType]::Allow)
 [void]$security.AddAccessRule($rule)
}
[IO.Directory]::CreateDirectory($root,$security)|Out-Null
$created=Get-Item -LiteralPath $root -Force
if(-not $created.PSIsContainer -or ($created.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'CREATED_DIR'}
$actualAcl=Get-Acl -LiteralPath $root
$actualRules=@($actualAcl.Access)
if(-not $actualAcl.AreAccessRulesProtected -or $actualRules.Count -ne 3){throw 'CREATED_ACL'}
$seen=@()
foreach($actualRule in $actualRules){
 $actualSid=$actualRule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
 if($allowed -cnotcontains $actualSid -or $seen -ccontains $actualSid -or
  $actualRule.AccessControlType.ToString() -cne 'Allow' -or [int]$actualRule.FileSystemRights -ne 0x1F01FF -or
  $actualRule.IsInherited -or [int]$actualRule.InheritanceFlags -ne 3 -or
  [int]$actualRule.PropagationFlags -ne 0){throw 'CREATED_ACL'}
 $seen+=@($actualSid)
}
'''.replace("@ROOT@", _ps_literal(paths["directory"])).replace("@SID@", _ps_literal(sid)).replace(
        "@ANCESTORS@", _guest_fixed_ancestor_guard(_GUEST_ROOT))


def _guest_owner_task_script(binding: Mapping[str, Any], material: Mapping[str, Any],
                             paths: Mapping[str, str], provision_id: str) -> str:
    """Fixed limited original-user readback; outputs bounded provenance only."""
    template = r'''$ErrorActionPreference='Stop'
$root=@ROOT@;$sid=@SID@;$provenance=@PROVENANCE@
try {
 @ANCESTORS@
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 $limited=-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
 if($identity.User.Value -cne $sid -or (Get-Process -Id $PID).SessionId -ne 1 -or -not $limited){throw 'OWNER'}
 $paths=@{directory=$root;certificate=@CERT@;privateKey=@KEY@;trustStore=@TRUST@}
 $hashes=@{certificate=@CERT_HASH@;privateKey=@KEY_HASH@;trustStore=@TRUST_HASH@}
 foreach($name in @('certificate','privateKey','trustStore')){
  $item=Get-Item -LiteralPath $paths[$name] -Force
  if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
   (Get-FileHash -LiteralPath $paths[$name] -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hashes[$name]){throw 'HASH'}
 }
 $pem=[IO.File]::ReadAllText($paths.certificate)
 $match=[regex]::Match($pem,'-----BEGIN CERTIFICATE-----\s*(?<body>[A-Za-z0-9+/=\s]+)\s*-----END CERTIFICATE-----')
 if(-not $match.Success){throw 'CERT'}
 $der=[Convert]::FromBase64String(($match.Groups['body'].Value -replace '\s',''))
 $leaf=[Security.Cryptography.X509Certificates.X509Certificate2]::new($der)
 $leafHash=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($der)).Replace('-','').ToLowerInvariant()
 if($leafHash -cne @LEAF_HASH@ -or $leaf.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::DnsName,$false) -cne 'github.com') {throw 'CERT'}
 $now=[DateTime]::UtcNow
 if($leaf.NotBefore.ToUniversalTime() -gt $now -or $leaf.NotAfter.ToUniversalTime() -le $now){throw 'CERT_TIME'}
 # The host verified the certificate-only PKCS12 and sent its digest in the
 # fixed campaign. This original-user task rehashes the same bytes above.
 $acls=@{}
 foreach($name in @('directory','certificate','privateKey','trustStore')){
  $a=Get-Acl -LiteralPath $paths[$name]
  $rules=@($a.Access|ForEach-Object {[pscustomobject]@{sid=$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value;
   rights=[int]$_.FileSystemRights;type=$_.AccessControlType.ToString();inherited=$_.IsInherited;
   inheritance=[int]$_.InheritanceFlags;propagation=[int]$_.PropagationFlags}})
  $acls[$name]=[pscustomobject]@{path=$paths[$name];protected=$a.AreAccessRulesProtected;aces=$rules}
 }
 $receipt=[pscustomobject]@{schemaVersion=1;provisionId=@PROVISION@;leaseId=@LEASE@;stageCorrelationId=@STAGE@;
  sourceSha=@SOURCE@;sourceFingerprint=@FINGERPRINT@;fixtureReceiptArtifactId=@RECEIPT@;
  baseMsiArtifactId=@BASE@;targetMsiArtifactId=@TARGET@;socketPath=@SOCKET@;qemuPid=@QEMU_PID@;
  startTicks=@TICKS@;originalSid=$identity.User.Value;sessionId=1;limited=$limited;paths=$paths;
  fileSha256=$hashes;peerCertificateSha256=$leafHash;certificateDnsNames=@('github.com');
  certificateServerAuth=$true;certificateValidFromUtc=@VALID_FROM@;certificateValidUntilUtc=@VALID_UNTIL@;
  privateKeyMatchesCertificate=$true;trustStoreType='PKCS12';trustStoreContainsCertificate=$true;
  trustStoreAlias='vpn-control-fixture-github';acls=$acls}
 $json=$receipt|ConvertTo-Json -Depth 9 -Compress
 if($json.Length -gt 12000){throw 'RECEIPT_SIZE'}
 [IO.File]::WriteAllText($provenance,$json,[Text.UTF8Encoding]::new($false))
 $fileAcl=Get-Acl -LiteralPath $paths.certificate
 Set-Acl -LiteralPath $provenance -AclObject $fileAcl
 exit 0
}catch{exit 1}
'''
    values = {"ROOT": paths["directory"], "SID": binding["originalSid"],
              "PROVENANCE": paths["directory"] + r"\provenance.json", "CERT": paths["certificate"],
              "KEY": paths["privateKey"], "TRUST": paths["trustStore"],
              "CERT_HASH": material["fileSha256"]["certificate"],
              "KEY_HASH": material["fileSha256"]["privateKey"],
              "TRUST_HASH": material["fileSha256"]["trustStore"],
              "LEAF_HASH": material["peerCertificateSha256"], "PROVISION": provision_id,
              "LEASE": binding["leaseId"], "STAGE": binding["stageCorrelationId"],
              "SOURCE": binding["sourceSha"], "FINGERPRINT": binding["sourceFingerprint"],
              "RECEIPT": binding["fixtureReceiptArtifactId"],
              "BASE": binding["baseMsiArtifactId"], "TARGET": binding["targetMsiArtifactId"],
              "SOCKET": binding["socketPath"], "QEMU_PID": binding["qemuPid"],
              "TICKS": binding["startTicks"],
              "VALID_FROM": material["certificateValidFromUtc"],
              "VALID_UNTIL": material["certificateValidUntilUtc"]}
    for name, value in values.items():
        template = template.replace("@" + name + "@", str(value) if type(value) is int else _ps_literal(value))
    return template.replace("@ANCESTORS@", _guest_fixed_ancestor_guard(paths["directory"]))


def _guest_finalize_script(binding: Mapping[str, Any], material: Mapping[str, Any],
                           paths: Mapping[str, str], provision_id: str,
                           correlation_id: str) -> str:
    owner = _guest_owner_task_script(binding, material, paths, provision_id)
    encoded = base64.b64encode(gzip.compress(owner.encode("utf-16le"), mtime=0)).decode("ascii")
    if len(encoded) > 30000:
        raise WindowsFixtureCredentialsError("Credential owner task is too large.")
    task = "VpnControlFixtureCredentials-" + correlation_id
    script = r'''$ErrorActionPreference='Stop'
$root=@ROOT@;$sid=@SID@;$task=@TASK@
@ANCESTORS@
$paths=@(@CERT@,@KEY@,@TRUST@)
if(-not [IO.Directory]::Exists($root) -or (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue)){throw 'EXISTING_TASK'}
foreach($path in $paths){
 $file=Get-Item -LiteralPath $path -Force
 if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'FILE'}
 $security=New-Object Security.AccessControl.FileSecurity
 $security.SetAccessRuleProtection($true,$false)
 foreach($allowedSid in @('S-1-5-18','S-1-5-32-544',$sid)){
  $rule=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($allowedSid),
   [Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow)
  [void]$security.AddAccessRule($rule)
 }
 Set-Acl -LiteralPath $path -AclObject $security
}
$packed=[Convert]::FromBase64String(@BODY@)
$inputStream=[IO.MemoryStream]::new([byte[]]$packed)
$decompressor=[IO.Compression.GzipStream]::new($inputStream,[IO.Compression.CompressionMode]::Decompress)
$outputStream=[IO.MemoryStream]::new();$decompressor.CopyTo($outputStream)
$body=[Convert]::ToBase64String($outputStream.ToArray())
$decompressor.Dispose();$inputStream.Dispose();$outputStream.Dispose()
$action=New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument ('-NoProfile -NonInteractive -EncodedCommand '+$body)
$principal=New-ScheduledTaskPrincipal -UserId 'VPNMSIX64\vpncp117' -LogonType Interactive -RunLevel Limited
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings|Out-Null
Start-ScheduledTask -TaskName $task
'''
    for name, value in {"ROOT": paths["directory"], "SID": binding["originalSid"],
                        "TASK": task, "CERT": paths["certificate"],
                        "KEY": paths["privateKey"], "TRUST": paths["trustStore"],
                        "BODY": encoded}.items():
        script = script.replace("@" + name + "@", _ps_literal(value))
    script = script.replace("@ANCESTORS@", _guest_fixed_ancestor_guard(paths["directory"]))
    if len(base64.b64encode(script.encode("utf-16le"))) > 30000:
        raise WindowsFixtureCredentialsError("Credential task bootstrap is too large.")
    return script


def _guest_observe_script(paths: Mapping[str, str], correlation_id: str) -> str:
    """SYSTEM readback of current bytes/ACL and terminal owner task."""
    template = r'''$ErrorActionPreference='Stop'
try {
 $paths=@{directory=@ROOT@;certificate=@CERT@;privateKey=@KEY@;trustStore=@TRUST@}
 @ANCESTORS@
 $taskName=@TASK@
 $task=Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
 $info=Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
 $hashes=@{};$acls=@{}
 foreach($name in @('certificate','privateKey','trustStore')){
  $item=Get-Item -LiteralPath $paths[$name] -Force
  if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'FILE'}
  $hashes[$name]=(Get-FileHash -LiteralPath $paths[$name] -Algorithm SHA256).Hash.ToLowerInvariant()
 }
 foreach($name in @('directory','certificate','privateKey','trustStore')){
  $acl=Get-Acl -LiteralPath $paths[$name]
  $rules=@($acl.Access|ForEach-Object {[pscustomobject]@{sid=$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value;
   rights=[int]$_.FileSystemRights;type=$_.AccessControlType.ToString();inherited=$_.IsInherited;
   inheritance=[int]$_.InheritanceFlags;propagation=[int]$_.PropagationFlags}})
  $acls[$name]=[pscustomobject]@{path=$paths[$name];protected=$acl.AreAccessRulesProtected;aces=$rules}
 }
 $provenance=@PROVENANCE@
 $item=Get-Item -LiteralPath $provenance -Force
 if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -gt 12000){throw 'PROVENANCE'}
 $pAcl=Get-Acl -LiteralPath $provenance
 $pRules=@($pAcl.Access|ForEach-Object {[pscustomobject]@{sid=$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value;
  rights=[int]$_.FileSystemRights;type=$_.AccessControlType.ToString();inherited=$_.IsInherited;
  inheritance=[int]$_.InheritanceFlags;propagation=[int]$_.PropagationFlags}})
 $receipt=[pscustomobject]@{schemaVersion=1;taskState=$task.State.ToString();taskLastResult=[int]$info.LastTaskResult;
  fileSha256=$hashes;acls=$acls;provenanceAcl=[pscustomobject]@{path=$provenance;protected=$pAcl.AreAccessRulesProtected;aces=$pRules}}
 $receipt|ConvertTo-Json -Depth 8 -Compress
}catch{exit 1}
'''
    values = {"ROOT": paths["directory"], "CERT": paths["certificate"],
              "KEY": paths["privateKey"], "TRUST": paths["trustStore"],
              "PROVENANCE": paths["directory"] + r"\provenance.json",
              "TASK": "VpnControlFixtureCredentials-" + correlation_id}
    for name, value in values.items():
        template = template.replace("@" + name + "@", _ps_literal(value))
    return template.replace("@ANCESTORS@", _guest_fixed_ancestor_guard(paths["directory"]))


def _guest_cleanup_script(paths: Mapping[str, str], provision_correlation_id: str) -> str:
    """SYSTEM removes only the one exact credential generation, never stage data."""
    template = r'''$ErrorActionPreference='Stop'
$root=@ROOT@;$taskName=@TASK@
@ANCESTORS@
$item=Get-Item -LiteralPath $root -Force
if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'ROOT'}
$allowed=@('server-cert.pem','server-key.pem','fixture-trust.p12','provenance.json')
$files=@(Get-ChildItem -LiteralPath $root -Force)
if($files.Count -ne 4){throw 'FILE_COUNT'}
foreach($file in $files){
 if($allowed -cnotcontains $file.Name -or $file.PSIsContainer -or
  ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'FILE_INVENTORY'}
}
$task=Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
if($task.State.ToString() -cne 'Ready'){throw 'TASK_ACTIVE'}
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
foreach($name in $allowed){Remove-Item -LiteralPath (Join-Path $root $name) -Force}
[IO.Directory]::Delete($root)
'''
    return template.replace("@ROOT@", _ps_literal(paths["directory"])).replace(
        "@TASK@", _ps_literal("VpnControlFixtureCredentials-" + provision_correlation_id)).replace(
        "@ANCESTORS@", _guest_fixed_ancestor_guard(paths["directory"]))


def _guest_abort_script(paths: Mapping[str, str], provision_correlation_id: str,
                        sid: str) -> str:
    """Remove a partial generation while the original credentials role is held."""
    template = r'''$ErrorActionPreference='Stop'
$root=@ROOT@;$taskName=@TASK@;$sid=@SID@
@ANCESTORS@
$task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if($null -ne $task -and $task.State.ToString() -cne 'Ready'){throw 'TASK_ACTIVE'}
if([IO.File]::Exists($root)){throw 'ROOT_FILE'}
if([IO.Directory]::Exists($root)){
 @ROOT_ANCESTORS@
 $item=Get-Item -LiteralPath $root -Force
 if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'ROOT_REPARSE'}
 $acl=Get-Acl -LiteralPath $root
 $rules=@($acl.Access)
 if(-not $acl.AreAccessRulesProtected -or $rules.Count -ne 3){throw 'ROOT_ACL'}
 $allowedSids=@('S-1-5-18','S-1-5-32-544',$sid)
 foreach($rule in $rules){
  if($allowedSids -cnotcontains $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -or
   $rule.AccessControlType.ToString() -cne 'Allow' -or [int]$rule.FileSystemRights -ne 0x1F01FF -or
   $rule.IsInherited){throw 'ROOT_ACL'}
 }
 $allowed=@('server-cert.pem','server-key.pem','fixture-trust.p12','provenance.json')
 foreach($file in @(Get-ChildItem -LiteralPath $root -Force)){
  if($allowed -cnotcontains $file.Name -or $file.PSIsContainer -or
   ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'FILE_INVENTORY'}
 }
}
if($null -ne $task){Unregister-ScheduledTask -TaskName $taskName -Confirm:$false}
if([IO.Directory]::Exists($root)){
 foreach($file in @(Get-ChildItem -LiteralPath $root -Force)){
  Remove-Item -LiteralPath $file.FullName -Force
 }
 [IO.Directory]::Delete($root)
}
'''
    for name, value in {"ROOT": paths["directory"],
                        "TASK": "VpnControlFixtureCredentials-" + provision_correlation_id,
                        "SID": sid}.items():
        template = template.replace("@" + name + "@", _ps_literal(value))
    return template.replace("@ANCESTORS@", _guest_fixed_ancestor_guard(_GUEST_ROOT)).replace(
        "@ROOT_ANCESTORS@", _guest_fixed_ancestor_guard(paths["directory"]))


def _guest_cleanup_observe_script(paths: Mapping[str, str], provision_correlation_id: str,
                                  stage_correlation_id: str) -> str:
    template = r'''$ErrorActionPreference='Stop'
$root=@ROOT@;$taskName=@TASK@;$stage=@STAGE@
@ANCESTORS@
$absent=(-not [IO.Directory]::Exists($root) -and -not [IO.File]::Exists($root))
$taskAbsent=($null -eq (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue))
([pscustomobject]@{schemaVersion=1;credentialDirectoryAbsent=$absent;taskAbsent=$taskAbsent;
 stagePresent=$true;stageCorrelationId=@CORR@}|ConvertTo-Json -Compress)
'''
    stage_path = _GUEST_ROOT + r"\mcp-update-fixture-" + stage_correlation_id
    for name, value in {"ROOT": paths["directory"], "TASK": "VpnControlFixtureCredentials-" + provision_correlation_id,
                        "STAGE": stage_path, "CORR": stage_correlation_id}.items():
        template = template.replace("@" + name + "@", _ps_literal(value))
    return template.replace("@ANCESTORS@", _guest_fixed_ancestor_guard(_GUEST_ROOT) +
                            _guest_fixed_ancestor_guard(stage_path))


def _binding(root: Path, lease_id: str, stage_correlation_id: str, *,
             provision_correlation_id: str | None = None,
             cleanup_correlation_id: str | None = None,
             require_credentials: str = "absent") -> dict[str, Any]:
    """Read the exact campaign, stage, and live QEMU generation before any use."""
    if not _canonical(lease_id) or not _canonical(stage_correlation_id) or lease_id == stage_correlation_id:
        raise WindowsFixtureCredentialsError("Fixture credential identity is invalid.")
    root = Path(root).resolve(strict=True)
    config, target, guest = base._descriptor(root)
    env, socket, pid, ticks, sid = guest
    if env != "windows-cp117" or not isinstance(sid, str) or not _SID.fullmatch(sid):
        raise WindowsFixtureCredentialsError("Original CP117 owner changed.")
    staged = stage.status(root, {"correlationId": stage_correlation_id})
    if staged.get("state") != "staged-not-server-ready":
        raise WindowsFixtureCredentialsError("Exact fixture stage is unavailable.")
    stage_intent = stage._read_intent(root, stage_correlation_id)
    if not isinstance(stage_intent, dict) or stage_intent.get("leaseId") != lease_id:
        raise WindowsFixtureCredentialsError("Fixture stage campaign changed.")
    directory, lock = lease._locked(root)
    try:
        current = lease._active(directory)
        in_provision = (isinstance(current, dict) and provision_correlation_id is not None and
                        current.get("state") == "role-active" and
                        current.get("role") == "credentials" and
                        current.get("correlationId") == provision_correlation_id)
        in_cleanup = (isinstance(current, dict) and cleanup_correlation_id is not None and
                      current.get("state") == "role-active" and
                      current.get("role") == "credentials-cleanup" and
                      current.get("correlationId") == cleanup_correlation_id)
        idle = (isinstance(current, dict) and current.get("state") == "active"
                and current.get("role") is None)
        live_use = (isinstance(current, dict) and require_credentials == "ready"
                    and current.get("state") == "role-active"
                    and current.get("role") in {"server-start", "owner-network", "network-probe",
                                                "target", "public", "server-stop"})
        admissible_server = ({"stopped", "starting", "live", "stopping"}
                             if require_credentials == "ready" and not in_cleanup else {"stopped"})
        if (not isinstance(current, dict) or not (idle or in_provision or in_cleanup or live_use)
                or current.get("server") not in admissible_server
                or current.get("credentials") != require_credentials):
            raise WindowsFixtureCredentialsError("CP117 credential campaign is not idle.")
        identity = current.get("identity")
        if (not isinstance(identity, dict) or identity.get("leaseId") != lease_id
                or identity.get("host") != "archlinux" or identity.get("environment") != env
                or identity.get("operator") != "windows-base"
                or identity.get("sourceSha") != staged.get("sourceSha")
                or any(stage_intent["request"].get(name) != identity.get(name) for name in
                       ("sourceSha", "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId"))
                or identity.get("socketPath") != socket or identity.get("qemuPid") != pid
                or identity.get("startTicks") != ticks
                or identity.get("targetMsiArtifactId", "").removeprefix("sha256-")
                != staged.get("targetMsiSha256")):
            raise WindowsFixtureCredentialsError("CP117 credential campaign identity changed.")
        if not lease._remote_confirm(base._campaign_remote(config, target), "status", current, None):
            raise WindowsFixtureCredentialsError("CP117 remote campaign is unverified.")
    finally:
        os.close(lock)
    pair = public._admit_pair(root, identity["sourceSha"], identity["fixtureReceiptArtifactId"],
                              identity["baseMsiArtifactId"], identity["targetMsiArtifactId"])
    if pair["sourceFingerprint"] != stage_intent["sourceFingerprint"]:
        raise WindowsFixtureCredentialsError("Fixture source fingerprint changed.")
    return {"leaseId": lease_id, "stageCorrelationId": stage_correlation_id,
            "sourceSha": identity["sourceSha"], "sourceFingerprint": pair["sourceFingerprint"],
            "fixtureReceiptArtifactId": identity["fixtureReceiptArtifactId"],
            "baseMsiArtifactId": identity["baseMsiArtifactId"],
            "targetMsiArtifactId": identity["targetMsiArtifactId"],
            "socketPath": socket, "qemuPid": pid, "startTicks": ticks,
            "originalSid": sid, "sessionId": 1, "limited": True}


def _valid_acl(receipt: Any, path: str, sid: str, *, directory: bool) -> bool:
    if (not isinstance(receipt, dict) or set(receipt) != {"path", "protected", "aces"}
            or receipt["path"] != path or receipt["protected"] is not True
            or not isinstance(receipt["aces"], list) or len(receipt["aces"]) != 3):
        return False
    observed = set()
    for ace in receipt["aces"]:
        if (not isinstance(ace, dict) or set(ace) != {"sid", "rights", "type", "inherited",
                                                     "inheritance", "propagation"}
                or ace["sid"] not in {"S-1-5-18", "S-1-5-32-544", sid}
                or ace["sid"] in observed or ace["rights"] != 0x1F01FF
                or ace["type"] != "Allow" or ace["inherited"] is not False
                or ace["inheritance"] != (3 if directory else 0) or ace["propagation"] != 0):
            return False
        observed.add(ace["sid"])
    return observed == {"S-1-5-18", "S-1-5-32-544", sid}


def _validate_observation(binding: Mapping[str, Any], observed: Mapping[str, Any], *, now: int) -> dict[str, Any]:
    """Validate a future trusted QGA readback, never caller-supplied proof."""
    fields = set(binding) | {"schemaVersion", "provisionId", "paths", "fileSha256",
                             "peerCertificateSha256", "certificateDnsNames", "certificateServerAuth",
                             "certificateValidFromUtc", "certificateValidUntilUtc",
                             "privateKeyMatchesCertificate", "trustStoreType",
                             "trustStoreContainsCertificate", "trustStoreAlias", "acls"}
    if (not isinstance(observed, Mapping) or set(observed) != fields or
            any(observed.get(key) != value for key, value in binding.items()) or
            observed["schemaVersion"] != 1 or not _canonical(observed["provisionId"])):
        raise WindowsFixtureCredentialsError("Credential provenance identity changed.")
    paths = _fixed_paths(binding["stageCorrelationId"])
    if observed["paths"] != paths:
        raise WindowsFixtureCredentialsError("Credential path escaped the fixed private stage.")
    hashes = observed["fileSha256"]
    if (not isinstance(hashes, dict) or set(hashes) != {"certificate", "privateKey", "trustStore"}
            or any(not isinstance(value, str) or not _HASH.fullmatch(value) for value in hashes.values())
            or not isinstance(observed["peerCertificateSha256"], str)
            or not _HASH.fullmatch(observed["peerCertificateSha256"])):
        raise WindowsFixtureCredentialsError("Credential bytes are unverified.")
    if (observed["certificateDnsNames"] != ["github.com"]
            or observed["certificateServerAuth"] is not True
            or observed["privateKeyMatchesCertificate"] is not True
            or observed["trustStoreType"] != "PKCS12"
            or observed["trustStoreContainsCertificate"] is not True
            or observed["trustStoreAlias"] != _ALIAS
            or type(now) is not int or type(observed["certificateValidFromUtc"]) is not int
            or type(observed["certificateValidUntilUtc"]) is not int
            or not observed["certificateValidFromUtc"] <= now < observed["certificateValidUntilUtc"]):
        raise WindowsFixtureCredentialsError("Credential certificate or JVM trust is unverified.")
    acls = observed["acls"]
    if (not isinstance(acls, dict) or set(acls) != set(paths)
            or any(not _valid_acl(acls[name], path, binding["originalSid"], directory=name == "directory")
                   for name, path in paths.items())):
        raise WindowsFixtureCredentialsError("Credential ACL is not owner-private.")
    return {"provisionId": observed["provisionId"], "paths": paths,
            "certificateSha256": hashes["certificate"],
            "privateKeySha256": hashes["privateKey"],
            "trustStoreSha256": hashes["trustStore"],
            "peerCertificateSha256": observed["peerCertificateSha256"]}


def _trusted_readback(root: Path, binding: Mapping[str, Any]) -> dict[str, Any]:
    try:
        record = _provision_record(root, binding)
    except WindowsFixtureCredentialsError as error:
        raise WindowsFixtureCredentialsError("FIXTURE_CREDENTIAL_PROVENANCE_READBACK_UNAVAILABLE") from error
    if (record is None or record["binding"] != binding or record["request"]["leaseId"] != binding["leaseId"]
            or record["request"]["stageCorrelationId"] != binding["stageCorrelationId"]):
        raise WindowsFixtureCredentialsError("FIXTURE_CREDENTIAL_PROVENANCE_READBACK_UNAVAILABLE")
    return _remote_observe(root, record["request"], binding, record)["observation"]


def verified_descriptor(root: Path | str, lease_id: str, stage_correlation_id: str) -> dict[str, Any]:
    """Internal server join point. Static local receipts never establish trust."""
    if not _canonical(lease_id) or not _canonical(stage_correlation_id):
        raise WindowsFixtureCredentialsError("Fixture credential identity is invalid.")
    root = Path(root).resolve(strict=True)
    binding = _binding(root, lease_id, stage_correlation_id, require_credentials="ready")
    observed = _trusted_readback(root, binding)
    import time
    return _validate_observation(binding, observed, now=int(time.time()))

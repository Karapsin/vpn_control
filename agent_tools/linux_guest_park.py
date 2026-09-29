"""One-shot, exact-generation graceful park for four disposable Linux guests.

Parking releases QEMU memory only. Preparation and acceptance role claims and
all evidence remain in place. No force stop, guest restart, or replay exists.
"""
from __future__ import annotations

import json
import hashlib
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

try:
    from . import ssh_transport
except ImportError:  # pragma: no cover - direct MCP fallback
    import ssh_transport  # type: ignore[no-redef]


_ROLES = {"ubuntu-fresh": ("ubuntu", "fresh-deb-dependencies", 2330),
          "ubuntu-update": ("ubuntu", "package-update", 2331),
          "arch-update": ("arch", "package-update", 2332),
          "arch-rollback": ("arch", "arch-rollback", 2333)}
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_JOURNAL = "linux-guest-park"


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def _canonical(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


@dataclass(frozen=True)
class Intent:
    correlation_id: str
    preparation_correlation_id: str
    guest_role: str
    source_sha: str
    qemu_pid: int
    qemu_start_ticks: int
    disk_device: int
    disk_inode: int
    qmp_inode: int

    @classmethod
    def from_evidence(cls, raw: Mapping[str, Any], guest: Mapping[str, Any],
                      receipt: Mapping[str, Any], qmp_inode: int) -> "Intent":
        _need(set(raw) == {"correlationId", "preparationCorrelationId", "guestRole", "sourceSha"},
              "Park request schema differs")
        role = raw.get("guestRole")
        _need(isinstance(role, str) and role in _ROLES, "Park role is not fixed")
        distro, profile, port = _ROLES[role]
        tree = "/home/kardinal/vpn-control-install-vm-parity-" + role
        _need(all(isinstance(raw.get(k), str) for k in raw) and
              _UUID.fullmatch(raw["correlationId"]) is not None and
              _UUID.fullmatch(raw["preparationCorrelationId"]) is not None and
              raw["correlationId"] != raw["preparationCorrelationId"] and
              _SHA.fullmatch(raw["sourceSha"]) is not None,
              "Park correlation or source is invalid")
        _need(guest.get("schemaVersion") == 1 and guest.get("host") == "archlinux" and
              guest.get("guestRole") == role and guest.get("distribution") == distro and
              guest.get("profile") == profile and guest.get("tree") == tree and
              guest.get("sshPort") == port and guest.get("sourceSha") == raw["sourceSha"] and
              guest.get("pristine") is True,
              "Park guest manifest differs")
        generation = {"pid": guest.get("qemuPid"), "startTicks": guest.get("qemuStartTicks"),
                      "diskDevice": guest.get("diskDevice"), "diskInode": guest.get("diskInode"),
                      "sshPort": port, "tree": tree}
        _need(receipt.get("schemaVersion") == 1 and receipt.get("host") == "archlinux" and
              receipt.get("state") == "ready" and receipt.get("guestRole") == role and
              receipt.get("profile") == profile and receipt.get("distribution") == distro and
              receipt.get("correlationId") == raw["preparationCorrelationId"] and
              receipt.get("sourceSha") == raw["sourceSha"] and receipt.get("qemu") == generation and
              receipt.get("safety") == {"ownerRuntimeOff": True,
                  "protectedJobsTerminal": True, "rootOwnedStage": True} and
              all(type(generation[k]) is int and generation[k] > 0 for k in
                  ("pid", "startTicks", "diskDevice", "diskInode")) and
              type(qmp_inode) is int and qmp_inode > 0,
              "Park preparation receipt or generation differs")
        return cls(raw["correlationId"], raw["preparationCorrelationId"], role,
                   raw["sourceSha"], generation["pid"], generation["startTicks"],
                   generation["diskDevice"], generation["diskInode"], qmp_inode)

    def public(self) -> dict[str, Any]:
        return {"correlationId": self.correlation_id,
                "preparationCorrelationId": self.preparation_correlation_id,
                "guestRole": self.guest_role, "sourceSha": self.source_sha,
                "qemuPid": self.qemu_pid, "qemuStartTicks": self.qemu_start_ticks,
                "diskDevice": self.disk_device, "diskInode": self.disk_inode,
                "qmpInode": self.qmp_inode}


class Driver(Protocol):
    def preflight(self, intent: Mapping[str, Any]) -> Mapping[str, Any]: ...
    def start(self, intent: Mapping[str, Any]) -> Mapping[str, Any]: ...
    def status(self, intent: Mapping[str, Any]) -> Mapping[str, Any]: ...


def load_prepared_evidence(root: Path, raw: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load only sealed, source-bound local preparation evidence for one fixed role."""
    from agent_tools import linux_deb_arch_guest_prepare as prep, native_artifact_registry

    corr = raw.get("preparationCorrelationId")
    role = raw.get("guestRole")
    source = raw.get("sourceSha")
    _need(isinstance(corr, str) and _UUID.fullmatch(corr) is not None and
          isinstance(role, str) and role in _ROLES and
          isinstance(source, str) and _SHA.fullmatch(source) is not None,
          "Park preparation identity is invalid")
    stored = prep._read(root, corr)
    _need(isinstance(stored, dict) and stored.get("correlationId") == corr and
          stored.get("sourceSha") == source, "Park preparation journal differs")
    request = prep.Request.parse({key: stored[key] for key in
        ("profile", "distribution", "correlationId", "sourceSha", "artifactIds")})
    _need(request.public_mapping() == stored and request.guest_role == role and
          prep._role_claim_matches(root, request),
          "Park preparation role claim differs")
    directory = prep._journal_dir(root, create=False)
    _need(directory is not None, "Park preparation evidence is absent")
    evidence = directory / corr
    _need(_private_dir(evidence), "Park preparation evidence is absent")
    result = []
    for name, kind in (("guest-manifest.json", "guest-manifest"),
                       ("preparation-receipt.json", "linux-guest-preparation")):
        path = evidence / name
        value = _read(path, 16384)
        raw_bytes = _canonical(value)
        identifier = "sha256-" + hashlib.sha256(raw_bytes).hexdigest()
        verified = native_artifact_registry.verify_artifact(root, identifier)
        artifact = verified.get("artifact", {})
        location = verified.get("location", {})
        _need(verified.get("verification") == "verified" and
              artifact.get("artifactId") == identifier and
              artifact.get("platform") == "linux" and
              artifact.get("artifactKind") == kind and
              artifact.get("sourceSha") == source and
              location.get("localPath") == str(path.resolve(strict=True)) and
              location.get("evidenceClass") == "local-verified" and
              verified.get("observedSha256") == identifier.removeprefix("sha256-"),
              "Park preparation artifact is not verified")
        result.append(value)
    guest, receipt = result
    _need(receipt.get("guestManifestArtifactId") ==
          "sha256-" + hashlib.sha256(_canonical(guest)).hexdigest(),
          "Park preparation receipt references a different manifest")
    return guest, receipt


def _private_dir(path: Path, create: bool = False) -> bool:
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
          stat.S_IMODE(info.st_mode) == 0o700, "Park journal directory is unsafe")
    return True


def _journal(root: Path, create: bool) -> Path | None:
    index = root / ".rag_index"
    if not _private_dir(index, create):
        return None
    directory = index / _JOURNAL
    return directory if _private_dir(directory, create) else None


def _read(path: Path, limit: int = 2048) -> dict[str, Any]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
              stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= limit,
              "Park journal file is unsafe")
        raw = os.read(fd, info.st_size + 1)
        _need(len(raw) == info.st_size, "Park journal changed")
        value = json.loads(raw)
        _need(isinstance(value, dict), "Park journal schema differs")
        return value
    finally:
        os.close(fd)


def _write_once(path: Path, value: Mapping[str, Any]) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(_canonical(value)); stream.flush(); os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


class Adapter:
    """Local durable intent and response-loss boundary for an injected fixed driver."""

    def __init__(self, root: Path | str, *, driver: Driver | None = None):
        self.root = Path(root).resolve(strict=True)
        self.driver = driver

    def _admit(self, raw: Mapping[str, Any]) -> Intent:
        _need(self.driver is not None, "Park fixed driver is unavailable")
        guest, receipt = load_prepared_evidence(self.root, raw)
        provisional = Intent.from_evidence(raw, guest, receipt, 1)
        pre = self.driver.preflight(provisional.public())
        _need(pre.get("ready") is True and pre.get("ownerRuntimeOff") is True and
              pre.get("packageProcessesOff") is True and
              pre.get("protectedJobsTerminal") is True and
              all(pre.get(field) == value for field, value in
                  (("qemuPid", provisional.qemu_pid),
                   ("qemuStartTicks", provisional.qemu_start_ticks),
                   ("diskDevice", provisional.disk_device),
                   ("diskInode", provisional.disk_inode))),
              "Park preflight is not idle or exact")
        return Intent.from_evidence(raw, guest, receipt, pre.get("qmpInode"))

    def preflight(self, raw: Mapping[str, Any]) -> dict[str, Any]:
        corr = raw.get("correlationId")
        _need(isinstance(corr, str) and _UUID.fullmatch(corr) is not None,
              "Park correlation is invalid")
        directory = _journal(self.root, False)
        if directory is not None and (directory / (corr + ".json")).exists():
            return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
        try:
            intent = self._admit(raw)
        except (ValueError, TypeError, KeyError, OSError, TimeoutError):
            return {"state": "blocked", "correlationId": corr, "reason": "admission-failed"}
        return {"state": "ready", **intent.public(), "ownerRuntimeOff": True,
                "packageProcessesOff": True, "protectedJobsTerminal": True,
                "nativeActionAllowed": False}

    def start(self, raw: Mapping[str, Any]) -> dict[str, Any]:
        corr = raw.get("correlationId")
        _need(isinstance(corr, str) and _UUID.fullmatch(corr) is not None,
              "Park correlation is invalid")
        directory = _journal(self.root, False)
        if directory is not None and (directory / (corr + ".json")).exists():
            return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
        try:
            intent = self._admit(raw)
        except (ValueError, TypeError, KeyError, OSError, TimeoutError):
            return {"state": "blocked", "correlationId": corr, "reason": "admission-failed"}
        directory = _journal(self.root, True)
        assert directory is not None
        try:
            _write_once(directory / (intent.guest_role + ".claim"),
                        {"guestRole": intent.guest_role,
                         "correlationId": intent.correlation_id,
                         "preparationCorrelationId": intent.preparation_correlation_id,
                         "sourceSha": intent.source_sha})
            _write_once(directory / (corr + ".json"), intent.public())
        except FileExistsError:
            return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
        try:
            result = self.driver.start(intent.public())
        except Exception:
            return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
        try:
            return self._result(intent, result)
        except (AttributeError, TypeError):
            return {"state": "unknown", "correlationId": corr, "replayAllowed": False}

    def status(self, correlation: str) -> dict[str, Any]:
        _need(isinstance(correlation, str) and _UUID.fullmatch(correlation) is not None,
              "Park status correlation is invalid")
        directory = _journal(self.root, False)
        if directory is None:
            return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
        try:
            stored = _read(directory / (correlation + ".json"))
            _need(stored.get("correlationId") == correlation and self.driver is not None,
                  "Park intent differs")
            intent = Intent(**{name: stored[key] for name, key in
                (("correlation_id", "correlationId"),
                 ("preparation_correlation_id", "preparationCorrelationId"),
                 ("guest_role", "guestRole"), ("source_sha", "sourceSha"),
                 ("qemu_pid", "qemuPid"), ("qemu_start_ticks", "qemuStartTicks"),
                 ("disk_device", "diskDevice"), ("disk_inode", "diskInode"),
                 ("qmp_inode", "qmpInode"))})
            _need(intent.public() == stored, "Park intent schema differs")
            claim = _read(directory / (intent.guest_role + ".claim"), 512)
            _need(claim == {"guestRole": intent.guest_role,
                            "correlationId": intent.correlation_id,
                            "preparationCorrelationId": intent.preparation_correlation_id,
                            "sourceSha": intent.source_sha}, "Park role claim differs")
            return self._result(intent, self.driver.status(stored))
        except (OSError, ValueError, KeyError, TypeError, AttributeError, TimeoutError):
            return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}

    @staticmethod
    def _result(intent: Intent, result: Mapping[str, Any]) -> dict[str, Any]:
        if (result.get("state") == "parked" and
                result.get("correlationId") == intent.correlation_id and
                result.get("qemuPid") == intent.qemu_pid and
                result.get("qemuStartTicks") == intent.qemu_start_ticks and
                result.get("diskDevice") == intent.disk_device and
                result.get("diskInode") == intent.disk_inode and
                result.get("qmpInode") == intent.qmp_inode and
                result.get("ownerRuntimeOff") is True and
                result.get("terminalAbsence") is True):
            return {"state": "parked", **intent.public(), "ownerRuntimeOff": True,
                    "terminalAbsence": True, "replayAllowed": False}
        return {"state": "unknown", "correlationId": intent.correlation_id,
                "replayAllowed": False}


# Executed only on the fixed archlinux SSH alias. All paths, ports, and role
# names below are fixed; the argument carries only identities to compare.
_REMOTE = r'''import json,os,pwd,re,shlex,socket,stat,struct,subprocess,sys,time
mode=sys.argv[1]; intent=json.loads(sys.argv[2]);role=intent['guestRole']
if os.geteuid()!=0:raise SystemExit(2)
OWNER=pwd.getpwnam('kardinal').pw_uid;PARK_OWNER=0
roles={'ubuntu-fresh':2330,'ubuntu-update':2331,'arch-update':2332,'arch-rollback':2333}
if mode not in ('preflight','start','status') or role not in roles:raise SystemExit(2)
if set(intent)!={'correlationId','preparationCorrelationId','guestRole','sourceSha','qemuPid','qemuStartTicks','diskDevice','diskInode','qmpInode'}:raise SystemExit(2)
if not re.fullmatch('[0-9a-f]{40}',intent['sourceSha']):raise SystemExit(2)
for key in ('correlationId','preparationCorrelationId'):
 if not re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',intent[key]):raise SystemExit(2)
for key in ('qemuPid','qemuStartTicks','diskDevice','diskInode','qmpInode'):
 if type(intent[key]) is not int or intent[key]<=0:raise SystemExit(2)
tree='/home/kardinal/vpn-control-install-vm-parity-'+role;disk=tree+'/task.qcow2';qmp=tree+'/qmp.sock';port=roles[role]
root='/home/kardinal/.vpn-control-parity-prepare';parkroot='/home/kardinal/.vpn-control-parity-park'
def safe(path,kind,owner=None):
 cur='/'
 for part in path.strip('/').split('/'):
  cur=os.path.join(cur,part);info=os.lstat(cur)
  if stat.S_ISLNK(info.st_mode):raise ValueError('symlink')
 info=os.lstat(path)
 if not (stat.S_ISDIR if kind=='dir' else stat.S_ISREG if kind=='file' else stat.S_ISSOCK)(info.st_mode):raise ValueError('kind')
 if owner is not None and (info.st_uid!=owner or info.st_mode & 0o022):raise ValueError('owner')
 return info
def private(path,limit=16384,owner=OWNER):
 info=safe(path,'file',owner)
 if stat.S_IMODE(info.st_mode)!=0o600 or not 0<info.st_size<=limit:raise ValueError('private-file')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  check=os.fstat(fd)
  if check.st_ino!=info.st_ino or check.st_dev!=info.st_dev:raise ValueError('replaced')
  data=os.read(fd,info.st_size+1)
  if len(data)!=info.st_size:raise ValueError('changed')
  return json.loads(data)
 finally:os.close(fd)
def ticks(pid):
 try:return int(open('/proc/%d/stat'%pid,encoding='ascii').read().rsplit(')',1)[1].split()[19])
 except (OSError,ValueError,IndexError):return None
def claims():
 safe(root,'dir',OWNER)
 claim=private(root+'/'+role+'.claim',1024)
 if claim.get('guestRole')!=role or claim.get('correlationId')!=intent['preparationCorrelationId'] or claim.get('sourceSha')!=intent['sourceSha']:raise ValueError('prep-claim')
 job=root+'/'+intent['preparationCorrelationId'];safe(job,'dir',OWNER)
 state=private(job+'/state.json')
 if state.get('state')!='ready' or state.get('guestRole')!=role or state.get('sourceSha')!=intent['sourceSha']:raise ValueError('prep-state')
 manifest=private(job+'/guest-manifest.json',8192)
 receipt=private(job+'/preparation-receipt.json')
 if manifest.get('schemaVersion')!=1 or manifest.get('host')!='archlinux' or manifest.get('guestRole')!=role or manifest.get('qemuPid')!=intent['qemuPid'] or manifest.get('qemuStartTicks')!=intent['qemuStartTicks'] or manifest.get('diskDevice')!=intent['diskDevice'] or manifest.get('diskInode')!=intent['diskInode'] or manifest.get('tree')!=tree or manifest.get('sshPort')!=port or manifest.get('sourceSha')!=intent['sourceSha']:raise ValueError('prep-manifest')
 if receipt.get('schemaVersion')!=1 or receipt.get('state')!='ready' or receipt.get('guestRole')!=role or receipt.get('sourceSha')!=intent['sourceSha'] or receipt.get('correlationId')!=intent['preparationCorrelationId'] or receipt.get('qemu')!={'pid':intent['qemuPid'],'startTicks':intent['qemuStartTicks'],'diskDevice':intent['diskDevice'],'diskInode':intent['diskInode'],'sshPort':port,'tree':tree}:raise ValueError('prep-receipt')
 jobs='/home/kardinal/.vpn-control-parity-jobs'
 if os.path.lexists(jobs):
  safe(jobs,'dir',OWNER)
  path=jobs+'/'+role+'.claim'
  if os.path.lexists(path):
   accepted=private(path,512)
   corr=accepted.get('correlationId')
   if accepted.get('guestRole')!=role or not isinstance(corr,str) or not re.fullmatch('[0-9a-f-]{36}',corr):raise ValueError('acceptance-claim')
   result=private(jobs+'/'+corr+'/result.json')
   if result.get('state')!='terminal' or result.get('correlationId')!=corr or result.get('guestRole')!=role:raise ValueError('acceptance-active')
   worker=private(jobs+'/'+corr+'/worker.json',512)
   if type(worker.get('pid')) is not int or type(worker.get('startTicks')) is not int or ticks(worker['pid'])==worker['startTicks']:raise ValueError('acceptance-worker-active')
def proc_identity():
 if ticks(intent['qemuPid'])!=intent['qemuStartTicks']:raise ValueError('pid-generation')
 safe(tree,'dir',OWNER);info=safe(disk,'file',OWNER);q=safe(qmp,'socket',OWNER)
 if (info.st_dev,info.st_ino)!=(intent['diskDevice'],intent['diskInode']) or (mode!='preflight' and q.st_ino!=intent['qmpInode']):raise ValueError('inode')
 raw=open('/proc/%d/cmdline'%intent['qemuPid'],'rb').read(16385)
 if not raw or len(raw)>16384:raise ValueError('argv')
 args=raw.rstrip(b'\0').split(b'\0')
 if os.path.basename(args[0])!=b'qemu-system-x86_64' or not any(b'file='+disk.encode()+b',if=virtio,format=qcow2' in a for a in args) or not any(b'hostfwd=tcp:127.0.0.1:'+str(port).encode()+b'-:22' in a for a in args) or not any(b'unix:'+qmp.encode()+b',server=on,wait=off' in a for a in args):raise ValueError('argv-identity')
 fds=set();disk_held=False
 for name in os.listdir('/proc/%d/fd'%intent['qemuPid']):
  path='/proc/%d/fd/%s'%(intent['qemuPid'],name)
  try:
   fds.add(os.readlink(path));fdinfo=os.stat(path)
  except OSError:raise ValueError('fd-unreadable')
  if (fdinfo.st_dev,fdinfo.st_ino)==(intent['diskDevice'],intent['diskInode']):disk_held=True
 if not disk_held:raise ValueError('disk-fd')
 qmp_sockets=[]
 for line in open('/proc/net/unix',encoding='ascii'):
  fields=line.split()
  if len(fields)>7 and fields[7]==qmp:qmp_sockets.append(int(fields[6]))
 if len(qmp_sockets)!=1 or 'socket:[%d]'%qmp_sockets[0] not in fds:raise ValueError('qmp-fd')
 return q
guest=r"""import json,os
ancestors=set();me=os.getpid()
while me>1 and me not in ancestors:
 ancestors.add(me);me=int(open('/proc/%d/stat'%me).read().rsplit(')',1)[1].split()[1])
owner=[];package=[]
for name in os.listdir('/proc'):
 if not name.isdigit() or int(name) in ancestors:continue
 try:
  raw=open('/proc/'+name+'/cmdline','rb').read(8193);exe=os.readlink('/proc/'+name+'/exe')
 except FileNotFoundError:continue
 except OSError:raise ValueError('process-unreadable')
 if len(raw)>8192:raise ValueError('argv-oversize')
 parts=raw.rstrip(b'\0').split(b'\0');first=os.path.basename(parts[0]).decode('ascii','replace') if parts else ''
 if exe.startswith('/opt/vpn-control/') or os.path.basename(exe)=='sing-box' or first=='sing-box' or any(x.startswith(b'/opt/vpn-control/') for x in parts):owner.append(name)
 if first in ('apt','apt-get','dpkg','pacman','packagekitd'):package.append(name)
print(json.dumps({'ownerRuntimeOff':not owner,'packageProcessesOff':not package}))"""
def guest_idle():
 for name in ('client-key','known-hosts'):safe(tree+'/'+name,'file',OWNER)
 cmd=['ssh','-p',str(port),'-i',tree+'/client-key','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+tree+'/known-hosts','-o','BatchMode=yes','-o','ConnectTimeout=8','vpnfixture@127.0.0.1', 'sudo -n -- python3 -I -B -c '+shlex.quote(guest)]
 done=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=15)
 if done.returncode!=0 or len(done.stdout)>1024:raise ValueError('guest-probe')
 facts=json.loads(done.stdout)
 if facts!={'ownerRuntimeOff':True,'packageProcessesOff':True}:raise ValueError('guest-busy')
 return facts
def write(path,value):
 data=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
 d=os.open(os.path.dirname(path),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(d)
 finally:os.close(d)
def absence():
 if ticks(intent['qemuPid'])==intent['qemuStartTicks']:return False
 info=safe(disk,'file',OWNER)
 if (info.st_dev,info.st_ino)!=(intent['diskDevice'],intent['diskInode']):return False
 for name in os.listdir('/proc'):
  if not name.isdigit():continue
  process='/proc/'+name
  try:raw=open(process+'/cmdline','rb').read(16385)
  except OSError:
   if os.path.exists(process):raise ValueError('live-cmdline-unreadable')
   continue
  if len(raw)>16384:raise ValueError('live-cmdline-oversize')
  if b'qemu-system-x86_64' in raw and (disk.encode() in raw or qmp.encode() in raw or b'hostfwd=tcp:127.0.0.1:'+str(port).encode()+b'-:22' in raw):return False
  try:names=os.listdir(process+'/fd')
  except OSError:
   if os.path.exists(process):raise ValueError('live-fds-unreadable')
   continue
  for fd in names:
   path=process+'/fd/'+fd
   try:held=os.stat(path)
   except OSError:
    if os.path.exists(process):raise ValueError('live-fd-unreadable')
    continue
   if (held.st_dev,held.st_ino)==(intent['diskDevice'],intent['diskInode']):return False
 for path in ('/proc/net/tcp','/proc/net/tcp6'):
  for line in open(path,encoding='ascii').readlines()[1:]:
   parts=line.split()
   if len(parts)<10:raise ValueError('net-inventory')
   if int(parts[1].split(':')[1],16)==port and parts[3]=='0A':return False
 for line in open('/proc/net/unix',encoding='ascii'):
  parts=line.split()
  if len(parts)>7 and parts[7]==qmp:return False
 return True
def receipt():
 return {'state':'parked','correlationId':intent['correlationId'],'qemuPid':intent['qemuPid'],'qemuStartTicks':intent['qemuStartTicks'],'diskDevice':intent['diskDevice'],'diskInode':intent['diskInode'],'qmpInode':intent['qmpInode'],'ownerRuntimeOff':True,'terminalAbsence':True}
try:
 claims()
 if os.path.lexists(parkroot):safe(parkroot,'dir',PARK_OWNER)
 journal=parkroot+'/'+intent['correlationId']+'.json'
 if mode=='preflight':
  if os.path.lexists(journal) or os.path.lexists(parkroot+'/'+role+'.claim'):raise ValueError('already-journaled')
  proc_identity();guest_idle()
  print(json.dumps({'ready':True,'qmpInode':os.lstat(qmp).st_ino,'ownerRuntimeOff':True,'packageProcessesOff':True,'protectedJobsTerminal':True,'qemuPid':intent['qemuPid'],'qemuStartTicks':intent['qemuStartTicks'],'diskDevice':intent['diskDevice'],'diskInode':intent['diskInode']}))
 elif mode=='start':
  if os.path.lexists(journal) or os.path.lexists(parkroot+'/'+role+'.claim'):raise ValueError('already-journaled')
  proc_identity();guest_idle()
  os.makedirs(parkroot,mode=0o700,exist_ok=True);safe(parkroot,'dir',PARK_OWNER)
  write(parkroot+'/'+role+'.claim',{'guestRole':role,'correlationId':intent['correlationId'],'preparationCorrelationId':intent['preparationCorrelationId'],'sourceSha':intent['sourceSha']})
  write(journal,intent)
  proc_identity();guest_idle()
  sock=socket.socket(socket.AF_UNIX);sock.settimeout(5);sock.connect(qmp)
  try:
   peer=struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
   if peer[0]!=intent['qemuPid'] or os.lstat(qmp).st_ino!=intent['qmpInode'] or ticks(intent['qemuPid'])!=intent['qemuStartTicks']:raise ValueError('qmp-peer')
   stream=sock.makefile('rwb',buffering=0)
   greeting=json.loads(stream.readline(65537))
   if 'QMP' not in greeting:raise ValueError('qmp-greeting')
   for command in ('qmp_capabilities','system_powerdown'):
    stream.write(json.dumps({'execute':command}).encode()+b'\r\n')
    for _ in range(32):
     line=stream.readline(65537)
     if not line or len(line)>65536:raise ValueError('qmp-response')
     response=json.loads(line)
     if 'error' in response:raise ValueError('qmp-error')
     if 'return' in response:break
    else:raise ValueError('qmp-response')
  finally:sock.close()
  deadline=time.monotonic()+60
  while time.monotonic()<deadline:
   if absence():
    done=receipt();write(parkroot+'/'+intent['correlationId']+'.result.json',done)
    print(json.dumps(done));break
   time.sleep(1)
  else:print(json.dumps({'state':'unknown','correlationId':intent['correlationId']}))
 else:
  stored=private(journal,2048,PARK_OWNER)
  if stored!=intent:raise ValueError('park-intent')
  if private(parkroot+'/'+role+'.claim',512,PARK_OWNER)!={'guestRole':role,'correlationId':intent['correlationId'],'preparationCorrelationId':intent['preparationCorrelationId'],'sourceSha':intent['sourceSha']}:raise ValueError('park-claim')
  result=parkroot+'/'+intent['correlationId']+'.result.json'
  if os.path.lexists(result):
   done=private(result,2048,PARK_OWNER)
   if done!=receipt() or not absence():raise ValueError('park-result')
   print(json.dumps(done))
  elif absence():
   done=receipt();write(result,done);print(json.dumps(done))
  else:print(json.dumps({'state':'unknown','correlationId':intent['correlationId']}))
except Exception:
 print(json.dumps({'state':'unknown','correlationId':intent['correlationId']}))
'''


class FixedRemoteDriver:
    """Only the configured archlinux alias may execute the fixed remote program."""

    def __init__(self, root: Path | str, *, runner: Any = subprocess.run):
        self.root = Path(root).resolve(strict=True)
        self.runner = runner

    def _call(self, mode: str, intent: Mapping[str, Any]) -> Mapping[str, Any]:
        config = ssh_transport.load_config(self.root)
        host = config.hosts.get("archlinux")
        _need(host is not None and host.user == "kardinal" and host.password is None,
              "Fixed Linux park host is unavailable")
        command = ("sudo", "-n", "python3", "-I", "-B", "-c", _REMOTE, mode,
                   json.dumps(dict(intent), sort_keys=True, separators=(",", ",")))
        argv = ssh_transport.build_ssh_argv(config, "archlinux", 90, command=command)
        done = self.runner(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=100)
        _need(done.returncode == 0 and len(done.stdout) <= 2048,
              "Fixed Linux park response is uncertain")
        result = json.loads(done.stdout)
        _need(isinstance(result, dict), "Fixed Linux park response differs")
        return result

    def preflight(self, intent: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._call("preflight", intent)

    def start(self, intent: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._call("start", intent)

    def status(self, intent: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._call("status", intent)

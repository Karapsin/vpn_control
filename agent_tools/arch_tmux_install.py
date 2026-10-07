"""One-shot installation of the current signed ``extra/tmux`` candidate on Arch.

This is deliberately a private helper, not a general package interface.  It has
one host, repository, package, transport, credential loader, and status route.
The accepted source SHA and candidate version are durably fenced before sudo is
started; loss of a start response therefore requires status, never retry.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Mapping

try:
    from . import ssh_transport
    from . import windows_vm_virt_firmware_install as credential_policy
except ImportError:
    import ssh_transport  # type: ignore[no-redef]
    import windows_vm_virt_firmware_install as credential_policy  # type: ignore[no-redef]


HOST = "archlinux"
REPOSITORY = "extra"
PACKAGE = "tmux"
TOOL = "/usr/bin/tmux"
_UUID = re.compile(r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$")

# This private remote program emits a finite JSON projection only.  Pacman,
# sudo and /proc diagnostics are never forwarded.  Its remote fence is owned
# by the SSH account, is create-only, and is intentionally retained for status.
_REMOTE = r'''import hashlib,json,os,stat,subprocess,sys
HOST='archlinux';REPOSITORY='extra';PACKAGE='tmux';TOOL='/usr/bin/tmux';MODE=__MODE__;CORR=__CORR__;SOURCE=__SOURCE__;EXPECTED=__CANDIDATE__;EXPECTED_GENERATION=__GENERATION__
ENV={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C'}
def run(argv,out=False,timeout=30,input=None):return subprocess.run(argv,input=input,stdin=subprocess.DEVNULL if input is None else None,stdout=subprocess.PIPE if out else subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=timeout,check=False,env=ENV)
def candidate():
 r=run(['/usr/bin/pacman','-Si',REPOSITORY+'/'+PACKAGE],True,10)
 if r.returncode or not 0<len(r.stdout)<=8192:return None
 fields={}
 for line in r.stdout.decode('utf-8','strict').splitlines():
  if ':' in line:
   k,v=line.split(':',1);fields[k.strip()]=v.strip()
 v=fields.get('Version');return v if fields.get('Name')==PACKAGE and fields.get('Repository')==REPOSITORY and isinstance(v,str) and 0<len(v)<=128 else None
def installed():
 r=run(['/usr/bin/pacman','-Q',PACKAGE],True,10)
 if r.returncode or not 0<len(r.stdout)<=256:return None
 parts=r.stdout.decode('utf-8','strict').strip().split(' ',1);return parts[1] if len(parts)==2 and parts[0]==PACKAGE else None
def locked():
 try:os.lstat('/var/lib/pacman/db.lck');return True
 except FileNotFoundError:return False
 except OSError:return None
def cache_policy():
 r=run(['/usr/bin/pacman-conf','CacheDir'],True,10)
 if r.returncode or not 0<len(r.stdout)<=1024:return False
 roots=r.stdout.decode('utf-8','strict').splitlines()
 if not roots:return False
 for p in roots:
  if not p.startswith('/') or '\x00' in p:return False
  s=os.lstat(p)
  if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or stat.S_IMODE(s.st_mode)&0o022:return False
 return True
def sole():
 try:
  ours=os.getpid()
  for name in os.listdir('/proc'):
   if not name.isdigit() or int(name)==ours:continue
   try:raw=open('/proc/'+name+'/cmdline','rb').read(4097)
   except (OSError,ValueError):return None
   if len(raw)>4096: return None
   argv=raw.split(b'\0');base=argv[0].rsplit(b'/',1)[-1]
   if base in (b'pacman',b'pacman-key'):return False
  return True
 except OSError:return None
def generation():
 try:
  rows=[]
  for p in ('/var/lib/pacman/local','/var/lib/pacman/sync','/var/cache/pacman/pkg'):
   s=os.lstat(p)
   if not stat.S_ISDIR(s.st_mode):return None
   rows.append((p,s.st_dev,s.st_ino,s.st_mtime_ns,s.st_ctime_ns,s.st_size,s.st_uid,s.st_gid,s.st_nlink,stat.S_IMODE(s.st_mode)))
  return hashlib.sha256(repr(rows).encode()).hexdigest()
 except OSError:return None
def fence():return os.path.expanduser('~/.local/state/vpn-control/arch-tmux-install/'+CORR+'.json')
def terminal():return fence()+'.terminal'
def owned_parent(path):
 parent=os.path.dirname(path);os.makedirs(parent,mode=0o700,exist_ok=True);s=os.lstat(parent)
 return stat.S_ISDIR(s.st_mode) and s.st_uid==os.geteuid() and stat.S_IMODE(s.st_mode)==0o700 and s.st_nlink>=2
def write(path,value):
 if not owned_parent(path):raise ValueError()
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:os.write(fd,json.dumps(value,sort_keys=True,separators=(',',':')).encode());os.fsync(fd)
 finally:os.close(fd)
 d=os.open(os.path.dirname(path),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(d)
 finally:os.close(d)
def read(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  named=os.lstat(path);before=os.fstat(fd)
  def good(s):return stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and s.st_size<=1024
  def gen(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  if not good(named) or not good(before) or gen(named)!=gen(before):raise ValueError()
  raw=os.read(fd,1025);after=os.fstat(fd);named_after=os.lstat(path)
 finally:os.close(fd)
 if len(raw)!=before.st_size or gen(before)!=gen(after) or gen(named)!=gen(named_after):raise ValueError()
 return json.loads(raw)
def emit(state,candidate_version=None,installed_version=None,signature=False,integrity=False,fence_state='absent'):
 print(json.dumps({'schemaVersion':1,'host':HOST,'correlationId':CORR,'sourceSha':SOURCE,'state':state,'repository':REPOSITORY,'package':PACKAGE,'candidateVersion':candidate_version,'installedVersion':installed_version,'lockClear':locked() is False,'cachePolicyValid':cache_policy(),'fullGeneration':generation(),'soleTransactionGuard':sole() is True,'pacmanSignatureVerified':signature,'packageIntegrityVerified':integrity,'tmuxPresent':os.path.isfile(TOOL) and os.access(TOOL,os.X_OK),'remoteFence':fence_state},sort_keys=True,separators=(',',':')))
try:
 c=candidate();i=installed();l=locked();cp=cache_policy();sg=sole();g=generation()
 if MODE=='preflight':
  state='candidate-unavailable' if c is None else 'lock-present' if l is not False else 'cache-policy-invalid' if not cp else 'transaction-guard-unavailable' if sg is None else 'transaction-active' if not sg else 'generation-unavailable' if g is None else 'package-present' if i==c and os.path.isfile(TOOL) else 'ready'
  emit(state,c,i,fence_state='absent');raise SystemExit
 if MODE=='start':
  if c is None or c!=EXPECTED or g!=EXPECTED_GENERATION or l is not False or not cp or sg is not True:emit('admission-changed',c,i);raise SystemExit
  path=fence();write(path,{'schemaVersion':1,'correlationId':CORR,'sourceSha':SOURCE,'candidateVersion':c,'generation':g})
  secret=sys.stdin.buffer.read(513)
  if not 1<=len(secret)<=512 or b'\0' in secret:raise ValueError()
  r=run(['/usr/bin/sudo','-S','-p','','--','/usr/bin/pacman','-S','--noconfirm',REPOSITORY+'/'+PACKAGE+'='+c],timeout=180,input=secret)
  if r.returncode:write(terminal(),{'schemaVersion':1,'correlationId':CORR,'sourceSha':SOURCE,'candidateVersion':c,'generation':g,'state':'transaction-failed','signature':False});emit('transaction-failed',c,installed(),fence_state='recorded');raise SystemExit
  i=installed();integrity=run(['/usr/bin/pacman','-Qkk',PACKAGE]).returncode==0
  state='verified' if i==c and integrity and os.path.isfile(TOOL) and os.access(TOOL,os.X_OK) else 'package-verification-failed';write(terminal(),{'schemaVersion':1,'correlationId':CORR,'sourceSha':SOURCE,'candidateVersion':c,'generation':g,'state':state,'signature':True});emit(state,c,i,True,integrity,'recorded');raise SystemExit
 if MODE=='status':
  record=read(fence());t=read(terminal())
  if record is None or t is None or record!={'schemaVersion':1,'correlationId':CORR,'sourceSha':SOURCE,'candidateVersion':EXPECTED,'generation':EXPECTED_GENERATION} or t!={'schemaVersion':1,'correlationId':CORR,'sourceSha':SOURCE,'candidateVersion':EXPECTED,'generation':EXPECTED_GENERATION,'state':t.get('state'),'signature':t.get('signature')} or t.get('state')!='verified' or t.get('signature') is not True or not isinstance(record.get('generation'),str) or len(record['generation'])!=64 or any(x not in '0123456789abcdef' for x in record['generation']):raise ValueError()
  integrity=run(['/usr/bin/pacman','-Qkk',PACKAGE]).returncode==0
  emit('verified' if i==EXPECTED and integrity and os.path.isfile(TOOL) and os.access(TOOL,os.X_OK) else 'unverified',c,i,True,integrity,'recorded')
except (OSError,ValueError,UnicodeDecodeError,json.JSONDecodeError,subprocess.TimeoutExpired):emit('unknown',None,None,False,False,'unknown')
'''


def _validate(host: str, correlation_id: str, source_sha: str, timeout_seconds: int) -> None:
    if host != HOST or not isinstance(correlation_id, str) or not _UUID.fullmatch(correlation_id) or not isinstance(source_sha, str) or not _SHA.fullmatch(source_sha) or type(timeout_seconds) is not int or not 10 <= timeout_seconds <= 300:
        raise ValueError("Arch tmux install requires fixed host, correlation, source SHA and timeout.")


def _source_binding(root: str | Path, source_sha: str) -> str | None:
    """Bind the admitted source, fixed helpers, and private SSH config by digest."""
    root_path = Path(root).resolve(strict=True)
    try:
        head = subprocess.run(["/usr/bin/git", "-C", str(root_path), "rev-parse", "HEAD"],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=10, check=False)
        if head.returncode != 0 or head.stdout.decode("ascii", "strict").strip() != source_sha:
            return None
        paths = (Path(__file__).resolve(), Path(ssh_transport.__file__).resolve(),
                 root_path / ssh_transport.CONFIG_FILENAME)
        digest = hashlib.sha256()
        for path in paths:
            info = os.lstat(path)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1_048_576:
                return None
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                opened = os.fstat(fd)
                data = os.read(fd, info.st_size + 1)
            finally:
                os.close(fd)
            if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) or len(data) != info.st_size:
                return None
            digest.update(path.name.encode("ascii")); digest.update(data)
        return digest.hexdigest()
    except (OSError, UnicodeDecodeError, subprocess.TimeoutExpired):
        return None


def _journal(root: str | Path, create: bool) -> Path:
    directory = Path(root).resolve() / ".rag_index" / "arch-tmux-install"
    if create: directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = os.lstat(directory)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("Arch tmux journal is unsafe.")
    return directory


def _intent(correlation_id: str, source_sha: str, candidate: str, generation: str, binding: str) -> dict[str, str | int]:
    return {"schemaVersion": 1, "correlationId": correlation_id, "host": HOST, "repository": REPOSITORY,
            "package": PACKAGE, "sourceSha": source_sha, "candidateVersion": candidate, "fullGeneration": generation,
            "sourceBinding": binding}


def _save_intent(directory: Path, value: Mapping[str, Any]) -> None:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    path = directory / "intent.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try: os.write(fd, raw); os.fsync(fd)
    finally: os.close(fd)
    parent = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try: os.fsync(parent)
    finally: os.close(parent)


def _read_intent(directory: Path, correlation_id: str, source_sha: str) -> dict[str, Any]:
    path = directory / "intent.json"
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        named = os.lstat(path); before = os.fstat(fd); raw = os.read(fd, 1025)
        after = os.fstat(fd); named_after = os.lstat(path)
    finally: os.close(fd)
    generation = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid, item.st_nlink,
                               item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if (not stat.S_ISREG(named.st_mode) or not stat.S_ISREG(before.st_mode) or named.st_uid != os.getuid()
            or before.st_uid != os.getuid() or stat.S_IMODE(named.st_mode) != 0o600
            or stat.S_IMODE(before.st_mode) != 0o600 or named.st_nlink != 1 or before.st_nlink != 1
            or generation(named) != generation(before) or generation(before) != generation(after)
            or generation(named) != generation(named_after) or len(raw) != before.st_size or len(raw) > 1024):
        raise ValueError("Arch tmux intent is unsafe.")
    value = json.loads(raw)
    required = {"schemaVersion", "correlationId", "host", "repository", "package", "sourceSha", "candidateVersion", "fullGeneration", "sourceBinding"}
    if not isinstance(value, Mapping) or set(value) != required or value.get("schemaVersion") != 1 or value.get("correlationId") != correlation_id or value.get("sourceSha") != source_sha or value.get("host") != HOST or value.get("repository") != REPOSITORY or value.get("package") != PACKAGE or not isinstance(value.get("candidateVersion"), str) or not _VERSION.fullmatch(value["candidateVersion"]) or not isinstance(value.get("fullGeneration"), str) or not re.fullmatch(r"[0-9a-f]{64}", value["fullGeneration"]) or not isinstance(value.get("sourceBinding"), str) or not re.fullmatch(r"[0-9a-f]{64}", value["sourceBinding"]):
        raise ValueError("Arch tmux intent changed.")
    return dict(value)


def _parse(value: object, correlation_id: str, source_sha: str) -> dict[str, Any]:
    required = {"schemaVersion", "host", "correlationId", "sourceSha", "state", "repository", "package", "candidateVersion", "installedVersion", "lockClear", "cachePolicyValid", "fullGeneration", "soleTransactionGuard", "pacmanSignatureVerified", "packageIntegrityVerified", "tmuxPresent", "remoteFence"}
    if not isinstance(value, Mapping) or set(value) != required or value.get("schemaVersion") != 1 or value.get("host") != HOST or value.get("correlationId") != correlation_id or value.get("sourceSha") != source_sha or value.get("repository") != REPOSITORY or value.get("package") != PACKAGE or value.get("state") not in {"ready", "package-present", "candidate-unavailable", "lock-present", "cache-policy-invalid", "transaction-guard-unavailable", "transaction-active", "generation-unavailable", "admission-changed", "transaction-failed", "verified", "package-verification-failed", "unverified", "unknown"} or value.get("remoteFence") not in {"absent", "recorded", "unknown"}:
        raise ValueError("Arch tmux response is invalid.")
    for field in ("candidateVersion", "installedVersion"):
        if value[field] is not None and (not isinstance(value[field], str) or not _VERSION.fullmatch(value[field])): raise ValueError("Arch tmux version is invalid.")
    if value["fullGeneration"] is not None and (not isinstance(value["fullGeneration"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["fullGeneration"])): raise ValueError("Arch tmux generation is invalid.")
    if any(type(value[key]) is not bool for key in ("lockClear", "cachePolicyValid", "soleTransactionGuard", "pacmanSignatureVerified", "packageIntegrityVerified", "tmuxPresent")): raise ValueError("Arch tmux response is invalid.")
    return dict(value)


def _remote(root: str | Path, correlation_id: str, source_sha: str, mode: str, timeout_seconds: int, *, candidate: str | None = None, generation: str | None = None, credential: bytes | None = None) -> dict[str, Any]:
    program = _REMOTE.replace("__MODE__", repr(mode)).replace("__CORR__", repr(correlation_id)).replace("__SOURCE__", repr(source_sha)).replace("__CANDIDATE__", repr(candidate)).replace("__GENERATION__", repr(generation))
    config = ssh_transport.load_config(Path(root).resolve(strict=True))
    if HOST not in config.hosts or ssh_transport.connection_host(config, HOST).password is not None: raise ValueError("Configured Arch transport is unavailable.")
    argv = ssh_transport.build_ssh_argv(config, HOST, min(timeout_seconds, 60), command=("/usr/bin/python3", "-c", "exec(" + repr(program) + ")"), ssh_binary="/usr/bin/ssh", nested_ssh_binary="/usr/bin/ssh")
    completed = subprocess.run(argv, input=credential, stdin=subprocess.DEVNULL if credential is None else None, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout_seconds, check=False)
    if completed.returncode != 0 or not 0 < len(completed.stdout) <= 2048: raise ValueError("Arch tmux transport is unknown.")
    return _parse(json.loads(completed.stdout), correlation_id, source_sha)


def _public(result: Mapping[str, Any], correlation_id: str, source_sha: str) -> dict[str, Any]:
    return {key: result.get(key) for key in ("state", "candidateVersion", "installedVersion", "lockClear", "cachePolicyValid", "fullGeneration", "soleTransactionGuard", "pacmanSignatureVerified", "packageIntegrityVerified", "tmuxPresent", "remoteFence")} | {"correlationId": correlation_id, "sourceSha": source_sha, "host": HOST, "repository": REPOSITORY, "package": PACKAGE, "replayAllowed": False, "nativeActionAllowed": False}


def preflight(root: str | Path, *, host: str, correlation_id: str, source_sha: str, timeout_seconds: int = 60) -> dict[str, Any]:
    _validate(host, correlation_id, source_sha, timeout_seconds)
    binding = _source_binding(root, source_sha)
    try: result = _remote(root, correlation_id, source_sha, "preflight", timeout_seconds) if binding is not None else {"state": "source-closed"}
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError): result = {"state": "unknown"}
    public = _public(result, correlation_id, source_sha)
    public["credentialMetadataValid"] = credential_policy._credential_metadata(root)
    public["signaturePolicy"] = credential_policy._signature_policy_state(root, timeout_seconds)
    public["sourceBinding"] = binding
    public["safeStartAllowed"] = public["state"] == "ready" and binding is not None and public["credentialMetadataValid"] and str(public["signaturePolicy"]).startswith("required-trusted-")
    return public


def start(root: str | Path, *, host: str, correlation_id: str, source_sha: str, timeout_seconds: int = 180, credential_path: Path | None = None) -> dict[str, Any]:
    _validate(host, correlation_id, source_sha, timeout_seconds)
    try: directory = _journal(root, False); _read_intent(directory, correlation_id, source_sha); raise ValueError("Arch tmux install intent already exists; use exact status.")
    except FileNotFoundError: pass
    admission = preflight(root, host=host, correlation_id=correlation_id, source_sha=source_sha, timeout_seconds=min(timeout_seconds, 60))
    if not admission["safeStartAllowed"]: raise ValueError("Arch tmux install preflight is not safe.")
    candidate, generation, binding = admission["candidateVersion"], admission["fullGeneration"], admission.get("sourceBinding")
    if not isinstance(candidate, str) or not isinstance(generation, str) or not isinstance(binding, str) or _source_binding(root, source_sha) != binding or not credential_policy._signature_policy(root, min(timeout_seconds, 60)):
        raise ValueError("Arch tmux install admission changed.")
    credential = credential_policy._read_credential(root, credential_path=credential_path)
    directory = _journal(root, True)
    try: _save_intent(directory, _intent(correlation_id, source_sha, candidate, generation, binding))
    except FileExistsError as error: raise ValueError("Arch tmux install intent already exists; use exact status.") from error
    try: result = _remote(root, correlation_id, source_sha, "start", timeout_seconds, candidate=candidate, generation=generation, credential=credential)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError): result = {"state": "unknown"}
    return _public(result, correlation_id, source_sha)


def status(root: str | Path, *, host: str, correlation_id: str, source_sha: str, timeout_seconds: int = 60) -> dict[str, Any]:
    _validate(host, correlation_id, source_sha, timeout_seconds)
    try: intent = _read_intent(_journal(root, False), correlation_id, source_sha)
    except FileNotFoundError: return _public({"state": "intent-absent"}, correlation_id, source_sha)
    candidate, generation, binding = intent.get("candidateVersion"), intent.get("fullGeneration"), intent.get("sourceBinding")
    if not isinstance(candidate, str) or not isinstance(generation, str) or not isinstance(binding, str) or _source_binding(root, source_sha) != binding:
        return _public({"state": "source-changed"}, correlation_id, source_sha)
    try: result = _remote(root, correlation_id, source_sha, "status", timeout_seconds, candidate=candidate, generation=generation)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError): result = {"state": "unknown"}
    return _public(result, correlation_id, source_sha)

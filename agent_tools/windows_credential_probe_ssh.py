"""Fixed SSH backend for the non-replayable Windows QGA credential probe.

The caller supplies only a configured host and a UUID correlation.  The private
inventory supplies the VM binding and credential file; this module never turns
either into command arguments or a public receipt.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import sys
import tempfile
import uuid
from typing import Any, Mapping

try:
    from . import ssh_transport
except ImportError:  # pragma: no cover
    import ssh_transport


REPO_ROOT = Path(__file__).resolve().parents[1]
_HELPERS = (
    ("windows_credential_validity_qga.py", REPO_ROOT / "scripts" / "windows_credential_validity_qga.py"),
    ("native_fixture_qga.py", REPO_ROOT / "scripts" / "native_fixture_qga.py"),
    ("windows_task_admission.ps1", REPO_ROOT / "scripts" / "windows_task_admission.ps1"),
)
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_SID = re.compile(r"^S-1-5-21-(?:[0-9]+-){3}[0-9]+$")
_SOCKET_PATH = re.compile(r"^/[A-Za-z0-9._/-]+$")
_MAX_SECRET = 512
_MAX_OUTPUT = 8192
_MAX_REMOTE_PAYLOAD = 4 * 1024 * 1024 + 4096


class WindowsCredentialProbeSshError(ValueError):
    pass


# This program is fixed here, invoked with fixed argv, and receives all helper
# bytes and private input through stdin.  It reserves its leaf before reading
# stdin, so a lost submit response can only be observed, never replayed.
_REMOTE_START = r'''import base64,hashlib,json,os,re,stat,sys
root,env,corr=sys.argv[1:]
def out(v): print(json.dumps(v,sort_keys=True,separators=(",",":")))
def bad(reason): out({"state":"unknown","reason":reason}); raise SystemExit(0)
def safe_name(v): return isinstance(v,str) and v and all(c.isalnum() or c in "_.-" for c in v)
def safe_dir(path):
 if not path.startswith("/") or ".." in path.split("/"): raise ValueError()
 if os.path.islink(path): raise ValueError()
 i=os.stat(path)
 if not stat.S_ISDIR(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o700: raise ValueError()
def live(socket_path,pid,ticks):
 if not isinstance(socket_path,str) or not socket_path or any(c.isspace() for c in socket_path): return False
 s=os.lstat(socket_path)
 if not stat.S_ISSOCK(s.st_mode): return False
 raw=open("/proc/%d/stat"%pid,"rb").read().split()
 if len(raw)<22 or raw[21].decode()!=str(ticks): return False
 inodes=set()
 for name in os.listdir("/proc/%d/fd"%pid):
  try:
   target=os.readlink("/proc/%d/fd/%s"%(pid,name))
   if target.startswith("socket:[") and target.endswith("]"): inodes.add(target[8:-1].encode())
  except OSError: pass
 if not inodes: return False
 wanted=os.fsencode(socket_path)
 for line in open("/proc/net/unix","rb"):
  parts=line.split()
  if len(parts)==8 and parts[6] in inodes and parts[7]==wanted: return True
 return False
try:
 safe_dir(root)
 header=sys.stdin.buffer.read(4)
 if len(header)!=4: bad("invalid_input")
 length=int.from_bytes(header,"big")
 if length<1 or length>4198400: bad("invalid_input")
 raw=sys.stdin.buffer.read(length)
 if len(raw)!=length or sys.stdin.buffer.read(1): bad("invalid_input")
 value=json.loads(raw.decode("utf-8"))
 need={"schema","socketPath","pid","startTicks","accountName","expectedSid","helpers","credential"}
 if set(value)!=need or value["schema"]!=1 or not safe_name(env) or not safe_name(corr): bad("invalid_input")
 if not isinstance(value["pid"],int) or value["pid"]<=0 or not isinstance(value["startTicks"],int) or value["startTicks"]<=0: bad("invalid_input")
 if not isinstance(value["socketPath"],str) or re.fullmatch(r"/[A-Za-z0-9._/-]+",value["socketPath"]) is None or not live(value["socketPath"],value["pid"],value["startTicks"]): bad("vm_binding_unverified")
 names=("windows_credential_validity_qga.py","native_fixture_qga.py","windows_task_admission.ps1")
 helpers=value["helpers"]
 if not isinstance(helpers,list) or [x.get("name") if isinstance(x,dict) else None for x in helpers]!=list(names): bad("invalid_input")
 parent=os.path.join(root,env); os.mkdir(parent,0o700) if not os.path.exists(parent) else None; safe_dir(parent)
 stage=os.path.join(parent,corr); os.mkdir(stage,0o700); safe_dir(stage)
 hashes={}
 for item in helpers:
  raw=base64.b64decode(item.get("data",""),validate=True); digest=item.get("sha256")
  if not raw or len(raw)>1048576 or not isinstance(digest,str) or hashlib.sha256(raw).hexdigest()!=digest: bad("invalid_input")
  fd=os.open(os.path.join(stage,item["name"]),os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
  with os.fdopen(fd,"wb") as f: f.write(raw); f.flush(); os.fsync(f.fileno())
  hashes[item["name"]]=digest
 binding={"socketPath":value["socketPath"],"pid":value["pid"],"startTicks":value["startTicks"]}
 fd=os.open(os.path.join(stage,"binding.json"),os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
 with os.fdopen(fd,"w",encoding="utf-8") as f: json.dump(binding,f,separators=(",",":")); f.flush(); os.fsync(f.fileno())
 secret=base64.b64decode(value["credential"],validate=True)
 if not secret or len(secret)>512: bad("invalid_input")
 credential=os.path.join(stage,"credential")
 fd=os.open(credential,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
 with os.fdopen(fd,"wb") as f: f.write(secret); f.flush(); os.fsync(f.fileno())
 sys.path.insert(0,stage)
 from pathlib import Path
 from windows_credential_validity_qga import CredentialProbeAdmission,FixedCredentialProbeClient,WindowsCredentialValidityProbe
 admission=CredentialProbeAdmission(socket_path=value["socketPath"],vm_identity="%d:%d"%(value["pid"],value["startTicks"]),account_name=value["accountName"],expected_sid=value["expectedSid"],correlation_id=corr,helper_path=Path(stage,"windows_task_admission.ps1"),helper_sha256=hashes["windows_task_admission.ps1"],credential_path=Path(credential))
 try:
  result=WindowsCredentialValidityProbe(FixedCredentialProbeClient(value["socketPath"]),os.path.join(stage,"journal")).start(admission)
 finally:
  try: os.unlink(credential)
  except OSError: pass
 out(result)
except FileExistsError: out({"state":"unknown","reason":"exclusive_stage_exists"})
except Exception: out({"state":"unknown","reason":"start_failed"})
'''

_REMOTE_STATUS = r'''import json,os,stat,sys
root,env,corr=sys.argv[1:]
def out(v): print(json.dumps(v,sort_keys=True,separators=(",",":")))
def live(socket_path,pid,ticks):
 if not isinstance(socket_path,str) or not socket_path or any(c.isspace() for c in socket_path): return False
 s=os.lstat(socket_path)
 if not stat.S_ISSOCK(s.st_mode): return False
 raw=open("/proc/%d/stat"%pid,"rb").read().split()
 if len(raw)<22 or raw[21].decode()!=str(ticks): return False
 inodes=set()
 for name in os.listdir("/proc/%d/fd"%pid):
  try:
   target=os.readlink("/proc/%d/fd/%s"%(pid,name))
   if target.startswith("socket:[") and target.endswith("]"): inodes.add(target[8:-1].encode())
  except OSError: pass
 if not inodes: return False
 wanted=os.fsencode(socket_path)
 for line in open("/proc/net/unix","rb"):
  parts=line.split()
  if len(parts)==8 and parts[6] in inodes and parts[7]==wanted: return True
 return False
try:
 stage=os.path.join(root,env,corr)
 if not stage.startswith(root+"/") or os.path.islink(stage): raise ValueError()
 i=os.stat(stage)
 if not stat.S_ISDIR(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o700: raise ValueError()
 sys.path.insert(0,stage)
 from windows_credential_validity_qga import FixedCredentialProbeClient,WindowsCredentialValidityProbe
 # The stored journal retains the original socket binding; status never reads local helpers.
 journal=os.path.join(stage,"journal")
 binding=json.load(open(os.path.join(stage,"binding.json"),"r",encoding="utf-8")); socket=binding["socketPath"]
 if not live(socket,binding["pid"],binding["startTicks"]): raise ValueError()
 out(WindowsCredentialValidityProbe(FixedCredentialProbeClient(socket),journal).status(corr))
except Exception: out({"state":"unknown","reason":"status_failed"})
'''


def _descriptor(target: Any) -> tuple[str, str, int, int, str, str, Path]:
    """Adapt the typed inventory field owned by ssh_transport."""
    value = getattr(target, "windows_credential_probe", None)
    if value is None:
        raise WindowsCredentialProbeSshError("Windows credential probe is not configured for this host.")
    try:
        environment = value.environment; socket = str(value.qga_socket_path)
        pid = value.qemu_pid; ticks = value.qemu_start_ticks
        account = value.account_name; sid = value.expected_sid; credential = Path(value.credential_path)
    except AttributeError as error:
        raise WindowsCredentialProbeSshError("Windows credential probe configuration is invalid.") from error
    if (not isinstance(environment, str) or not _ID.fullmatch(environment) or not isinstance(socket, str)
            or not _SOCKET_PATH.fullmatch(socket) or ".." in PurePosixPath(socket).parts
            or type(pid) is not int or pid <= 0 or type(ticks) is not int or ticks <= 0
            or not isinstance(account, str) or not _ID.fullmatch(account)
            or not isinstance(sid, str) or not _SID.fullmatch(sid)):
        raise WindowsCredentialProbeSshError("Windows credential probe configuration is invalid.")
    return environment, socket, pid, ticks, account, sid, credential


def _correlation(value: str) -> None:
    try:
        uuid.UUID(value)
    except (TypeError, ValueError) as error:
        raise WindowsCredentialProbeSshError("Credential probe correlation is invalid.") from error


def _linux_socket_binding(socket_path: str, pid: int, start_ticks: int) -> bool:
    """Confirm a pathname socket belongs to this exact live Linux process."""
    try:
        if not _SOCKET_PATH.fullmatch(socket_path):
            return False
        info = os.lstat(socket_path)
        if not stat.S_ISSOCK(info.st_mode):
            return False
        process = Path(f"/proc/{pid}")
        fields = (process / "stat").read_bytes().split()
        if len(fields) < 22 or fields[21] != str(start_ticks).encode():
            return False
        inodes: set[bytes] = set()
        for entry in (process / "fd").iterdir():
            try:
                target = os.readlink(entry)
            except OSError:
                continue
            if target.startswith("socket:[") and target.endswith("]"):
                inodes.add(target[8:-1].encode())
        if not inodes:
            return False
        for line in Path("/proc/net/unix").read_bytes().splitlines():
            fields = line.split()
            if len(fields) == 8 and fields[6] in inodes and fields[7] == os.fsencode(socket_path):
                return True
    except OSError:
        return False
    return False


def _config(root: Path | str) -> Any:
    try:
        return ssh_transport.load_config(root)
    except (ssh_transport.SshConfigError, OSError, ValueError, TypeError) as error:
        raise WindowsCredentialProbeSshError("Windows credential probe configuration is unavailable.") from error


def _private_secret(path: Path) -> bytes:
    try:
        parent = os.path.dirname(os.path.abspath(os.fspath(path)))
        if sys.platform == "darwin" and (parent == "/var" or parent.startswith("/var/")):
            parent = "/private" + parent
        protected_below = True
        while True:
            ancestor = os.lstat(parent); mode = stat.S_IMODE(ancestor.st_mode)
            sticky = ancestor.st_uid == 0 and bool(mode & stat.S_ISVTX)
            writable = mode & 0o022
            if (not stat.S_ISDIR(ancestor.st_mode) or stat.S_ISLNK(ancestor.st_mode)
                    or ancestor.st_uid not in {0, os.getuid()} or (writable and not (sticky and protected_below))):
                raise ValueError
            if writable: protected_below = False
            next_parent = os.path.dirname(parent)
            if next_parent == parent: break
            parent = next_parent
        info = os.lstat(path)
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077 or not 0 < info.st_size <= _MAX_SECRET:
            raise ValueError
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(fd); raw = os.read(fd, _MAX_SECRET + 1)
        finally: os.close(fd)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (info.st_dev, info.st_ino, info.st_size) or not raw or len(raw) > _MAX_SECRET:
            raise ValueError
        return raw
    except OSError as error:
        raise WindowsCredentialProbeSshError("Private credential input is unavailable.") from error
    except ValueError as error:
        raise WindowsCredentialProbeSshError("Private credential input is unavailable.") from error


def _capture_helpers() -> tuple[list[dict[str, str]], dict[str, str]]:
    helpers: list[dict[str, str]] = []; hashes: dict[str, str] = {}
    for name, path in _HELPERS:
        try:
            info = os.lstat(path)
            if path.is_symlink() or not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 1024 * 1024: raise ValueError
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                opened = os.fstat(fd); raw = os.read(fd, 1024 * 1024 + 1)
            finally:
                os.close(fd)
            if (opened.st_dev, opened.st_ino, opened.st_size) != (info.st_dev, info.st_ino, info.st_size) or len(raw) != info.st_size: raise ValueError
        except (OSError, ValueError) as error:
            raise WindowsCredentialProbeSshError("Approved probe helper cannot be frozen.") from error
        digest = hashlib.sha256(raw).hexdigest(); hashes[name] = digest
        helpers.append({"name": name, "sha256": digest, "data": base64.b64encode(raw).decode("ascii")})
    return helpers, hashes


def _intent_path(root: Path, correlation: str) -> Path:
    return root / ".rag_index" / "windows-credential-probe-ssh" / (correlation + ".json")


def _write_intent(root: Path, correlation: str, record: Mapping[str, Any]) -> None:
    path = _intent_path(root, correlation); path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError as error:
        raise WindowsCredentialProbeSshError("Credential probe correlation already has durable intent.") from error
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(record, f, sort_keys=True, separators=(",", ":")); f.write("\n"); f.flush(); os.fsync(f.fileno())


def _read_intent(root: Path, correlation: str) -> dict[str, Any]:
    path = _intent_path(root, correlation)
    try:
        info = os.lstat(path)
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077: raise ValueError
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WindowsCredentialProbeSshError("Credential probe has no durable intent.") from error
    if not isinstance(value, dict) or set(value) != {"host", "environment", "socketPath", "pid", "startTicks", "accountName", "expectedSid", "helperHashes"}:
        raise WindowsCredentialProbeSshError("Credential probe durable intent is invalid.")
    return value


def _run_ssh(config: Any, host: str, command: tuple[str, ...], payload: bytes | None, timeout: int) -> bytes | None:
    try:
        argv = ssh_transport.build_ssh_argv(config, host, timeout, command=command)
    except (ssh_transport.SshConfigError, ValueError, TypeError):
        return None
    target = config.hosts[host]; connection = config.hosts[target.gateway] if target.transport == "nested" else target
    try:
        if connection.password is not None:
            with tempfile.TemporaryDirectory(prefix="vpn-control-askpass-") as directory:
                _, env = ssh_transport._askpass_environment(connection.password, Path(directory))
                done = subprocess.run(argv, input=payload, capture_output=True, timeout=timeout + 1, env=env, check=False)
        else:
            done = subprocess.run(argv, input=payload, capture_output=True, timeout=timeout + 1, check=False)
    except (OSError, subprocess.TimeoutExpired): return None
    if done.returncode != 0 or len(done.stdout) > _MAX_OUTPUT: return None
    return done.stdout


def _public(raw: bytes | None, correlation: str) -> dict[str, Any]:
    if raw is None: return {"state": "unknown", "correlationId": correlation}
    try: value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError): return {"state": "unknown", "correlationId": correlation}
    if not isinstance(value, dict) or value.get("state") not in {"intent", "submitted", "unknown", "terminal"}: return {"state": "unknown", "correlationId": correlation}
    result = {"state": value["state"], "correlationId": correlation}
    for key in ("pid", "success", "errorCategory", "duplicate"):
        if key in value: result[key] = value[key]
    return result


def _remote_payload(value: Mapping[str, Any]) -> bytes:
    """Frame the private SSH stdin payload so helper bytes never become argv."""
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    if not 0 < len(raw) <= _MAX_REMOTE_PAYLOAD:
        raise WindowsCredentialProbeSshError("Credential probe private payload is too large.")
    return struct.pack(">I", len(raw)) + raw


def _remote_command(program: str, *arguments: str) -> tuple[str, ...]:
    """Carry fixed multiline remote code as a control-character-free SSH argv item."""
    return ("python3", "-c", "exec(" + repr(program) + ")", *arguments)


def start_with_private_secret(root: Path | str, host: str, correlation_id: str, secret: bytes,
                              timeout_seconds: int = ssh_transport.DEFAULT_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Internal fixed dispatch for a privately generated fixture credential.

    The MCP route still uses ``start`` and its configured credential file. This
    entry point keeps the same frozen helper, journal, and QGA operation while a
    recovery verifies a new store handle before publishing it as active.
    """
    _correlation(correlation_id); config = _config(root)
    target = config.hosts.get(host)
    if target is None or target.fixture_transfer_root is None: raise WindowsCredentialProbeSshError("Configured fixture transfer root is required.")
    env, socket, pid, ticks, account, sid, _ = _descriptor(target)
    if not isinstance(secret, bytes) or not 0 < len(secret) <= _MAX_SECRET:
        raise WindowsCredentialProbeSshError("Private generated credential is invalid.")
    helpers, hashes = _capture_helpers()
    root_path = Path(root).resolve()
    record = {"host": host, "environment": env, "socketPath": socket, "pid": pid, "startTicks": ticks, "accountName": account, "expectedSid": sid, "helperHashes": hashes}
    _write_intent(root_path, correlation_id, record)
    payload = {"schema": 1, "socketPath": socket, "pid": pid, "startTicks": ticks, "accountName": account, "expectedSid": sid, "helpers": helpers, "credential": base64.b64encode(secret).decode("ascii")}
    secret = b""
    raw = _run_ssh(config, host, _remote_command(_REMOTE_START, str(target.fixture_transfer_root), env, correlation_id), _remote_payload(payload), timeout_seconds)
    return _public(raw, correlation_id)


def start(root: Path | str, host: str, correlation_id: str, timeout_seconds: int = ssh_transport.DEFAULT_TIMEOUT_SECONDS) -> dict[str, Any]:
    config = _config(root)
    target = config.hosts.get(host)
    if target is None:
        raise WindowsCredentialProbeSshError("Configured fixture transfer root is required.")
    _, _, _, _, _, _, credential = _descriptor(target)
    return start_with_private_secret(root, host, correlation_id, _private_secret(credential), timeout_seconds)


def status(root: Path | str, host: str, correlation_id: str, timeout_seconds: int = ssh_transport.DEFAULT_TIMEOUT_SECONDS) -> dict[str, Any]:
    _correlation(correlation_id); root_path = Path(root).resolve(); intent = _read_intent(root_path, correlation_id)
    if intent["host"] != host: raise WindowsCredentialProbeSshError("Credential probe correlation binding is invalid.")
    config = _config(root); target = config.hosts.get(host)
    if target is None or target.fixture_transfer_root is None: raise WindowsCredentialProbeSshError("Configured fixture transfer root is required.")
    # Only the durable binding controls observation; local helper source changes are irrelevant.
    raw = _run_ssh(config, host, _remote_command(_REMOTE_STATUS, str(target.fixture_transfer_root), intent["environment"], correlation_id), None, timeout_seconds)
    return _public(raw, correlation_id)

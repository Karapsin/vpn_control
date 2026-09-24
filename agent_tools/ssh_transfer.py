"""Narrow, verified SSH publication for the checked-in desktop fixture entrypoint.

This is deliberately not a remote command facility.  It accepts one fixed set of
small, checked-in Python helpers, records a correlation before connecting, and
publishes bytes only after the receiver has verified them.  It never starts a
fixture, installer, VM, VPN, or arbitrary remote program.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import select
import stat
import subprocess
import threading
import time
from typing import Any, Mapping

try:
    from . import ssh_transport
except ImportError:  # pragma: no cover
    import ssh_transport


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = REPO_ROOT / "scripts"
SCENARIO_ID = "desktop-update-entrypoint"
MANIFEST_NAME = "SHA256SUMS.txt"
CANONICAL_HELPERS = (
    "prepare_desktop_update_fixture.py",
    "fixture_environment.py",
    "macos_packaging_jdk_preflight.py",
)
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_OUTPUT_BYTES = 4096
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class SshTransferError(ValueError):
    """The fixed fixture transfer could not be safely prepared."""


@dataclass(frozen=True)
class TransferIdentity:
    scenario_id: str
    owner: str
    environment: str
    correlation_id: str
    source_manifest_sha256: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "TransferIdentity":
        required = {"scenarioId", "owner", "environment", "correlationId", "sourceManifestSha256"}
        if not isinstance(value, Mapping) or set(value) != required:
            raise SshTransferError("Transfer identity has unsupported or missing fields.")
        scenario = value["scenarioId"]
        if scenario != SCENARIO_ID:
            raise SshTransferError("Transfer scenario is not approved.")
        fields = (("owner", value["owner"]), ("environment", value["environment"]),
                  ("correlationId", value["correlationId"]))
        for label, field in fields:
            if not isinstance(field, str) or not _ID.fullmatch(field):
                raise SshTransferError(f"Transfer identity {label} is invalid.")
        digest = value["sourceManifestSha256"]
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise SshTransferError("Transfer identity source manifest SHA-256 is invalid.")
        return cls(scenario, value["owner"], value["environment"], value["correlationId"], digest)

    def as_dict(self) -> dict[str, str]:
        return {"scenarioId": self.scenario_id, "owner": self.owner,
                "environment": self.environment, "correlationId": self.correlation_id,
                "sourceManifestSha256": self.source_manifest_sha256}


@dataclass(frozen=True)
class CapturedSource:
    identity: TransferIdentity
    contents: Mapping[str, bytes]
    hashes: Mapping[str, str]


def _sha256(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def _capture_source(source_directory: Path | str, owner: str, environment: str,
                    correlation_id: str) -> CapturedSource:
    """Freeze exactly the fixed helper set and its deterministic manifest once."""
    source = Path(source_directory)
    if not source.is_absolute() or source.is_symlink() or not source.is_dir():
        raise SshTransferError("Fixture source directory must be an absolute regular directory.")
    identity_stub = {"scenarioId": SCENARIO_ID, "owner": owner, "environment": environment,
                     "correlationId": correlation_id, "sourceManifestSha256": "0" * 64}
    TransferIdentity.from_mapping(identity_stub)
    expected_names = set(CANONICAL_HELPERS) | {MANIFEST_NAME}
    try:
        entries = {entry.name: entry for entry in source.iterdir()}
    except OSError as error:
        raise SshTransferError("Fixture source directory cannot be read.") from error
    if set(entries) != expected_names:
        raise SshTransferError("Fixture source must contain exactly the approved helpers and SHA256SUMS.txt.")
    contents: dict[str, bytes] = {}
    for name in (*CANONICAL_HELPERS, MANIFEST_NAME):
        path = entries[name]
        try:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_size <= 0 or info.st_size > MAX_FILE_BYTES:
                raise SshTransferError(f"Fixture source file is not an approved regular size: {name}")
            contents[name] = path.read_bytes()
        except OSError as error:
            raise SshTransferError(f"Fixture source file cannot be read: {name}") from error
    helper_hashes = {name: _sha256(contents[name]) for name in CANONICAL_HELPERS}
    for name in CANONICAL_HELPERS:
        try:
            canonical = (SCRIPTS_ROOT / name).read_bytes()
        except OSError as error:
            raise SshTransferError(f"Checked-in fixture helper cannot be read: {name}") from error
        if contents[name] != canonical:
            raise SshTransferError(f"Fixture helper differs from checked-in {name}.")
    expected_manifest = "".join(f"{helper_hashes[name]}  {name}\n" for name in sorted(CANONICAL_HELPERS)).encode()
    if contents[MANIFEST_NAME] != expected_manifest:
        raise SshTransferError("Fixture SHA256SUMS.txt does not exactly describe the approved helpers.")
    manifest_hash = _sha256(contents[MANIFEST_NAME])
    identity = TransferIdentity(SCENARIO_ID, owner, environment, correlation_id, manifest_hash)
    return CapturedSource(identity, contents, {**helper_hashes, MANIFEST_NAME: manifest_hash})


def _intent_path(root: Path, identity: TransferIdentity) -> Path:
    return root / ".rag_index" / "ssh-transfer-receipts" / f"{identity.correlation_id}.json"


def _private_intent(root: Path, host: str, remote_root: PurePosixPath, identity: TransferIdentity, hashes: Mapping[str, str]) -> Path:
    """Reserve a local durable identity before the first remote write attempt."""
    index = root / ".rag_index"
    try:
        if index.exists() or index.is_symlink():
            metadata = index.lstat()
            if index.is_symlink() or not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
                raise SshTransferError("Local transfer receipt parent is unsafe.")
        else:
            index.mkdir(mode=0o700)
        directory = _intent_path(root, identity).parent
    except OSError as error:
        raise SshTransferError("Local transfer receipt parent cannot be prepared.") from error
    try:
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
        if directory.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise SshTransferError("Local transfer receipt directory is not private.")
        path = _intent_path(root, identity)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=True) as handle:
            json.dump({"identity": identity.as_dict(), "host": host, "fixtureTransferRoot": str(remote_root),
                       "hashes": dict(hashes), "state": "submitted"}, handle,
                      sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush(); os.fsync(handle.fileno())
        parent_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except FileExistsError as error:
        raise SshTransferError("Transfer correlation already has a durable local receipt.") from error
    except OSError as error:
        raise SshTransferError("Local transfer receipt cannot be reserved privately.") from error
    return path


def _require_intent(root: Path, host: str, remote_root: PurePosixPath, identity: TransferIdentity) -> Path:
    path = _intent_path(root, identity)
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            raw = source.read(8193)
        if not stat.S_ISREG(info.st_mode) or len(raw) > 8192:
            raise ValueError
        value = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SshTransferError("No matching durable transfer intent is available for status.") from error
    if not isinstance(value, dict) or value.get("identity") != identity.as_dict() or value.get("host") != host or value.get("fixtureTransferRoot") != str(remote_root):
        raise SshTransferError("Transfer intent does not match this host or destination.")
    return path


_RECEIVER = r'''import errno,hashlib,json,os,stat,sys
root,owner,environment,correlation,expected_manifest=sys.argv[1:]
names=("fixture_environment.py","macos_packaging_jdk_preflight.py","prepare_desktop_update_fixture.py")
ident={"scenarioId":"desktop-update-entrypoint","owner":owner,"environment":environment,"correlationId":correlation,"sourceManifestSha256":expected_manifest}
def bad(message): raise ValueError(message)
DIR_FLAGS=os.O_RDONLY|os.O_DIRECTORY|getattr(os,"O_NOFOLLOW",0)
def private_fd(fd):
 info=os.fstat(fd)
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700: bad("unsafe private directory")
def anchored_root(path):
 if not path.startswith("/"): bad("invalid private directory")
 fd=os.open("/",DIR_FLAGS)
 try:
  for part in path.split("/")[1:]:
   if not part or part in (".",".."): bad("invalid private directory")
   child=os.open(part,DIR_FLAGS,dir_fd=fd); os.close(fd); fd=child
  private_fd(fd); return fd
 except Exception:
  os.close(fd); raise
def private_child(parent,name,create=False):
 try: fd=os.open(name,DIR_FLAGS,dir_fd=parent)
 except OSError as error:
  if not create or error.errno!=errno.ENOENT: raise
  os.mkdir(name,0o700,dir_fd=parent)
  fd=os.open(name,DIR_FLAGS,dir_fd=parent)
 private_fd(fd); return fd
root_fd=anchored_root(root)
environment_fd=private_child(root_fd,environment,True)
owner_fd=private_child(environment_fd,owner,True)
# Reserve the final leaf before receiving.  Receipt creation below is the only
# publication marker, so an interrupted stream remains nonterminal and cannot
# be replaced by another submitter.
os.mkdir(correlation,0o700,dir_fd=owner_fd)
stage_fd=os.open(correlation,DIR_FLAGS,dir_fd=owner_fd); private_fd(stage_fd)
try:
 header=sys.stdin.buffer.readline(4097)
 if not header or len(header)>4096: bad("invalid transfer header")
 value=json.loads(header.decode("utf-8"))
 if set(value)!={"schema","files"} or value["schema"]!=1 or not isinstance(value["files"],list): bad("invalid transfer header")
 files=value["files"]
 if [f.get("name") if isinstance(f,dict) else None for f in files] != list(names): bad("unexpected transfer files")
 expected={}
 for item in files:
  size,digest=item.get("size"),item.get("sha256")
  if type(size) is not int or size<=0 or size>8388608 or type(digest) is not str or len(digest)!=64 or any(c not in "0123456789abcdef" for c in digest): bad("invalid transfer file metadata")
  expected[item["name"]]=(size,digest)
 actual={}
 for name in names:
  size,digest=expected[name]; fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600,dir_fd=stage_fd)
  h=hashlib.sha256(); left=size
  with os.fdopen(fd,"wb") as target:
   while left:
    chunk=sys.stdin.buffer.read(min(left,65536))
    if not chunk: bad("interrupted transfer stream")
    target.write(chunk); h.update(chunk); left-=len(chunk)
   target.flush(); os.fsync(target.fileno())
  if h.hexdigest()!=digest: bad("transferred file hash mismatch")
  actual[name]=digest
 manifest="".join(actual[n]+"  "+n+"\n" for n in names).encode()
 if hashlib.sha256(manifest).hexdigest()!=expected_manifest: bad("manifest hash mismatch")
 fd=os.open("SHA256SUMS.txt",os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600,dir_fd=stage_fd)
 with os.fdopen(fd,"wb") as out: out.write(manifest); out.flush(); os.fsync(out.fileno())
 receipt={"identity":ident,"state":"published","hashes":{**actual,"SHA256SUMS.txt":expected_manifest}}
 fd=os.open("receipt.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600,dir_fd=stage_fd)
 with os.fdopen(fd,"w",encoding="utf-8") as out: json.dump(receipt,out,sort_keys=True,separators=(",",":")); out.write("\n"); out.flush(); os.fsync(out.fileno())
 for directory_fd in (stage_fd,owner_fd,environment_fd,root_fd): os.fsync(directory_fd)
 print(json.dumps(receipt,sort_keys=True,separators=(",",":")))
except Exception as error:
 print(json.dumps({"state":"unknown","reason":"publish_failed"},separators=(",",":")))
 raise SystemExit(64)
finally:
 for fd in (stage_fd,owner_fd,environment_fd,root_fd): os.close(fd)'''
_STATUS = r'''import hashlib,json,os,stat,sys
root,owner,environment,correlation,expected=sys.argv[1:]
def unknown(reason): print(json.dumps({"state":"unknown","reason":reason},separators=(",",":"))); raise SystemExit(0)
DIR_FLAGS=os.O_RDONLY|os.O_DIRECTORY|getattr(os,"O_NOFOLLOW",0)
def private_fd(fd):
 info=os.fstat(fd)
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700: unknown("unsafe_destination")
def anchored_root(path):
 if not path.startswith("/"): unknown("unsafe_destination")
 fd=os.open("/",DIR_FLAGS)
 try:
  for part in path.split("/")[1:]:
   if not part or part in (".",".."): unknown("unsafe_destination")
   child=os.open(part,DIR_FLAGS,dir_fd=fd); os.close(fd); fd=child
  private_fd(fd); return fd
 except Exception:
  os.close(fd); raise
def child(parent,name):
 fd=os.open(name,DIR_FLAGS,dir_fd=parent); private_fd(fd); return fd
def read_regular(parent,name,limit):
 fd=os.open(name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_NONBLOCK",0),dir_fd=parent)
 try:
  if not stat.S_ISREG(os.fstat(fd).st_mode): unknown("invalid_receipt")
  chunks=[]; total=0
  while total<=limit:
   chunk=os.read(fd,min(65536,limit+1-total))
   if not chunk: return b"".join(chunks)
   chunks.append(chunk); total+=len(chunk)
  unknown("invalid_receipt")
 finally: os.close(fd)
try:
 root_fd=anchored_root(root); environment_fd=child(root_fd,environment); owner_fd=child(environment_fd,owner); parent_fd=child(owner_fd,correlation)
 raw=read_regular(parent_fd,"receipt.json",4096)
 value=json.loads(raw.decode("utf-8"))
 ident=value.get("identity") if isinstance(value,dict) else None
 if value.get("state")!="published" or not isinstance(ident,dict) or ident!={"scenarioId":"desktop-update-entrypoint","owner":owner,"environment":environment,"correlationId":correlation,"sourceManifestSha256":expected}: unknown("receipt_mismatch")
 hashes=value.get("hashes")
 names=("fixture_environment.py","macos_packaging_jdk_preflight.py","prepare_desktop_update_fixture.py")
 if not isinstance(hashes,dict) or set(hashes)!=set(names)|{"SHA256SUMS.txt"} or hashes.get("SHA256SUMS.txt")!=expected: unknown("invalid_receipt")
 for name in names:
  digest=hashes.get(name)
  if not isinstance(digest,str) or len(digest)!=64: unknown("invalid_receipt")
  if hashlib.sha256(read_regular(parent_fd,name,8388608)).hexdigest()!=digest: unknown("destination_hash_mismatch")
 manifest="".join(hashes[n]+"  "+n+"\n" for n in names).encode()
 actual_manifest=read_regular(parent_fd,"SHA256SUMS.txt",8388608)
 if hashlib.sha256(manifest).hexdigest()!=expected or actual_manifest!=manifest: unknown("destination_hash_mismatch")
 print(json.dumps({"state":"published","identity":ident,"hashes":value.get("hashes")},sort_keys=True,separators=(",",":")))
except FileNotFoundError: unknown("not_published")
except (OSError,ValueError,UnicodeError,json.JSONDecodeError): unknown("invalid_receipt")
finally:
 for name in ("parent_fd","owner_fd","environment_fd","root_fd"):
  if name in globals(): os.close(globals()[name])'''


def _python_command(program: str, *arguments: str) -> tuple[str, ...]:
    return ("python3", "-c", "exec(" + repr(program) + ")", *arguments)


def _bounded_run(argv: list[str], payload: bytes | None, timeout_seconds: int) -> tuple[int, bytes]:
    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError as error:
        raise SshTransferError("ssh_unavailable") from error
    assert process.stdin is not None and process.stdout is not None
    writer_error: list[OSError] = []
    def write_input() -> None:
        try:
            if payload: process.stdin.write(payload); process.stdin.flush()
        except OSError as error: writer_error.append(error)
        finally:
            try: process.stdin.close()
            except OSError: pass
    writer = threading.Thread(target=write_input, daemon=True); writer.start()
    chunks: list[bytes] = []; received = 0; deadline = time.monotonic() + timeout_seconds + 1
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise SshTransferError("timeout")
            ready, _, _ = select.select([process.stdout], [], [], remaining)
            if ready:
                chunk = os.read(process.stdout.fileno(), min(1024, MAX_OUTPUT_BYTES + 1 - received))
                if chunk:
                    chunks.append(chunk); received += len(chunk)
                    if received > MAX_OUTPUT_BYTES: raise SshTransferError("oversized_remote_output")
                    continue
                if process.poll() is not None: return process.returncode, b"".join(chunks)
            if process.poll() is not None and not ready: continue
    except SshTransferError:
        process.kill(); process.wait()
        raise
    except (OSError, ValueError) as error:
        process.kill(); process.wait()
        raise SshTransferError("ssh_io_error") from error
    finally:
        process.stdout.close(); writer.join(timeout=0.1)


def _transfer_root(config: Any, host: str) -> PurePosixPath:
    if host not in config.hosts:
        raise SshTransferError("Unknown VM host alias.")
    target = config.hosts[host]
    connection = config.hosts[target.gateway] if target.transport == "nested" else target
    if connection.password is not None:
        raise SshTransferError("Fixture transfer requires a key or agent profile.")
    root = getattr(target, "fixture_transfer_root", None)
    if not isinstance(root, PurePosixPath) or not root.is_absolute():
        raise SshTransferError("VM host has no approved fixture transfer root.")
    return root


def _payload(source: CapturedSource) -> bytes:
    files = [{"name": name, "size": len(source.contents[name]), "sha256": source.hashes[name]}
             for name in sorted(CANONICAL_HELPERS)]
    return json.dumps({"schema": 1, "files": files}, sort_keys=True, separators=(",", ":")).encode() + b"\n" + b"".join(source.contents[item["name"]] for item in files)


def _parse_remote(output: bytes) -> dict[str, Any] | None:
    try:
        value = json.loads(output.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def publish(root: Path | str, host: str, source_directory: Path | str, owner: str, environment: str,
            correlation_id: str, timeout_seconds: int = ssh_transport.DEFAULT_TIMEOUT_SECONDS,
            ssh_binary: str = "ssh") -> dict[str, Any]:
    source = _capture_source(source_directory, owner, environment, correlation_id)
    try:
        config = ssh_transport.load_config(root)
        remote_root = _transfer_root(config, host)
        intent = _private_intent(Path(root).resolve(), host, remote_root, source.identity, source.hashes)
        argv = ssh_transport.build_ssh_argv(config, host, timeout_seconds,
            command=_python_command(_RECEIVER, str(remote_root), source.identity.owner, source.identity.environment,
                                    source.identity.correlation_id, source.identity.source_manifest_sha256), ssh_binary=ssh_binary)
        returncode, output = _bounded_run(argv, _payload(source), timeout_seconds)
    except (ssh_transport.SshConfigError, SshTransferError) as error:
        return {"ok": False, "state": "unknown", "reason": str(error), "identity": source.identity.as_dict(), "intentPath": str(locals().get("intent", ""))}
    remote = _parse_remote(output)
    if returncode == 255:
        return {"ok": False, "state": "unknown", "reason": "ssh_transport_unavailable",
                "identity": source.identity.as_dict(), "intentPath": str(intent)}
    if returncode != 0 or remote is None or remote.get("state") != "published" or remote.get("identity") != source.identity.as_dict() or remote.get("hashes") != dict(source.hashes):
        return {"ok": False, "state": "unknown", "reason": "interrupted_or_unverified", "identity": source.identity.as_dict(), "intentPath": str(intent)}
    return {"ok": True, "state": "published", "identity": source.identity.as_dict(), "sourceHashes": dict(source.hashes),
            "destinationHashes": remote.get("hashes"), "intentPath": str(intent)}


def status(root: Path | str, host: str, identity: Mapping[str, Any], timeout_seconds: int = ssh_transport.DEFAULT_TIMEOUT_SECONDS,
           ssh_binary: str = "ssh") -> dict[str, Any]:
    value = TransferIdentity.from_mapping(identity)
    try:
        config = ssh_transport.load_config(root); remote_root = _transfer_root(config, host)
        _require_intent(Path(root).resolve(), host, remote_root, value)
        argv = ssh_transport.build_ssh_argv(config, host, timeout_seconds,
            command=_python_command(_STATUS, str(remote_root), value.owner, value.environment, value.correlation_id,
                                    value.source_manifest_sha256), ssh_binary=ssh_binary)
        returncode, output = _bounded_run(argv, None, timeout_seconds)
    except (ssh_transport.SshConfigError, SshTransferError) as error:
        return {"ok": False, "state": "unknown", "reason": str(error), "identity": value.as_dict()}
    remote = _parse_remote(output)
    if returncode == 255:
        return {"ok": False, "state": "unknown", "reason": "ssh_transport_unavailable", "identity": value.as_dict()}
    if returncode != 0 or remote is None or remote.get("state") != "published" or remote.get("identity") != value.as_dict():
        return {"ok": False, "state": "unknown", "reason": remote.get("reason", "interrupted_or_unverified") if remote else "interrupted_or_unverified", "identity": value.as_dict()}
    return {"ok": True, "state": "published", "identity": value.as_dict(), "destinationHashes": remote.get("hashes")}

"""Journaled, fixed Fedora HTTPS fixture server for one public RPM intent.

The route owns a server workspace separate from the public install job. It
stages only verified same-source RPM bytes and fixed server code. A lost start
response is observed through the original correlation; start never replays it.
"""

from __future__ import annotations

from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import tempfile
import threading
from typing import Any, Mapping

from . import (native_artifact_registry, native_rpm_public_install_adapter as adapter,
               native_rpm_public_install_ssh as rpm, native_scenario_bundle,
               native_scenario_ssh, ssh_transport)


_SHA = re.compile(r"[0-9a-f]{40}\Z")
_ARTIFACT = re.compile(r"sha256-[0-9a-f]{64}\Z")
_HOST = "fedora2328"
_ENVIRONMENT = "fedora2328"
_STATE = Path(".rag_index/linux-rpm-fixture-server")
_SOURCE_FILES = (
    "scripts/prepare_desktop_update_fixture.py",
    "scripts/fixture_environment.py",
    "scripts/macos_packaging_jdk_preflight.py",
    "agent_tools/linux_rpm_fixture_server.py",
    "agent_tools/linux_rpm_fixture_server_guest.py",
)
_MAX_PAYLOAD = 1024 * 1024 * 1024


class LinuxRpmFixtureServerError(ValueError):
    pass


def _require(value: bool, reason: str) -> None:
    if not value:
        raise LinuxRpmFixtureServerError(reason)


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _request(raw: Mapping[str, Any]) -> tuple[dict[str, Any], adapter.RpmPublicInstallIntent]:
    required = {"sourceSha", "scenarioId", "host", "environment", "bundleHash",
                "artifactIds", "credentialHandle", "correlationId"}
    _require(isinstance(raw, Mapping) and set(raw) == required, "Invalid Fedora fixture server request.")
    source = raw["sourceSha"]
    _require(isinstance(source, str) and bool(_SHA.fullmatch(source)), "Invalid exact source SHA.")
    _require(raw["host"] == _HOST and raw["environment"] == _ENVIRONMENT,
             "Fixture server requires the identified Fedora guest.")
    intent = adapter.RpmPublicInstallIntent.from_mapping({key: value for key, value in raw.items()
                                                          if key != "sourceSha"})
    return dict(raw), intent


def _registered(root: Path, artifact_id: str, source: str) -> Path:
    _require(isinstance(artifact_id, str) and bool(_ARTIFACT.fullmatch(artifact_id)),
             "Fixture artifact ID is invalid.")
    value = native_artifact_registry.verify_artifact(root, artifact_id)
    item, location = value.get("artifact"), value.get("location")
    _require(value.get("verification") == "verified" and isinstance(item, Mapping) and
             isinstance(location, Mapping) and item.get("sourceSha") == source and
             isinstance(location.get("localPath"), str), "Exact-source fixture artifact is unavailable.")
    return Path(location["localPath"])


def _admit(root: Path, request: Mapping[str, Any], intent: adapter.RpmPublicInstallIntent) -> dict[str, Any]:
    source = request["sourceSha"]
    head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True,
                          text=True, timeout=10, check=False)
    _require(head.returncode == 0 and head.stdout.strip() == source,
             "Server fixture source differs from checkout HEAD.")
    # Public admission proves the owner-only authorization handle is bound to
    # this full intent before a server correlation is journaled or sent.
    public_admission = rpm.admission(root, intent)
    paths = public_admission["paths"]
    typed = public_admission["typed"]
    for label, artifact_id in intent.artifact_ids.items():
        _require(paths[label] == _registered(root, artifact_id, source),
                 "Server fixture artifact differs from public admission.")
    receipt = rpm._fixture(paths["sourceFixture"], typed)
    provenance = receipt.get("derivedFrom")
    _require(isinstance(provenance, dict) and provenance.get("scope") == "rpm-only" and
             provenance.get("sourceShaFromSnapshot") == source and
             provenance.get("sourceFingerprint") == typed["sourceFingerprint"],
             "RPM-only fixture provenance differs from exact source.")
    _require(rpm._sha(paths["targetPackage"], 1024 * 1024 * 1024) == typed["targetPackageSha256"],
             "Server target RPM bytes changed.")
    config = public_admission["config"]
    host = config.hosts.get(_HOST)
    _require(host is not None and host.user == "vpnfixture" and
             host.fixture_transfer_root is not None and host.fixture_transfer_root.is_absolute(),
             "Fedora fixture account/root is unavailable.")
    public = {**intent.public_mapping(), "sourceSha": source,
              "sourceFingerprint": typed["sourceFingerprint"],
              "expectedBaseVersion": typed["expectedBaseVersion"],
              "expectedTargetVersion": typed["expectedTargetVersion"],
              "expectedBaseNevra": typed["expectedBaseNevra"],
              "expectedTargetNevra": typed["expectedTargetNevra"],
              "publicIntentSha256": hashlib.sha256(_canonical(intent.public_mapping())).hexdigest(),
              "authorizationHandleSha256": hashlib.sha256(intent.credential_handle.encode()).hexdigest()}
    return {"paths": paths, "typed": typed, "public": public,
            "config": config, "remoteRoot": str(host.fixture_transfer_root)}


def _state_dir(root: Path, *, create: bool) -> Path | None:
    directory = root / _STATE
    if create:
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    if not directory.exists():
        return None
    info = directory.lstat()
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
             stat.S_IMODE(info.st_mode) == 0o700, "Fixture server journal directory is unsafe.")
    return directory


def _journal(root: Path, correlation: str) -> dict[str, Any] | None:
    directory = _state_dir(root, create=False)
    if directory is None:
        return None
    path = directory / (correlation + ".json")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                 stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 8192,
                 "Fixture server journal is unsafe.")
        raw = os.read(fd, info.st_size + 1)
        _require(len(raw) == info.st_size, "Fixture server journal changed.")
        value = json.loads(raw)
        _require(isinstance(value, dict) and value.get("correlationId") == correlation,
                 "Fixture server journal is invalid.")
        return value
    finally:
        os.close(fd)


def _save_journal(root: Path, value: Mapping[str, Any]) -> None:
    directory = _state_dir(root, create=True)
    assert directory is not None
    path = directory / (value["correlationId"] + ".json")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(_canonical(value))
        stream.flush()
        os.fsync(stream.fileno())
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _payload(root: Path, captured: Mapping[str, Any], destination: Path) -> dict[str, dict[str, Any]]:
    files: dict[str, Path] = {"source-fixture.tar": captured["paths"]["sourceFixture"]}
    for name in _SOURCE_FILES:
        path = root / name
        _require(path.is_file() and not path.is_symlink(), "Server helper source is missing or unsafe.")
        files[name] = path
    hashes: dict[str, dict[str, Any]] = {}
    with tarfile.open(destination, "w") as archive:
        for name, path in files.items():
            size = path.stat().st_size
            _require(0 < size <= (1024 * 1024 * 1024 if name == "source-fixture.tar" else 1024 * 1024),
                     "Server payload member exceeds its bound.")
            digest = rpm._sha(path, size)
            archive.add(path, arcname=name, recursive=False)
            hashes[name] = {"size": size, "sha256": digest}
    _require(destination.stat().st_size <= _MAX_PAYLOAD, "Server payload exceeds its bound.")
    return hashes


_SUBMIT = r'''import hashlib,json,os,pwd,stat,subprocess,sys,tarfile
root,metadata,size,digest=sys.argv[1:]; intent=json.loads(metadata); size=int(size)
def fail(reason):
 print(json.dumps({'state':'unknown','correlationId':intent.get('correlationId'),'reason':reason,'replayAllowed':False},separators=(',',':')));raise SystemExit(0)
if pwd.getpwuid(os.geteuid()).pw_name!='vpnfixture':fail('wrong-account')
if not os.path.isabs(root) or '..' in root.split('/') or not 0<size<=1073741824:fail('invalid-root-or-size')
info=os.stat(root,follow_symlinks=False)
if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:fail('unsafe-root')
parent=os.path.join(root,'linux-rpm-fixture-server-jobs');os.makedirs(parent,mode=0o700,exist_ok=True)
info=os.stat(parent,follow_symlinks=False)
if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:fail('unsafe-parent')
job=os.path.join(parent,intent['correlationId'])
try:os.mkdir(job,0o700)
except FileExistsError:fail('existing-correlation')
def durable(path,value):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as out:out.write((json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode());out.flush();os.fsync(out.fileno())
 fd=os.open(job,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
durable(os.path.join(job,'intent.json'),intent)
payload=os.path.join(job,'payload.tar');fd=os.open(payload,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
remaining=size;h=hashlib.sha256()
with os.fdopen(fd,'wb') as out:
 while remaining:
  block=sys.stdin.buffer.read(min(65536,remaining))
  if not block:fail('transfer-interrupted')
  out.write(block);h.update(block);remaining-=len(block)
 out.flush();os.fsync(out.fileno())
if h.hexdigest()!=digest:fail('payload-digest-mismatch')
stage=os.path.join(job,'stage');os.mkdir(stage,0o700)
expected=intent['fileHashes']
with tarfile.open(payload,'r:') as bundle:
 members=bundle.getmembers()
 if {m.name for m in members}!=set(expected) or len(members)!=len(expected):fail('payload-inventory-mismatch')
 for member in members:
  name=member.name
  if not member.isfile() or name.startswith('/') or '..' in name.split('/') or member.size!=expected[name]['size'] or member.size>1073741824:fail('payload-member-unsafe')
  path=os.path.join(stage,name);os.makedirs(os.path.dirname(path),mode=0o700,exist_ok=True)
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);h=hashlib.sha256()
  with os.fdopen(fd,'wb') as out:
   source=bundle.extractfile(member)
   while block:=source.read(65536):out.write(block);h.update(block)
   out.flush();os.fsync(out.fileno())
  if h.hexdigest()!=expected[name]['sha256']:fail('payload-member-digest-mismatch')
fixture=os.path.join(stage,'fixture');os.mkdir(fixture,0o700)
with tarfile.open(os.path.join(stage,'source-fixture.tar'),'r:*') as bundle:
 members=bundle.getmembers();seen=set()
 for member in members:
  name=member.name.removeprefix('./')
  if not member.isfile() or name in seen or name.startswith('/') or '..' in name.split('/') or not (name=='fixture-receipt.json' or name.startswith('packages/base/') or name.startswith('packages/target/')) or member.size>1073741824:fail('fixture-member-unsafe')
  seen.add(name);path=os.path.join(fixture,name);os.makedirs(os.path.dirname(path),mode=0o700,exist_ok=True)
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
  with os.fdopen(fd,'wb') as out:
   source=bundle.extractfile(member)
   while block:=source.read(65536):out.write(block)
   out.flush();os.fsync(out.fileno())
 if len(seen)!=3:fail('fixture-inventory-mismatch')
worker=os.path.join(stage,'agent_tools','linux_rpm_fixture_server_guest.py')
proc=subprocess.Popen([sys.executable,'-I','-B',worker,'prepare',job],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
durable(os.path.join(job,'worker-process.json'),{'pid':proc.pid,'correlationId':intent['correlationId']})
print(json.dumps({'state':'submitted','correlationId':intent['correlationId'],'replayAllowed':False},separators=(',',':')))
'''


_STATUS = r'''import hashlib,json,os,pwd,stat,subprocess,sys
root,corr,worker_sha,guard_sha=sys.argv[1:]
def unknown():print(json.dumps({'state':'unknown','correlationId':corr,'replayAllowed':False},separators=(',',':')));raise SystemExit(0)
if pwd.getpwuid(os.geteuid()).pw_name!='vpnfixture' or not os.path.isabs(root) or '..' in root.split('/'):unknown()
job=os.path.join(root,'linux-rpm-fixture-server-jobs',corr)
try:
 info=os.stat(job,follow_symlinks=False)
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:unknown()
 worker=os.path.join(job,'stage','agent_tools','linux_rpm_fixture_server_guest.py')
 info=os.stat(worker,follow_symlinks=False)
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>1048576:unknown()
 fd=os.open(worker,os.O_RDONLY|os.O_NOFOLLOW);h=hashlib.sha256();chunks=[]
 try:
  while block:=os.read(fd,65536):h.update(block);chunks.append(block)
  after=os.fstat(fd)
 finally:os.close(fd)
 if h.hexdigest()!=worker_sha or (info.st_dev,info.st_ino,info.st_size)!=(after.st_dev,after.st_ino,after.st_size):unknown()
 worker_source=b''.join(chunks).decode('utf-8')
 guard=os.path.join(job,'stage','linux-rpm-fixture-server.py')
 info=os.stat(guard,follow_symlinks=False)
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>1048576:unknown()
 fd=os.open(guard,os.O_RDONLY|os.O_NOFOLLOW);h=hashlib.sha256()
 try:
  while block:=os.read(fd,65536):h.update(block)
  after=os.fstat(fd)
 finally:os.close(fd)
 if h.hexdigest()!=guard_sha or (info.st_dev,info.st_ino,info.st_size)!=(after.st_dev,after.st_ino,after.st_size):unknown()
 result=subprocess.run([sys.executable,'-I','-B','-c',worker_source,'status',job,guard_sha],capture_output=True,text=True,timeout=30)
 if result.returncode or len(result.stdout)>4096:unknown()
 value=json.loads(result.stdout)
 if value.get('correlationId')!=corr or value.get('state') not in ('ready','unknown'):unknown()
 print(json.dumps(value,separators=(',',':')))
except Exception:unknown()
'''


def _remote(captured: Mapping[str, Any], program: str, args: tuple[str, ...],
            payload: Path | None = None) -> dict[str, Any] | None:
    config = captured["config"]
    command = native_scenario_ssh._py(program, *args)
    argv = ssh_transport.build_ssh_argv(config, _HOST, 30, command=command)
    connection = ssh_transport.connection_host(config, _HOST)
    context = tempfile.TemporaryDirectory(prefix="vpn-rpm-server-askpass-") if connection.password else nullcontext(None)
    with context as temporary:
        environment = (ssh_transport._askpass_environment(connection.password, Path(temporary))[1]
                       if temporary is not None else None)
        try:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, env=environment)
        except OSError:
            return None
        errors: list[Exception] = []
        def write() -> None:
            try:
                if payload is not None:
                    with payload.open("rb") as source:
                        while block := source.read(65536):
                            process.stdin.write(block)
                process.stdin.close()
            except (OSError, BrokenPipeError) as error:
                errors.append(error)
                try:
                    process.stdin.close()
                except OSError:
                    pass
        writer = threading.Thread(target=write, daemon=True)
        writer.start()
        timed_out = threading.Event()
        def timeout() -> None:
            timed_out.set()
            try:
                process.kill()
            except OSError:
                pass
        timer = threading.Timer(360 if payload is not None else 40, timeout)
        timer.start()
        try:
            output = process.stdout.read(8193)
            process.wait()
        finally:
            timer.cancel()
            process.stdout.close()
        writer.join(timeout=1)
        if timed_out.is_set() or errors or process.returncode != 0 or len(output) > 8192:
            return None
        try:
            value = json.loads(output)
            return value if isinstance(value, dict) else None
        except (UnicodeError, ValueError):
            return None


def start(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    root = Path(root).resolve(strict=True)
    request, intent = _request(inputs)
    captured = _admit(root, request, intent)
    record = captured["public"]
    if _journal(root, intent.correlation_id) is not None:
        raise LinuxRpmFixtureServerError("Fixture server correlation already has an intent; observe it.")
    with tempfile.TemporaryDirectory(prefix="vpn-rpm-server-transfer-") as temporary:
        payload = Path(temporary) / "server-payload.tar"
        hashes = _payload(root, captured, payload)
        record = {**record, "serverGuestSha256": hashes["agent_tools/linux_rpm_fixture_server_guest.py"]["sha256"],
                  "serverGuardSha256": hashes["agent_tools/linux_rpm_fixture_server.py"]["sha256"],
                  "payloadSha256": rpm._sha(payload, _MAX_PAYLOAD)}
        metadata = {**record, "fileHashes": hashes}
        # This exact record is durable before the first guest byte is sent.
        _save_journal(root, record)
        result = _remote(captured, _SUBMIT,
                         (captured["remoteRoot"], json.dumps(metadata, sort_keys=True, separators=(",", ":")),
                          str(payload.stat().st_size), record["payloadSha256"]), payload)
    if result and result.get("state") == "submitted" and result.get("correlationId") == intent.correlation_id:
        return result
    return {"state": "unknown", "correlationId": intent.correlation_id, "replayAllowed": False}


def status(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    _require(isinstance(inputs, Mapping) and set(inputs) == {"correlationId"},
             "Server status requires only correlationId.")
    correlation = inputs["correlationId"]
    _require(isinstance(correlation, str) and bool(re.fullmatch(r"[0-9a-f-]{36}", correlation)),
             "Server correlation is invalid.")
    root = Path(root).resolve(strict=True)
    record = _journal(root, correlation)
    if record is None:
        raise LinuxRpmFixtureServerError("Fixture server correlation is not journaled.")
    config = ssh_transport.load_config(root)
    host = config.hosts.get(_HOST)
    if host is None or host.user != "vpnfixture" or host.fixture_transfer_root is None:
        return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    captured = {"config": config}
    result = _remote(captured, _STATUS, (str(host.fixture_transfer_root), correlation,
                                         record["serverGuestSha256"], record["serverGuardSha256"]))
    if (result is None or result.get("state") != "ready" or
            result.get("correlationId") != correlation or
            result.get("sourceSha") != record["sourceSha"] or
            result.get("publicIntentSha256") != record["publicIntentSha256"]):
        return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    return result


def collect(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    return status(root, inputs)


def ready_for_public(root: Path | str, intent: adapter.RpmPublicInstallIntent,
                     source_fingerprint: str) -> bool:
    """Read one exact protected server journal and fresh live guest status."""
    try:
        root = Path(root).resolve(strict=True)
        record = _journal(root, intent.correlation_id)
        if record is None:
            return False
        head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10, check=False)
        public_digest = hashlib.sha256(_canonical(intent.public_mapping())).hexdigest()
        if (head.returncode != 0 or record.get("sourceSha") != head.stdout.strip() or
                record.get("sourceFingerprint") != source_fingerprint or
                record.get("publicIntentSha256") != public_digest or
                record.get("authorizationHandleSha256") !=
                hashlib.sha256(intent.credential_handle.encode()).hexdigest()):
            return False
        observed = status(root, {"correlationId": intent.correlation_id})
        return (observed.get("state") == "ready" and
                observed.get("correlationId") == intent.correlation_id and
                observed.get("sourceSha") == record["sourceSha"] and
                observed.get("publicIntentSha256") == public_digest)
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
        return False

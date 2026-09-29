"""Journaled, fixed Fedora HTTPS fixture server for one public RPM intent.

The route owns a server workspace separate from the public install job. It
stages only verified same-source RPM bytes and fixed server code. A lost start
response is observed through the original correlation; start never replays it.
"""

from __future__ import annotations

from contextlib import nullcontext
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
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
_STOP_STATE = Path(".rag_index/linux-rpm-fixture-server-stop")
_RECOVERED_PUBLIC = "944447ff-7ee3-42df-8ca8-f02dac670459"
_RECOVERED_CLEANUP = "5eac659d-a6d4-4005-b97a-40063b10d8bf"
_RECOVERED_SOURCE = "a876f46fa4582e6218d341ac7012fd31bc919758"
_RECOVERED_TARGET = "vpn-control-2.2.0-1.x86_64"
_RECOVERED_HEADER = "3ef23bc543b6302432f514edc94ba04d75a8dc3d"
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


def _guest_phase(job: Path, correlation: str, uid: int) -> str:
    """Classify only fixed private journal markers; never infer product success."""
    def marker(path: Path) -> bool | None:
        try:
            info = path.lstat()
        except FileNotFoundError:
            return False
        except OSError:
            return None
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o600:
            return None
        return True

    receipt = marker(job / "server-receipt.json")
    ready = marker(job / "fixture-server-ready.json")
    probe = marker(job / "stage" / "fixture" / "probe-events" / (correlation + ".json"))
    worker = marker(job / "worker-process.json")
    if None in (receipt, ready, probe, worker):
        return "uninspectable"
    if receipt:
        return "receipt-present-unverified"
    if ready and probe:
        return "probe-present-no-receipt"
    if ready:
        return "server-ready-no-probe"
    if worker:
        return "worker-submitted-no-ready"
    return "worker-marker-missing"


def _guest_log_signal(job: Path, uid: int) -> dict[str, str] | None:
    """Return only a fixed server failure stage and exception class."""
    path = job / "fixture-server.log"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid or
                stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= 65536):
            return None
        raw = os.read(fd, before.st_size + 1)
        after = os.fstat(fd)
        current = path.lstat()
        if (len(raw) != before.st_size or
                (before.st_dev, before.st_ino, before.st_size) !=
                (after.st_dev, after.st_ino, after.st_size) or
                (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino)):
            return None
        rows = raw.splitlines()
        if not rows or len(rows[-1]) > 1024:
            return None
        value = json.loads(rows[-1])
        stages = {"connect-admission", "tls-handshake", "tunneled-get"}
        errors = {"SSLError", "TimeoutError", "ConnectionResetError", "BrokenPipeError",
                  "ValueError", "EOFError", "OSError"}
        if (not isinstance(value, dict) or set(value) != {"request", "stage", "exceptionType"} or
                value["request"] != "closed-or-rejected" or value["stage"] not in stages or
                value["exceptionType"] not in errors):
            return None
        return {"stage": value["stage"], "exceptionType": value["exceptionType"]}
    except (OSError, UnicodeError, ValueError, TypeError):
        return None
    finally:
        os.close(fd)


def _guest_log_activity(job: Path, uid: int) -> str:
    """Classify the last private server log row without exporting its content."""
    try:
        fd = os.open(job / "fixture-server.log", os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return "empty"
    except OSError:
        return "uninspectable"
    try:
        info = os.fstat(fd)
        mode = stat.S_IMODE(info.st_mode)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or
                mode not in (0o600, 0o644) or info.st_size > 65536):
            return "uninspectable"
        prefix = "unsafe-" if mode == 0o644 else ""
        raw = os.read(fd, info.st_size + 1)
        after = os.fstat(fd)
        current = (job / "fixture-server.log").lstat()
        if (len(raw) != info.st_size or (info.st_dev, info.st_ino, info.st_size) !=
                (after.st_dev, after.st_ino, after.st_size) or
                (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)):
            return "uninspectable"
        rows = raw.splitlines()
        if not rows:
            return prefix + "empty"
        if len(rows[-1]) > 1024:
            return prefix + "unrecognized"
        value = json.loads(rows[-1])
        if (isinstance(value, dict) and set(value) == {"served", "bytes"} and
                value["served"] == "manifest" and type(value["bytes"]) is int and
                0 < value["bytes"] <= 1048576):
            return prefix + "manifest-served"
        if (isinstance(value, dict) and set(value) == {"request", "stage", "exceptionType"} and
                value.get("request") == "closed-or-rejected" and
                value.get("stage") in {"connect-admission", "tls-handshake", "tunneled-get"} and
                value.get("exceptionType") in {"SSLError", "TimeoutError", "ConnectionResetError",
                                               "BrokenPipeError", "ValueError", "EOFError", "OSError"}):
            return prefix + value["stage"] + "-" + value["exceptionType"]
        return prefix + "unrecognized"
    except (OSError, ValueError, UnicodeError, TypeError):
        return "uninspectable"
    finally:
        os.close(fd)


def _guest_private_json(path: Path, uid: int) -> dict[str, Any] | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid or
                stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= 8192):
            return None
        raw = os.read(fd, before.st_size + 1)
        after = os.fstat(fd)
        current = path.lstat()
        if (len(raw) != before.st_size or
                (before.st_dev, before.st_ino, before.st_size) !=
                (after.st_dev, after.st_ino, after.st_size) or
                (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino)):
            return None
        value = json.loads(raw)
        return value if isinstance(value, dict) else None
    except (OSError, ValueError, UnicodeError):
        return None
    finally:
        os.close(fd)


def _guest_worker_failure(job: Path, uid: int) -> dict[str, str] | None:
    value = _guest_private_json(job / "worker-failure.json", uid)
    if (not isinstance(value, dict) or
            set(value) not in ({"schemaVersion", "phase", "exceptionType"},
                               {"schemaVersion", "phase", "exceptionType", "failureKind"}) or
            value["schemaVersion"] != 1 or value["phase"] != "java-probe" or
            value["exceptionType"] not in {"ValueError", "TimeoutExpired", "OSError"}):
        return None
    result = {"phase": value["phase"], "exceptionType": value["exceptionType"]}
    if "failureKind" in value:
        if value["failureKind"] not in {"tls-handshake", "manifest-digest", "certificate-digest",
                                        "connection", "java-compile", "java-failed"}:
            return None
        result["failureKind"] = value["failureKind"]
    return result


def _guest_server_process(job: Path, uid: int, *, proc_root: Path = Path("/proc")) -> str:
    ready = _guest_private_json(job / "fixture-server-ready.json", uid)
    if ready is None:
        return "unverified"
    pid = ready.get("serverPid")
    identity = ready.get("serverProcessStartIdentity")
    if type(pid) is not int or pid <= 1 or not isinstance(identity, str):
        return "unverified"
    try:
        boot = (proc_root / "sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        prefix = "linux:" + boot + ":"
        if not identity.startswith(prefix) or not identity[len(prefix):].isdigit():
            return "unverified"
        process = proc_root / str(pid)
        if not process.exists():
            return "absent"
        parts = (process / "stat").read_text(encoding="ascii").rsplit(")", 1)[1].split()
        status = (process / "status").read_text(encoding="ascii")
        rows = [line.split()[1:] for line in status.splitlines() if line.startswith("Uid:")]
        if len(parts) <= 19 or len(rows) != 1 or len(rows[0]) != 4:
            return "unverified"
        if any(int(value) != uid for value in rows[0]):
            return "different-generation"
        if parts[0] == "Z":
            return "absent"
        return "live" if int(parts[19]) == int(identity[len(prefix):]) else "different-generation"
    except (OSError, ValueError, IndexError):
        return "unverified"


def _guest_stop_identity(job: Path, source: str, public_digest: str, uid: int,
                         *, proc_root: Path = Path("/proc")) -> int | None:
    """Admit only the exact fixture server process from this private job."""
    if job.parent.name != "linux-rpm-fixture-server-jobs":
        return None
    intent = _guest_private_json(job / "intent.json", uid)
    ready = _guest_private_json(job / "fixture-server-ready.json", uid)
    if (not isinstance(intent, dict) or not isinstance(ready, dict) or
            intent.get("correlationId") != job.name or intent.get("sourceSha") != source or
            intent.get("publicIntentSha256") != public_digest):
        return None
    pid, identity = ready.get("serverPid"), ready.get("serverProcessStartIdentity")
    if type(pid) is not int or pid <= 1 or not isinstance(identity, str):
        return None
    try:
        boot = (proc_root / "sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        prefix = "linux:" + boot + ":"
        if not identity.startswith(prefix) or not identity[len(prefix):].isdigit():
            return None
        process = proc_root / str(pid)
        parts = (process / "stat").read_text(encoding="ascii").rsplit(")", 1)[1].split()
        status = (process / "status").read_text(encoding="ascii")
        rows = [line.split()[1:] for line in status.splitlines() if line.startswith("Uid:")]
        raw = (process / "cmdline").read_bytes()
        if (len(parts) <= 19 or parts[0] in {"Z", "X"} or
                int(parts[19]) != int(identity[len(prefix):]) or
                len(rows) != 1 or len(rows[0]) != 4 or
                any(int(value) != uid for value in rows[0]) or not 0 < len(raw) <= 8192):
            return None
        argv = [part.decode("utf-8") for part in raw.split(b"\0") if part]
        script = job / "stage" / "scripts" / "prepare_desktop_update_fixture.py"
        runner = ("import runpy,sys; "
                  "from pathlib import Path; "
                  "script=Path(sys.argv[1]).resolve(strict=True); "
                  "sys.path.insert(0,str(script.parent)); "
                  "sys.argv=[str(script),*sys.argv[2:]]; "
                  "runpy.run_path(str(script),run_name='__main__')")
        expected = [sys.executable, "-I", "-B", "-c", runner, str(script), "serve",
                    "--directory", str(job / "stage" / "fixture"),
                    "--certificate", str(job / "stage" / "fixture-certificate.pem"),
                    "--private-key", str(job / "stage" / "fixture-private-key.pem"),
                    "--ready-file", str(job / "fixture-server-ready.json"),
                    "--confirm-owned-disposable-guest"]
        return pid if argv == expected else None
    except (OSError, ValueError, UnicodeError, IndexError):
        return None


def _guest_worker_state(job: Path, uid: int, *, proc_root: Path = Path("/proc")) -> str:
    worker = _guest_private_json(job / "worker-process.json", uid)
    if (not isinstance(worker, dict) or worker.get("correlationId") != job.name or
            type(worker.get("pid")) is not int or worker["pid"] <= 1):
        return "unverified"
    process = proc_root / str(worker["pid"])
    if not process.exists():
        return "absent"
    try:
        fields = (process / "stat").read_text(encoding="ascii").rsplit(")", 1)[1].split()
        return "zombie" if fields and fields[0] in {"Z", "X"} else "present"
    except (OSError, ValueError, IndexError):
        return "unverified"


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
              "expectedDesktopJarSha256": typed["expectedDesktopJarSha256"],
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


_STATUS = (r'''import hashlib,json,os,pwd,stat,subprocess,sys
from pathlib import Path
from typing import Any
''' + inspect.getsource(_guest_phase) + inspect.getsource(_guest_log_signal) +
           inspect.getsource(_guest_log_activity) +
           inspect.getsource(_guest_private_json) + inspect.getsource(_guest_worker_failure) +
           inspect.getsource(_guest_server_process) + inspect.getsource(_guest_stop_identity) +
           inspect.getsource(_guest_worker_state) + r'''
root,corr,worker_sha,guard_sha=sys.argv[1:]
def unknown(phase='uninspectable'):
 job=Path(root)/'linux-rpm-fixture-server-jobs'/corr
 signal=_guest_log_signal(job,os.geteuid())
 activity=_guest_log_activity(job,os.geteuid())
 failure=_guest_worker_failure(job,os.geteuid())
 server=_guest_server_process(job,os.geteuid())
 worker_state=_guest_worker_state(job,os.geteuid())
 intent=_guest_private_json(job/'intent.json',os.geteuid())
 stop_admissible=(isinstance(intent,dict) and server=='live' and worker_state in ('absent','zombie') and
  _guest_stop_identity(job,intent.get('sourceSha'),intent.get('publicIntentSha256'),os.geteuid()) is not None)
 print(json.dumps({'state':'unknown','correlationId':corr,'phase':phase,'replayAllowed':False,
  'serverProcess':server,'workerProcess':worker_state,'serverStopAdmissible':stop_admissible,
  'serverActivity':activity,
  **({'serverEvent':signal} if signal is not None else {}),
  **({'workerFailure':failure} if failure is not None else {})},separators=(',',':')));raise SystemExit(0)
if pwd.getpwuid(os.geteuid()).pw_name!='vpnfixture' or not os.path.isabs(root) or '..' in root.split('/'):unknown('guest-identity-unavailable')
job=os.path.join(root,'linux-rpm-fixture-server-jobs',corr)
try:
 info=os.stat(job,follow_symlinks=False)
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:unknown('job-directory-unsafe')
 worker=os.path.join(job,'stage','agent_tools','linux_rpm_fixture_server_guest.py')
 info=os.stat(worker,follow_symlinks=False)
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>1048576:unknown('worker-source-unsafe')
 fd=os.open(worker,os.O_RDONLY|os.O_NOFOLLOW);h=hashlib.sha256();chunks=[]
 try:
  while block:=os.read(fd,65536):h.update(block);chunks.append(block)
  after=os.fstat(fd)
 finally:os.close(fd)
 if h.hexdigest()!=worker_sha or (info.st_dev,info.st_ino,info.st_size)!=(after.st_dev,after.st_ino,after.st_size):unknown('worker-source-mismatch')
 worker_source=b''.join(chunks).decode('utf-8')
 guard=os.path.join(job,'stage','agent_tools','linux_rpm_fixture_server.py')
 info=os.stat(guard,follow_symlinks=False)
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>1048576:unknown('server-guard-unsafe')
 fd=os.open(guard,os.O_RDONLY|os.O_NOFOLLOW);h=hashlib.sha256()
 try:
  while block:=os.read(fd,65536):h.update(block)
  after=os.fstat(fd)
 finally:os.close(fd)
 if h.hexdigest()!=guard_sha or (info.st_dev,info.st_ino,info.st_size)!=(after.st_dev,after.st_ino,after.st_size):unknown('server-guard-mismatch')
 result=subprocess.run([sys.executable,'-I','-B','-c',worker_source,'status',job,guard_sha],capture_output=True,text=True,timeout=30)
 if result.returncode or len(result.stdout)>4096:unknown(_guest_phase(Path(job),corr,os.geteuid()))
 value=json.loads(result.stdout)
 if value.get('correlationId')!=corr or value.get('state') not in ('ready','unknown'):unknown('worker-response-invalid')
 if value.get('state')=='unknown':unknown(_guest_phase(Path(job),corr,os.geteuid()))
 server=_guest_server_process(Path(job),os.geteuid())
 worker_state=_guest_worker_state(Path(job),os.geteuid())
 intent=_guest_private_json(Path(job)/'intent.json',os.geteuid())
 stop_admissible=(isinstance(intent,dict) and server=='live' and worker_state in ('absent','zombie') and
  _guest_stop_identity(Path(job),intent.get('sourceSha'),intent.get('publicIntentSha256'),os.geteuid()) is not None)
 value.update({'serverProcess':server,'workerProcess':worker_state,'serverStopAdmissible':stop_admissible})
 print(json.dumps(value,separators=(',',':')))
except Exception as error:unknown('guest-observer-exception-'+type(error).__name__)
''')


_STOP = (r'''import json,os,pwd,select,signal,stat,sys
from pathlib import Path
from typing import Any
''' + inspect.getsource(_guest_private_json) + inspect.getsource(_guest_stop_identity) + r'''
root,corr,source,public_digest=sys.argv[1:]
def unknown(reason):
 print(json.dumps({'state':'unknown','correlationId':corr,'reason':reason,'replayAllowed':False},separators=(',',':')));raise SystemExit(0)
if pwd.getpwuid(os.geteuid()).pw_name!='vpnfixture' or not os.path.isabs(root) or '..' in root.split('/'):unknown('guest-identity-unavailable')
job=Path(root)/'linux-rpm-fixture-server-jobs'/corr
try:
 info=job.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:unknown('job-unsafe')
 if (job/'server-stop-intent.json').exists():unknown('existing-stop-intent')
 worker=_guest_private_json(job/'worker-process.json',os.geteuid())
 if not isinstance(worker,dict) or worker.get('correlationId')!=corr or type(worker.get('pid')) is not int:unknown('worker-identity-unknown')
 worker_proc=Path('/proc')/str(worker['pid'])
 if worker_proc.exists():
  fields=(worker_proc/'stat').read_text(encoding='ascii').rsplit(')',1)[1].split()
  if not fields or fields[0] not in ('Z','X'):unknown('worker-may-be-active')
 pid=_guest_stop_identity(job,source,public_digest,os.geteuid())
 if pid is None:unknown('server-identity-unavailable')
 if not hasattr(os,'pidfd_open') or not hasattr(signal,'pidfd_send_signal'):unknown('pidfd-unavailable')
 pidfd=os.pidfd_open(pid,0)
 try:
  if _guest_stop_identity(job,source,public_digest,os.geteuid())!=pid:unknown('server-generation-changed')
  receipt={'schemaVersion':1,'correlationId':corr,'sourceSha':source,
   'publicIntentSha256':public_digest,'serverPid':pid}
  path=job/'server-stop-intent.json'
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb') as out:
   out.write((json.dumps(receipt,sort_keys=True,separators=(',',':'))+'\n').encode());out.flush();os.fsync(out.fileno())
  fd=os.open(job,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
  signal.pidfd_send_signal(pidfd,signal.SIGTERM)
  poller=select.poll();poller.register(pidfd,select.POLLIN)
  exited=bool(poller.poll(5000))
  if exited:
   print(json.dumps({'state':'terminal','result':'stopped','correlationId':corr,
    'pidfdExitObserved':True,'replayAllowed':False},separators=(',',':')))
  else:unknown('stop-not-observed')
 finally:os.close(pidfd)
except Exception as error:unknown('stop-exception-'+type(error).__name__)
''')


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
    if isinstance(result, Mapping) and result.get("state") == "unknown" and result.get("correlationId") == correlation:
        phase = result.get("phase")
        allowed = {"uninspectable", "receipt-present-unverified", "probe-present-no-receipt",
                   "server-ready-no-probe", "worker-submitted-no-ready", "worker-marker-missing",
                   "guest-identity-unavailable", "job-directory-unsafe", "worker-source-unsafe",
                   "worker-source-mismatch", "server-guard-unsafe", "server-guard-mismatch",
                   "worker-response-invalid", "guest-observer-exception-FileNotFoundError",
                   "guest-observer-exception-PermissionError", "guest-observer-exception-OSError",
                   "guest-observer-exception-ValueError", "guest-observer-exception-KeyError",
                   "guest-observer-exception-TimeoutExpired"}
        public = {"state": "unknown", "correlationId": correlation,
                  "phase": phase if phase in allowed else "uninspectable", "replayAllowed": False}
        if result.get("serverProcess") in {"live", "absent", "different-generation", "unverified"}:
            public["serverProcess"] = result["serverProcess"]
        if result.get("workerProcess") in {"absent", "zombie", "present", "unverified"}:
            public["workerProcess"] = result["workerProcess"]
        if type(result.get("serverStopAdmissible")) is bool:
            public["serverStopAdmissible"] = result["serverStopAdmissible"]
        activity_allowed = {"empty", "manifest-served", "unrecognized", "uninspectable",
                            "unsafe-empty", "unsafe-manifest-served", "unsafe-unrecognized"}
        activity_allowed.update(prefix + stage + "-" + error
                                for prefix in ("", "unsafe-")
                                for stage in ("connect-admission", "tls-handshake", "tunneled-get")
                                for error in ("SSLError", "TimeoutError", "ConnectionResetError",
                                              "BrokenPipeError", "ValueError", "EOFError", "OSError"))
        if result.get("serverActivity") in activity_allowed:
            public["serverActivity"] = result["serverActivity"]
        event = result.get("serverEvent")
        if (isinstance(event, Mapping) and set(event) == {"stage", "exceptionType"} and
                event["stage"] in {"connect-admission", "tls-handshake", "tunneled-get"} and
                event["exceptionType"] in {"SSLError", "TimeoutError", "ConnectionResetError",
                                           "BrokenPipeError", "ValueError", "EOFError", "OSError"}):
            public["serverEvent"] = dict(event)
        failure = result.get("workerFailure")
        if (isinstance(failure, Mapping) and
                set(failure) in ({"phase", "exceptionType"},
                                 {"phase", "exceptionType", "failureKind"}) and
                failure["phase"] == "java-probe" and
                failure["exceptionType"] in {"ValueError", "TimeoutExpired", "OSError"} and
                ("failureKind" not in failure or failure["failureKind"] in
                 {"tls-handshake", "manifest-digest", "certificate-digest", "connection",
                  "java-compile", "java-failed"})):
            public["workerFailure"] = dict(failure)
        return public
    if (result is None or result.get("state") != "ready" or
            result.get("correlationId") != correlation or
            result.get("sourceSha") != record["sourceSha"] or
            result.get("publicIntentSha256") != record["publicIntentSha256"]):
        return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    return result


def collect(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    return status(root, inputs)


def _stop_journal_path(root: Path, correlation: str, *, create: bool) -> Path | None:
    directory = root / _STOP_STATE
    if create:
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    if not directory.exists():
        return None
    info = directory.lstat()
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
             stat.S_IMODE(info.st_mode) == 0o700, "Fixture server stop journal directory is unsafe.")
    return directory / (correlation + ".json")


def stop(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Send one scoped SIGTERM via pidfd; uncertainty never authorizes another."""
    _require(isinstance(inputs, Mapping) and set(inputs) == {"correlationId"},
             "Server stop requires only correlationId.")
    correlation = inputs["correlationId"]
    _require(isinstance(correlation, str) and bool(re.fullmatch(r"[0-9a-f-]{36}", correlation)),
             "Server stop correlation is invalid.")
    root = Path(root).resolve(strict=True)
    record = _journal(root, correlation)
    _require(record is not None and record.get("correlationId") == correlation and
             isinstance(record.get("sourceSha"), str) and _SHA.fullmatch(record["sourceSha"]) and
             isinstance(record.get("publicIntentSha256"), str) and
             re.fullmatch(r"[0-9a-f]{64}", record["publicIntentSha256"]),
             "Exact server intent is unavailable for scoped stop.")
    path = _stop_journal_path(root, correlation, create=True)
    assert path is not None
    if path.exists() or path.is_symlink():
        return {"state": "unknown", "correlationId": correlation,
                "reason": "existing-stop-intent", "replayAllowed": False}
    config = ssh_transport.load_config(root)
    host = config.hosts.get(_HOST)
    _require(host is not None and host.user == "vpnfixture" and host.fixture_transfer_root is not None,
             "Fedora fixture guest is unavailable for scoped stop.")
    observed = status(root, {"correlationId": correlation})
    _require(observed.get("state") in {"unknown", "ready"} and
             observed.get("serverProcess") == "live" and
             observed.get("workerProcess") in {"absent", "zombie"} and
             observed.get("serverStopAdmissible") is True,
             "Exact live fixture server role is not admitted for stop.")
    if observed["state"] == "ready":
        from . import linux_rpm_base_prepare as base
        public = rpm.RpmPublicInstallSshDriver(root).status(correlation)
        _require(public.get("state") == "terminal" and
                 public.get("correlationId") == correlation and
                 type(public.get("exitCode")) is int and public["exitCode"] != 0,
                 "READY server requires exact terminal failed public job before stop.")
        if correlation == _RECOVERED_PUBLIC:
            from . import linux_rpm_workspace_recovery as recovery
            _require(record.get("sourceSha") == _RECOVERED_SOURCE and
                     record.get("expectedTargetNevra") == _RECOVERED_TARGET,
                     "Recovered READY server source or target changed.")
            cleanup = recovery.cleanup_status(root, {"cleanupCorrelationId": _RECOVERED_CLEANUP})
            _require(cleanup.get("state") == "terminal" and cleanup.get("result") == "passed" and
                     cleanup.get("correlationId") == _RECOVERED_CLEANUP and
                     cleanup.get("workspaceRemoved") is True,
                     "Recovered READY server requires exact completed workspace cleanup.")
            idle = base.preflight(root, {"host": _HOST, "environment": _ENVIRONMENT,
                                         "expectedCurrentNevra": _RECOVERED_TARGET,
                                         "includeCurrentHeader": True})
            _require(idle.get("state") == "ready" and idle.get("currentNevra") == _RECOVERED_TARGET and
                     idle.get("currentHeaderSha1") == _RECOVERED_HEADER,
                     "Recovered READY server requires fresh idle exact target RPM.")
        else:
            idle = base.preflight(root, {"host": _HOST, "environment": _ENVIRONMENT,
                                         "expectedCurrentNevra": record["expectedBaseNevra"]})
            _require(idle.get("state") == "ready" and
                     idle.get("currentNevra") == record["expectedBaseNevra"],
                     "READY server requires fresh idle unchanged Fedora base before stop.")
    local = {"schemaVersion": 1, "correlationId": correlation,
             "sourceSha": record["sourceSha"], "publicIntentSha256": record["publicIntentSha256"]}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(_canonical(local))
        stream.flush()
        os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    result = _remote({"config": config}, _STOP,
                     (str(host.fixture_transfer_root), correlation,
                      record["sourceSha"], record["publicIntentSha256"]))
    if (isinstance(result, Mapping) and result.get("correlationId") == correlation and
            result.get("state") == "terminal" and result.get("result") == "stopped" and
            result.get("pidfdExitObserved") is True and result.get("replayAllowed") is False):
        return {"state": "terminal", "result": "stopped", "correlationId": correlation,
                "pidfdExitObserved": True, "replayAllowed": False}
    return {"state": "unknown", "correlationId": correlation,
            "reason": "stop-result-uncertain", "replayAllowed": False}


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

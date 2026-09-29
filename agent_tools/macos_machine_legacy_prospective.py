"""Prospective, read-only preservation journal for the CP174 unknown Mac job.

This can prove equality across a *new* campaign.  It cannot reconstruct CP174's
missing launch boot token or turn that historical outcome into a terminal one.
"""
from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import time
from typing import Any, Callable, Mapping, Protocol
from uuid import UUID

from .macos_machine_acceptance import VM_NAME
from .macos_machine_tart_readonly import TartReadOnlyProvider


OLD_SOURCE = "5cebf153039c7540952b5b0278c04054bc15d65c"
OLD_OPERATION = "d98286a2-1094-4459-8e8d-bc6a2d91a851"
OLD_JOB = "465a954f-cd70-45c4-896d-67e4508bae49"
OLD_REQUEST = "af7f2c4e-c33e-4dd3-8f9c-47d5c0f4a138"
OLD_PACKAGE_SHA = "a0b2c2e1709f6d9cb1717e5ce5dec84e4a0195fe7cbdc4904d0487e758ccd6d4"
OLD_WORKER_SHA = "58237432121c1e9f9fbf2b60c7bba5d1e4263405cce706eb65b56d00ffc5096d"
OLD_APP = "/Applications/vpn-control-machine-update173.app"
OLD_STATE = "/Users/admin/macos-machine-update173/state"
_GROUP = ".rag_index/macos-machine-legacy-prospective"
_SOURCE = re.compile(r"[0-9a-f]{40}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


class LegacyProspectiveError(ValueError):
    pass


def _uuid(value: Any) -> str:
    try:
        if type(value) is not str or str(UUID(value)) != value:
            raise ValueError()
    except ValueError as error:
        raise LegacyProspectiveError("Noncanonical correlation UUID.") from error
    return value


@dataclass(frozen=True)
class ProspectiveContext:
    source_sha: str
    source_fingerprint: str
    fixture_receipt_artifact_id: str
    base_dmg_artifact_id: str
    target_dmg_artifact_id: str
    correlation_id: str
    boot_session_uuid: str
    reservation_id: str

    def validate(self) -> None:
        if type(self.source_sha) is not str or not _SOURCE.fullmatch(self.source_sha):
            raise LegacyProspectiveError("Current source SHA is invalid.")
        if type(self.source_fingerprint) is not str or not _SHA.fullmatch(self.source_fingerprint):
            raise LegacyProspectiveError("Current source fingerprint is invalid.")
        for value in (self.fixture_receipt_artifact_id, self.base_dmg_artifact_id,
                      self.target_dmg_artifact_id):
            if type(value) is not str or not value.startswith("sha256-") or not _SHA.fullmatch(value[7:]):
                raise LegacyProspectiveError("Current artifact identity is invalid.")
        _uuid(self.correlation_id)
        if type(self.boot_session_uuid) is not str:
            raise LegacyProspectiveError("Current boot identity is invalid.")
        _uuid(self.boot_session_uuid.lower())
        if type(self.reservation_id) is not str or not re.fullmatch(r"env-[a-zA-Z0-9-]+", self.reservation_id):
            raise LegacyProspectiveError("Current reservation identity is invalid.")

    def record(self) -> dict[str, str]:
        self.validate()
        return dict(sourceSha=self.source_sha, sourceFingerprint=self.source_fingerprint,
                    fixtureReceiptArtifactId=self.fixture_receipt_artifact_id,
                    baseDmgArtifactId=self.base_dmg_artifact_id,
                    targetDmgArtifactId=self.target_dmg_artifact_id,
                    correlationId=self.correlation_id, bootSessionUuid=self.boot_session_uuid,
                    reservationId=self.reservation_id)


class LegacyObservationBoundary(Protocol):
    def generation(self) -> tuple[str, str]: ...
    def read_input(self, name: str) -> Mapping[str, Any]: ...
    def read_protected(self) -> Mapping[str, Any]: ...
    def read_public(self) -> Mapping[str, Any]: ...


def _input(value: Mapping[str, Any], expected_hash: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"device", "inode", "mode", "size", "sha256"}:
        raise LegacyProspectiveError("Old input metadata is incomplete.")
    for key in ("device", "inode", "size"):
        if type(value[key]) is not int or value[key] <= 0:
            raise LegacyProspectiveError("Old input identity is invalid.")
    if type(value["mode"]) is not int or value["mode"] not in (0o400, 0o500, 0o600, 0o700):
        raise LegacyProspectiveError("Old input mode is unsafe.")
    if value["sha256"] != expected_hash:
        raise LegacyProspectiveError("Old input bytes differ from frozen CP174 artifacts.")
    return dict(value)


def _public(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or value.get("ok") is not True or value.get("code") != "OK" or \
            value.get("final") is not True or not isinstance(value.get("data"), Mapping):
        raise LegacyProspectiveError("Old public status is unavailable.")
    entries = value["data"].get("installations")
    if not isinstance(entries, list) or len(entries) > 32:
        raise LegacyProspectiveError("Old public installation list is malformed.")
    matching = [entry for entry in entries if isinstance(entry, Mapping) and entry.get("jobId") == OLD_JOB]
    if len(matching) != 1:
        raise LegacyProspectiveError("Old public job is absent or ambiguous.")
    entry = matching[0]
    expected = {"jobId": OLD_JOB, "originRequestId": OLD_REQUEST,
                "operationId": OLD_OPERATION, "phase": "unknown",
                "code": "OUTCOME_UNKNOWN", "final": False, "cleanupCode": None,
                "installed": None}
    if not set(expected).issubset(entry) or "originControllerId" not in entry or \
            any(type(entry.get(k)) is not type(v) or entry.get(k) != v for k, v in expected.items()) or \
            type(entry.get("originControllerId")) is not str:
        raise LegacyProspectiveError("Old public outcome is no longer UNKNOWN.")
    _uuid(entry["originControllerId"])
    return {**expected, "originControllerId": entry["originControllerId"]}


def _observe(boundary: LegacyObservationBoundary, context: ProspectiveContext) -> dict[str, Any]:
    context.validate()
    before = boundary.generation()
    if before != (context.boot_session_uuid, context.reservation_id):
        raise LegacyProspectiveError("Old-job observation has a different boot or reservation.")
    package = _input(boundary.read_input("package.dmg"), OLD_PACKAGE_SHA)
    worker = _input(boundary.read_input("vpn-control-install-worker"), OLD_WORKER_SHA)
    protected = boundary.read_protected()
    if not isinstance(protected, Mapping) or set(protected) != {"jobId", "receiptAbsent"} or \
            protected.get("jobId") != OLD_JOB or protected.get("receiptAbsent") is not True:
        raise LegacyProspectiveError("Old protected status is present or unreadable.")
    public = _public(boundary.read_public())
    after = boundary.generation()
    if after != before:
        raise LegacyProspectiveError("Boot or reservation changed during old-job observation.")
    return {"oldSourceSha": OLD_SOURCE, "oldOperationId": OLD_OPERATION,
            "oldJobId": OLD_JOB, "oldPackage": package, "oldWorker": worker,
            "protectedReceiptAbsent": True, "publicUnknown": public}


def _private_group(root: Path) -> Path:
    root = root.resolve(strict=True)
    parent = root / ".rag_index"
    parent.mkdir(mode=0o700, exist_ok=True)
    group = parent / "macos-machine-legacy-prospective"
    group.mkdir(mode=0o700, exist_ok=True)
    for path in (parent, group):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise LegacyProspectiveError("Prospective journal directory is unsafe.")
    return group


def _read(path: Path) -> Mapping[str, Any]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or \
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or \
                not 0 < info.st_size <= 8192:
            raise LegacyProspectiveError("Prospective journal file is unsafe.")
        raw = os.read(fd, 8193)
        after = os.fstat(fd)
        now = path.lstat()
        keys = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_uid", "st_mode", "st_nlink")
        if len(raw) != info.st_size or tuple(getattr(info, k) for k in keys) != \
                tuple(getattr(after, k) for k in keys) or tuple(getattr(info, k) for k in keys) != \
                tuple(getattr(now, k) for k in keys):
            raise LegacyProspectiveError("Prospective journal changed during read.")
        value = json.loads(raw)
    finally:
        os.close(fd)
    if not isinstance(value, dict):
        raise LegacyProspectiveError("Prospective journal is malformed.")
    return value


class MacLegacyProspectiveJournal:
    """Create one immutable baseline, then compare a fresh post-campaign read."""

    def __init__(self, root: Path, boundary: LegacyObservationBoundary,
                 *, clock_ms: Callable[[], int] | None = None):
        self.group = _private_group(Path(root))
        self.boundary = boundary
        self.clock_ms = clock_ms or (lambda: time.time_ns() // 1_000_000)

    def _path(self, context: ProspectiveContext) -> Path:
        context.validate()
        return self.group / (context.correlation_id + ".json")

    def baseline(self, context: ProspectiveContext) -> Mapping[str, Any]:
        path = self._path(context)
        lock_fd = os.open(self.group / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            lock_info = os.fstat(lock_fd)
            if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != os.getuid() or \
                    stat.S_IMODE(lock_info.st_mode) != 0o600 or lock_info.st_nlink != 1:
                raise LegacyProspectiveError("Prospective journal lock is unsafe.")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            if path.exists() or path.is_symlink():
                raise LegacyProspectiveError("Prospective baseline already exists; no overwrite.")
            started = self.clock_ms()
            if type(started) is not int or started <= 0:
                raise LegacyProspectiveError("Prospective clock is invalid.")
            observation = _observe(self.boundary, context)
            second_observation = _observe(self.boundary, context)
            if second_observation != observation:
                raise LegacyProspectiveError("Independent pre-effect old-job samples differ.")
            finished = self.clock_ms()
            if type(finished) is not int or not 0 <= finished - started <= 60000:
                raise LegacyProspectiveError("Prospective baseline is stale.")
            record = {"schemaVersion": 1, "context": context.record(),
                      "observation": observation, "preEffectSampleCount": 2,
                      "observedAtUnixMs": finished}
            raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
            if len(raw) > 8192:
                raise LegacyProspectiveError("Prospective baseline is oversized.")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                if os.write(fd, raw) != len(raw):
                    raise LegacyProspectiveError("Prospective baseline write was incomplete.")
                os.fsync(fd)
            finally:
                os.close(fd)
            directory = os.open(self.group, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            return {"baselineRecorded": True, "legacyProspectivePreserved": True,
                    "legacyProspectiveBaselineId": "sha256-" + hashlib.sha256(raw).hexdigest(),
                    "correlationId": context.correlation_id, "observedAtUnixMs": finished}
        finally:
            os.close(lock_fd)

    def verify(self, context: ProspectiveContext) -> Mapping[str, Any]:
        path = self._path(context)
        record = _read(path)
        if set(record) != {"schemaVersion", "context", "observation", "preEffectSampleCount", "observedAtUnixMs"} or \
                type(record["schemaVersion"]) is not int or record["schemaVersion"] != 1 or \
                type(record["preEffectSampleCount"]) is not int or record["preEffectSampleCount"] != 2 or \
                record["context"] != context.record() or type(record["observedAtUnixMs"]) is not int:
            raise LegacyProspectiveError("Prospective baseline binding changed.")
        started = self.clock_ms()
        if type(started) is not int or started < record["observedAtUnixMs"]:
            raise LegacyProspectiveError("Prospective verification clock is invalid.")
        fresh = _observe(self.boundary, context)
        finished = self.clock_ms()
        if type(finished) is not int or not 0 <= finished - started <= 60000 or \
                fresh != record["observation"]:
            raise LegacyProspectiveError("Old unknown job changed or fresh proof is stale.")
        baseline_id = "sha256-" + hashlib.sha256(json.dumps(record, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        return {"legacyProspectivePreservedAfter": True,
                "legacyProspectiveBaselineId": baseline_id, "scope": "prospective-only",
                "historicalOutcome": "unknown", "replayAllowed": False,
                "correlationId": context.correlation_id, "baselineObservedAtUnixMs": record["observedAtUnixMs"],
                "verifiedAtUnixMs": finished}

    def verify_bound(self, source_sha: str, correlation_id: str,
                     fixture_receipt_artifact_id: str, boot_session_uuid: str,
                     reservation_id: str) -> Mapping[str, Any]:
        """Terminal readback when only the five carried campaign fields exist.

        The other artifact fields come from the private pre-effect journal.  The
        caller must compare the returned baseline ID to the admission's ID.
        """
        _uuid(correlation_id)
        record = _read(self.group / (correlation_id + ".json"))
        stored = record.get("context")
        if not isinstance(stored, dict):
            raise LegacyProspectiveError("Prospective context is unavailable.")
        expected = {"sourceSha": source_sha, "correlationId": correlation_id,
                    "fixtureReceiptArtifactId": fixture_receipt_artifact_id,
                    "bootSessionUuid": boot_session_uuid,
                    "reservationId": reservation_id}
        if any(stored.get(key) != value for key, value in expected.items()):
            raise LegacyProspectiveError("Prospective terminal identity changed.")
        try:
            context = ProspectiveContext(stored["sourceSha"], stored["sourceFingerprint"],
                                         stored["fixtureReceiptArtifactId"],
                                         stored["baseDmgArtifactId"],
                                         stored["targetDmgArtifactId"],
                                         stored["correlationId"], stored["bootSessionUuid"],
                                         stored["reservationId"])
        except (KeyError, TypeError) as error:
            raise LegacyProspectiveError("Prospective context is incomplete.") from error
        if stored != context.record():
            raise LegacyProspectiveError("Prospective context has unsupported fields.")
        return self.verify(context)


_INPUT_READ = r'''import hashlib,json,os,pathlib,stat,sys
name=sys.argv[1]
if name not in ('package.dmg','vpn-control-install-worker'):raise ValueError('name')
path=pathlib.Path('/Users/admin/Library/Application Support/vpn-control-install-inputs/465a954f-cd70-45c4-896d-67e4508bae49')/name
parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
try:
 for part in path.parts[1:-1]:
  child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
  info=os.fstat(child)
  if not stat.S_ISDIR(info.st_mode) or info.st_mode&0o022:raise ValueError('ancestor')
  os.close(parent);parent=child
 fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
 try:
  before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode) or before.st_uid!=501 or before.st_nlink!=1 or not 0<before.st_size<=512*1024*1024 or stat.S_IMODE(before.st_mode) not in (0o400,0o500,0o600,0o700):raise ValueError('input')
  digest=hashlib.sha256()
  while True:
   block=os.read(fd,1024*1024)
   if not block:break
   digest.update(block)
  after=os.fstat(fd);now=os.stat(name,dir_fd=parent,follow_symlinks=False)
  keys=('st_dev','st_ino','st_size','st_mtime_ns','st_uid','st_mode','st_nlink')
  if tuple(getattr(before,k) for k in keys)!=tuple(getattr(after,k) for k in keys) or tuple(getattr(before,k) for k in keys)!=tuple(getattr(now,k) for k in keys):raise ValueError('changed')
  print(json.dumps({'device':before.st_dev,'inode':before.st_ino,'mode':stat.S_IMODE(before.st_mode),'size':before.st_size,'sha256':digest.hexdigest()},sort_keys=True,separators=(',',':')))
 finally:os.close(fd)
finally:os.close(parent)
'''

_PROTECTED_READ = r'''import json,os,pathlib,stat
path=pathlib.Path('/Library/Application Support/vpn-control-install-jobs/465a954f-cd70-45c4-896d-67e4508bae49/status.json')
parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
try:
 for part in path.parts[1:-1]:
  try:child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
  except FileNotFoundError:
   print(json.dumps({'jobId':'465a954f-cd70-45c4-896d-67e4508bae49','receiptAbsent':True}));raise SystemExit(0)
  info=os.fstat(child)
  if not stat.S_ISDIR(info.st_mode) or info.st_mode&0o022:raise ValueError('ancestor')
  os.close(parent);parent=child
 try:
  os.stat(path.name,dir_fd=parent,follow_symlinks=False)
 except FileNotFoundError:
  print(json.dumps({'jobId':'465a954f-cd70-45c4-896d-67e4508bae49','receiptAbsent':True}));raise SystemExit(0)
 raise ValueError('protected receipt present')
finally:os.close(parent)
'''


class TartLegacyObservationBoundary:
    """Four separate, fixed read-only guest calls; generation comes from owner."""

    def __init__(self, generation: Callable[[], tuple[str, str]], *, runner=subprocess.run):
        self._generation = generation
        self.runner = runner

    def generation(self) -> tuple[str, str]:
        value = self._generation()
        if not isinstance(value, tuple) or len(value) != 2:
            raise LegacyProspectiveError("Guest generation is unavailable.")
        return value

    def _exec(self, argv: list[str], *, timeout: int = 90) -> Mapping[str, Any]:
        TartReadOnlyProvider(runner=self.runner)._require_running()
        try:
            result = self.runner(["tart", "exec", VM_NAME, *argv], capture_output=True,
                                 text=True, timeout=timeout, check=False)
            if result.returncode != 0 or len(result.stdout) > 65536:
                raise ValueError()
            value = json.loads(result.stdout)
            if not isinstance(value, dict):
                raise ValueError()
            return value
        except (OSError, subprocess.TimeoutExpired, TypeError, ValueError) as error:
            raise LegacyProspectiveError("Fixed legacy guest read failed.") from error

    def read_input(self, name: str) -> Mapping[str, Any]:
        if name not in ("package.dmg", "vpn-control-install-worker"):
            raise LegacyProspectiveError("Unsupported old input name.")
        return self._exec(["/usr/bin/sudo", "-n", "/usr/bin/python3", "-c", _INPUT_READ, name])

    def read_protected(self) -> Mapping[str, Any]:
        return self._exec(["/usr/bin/sudo", "-n", "/usr/bin/python3", "-c", _PROTECTED_READ])

    def read_public(self) -> Mapping[str, Any]:
        return self._exec([OLD_APP + "/Contents/MacOS/vpn-control", "--state-dir", OLD_STATE,
                           "--json", "updates", "status"], timeout=30)

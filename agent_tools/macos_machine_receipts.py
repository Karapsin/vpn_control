"""Strict, read-only schemas for future Mac machine fixture evidence.

These validators do not turn a guest-owned JSON file into native evidence. A
reviewed producer, no-follow guest readback, and fresh kernel observations must
be wired before the terminal observer can set either acceptance flag to true.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
import subprocess
from typing import Any, Mapping
from uuid import UUID


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_SOURCE = re.compile(r"[0-9a-f]{40}\Z")
_START = re.compile(r"darwin:[1-9][0-9]*:[0-9]{1,6}\Z")
_GUEST_READ = r'''import json,os,pathlib,stat,sys,uuid
source,correlation,name=sys.argv[1:]
if len(source)!=40 or any(c not in '0123456789abcdef' for c in source):raise ValueError('source')
if str(uuid.UUID(correlation))!=correlation:raise ValueError('correlation')
if name not in ('server-stop','rollback-trace'):raise ValueError('kind')
root=pathlib.Path('/Users/admin/macos-parity'+source[:7])
path=root/'state'/'acceptance-evidence'/correlation/(name+'.json')
parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
try:
 for index,part in enumerate(path.parts[1:-1]):
  child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
  info=os.fstat(child)
  if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0,501) or info.st_mode & 0o022 or (index>=3 and (info.st_uid!=501 or stat.S_IMODE(info.st_mode)!=0o700)):
   os.close(child);raise ValueError('ancestor')
  os.close(parent);parent=child
 fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
 try:
  before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode) or before.st_uid!=501 or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1 or not 0<before.st_size<=16384:raise ValueError('receipt')
  raw=os.read(fd,16385)
  after=os.fstat(fd);now=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
  if len(raw)!=before.st_size or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_uid,before.st_mode,before.st_nlink)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_uid,after.st_mode,after.st_nlink) or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_uid,before.st_mode,before.st_nlink)!=(now.st_dev,now.st_ino,now.st_size,now.st_mtime_ns,now.st_uid,now.st_mode,now.st_nlink):raise ValueError('changed')
 finally:os.close(fd)
finally:os.close(parent)
value=json.loads(raw)
if not isinstance(value,dict):raise ValueError('object')
print(json.dumps(value,sort_keys=True,separators=(',',':')))
'''


class MacReceiptError(ValueError):
    pass


def read_guest_candidate(source_sha: str, correlation_id: str, kind: str,
                         *, runner=subprocess.run) -> Mapping[str, Any]:
    """Read only a fixed private guest leaf; return untrusted candidate JSON."""
    from . import macos_machine_acceptance as gate
    from .macos_machine_tart_readonly import TartReadOnlyProvider
    if not isinstance(source_sha, str) or not _SOURCE.fullmatch(source_sha) or \
            kind not in {"server-stop", "rollback-trace"}:
        raise MacReceiptError("Mac fixture receipt source or kind is invalid.")
    _uuid(correlation_id)
    try:
        TartReadOnlyProvider(runner=runner)._require_running()
        result = runner(["tart", "exec", gate.VM_NAME, "/usr/bin/python3", "-c", _GUEST_READ,
                         source_sha, correlation_id, kind], capture_output=True,
                        text=True, timeout=30, check=False)
        if result.returncode != 0 or len(result.stdout) > 32768:
            raise ValueError()
        value = json.loads(result.stdout)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (OSError, subprocess.TimeoutExpired, TypeError, ValueError) as error:
        raise MacReceiptError("Fixed guest receipt readback is unavailable.") from error


def _uuid(value: Any) -> str:
    if not isinstance(value, str):
        raise MacReceiptError("Mac fixture receipt UUID is invalid.")
    try:
        if str(UUID(value)) != value:
            raise ValueError()
    except ValueError as error:
        raise MacReceiptError("Mac fixture receipt UUID is invalid.") from error
    return value


@dataclass(frozen=True)
class ReceiptBinding:
    source_sha: str
    correlation_id: str
    scenario: str
    job_id: str
    operation_id: str
    boot_session_uuid: str
    reservation_id: str
    fixture_receipt_artifact_id: str

    def validate(self) -> None:
        if not _SOURCE.fullmatch(self.source_sha) or self.scenario not in {"install", "rollback"}:
            raise MacReceiptError("Mac fixture receipt source or scenario is invalid.")
        for value in (self.correlation_id, self.job_id, self.operation_id, self.boot_session_uuid):
            _uuid(value.lower() if value == self.boot_session_uuid else value)
        if not self.reservation_id.startswith("env-") or not self.reservation_id[4:].isalnum():
            raise MacReceiptError("Mac fixture reservation identity is invalid.")
        if not self.fixture_receipt_artifact_id.startswith("sha256-") or \
                not _SHA.fullmatch(self.fixture_receipt_artifact_id[7:]):
            raise MacReceiptError("Mac fixture artifact identity is invalid.")


def _common(value: Mapping[str, Any], binding: ReceiptBinding, kind: str) -> None:
    binding.validate()
    expected = {"schemaVersion": 1, "kind": kind, "sourceSha": binding.source_sha,
                "correlationId": binding.correlation_id, "scenario": binding.scenario,
                "jobId": binding.job_id, "operationId": binding.operation_id,
                "bootSessionUuid": binding.boot_session_uuid,
                "reservationId": binding.reservation_id,
                "fixtureReceiptArtifactId": binding.fixture_receipt_artifact_id}
    if not isinstance(value, Mapping) or type(value.get("schemaVersion")) is not int or \
            any(value.get(key) != item for key, item in expected.items()):
        raise MacReceiptError("Mac fixture receipt campaign binding changed.")


def validate_server_stop(value: Mapping[str, Any], binding: ReceiptBinding,
                         *, expected_instance_id: str, expected_pid: int,
                         expected_start: str, expected_ready_sha256: str,
                         fresh_pid_generation_absent: bool,
                         fresh_listener_absent: bool) -> None:
    """Admit a stop receipt only with an independent fresh process/socket probe."""
    _common(value, binding, "server-stop")
    fields = {"schemaVersion", "kind", "sourceSha", "correlationId", "scenario", "jobId",
              "operationId", "bootSessionUuid", "reservationId", "fixtureReceiptArtifactId",
              "serverInstanceId", "serverPid", "serverProcessStartIdentity", "readySha256",
              "stopRequestCount", "serverExitCode", "stopReceiptFinal"}
    if set(value) != fields or value.get("serverInstanceId") != _uuid(expected_instance_id) or \
            type(expected_pid) is not int or expected_pid <= 0 or \
            type(value.get("serverPid")) is not int or value["serverPid"] != expected_pid or \
            not _START.fullmatch(expected_start) or value.get("serverProcessStartIdentity") != expected_start or \
            not _SHA.fullmatch(expected_ready_sha256) or value.get("readySha256") != expected_ready_sha256 or \
            type(value.get("stopRequestCount")) is not int or value["stopRequestCount"] != 1 or \
            type(value.get("serverExitCode")) is not int or value["serverExitCode"] != 0 or \
            value.get("stopReceiptFinal") is not True or fresh_pid_generation_absent is not True or \
            fresh_listener_absent is not True:
        raise MacReceiptError("Mac fixture server stop is unproven.")


def validate_rollback_trace(value: Mapping[str, Any], binding: ReceiptBinding,
                            *, base_device: int, base_inode: int, base_jar_sha256: str,
                            candidate_device: int, candidate_inode: int,
                            candidate_jar_sha256: str,
                            protected_code: str, public_code: str,
                            fresh_stage_absent: bool, fresh_backup_absent: bool) -> None:
    """Check ordered move/fault/restore claims against independent terminal state."""
    _common(value, binding, "rollback-trace")
    fields = {"schemaVersion", "kind", "sourceSha", "correlationId", "scenario", "jobId",
              "operationId", "bootSessionUuid", "reservationId", "fixtureReceiptArtifactId",
              "events", "finalBaseDevice", "finalBaseInode", "finalBaseJarSha256"}
    events = value.get("events")
    wanted = ("base-observed", "candidate-armed", "base-moved-to-backup",
              "candidate-move-failed", "base-restored", "candidate-cleaned")
    if binding.scenario != "rollback" or set(value) != fields or \
            not isinstance(events, list) or len(events) != len(wanted) or \
            protected_code != "PERSISTENCE_FAILED" or public_code != "PERSISTENCE_FAILED" or \
            type(base_device) is not int or base_device <= 0 or \
            type(base_inode) is not int or base_inode <= 0 or \
            not _SHA.fullmatch(base_jar_sha256) or \
            type(candidate_device) is not int or candidate_device <= 0 or \
            type(candidate_inode) is not int or candidate_inode <= 0 or \
            not _SHA.fullmatch(candidate_jar_sha256) or \
            type(value.get("finalBaseDevice")) is not int or value["finalBaseDevice"] != base_device or \
            type(value.get("finalBaseInode")) is not int or value["finalBaseInode"] != base_inode or \
            value.get("finalBaseJarSha256") != base_jar_sha256 or \
            fresh_stage_absent is not True or fresh_backup_absent is not True:
        raise MacReceiptError("Mac rollback terminal state is unproven.")
    previous = -1
    for index, (event, label) in enumerate(zip(events, wanted)):
        if not isinstance(event, dict) or set(event) != {"sequence", "type", "observedAtUnixMs",
                                                    "device", "inode", "sha256"} or \
                type(event.get("sequence")) is not int or event["sequence"] != index or \
                event.get("type") != label or \
                type(event.get("observedAtUnixMs")) is not int or \
                event["observedAtUnixMs"] <= previous or \
                type(event.get("device")) is not int or event["device"] <= 0 or \
                type(event.get("inode")) is not int or event["inode"] <= 0 or \
                not isinstance(event.get("sha256"), str) or not _SHA.fullmatch(event["sha256"]):
            raise MacReceiptError("Mac rollback trace order or byte identity is invalid.")
        previous = event["observedAtUnixMs"]
    if any(events[index][field] != events[0][field]
           for index in (2, 4) for field in ("device", "inode", "sha256")) or \
            (events[0]["device"], events[0]["inode"], events[0]["sha256"]) != \
            (base_device, base_inode, base_jar_sha256) or \
            any((events[index]["device"], events[index]["inode"], events[index]["sha256"]) !=
                (candidate_device, candidate_inode, candidate_jar_sha256)
                for index in (1, 3, 5)):
        raise MacReceiptError("Mac rollback trace did not preserve exact base and candidate identities.")

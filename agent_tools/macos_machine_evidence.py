"""Fail-closed composition of protected Mac worker and fixture evidence.

Worker events are produced by the root-owned Darwin installer job, and must be
read separately from the owner-writable acceptance receipt. The latter alone
never proves a rollback transition.
"""
from __future__ import annotations

import json
import re
import subprocess
from typing import Any, Mapping

from . import macos_machine_acceptance as gate
from .macos_machine_receipts import MacReceiptError, ReceiptBinding, _uuid, validate_rollback_trace
from .macos_machine_tart_readonly import TartReadOnlyProvider


LEGACY_JOB_ID = "465a954f-cd70-45c4-896d-67e4508bae49"
_LEGACY_READ = r'''import hashlib,json,os,pathlib,stat,sys
job='465a954f-cd70-45c4-896d-67e4508bae49'
root=pathlib.Path('/Users/admin/Library/Application Support/vpn-control-install-inputs')/job
protected=pathlib.Path('/Library/Application Support/vpn-control-install-jobs')/job/'status.json'
def absent(path):
 try:path.lstat();return False
 except FileNotFoundError:return True
def fixed_file(name):
 parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
 try:
  for part in (root/name).parts[1:-1]:
   child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
   info=os.fstat(child)
   if not stat.S_ISDIR(info.st_mode) or info.st_mode&0o022:raise ValueError('ancestor')
   os.close(parent);parent=child
  fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
  try:
   before=os.fstat(fd)
   if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=501 or not 0<before.st_size<=512*1024*1024:raise ValueError('input')
   digest=hashlib.sha256()
   while True:
    block=os.read(fd,1024*1024)
    if not block:break
    digest.update(block)
   after=os.fstat(fd);now=os.stat(name,dir_fd=parent,follow_symlinks=False)
   fields=('st_dev','st_ino','st_size','st_mtime_ns','st_uid','st_mode','st_nlink')
   if tuple(getattr(before,k) for k in fields)!=tuple(getattr(after,k) for k in fields) or tuple(getattr(before,k) for k in fields)!=tuple(getattr(now,k) for k in fields):raise ValueError('changed')
   return {'device':before.st_dev,'inode':before.st_ino,'mode':stat.S_IMODE(before.st_mode),'size':before.st_size,'sha256':digest.hexdigest()}
  finally:os.close(fd)
 finally:os.close(parent)
if not absent(protected):raise ValueError('legacy protected status changed')
package=fixed_file('package.dmg');worker=fixed_file('vpn-control-install-worker')
if not absent(protected):raise ValueError('legacy protected status changed')
print(json.dumps({'jobId':job,'protectedReceiptAbsent':True,'package':package,'worker':worker},sort_keys=True,separators=(',',':')))
'''


def read_legacy_unknown(*, runner=subprocess.run) -> Mapping[str, Any]:
    """Read fixed old inputs and protected absence, without resolving its outcome."""
    try:
        TartReadOnlyProvider(runner=runner)._require_running()
        result = runner(["tart", "exec", gate.VM_NAME, "/usr/bin/sudo", "-n",
                         "/usr/bin/python3", "-c", _LEGACY_READ],
                        capture_output=True, text=True, timeout=90, check=False)
        if result.returncode != 0 or len(result.stdout) > 2048:
            raise ValueError()
        value = json.loads(result.stdout)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (OSError, subprocess.TimeoutExpired, TypeError, ValueError) as error:
        raise MacReceiptError("Historical unknown Mac job readback is unavailable.") from error


def legacy_unknown_preserved(observed: Mapping[str, Any], baseline: Mapping[str, Any] | None) -> bool:
    """A current absence alone never becomes a historical preservation claim."""
    if baseline is None or not isinstance(observed, Mapping) or not isinstance(baseline, Mapping):
        return False
    if set(observed) != {"jobId", "protectedReceiptAbsent", "package", "worker"} or \
            observed.get("jobId") != LEGACY_JOB_ID or observed.get("protectedReceiptAbsent") is not True:
        return False
    for name in ("package", "worker"):
        value, expected = observed.get(name), baseline.get(name)
        if not isinstance(value, Mapping) or not isinstance(expected, Mapping) or \
                set(value) != {"device", "inode", "mode", "size", "sha256"} or set(expected) != set(value) or \
                any(type(value.get(field)) is not int or value[field] <= 0 for field in ("device", "inode", "mode", "size")) or \
                not isinstance(value.get("sha256"), str) or \
                re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is None or \
                value != expected:
            return False
    return baseline.get("jobId") == LEGACY_JOB_ID and baseline.get("reviewed") is True


_WORKER_READ = r'''import json,os,pathlib,stat,sys,uuid
job=sys.argv[1]
if str(uuid.UUID(job))!=job:raise ValueError('job')
path=pathlib.Path('/Library/Application Support/vpn-control-install-jobs')/job/'acceptance-events.jsonl'
parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
try:
 for part in path.parts[1:-1]:
  child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
  info=os.fstat(child)
  if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('ancestor')
  os.close(parent);parent=child
 fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
 try:
  before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1 or not 0<before.st_size<=8192:raise ValueError('events')
  raw=os.read(fd,8193);after=os.fstat(fd);now=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
  fields=('st_dev','st_ino','st_size','st_mtime_ns','st_uid','st_mode','st_nlink')
  if len(raw)!=before.st_size or tuple(getattr(before,k) for k in fields)!=tuple(getattr(after,k) for k in fields) or tuple(getattr(before,k) for k in fields)!=tuple(getattr(now,k) for k in fields):raise ValueError('changed')
 finally:os.close(fd)
finally:os.close(parent)
lines=raw.splitlines()
if len(lines)!=5:raise ValueError('count')
value=[json.loads(line) for line in lines]
print(json.dumps(value,sort_keys=True,separators=(',',':')))
'''


def read_worker_events(job_id: str, *, runner=subprocess.run) -> list[dict[str, Any]]:
    """Read one fixed root-owned worker trace without accepting caller paths."""
    _uuid(job_id)
    try:
        TartReadOnlyProvider(runner=runner)._require_running()
        result = runner(["tart", "exec", gate.VM_NAME, "/usr/bin/sudo", "-n",
                         "/usr/bin/python3", "-c", _WORKER_READ, job_id],
                        capture_output=True, text=True, timeout=30, check=False)
        if result.returncode != 0 or len(result.stdout) > 8192:
            raise ValueError()
        value = json.loads(result.stdout)
        if not isinstance(value, list):
            raise ValueError()
        return value
    except (OSError, subprocess.TimeoutExpired, TypeError, ValueError) as error:
        raise MacReceiptError("Protected Mac worker trace is unavailable.") from error


def verify_worker_events(events: list[Mapping[str, Any]], *, job_id: str,
                         base: tuple[int, int, str], candidate: tuple[int, int, str]) -> None:
    """Require exact kernel identities at every in-worker transition."""
    _uuid(job_id)
    wanted = ("base-observed", "candidate-armed", "base-moved-to-backup",
              "candidate-move-failed", "base-restored")
    if not isinstance(events, list) or len(events) != 5:
        raise MacReceiptError("Mac worker transition count is incomplete.")
    previous = -1
    for index, (event, label) in enumerate(zip(events, wanted)):
        identity = base if index in (0, 2, 4) else candidate
        if not isinstance(event, Mapping) or set(event) != {
                "jobId", "sequence", "type", "observedAtUnixMs", "device", "inode", "sha256"} or \
                event.get("jobId") != job_id or type(event.get("sequence")) is not int or \
                event["sequence"] != index or event.get("type") != label or \
                type(event.get("observedAtUnixMs")) is not int or \
                event["observedAtUnixMs"] <= previous or \
                (event.get("device"), event.get("inode"), event.get("sha256")) != identity:
            raise MacReceiptError("Mac worker transition identity or order changed.")
        previous = event["observedAtUnixMs"]


def compose_rollback_trace(binding: ReceiptBinding, worker_events: list[Mapping[str, Any]],
                           *, base: tuple[int, int, str], candidate: tuple[int, int, str],
                           cleanup_at_unix_ms: int, protected_code: str, public_code: str,
                           fresh_stage_absent: bool, fresh_backup_absent: bool) -> dict[str, Any]:
    """Build a candidate receipt only after worker and terminal cleanup agree."""
    binding.validate()
    verify_worker_events(worker_events, job_id=binding.job_id, base=base, candidate=candidate)
    if binding.scenario != "rollback" or type(cleanup_at_unix_ms) is not int or \
            cleanup_at_unix_ms <= worker_events[-1]["observedAtUnixMs"] or \
            protected_code != "PERSISTENCE_FAILED" or public_code != "PERSISTENCE_FAILED" or \
            fresh_stage_absent is not True or fresh_backup_absent is not True:
        raise MacReceiptError("Mac candidate cleanup is unproven.")
    names = ("schemaVersion", "kind", "sourceSha", "correlationId", "scenario", "jobId",
             "operationId", "bootSessionUuid", "reservationId", "fixtureReceiptArtifactId")
    receipt = dict(zip(names, (1, "rollback-trace", binding.source_sha, binding.correlation_id,
        binding.scenario, binding.job_id, binding.operation_id, binding.boot_session_uuid,
        binding.reservation_id, binding.fixture_receipt_artifact_id)))
    receipt["events"] = [{key: event[key] for key in (
        "sequence", "type", "observedAtUnixMs", "device", "inode", "sha256")}
        for event in worker_events]
    receipt["events"].append({"sequence": 5, "type": "candidate-cleaned",
        "observedAtUnixMs": cleanup_at_unix_ms, "device": candidate[0],
        "inode": candidate[1], "sha256": candidate[2]})
    receipt.update(finalBaseDevice=base[0], finalBaseInode=base[1], finalBaseJarSha256=base[2])
    validate_rollback_trace(receipt, binding, base_device=base[0], base_inode=base[1],
        base_jar_sha256=base[2], candidate_device=candidate[0], candidate_inode=candidate[1],
        candidate_jar_sha256=candidate[2], protected_code=protected_code, public_code=public_code,
        fresh_stage_absent=fresh_stage_absent, fresh_backup_absent=fresh_backup_absent)
    return receipt

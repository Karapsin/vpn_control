"""Read-only Tart owner, public status, and reservation admission observer.

This composes the fixed guest byte reader with reviewed process-role parsing.
Mutation and secure UI remain unavailable. Every Tart command has fixed argv.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess
import time
from typing import Any, Mapping

from scripts.macos_fixture_processes import (FixtureProcessObserver, INITIAL_SERVE_OWNER,
    INTERNAL_HEADLESS_OWNER, PLAIN_RETURN_GUI, process_rows)

from . import macos_machine_acceptance as gate
from . import native_environment
from .macos_machine_boundary import MacMachineBoundaryError, NativeTerminalQuery, VerifiedPair
from .macos_machine_tart_readonly import TartReadOnlyProvider
from .macos_machine_receipts import (ReceiptBinding, read_guest_candidate,
    validate_rollback_trace, MacReceiptError)
from .macos_machine_evidence import read_worker_events, verify_worker_events
from . import macos_machine_server_stop
from .macos_machine_legacy_prospective import (LegacyProspectiveError,
    MacLegacyProspectiveJournal, ProspectiveContext, TartLegacyObservationBoundary)


_PROTECTED_READ = r'''import json,os,pathlib,stat,sys,uuid
job=sys.argv[1]
if str(uuid.UUID(job))!=job:raise ValueError('job')
parent=pathlib.Path('/Library/Application Support/vpn-control-install-jobs')/job
path=parent/'status.json'
current=pathlib.Path('/')
for part in path.parts[1:-1]:
 current=current/part
 info=current.lstat()
 if not stat.S_ISDIR(info.st_mode):raise ValueError('ancestor')
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
try:
 info=os.fstat(fd)
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_size>8192:raise ValueError('receipt')
 raw=os.read(fd,8193)
finally:os.close(fd)
value=json.loads(raw)
if value.get('jobId')!=job:raise ValueError('receipt job')
root=pathlib.Path('/Applications')
stage=root/('.vpn-control-stage-'+job+'.app')
backup=root/('.vpn-control-backup-'+job+'.app')
def absent(path):
 try:path.lstat();return False
 except FileNotFoundError:return True
print(json.dumps({'jobId':job,'phase':value.get('phase'),'code':value.get('code'),
 'stageAbsent':absent(stage),'backupAbsent':absent(backup)},sort_keys=True,separators=(',',':')))
'''


class TartMacObserver(TartReadOnlyProvider):
    """An exact diagnostic that can admit readback, never a native action."""

    def __init__(self, repository_root: Path, *, runner=subprocess.run, clock_ms=None):
        super().__init__(runner=runner)
        self.root = Path(repository_root).resolve(strict=True)
        self.clock_ms = clock_ms or (lambda: time.time_ns() // 1_000_000)

    def _reservation(self) -> str:
        directory, path = native_environment._root_paths(self.root)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != native_environment.os.getuid() or \
                stat.S_IMODE(info.st_mode) != 0o700:
            raise MacMachineBoundaryError("Mac resource reservation directory is unsafe.")
        records = native_environment._load(path)["reservations"]
        candidates = [record for record in records if isinstance(record, dict) and
                      record.get("hostAlias") == "local-macos" and record.get("environment") == gate.VM_NAME and
                      record.get("operator") == "macos-parity-agent" and record.get("allocationState") == "running"]
        if len(candidates) != 1 or len([record for record in records if isinstance(record, dict) and
                record.get("environment") == gate.VM_NAME]) != 1:
            raise MacMachineBoundaryError("Exact running Tart reservation is unavailable.")
        record = candidates[0]
        observation = record.get("lastObservation")
        if not isinstance(observation, dict) or observation.get("state") != "OBSERVED" or \
                type(observation.get("observedAtUnixMs")) is not int or \
                not 0 <= self.clock_ms() - observation["observedAtUnixMs"] <= 60000 or \
                not isinstance(record.get("id"), str) or not record["id"].startswith("env-"):
            raise MacMachineBoundaryError("Tart resource proof is stale or incomplete.")
        memory = record.get("requestedMemoryBytes")
        if type(memory) is not int or memory <= 0:
            raise MacMachineBoundaryError("Tart reservation memory is invalid.")
        self._require_running()
        try:
            completed = self.runner(["tart", "get", gate.VM_NAME, "--format", "json"],
                                    capture_output=True, text=True, timeout=15, check=False)
            if completed.returncode != 0 or len(completed.stdout) > 65536:
                raise ValueError()
            live = json.loads(completed.stdout)
        except (OSError, subprocess.TimeoutExpired, TypeError, ValueError) as error:
            raise MacMachineBoundaryError("Fresh Tart allocation is unavailable.") from error
        if not isinstance(live, dict) or live.get("Running") is not True or \
                live.get("State") != "running" or type(live.get("Memory")) is not int or \
                live["Memory"] * 1024 * 1024 != memory:
            raise MacMachineBoundaryError("Fresh Tart allocation differs from its reservation.")
        try:
            pressure = self.runner(["/usr/sbin/sysctl", "-n", "kern.memorystatus_vm_pressure_level"],
                                   capture_output=True, text=True, timeout=15, check=False)
            pages = self.runner(["/usr/bin/vm_stat"], capture_output=True, text=True,
                                timeout=15, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise MacMachineBoundaryError("Fresh Mac host memory observation is unavailable.") from error
        if pressure.returncode != 0 or pressure.stdout.strip() != "1" or pages.returncode != 0 or \
                len(pages.stdout) > 65536:
            raise MacMachineBoundaryError("Mac host memory pressure is unsafe.")
        page_size = re.search(r"page size of (\d+) bytes", pages.stdout)
        counts = [re.search(r"^" + name + r":\s+(\d+)", pages.stdout, re.MULTILINE)
                  for name in ("Pages free", "Pages inactive", "Pages speculative")]
        if page_size is None or any(value is None for value in counts) or \
                int(page_size.group(1)) * sum(int(value.group(1)) for value in counts) < 8 * 1024**3:
            raise MacMachineBoundaryError("Mac host memory headroom is unsafe.")
        return record["id"]

    def _exec(self, argv: list[str], *, timeout: int = 30) -> str:
        self._require_running()
        try:
            completed = self.runner(["tart", "exec", gate.VM_NAME, *argv], capture_output=True,
                                    text=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise MacMachineBoundaryError("Fixed Tart observation is unavailable.") from error
        if completed.returncode != 0 or len(completed.stdout) > 1024 * 1024:
            raise MacMachineBoundaryError("Fixed Tart observation failed.")
        return completed.stdout

    def _processes(self, launcher: str, state_dir: str):
        raw = self._exec(["/bin/ps", "-axo", "pid=,lstart=,command="])
        rows = process_rows(raw)
        observer = FixtureProcessObserver(launcher, state_dir)
        owner = observer.identify(rows, INITIAL_SERVE_OWNER)
        prompts = sum(1 for row in rows if row.argv and Path(row.argv[0]).name == "SecurityAgent")
        return owner, prompts

    def _public(self, launcher: str, state_dir: str, *args: str) -> Mapping[str, Any]:
        raw = self._exec([launcher, "--state-dir", state_dir, "--json", *args])
        if len(raw) > 65536:
            raise MacMachineBoundaryError("Public Mac status is unbounded.")
        try:
            value = json.loads(raw)
        except (TypeError, ValueError) as error:
            raise MacMachineBoundaryError("Public Mac status is malformed.") from error
        if not isinstance(value, dict) or value.get("ok") is not True or value.get("code") != "OK" or \
                value.get("final") is not True or not isinstance(value.get("data"), dict) or \
                not isinstance(value.get("controllerId"), str):
            raise MacMachineBoundaryError("Public Mac status is not authoritative.")
        return value

    def observe_admission(self, vm_name: str, source_sha: str,
                          pair: VerifiedPair | None = None) -> Mapping[str, Any]:
        if pair is None or pair.source_sha != source_sha:
            raise MacMachineBoundaryError("Verified Mac pair snapshot is unavailable.")
        guest = dict(super().observe_admission(vm_name, source_sha, pair))
        reservation_id = self._reservation()
        boot = self._boot_session()
        fixed = gate._fixed_paths({"sourceSha": source_sha})
        launcher = fixed["app"] + "/Contents/MacOS/vpn-control"
        state_dir = fixed["guestRoot"] + "/state"
        before, prompt_count = self._processes(launcher, state_dir)
        if before is None:
            raise MacMachineBoundaryError("Exact original Tart owner is unavailable.")
        status = self._public(launcher, state_dir, "status")
        updates = self._public(launcher, state_dir, "updates", "status")
        after, second_prompt_count = self._processes(launcher, state_dir)
        if after != before or second_prompt_count != prompt_count or \
                status["controllerId"] != updates["controllerId"] or \
                status["data"].get("runtimeRunning") is not False or \
                status["data"].get("configuredMode") != "proxy-only":
            raise MacMachineBoundaryError("Tart owner or public state changed during readback.")
        if self._reservation() != reservation_id or self._boot_session() != boot:
            raise MacMachineBoundaryError("Tart allocation or boot changed during readback.")
        phase = updates["data"].get("phase")
        if phase != "ready" and not (phase == "installing" and prompt_count == 1):
            raise MacMachineBoundaryError("Public Mac update is not ready or awaiting exact authorization.")
        installations = updates["data"].get("installations")
        if not isinstance(installations, list) or len(installations) > 32:
            raise MacMachineBoundaryError("Public Mac installation history is malformed.")
        active = sum(1 for item in installations if isinstance(item, dict) and item.get("final") is False)
        conflicts = active if prompt_count == 0 else max(0, active - 1)
        start_identity = int.from_bytes(hashlib.sha256(before.started.encode()).digest()[:8], "big") or 1
        # A new baseline can prove only preservation during this campaign. It
        # never upgrades the CP174 unknown or claims a CP174 input fingerprint.
        prospective = {"legacyProspectivePreserved": False}
        if pair.correlation_id:
            context = ProspectiveContext(source_sha, pair.source_fingerprint,
                pair.fixture_receipt_artifact_id, pair.base_dmg_artifact_id,
                pair.target_dmg_artifact_id, pair.correlation_id, boot, reservation_id)
            legacy = MacLegacyProspectiveJournal(self.root,
                TartLegacyObservationBoundary(
                    generation=lambda: (self._boot_session(), self._reservation()),
                    runner=self.runner))
            try:
                observation = legacy.verify(context)
                prospective = {"legacyProspectivePreserved": observation["legacyProspectivePreservedAfter"],
                    "legacyProspectiveBaselineId": observation["legacyProspectiveBaselineId"]}
            except FileNotFoundError:
                if phase == "ready" and prompt_count == 0 and active == 0:
                    try:
                        observation = legacy.baseline(context)
                        prospective = {"legacyProspectivePreserved": observation["legacyProspectivePreserved"],
                            "legacyProspectiveBaselineId": observation["legacyProspectiveBaselineId"]}
                    except (LegacyProspectiveError, OSError, ValueError):
                        pass
            except (LegacyProspectiveError, OSError, ValueError):
                pass
        return {**guest, "resourceAdmitted": True, "reservationId": reservation_id,
                "ownerReady": True, "controllerId": status["controllerId"],
                "ownerPid": before.pid, "ownerStartTicks": start_identity,
                "bootSessionUuid": boot, "runtimeRunning": False,
                "existingPromptCount": prompt_count, "conflictingJobCount": conflicts,
                "legacyUnknownPreserved": False, **prospective,
                "sourceFingerprint": pair.source_fingerprint,
                "fixtureReceiptArtifactId": pair.fixture_receipt_artifact_id,
                "baseDmgArtifactId": "sha256-" + guest["baseDmgSha256"],
                "targetDmgArtifactId": "sha256-" + guest["targetDmgSha256"]}

    def _boot_session(self) -> str:
        value = self._exec(["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"]).strip()
        if not value or len(value) > 64:
            raise MacMachineBoundaryError("Tart boot generation is unavailable.")
        return value

    def _protected_receipt(self, job_id: str) -> Mapping[str, Any]:
        gate._uuid(job_id)
        raw = self._exec(["/usr/bin/sudo", "-n", "/usr/bin/python3", "-c", _PROTECTED_READ, job_id])
        if len(raw) > 2048:
            raise MacMachineBoundaryError("Protected Mac receipt is unbounded.")
        try:
            value = json.loads(raw)
        except (TypeError, ValueError) as error:
            raise MacMachineBoundaryError("Protected Mac receipt is malformed.") from error
        if not isinstance(value, dict) or set(value) != {"jobId", "phase", "code", "stageAbsent", "backupAbsent"} or \
                value.get("jobId") != job_id:
            raise MacMachineBoundaryError("Protected Mac receipt identity changed.")
        return value

    def observe_terminal(self, vm_name: str, query: NativeTerminalQuery) -> Mapping[str, Any]:
        if vm_name != gate.VM_NAME or query.app != gate._fixed_paths({"sourceSha": query.source_sha})["app"] or \
                query.guest_root != gate._fixed_paths({"sourceSha": query.source_sha})["guestRoot"]:
            raise MacMachineBoundaryError("Terminal Tart source or app identity changed.")
        gate._uuid(query.job_id); gate._uuid(query.operation_id)
        if self._reservation() != query.reservation_id or self._boot_session() != query.boot_session_uuid:
            raise MacMachineBoundaryError("Tart allocation or boot changed before terminal readback.")
        launcher = query.app + "/Contents/MacOS/vpn-control"
        state_dir = query.guest_root + "/state"
        observer = FixtureProcessObserver(launcher, state_dir)
        before_rows = process_rows(self._exec(["/bin/ps", "-axo", "pid=,lstart=,command="]))
        new_owner = observer.identify(before_rows, INTERNAL_HEADLESS_OWNER)
        gui = observer.identify(before_rows, PLAIN_RETURN_GUI)
        old = [row for row in before_rows if row.pid == query.prior_owner_pid and
               (int.from_bytes(hashlib.sha256(row.started.encode()).digest()[:8], "big") or 1) ==
               query.prior_owner_start_ticks]
        if new_owner is None or gui is None or old or new_owner.pid == query.prior_owner_pid:
            raise MacMachineBoundaryError("Replacement Mac owner or GUI is unavailable.")
        public_status = self._public(launcher, state_dir, "status")
        updates = self._public(launcher, state_dir, "updates", "status")
        after_rows = process_rows(self._exec(["/bin/ps", "-axo", "pid=,lstart=,command="]))
        if observer.identify(after_rows, INTERNAL_HEADLESS_OWNER) != new_owner or \
                observer.identify(after_rows, PLAIN_RETURN_GUI) != gui or \
                public_status["controllerId"] != updates["controllerId"] or \
                public_status["data"].get("runtimeRunning") is not False:
            raise MacMachineBoundaryError("Replacement Mac owner changed during status read.")
        if public_status["controllerId"] == query.prior_controller_id:
            raise MacMachineBoundaryError("Public Mac controller did not change.")
        entries = updates["data"].get("installations")
        matched = [item for item in entries if isinstance(item, dict) and
                   item.get("jobId") == query.job_id and item.get("operationId") == query.operation_id] \
            if isinstance(entries, list) and len(entries) <= 32 else []
        if len(matched) != 1 or matched[0].get("final") is not True or \
                matched[0].get("originControllerId") != query.prior_controller_id:
            raise MacMachineBoundaryError("Exact public Mac installation is not terminal.")
        protected = self._protected_receipt(query.job_id)
        guest = super().observe_admission(vm_name, query.source_sha)
        if self._reservation() != query.reservation_id or self._boot_session() != query.boot_session_uuid:
            raise MacMachineBoundaryError("Tart allocation or boot changed during terminal readback.")
        entry = matched[0]
        server_stopped = False
        try:
            stop = macos_machine_server_stop.status(self.root, query.correlation_id,
                macos_machine_server_stop.TartBoundary(runner=self.runner))
            receipt = stop.get("receipt") if stop.get("state") == "complete" else None
            server_stopped = isinstance(receipt, dict) and all(receipt.get(key) == value for key, value in {
                "sourceSha": query.source_sha, "correlationId": query.correlation_id,
                "scenario": query.scenario, "jobId": query.job_id,
                "operationId": query.operation_id, "bootSessionUuid": query.boot_session_uuid,
                "reservationId": query.reservation_id,
                "fixtureReceiptArtifactId": query.fixture_receipt_artifact_id}.items())
        except (MacReceiptError, OSError, ValueError):
            server_stopped = False
        rollback_proven = False
        if query.scenario == "rollback":
            binding = ReceiptBinding(query.source_sha, query.correlation_id,
                query.scenario, query.job_id, query.operation_id,
                query.boot_session_uuid, query.reservation_id,
                query.fixture_receipt_artifact_id)
            try:
                worker = read_worker_events(query.job_id, runner=self.runner)
                base = (guest["baseDevice"], guest["baseInode"], query.base_jar_sha256)
                candidate = (worker[1]["device"], worker[1]["inode"],
                             query.target_jar_sha256)
                verify_worker_events(worker, job_id=query.job_id, base=base,
                                     candidate=candidate)
                trace = read_guest_candidate(query.source_sha, query.correlation_id,
                    "rollback-trace", runner=self.runner)
                for index, event in enumerate(worker):
                    if trace["events"][index] != {key: event[key] for key in (
                            "sequence", "type", "observedAtUnixMs", "device", "inode", "sha256")}:
                        raise MacReceiptError("Mac rollback receipt differs from protected worker trace.")
                validate_rollback_trace(trace, binding,
                    base_device=base[0], base_inode=base[1], base_jar_sha256=base[2],
                    candidate_device=candidate[0], candidate_inode=candidate[1],
                    candidate_jar_sha256=candidate[2],
                    protected_code=protected["code"], public_code=entry.get("code"),
                    fresh_stage_absent=protected["stageAbsent"],
                    fresh_backup_absent=protected["backupAbsent"])
                rollback_proven = True
            except (MacReceiptError, KeyError, IndexError, TypeError, ValueError):
                rollback_proven = False
        prospective = {"legacyProspectivePreservedAfter": False}
        try:
            legacy = MacLegacyProspectiveJournal(self.root,
                TartLegacyObservationBoundary(
                    generation=lambda: (self._boot_session(), self._reservation()),
                    runner=self.runner))
            observation = legacy.verify_bound(query.source_sha, query.correlation_id,
                query.fixture_receipt_artifact_id, query.boot_session_uuid,
                query.reservation_id)
            prospective = {
                "legacyProspectivePreservedAfter": observation["legacyProspectivePreservedAfter"],
                "legacyProspectiveBaselineId": observation["legacyProspectiveBaselineId"]}
        except (LegacyProspectiveError, OSError, ValueError):
            pass
        return {"sourceSha": query.source_sha, "operationId": query.operation_id,
                "jobId": query.job_id, "bootSessionUuid": query.boot_session_uuid,
                "app": query.app, "runtimeRunning": False,
                "cleanupCode": entry.get("cleanupCode"), "signatureValid": guest["baseSignatureValid"],
                "oldOwnerExited": True, "guiReturned": True, "guiBundlePath": query.app,
                "fixtureServerStopped": server_stopped,
                "publicFinal": True, "publicCode": entry.get("code"), "installed": entry.get("installed"),
                "protectedPhase": protected["phase"], "protectedCode": protected["code"],
                "installedJarSha256": guest["baseJarSha256"],
                "baseDevice": guest["baseDevice"], "baseInode": guest["baseInode"],
                "backupAbsent": protected["backupAbsent"], "stageAbsent": protected["stageAbsent"],
                "rollbackFaultObserved": rollback_proven,
                **prospective,
                "newOwnerPid": new_owner.pid, "guiPid": gui.pid}

"""Durable, correlation-bound execution state for fixed native scenarios.

This is deliberately only an orchestration core.  A caller supplies a fixed
driver which knows how to submit and *read* one approved scenario; this module
never accepts a command, a host address, or an SSH argument from an API user.
The local journal is written before submission, so losing a submit response
cannot turn a retry into a second effect.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Mapping, Protocol

try:  # Windows has no fcntl/flock or POSIX mode-bit ownership model.
    import fcntl
except ImportError:  # pragma: no cover - exercised by Windows import/discovery
    fcntl = None


_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ARTIFACT_ID = re.compile(r"^sha256-[0-9a-f]{64}$")
_JOURNAL_VERSION = 1
_FAILURE_EXCERPT_LIMIT = 1_024
_SCENARIOS = {"linux-public-update-preflight"}


class ScenarioExecutionError(ValueError):
    """A scenario request or durable record is invalid."""


class ExecutionState(str, Enum):
    INTENT = "intent"
    SUBMITTING = "submitting"
    SUBMITTED = "submitted"
    TERMINAL = "terminal"
    UNKNOWN = "unknown"


class ObservationStatus(str, Enum):
    RUNNING = "running"
    TERMINAL = "terminal"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ScenarioPlan:
    scenario_id: str
    host: str
    environment: str
    bundle_hash: str
    artifact_ids: Mapping[str, str]
    correlation_id: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ScenarioPlan":
        required = {"scenarioId", "host", "environment", "bundleHash", "artifactIds", "correlationId"}
        if not isinstance(value, Mapping) or set(value) != required:
            raise ScenarioExecutionError("Scenario request must contain exactly scenarioId, host, environment, bundleHash, artifactIds and correlationId.")
        strings = {key: value[key] for key in required - {"artifactIds"}}
        for key, item in strings.items():
            if not isinstance(item, str) or not _TOKEN.fullmatch(item):
                raise ScenarioExecutionError(f"Scenario request {key} is invalid.")
        if not _SHA256.fullmatch(value["bundleHash"]):
            raise ScenarioExecutionError("Scenario request bundleHash must be a lowercase SHA-256.")
        if value["scenarioId"] not in _SCENARIOS:
            raise ScenarioExecutionError("Scenario request scenarioId is not allowlisted.")
        artifacts = value["artifactIds"]
        if not isinstance(artifacts, Mapping) or not artifacts:
            raise ScenarioExecutionError("Scenario request artifactIds must be a nonempty object.")
        normalized: dict[str, str] = {}
        for key, item in artifacts.items():
            if not isinstance(key, str) or not _TOKEN.fullmatch(key) or not isinstance(item, str) or not _ARTIFACT_ID.fullmatch(item):
                raise ScenarioExecutionError("Scenario request artifactIds must map safe names to canonical sha256 IDs.")
            normalized[key] = item
        return cls(value["scenarioId"], value["host"], value["environment"], value["bundleHash"], dict(sorted(normalized.items())), value["correlationId"])

    def as_dict(self) -> dict[str, Any]:
        return {"scenarioId": self.scenario_id, "host": self.host, "environment": self.environment,
                "bundleHash": self.bundle_hash, "artifactIds": dict(self.artifact_ids), "correlationId": self.correlation_id}


@dataclass(frozen=True)
class JobIdentity:
    job_id: str
    pid: int | None
    start_ticks: int | None
    receipt_path: str | None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any], *, allow_pending: bool = False) -> "JobIdentity":
        required = {"jobId", "pid", "startTicks", "receiptPath"}
        if not isinstance(value, Mapping) or set(value) != required:
            raise ScenarioExecutionError("Job identity has unsupported or missing fields.")
        job = value["jobId"]
        if not isinstance(job, str) or not _TOKEN.fullmatch(job):
            raise ScenarioExecutionError("Job identity jobId is invalid.")
        pid, ticks = value["pid"], value["startTicks"]
        pending = pid is None and ticks is None
        if pending and not allow_pending:
            raise ScenarioExecutionError("Job identity PID generation is unavailable.")
        if not pending and (isinstance(pid, bool) or not isinstance(pid, int) or pid < 1 or isinstance(ticks, bool) or not isinstance(ticks, int) or ticks < 1):
            raise ScenarioExecutionError("Job identity PID generation is invalid.")
        receipt = value["receiptPath"]
        if receipt is not None and (not isinstance(receipt, str) or not receipt.startswith("/") or len(receipt) > 512 or "\x00" in receipt):
            raise ScenarioExecutionError("Job identity receiptPath is invalid.")
        return cls(job, pid, ticks, receipt)

    def as_dict(self) -> dict[str, Any]:
        return {"jobId": self.job_id, "pid": self.pid, "startTicks": self.start_ticks, "receiptPath": self.receipt_path}


@dataclass(frozen=True)
class DriverObservation:
    status: ObservationStatus
    reason: str
    identity: JobIdentity | None = None
    receipt: Mapping[str, Any] | None = None
    evidence_paths: tuple[str, ...] = ()
    failure_excerpt: str | None = None


class ScenarioDriver(Protocol):
    """Private, fixed-scenario adapter.  ``discover`` and ``observe`` are read-only."""
    def submit(self, plan: ScenarioPlan) -> JobIdentity: ...
    def discover(self, plan: ScenarioPlan) -> JobIdentity | None: ...
    def observe(self, plan: ScenarioPlan, identity: JobIdentity) -> DriverObservation: ...


class ScenarioExecutor:
    def __init__(self, journal_directory: Path | str, driver: ScenarioDriver):
        self.journal_directory = Path(journal_directory)
        self.driver = driver

    def start(self, request: Mapping[str, Any]) -> dict[str, Any]:
        plan = ScenarioPlan.from_mapping(request)
        self._require_private_journal_platform()
        with self._journal_lock():
            record = self._read(plan.correlation_id)
            if record is not None:
                if record["plan"] != plan.as_dict():
                    raise ScenarioExecutionError("Correlation ID already belongs to a different immutable scenario plan.")
                return self._public(record, duplicate=True)
            record = self._new_record(plan)
            if not self._create_intent(record):
                record = self._require(plan.correlation_id)
                if record["plan"] != plan.as_dict():
                    raise ScenarioExecutionError("Correlation ID already belongs to a different immutable scenario plan.")
                return self._public(record, duplicate=True)
            # Intent is durable before any effect may be submitted.
            record["state"] = ExecutionState.SUBMITTING.value
            self._write(record)
        try:
            identity = self.driver.submit(plan)
            # A detached remote wrapper may publish its job identity before the
            # child PID receipt exists; status discovers that generation later.
            self._validate_identity_for_record(identity, allow_pending=True)
        except Exception:
            # A driver exception after it has reached the remote side is ambiguous.
            # Never retry it here; later status/resume may discover by correlation.
            with self._journal_lock():
                current = self._require(plan.correlation_id)
                if current["state"] == ExecutionState.TERMINAL.value:
                    return self._public(current)
                current["lastReason"] = "submit_response_unavailable"
                self._write(current)
                return self._public(current)
        with self._journal_lock():
            current = self._require(plan.correlation_id)
            if current["state"] == ExecutionState.TERMINAL.value:
                return self._public(current)
            existing = JobIdentity.from_mapping(current["identity"], allow_pending=True) if current.get("identity") else None
            if existing is not None and existing.pid is not None and existing != identity:
                # An observation found a different generation while submit was in
                # flight.  Do not replace a durable identity with a stale response.
                return self._public(current)
            current["identity"] = identity.as_dict()
            current["state"] = ExecutionState.SUBMITTED.value
            current["lastReason"] = "submitted"
            self._write(current)
            return self._public(current)

    def status(self, correlation_id: str) -> dict[str, Any]:
        self._require_private_journal_platform()
        with self._journal_lock():
            record = self._require(correlation_id)
            if record["state"] == ExecutionState.TERMINAL.value:
                return self._public(record)
            initial_identity = record.get("identity")
        observed = self._observe(record)
        with self._journal_lock():
            current = self._require(correlation_id)
            # Observation takes place outside the lock.  A later terminal fact or
            # a newly discovered PID generation always wins over stale results.
            if current["state"] == ExecutionState.TERMINAL.value:
                return self._public(current)
            if current.get("identity") != initial_identity:
                return self._public(current)
            self._write(observed)
            return self._public(observed)

    def resume(self, correlation_id: str) -> dict[str, Any]:
        """Recover observation after a disconnected caller; this never calls submit."""
        return self.status(correlation_id)

    def collect(self, correlation_id: str, *, include_failure_excerpt: bool = False) -> dict[str, Any]:
        self._require_private_journal_platform()
        with self._journal_lock():
            record = self._require(correlation_id)
            result = self._public(record)
            result["evidencePaths"] = list(record.get("evidencePaths", []))
            if include_failure_excerpt and isinstance(record.get("failureExcerpt"), str):
                result["failureExcerpt"] = record["failureExcerpt"]
            return result

    def _observe(self, record: dict[str, Any]) -> dict[str, Any]:
        plan = ScenarioPlan.from_mapping(record["plan"])
        identity = JobIdentity.from_mapping(record["identity"], allow_pending=True) if record.get("identity") else None
        if identity is None or identity.pid is None:
            try:
                discovered = self.driver.discover(plan)
            except Exception:
                discovered = None
            if discovered is not None:
                self._validate_identity_for_record(discovered, allow_pending=True)
                identity = discovered
                record["identity"] = identity.as_dict()
                record["state"] = ExecutionState.SUBMITTED.value
                record["lastReason"] = "discovered_by_correlation"
            else:
                record["state"] = ExecutionState.UNKNOWN.value
                record["lastReason"] = "job_not_discovered"
                return record
        try:
            observation = self.driver.observe(plan, identity)
        except Exception:
            observation = DriverObservation(ObservationStatus.UNKNOWN, "observer_unavailable")
        self._apply_observation(record, plan, identity, observation)
        return record

    def _apply_observation(self, record: dict[str, Any], plan: ScenarioPlan, identity: JobIdentity, observation: DriverObservation) -> None:
        reason = observation.reason if isinstance(observation.reason, str) and "\x00" not in observation.reason else "invalid_observation"
        reason = reason[:256]
        if observation.identity is not None:
            self._validate_identity_for_record(observation.identity, allow_pending=True)
            if observation.identity != identity:
                record["state"], record["lastReason"] = ExecutionState.UNKNOWN.value, "job_identity_mismatch"
                return
            identity = observation.identity
            record["identity"] = identity.as_dict()
        paths = [path for path in observation.evidence_paths if isinstance(path, str) and path.startswith("/") and len(path) <= 512]
        record["evidencePaths"] = paths[:8]
        if isinstance(observation.failure_excerpt, str):
            record["failureExcerpt"] = observation.failure_excerpt.replace("\x00", "")[:_FAILURE_EXCERPT_LIMIT]
        if observation.status is ObservationStatus.TERMINAL and self._terminal_matches(plan, identity, observation.receipt):
            record["state"] = ExecutionState.TERMINAL.value
            record["lastReason"] = "correlated_receipt"
            record["exitCode"] = observation.receipt["exitCode"]  # validated above
            record["receipt"] = dict(observation.receipt)
        elif observation.status is ObservationStatus.RUNNING:
            record["state"], record["lastReason"] = ExecutionState.SUBMITTED.value, reason
        else:
            record["state"], record["lastReason"] = ExecutionState.UNKNOWN.value, reason

    @staticmethod
    def _terminal_matches(plan: ScenarioPlan, identity: JobIdentity, receipt: Mapping[str, Any] | None) -> bool:
        if identity.pid is None or identity.start_ticks is None or not isinstance(receipt, Mapping):
            return False
        expected = {"scenarioId": plan.scenario_id, "host": plan.host, "environment": plan.environment,
                    "bundleHash": plan.bundle_hash, "correlationId": plan.correlation_id, "jobId": identity.job_id,
                    "pid": identity.pid, "startTicks": identity.start_ticks}
        if set(receipt) != {*expected, "artifactIds", "exitCode"} or any(receipt.get(key) != item for key, item in expected.items()):
            return False
        if receipt.get("artifactIds") != dict(plan.artifact_ids):
            return False
        code = receipt.get("exitCode")
        return isinstance(code, int) and not isinstance(code, bool)

    @staticmethod
    def _validate_identity_for_record(identity: JobIdentity, *, allow_pending: bool = False) -> None:
        JobIdentity.from_mapping(identity.as_dict(), allow_pending=allow_pending)

    def _new_record(self, plan: ScenarioPlan) -> dict[str, Any]:
        return {"journalVersion": _JOURNAL_VERSION, "plan": plan.as_dict(), "state": ExecutionState.INTENT.value,
                "identity": None, "lastReason": "intent_recorded", "evidencePaths": []}

    def _path(self, correlation_id: str) -> Path:
        if not isinstance(correlation_id, str) or not _TOKEN.fullmatch(correlation_id):
            raise ScenarioExecutionError("Correlation ID is invalid.")
        return self.journal_directory / (correlation_id + ".json")

    def _ensure_private_journal(self) -> None:
        self.journal_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = os.lstat(self.journal_directory)
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077):
            raise ScenarioExecutionError("Scenario journal directory has unsafe type, owner, or permissions.")

    @staticmethod
    def _require_private_journal_platform() -> None:
        if os.name != "posix" or fcntl is None:
            raise ScenarioExecutionError("Durable scenario execution requires POSIX private journal support.")

    @contextmanager
    def _journal_lock(self):
        self._ensure_private_journal()
        lock_path = self.journal_directory / ".scenario.lock"
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) & 0o077):
                raise ScenarioExecutionError("Scenario journal lock has unsafe type, owner, or permissions.")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)

    def _validate_record(self, value: Any, correlation_id: str) -> None:
        if not isinstance(value, dict) or value.get("journalVersion") != _JOURNAL_VERSION or not isinstance(value.get("plan"), dict):
            raise ScenarioExecutionError("Scenario journal is invalid.")
        plan = ScenarioPlan.from_mapping(value["plan"])
        if plan.correlation_id != correlation_id:
            raise ScenarioExecutionError("Scenario journal correlation does not match its filename.")
        state = value.get("state")
        base = {"journalVersion", "plan", "state", "identity", "lastReason", "evidencePaths"}
        optional = {"failureExcerpt"}
        if state == ExecutionState.TERMINAL.value:
            optional |= {"exitCode", "receipt"}
        if state not in {item.value for item in ExecutionState} or set(value) - base - optional or not base <= set(value):
            raise ScenarioExecutionError("Scenario journal has invalid fields.")
        identity = value["identity"]
        if identity is not None:
            parsed = JobIdentity.from_mapping(identity, allow_pending=True)
        else:
            parsed = None
        if not isinstance(value["lastReason"], str) or len(value["lastReason"]) > 256 or "\x00" in value["lastReason"]:
            raise ScenarioExecutionError("Scenario journal reason is invalid.")
        paths = value["evidencePaths"]
        if (not isinstance(paths, list) or len(paths) > 8 or any(not isinstance(path, str) or not path.startswith("/") or len(path) > 512 or "\x00" in path for path in paths)):
            raise ScenarioExecutionError("Scenario journal evidence paths are invalid.")
        excerpt = value.get("failureExcerpt")
        if excerpt is not None and (not isinstance(excerpt, str) or len(excerpt) > _FAILURE_EXCERPT_LIMIT or "\x00" in excerpt):
            raise ScenarioExecutionError("Scenario journal failure excerpt is invalid.")
        if state == ExecutionState.TERMINAL.value:
            if parsed is None or parsed.pid is None or not isinstance(value.get("exitCode"), int) or isinstance(value["exitCode"], bool):
                raise ScenarioExecutionError("Scenario terminal journal is incomplete.")
            receipt = value.get("receipt")
            if not self._terminal_matches(plan, parsed, receipt) or receipt["exitCode"] != value["exitCode"]:
                raise ScenarioExecutionError("Scenario terminal receipt is invalid.")

    def _read(self, correlation_id: str) -> dict[str, Any] | None:
        path = self._path(correlation_id)
        try:
            metadata = os.lstat(path)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
                raise ScenarioExecutionError("Scenario journal has unsafe type, owner, or permissions.")
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                opened = os.fstat(descriptor)
                if not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.getuid() or stat.S_IMODE(opened.st_mode) & 0o077:
                    raise ScenarioExecutionError("Scenario journal has unsafe type, owner, or permissions.")
                with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
                    descriptor = -1
                    value = json.load(handle)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
        except FileNotFoundError:
            return None
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ScenarioExecutionError("Scenario journal is unreadable.") from error
        self._validate_record(value, correlation_id)
        return value

    def _require(self, correlation_id: str) -> dict[str, Any]:
        record = self._read(correlation_id)
        if record is None:
            raise ScenarioExecutionError("No scenario journal exists for this correlation ID.")
        return record

    def _write(self, record: dict[str, Any]) -> None:
        self._validate_record(record, ScenarioPlan.from_mapping(record["plan"]).correlation_id)
        plan = ScenarioPlan.from_mapping(record["plan"])
        self._ensure_private_journal()
        path = self._path(plan.correlation_id)
        payload = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        descriptor, temporary = tempfile.mkstemp(prefix=".scenario-", dir=self.journal_directory)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                descriptor = -1
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            directory_fd = os.open(self.journal_directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def _create_intent(self, record: dict[str, Any]) -> bool:
        """Atomically claim a correlation before calling the effectful driver."""
        plan = ScenarioPlan.from_mapping(record["plan"])
        self._validate_record(record, plan.correlation_id)
        self._ensure_private_journal()
        path = self._path(plan.correlation_id)
        payload = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            return False
        try:
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        directory_fd = os.open(self.journal_directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return True

    @staticmethod
    def _public(record: Mapping[str, Any], *, duplicate: bool = False) -> dict[str, Any]:
        plan = record["plan"]
        result: dict[str, Any] = {"scenarioId": plan["scenarioId"], "host": plan["host"],
            "environment": plan["environment"], "bundleHash": plan["bundleHash"],
            "artifactIds": plan["artifactIds"], "correlationId": plan["correlationId"],
            "state": record["state"], "reason": record.get("lastReason", "unknown")}
        if record.get("identity") is not None:
            result["jobIdentity"] = record["identity"]
        if "exitCode" in record:
            result["exitCode"] = record["exitCode"]
        if duplicate:
            result["duplicate"] = True
        return result

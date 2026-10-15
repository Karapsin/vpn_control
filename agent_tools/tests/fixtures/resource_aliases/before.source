"""Durable, fail-closed reservations for native test environments.

This module only records caller supplied facts.  It does not inspect hosts,
connect over SSH/ADB, start a VM, or terminate a job.  A caller that has fresh
receipts may reserve capacity before submitting a native operation; uncertain
job evidence intentionally prevents release rather than being treated as gone.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
from typing import Any, Mapping

try:  # Supports both the package tests and the standalone MCP CLI fallback.
    from . import vm_workflow
except ImportError:  # pragma: no cover - exercised by the server's script mode.
    import vm_workflow  # type: ignore[no-redef]


_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DEFAULT_MAX_AGE_MS = 60_000
_STATE_VERSION = 1


class NativeEnvironmentError(ValueError):
    """A reservation or supplied observation is unsafe or insufficient."""


def _positive(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise NativeEnvironmentError(f"{label} must be a positive integer")
    return value


def _name(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SAFE_NAME.fullmatch(value):
        raise NativeEnvironmentError(f"{label} is unsafe")
    return value


def _root_paths(root: str | Path) -> tuple[Path, Path]:
    directory = Path(root).resolve() / ".rag_index" / "native-environments"
    return directory, directory / "reservations.json"


def _require_private(path: Path, *, directory: bool = False) -> None:
    try:
        value = os.lstat(path)
    except OSError as error:
        raise NativeEnvironmentError("native environment state cannot be inspected") from error
    expected = stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode)
    if not expected or value.st_uid != os.getuid() or value.st_mode & 0o077:
        raise NativeEnvironmentError("native environment state is not a private regular file")


def _secure_directory(directory: Path) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    _require_private(directory, directory=True)
    # mkdir honors umask; repair a newly-created or legacy private directory.
    os.chmod(directory, 0o700)
    _require_private(directory, directory=True)


def _read_private(path: Path) -> str:
    _require_private(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            return stream.read()
    except OSError as error:
        raise NativeEnvironmentError("native environment state is unreadable") from error


def _load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"version": _STATE_VERSION, "reservations": []}
    try:
        raw = json.loads(_read_private(path))
    except (NativeEnvironmentError, json.JSONDecodeError) as error:
        raise NativeEnvironmentError("native environment state is unreadable") from error
    if not isinstance(raw, dict) or raw.get("version") != _STATE_VERSION or not isinstance(raw.get("reservations"), list):
        raise NativeEnvironmentError("native environment state has an unsupported schema")
    return raw


def _save(path: Path, state: Mapping[str, Any]) -> None:
    payload = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
    temporary = path.with_name(path.name + "." + secrets.token_hex(16) + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        _require_private(temporary)
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        _require_private(path)
    except OSError as error:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise NativeEnvironmentError("native environment state cannot be saved") from error


class _LockedState:
    def __init__(self, root: str | Path) -> None:
        if os.name != "posix":
            raise NativeEnvironmentError("native environment reservations are unsupported on this platform")
        self.directory, self.path = _root_paths(root)
        self.lock = None
        self.state: dict[str, Any] | None = None

    def __enter__(self) -> "_LockedState":
        # Import only on the supported platform so module discovery remains portable.
        import fcntl
        _secure_directory(self.directory)
        lock_path = self.directory / "lock"
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        self.lock = os.fdopen(descriptor, "r+", encoding="utf-8")
        _require_private(lock_path)
        fcntl.flock(self.lock.fileno(), fcntl.LOCK_EX)
        self.state = _load(self.path)
        return self

    def save(self) -> None:
        assert self.state is not None
        _save(self.path, self.state)

    def __exit__(self, *_: Any) -> None:
        assert self.lock is not None
        import fcntl
        fcntl.flock(self.lock.fileno(), fcntl.LOCK_UN)
        self.lock.close()


def _request(request: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(request, Mapping):
        raise NativeEnvironmentError("reservation request must be an object")
    host = _name(request.get("hostAlias"), "host alias")
    environment = _name(request.get("environment"), "environment")
    operator = _name(request.get("operator"), "operator")
    requested = _positive(request.get("requestedMemoryBytes"), "requested memory")
    measurement = request.get("measurement")
    if not isinstance(measurement, Mapping):
        raise NativeEnvironmentError("host measurement is required")
    headroom = _positive(request.get("headroomBytes"), "host headroom")
    state = request.get("allocationState", "pending")
    if state not in ("pending", "running"):
        raise NativeEnvironmentError("allocation state must be pending or running")
    return {"hostAlias": host, "environment": environment, "operator": operator,
            "requestedMemoryBytes": requested, "measurement": measurement,
            "headroomBytes": headroom, "allocationState": state,
            "runningAllocationMapping": request.get("runningAllocationMapping")}


def _receipt_status(request: Mapping[str, Any]) -> dict[str, Any]:
    """Summarize supplied receipts without claiming that a probe was performed."""
    observations = request.get("observations", [])
    if observations is None:
        observations = []
    if not isinstance(observations, list):
        raise NativeEnvironmentError("observations must be a list")
    now = request.get("nowUnixMs", time.time_ns() // 1_000_000)
    now = _positive(now, "observation clock")
    maximum_age = request.get("maxObservationAgeMs", _DEFAULT_MAX_AGE_MS)
    maximum_age = _positive(maximum_age, "maximum observation age")
    normalized: list[dict[str, Any]] = []
    active_job = "absent"
    active_job_receipt: dict[str, Any] | None = None
    for receipt in observations:
        if not isinstance(receipt, Mapping):
            raise NativeEnvironmentError("observation receipt must be an object")
        kind = _name(receipt.get("kind"), "observation kind")
        source = _name(receipt.get("source"), "observation source")
        observed = _positive(receipt.get("observedAtUnixMs"), "observation timestamp")
        outcome = receipt.get("outcome", receipt.get("state", "unknown"))
        if outcome not in ("ready", "available", "active", "complete", "absent", "unknown", "unavailable"):
            raise NativeEnvironmentError("observation outcome is unsupported")
        stale = observed > now or now - observed > maximum_age
        item = {"kind": kind, "source": source, "observedAtUnixMs": observed,
                "outcome": outcome, "stale": stale, "unknown": outcome == "unknown"}
        for key in ("reservationId", "reservationToken"):
            if key in receipt:
                if not isinstance(receipt[key], str) or not receipt[key]:
                    raise NativeEnvironmentError(f"{key} must be a nonempty string when supplied")
                item[key] = receipt[key]
        normalized.append(item)
        if kind == "active-job":
            active_job_receipt = item
            if stale or outcome in ("unknown", "unavailable"):
                active_job = "unknown"
            elif outcome == "active":
                active_job = "active"
    freshness = "stale" if any(item["stale"] for item in normalized) else "fresh"
    uncertainty = any(item["unknown"] or item["stale"] for item in normalized)
    return {"state": "UNKNOWN" if uncertainty else "OBSERVED", "source": "supplied-receipts",
            "observedAtUnixMs": now, "maximumAgeMs": maximum_age, "freshness": freshness,
            "observations": normalized, "activeJob": active_job,
            "activeJobReceipt": active_job_receipt,
            "ready": False}


def environment_status(root: str | Path, request: Mapping[str, Any]) -> dict[str, Any]:
    """Return a compact status of caller-supplied evidence; it performs no probe."""
    _ = root  # Deliberately no state or native-host access for an observation aggregate.
    return _receipt_status(request)


def _identity(reservation: Mapping[str, Any]) -> dict[str, str]:
    return {"reservationId": reservation["id"], "token": reservation["token"],
            "hostAlias": reservation["hostAlias"], "environment": reservation["environment"],
            "operator": reservation["operator"]}


def _running_mapping(records: list[Mapping[str, Any]], request: Mapping[str, Any]) -> None:
    running = [record for record in records if record.get("allocationState") == "running"]
    if not running:
        return
    mapping = request.get("runningAllocationMapping")
    if not isinstance(mapping, list):
        raise NativeEnvironmentError("running reservations require exact runningAllocationMapping")
    actual: dict[str, int] = {}
    for item in mapping:
        if not isinstance(item, Mapping) or set(item) != {"reservationId", "memoryBytes"}:
            raise NativeEnvironmentError("running allocation mapping is unsafe")
        identifier = item["reservationId"]
        if not isinstance(identifier, str) or identifier in actual:
            raise NativeEnvironmentError("running allocation mapping is ambiguous")
        actual[identifier] = _positive(item["memoryBytes"], "running allocation memory")
    expected = {record["id"]: record["requestedMemoryBytes"] for record in running}
    if actual != expected:
        raise NativeEnvironmentError("running reservation mapping is ambiguous")
    configured = request["measurement"].get("runningConfiguredMemoryBytes")
    if not isinstance(configured, int) or isinstance(configured, bool) or configured < sum(actual.values()):
        raise NativeEnvironmentError("running configured memory cannot contain the exact running allocation mapping")


def _matching_job_receipt(record: Mapping[str, Any], receipt: Mapping[str, Any]) -> dict[str, Any] | None:
    for item in receipt["observations"]:
        if item["kind"] == "active-job" and not item["stale"] and \
                item.get("reservationId") == record["id"] and item.get("reservationToken") == record["token"]:
            return item
    return None


def _release_job_state(record: Mapping[str, Any], now: int) -> str:
    """Return absent, active, or unknown without inferring a missing job ended."""
    evidence = record.get("activeJobEvidence")
    if evidence is None:
        return "unknown" if record.get("allocationState") == "running" else record.get("activeJob", "absent")
    if not isinstance(evidence, Mapping):
        return "unknown"
    observed = evidence.get("observedAtUnixMs")
    maximum = record.get("observationMaximumAgeMs")
    if not isinstance(observed, int) or not isinstance(maximum, int) or observed > now or now - observed > maximum:
        return "unknown"
    outcome = evidence.get("outcome")
    if outcome in ("complete", "absent"):
        return "absent"
    return "active" if outcome == "active" else "unknown"


def reserve_environment(root: str | Path, request: Mapping[str, Any]) -> dict[str, Any]:
    """Atomically admit and persist one capacity reservation.

    Same operator/environment/host/memory requests are idempotent.  A different
    operator targeting an occupied host/environment is rejected, even if capacity
    remains, so ownership is always unambiguous.
    """
    parsed = _request(request)
    receipt = _receipt_status(request)
    with _LockedState(root) as locked:
        assert locked.state is not None
        records = locked.state["reservations"]
        same_target = [r for r in records if r["hostAlias"] == parsed["hostAlias"] and r["environment"] == parsed["environment"]]
        same_host = [r for r in records if r["hostAlias"] == parsed["hostAlias"]]
        for record in same_target:
            exact = all(record[key] == parsed[key] for key in ("hostAlias", "environment", "operator", "requestedMemoryBytes"))
            if exact:
                if parsed["allocationState"] == "running" and record["allocationState"] == "pending":
                    supplied = request.get("reservationIdentity")
                    if supplied != _identity(record):
                        raise NativeEnvironmentError("pending reservation requires its exact identity to transition to running")
                    proposed = [*same_host]
                    proposed[proposed.index(record)] = {**record, "allocationState": "running"}
                    _running_mapping(proposed, request)
                    record["allocationState"] = "running"
                elif parsed["allocationState"] != record["allocationState"]:
                    raise NativeEnvironmentError("reservation allocation state conflicts with the existing reservation")
                # Old active/unknown evidence is monotonic.  Only a fresh receipt
                # correlated to the opaque reservation can record a terminal job.
                job_receipt = _matching_job_receipt(record, receipt)
                if job_receipt is not None:
                    record["activeJob"] = "active" if job_receipt["outcome"] == "active" else (
                        "unknown" if job_receipt["outcome"] in ("unknown", "unavailable") else "absent"
                    )
                    record["activeJobEvidence"] = job_receipt
                    record["observationMaximumAgeMs"] = receipt["maximumAgeMs"]
                record["lastObservation"] = receipt
                locked.save()
                return {"ok": True, "state": "reserved", "idempotent": True,
                        "identity": _identity(record), "reservation": {"memoryBytes": record["requestedMemoryBytes"], "allocationState": record["allocationState"]},
                        "nativeActionAllowed": False}
        if same_target:
            raise NativeEnvironmentError("environment is already reserved by a different operator or request")

        if parsed["allocationState"] == "running":
            raise NativeEnvironmentError("new reservations must begin pending before an exact running transition")
        _running_mapping(same_host, parsed)
        pending = [{"id": r["id"], "memoryBytes": r["requestedMemoryBytes"]}
                   for r in same_host if r["allocationState"] == "pending"]
        try:
            plan = vm_workflow.admit_plan(parsed["measurement"], requested_memory_bytes=parsed["requestedMemoryBytes"],
                                          headroom_bytes=parsed["headroomBytes"], reservations=pending)
        except vm_workflow.VmWorkflowError as error:
            raise NativeEnvironmentError(str(error)) from error
        record = {"id": "env-" + secrets.token_hex(16), "token": secrets.token_urlsafe(24),
                  "hostAlias": parsed["hostAlias"], "environment": parsed["environment"], "operator": parsed["operator"],
                  "requestedMemoryBytes": parsed["requestedMemoryBytes"], "allocationState": parsed["allocationState"],
                  "createdAtUnixMs": time.time_ns() // 1_000_000, "activeJob": receipt["activeJob"],
                  "activeJobEvidence": receipt["activeJobReceipt"], "observationMaximumAgeMs": receipt["maximumAgeMs"],
                  "lastObservation": receipt}
        records.append(record)
        locked.save()
        return {"ok": True, "state": "reserved", "idempotent": False, "identity": _identity(record),
                "reservation": {"memoryBytes": record["requestedMemoryBytes"], "allocationState": record["allocationState"]},
                "plan": plan, "nativeActionAllowed": False}


def release_environment(root: str | Path, identity: Mapping[str, Any]) -> dict[str, Any]:
    """Release a matching reservation, refusing explicit active or unknown jobs."""
    if not isinstance(identity, Mapping):
        raise NativeEnvironmentError("reservation identity must be an object")
    required = ("reservationId", "token", "hostAlias", "environment", "operator")
    if set(identity) != set(required) or any(not isinstance(identity[key], str) for key in required):
        raise NativeEnvironmentError("reservation identity must contain exactly its opaque fields")
    with _LockedState(root) as locked:
        assert locked.state is not None
        for index, record in enumerate(locked.state["reservations"]):
            if all(identity[key] == _identity(record)[key] for key in required):
                if _release_job_state(record, time.time_ns() // 1_000_000) in ("active", "unknown"):
                    raise NativeEnvironmentError("reservation has explicit active or unknown job evidence")
                del locked.state["reservations"][index]
                locked.save()
                return {"ok": True, "state": "released", "identity": dict(identity), "nativeActionAllowed": False}
    raise NativeEnvironmentError("reservation identity is unknown or does not match")

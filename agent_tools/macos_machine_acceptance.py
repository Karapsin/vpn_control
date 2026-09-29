"""One-shot admission and evidence gate for the disposable Tart machine update.

The native boundary is intentionally injected. This module neither boots Tart nor
reads a password. An MCP adapter must supply verified observations and a secure
UI implementation after independent review; caller claims cannot become a grant.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any, Mapping, Protocol
from uuid import UUID


VM_NAME = "vpn-control-boot-control53"
_GROUP = ".rag_index/macos-machine-acceptance"
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_SOURCE = re.compile(r"[0-9a-f]{40}\Z")
_SCENARIOS = {"install", "rollback"}


class MacMachineAcceptanceError(ValueError):
    pass


class Boundary(Protocol):
    def current_source_sha(self) -> str: ...
    def source_tree_clean(self) -> bool: ...
    def admission(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...
    def submit(self, request: Mapping[str, Any], admission: Mapping[str, Any]) -> Mapping[str, Any]: ...
    def prompt(self, request: Mapping[str, Any], operation: Mapping[str, Any]) -> Mapping[str, Any]: ...
    def secure_authorize(self, request: Mapping[str, Any], operation: Mapping[str, Any]) -> None: ...
    def terminal(self, request: Mapping[str, Any], operation: Mapping[str, Any]) -> Mapping[str, Any]: ...


def _uuid(value: Any) -> str:
    if not isinstance(value, str):
        raise MacMachineAcceptanceError("Correlation must be a canonical UUID.")
    try:
        if str(UUID(value)) != value:
            raise ValueError()
    except ValueError as error:
        raise MacMachineAcceptanceError("Correlation must be a canonical UUID.") from error
    return value


def _request(value: Mapping[str, Any]) -> dict[str, Any]:
    fields = {"correlationId", "scenario", "sourceSha", "sourceFingerprint",
              "fixtureReceiptArtifactId", "baseDmgArtifactId", "targetDmgArtifactId",
              "baseJarSha256", "targetJarSha256"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise MacMachineAcceptanceError("Machine acceptance request has unsupported fields.")
    request = dict(value)
    _uuid(request["correlationId"])
    if request["scenario"] not in _SCENARIOS or not _SOURCE.fullmatch(str(request["sourceSha"])):
        raise MacMachineAcceptanceError("Scenario or source is invalid.")
    for field in ("sourceFingerprint", "baseJarSha256", "targetJarSha256"):
        if not isinstance(request[field], str) or not _SHA.fullmatch(request[field]):
            raise MacMachineAcceptanceError("Machine acceptance digest is invalid.")
    for field in ("fixtureReceiptArtifactId", "baseDmgArtifactId", "targetDmgArtifactId"):
        if not isinstance(request[field], str) or not request[field].startswith("sha256-") or \
                not _SHA.fullmatch(request[field][7:]):
            raise MacMachineAcceptanceError("Machine acceptance artifact is invalid.")
    return request


def _fixed_paths(request: Mapping[str, Any]) -> dict[str, str]:
    suffix = request["sourceSha"][:7]
    return {"vmName": VM_NAME, "app": f"/Applications/vpn-control-parity{suffix}.app",
            "guestRoot": f"/Users/admin/macos-parity{suffix}"}


def _admit(request: Mapping[str, Any], observed: Mapping[str, Any], *, expected_prompt_count: int = 0) -> dict[str, Any]:
    """Require fresh exact guest/resource proof before a public install call."""
    if not isinstance(observed, Mapping):
        raise MacMachineAcceptanceError("Guest admission is unavailable.")
    fixed = _fixed_paths(request)
    expected = {"sourceSha": request["sourceSha"], "sourceFingerprint": request["sourceFingerprint"],
                "fixtureReceiptArtifactId": request["fixtureReceiptArtifactId"],
                "baseDmgArtifactId": request["baseDmgArtifactId"],
                "targetDmgArtifactId": request["targetDmgArtifactId"], **fixed}
    if any(observed.get(key) != value for key, value in expected.items()):
        raise MacMachineAcceptanceError("Exact source, artifact, or guest path changed.")
    if observed.get("vmRunning") is not True or observed.get("resourceAdmitted") is not True or \
            observed.get("ownerReady") is not True or observed.get("runtimeRunning") is not False or \
            observed.get("existingPromptCount") != expected_prompt_count or observed.get("conflictingJobCount") != 0 or \
            observed.get("legacyUnknownPreserved") is not True:
        raise MacMachineAcceptanceError("Guest, owner, or resource admission is incomplete.")
    for field in ("reservationId", "bootSessionUuid", "controllerId"):
        if not isinstance(observed.get(field), str) or not observed[field]:
            raise MacMachineAcceptanceError("Guest generation proof is incomplete.")
    for field in ("ownerPid", "ownerStartTicks", "baseDevice", "baseInode"):
        if type(observed.get(field)) is not int or observed[field] <= 0:
            raise MacMachineAcceptanceError("Owner or installed base generation is invalid.")
    if observed.get("baseJarSha256") != request["baseJarSha256"] or \
            observed.get("baseSignatureValid") is not True or \
            observed.get("baseRootOwned") is not True or \
            observed.get("targetDmgSha256") != request["targetDmgArtifactId"][7:] or \
            observed.get("baseDmgSha256") != request["baseDmgArtifactId"][7:]:
        raise MacMachineAcceptanceError("Installed base or frozen DMG proof changed.")
    return {key: observed[key] for key in (*expected, "reservationId", "bootSessionUuid", "controllerId",
            "ownerPid", "ownerStartTicks", "baseDevice", "baseInode", "baseJarSha256",
            "baseSignatureValid", "baseRootOwned", "targetDmgSha256", "baseDmgSha256")}


def _private_group(root: Path) -> Path:
    root = root.resolve(strict=True)
    parent = root / ".rag_index"
    parent.mkdir(mode=0o700, exist_ok=True)
    group = parent / "macos-machine-acceptance"
    group.mkdir(mode=0o700, exist_ok=True)
    for path in (parent, group):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise MacMachineAcceptanceError("Machine acceptance journal is not owner-private.")
    return group


def _read(path: Path) -> dict[str, Any] | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 8192:
            raise MacMachineAcceptanceError("Machine acceptance journal is unsafe.")
        return json.load(stream)


def _save(path: Path, record: Mapping[str, Any]) -> None:
    temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(record, stream, sort_keys=True, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _path(group: Path, correlation: str) -> Path:
    return group / (correlation + ".json")


def _lock(group: Path):
    fd = os.open(group / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        os.close(fd)
        raise MacMachineAcceptanceError("Machine acceptance lock is unsafe.")
    return os.fdopen(fd, "r+")


def _public(record: Mapping[str, Any]) -> dict[str, Any]:
    return {"state": record["state"], "correlationId": record["request"]["correlationId"],
            "scenario": record["request"]["scenario"], "sourceSha": record["request"]["sourceSha"],
            "replayAllowed": False, "operationId": record.get("operationId"),
            "jobId": record.get("jobId"), "accepted": record["state"] == "complete"}


def start(root: Path, inputs: Mapping[str, Any], boundary: Boundary) -> dict[str, Any]:
    request = _request(inputs)
    group = _private_group(root)
    with _lock(group) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        path = _path(group, request["correlationId"])
        old = _read(path)
        if old is not None:
            if old.get("request") != request:
                raise MacMachineAcceptanceError("Correlation is bound to different inputs.")
            return _public(old)
        # One fixed Tart VM is shared by all correlations. A prior unknown owns
        # it until exact terminal/cleanup proof, even after a process restart.
        entries = list(group.glob("*.json"))
        if len(entries) > 128:
            raise MacMachineAcceptanceError("Machine acceptance journal is unbounded.")
        for other in entries:
            prior = _read(other)
            if prior is None or prior.get("state") != "complete":
                raise MacMachineAcceptanceError("A prior Tart campaign is unresolved.")
        if boundary.current_source_sha() != request["sourceSha"] or boundary.source_tree_clean() is not True:
            raise MacMachineAcceptanceError("Source freeze changed.")
        admission = _admit(request, boundary.admission(request))
        record: dict[str, Any] = {"schemaVersion": 1, "request": request, "admission": admission,
                                  "state": "unknown", "phase": "install-dispatched",
                                  "operationId": None, "jobId": None}
        _save(path, record)  # Durable uncertainty before the sole native mutation.
        try:
            result = boundary.submit(request, admission)
            if isinstance(result, Mapping) and result.get("accepted") is True and \
                    result.get("controllerId") == admission["controllerId"]:
                record["operationId"] = _uuid(result.get("operationId"))
                record["jobId"] = _uuid(result.get("jobId"))
                record["phase"] = "awaiting-authorization"
                _save(path, record)
        except Exception:
            pass  # The durable intent remains unknown and cannot be replayed.
        return _public(record)


def authorize(root: Path, correlation_id: str, boundary: Boundary) -> dict[str, Any]:
    correlation = _uuid(correlation_id)
    group = _private_group(root)
    with _lock(group) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        path = _path(group, correlation)
        record = _read(path)
        if record is None or record.get("phase") != "awaiting-authorization" or record.get("state") != "unknown":
            raise MacMachineAcceptanceError("Exact pending authorization is unavailable.")
        request, admission = record["request"], record["admission"]
        if boundary.current_source_sha() != request["sourceSha"] or boundary.source_tree_clean() is not True or \
                _admit(request, boundary.admission(request), expected_prompt_count=1) != admission:
            raise MacMachineAcceptanceError("Guest admission changed before authorization.")
        operation = {"operationId": record["operationId"], "jobId": record["jobId"],
                     "controllerId": admission["controllerId"], "ownerPid": admission["ownerPid"],
                     "ownerStartTicks": admission["ownerStartTicks"], "bootSessionUuid": admission["bootSessionUuid"]}
        prompt = boundary.prompt(request, operation)
        if not isinstance(prompt, Mapping) or prompt != {**operation, "visible": True, "count": 1}:
            raise MacMachineAcceptanceError("Secure prompt is not uniquely bound to the job.")
        record["phase"] = "authorization-dispatched"
        _save(path, record)  # A lost secure UI result is never attempted again.
        try:
            boundary.secure_authorize(request, operation)
        except Exception:
            pass
        return _public(record)


def status(root: Path, correlation_id: str, boundary: Boundary) -> dict[str, Any]:
    correlation = _uuid(correlation_id)
    group = _private_group(root)
    with _lock(group) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        path = _path(group, correlation)
        record = _read(path)
        if record is None:
            return {"state": "absent", "correlationId": correlation, "replayAllowed": False}
        if record.get("state") == "complete" or not record.get("operationId") or not record.get("jobId"):
            return _public(record)
        operation = {"operationId": record["operationId"], "jobId": record["jobId"],
                     "admission": record["admission"]}
        try:
            evidence = boundary.terminal(record["request"], operation)
            _verify_terminal(record, evidence)
        except Exception:
            return _public(record)
        record["state"] = "complete"
        record["phase"] = "verified-terminal"
        record["evidence"] = {key: evidence[key] for key in (
            "sourceSha", "operationId", "jobId", "bootSessionUuid", "protectedPhase",
            "protectedCode", "installedJarSha256", "newOwnerPid", "guiPid") if key in evidence}
        _save(path, record)
        return _public(record)


def _verify_terminal(record: Mapping[str, Any], evidence: Mapping[str, Any]) -> None:
    if not isinstance(evidence, Mapping):
        raise MacMachineAcceptanceError("Native terminal evidence is unavailable.")
    request, admission = record["request"], record["admission"]
    expected = {"sourceSha": request["sourceSha"], "operationId": record["operationId"],
                "jobId": record["jobId"], "bootSessionUuid": admission["bootSessionUuid"],
                "app": admission["app"], "runtimeRunning": False, "cleanupCode": "OK",
                "signatureValid": True, "oldOwnerExited": True, "guiReturned": True,
                "guiBundlePath": admission["app"], "fixtureServerStopped": True,
                "publicFinal": True}
    if any(evidence.get(key) != value for key, value in expected.items()):
        raise MacMachineAcceptanceError("Native terminal identity or cleanup is incomplete.")
    if request["scenario"] == "install":
        wanted = {"protectedPhase": "SUCCEEDED", "protectedCode": "OK", "publicCode": "OK",
                  "installed": True, "installedJarSha256": request["targetJarSha256"],
                  "backupAbsent": True, "stageAbsent": True}
    else:
        wanted = {"protectedPhase": "FAILED", "protectedCode": "PERSISTENCE_FAILED",
                  "publicCode": "PERSISTENCE_FAILED", "installed": None,
                  "installedJarSha256": request["baseJarSha256"],
                  "baseDevice": admission["baseDevice"], "baseInode": admission["baseInode"],
                  "rollbackFaultObserved": True, "stageAbsent": True}
    if any(evidence.get(key) != value for key, value in wanted.items()):
        raise MacMachineAcceptanceError("Machine install or rollback outcome is unproven.")
    if not isinstance(evidence.get("newOwnerPid"), int) or evidence["newOwnerPid"] <= 0 or \
            evidence["newOwnerPid"] == admission["ownerPid"] or \
            not isinstance(evidence.get("guiPid"), int) or evidence["guiPid"] <= 0:
        raise MacMachineAcceptanceError("Replacement owner or GUI generation is unproven.")

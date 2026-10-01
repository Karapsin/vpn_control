"""Private, durable, redacted evidence for failed native MCP operations.

This module records only caller-supplied, allowlisted metadata.  It never
executes an operation, follows evidence paths, logs input, or replays a failed
operation.  The receipt is historical: an ``nativeUNKNOWN`` observation stays
unknown and a ``terminalFailure`` stays terminal.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any, Iterator, Mapping


_RELATIVE = Path(".rag_index") / "native-failures"
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SHA = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_HEX = re.compile(r"^[0-9a-f]{64}$")
_MAX_RECORD = 8192
_MAX_OBSERVATIONS = 8


# These descriptions are deliberately a closed table.  They turn only the
# bounded state/phase projections already returned by the fixed CP117 readers
# into safe fingerprint components; raw receipts and transport errors never
# participate.  The references identify the existing deterministic regression
# that protects each reader without exposing an evidence location.
_WINDOWS_FAILURE_DETAILS: dict[str, tuple[str, str]] = {
    "windows-fixture-stage-recover-7f27": (
        "fixture_stage_recovery",
        "agent_tools.tests.test_windows_update_fixture_stage_recovery.StageRecoveryTest",
    ),
    "windows-msi-owner-census": (
        "owner_census",
        "agent_tools.tests.test_windows_msi_owner_census.OwnerCensusTests",
    ),
    "windows-fixture-stage-diagnostic": (
        "fixture_stage_diagnostic",
        "agent_tools.tests.test_windows_update_fixture_stage.WindowsUpdateFixtureStageTest",
    ),
}
_FIXTURE_STAGE_DIAGNOSTIC_TYPES = {
    "remote-stage-absent": "remote_stage_absent",
    "remote-stage-partial": "remote_stage_partial",
    "remote-binding-mismatch": "remote_binding_mismatch",
    "remote-dispatch-malformed": "remote_dispatch_malformed",
    "guest-stage-absent": "guest_stage_absent",
    "guest-stage-partial": "guest_stage_partial",
    "guest-stage-full": "guest_stage_full",
    "receipt-pending": "receipt_pending",
    "receipt-absent": "receipt_absent",
    "receipt-present-unverified": "receipt_present_unverified",
    "qga-protocol": "qga_protocol",
    "local-intent": "local_intent",
    "local-artifact": "local_artifact",
    "descriptor": "descriptor",
}


class NativeFailureEvidenceError(ValueError):
    """Failure evidence is malformed or cannot be privately persisted."""


def bounded_failure_details(action: Any, result: Mapping[str, Any]) -> dict[str, str]:
    """Return a finite public failure descriptor for selected CP117 readers.

    This is intentionally a projection, not diagnosis.  It accepts only an
    action in the fixed table and a reader's already bounded ``state`` and,
    for the fixture-stage diagnostic, ``phase``.  Every unavailable,
    malformed, successful, or newly introduced result falls back to the exact
    generic ``outcome_unknown`` label.  The raw receipt and correlation remain
    private in the normal evidence record.
    """
    if (not isinstance(action, str) or action not in _WINDOWS_FAILURE_DETAILS
            or not isinstance(result, Mapping) or result.get("state") != "unknown"):
        return {}
    failure_phase, regression_reference = _WINDOWS_FAILURE_DETAILS[action]
    failure_type = "outcome_unknown"
    if action == "windows-fixture-stage-diagnostic" and isinstance(result, Mapping):
        phase = result.get("phase")
        if isinstance(phase, str):
            failure_type = _FIXTURE_STAGE_DIAGNOSTIC_TYPES.get(phase, failure_type)
    return {"failurePhase": failure_phase, "failureType": failure_type,
            "regressionReference": regression_reference}


def record_failure(root: Path | str, context: Mapping[str, Any], result: Mapping[str, Any]) -> dict[str, Any]:
    """Persist a redacted immutable failure receipt and return its compact identity.

    Accepted context keys are ``tool``, ``action``, ``sourceSha``,
    ``sourceFingerprint``, ``artifactIds``, ``environmentAlias``, and
    ``operationCorrelation``.  Result accepts ``classification``, ``errorCategory``,
    ``before``, ``after``, ``observations``, and ``evidencePaths``.  Everything
    else is rejected instead of accidentally becoming durable evidence.
    """
    if os.name == "nt":
        raise NativeFailureEvidenceError("native failure evidence writes are unsupported on Windows without verified private-directory ACL admission")
    normalized = _normalize(context, result)
    encoded = _encode(normalized)
    fingerprint = hashlib.sha256(encoded).hexdigest()
    evidence_id = "native-failure-" + fingerprint[:32]
    directory = _prepare(root)
    path = directory / (evidence_id + ".json")
    receipt = {"schemaVersion": 1, "evidenceId": evidence_id, "fingerprint": fingerprint, **normalized}
    with _locked(directory):
        _cleanup(directory)
        if path.exists() or path.is_symlink():
            existing = _read(path)
            if existing != receipt:
                raise NativeFailureEvidenceError("failure evidence ID conflicts with existing receipt")
        else:
            _exclusive_write(path, _encode(receipt))
    return {"evidenceId": evidence_id, "evidencePath": str(path),
            "classification": normalized["classification"], "summaryCounts": normalized["summaryCounts"]}


def _normalize(context: Mapping[str, Any], result: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(context, Mapping) or not isinstance(result, Mapping):
        raise NativeFailureEvidenceError("failure context and result must be objects")
    context_allowed = {"tool", "action", "sourceSha", "sourceFingerprint", "artifactIds", "environmentAlias", "operationCorrelation"}
    result_allowed = {"classification", "errorCategory", "before", "after", "observations", "evidencePaths",
                      "failurePhase", "failureType", "regressionReference"}
    if set(context) - context_allowed or set(result) - result_allowed:
        raise NativeFailureEvidenceError("failure evidence contains unsupported fields")
    if "tool" not in context or "action" not in context:
        raise NativeFailureEvidenceError("failure context requires tool and action")
    classification = result.get("classification")
    if classification not in {"nativeUNKNOWN", "terminalFailure"}:
        raise NativeFailureEvidenceError("failure classification must be nativeUNKNOWN or terminalFailure")
    value: dict[str, Any] = {"tool": _token(context["tool"], "tool"), "action": _token(context["action"], "action"),
                             "classification": classification, "errorCategory": _token(result.get("errorCategory"), "error category")}
    detail_fields = {"failurePhase", "failureType", "regressionReference"}
    supplied_details = detail_fields & set(result)
    if supplied_details:
        if supplied_details != detail_fields:
            raise NativeFailureEvidenceError("failure detail is incomplete")
        expected = _allowed_failure_detail(context["action"], result["failurePhase"], result["failureType"],
                                           result["regressionReference"])
        if expected is None:
            raise NativeFailureEvidenceError("failure detail is invalid")
        value.update(expected)
    optional_tokens = {"environmentAlias": "environment alias", "operationCorrelation": "operation correlation"}
    for field, label in optional_tokens.items():
        if field in context:
            value[field] = _token(context[field], label)
    if "sourceSha" in context:
        if not isinstance(context["sourceSha"], str) or not _SHA.fullmatch(context["sourceSha"]):
            raise NativeFailureEvidenceError("source SHA is invalid")
        value["sourceSha"] = context["sourceSha"]
    if "sourceFingerprint" in context:
        value["sourceFingerprint"] = _hex(context["sourceFingerprint"], "source fingerprint")
    if "artifactIds" in context:
        ids = context["artifactIds"]
        if not isinstance(ids, list) or not 1 <= len(ids) <= _MAX_OBSERVATIONS:
            raise NativeFailureEvidenceError("artifact IDs are invalid")
        value["artifactIds"] = [_token(item, "artifact ID") for item in ids]
    for field in ("before", "after"):
        if field in result:
            value[field] = _observation(result[field], field)
    observations = result.get("observations", [])
    if not isinstance(observations, list) or len(observations) > _MAX_OBSERVATIONS:
        raise NativeFailureEvidenceError("observations are invalid")
    if observations:
        value["observations"] = [_observation(item, "observation") for item in observations]
    paths = result.get("evidencePaths", [])
    if not isinstance(paths, list) or len(paths) > _MAX_OBSERVATIONS:
        raise NativeFailureEvidenceError("evidence paths are invalid")
    if paths:
        value["evidencePaths"] = [_path(item) for item in paths]
    value["summaryCounts"] = {"before": int("before" in value), "after": int("after" in value),
                              "observations": len(value.get("observations", [])), "evidencePaths": len(value.get("evidencePaths", []))}
    return value


def _allowed_failure_detail(action: Any, failure_phase: Any, failure_type: Any,
                            regression_reference: Any) -> dict[str, str] | None:
    """Validate a detail independently of untrusted receipt input."""
    if not isinstance(action, str) or action not in _WINDOWS_FAILURE_DETAILS:
        return None
    phase, reference = _WINDOWS_FAILURE_DETAILS[action]
    allowed_types = {"outcome_unknown"}
    if action == "windows-fixture-stage-diagnostic":
        allowed_types.update(_FIXTURE_STAGE_DIAGNOSTIC_TYPES.values())
    if failure_phase != phase or failure_type not in allowed_types or regression_reference != reference:
        return None
    return {"failurePhase": phase, "failureType": failure_type, "regressionReference": reference}


def _observation(raw: Any, label: str) -> dict[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) - {"state", "category", "count", "evidenceId"} or not raw:
        raise NativeFailureEvidenceError(f"{label} is invalid")
    out: dict[str, Any] = {}
    if "state" in raw: out["state"] = _token(raw["state"], "observation state")
    if "category" in raw: out["category"] = _token(raw["category"], "observation category")
    if "evidenceId" in raw: out["evidenceId"] = _token(raw["evidenceId"], "observation evidence ID")
    if "count" in raw:
        if isinstance(raw["count"], bool) or not isinstance(raw["count"], int) or not 0 <= raw["count"] <= 1_000_000:
            raise NativeFailureEvidenceError("observation count is invalid")
        out["count"] = raw["count"]
    return out


def _path(raw: Any) -> str:
    # Evidence paths are opaque local identifiers, never URLs or command text.
    if not isinstance(raw, str) or len(raw) > 256 or not raw.startswith("/") or any(part in {"", ".", ".."} for part in raw.split("/")[1:]) or "://" in raw or "\x00" in raw:
        raise NativeFailureEvidenceError("evidence path is invalid")
    return raw


def _token(raw: Any, label: str) -> str:
    if not isinstance(raw, str) or not _TOKEN.fullmatch(raw):
        raise NativeFailureEvidenceError(f"{label} is invalid")
    return raw


def _hex(raw: Any, label: str) -> str:
    if not isinstance(raw, str) or not _HEX.fullmatch(raw): raise NativeFailureEvidenceError(f"{label} is invalid")
    return raw


def _prepare(root: Path | str) -> Path:
    root_path = Path(root)
    if not root_path.is_absolute() or not _directory(root_path):
        raise NativeFailureEvidenceError("failure evidence root must be an existing absolute non-symlink directory")
    root_path = root_path.resolve(strict=True)
    _private_directory(root_path / ".rag_index")
    directory = root_path / _RELATIVE
    _private_directory(directory)
    return directory


def _directory(path: Path) -> bool:
    try:
        info = path.lstat(); return not path.is_symlink() and stat.S_ISDIR(info.st_mode)
    except OSError: return False


def _private_directory(path: Path) -> None:
    try:
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid(): raise NativeFailureEvidenceError("failure evidence directory is unsafe")
        else: path.mkdir(mode=0o700)
        os.chmod(path, 0o700)
        if stat.S_IMODE(path.lstat().st_mode) != 0o700: raise NativeFailureEvidenceError("failure evidence directory is not private")
    except OSError as error: raise NativeFailureEvidenceError("failure evidence directory cannot be prepared") from error


@contextmanager
def _locked(directory: Path) -> Iterator[None]:
    try:
        import fcntl
        lock = directory / ".lock"; fd = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "r+b") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600: raise NativeFailureEvidenceError("failure evidence lock is unsafe")
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try: yield
            finally: fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
    except OSError as error: raise NativeFailureEvidenceError("failure evidence cannot be locked") from error


def _exclusive_write(path: Path, contents: bytes) -> None:
    temporary = path.with_name(".tmp-" + secrets.token_hex(16))
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream: stream.write(contents); stream.flush(); os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False); _fsync_directory(path.parent)
    except OSError as error: raise NativeFailureEvidenceError("failure evidence cannot be published") from error
    finally:
        try: temporary.unlink()
        except FileNotFoundError: pass
        except OSError: pass


def _read(path: Path) -> dict[str, Any]:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0));
        with os.fdopen(fd, "rb") as stream: info = os.fstat(stream.fileno()); raw = stream.read(_MAX_RECORD + 1)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or len(raw) > _MAX_RECORD: raise NativeFailureEvidenceError("failure evidence is corrupt")
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error: raise NativeFailureEvidenceError("failure evidence is corrupt") from error
    if not isinstance(value, dict): raise NativeFailureEvidenceError("failure evidence is corrupt")
    return value


def _cleanup(directory: Path) -> None:
    try:
        for item in directory.iterdir():
            if item.name.startswith(".tmp-"):
                info = item.lstat()
                if item.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid(): raise NativeFailureEvidenceError("failure evidence temporary file is unsafe")
                item.unlink()
    except OSError as error: raise NativeFailureEvidenceError("failure evidence temporary files cannot be cleaned") from error


def _fsync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try: os.fsync(fd)
    finally: os.close(fd)


def _encode(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")

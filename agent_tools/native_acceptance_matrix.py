"""Private, fail-closed native acceptance evidence matrix.

This module is intentionally only an evidence ledger and report builder.  It
hashes evidence and registered artifact bytes. It does not run a command,
contact a host, or infer a
native result from a build/component receipt.  Callers may record an explicitly
reviewed observation and later ask for a compact JSON/table status report.
"""
from __future__ import annotations

from contextlib import contextmanager
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
from typing import Any, Iterator, Mapping


REQUIREMENTS_PATH = Path(__file__).with_name("native_acceptance_requirements.json")
RECEIPTS_RELATIVE = Path(".rag_index") / "native-acceptance"
_SHA = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_ARTIFACT = re.compile(r"^sha256-[0-9a-f]{64}$")
_PLATFORMS = {"android", "linux", "windows", "macos", "cross-platform"}
_RESULTS = {"passed", "failed", "unknown"}
_SCOPES = {"full-native"}
_NEXT = {"none", "inspect-evidence", "collect-native-scenario", "rerun-required-scenario", "verify-artifact", "await-ci", "capture-visual-review"}
_MAX_RECORD = 16384


class NativeAcceptanceMatrixError(ValueError):
    """A requirements document, observation, or private receipt is unsafe."""


def load_requirements(path: Path | str = REQUIREMENTS_PATH) -> dict[str, dict[str, Any]]:
    """Load the tracked declarative requirement set without following receipts."""
    file_path = Path(path)
    try:
        raw = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeAcceptanceMatrixError("native acceptance requirements cannot be read") from error
    if not isinstance(raw, Mapping) or set(raw) != {"schemaVersion", "requirements"} or raw["schemaVersion"] != 1:
        raise NativeAcceptanceMatrixError("native acceptance requirements schema is invalid")
    requirements = raw["requirements"]
    if not isinstance(requirements, list) or not requirements:
        raise NativeAcceptanceMatrixError("native acceptance requirements are empty")
    normalized: dict[str, dict[str, Any]] = {}
    for value in requirements:
        item = _requirement(value)
        if item["requirementId"] in normalized:
            raise NativeAcceptanceMatrixError("native acceptance requirement IDs must be unique")
        normalized[item["requirementId"]] = item
    return normalized


def matrix_record(root: Path | str, observation: Mapping[str, Any], *, requirements_path: Path | str = REQUIREMENTS_PATH) -> dict[str, Any]:
    """Persist one reviewed full-native observation in private ignored storage.

    The receipt is immutable.  Exact duplicate observations are rejected. Distinct partial observations
    remain separate; conflicts cannot silently replace earlier evidence.
    """
    requirements = load_requirements(requirements_path)
    directory = _prepare_directory(root)
    item = _observation(root, observation, requirements)
    encoded = _encode(item)
    receipt_id = "native-acceptance-" + hashlib.sha256(encoded).hexdigest()[:32]
    path = directory / (receipt_id + ".json")
    with _locked(directory):
        _cleanup(directory)
        for existing_path in directory.glob("*.json"):
            existing = _read_receipt(existing_path, requirements)
            if _encode(existing) == _encode(item):
                raise NativeAcceptanceMatrixError("native acceptance observation is an exact duplicate")
        _exclusive_write(path, _encode({"schemaVersion": 1, "receiptId": receipt_id, **item}))
    return {"receiptId": receipt_id, "receiptPath": str(path), "historical": False,
            "requirementId": item["requirementId"], "result": item["result"]}


def matrix_status(root: Path | str, current_source_sha: str, *, requirements_path: Path | str = REQUIREMENTS_PATH) -> dict[str, Any]:
    """Return a compact machine-readable report and a human-readable table."""
    if not isinstance(current_source_sha, str) or not _SHA.fullmatch(current_source_sha):
        raise NativeAcceptanceMatrixError("current source SHA is invalid")
    requirements = load_requirements(requirements_path)
    directory = _existing_directory(root)
    records = [] if directory is None else _records_read_only(directory, requirements)
    for record in records:
        record["_verificationError"] = _verification_error(root, record)
    rows: list[dict[str, Any]] = []
    for requirement in requirements.values():
        matching = [record for record in records if record["requirementId"] == requirement["requirementId"]]
        row = _row(requirement, matching, current_source_sha)
        rows.append(row)
    summary = {state: sum(row["status"] == state for row in rows)
               for state in ("passed", "failed", "unknown", "historical", "conflicting", "open")}
    gate = "passed" if summary["passed"] == len(rows) else "open"
    return {"schemaVersion": 1, "currentSourceSHA": current_source_sha, "gate": gate,
            "summary": summary, "requirements": rows, "table": _table(rows)}


def _requirement(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"requirementId", "platform", "requiredScenarios", "description"}:
        raise NativeAcceptanceMatrixError("native acceptance requirement fields are invalid")
    requirement_id = _token(value["requirementId"], "requirement ID")
    platform = value["platform"]
    if platform not in _PLATFORMS:
        raise NativeAcceptanceMatrixError("native acceptance requirement platform is invalid")
    scenarios = value["requiredScenarios"]
    if not isinstance(scenarios, list) or not scenarios or len(scenarios) > 32:
        raise NativeAcceptanceMatrixError("native acceptance required scenarios are invalid")
    normalized_scenarios = [_token(item, "required scenario") for item in scenarios]
    if len(set(normalized_scenarios)) != len(normalized_scenarios):
        raise NativeAcceptanceMatrixError("native acceptance required scenarios must be unique")
    if not isinstance(value["description"], str) or not value["description"].strip() or len(value["description"]) > 240:
        raise NativeAcceptanceMatrixError("native acceptance requirement description is invalid")
    return {"requirementId": requirement_id, "platform": platform,
            "requiredScenarios": normalized_scenarios, "description": value["description"]}


def _observation(root: Path | str, value: Mapping[str, Any], requirements: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    normalized = _stored_observation(value, requirements)
    _verify_evidence(root, normalized["evidencePath"], normalized["evidenceHash"])
    _verify_artifacts(root, normalized["immutableArtifactIDs"], normalized["platform"], normalized["originalSourceSHA"])
    return normalized


def _stored_observation(value: Mapping[str, Any], requirements: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    fields = {"requirementId", "platform", "originalSourceSHA", "immutableArtifactIDs", "evidencePath", "evidenceHash", "environment", "result", "scenarioResults", "missingEvidence", "nextFixedCommand", "reviewerAttestation", "evidenceScope"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeAcceptanceMatrixError("native acceptance observation fields are invalid")
    requirement_id = _token(value["requirementId"], "requirement ID")
    requirement = requirements.get(requirement_id)
    if requirement is None or value["platform"] != requirement["platform"]:
        raise NativeAcceptanceMatrixError("native acceptance observation requirement/platform mismatch")
    if not isinstance(value["originalSourceSHA"], str) or not _SHA.fullmatch(value["originalSourceSHA"]):
        raise NativeAcceptanceMatrixError("native acceptance original source SHA is invalid")
    artifacts = value["immutableArtifactIDs"]
    if not isinstance(artifacts, list) or not artifacts or len(artifacts) > 16 or not all(isinstance(item, str) and _ARTIFACT.fullmatch(item) for item in artifacts):
        raise NativeAcceptanceMatrixError("native acceptance immutable artifact IDs are invalid")
    if len(set(artifacts)) != len(artifacts):
        raise NativeAcceptanceMatrixError("native acceptance immutable artifact IDs must be unique")
    evidence_path = _evidence_path(value["evidencePath"])
    if not isinstance(value["evidenceHash"], str) or not _HASH.fullmatch(value["evidenceHash"]):
        raise NativeAcceptanceMatrixError("native acceptance evidence hash is invalid")
    environment = _token(value["environment"], "environment")
    result = value["result"]
    if result not in _RESULTS:
        raise NativeAcceptanceMatrixError("native acceptance result is invalid")
    if value["evidenceScope"] not in {"full-native", "component", "limited"}:
        raise NativeAcceptanceMatrixError("native acceptance evidence scope is invalid")
    if value["nextFixedCommand"] not in _NEXT:
        raise NativeAcceptanceMatrixError("native acceptance next fixed command is invalid")
    if not isinstance(value["reviewerAttestation"], str) or not value["reviewerAttestation"].strip() or len(value["reviewerAttestation"]) > 240:
        raise NativeAcceptanceMatrixError("native acceptance reviewer attestation is invalid")
    results = value["scenarioResults"]
    if not isinstance(results, Mapping) or set(results) - set(requirement["requiredScenarios"]):
        raise NativeAcceptanceMatrixError("native acceptance scenario results are invalid")
    normalized_results: dict[str, str] = {}
    for scenario, state in results.items():
        if state not in _RESULTS:
            raise NativeAcceptanceMatrixError("native acceptance scenario result is invalid")
        normalized_results[scenario] = state
    missing = value["missingEvidence"]
    if not isinstance(missing, list) or len(missing) > 32:
        raise NativeAcceptanceMatrixError("native acceptance missing evidence is invalid")
    normalized_missing = [_token(item, "missing evidence") for item in missing]
    if len(set(normalized_missing)) != len(normalized_missing):
        raise NativeAcceptanceMatrixError("native acceptance missing evidence must be unique")
    return {"requirementId": requirement_id, "platform": requirement["platform"],
            "originalSourceSHA": value["originalSourceSHA"], "immutableArtifactIDs": artifacts,
            "evidencePath": evidence_path, "evidenceHash": value["evidenceHash"], "environment": environment,
            "result": result, "scenarioResults": normalized_results, "missingEvidence": normalized_missing,
            "nextFixedCommand": value["nextFixedCommand"], "reviewerAttestation": value["reviewerAttestation"],
            "evidenceScope": value["evidenceScope"]}


def _row(requirement: Mapping[str, Any], records: list[Mapping[str, Any]], current_source_sha: str) -> dict[str, Any]:
    current = [record for record in records if record["originalSourceSHA"] == current_source_sha]
    if not current:
        if records:
            return {"requirementId": requirement["requirementId"], "platform": requirement["platform"], "status": "historical",
                    "requiredScenarios": requirement["requiredScenarios"], "missingScenarios": requirement["requiredScenarios"],
                    "historicalReceiptCount": len(records), "reason": "only evidence from another source SHA is available",
                    "nextFixedCommand": "collect-native-scenario"}
        return {"requirementId": requirement["requirementId"], "platform": requirement["platform"], "status": "open",
                "requiredScenarios": requirement["requiredScenarios"], "missingScenarios": requirement["requiredScenarios"],
                "reason": "no reviewed full-native evidence", "nextFixedCommand": "collect-native-scenario"}
    verification_failures = [record["_verificationError"] for record in current if record.get("_verificationError")]
    verified_current = [record for record in current if not record.get("_verificationError")]
    states = {scenario: {record["scenarioResults"][scenario] for record in verified_current if scenario in record["scenarioResults"]}
              for scenario in requirement["requiredScenarios"]}
    conflicts = [scenario for scenario, values in states.items() if "passed" in values and ("failed" in values or "unknown" in values)]
    full = [record for record in verified_current if record["evidenceScope"] == "full-native"]
    full_states = {scenario: {record["scenarioResults"][scenario] for record in full if scenario in record["scenarioResults"]}
                   for scenario in requirement["requiredScenarios"]}
    missing_scenarios = [scenario for scenario, values in full_states.items() if values != {"passed"}]
    record = current[0]
    row = {"requirementId": requirement["requirementId"], "platform": requirement["platform"], "requiredScenarios": requirement["requiredScenarios"],
           "originalSourceSHA": record["originalSourceSHA"], "immutableArtifactIDs": record["immutableArtifactIDs"],
           "evidencePath": record["evidencePath"], "evidenceHash": record["evidenceHash"], "environment": record["environment"],
           "result": record["result"], "missingEvidence": record["missingEvidence"], "missingScenarios": missing_scenarios,
           "nextFixedCommand": record["nextFixedCommand"], "receiptCount": len(current), "conflictingScenarios": conflicts,
           "partialReceiptCount": len(current) - len(full), "verificationFailures": verification_failures}
    if verification_failures:
        row.update(status="unknown", reason="recorded evidence or registered artifacts no longer verify")
    elif conflicts or len({record["result"] for record in current}) > 1:
        row.update(status="conflicting", reason="current evidence observations conflict")
    elif any(record["result"] == "failed" for record in current):
        row.update(status="failed", reason="reviewed native evidence recorded a failure")
    elif any(record["result"] == "unknown" for record in current):
        row.update(status="unknown", reason="reviewed native evidence outcome is unknown")
    elif any(record["missingEvidence"] for record in full) or missing_scenarios:
        row.update(status="open", reason="required native scenarios or evidence are incomplete")
    else:
        row.update(status="passed", reason="reviewed full-native evidence covers current source")
    return row


def _evidence_path(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 256 or "\x00" in value or "://" in value:
        raise NativeAcceptanceMatrixError("native acceptance evidence path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or not value or any(part in {"", ".", ".."} for part in path.parts):
        raise NativeAcceptanceMatrixError("native acceptance evidence path is invalid")
    return value


def _verify_evidence(root: Path | str, relative_path: str, declared_hash: str) -> None:
    root_path = Path(root).resolve(strict=True)
    path = root_path.joinpath(*PurePosixPath(relative_path).parts)
    try:
        if not path.is_file() or path.is_symlink() or any(parent.is_symlink() for parent in [root_path.joinpath(*path.relative_to(root_path).parts[:index]) for index in range(1, len(path.relative_to(root_path).parts) + 1)]):
            raise NativeAcceptanceMatrixError("native acceptance evidence path is missing or unsafe")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        if digest.hexdigest() != declared_hash:
            raise NativeAcceptanceMatrixError("native acceptance evidence hash does not match current evidence bytes")
    except OSError as error:
        raise NativeAcceptanceMatrixError("native acceptance evidence path is missing or unsafe") from error


def _verify_artifacts(root: Path | str, artifact_ids: list[str], platform: str, source_sha: str) -> None:
    try:
        from agent_tools import native_artifact_registry as registry
    except ImportError:
        import native_artifact_registry as registry  # type: ignore[no-redef]
    platforms: set[str] = set()
    for artifact_id in artifact_ids:
        found = registry.find_artifacts(root, {"artifactId": artifact_id, "limit": 1})["matches"]
        if len(found) != 1 or found[0].get("sourceSha") != source_sha:
            raise NativeAcceptanceMatrixError("native acceptance artifact is not registered for the original source SHA")
        artifact_platform = found[0].get("platform")
        platforms.add(artifact_platform)
        if registry.verify_artifact(root, artifact_id).get("verification") != "verified":
            raise NativeAcceptanceMatrixError("native acceptance artifact bytes are not currently verified")
    expected = _PLATFORMS - {"cross-platform"} if platform == "cross-platform" else {platform}
    if platforms != expected:
        raise NativeAcceptanceMatrixError("native acceptance registered artifacts do not cover the requirement platform")


def _verification_error(root: Path | str, record: Mapping[str, Any]) -> str | None:
    try:
        _verify_evidence(root, record["evidencePath"], record["evidenceHash"])
        _verify_artifacts(root, record["immutableArtifactIDs"], record["platform"], record["originalSourceSHA"])
    except (NativeAcceptanceMatrixError, OSError, ValueError) as error:
        return str(error)
    return None


def _prepare_directory(root: Path | str) -> Path:
    root_path = Path(root)
    try:
        info = root_path.lstat()
        if not root_path.is_absolute() or root_path.is_symlink() or not stat.S_ISDIR(info.st_mode):
            raise NativeAcceptanceMatrixError("native acceptance root must be an absolute non-symlink directory")
        root_path = root_path.resolve(strict=True)
    except OSError as error:
        raise NativeAcceptanceMatrixError("native acceptance root is invalid") from error
    parent = root_path / ".rag_index"
    try:
        if not parent.exists():
            parent.mkdir(mode=0o700)
        info = parent.lstat()
        if parent.is_symlink() or not stat.S_ISDIR(info.st_mode):
            raise NativeAcceptanceMatrixError("native acceptance receipt parent is unsafe")
    except OSError as error:
        raise NativeAcceptanceMatrixError("native acceptance receipt parent cannot be prepared") from error
    directory = root_path / RECEIPTS_RELATIVE
    _private_directory(directory)
    return directory


def _existing_directory(root: Path | str) -> Path | None:
    """Return an existing private receipt store without creating status state."""
    root_path = Path(root)
    try:
        info = root_path.lstat()
        if not root_path.is_absolute() or root_path.is_symlink() or not stat.S_ISDIR(info.st_mode):
            raise NativeAcceptanceMatrixError("native acceptance root must be an absolute non-symlink directory")
        root_path = root_path.resolve(strict=True)
        parent = root_path / ".rag_index"
        if not parent.exists():
            return None
        info = parent.lstat()
        if parent.is_symlink() or not stat.S_ISDIR(info.st_mode):
            raise NativeAcceptanceMatrixError("native acceptance receipt parent is unsafe")
        directory = root_path / RECEIPTS_RELATIVE
        if not directory.exists():
            return None
        info = directory.lstat()
        if (directory.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
                stat.S_IMODE(info.st_mode) != 0o700):
            raise NativeAcceptanceMatrixError("native acceptance directory is unsafe")
        return directory
    except OSError as error:
        raise NativeAcceptanceMatrixError("native acceptance receipt store is unavailable or unsafe") from error


def _private_directory(path: Path) -> None:
    try:
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                raise NativeAcceptanceMatrixError("native acceptance directory is unsafe")
        else:
            path.mkdir(mode=0o700)
        if stat.S_IMODE(path.lstat().st_mode) != 0o700:
            raise NativeAcceptanceMatrixError("native acceptance directory is not private")
    except OSError as error:
        raise NativeAcceptanceMatrixError("native acceptance directory cannot be prepared") from error


@contextmanager
def _locked(directory: Path) -> Iterator[None]:
    try:
        import fcntl
        lock = directory / ".lock"
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "r+b") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
                raise NativeAcceptanceMatrixError("native acceptance lock is unsafe")
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try: yield
            finally: fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
    except OSError as error:
        raise NativeAcceptanceMatrixError("native acceptance receipt cannot be locked") from error


def _records_read_only(directory: Path, requirements: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Read atomically published immutable receipts without locking or cleanup."""
    try:
        paths = sorted(directory.glob("*.json"))
    except OSError as error:
        raise NativeAcceptanceMatrixError("native acceptance receipts cannot be listed") from error
    return [_read_receipt(path, requirements) for path in paths]


def _read_receipt(path: Path, requirements: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise NativeAcceptanceMatrixError("native acceptance receipt is unsafe")
            raw = stream.read(_MAX_RECORD + 1)
        if len(raw) > _MAX_RECORD:
            raise NativeAcceptanceMatrixError("native acceptance receipt is unsafe")
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeAcceptanceMatrixError("native acceptance receipt is corrupt") from error
    if not isinstance(value, Mapping) or value.get("schemaVersion") != 1:
        raise NativeAcceptanceMatrixError("native acceptance receipt is corrupt")
    fields = {"requirementId", "platform", "originalSourceSHA", "immutableArtifactIDs", "evidencePath", "evidenceHash", "environment", "result", "scenarioResults", "missingEvidence", "nextFixedCommand", "reviewerAttestation", "evidenceScope"}
    raw = {key: item for key, item in value.items() if key not in {"schemaVersion", "receiptId"}}
    if set(raw) != fields:
        raise NativeAcceptanceMatrixError("native acceptance receipt is corrupt")
    # Receipt loading validates its schema only; the bytes/artifacts were checked
    # at record time and a later change must be reported by explicit re-recording.
    normalized = _stored_observation(raw, requirements)
    if not isinstance(value["receiptId"], str) or not value["receiptId"].startswith("native-acceptance-"):
        raise NativeAcceptanceMatrixError("native acceptance receipt is corrupt")
    return normalized


def _cleanup(directory: Path) -> None:
    for path in directory.glob(".tmp-*"):
        try:
            info = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise NativeAcceptanceMatrixError("native acceptance temporary file is unsafe")
            path.unlink()
        except OSError as error:
            raise NativeAcceptanceMatrixError("native acceptance temporary files cannot be cleaned") from error


def _exclusive_write(path: Path, contents: bytes) -> None:
    temporary = path.with_name(".tmp-" + secrets.token_hex(16))
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(contents); stream.flush(); os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
        _fsync_directory(path.parent)
    except OSError as error:
        raise NativeAcceptanceMatrixError("native acceptance receipt cannot be published") from error
    finally:
        try: temporary.unlink()
        except FileNotFoundError: pass
        except OSError: pass


def _fsync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try: os.fsync(fd)
    finally: os.close(fd)


def _table(rows: list[Mapping[str, Any]]) -> str:
    lines = ["requirement | platform | status | missing scenarios | next action", "--- | --- | --- | --- | ---"]
    for row in rows:
        missing = ",".join(row["missingScenarios"]) or "-"
        lines.append(f"{row['requirementId']} | {row['platform']} | {row['status']} | {missing} | {row['nextFixedCommand']}")
    return "\n".join(lines)


def _token(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise NativeAcceptanceMatrixError(f"native acceptance {label} is invalid")
    return value


def _encode(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    """Expose fixed matrix-record and matrix-status data actions for MCP/CLI wiring."""
    parser = argparse.ArgumentParser(prog="native-acceptance-matrix")
    subparsers = parser.add_subparsers(dest="action", required=True)
    record = subparsers.add_parser("matrix-record")
    record.add_argument("--root", required=True)
    record.add_argument("--observation-file", required=True)
    record.add_argument("--requirements")
    status = subparsers.add_parser("matrix-status")
    status.add_argument("--root", required=True)
    status.add_argument("--current-source-sha", required=True)
    status.add_argument("--requirements")
    args = parser.parse_args(argv)
    requirements_path = args.requirements or REQUIREMENTS_PATH
    try:
        if args.action == "matrix-record":
            observation = json.loads(Path(args.observation_file).read_text(encoding="utf-8"))
            result = matrix_record(args.root, observation, requirements_path=requirements_path)
        else:
            result = matrix_status(args.root, args.current_source_sha, requirements_path=requirements_path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, NativeAcceptanceMatrixError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

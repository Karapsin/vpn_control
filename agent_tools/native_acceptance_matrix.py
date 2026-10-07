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
EQUIVALENCES_DIRECTORY = "equivalences"
_SHA = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_ARTIFACT = re.compile(r"^sha256-[0-9a-f]{64}$")
_RECEIPT_ID = re.compile(r"^native-acceptance-[0-9a-f]{32}$")
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
    # A record has no intrinsic current/historical status: that depends on the
    # checked-out source at status time. Preserve its original source identity.
    return {"receiptId": receipt_id, "receiptPath": str(path),
            "requirementId": item["requirementId"], "originalSourceSHA": item["originalSourceSHA"],
            "result": item["result"]}


def matrix_retract(root: Path | str, correction: Mapping[str, Any], *, requirements_path: Path | str = REQUIREMENTS_PATH) -> dict[str, Any]:
    """Publish one immutable reviewed correction without changing its receipt."""
    if not isinstance(correction, Mapping) or set(correction) != {"receiptId", "reason", "reviewer"}:
        raise NativeAcceptanceMatrixError("native acceptance retraction fields are invalid")
    receipt_id = correction["receiptId"]
    if not isinstance(receipt_id, str) or not _RECEIPT_ID.fullmatch(receipt_id):
        raise NativeAcceptanceMatrixError("native acceptance retraction receipt ID is invalid")
    for field in ("reason", "reviewer"):
        value = correction[field]
        if not isinstance(value, str) or not value.strip() or len(value) > (500 if field == "reason" else 240):
            raise NativeAcceptanceMatrixError(f"native acceptance retraction {field} is invalid")
    requirements = load_requirements(requirements_path)
    directory = _prepare_directory(root)
    with _locked(directory):
        _cleanup(directory)
        receipt_path = directory / (receipt_id + ".json")
        if not receipt_path.exists() or receipt_path.is_symlink():
            raise NativeAcceptanceMatrixError("native acceptance retraction references a foreign receipt")
        _read_receipt(receipt_path, requirements)
        original_hash = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
        retractions = directory / "retractions"
        _private_directory(retractions)
        path = retractions / ("retract-" + receipt_id + ".json")
        if path.exists() or path.is_symlink():
            raise NativeAcceptanceMatrixError("native acceptance receipt is already retracted")
        record = {"schemaVersion": 1, "receiptId": receipt_id, "originalReceiptSha256": original_hash,
                  "reason": correction["reason"], "reviewer": correction["reviewer"]}
        _exclusive_write(path, _encode(record))
    return {"receiptId": receipt_id, "retractionPath": str(path),
            "originalReceiptSha256": original_hash}


def matrix_equivalence_record(root: Path | str, value: Mapping[str, Any], *,
                              requirements_path: Path | str = REQUIREMENTS_PATH) -> dict[str, Any]:
    """Publish one reviewed, immutable committed-source equivalence link."""
    if not isinstance(value, Mapping) or set(value) != {"receiptId", "artifactSetId", "targetSourceSHA", "reviewerAttestation"}:
        raise NativeAcceptanceMatrixError("native acceptance equivalence fields are invalid")
    receipt_id = value["receiptId"]
    if not isinstance(receipt_id, str) or not _RECEIPT_ID.fullmatch(receipt_id):
        raise NativeAcceptanceMatrixError("native acceptance equivalence receipt ID is invalid")
    reviewer = value["reviewerAttestation"]
    if not isinstance(reviewer, str) or not reviewer.strip() or len(reviewer) > 240:
        raise NativeAcceptanceMatrixError("native acceptance equivalence reviewer is invalid")
    if not isinstance(value["artifactSetId"], str) or not _TOKEN.fullmatch(value["artifactSetId"]):
        raise NativeAcceptanceMatrixError("native acceptance equivalence artifact set is invalid")
    if not isinstance(value["targetSourceSHA"], str) or not _SHA.fullmatch(value["targetSourceSHA"]):
        raise NativeAcceptanceMatrixError("native acceptance equivalence target source is invalid")
    requirements = load_requirements(requirements_path)
    directory = _prepare_directory(root)
    with _locked(directory):
        receipt_path = directory / (receipt_id + ".json")
        receipt = _read_receipt(receipt_path, requirements)
        if (receipt["evidenceScope"] != "full-native" or receipt["result"] != "passed" or
                receipt["missingEvidence"] or set(receipt["scenarioResults"]) != set(requirements[receipt["requirementId"]]["requiredScenarios"]) or
                any(state != "passed" for state in receipt["scenarioResults"].values())):
            raise NativeAcceptanceMatrixError("only complete passed full-native receipts may be linked")
        _verify_evidence(root, receipt["evidencePath"], receipt["evidenceHash"])
        _verify_artifacts(root, receipt["immutableArtifactIDs"], receipt["platform"], receipt["originalSourceSHA"])
        for existing_path in directory.glob("native-acceptance-*.json"):
            existing = _read_receipt(existing_path, requirements)
            if existing["requirementId"] != receipt["requirementId"] or existing["originalSourceSHA"] != receipt["originalSourceSHA"]:
                continue
            if (existing["evidenceScope"] != "full-native" or existing["result"] != "passed" or existing["missingEvidence"] or
                    set(existing["scenarioResults"]) != set(requirements[existing["requirementId"]]["requiredScenarios"]) or
                    any(state != "passed" for state in existing["scenarioResults"].values())):
                raise NativeAcceptanceMatrixError("conflicting, partial, or unknown native evidence cannot be linked")
        try:
            from agent_tools import native_artifact_reuse as reuse
        except ImportError:
            import native_artifact_reuse as reuse  # type: ignore[no-redef]
        try:
            proof = reuse.acceptance_equivalence_check(root, value["artifactSetId"], receipt["originalSourceSHA"], value["targetSourceSHA"])
        except (reuse.ArtifactReuseError, OSError, ValueError) as error:
            raise NativeAcceptanceMatrixError("native acceptance equivalence is not verified") from error
        if proof["immutableArtifactIDs"] != receipt["immutableArtifactIDs"]:
            raise NativeAcceptanceMatrixError("native acceptance equivalence artifacts differ from receipt")
        receipt_hash = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
        body = {"schemaVersion": 1, "receiptId": receipt_id, "receiptSha256": receipt_hash,
                **proof, "reviewerAttestation": reviewer}
        link_id = "native-equivalence-" + hashlib.sha256(_encode(body)).hexdigest()[:32]
        links = directory / EQUIVALENCES_DIRECTORY
        _private_directory(links)
        path = links / (link_id + ".json")
        if path.exists() or path.is_symlink():
            raise NativeAcceptanceMatrixError("native acceptance equivalence is already recorded")
        _exclusive_write(path, _encode({"linkId": link_id, **body}))
    return {"linkId": link_id, "receiptId": receipt_id, "originalSourceSHA": receipt["originalSourceSHA"],
            "targetSourceSHA": proof["targetSourceSHA"], "requiredCurrentChecks": proof["requiredCurrentChecks"]}


def matrix_status(root: Path | str, current_source_sha: str, *, requirements_path: Path | str = REQUIREMENTS_PATH) -> dict[str, Any]:
    """Return a compact machine-readable report and a human-readable table."""
    if not isinstance(current_source_sha, str) or not _SHA.fullmatch(current_source_sha):
        raise NativeAcceptanceMatrixError("current source SHA is invalid")
    requirements = load_requirements(requirements_path)
    directory = _existing_directory(root)
    records = [] if directory is None else _records_read_only(directory, requirements)
    retracted = set() if directory is None else _read_retractions(directory, requirements)
    records = [record for record in records if record["receiptId"] not in retracted]
    links = [] if directory is None else _equivalences_read_only(directory, requirements, root, current_source_sha)
    by_receipt = {record["receiptId"]: record for record in records}
    for link in links:
        record = by_receipt.get(link["receiptId"])
        if record is not None:
            record["_equivalenceLink"] = link
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
            "summary": summary, "retractedCount": len(retracted),
            "retractedReceiptIds": sorted(retracted), "requirements": rows, "table": _table(rows)}


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
    current = [record for record in records if record["originalSourceSHA"] == current_source_sha or
               record.get("_equivalenceLink", {}).get("targetSourceSHA") == current_source_sha]
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
    link = record.get("_equivalenceLink")
    if isinstance(link, Mapping):
        row.update(equivalenceLinkId=link["linkId"], equivalentToSourceSHA=link["targetSourceSHA"],
                   requiredCurrentChecks=link["requiredCurrentChecks"])
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
        _verify_artifacts_readonly(root, record["immutableArtifactIDs"], record["platform"], record["originalSourceSHA"])
    except (NativeAcceptanceMatrixError, OSError, ValueError) as error:
        return str(error)
    return None


def _verify_artifacts_readonly(root: Path | str, artifact_ids: list[str], platform: str, source_sha: str) -> None:
    """Status-time artifact verification without registry housekeeping."""
    try:
        from agent_tools import native_artifact_registry as registry
    except ImportError:
        import native_artifact_registry as registry  # type: ignore[no-redef]
    platforms: set[str] = set()
    for artifact_id in artifact_ids:
        result = registry.verify_artifact_readonly(root, artifact_id)
        artifact = result.get("artifact")
        if not isinstance(artifact, Mapping) or artifact.get("sourceSha") != source_sha or result.get("verification") != "verified":
            raise NativeAcceptanceMatrixError("native acceptance artifact is not read-only verified for original source")
        platforms.add(artifact.get("platform"))
    expected = _PLATFORMS - {"cross-platform"} if platform == "cross-platform" else {platform}
    if platforms != expected:
        raise NativeAcceptanceMatrixError("native acceptance registered artifacts do not cover the requirement platform")


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
    return [{**_read_receipt(path, requirements), "receiptId": path.stem} for path in paths]


def _read_retractions(directory: Path, requirements: Mapping[str, Mapping[str, Any]]) -> set[str]:
    retractions = directory / "retractions"
    if not retractions.exists() and not retractions.is_symlink():
        return set()
    try:
        info = retractions.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
                stat.S_IMODE(info.st_mode) != 0o700):
            raise NativeAcceptanceMatrixError("native acceptance retraction directory is unsafe")
        paths = sorted(retractions.glob("*.json"))
    except OSError as error:
        raise NativeAcceptanceMatrixError("native acceptance retractions cannot be listed") from error
    found: set[str] = set()
    for path in paths:
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                    raise NativeAcceptanceMatrixError("native acceptance retraction is unsafe")
                raw = stream.read(_MAX_RECORD + 1)
            if len(raw) > _MAX_RECORD:
                raise NativeAcceptanceMatrixError("native acceptance retraction is unsafe")
            value = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise NativeAcceptanceMatrixError("native acceptance retraction is corrupt") from error
        if (not isinstance(value, Mapping) or set(value) !=
                {"schemaVersion", "receiptId", "originalReceiptSha256", "reason", "reviewer"} or
                value["schemaVersion"] != 1 or not isinstance(value["receiptId"], str) or
                not _RECEIPT_ID.fullmatch(value["receiptId"]) or
                path.name != "retract-" + value["receiptId"] + ".json" or
                not isinstance(value["originalReceiptSha256"], str) or
                not _HASH.fullmatch(value["originalReceiptSha256"])):
            raise NativeAcceptanceMatrixError("native acceptance retraction is corrupt")
        for field in ("reason", "reviewer"):
            if not isinstance(value[field], str) or not value[field].strip() or len(value[field]) > (500 if field == "reason" else 240):
                raise NativeAcceptanceMatrixError("native acceptance retraction is corrupt")
        receipt_path = directory / (value["receiptId"] + ".json")
        if not receipt_path.exists() or receipt_path.is_symlink():
            raise NativeAcceptanceMatrixError("native acceptance retraction references a foreign receipt")
        _read_receipt(receipt_path, requirements)
        if hashlib.sha256(receipt_path.read_bytes()).hexdigest() != value["originalReceiptSha256"]:
            raise NativeAcceptanceMatrixError("native acceptance retracted receipt changed")
        if value["receiptId"] in found:
            raise NativeAcceptanceMatrixError("native acceptance duplicate retraction")
        found.add(value["receiptId"])
    return found


def _read_receipt(path: Path, requirements: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise NativeAcceptanceMatrixError("native acceptance receipt is unsafe")
            raw = stream.read(_MAX_RECORD + 1)
            after = os.fstat(stream.fileno())
        named = path.lstat()
        if (info.st_nlink != 1 or not _same_generation(info, after) or not _same_generation(info, named) or
                len(raw) != info.st_size or len(raw) > _MAX_RECORD):
            raise NativeAcceptanceMatrixError("native acceptance receipt is unsafe")
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeAcceptanceMatrixError("native acceptance receipt is corrupt") from error
    if not isinstance(value, Mapping) or type(value.get("schemaVersion")) is not int or value.get("schemaVersion") != 1:
        raise NativeAcceptanceMatrixError("native acceptance receipt is corrupt")
    fields = {"requirementId", "platform", "originalSourceSHA", "immutableArtifactIDs", "evidencePath", "evidenceHash", "environment", "result", "scenarioResults", "missingEvidence", "nextFixedCommand", "reviewerAttestation", "evidenceScope"}
    raw = {key: item for key, item in value.items() if key not in {"schemaVersion", "receiptId"}}
    if set(raw) != fields:
        raise NativeAcceptanceMatrixError("native acceptance receipt is corrupt")
    # Receipt loading validates its schema only; the bytes/artifacts were checked
    # at record time and a later change must be reported by explicit re-recording.
    normalized = _stored_observation(raw, requirements)
    receipt_id = value.get("receiptId")
    if (not isinstance(receipt_id, str) or not _RECEIPT_ID.fullmatch(receipt_id) or
            path.name != receipt_id + ".json" or
            receipt_id != "native-acceptance-" + hashlib.sha256(_encode(normalized)).hexdigest()[:32]):
        raise NativeAcceptanceMatrixError("native acceptance receipt is corrupt")
    return normalized


def _equivalences_read_only(directory: Path, requirements: Mapping[str, Mapping[str, Any]],
                            root: Path | str, target_source_sha: str) -> list[dict[str, Any]]:
    """Load only links that still reproduce from committed Git and frozen bytes."""
    links = directory / EQUIVALENCES_DIRECTORY
    if not links.exists() and not links.is_symlink():
        return []
    try:
        info = links.lstat()
        if (links.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
                stat.S_IMODE(info.st_mode) != 0o700):
            raise NativeAcceptanceMatrixError("native acceptance equivalence directory is unsafe")
        paths = sorted(links.glob("native-equivalence-*.json"))
    except OSError as error:
        raise NativeAcceptanceMatrixError("native acceptance equivalences are unavailable") from error
    found = []
    directory_pin = _directory_pin(directory)
    links_pin = _directory_pin(links)
    for path in paths:
        link_pin = _file_pin(path)
        value = _read_private_link(path)
        _link_schema(value, path)
        link_digest = hashlib.sha256(_encode(value)).hexdigest()
        if value["targetSourceSHA"] != target_source_sha:
            continue
        receipt = directory / (value["receiptId"] + ".json")
        if not receipt.exists() or receipt.is_symlink():
            continue
        receipt_pin = _file_pin(receipt)
        if not _receipt_still_bound(receipt, value["receiptSha256"], directory, directory_pin, receipt_pin):
            continue
        observation = _read_receipt(receipt, requirements)
        if not _receipt_still_bound(receipt, value["receiptSha256"], directory, directory_pin, receipt_pin):
            continue
        if (observation["originalSourceSHA"] != value["originalSourceSHA"] or
                observation["immutableArtifactIDs"] != value["immutableArtifactIDs"] or
                observation["evidenceScope"] != "full-native" or observation["result"] != "passed" or
                observation["missingEvidence"] or set(observation["scenarioResults"]) != set(requirements[observation["requirementId"]]["requiredScenarios"]) or
                any(state != "passed" for state in observation["scenarioResults"].values())):
            continue
        try:
            _verify_evidence(root, observation["evidencePath"], observation["evidenceHash"])
        except NativeAcceptanceMatrixError:
            continue
        if not _receipt_still_bound(receipt, value["receiptSha256"], directory, directory_pin, receipt_pin):
            continue
        peers = [_read_receipt(item, requirements) for item in directory.glob("native-acceptance-*.json")]
        if any(peer["requirementId"] == observation["requirementId"] and
               peer["originalSourceSHA"] == observation["originalSourceSHA"] and
               (peer["evidenceScope"] != "full-native" or peer["result"] != "passed" or peer["missingEvidence"] or
                set(peer["scenarioResults"]) != set(requirements[peer["requirementId"]]["requiredScenarios"]) or
                any(state != "passed" for state in peer["scenarioResults"].values()))
               for peer in peers):
            continue
        if not _receipt_still_bound(receipt, value["receiptSha256"], directory, directory_pin, receipt_pin):
            continue
        try:
            from agent_tools import native_artifact_reuse as reuse
        except ImportError:
            import native_artifact_reuse as reuse  # type: ignore[no-redef]
        try:
            proof = reuse.acceptance_equivalence_check_readonly(root, value["artifactSetId"], value["originalSourceSHA"], target_source_sha)
        except (reuse.ArtifactReuseError, OSError, ValueError):
            continue
        expected = {key: value[key] for key in ("schemaVersion", "artifactSetId", "originalSourceSHA", "targetSourceSHA",
                                                 "immutableArtifactIDs", "productTreeSha256", "diffSha256", "changedPaths", "requiredCurrentChecks")}
        if proof != expected:
            continue
        if (not _receipt_still_bound(receipt, value["receiptSha256"], directory, directory_pin, receipt_pin) or
                not _link_still_bound(path, link_digest, links, links_pin, link_pin) or
                not _same_generation(_directory_pin(links), links_pin)):
            continue
        found.append(value)
    return found


def _read_private_link(path: Path) -> dict[str, Any]:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            raw = stream.read(_MAX_RECORD + 1)
            after = os.fstat(stream.fileno())
        named = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or
                len(raw) > _MAX_RECORD or len(raw) != info.st_size or not _same_generation(info, after) or not _same_generation(info, named)):
            raise NativeAcceptanceMatrixError("native acceptance equivalence is unsafe")
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, Mapping) or _encode(value) != raw:
            raise NativeAcceptanceMatrixError("native acceptance equivalence is noncanonical")
        return dict(value)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeAcceptanceMatrixError("native acceptance equivalence is corrupt") from error


def _link_schema(value: Any, path: Path) -> None:
    fields = {"linkId", "schemaVersion", "receiptId", "receiptSha256", "artifactSetId", "originalSourceSHA", "targetSourceSHA",
              "immutableArtifactIDs", "productTreeSha256", "diffSha256", "changedPaths", "requiredCurrentChecks", "reviewerAttestation"}
    if not isinstance(value, Mapping) or set(value) != fields or type(value.get("schemaVersion")) is not int or value.get("schemaVersion") != 1:
        raise NativeAcceptanceMatrixError("native acceptance equivalence is corrupt")
    if (not isinstance(value.get("linkId"), str) or not re.fullmatch(r"native-equivalence-[0-9a-f]{32}", value["linkId"]) or
            path.name != value["linkId"] + ".json" or not isinstance(value.get("receiptId"), str) or
            not _RECEIPT_ID.fullmatch(value["receiptId"]) or not isinstance(value.get("receiptSha256"), str) or
            not _HASH.fullmatch(value["receiptSha256"]) or not isinstance(value.get("artifactSetId"), str) or
            not _TOKEN.fullmatch(value["artifactSetId"]) or any(not isinstance(value.get(key), str) or not _SHA.fullmatch(value[key]) for key in ("originalSourceSHA", "targetSourceSHA")) or
            any(not isinstance(value.get(key), str) or not _HASH.fullmatch(value[key]) for key in ("productTreeSha256", "diffSha256")) or
            not isinstance(value.get("reviewerAttestation"), str) or not value["reviewerAttestation"].strip() or len(value["reviewerAttestation"]) > 240):
        raise NativeAcceptanceMatrixError("native acceptance equivalence is corrupt")
    artifacts = value.get("immutableArtifactIDs")
    if not isinstance(artifacts, list) or not artifacts or len(artifacts) > 16 or len(set(artifacts)) != len(artifacts) or not all(isinstance(item, str) and _ARTIFACT.fullmatch(item) for item in artifacts):
        raise NativeAcceptanceMatrixError("native acceptance equivalence is corrupt")
    paths = value.get("changedPaths")
    if (not isinstance(paths, list) or len(paths) > 512 or any(not isinstance(item, Mapping) or set(item) != {"status", "oldMode", "newMode", "path", "class"} or
            item.get("status") not in {"A", "M", "D"} or not isinstance(item.get("oldMode"), str) or not re.fullmatch(r"[0-7]{6}", item["oldMode"]) or
            not isinstance(item.get("newMode"), str) or not re.fullmatch(r"[0-7]{6}", item["newMode"]) or not isinstance(item.get("path"), str) or
            not item["path"] or item["path"].startswith("/") or any(part in {"", ".", ".."} for part in item["path"].split("/")) or
            item.get("class") not in {"docs", "test", "agent-tool"} for item in paths)):
        raise NativeAcceptanceMatrixError("native acceptance equivalence is corrupt")
    checks = value.get("requiredCurrentChecks")
    if not isinstance(checks, list) or not checks or len(checks) > 2 or checks[0] != "exact-sha-ci" or any(item not in {"exact-sha-ci", "changed-tool-tests"} for item in checks):
        raise NativeAcceptanceMatrixError("native acceptance equivalence is corrupt")
    body = {key: item for key, item in value.items() if key != "linkId"}
    if value["linkId"] != "native-equivalence-" + hashlib.sha256(_encode(body)).hexdigest()[:32]:
        raise NativeAcceptanceMatrixError("native acceptance equivalence is corrupt")


def _same_generation(first: os.stat_result, second: os.stat_result) -> bool:
    return (first.st_dev, first.st_ino, first.st_mode, first.st_uid, first.st_gid, first.st_nlink,
            first.st_size, first.st_mtime_ns, first.st_ctime_ns) == (
            second.st_dev, second.st_ino, second.st_mode, second.st_uid, second.st_gid, second.st_nlink,
            second.st_size, second.st_mtime_ns, second.st_ctime_ns)


def _directory_pin(path: Path) -> os.stat_result:
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise NativeAcceptanceMatrixError("native acceptance private directory changed")
    return info


def _file_pin(path: Path) -> os.stat_result:
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise NativeAcceptanceMatrixError("native acceptance immutable file changed")
    return info


def _receipt_still_bound(path: Path, expected_digest: str, parent: Path, parent_pin: os.stat_result,
                         original_pin: os.stat_result) -> bool:
    try:
        if not _same_generation(_directory_pin(parent), parent_pin):
            return False
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            raw = stream.read(_MAX_RECORD + 1)
            after = os.fstat(stream.fileno())
        named = path.lstat()
        return (_same_generation(before, original_pin) and _same_generation(before, after) and _same_generation(before, named) and
                len(raw) <= _MAX_RECORD and len(raw) == before.st_size and
                hashlib.sha256(raw).hexdigest() == expected_digest)
    except OSError:
        return False


def _link_still_bound(path: Path, expected_digest: str, parent: Path, parent_pin: os.stat_result,
                      original_pin: os.stat_result) -> bool:
    return _receipt_still_bound(path, expected_digest, parent, parent_pin, original_pin)


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
    """Expose fixed matrix record, retract and status actions for MCP/CLI wiring."""
    parser = argparse.ArgumentParser(prog="native-acceptance-matrix")
    subparsers = parser.add_subparsers(dest="action", required=True)
    record = subparsers.add_parser("matrix-record")
    record.add_argument("--root", required=True)
    record.add_argument("--observation-file", required=True)
    record.add_argument("--requirements")
    retract = subparsers.add_parser("matrix-retract")
    retract.add_argument("--root", required=True)
    retract.add_argument("--correction-file", required=True)
    retract.add_argument("--requirements")
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
        elif args.action == "matrix-retract":
            correction = json.loads(Path(args.correction_file).read_text(encoding="utf-8"))
            result = matrix_retract(args.root, correction, requirements_path=requirements_path)
        else:
            result = matrix_status(args.root, args.current_source_sha, requirements_path=requirements_path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, NativeAcceptanceMatrixError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

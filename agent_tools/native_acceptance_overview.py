"""Read-only summaries and bounded composition of existing native observations.

These helpers never start a native action.  A complete observation is still only
evidence for a human or a separately guarded native route, never admission.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Callable, Mapping


_SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_PLATFORMS = ("android", "linux", "windows", "macos")
_READS = {"environment-status", "linux-vm-readonly-inventory"}
_CORRELATION_READS = {
    "android": {"android-consent-acceptance-status"},
    "linux": {"linux-rpm-workspace-recovery-status", "linux-rpm-workspace-cleanup-status"},
    "windows": {"windows-msi-public-status"},
    "macos": set(),
}
_OWNER_READS = {
    "android": {"android-observe"},
    "linux": {"linux-rpm-owner-observe", "linux-owner-public-quit-status"},
    "windows": {"environment-status"},
    "macos": set(),
}


def checkout_state(root: Path) -> dict[str, bool]:
    """Observe tracked and untracked dirt without allowing Git's index refresh."""
    command = ["git", "--no-optional-locks", "-c", "core.fsmonitor=false",
               "-c", "core.untrackedCache=false", "status", "--porcelain=v1",
               "--untracked-files=normal"]
    completed = subprocess.run(command, cwd=root, env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               timeout=15, check=False)
    if completed.returncode != 0 or len(completed.stdout) > 1024 * 1024:
        raise ValueError("Read-only checkout status is unavailable.")
    dirty = bool(completed.stdout)
    return {"worktreeDirty": dirty, "checkoutExact": not dirty}


def read_artifact_index(root: Path, source: str, registry: Any) -> dict[str, Any]:
    """Read the immutable index without its normal lock/cleanup/create path."""
    if not isinstance(source, str) or not _SHA.fullmatch(source):
        raise ValueError("Artifact source is invalid.")
    owner_uid = getattr(os, "getuid", lambda: None)()
    if owner_uid is None:
        raise ValueError("Read-only artifact index requires owner identity.")
    for path in (root, root / ".rag_index", root / ".rag_index" / "native-artifacts"):
        try:
            info = path.lstat()
        except FileNotFoundError:
            if path != root:
                return {"matches": [], "records": {}}
            raise ValueError("Artifact root is unavailable.")
        if path.is_symlink() or not stat.S_ISDIR(info.st_mode):
            raise ValueError("Artifact index path is unsafe.")
        if path != root and (info.st_uid != owner_uid or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError("Artifact index ownership is uncertain.")
    index = root / ".rag_index" / "native-artifacts"
    entries = sorted(index.iterdir(), key=lambda path: path.name)
    if len(entries) > 1000:
        raise ValueError("Artifact index is too large for a bounded status view.")
    matches = []
    records: dict[str, dict[str, Any]] = {}
    for path in entries:
        if path.name == ".lock":
            continue
        if not re.fullmatch(r"sha256-[0-9a-f]{64}\.json", path.name):
            raise ValueError("Artifact index contains an incomplete or unsafe entry.")
        # The normal registry reader migrates schema 1 in place.  Refuse that
        # case before invoking it so this status view never performs a write.
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            raw = stream.read(registry.MAX_RECORD_BYTES + 1)
            after = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid or
                stat.S_IMODE(info.st_mode) != 0o600 or len(raw) > registry.MAX_RECORD_BYTES or
                (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or
                len(raw) != info.st_size):
            raise ValueError("Artifact index record is unsafe.")
        try:
            record = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError) as error:
            raise ValueError("Artifact index record is corrupt.") from error
        if not isinstance(record, dict) or record.get("schemaVersion") != 2:
            raise ValueError("Artifact index requires migration before read-only status.")
        allowed = {"schemaVersion", "artifactId", "platform", "artifactKind", "sha256", "size",
                   "sourceSha", "sourceFingerprint", "locations"}
        if (set(record) - allowed or
                record.get("artifactId") != path.stem or record.get("sha256") != path.stem[7:] or
                not isinstance(record.get("platform"), str) or record["platform"] not in _PLATFORMS):
            raise ValueError("Artifact index record identity is corrupt.")
        registry._identity(record)
        locations = record.get("locations")
        if not isinstance(locations, list) or not 1 <= len(locations) <= registry.MAX_LOCATIONS:
            raise ValueError("Artifact index locations are corrupt.")
        normalized = [registry._normalize_location(item) for item in locations]
        if len({item["locationId"] for item in normalized}) != len(normalized):
            raise ValueError("Artifact index locations conflict.")
        if record.get("sourceSha") == source:
            matches.append({"platform": record["platform"], "sourceSha": source,
                            "artifactKind": record["artifactKind"], "artifactId": record["artifactId"]})
            records[record["artifactId"]] = record
    return {"matches": matches, "records": records}


def verify_local_artifact_bytes(artifact_index: Mapping[str, Any], registry: Any) -> dict[str, str]:
    """Rehash a bounded current-source artifact set without the registry writer."""
    records = artifact_index.get("records")
    if not isinstance(records, Mapping) or len(records) > 32:
        raise ValueError("Current-source artifact set is unavailable or unbounded.")
    total = 0
    for record in records.values():
        if not isinstance(record, Mapping) or type(record.get("size")) is not int or not 0 < record["size"] <= 512 * 1024 * 1024:
            raise ValueError("Current-source artifact size is invalid or unbounded.")
    states: dict[str, str] = {}
    # Prioritize installed package inputs. Large source archives remain an
    # indexed claim so a status lookup never turns into an unbounded rebuild.
    ordered = sorted(records.items(), key=lambda pair:
                     (pair[1].get("artifactKind") not in {"package", "desktop-package", "native-fixture-apk"},
                      pair[0]))
    for identifier, record in ordered:
        if not isinstance(identifier, str) or not re.fullmatch(r"sha256-[0-9a-f]{64}", identifier):
            raise ValueError("Current-source artifact identity is invalid.")
        if total + record["size"] > 1024 * 1024 * 1024:
            states[identifier] = "registered-unverified"
            continue
        local = [location for location in record.get("locations", [])
                 if isinstance(location, Mapping) and location.get("evidenceClass") == "local-verified"]
        if len(local) != 1 or not isinstance(local[0].get("localPath"), str):
            states[identifier] = "registered-unverified"
            continue
        try:
            total += record["size"]
            size, digest = registry._stream_local_bytes(Path(local[0]["localPath"]))
            states[identifier] = ("verified-local-bytes" if size == record["size"] and
                                  digest == record.get("sha256") else "local-bytes-mismatch")
        except (ValueError, OSError):
            states[identifier] = "local-bytes-unavailable"
    return states


def discover_source_correlations(root: Path, source: str, artifact_index: Mapping[str, Any],
                                 android_document: Any, linux_cleanup: Any,
                                 linux_server: Any) -> dict[str, list[dict[str, str]]]:
    """List fixed private intents bound to current-source artifacts/journals.

    An intent is only a lookup key. A separate fresh status call must establish
    its operation state; neither this scan nor an intent alone claims success.
    """
    if not isinstance(source, str) or not _SHA.fullmatch(source):
        raise ValueError("Correlation source is invalid.")
    owner_uid = getattr(os, "getuid", lambda: None)()
    if owner_uid is None:
        raise ValueError("Private correlation discovery requires POSIX owner identity.")
    records = artifact_index.get("records")
    if not isinstance(records, Mapping):
        raise ValueError("Correlation artifact index is unavailable.")
    found: dict[str, list[dict[str, str]]] = {platform: [] for platform in _PLATFORMS}
    def entries(name: str) -> list[Path]:
        directory = root / ".rag_index" / name
        try:
            info = directory.lstat()
        except FileNotFoundError:
            return []
        if (directory.is_symlink() or not stat.S_ISDIR(info.st_mode) or
                info.st_uid != owner_uid or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError("Correlation intent directory is unsafe.")
        paths = sorted(directory.iterdir(), key=lambda item: item.name)
        if len(paths) > 32:
            raise ValueError("Correlation intent directory is too large.")
        safe: list[Path] = []
        for path in paths:
            if path.name == ".lock" or name == "android-document-jobs" and path.name.startswith(("lock-", "lease-")):
                continue
            if path.suffix != ".json" or not _UUID.fullmatch(path.stem):
                raise ValueError("Correlation intent entry is unexpected.")
            info = path.lstat()
            if (path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid or
                    stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 8192):
                raise ValueError("Correlation intent entry is unsafe.")
            safe.append(path)
        return safe
    for path in entries("android-document-jobs"):
        corr = path.stem
        intent = android_document._load(root, corr)
        if not isinstance(intent, Mapping) or intent.get("correlationId") != corr:
            continue
        artifact = records.get(intent.get("artifactId"))
        if (not isinstance(artifact, Mapping) or artifact.get("sourceSha") != source or
                artifact.get("platform") != "android" or
                intent.get("packageSha256") != artifact.get("sha256") or
                intent.get("device") not in {"api29", "api35"} or
                not isinstance(intent.get("cliStageCorrelationId"), str) or
                not isinstance(intent.get("openingReadbackCorrelationId"), str) or
                not isinstance(intent.get("backupSha256"), str)):
            continue
        found["android"].append({"correlationId": corr,
                                 "statusAction": "android-consent-acceptance-status",
                                 "sourceSha": source, "evidence": "source-bound-local-intent"})
    for path in entries("linux-rpm-workspace-cleanup"):
        corr = path.stem
        saved = linux_cleanup._read_cleanup_journal(linux_cleanup._cleanup_journal(root, corr))
        if not isinstance(saved, Mapping) or saved.get("cleanupCorrelationId") != corr:
            continue
        public = saved.get("correlationId")
        if not isinstance(public, str) or not _UUID.fullmatch(public):
            continue
        server = linux_server._journal(root, public)
        if (not isinstance(server, Mapping) or server.get("correlationId") != public or
                server.get("sourceSha") != source):
            continue
        found["linux"].append({"correlationId": corr,
                               "statusAction": "linux-rpm-workspace-cleanup-status",
                               "sourceSha": source, "evidence": "source-bound-local-intent"})
    return found


def read_macos_denial_summary(root: Path, source: str,
                              artifact_index: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Surface the fixed local Mac denial summary without treating it as live state."""
    if not isinstance(source, str) or not _SHA.fullmatch(source):
        raise ValueError("Mac summary source is invalid.")
    owner_uid = getattr(os, "getuid", lambda: None)()
    if owner_uid is None:
        raise ValueError("Mac summary discovery requires POSIX owner identity.")
    relative = (Path(".runtime/parity-evidence/continuation-macos") /
                ("fixture-" + source[:7]) / "native-machine-denial" /
                "reviewed-denial-summary.json")
    path = root / relative
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            return []
        if current.is_symlink() or not stat.S_ISDIR(info.st_mode):
            raise ValueError("Mac summary path is unsafe.")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return []
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        raw = stream.read(32769)
        after = os.fstat(stream.fileno())
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner_uid or before.st_nlink != 1 or
            not 0 < before.st_size <= 32768 or len(raw) != before.st_size or
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
        raise ValueError("Mac summary bytes are unsafe or changed.")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Mac summary is invalid.") from error
    records = artifact_index.get("records")
    if not isinstance(value, Mapping) or not isinstance(records, Mapping) or value.get("sourceSha") != source:
        return []
    base, target = value.get("baseArtifactId"), value.get("targetArtifactId")
    if (not isinstance(base, str) or not isinstance(target, str) or base == target or
            any(not isinstance(records.get(identifier), Mapping) or
                records[identifier].get("platform") != "macos" or
                records[identifier].get("sourceSha") != source for identifier in (base, target)) or
            value.get("finalPublicCode") != "CANCELLED" or value.get("installed") is not False or
            not isinstance(value.get("installOperationId"), str) or
            not _UUID.fullmatch(value["installOperationId"])):
        return []
    return [{"scenario": "machine-authorization-denial", "sourceSha": source,
             "correlationId": value["installOperationId"], "outcome": "cancelled",
             "artifactIds": [base, target], "evidencePath": relative.as_posix(),
             "evidenceSha256": hashlib.sha256(raw).hexdigest(),
             "evidence": "local-summary-not-matrix-reviewed", "liveOwnerVerified": False}]


def matrix_status_readonly(root: Path, source: str, matrix: Any, registry: Any,
                           artifact_index: Mapping[str, Any]) -> dict[str, Any]:
    """Build the canonical matrix rows without registry mutation or migration."""
    if not isinstance(source, str) or not _SHA.fullmatch(source):
        raise ValueError("Acceptance source is invalid.")
    requirements = matrix.load_requirements()
    directory = matrix._existing_directory(root)
    records = [] if directory is None else matrix._records_read_only(directory, requirements)
    retracted = set() if directory is None else matrix._read_retractions(directory, requirements)
    records = [record for record in records if record["receiptId"] not in retracted]
    indexed = artifact_index.get("records")
    if not isinstance(indexed, Mapping):
        raise ValueError("Read-only artifact index is incomplete.")
    for record in records:
        record["_verificationError"] = None
        if record["originalSourceSHA"] != source:
            continue
        try:
            matrix._verify_evidence(root, record["evidencePath"], record["evidenceHash"])
            platforms: set[str] = set()
            for identifier in record["immutableArtifactIDs"]:
                artifact = indexed.get(identifier)
                if not isinstance(artifact, Mapping) or artifact.get("sourceSha") != source:
                    raise ValueError("Native acceptance artifact is not indexed for current source.")
                platforms.add(artifact["platform"])
                local = [loc for loc in artifact["locations"] if loc["evidenceClass"] == "local-verified"]
                if len(local) != 1:
                    raise ValueError("Native acceptance artifact has no unique local location.")
                size, digest = registry._stream_local_bytes(Path(local[0]["localPath"]))
                if size != artifact["size"] or digest != artifact["sha256"]:
                    raise ValueError("Native acceptance artifact bytes changed.")
            expected = set(matrix._PLATFORMS) - {"cross-platform"} if record["platform"] == "cross-platform" else {record["platform"]}
            if platforms != expected:
                raise ValueError("Native acceptance artifact platform coverage is incomplete.")
        except (ValueError, OSError) as error:
            record["_verificationError"] = str(error)
    rows = [matrix._row(requirement, [record for record in records
                                     if record["requirementId"] == requirement["requirementId"]], source)
            for requirement in requirements.values()]
    summary = {state: sum(row["status"] == state for row in rows)
               for state in ("passed", "failed", "unknown", "historical", "conflicting", "open")}
    return {"schemaVersion": 1, "currentSourceSHA": source,
            "gate": "passed" if summary["passed"] == len(rows) else "open",
            "summary": summary, "retractedCount": len(retracted),
            "retractedReceiptIds": sorted(retracted), "requirements": rows}


def acceptance_status(matrix: Mapping[str, Any], request: Mapping[str, Any],
                      artifact_index: Mapping[str, Any] | None = None,
                      correlation_observer: Callable[[Mapping[str, Any], str, Mapping[str, Any]], Mapping[str, Any]] | None = None,
                      owner_observer: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
                      artifact_verification: Mapping[str, str] | None = None,
                      known_correlations: Mapping[str, list[dict[str, str]]] | None = None,
                      local_native_summaries: Mapping[str, list[dict[str, Any]]] | None = None) -> dict[str, Any]:
    if not isinstance(request, Mapping) or set(request) - {"sourceSha", "correlations", "ownerProbes"}:
        raise ValueError("Acceptance status accepts only sourceSha, correlations and ownerProbes.")
    source = matrix.get("currentSourceSHA")
    if not isinstance(source, str) or not _SHA.fullmatch(source) or request.get("sourceSha", source) != source:
        raise ValueError("Acceptance status source must be the current exact Git SHA.")
    correlations = request.get("correlations", [])
    if not isinstance(correlations, list) or len(correlations) > 4:
        raise ValueError("Acceptance correlations must be a bounded list.")
    correlation_requests: dict[tuple[str, str], Mapping[str, Any]] = {}
    explicit_platforms: set[str] = set()
    for item in correlations:
        if not isinstance(item, Mapping) or set(item) != {"platform", "correlationId", "statusAction"}:
            raise ValueError("Acceptance correlation fields are invalid.")
        platform, correlation = item["platform"], item["correlationId"]
        if (platform not in _PLATFORMS or platform in explicit_platforms or
                not isinstance(correlation, str) or not _UUID.fullmatch(correlation) or
                item["statusAction"] not in _CORRELATION_READS[platform]):
            raise ValueError("Acceptance correlation identity is invalid or repeated.")
        explicit_platforms.add(platform)
        correlation_requests[(platform, correlation)] = item
    for platform, known_items in (known_correlations or {}).items():
        if platform not in _PLATFORMS or not isinstance(known_items, list) or len(known_items) > 4:
            raise ValueError("Known current-source correlations are unbounded.")
        for item in known_items:
            if (not isinstance(item, Mapping) or item.get("sourceSha") != source or
                    not isinstance(item.get("correlationId"), str) or
                    not _UUID.fullmatch(item["correlationId"]) or
                    item.get("statusAction") not in _CORRELATION_READS[platform] or
                    item.get("evidence") != "source-bound-local-intent"):
                raise ValueError("Known correlation is not source-bound to a fixed status route.")
            key = (platform, item["correlationId"])
            correlation_requests.setdefault(key, {"platform": platform,
                "correlationId": item["correlationId"], "statusAction": item["statusAction"]})
    if len(correlation_requests) > 12:
        raise ValueError("Acceptance correlation observations are unbounded.")
    owners = request.get("ownerProbes", [])
    if not isinstance(owners, list) or len(owners) > 4:
        raise ValueError("Owner probes must be a bounded list.")
    owner_requests: dict[str, Mapping[str, Any]] = {}
    for item in owners:
        if not isinstance(item, Mapping) or set(item) != {"platform", "action", "inputs"}:
            raise ValueError("Owner probe fields are invalid.")
        platform = item["platform"]
        if (platform not in _PLATFORMS or platform in owner_requests or
                item["action"] not in _OWNER_READS[platform] or not isinstance(item["inputs"], dict)):
            raise ValueError("Owner probe is unsupported or repeated.")
        values = item["inputs"]
        if item["action"] == "android-observe":
            valid = (set(values) == {"host", "device", "timeoutSeconds"} and
                     values["host"] == "archlinux" and values["device"] in {"api29", "api35"} and
                     type(values["timeoutSeconds"]) is int and 1 <= values["timeoutSeconds"] <= 30)
        elif item["action"] == "linux-rpm-owner-observe":
            valid = (set(values) == {"host", "environment", "pid", "startTicks"} and
                     values["host"] == values["environment"] == "fedora2328" and
                     type(values["pid"]) is int and values["pid"] > 1 and
                     type(values["startTicks"]) is int and values["startTicks"] > 0)
        elif item["action"] == "linux-owner-public-quit-status":
            valid = (set(values) == {"correlationId"} and isinstance(values["correlationId"], str) and
                     _UUID.fullmatch(values["correlationId"]) is not None)
        else:
            valid = (set(values) == {"hostAlias", "observeHost", "vmIdentity", "timeoutSeconds"} and
                     values["hostAlias"] == "archlinux" and values["observeHost"] is True and
                     isinstance(values["vmIdentity"], dict) and type(values["timeoutSeconds"]) is int and
                     1 <= values["timeoutSeconds"] <= 30)
        if not valid:
            raise ValueError("Owner probe inputs are not fixed and bounded.")
        owner_requests[platform] = item
    observed_correlations: dict[str, list[Mapping[str, Any]]] = {}
    observed_owners: dict[str, Mapping[str, Any]] = {}
    def read_correlation(pair: tuple[str, Mapping[str, Any]]) -> tuple[str, Mapping[str, Any]]:
        platform, item = pair
        try:
            value = correlation_observer(item, source, artifact_index or {}) if correlation_observer else {}
            if (not isinstance(value, Mapping) or value.get("correlationId") != item["correlationId"] or
                    value.get("sourceSha") != source or value.get("state") != "verified" or
                    value.get("operationState") not in {"submitted", "running", "complete", "terminal", "observed"}):
                return platform, {}
            return platform, value
        except (ValueError, OSError, KeyError, TypeError):
            return platform, {}
    def read_owner(pair: tuple[str, Mapping[str, Any]]) -> tuple[str, Mapping[str, Any]]:
        platform, item = pair
        try:
            value = owner_observer(item) if owner_observer else {}
            if (not isinstance(value, Mapping) or value.get("state") not in {"running", "stopped"} or
                    value.get("evidenceScope") not in {"owner", "guest"} or
                    value.get("source") != "live-tool"):
                return platform, {}
            return platform, value
        except (ValueError, OSError, KeyError, TypeError):
            return platform, {}
    with ThreadPoolExecutor(max_workers=max(1, len(correlation_requests) + len(owner_requests))) as pool:
        futures = [pool.submit(read_correlation, (key[0], item))
                   for key, item in correlation_requests.items()]
        futures += [pool.submit(read_owner, pair) for pair in owner_requests.items()]
        for future in futures:
            platform, value = future.result()
            if "correlationId" in value:
                observed_correlations.setdefault(platform, []).append(value)
            elif platform in owner_requests and "evidenceScope" in value:
                observed_owners[platform] = value
    rows = matrix.get("requirements")
    if not isinstance(rows, list):
        raise ValueError("Acceptance matrix requirements are unavailable.")
    result = []
    for platform in _PLATFORMS:
        selected = [row for row in rows if isinstance(row, Mapping) and row.get("platform") == platform]
        if not selected:
            raise ValueError("Acceptance matrix lacks a platform.")
        reviewed = {artifact for row in selected if row.get("originalSourceSHA") == source
                    for artifact in row.get("immutableArtifactIDs", [])
                    if isinstance(artifact, str) and re.fullmatch(r"sha256-[0-9a-f]{64}", artifact)}
        registered = {item["artifactId"]: item.get("artifactKind")
                      for item in (artifact_index or {}).get("matches", [])
                      if isinstance(item, Mapping) and item.get("platform") == platform and
                      item.get("sourceSha") == source and isinstance(item.get("artifactId"), str) and
                      re.fullmatch(r"sha256-[0-9a-f]{64}", item["artifactId"])}
        artifacts = [{"sha256": identifier, "kind": registered.get(identifier),
                      "evidence": "reviewed-current-matrix" if identifier in reviewed else
                                  (artifact_verification or {}).get(identifier, "registered-unverified")}
                     for identifier in sorted(reviewed | registered.keys())]
        artifact_evidence = {item["evidence"] for item in artifacts}
        unmet = [{"requirementId": row.get("requirementId"), "status": row.get("status"),
                  "missingCount": len(row.get("missingScenarios", [])),
                  "nextFixedCommand": row.get("nextFixedCommand")}
                 for row in selected if row.get("status") != "passed"]
        observations = sorted(observed_correlations.get(platform, []), key=lambda item: item["correlationId"])
        active = [item for item in observations if item.get("operationState") in {"submitted", "running"}]
        observed = active[0] if len(active) == 1 else observations[0] if len(observations) == 1 else None
        owner = observed_owners.get(platform)
        if observed and owner and platform == "android":
            if (observed.get("deviceAlias") != owner.get("deviceAlias") or
                    observed.get("ownerIdentity") != owner.get("controllerId")):
                observed = None
                owner = None
        operation_state = observed.get("operationState") if observed else None
        result.append({"platform": platform, "sourceSha": source, "artifactHashes": artifacts,
                       "artifactEvidence": next(iter(artifact_evidence)) if len(artifact_evidence) == 1 else
                           "mixed" if artifact_evidence else "unknown",
                       "activeCorrelationId": observed["correlationId"] if observed and operation_state in {"submitted", "running"} else None,
                       "observedCorrelationId": observed["correlationId"] if observed else None,
                       "observedCorrelationIds": [item["correlationId"] for item in observations],
                       "correlationState": operation_state or "unknown",
                       "correlationEvidence": "verified-current-source-status" if observations else "unknown",
                       "correlationObservations": [{"correlationId": item["correlationId"],
                           "operationState": item["operationState"],
                           "evidence": "verified-current-source-status"} for item in observations],
                       "knownCorrelations": list((known_correlations or {}).get(platform, [])),
                       "localNativeSummaries": list((local_native_summaries or {}).get(platform, [])),
                       "ownerOrGuest": dict(owner) if owner else {"state": "unknown", "evidenceScope": "none"},
                       "ownerEvidence": "live-observer" if owner else "unknown",
                       "ownerSourceBinding": "verified-current-source-correlation"
                           if platform == "android" and observed and owner else "unknown",
                       "unmetGates": unmet})
    return {"state": "observed", "sourceSha": source, "matrixGate": matrix.get("gate"),
            "platforms": result, "nativeActionAllowed": False, "productAction": False}


def batch_preflight(request: Mapping[str, Any], dispatch: Callable[[str, dict[str, Any]], Mapping[str, Any]]) -> dict[str, Any]:
    if not isinstance(request, Mapping) or set(request) != {"reads"}:
        raise ValueError("VM preflight batch requires only reads.")
    reads = request["reads"]
    if not isinstance(reads, list) or not 1 <= len(reads) <= 4:
        raise ValueError("VM preflight batch requires one to four reads.")
    checked: list[tuple[str, str, dict[str, Any]]] = []
    ids: set[str] = set()
    for item in reads:
        if not isinstance(item, Mapping) or set(item) != {"id", "action", "inputs"}:
            raise ValueError("VM preflight read fields are invalid.")
        identifier, action, inputs = item["id"], item["action"], item["inputs"]
        if not isinstance(identifier, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", identifier) or identifier in ids:
            raise ValueError("VM preflight read ID is invalid or repeated.")
        if action not in _READS or not isinstance(inputs, dict):
            raise ValueError("VM preflight action is not a fixed read-only route.")
        if action == "linux-vm-readonly-inventory":
            if set(inputs) != {"host", "timeoutSeconds"} or inputs["host"] != "archlinux" or type(inputs["timeoutSeconds"]) is not int or not 1 <= inputs["timeoutSeconds"] <= 30:
                raise ValueError("Linux VM inventory fields are invalid.")
        else:
            if set(inputs) - {"hostAlias", "device", "jobIdentity", "artifactId", "locationId", "timeoutSeconds", "observations", "observeHost", "vmIdentity"} or not isinstance(inputs.get("hostAlias"), str):
                raise ValueError("Environment observation fields are invalid.")
            if type(inputs.get("timeoutSeconds", 30)) is not int or not 1 <= inputs.get("timeoutSeconds", 30) <= 30:
                raise ValueError("Environment observation timeout is invalid.")
        ids.add(identifier)
        checked.append((identifier, action, inputs))
    def observe(item: tuple[str, str, dict[str, Any]]) -> dict[str, Any]:
        identifier, action, inputs = item
        try:
            observation = dispatch(action, inputs)
            if (not isinstance(observation, Mapping) or observation.get("productAction") is True or
                    observation.get("nativeActionAllowed") is True):
                raise ValueError("Observation is unsafe or invalid.")
            if action == "environment-status":
                known = (observation.get("ok") is True and observation.get("state") == "READY" and
                         observation.get("source") == "live-tool" and observation.get("ready") is True)
            else:
                known = (observation.get("ok") is True and observation.get("inventoryComplete") is True and
                         observation.get("nativeActionAllowed") is False)
            return {"id": identifier, "action": action, "state": "observed" if known else "unknown",
                    "observation": dict(observation) if known else {"state": "unknown"}}
        except (ValueError, OSError, TypeError):
            return {"id": identifier, "action": action, "state": "unknown",
                    "observation": {"state": "unknown"}}
    with ThreadPoolExecutor(max_workers=len(checked)) as pool:
        results = list(pool.map(observe, checked))
    complete = all(item["state"] == "observed" for item in results)
    return {"state": "observed" if complete else "unknown", "observationsComplete": complete,
            "reads": results, "nativeActionAllowed": False, "productAction": False}

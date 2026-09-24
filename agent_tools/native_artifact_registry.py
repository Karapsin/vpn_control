"""Private, immutable byte-identity registry for native build artifacts.

The registry is deliberately local-only.  It indexes an explicitly supplied
artifact; it never searches a machine, contacts a host, downloads a file, or
executes a native action.  An index entry is historical evidence.  Call
``verify_artifact`` when a current local-byte assertion is required.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
from typing import Any, Iterator, Mapping

try:  # POSIX is the supported coordinator environment; keep import errors clear.
    import fcntl
except ImportError:  # pragma: no cover - exercised only on unsupported hosts.
    fcntl = None  # type: ignore[assignment]


INDEX_RELATIVE = Path(".rag_index") / "native-artifacts"
MAX_RECORD_BYTES = 8192
MAX_RESULTS = 100
DEFAULT_LIMIT = 20
MAX_LOCATIONS = 16
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_SHA = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_REMOTE_PATH = re.compile(r"^/[A-Za-z0-9._/@+=:,~-]+$")
_LOCAL_EVIDENCE = "local-verified"
_REMOTE_EVIDENCE = "unverified-remote"


class NativeArtifactRegistryError(ValueError):
    """An artifact record or private index is unsafe, malformed, or conflicted."""


def register_artifact(root: Path | str, record: Mapping[str, Any]) -> dict[str, Any]:
    """Verify supplied local bytes once and atomically register immutable evidence.

    Local records require ``localPath``, ``sha256``, ``size`` and evidence class
    ``local-verified``.  Remote evidence is metadata only and must use
    ``unverified-remote`` with ``hostAlias``, ``remotePath`` and a caller supplied
    receipt.  It is intentionally never verified through this API.
    """
    _require_posix_private_admission()
    identity, location = _normalize_registration(record)
    if location["evidenceClass"] == _LOCAL_EVIDENCE:
        size, digest = _stream_local_bytes(Path(location["localPath"]))
        if size != identity["size"] or digest != identity["sha256"]:
            raise NativeArtifactRegistryError("Artifact bytes do not match the declared size and SHA-256.")
    registry = _prepare_registry(root)
    artifact_id = "sha256-" + identity["sha256"]
    path = registry / (artifact_id + ".json")
    with _locked(registry):
        _cleanup_temporary(registry)
        if path.exists() or path.is_symlink():
            existing = _read_record(path)
            if _identity(existing) != identity:
                raise NativeArtifactRegistryError("Artifact ID already exists with conflicting immutable evidence.")
            locations = existing["locations"]
            matching = next((item for item in locations if item["locationId"] == location["locationId"]), None)
            if matching is not None:
                if matching != location:
                    raise NativeArtifactRegistryError("Artifact location ID already exists with conflicting immutable evidence.")
                return _public_record(existing)
            if len(locations) >= MAX_LOCATIONS:
                raise NativeArtifactRegistryError("Artifact has reached the bounded location evidence limit.")
            stored = {**existing, "locations": [*locations, location]}
            _atomic_replace(path, _bounded_encoded(stored))
            return _public_record(stored)
        stored = {"schemaVersion": 2, "artifactId": artifact_id, **identity, "locations": [location]}
        _exclusive_write(path, _bounded_encoded(stored))
    return _public_record(stored)


def find_artifacts(root: Path | str, query: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Return bounded historical index matches without reading artifact bytes."""
    registry = _prepare_registry(root)
    filters, limit = _normalize_query(query)
    matches: list[dict[str, Any]] = []
    with _locked(registry):
        _cleanup_temporary(registry)
        try:
            entries = sorted(registry.iterdir(), key=lambda item: item.name)
        except OSError as error:
            raise NativeArtifactRegistryError("Artifact index cannot be read.") from error
        for entry in entries:
            if entry.name == ".lock":
                continue
            if not entry.name.endswith(".json"):
                raise NativeArtifactRegistryError("Artifact index contains an unexpected entry.")
            record = _read_record(entry)
            if _matches(record, filters):
                matches.append(_public_record(record))
                if len(matches) >= limit:
                    break
    return {"matches": matches, "limit": limit, "historical": True}


def verify_artifact(root: Path | str, artifact_id: str, location_id: str | None = None) -> dict[str, Any]:
    """Re-read a registered local file, distinguishing stale evidence from history."""
    registry = _prepare_registry(root)
    if not isinstance(artifact_id, str) or not re.fullmatch(r"sha256-[0-9a-f]{64}", artifact_id):
        raise NativeArtifactRegistryError("Artifact ID is invalid.")
    with _locked(registry):
        _cleanup_temporary(registry)
        record = _read_record(registry / (artifact_id + ".json"))
    public = _public_record(record)
    if location_id is not None and (not isinstance(location_id, str) or not re.fullmatch(r"location-[0-9a-f]{64}", location_id)):
        raise NativeArtifactRegistryError("Artifact location ID is invalid.")
    locations = record["locations"]
    if location_id is None:
        locals_ = [item for item in locations if item["evidenceClass"] == _LOCAL_EVIDENCE]
        if len(locals_) == 1:
            location = locals_[0]
        elif len(locals_) > 1:
            raise NativeArtifactRegistryError("Artifact has multiple local locations; locationId is required.")
        elif len(locations) == 1:
            location = locations[0]
        else:
            raise NativeArtifactRegistryError("Artifact has no unique default location; locationId is required.")
    else:
        location = next((item for item in locations if item["locationId"] == location_id), None)
        if location is None:
            raise NativeArtifactRegistryError("Artifact location ID is not registered.")
    if location["evidenceClass"] == _REMOTE_EVIDENCE:
        return {"artifact": public, "location": _public_location(location), "verification": "unverified-remote",
                "message": "Remote evidence is historical and was not contacted."}
    try:
        size, digest = _stream_local_bytes(Path(location["localPath"]))
    except NativeArtifactRegistryError as error:
        return {"artifact": public, "location": _public_location(location), "verification": "missing-or-unsafe", "message": str(error)}
    if size != record["size"] or digest != record["sha256"]:
        return {"artifact": public, "location": _public_location(location), "verification": "mismatch", "observedSize": size, "observedSha256": digest}
    return {"artifact": public, "location": _public_location(location), "verification": "verified", "observedSize": size, "observedSha256": digest}


def _normalize_registration(value: Mapping[str, Any], *, historical: bool = False) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(value, Mapping):
        raise NativeArtifactRegistryError("Artifact record must be an object.")
    aliases = {"path": "localPath", "artifactKind": "artifactKind", "evidence": "evidenceClass"}
    raw = {aliases.get(str(key), str(key)): item for key, item in value.items()}
    allowed = {"platform", "artifactKind", "localPath", "sha256", "size", "evidenceClass",
               "sourceSha", "sourceFingerprint", "hostAlias", "remotePath", "receipt"}
    if set(raw) - allowed:
        raise NativeArtifactRegistryError("Artifact record has unsupported fields.")
    for field in ("platform", "artifactKind", "sha256", "size", "evidenceClass"):
        if field not in raw:
            raise NativeArtifactRegistryError(f"Artifact record is missing {field}.")
    identity: dict[str, Any] = {
        "platform": _token(raw["platform"], "platform"),
        "artifactKind": _token(raw["artifactKind"], "artifact kind"),
        "sha256": _sha256(raw["sha256"], "SHA-256"),
        "size": _size(raw["size"]),
    }
    if raw.get("evidenceClass") not in {_LOCAL_EVIDENCE, _REMOTE_EVIDENCE}:
        raise NativeArtifactRegistryError("Artifact evidence class is not approved.")
    if "sourceSha" in raw:
        source = raw["sourceSha"]
        if not isinstance(source, str) or not _SOURCE_SHA.fullmatch(source):
            raise NativeArtifactRegistryError("Source SHA must be an exact lowercase Git SHA.")
        identity["sourceSha"] = source
    if "sourceFingerprint" in raw:
        identity["sourceFingerprint"] = _sha256(raw["sourceFingerprint"], "source fingerprint")
    location: dict[str, Any] = {"evidenceClass": raw["evidenceClass"]}
    if raw["evidenceClass"] == _LOCAL_EVIDENCE:
        if set(raw) - {"platform", "artifactKind", "localPath", "sha256", "size", "evidenceClass", "sourceSha", "sourceFingerprint"}:
            raise NativeArtifactRegistryError("Local evidence cannot include remote location fields.")
        location["localPath"] = (_historical_absolute_path(raw.get("localPath"), "local artifact path")
                                 if historical else _safe_absolute_path(raw.get("localPath"), "local artifact path"))
    else:
        if set(raw) - {"platform", "artifactKind", "sha256", "size", "evidenceClass", "sourceSha", "sourceFingerprint", "hostAlias", "remotePath", "receipt"}:
            raise NativeArtifactRegistryError("Remote evidence fields are invalid.")
        location["hostAlias"] = _token(raw.get("hostAlias"), "host alias")
        remote_path = raw.get("remotePath")
        if not isinstance(remote_path, str) or not _REMOTE_PATH.fullmatch(remote_path) or "//" in remote_path or "/../" in remote_path or remote_path.endswith("/.."):
            raise NativeArtifactRegistryError("Remote artifact path is invalid.")
        location["remotePath"] = str(PurePosixPath(remote_path))
        receipt = raw.get("receipt")
        if not isinstance(receipt, str) or not _TOKEN.fullmatch(receipt):
            raise NativeArtifactRegistryError("Remote evidence requires a bounded opaque receipt.")
        location["receipt"] = receipt
    location["locationId"] = "location-" + hashlib.sha256(_encode(location)).hexdigest()
    return identity, location


def _normalize_query(query: Mapping[str, Any] | None) -> tuple[dict[str, Any], int]:
    if query is None:
        return {}, DEFAULT_LIMIT
    if not isinstance(query, Mapping):
        raise NativeArtifactRegistryError("Artifact query must be an object.")
    allowed = {"artifactId", "platform", "artifactKind", "evidenceClass", "sourceSha", "sourceFingerprint", "locationId", "limit"}
    if set(query) - allowed:
        raise NativeArtifactRegistryError("Artifact query has unsupported fields.")
    limit = query.get("limit", DEFAULT_LIMIT)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_RESULTS:
        raise NativeArtifactRegistryError("Artifact query limit must be between 1 and 100.")
    filters: dict[str, Any] = {}
    for field in ("platform", "artifactKind"):
        if field in query:
            filters[field] = _token(query[field], field)
    if "evidenceClass" in query:
        if query["evidenceClass"] not in {_LOCAL_EVIDENCE, _REMOTE_EVIDENCE}:
            raise NativeArtifactRegistryError("Artifact evidence class is not approved.")
        filters["evidenceClass"] = query["evidenceClass"]
    if "sourceSha" in query:
        source = query["sourceSha"]
        if not isinstance(source, str) or not _SOURCE_SHA.fullmatch(source):
            raise NativeArtifactRegistryError("Source SHA must be an exact lowercase Git SHA.")
        filters["sourceSha"] = source
    if "sourceFingerprint" in query:
        filters["sourceFingerprint"] = _sha256(query["sourceFingerprint"], "source fingerprint")
    if "artifactId" in query:
        artifact_id = query["artifactId"]
        if not isinstance(artifact_id, str) or not re.fullmatch(r"sha256-[0-9a-f]{64}", artifact_id):
            raise NativeArtifactRegistryError("Artifact ID is invalid.")
        filters["artifactId"] = artifact_id
    if "locationId" in query:
        location_id = query["locationId"]
        if not isinstance(location_id, str) or not re.fullmatch(r"location-[0-9a-f]{64}", location_id):
            raise NativeArtifactRegistryError("Artifact location ID is invalid.")
        filters["locationId"] = location_id
    return filters, limit


def _prepare_registry(root: Path | str) -> Path:
    _require_posix_private_admission()
    root_path = Path(root)
    if not root_path.is_absolute() or not _safe_directory(root_path):
        raise NativeArtifactRegistryError("Registry root must be an existing absolute non-symlink directory.")
    root_path = root_path.resolve(strict=True)
    index = root_path / INDEX_RELATIVE
    _ensure_private_directory(root_path / ".rag_index")
    _ensure_private_directory(index)
    return index


def _require_posix_private_admission() -> None:
    if os.name == "nt":
        raise NativeArtifactRegistryError(
            "Native artifact registry mutation is unsupported on Windows without verified private-directory ACL admission."
        )


def _ensure_private_directory(path: Path) -> None:
    try:
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or not _owner_is_current(info):
                raise NativeArtifactRegistryError("Artifact index directory is unsafe.")
        else:
            try:
                path.mkdir(mode=0o700)
            except FileExistsError:
                # A concurrent first-use creator still has to pass the private
                # ownership/mode validation below.
                pass
        os.chmod(path, 0o700)
        info = path.lstat()
        if stat.S_IMODE(info.st_mode) != 0o700:
            raise NativeArtifactRegistryError("Artifact index directory is not private.")
    except OSError as error:
        raise NativeArtifactRegistryError("Artifact index directory cannot be prepared.") from error


@contextmanager
def _locked(registry: Path) -> Iterator[None]:
    if fcntl is None:  # pragma: no cover - protected by POSIX-only admission.
        raise NativeArtifactRegistryError("Artifact registry requires POSIX file locking.")
    lock = registry / ".lock"
    try:
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "r+b") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
                raise NativeArtifactRegistryError("Artifact index lock is unsafe.")
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except OSError as error:
        raise NativeArtifactRegistryError("Artifact index cannot be locked.") from error


def _exclusive_write(path: Path, contents: bytes) -> None:
    temporary = path.with_name(".tmp-" + str(os.getpid()) + "-" + secrets.token_hex(12))
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as target:
            target.write(contents); target.flush(); os.fsync(target.fileno())
        # link(2) is an atomic no-overwrite publish operation.  A crash can leave
        # only the ignored temporary file, never a partial final record.
        os.link(temporary, path, follow_symlinks=False)
        _fsync_parent(path.parent)
    except FileExistsError as error:
        raise NativeArtifactRegistryError("Artifact ID already exists.") from error
    except OSError as error:
        raise NativeArtifactRegistryError("Artifact record cannot be written.") from error
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass


def _atomic_replace(path: Path, contents: bytes) -> None:
    temporary = path.with_name(".tmp-" + str(os.getpid()) + "-" + secrets.token_hex(12))
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as target:
            target.write(contents); target.flush(); os.fsync(target.fileno())
        os.replace(temporary, path)
        _fsync_parent(path.parent)
    except OSError as error:
        raise NativeArtifactRegistryError("Artifact record cannot be atomically updated.") from error
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass


def _cleanup_temporary(registry: Path) -> None:
    """Interrupted writes leave no index entry; discard their private staging file."""
    try:
        for entry in registry.iterdir():
            if not entry.name.startswith(".tmp-"):
                continue
            info = entry.lstat()
            if entry.is_symlink() or not stat.S_ISREG(info.st_mode) or not _owner_is_current(info):
                raise NativeArtifactRegistryError("Artifact index temporary record is unsafe.")
            entry.unlink()
    except OSError as error:
        raise NativeArtifactRegistryError("Artifact index temporary records cannot be cleaned.") from error


def _read_record(path: Path) -> dict[str, Any]:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            raw = source.read(MAX_RECORD_BYTES + 1)
        if not stat.S_ISREG(info.st_mode) or len(raw) > MAX_RECORD_BYTES:
            raise NativeArtifactRegistryError("Artifact index record is unsafe or oversized.")
        parsed = json.loads(raw.decode("utf-8"))
    except FileNotFoundError as error:
        raise NativeArtifactRegistryError("Artifact ID is not registered.") from error
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeArtifactRegistryError("Artifact index record is corrupt.") from error
    if not isinstance(parsed, dict) or not isinstance(parsed.get("artifactId"), str):
        raise NativeArtifactRegistryError("Artifact index record is corrupt.")
    if parsed.get("schemaVersion") == 1:
        # A schema-1 record has exactly one location.  Validate it through the
        # current input parser before replacing it under the caller's lock.
        candidate = {key: value for key, value in parsed.items() if key not in {"schemaVersion", "artifactId"}}
        try:
            identity, location = _normalize_registration(candidate, historical=True)
        except NativeArtifactRegistryError as error:
            raise NativeArtifactRegistryError("Artifact index record is corrupt.") from error
        expected = "sha256-" + identity["sha256"]
        migrated = {"schemaVersion": 2, "artifactId": expected, **identity, "locations": [location]}
        if parsed["artifactId"] != expected or path.name != expected + ".json":
            raise NativeArtifactRegistryError("Artifact index record identity is corrupt.")
        _atomic_replace(path, _bounded_encoded(migrated))
        return migrated
    if parsed.get("schemaVersion") != 2:
        raise NativeArtifactRegistryError("Artifact index record is corrupt.")
    allowed = {"schemaVersion", "artifactId", "platform", "artifactKind", "sha256", "size",
               "sourceSha", "sourceFingerprint", "locations"}
    if set(parsed) - allowed or not {"platform", "artifactKind", "sha256", "size", "locations"} <= set(parsed):
        raise NativeArtifactRegistryError("Artifact index record is corrupt.")
    identity = _identity(parsed)
    locations = parsed.get("locations")
    if not isinstance(locations, list) or not 1 <= len(locations) <= MAX_LOCATIONS:
        raise NativeArtifactRegistryError("Artifact index record is corrupt.")
    try:
        rebuilt_locations = [_normalize_location(item) for item in locations]
    except NativeArtifactRegistryError as error:
        raise NativeArtifactRegistryError("Artifact index record is corrupt.") from error
    if len({item["locationId"] for item in rebuilt_locations}) != len(rebuilt_locations):
        raise NativeArtifactRegistryError("Artifact index record has duplicate locations.")
    expected = "sha256-" + identity["sha256"]
    if parsed["artifactId"] != expected or path.name != expected + ".json":
        raise NativeArtifactRegistryError("Artifact index record identity is corrupt.")
    return {"schemaVersion": 2, "artifactId": expected, **identity, "locations": rebuilt_locations}


def _stream_local_bytes(path: Path) -> tuple[int, str]:
    _safe_absolute_path(path, "local artifact path")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise NativeArtifactRegistryError("Local artifact must be a regular file.")
            digest = hashlib.sha256(); size = 0
            while chunk := source.read(1024 * 1024):
                size += len(chunk); digest.update(chunk)
            after = os.fstat(source.fileno())
        if not _same_file_snapshot(before, after) or size != before.st_size:
            raise NativeArtifactRegistryError("Local artifact changed while it was verified.")
        return size, digest.hexdigest()
    except OSError as error:
        raise NativeArtifactRegistryError("Local artifact cannot be read safely.") from error


def _safe_absolute_path(value: Any, label: str) -> str:
    if not isinstance(value, (str, Path)):
        raise NativeArtifactRegistryError(f"{label} must be an absolute path.")
    path = Path(value)
    try:
        info = path.lstat()
    except OSError:
        info = None
    if not path.is_absolute() or info is None or path.is_symlink() or stat.S_ISLNK(info.st_mode):
        raise NativeArtifactRegistryError(f"{label} is missing, unsafe, or contains a symlink.")
    return str(path.resolve(strict=True))


def _historical_absolute_path(value: Any, label: str) -> str:
    """Validate stored syntax without asserting that historical bytes still exist."""
    if not isinstance(value, str):
        raise NativeArtifactRegistryError(f"{label} must be an absolute path.")
    path = Path(value)
    if not path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts[1:]):
        raise NativeArtifactRegistryError(f"{label} is invalid.")
    return value


def _same_file_snapshot(before: os.stat_result, after: os.stat_result) -> bool:
    return (before.st_dev == after.st_dev and before.st_ino == after.st_ino and before.st_size == after.st_size and
            before.st_mtime_ns == after.st_mtime_ns and before.st_ctime_ns == after.st_ctime_ns)


def _safe_path_components(path: Path) -> bool:
    current = Path(path.anchor)
    try:
        for part in path.parts[1:]:
            current /= part
            info = current.lstat()
            if current.is_symlink() or stat.S_ISLNK(info.st_mode):
                return False
    except OSError:
        return False
    return True


def _safe_directory(path: Path) -> bool:
    try:
        info = path.lstat()
        return not path.is_symlink() and stat.S_ISDIR(info.st_mode)
    except OSError:
        return False


def _owner_is_current(info: os.stat_result) -> bool:
    return info.st_uid == os.getuid()


def _fsync_parent(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        raise


def _token(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise NativeArtifactRegistryError(f"Artifact {label} is invalid.")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise NativeArtifactRegistryError(f"Artifact {label} is invalid.")
    return value


def _size(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > 2**63 - 1:
        raise NativeArtifactRegistryError("Artifact size is invalid.")
    return value


def _identity(record: Mapping[str, Any]) -> dict[str, Any]:
    candidate = {key: record.get(key) for key in ("platform", "artifactKind", "sha256", "size")}
    if "sourceSha" in record:
        candidate["sourceSha"] = record["sourceSha"]
    if "sourceFingerprint" in record:
        candidate["sourceFingerprint"] = record["sourceFingerprint"]
    # Reuse validation without accepting a malformed location from disk.
    try:
        identity, _ = _normalize_registration({**candidate, "evidenceClass": _REMOTE_EVIDENCE,
                                                "hostAlias": "validation", "remotePath": "/record",
                                                "receipt": "validation"})
    except NativeArtifactRegistryError as error:
        raise NativeArtifactRegistryError("Artifact index record is corrupt.") from error
    return identity


def _normalize_location(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise NativeArtifactRegistryError("Artifact location is invalid.")
    evidence = value.get("evidenceClass")
    if evidence == _LOCAL_EVIDENCE:
        if set(value) != {"locationId", "evidenceClass", "localPath"}:
            raise NativeArtifactRegistryError("Artifact local location fields are invalid.")
        location = {"evidenceClass": evidence,
                    "localPath": _historical_absolute_path(value.get("localPath"), "local artifact path")}
    elif evidence == _REMOTE_EVIDENCE:
        if set(value) != {"locationId", "evidenceClass", "hostAlias", "remotePath", "receipt"}:
            raise NativeArtifactRegistryError("Artifact remote location fields are invalid.")
        _, built = _normalize_registration({"platform": "validation", "artifactKind": "validation",
                                                "sha256": "0" * 64, "size": 0,
                                                "evidenceClass": evidence, "hostAlias": value.get("hostAlias"),
                                                "remotePath": value.get("remotePath"), "receipt": value.get("receipt")})
        location = {key: item for key, item in built.items() if key != "locationId"}
    else:
        raise NativeArtifactRegistryError("Artifact evidence class is not approved.")
    expected = "location-" + hashlib.sha256(_encode(location)).hexdigest()
    if value.get("locationId") != expected:
        raise NativeArtifactRegistryError("Artifact location identity is corrupt.")
    return {"locationId": expected, **location}


def _matches(record: Mapping[str, Any], filters: Mapping[str, Any]) -> bool:
    for key, value in filters.items():
        if key in {"evidenceClass", "locationId"}:
            if not any(location.get(key) == value for location in record["locations"]):
                return False
        elif record.get(key) != value:
            return False
    return True


def _encode(record: Mapping[str, Any]) -> bytes:
    return (json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def _bounded_encoded(record: Mapping[str, Any]) -> bytes:
    encoded = _encode(record)
    if len(encoded) > MAX_RECORD_BYTES:
        raise NativeArtifactRegistryError("Artifact record exceeds the bounded index entry size.")
    return encoded


def _public_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """Bounded inventory summary including only explicitly registered locations."""
    result = {key: value for key, value in record.items() if key not in {"schemaVersion", "locations"}}
    result["locations"] = [_public_location(location) for location in record["locations"]]
    return result


def _public_location(location: Mapping[str, Any]) -> dict[str, Any]:
    return dict(location)

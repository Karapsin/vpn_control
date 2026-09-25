"""Conservative, content-bound evidence for reusing registered native packages.

A reuse decision never changes an artifact's original source identity.  It is a
local decision only; CI must still verify the current commit's exact SHA.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Callable, Mapping

try:
    from . import native_artifact_registry as registry
except ImportError:  # MCP server script-style import
    import native_artifact_registry as registry  # type: ignore[no-redef]


class ArtifactReuseError(ValueError):
    """The proposed artifact set has incomplete or unsafe evidence."""


_SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_ALLOWED_PREFIXES = ("docs/", "agent_docs/", "tests/")
_FORBIDDEN = ("package", "packaging", "release", "native", "runtime", "workflow", "build", "gradle", "fixture")


def artifact_set_freeze(root: str | Path, value: Mapping[str, Any]) -> dict[str, Any]:
    """Bind currently verified local packages to the checked-out source and inputs.

    ``value`` has exactly ``sourceSha``, ``packages``, ``runtimePaths`` and
    ``provenance``.  Runtime paths are explicit repository-relative regular files;
    their bytes, not caller digests, are captured.  Provenance contains an
    attested architecture and either an unsigned signer or a hashed certificate.
    """
    root = _root(root)
    _fields(value, {"sourceSha", "packages", "runtimePaths", "provenance"})
    source = _sha(value["sourceSha"], "sourceSha")
    if _head(root) != source:
        raise ArtifactReuseError("sourceSha must be the checked-out HEAD commit")
    _require_clean_product(root)
    packages = _packages(root, value["packages"], source)
    inputs = _current_inputs(root, source, value["runtimePaths"], value["provenance"])
    record = {"schemaVersion": 1, "sourceSha": source, "productInputs": inputs, "packages": packages}
    frozen = {"artifactSetId": _set_id(record), **record}
    _store_set(root, frozen)
    return frozen


def artifact_set_verify(root: str | Path, artifact_set: str | Mapping[str, Any]) -> dict[str, Any]:
    """Re-read all package and runtime bytes and check immutable set identity."""
    root = _root(root)
    try:
        artifact_set = _load_set(root, artifact_set)
        _fields(artifact_set, {"artifactSetId", "schemaVersion", "sourceSha", "productInputs", "packages"})
        if artifact_set["schemaVersion"] != 1 or artifact_set["artifactSetId"] != _set_id(
                {key: artifact_set[key] for key in ("schemaVersion", "sourceSha", "productInputs", "packages")}):
            raise ArtifactReuseError("artifact set identity is invalid")
        source = _sha(artifact_set["sourceSha"], "sourceSha")
        inputs = artifact_set["productInputs"]
        _fields(inputs, {"buildManifestSha256", "runtimeFiles", "version", "provenance"})
        _digest(inputs["buildManifestSha256"])
        _version(inputs["version"])
        _validate_provenance(root, inputs["provenance"], verify_only=True)
        packages = artifact_set["packages"]
        if not isinstance(packages, list) or not packages or packages != sorted(packages, key=lambda p: p["artifactId"]):
            raise ArtifactReuseError("package list is invalid")
        _mixed(packages)
        checked = []
        for package in packages:
            _fields(package, {"artifactId", "locationId", "artifactKind", "platform", "sha256", "size", "sourceSha"})
            result = registry.verify_artifact(root, package["artifactId"], package["locationId"])
            artifact = result["artifact"]
            expected = {key: artifact[key] for key in ("artifactKind", "platform", "sha256", "size", "sourceSha")}
            if result["verification"] != "verified" or artifact["sourceSha"] != source or any(
                    package[key] != expected[key] for key in expected):
                raise ArtifactReuseError("registered package bytes or identity changed")
            checked.append({"artifactId": package["artifactId"], "verification": "verified"})
        runtime = inputs["runtimeFiles"]
        if not isinstance(runtime, list) or not runtime or runtime != sorted(runtime, key=lambda p: p["path"]):
            raise ArtifactReuseError("runtime file list is invalid")
        if _runtime_files(root, [item["path"] for item in runtime]) != runtime:
            raise ArtifactReuseError("runtime bytes changed")
        if _provenance(root, inputs["provenance"], verify_only=True) != inputs["provenance"]:
            raise ArtifactReuseError("signer bytes changed")
    except (ArtifactReuseError, registry.NativeArtifactRegistryError, KeyError, TypeError, ValueError, OSError) as error:
        return {"verification": "mismatch", "reason": str(error)}
    return {"verification": "verified", "packages": checked, "originalSourceSha": source}


def artifact_reuse_check(root: str | Path, value: Mapping[str, Any], *,
                         inspectors: Mapping[str, Callable[[Path, Mapping[str, Any]], Mapping[str, Any]]] | None = None) -> dict[str, Any]:
    """Allow a frozen set only when current Git changes are strictly safe docs/tests."""
    root = _root(root)
    _fields(value, {"artifactSetId"})
    frozen = _load_set(root, value["artifactSetId"])
    verified = artifact_set_verify(root, frozen)
    current = _head(root)
    original = frozen.get("sourceSha") if isinstance(frozen, Mapping) else None
    reasons: list[str] = []
    if verified["verification"] != "verified":
        reasons.append("artifact set or current bytes are not verified")
    try:
        _sha(original, "artifact set sourceSha")
        _require_clean_product(root)
        changed = _changed_paths(root, original, current)
        if changed is None or any(not _safe_doc_test_path(p) for p in changed):
            reasons.append("commit diff is not strictly docs/test-only")
        elif any(_git_mode(root, sha, p) == "120000" for sha in (original, current) for p in changed):
            reasons.append("changed docs/test path is a symlink")
        if verified["verification"] == "verified":
            actual = _current_inputs(root, current, [p["path"] for p in frozen["productInputs"]["runtimeFiles"]],
                                     frozen["productInputs"]["provenance"])
            if actual != frozen["productInputs"]:
                reasons.append("product inputs differ")
    except (ArtifactReuseError, registry.NativeArtifactRegistryError, KeyError, TypeError, OSError) as error:
        reasons.append(str(error))
    decision = "rebuild-required" if reasons else ("same-source" if current == original else "verified-equivalent-product-inputs")
    missing_checks: list[str] = []
    input_record = frozen.get("productInputs")
    provenance = input_record.get("provenance", {}) if isinstance(input_record, Mapping) else {}
    package_list = frozen.get("packages", []) if verified["verification"] == "verified" else []
    if verified["verification"] != "verified":
        missing_checks.append("artifact set verification")
    for package in package_list:
        inspector = (inspectors or {}).get(package["artifactKind"])
        if inspector is None or verified["verification"] != "verified":
            missing_checks.append(package["artifactKind"] + ": native signer/architecture inspection")
            continue
        try:
            inspected = inspector(root, package)
            if not isinstance(inspected, Mapping) or inspected.get("verified") is not True or inspected.get("architecture") != provenance.get("architecture") or inspected.get("signer") != provenance.get("signer"):
                missing_checks.append(package["artifactKind"] + ": native signer/architecture mismatch")
        except Exception:
            missing_checks.append(package["artifactKind"] + ": native signer/architecture inspection failed")
    return {"decision": decision, "reasons": reasons, "verification": verified["verification"],
            "originalSourceSha": original, "currentSourceSha": current,
            "attestation": provenance, "nativeAdmissionReady": not missing_checks,
            "missingChecks": missing_checks, "ciRequired": True}


def _root(root: str | Path) -> Path:
    path = Path(root)
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise ArtifactReuseError("root must be an absolute non-symlink directory")
    return path.resolve(strict=True)


def _fields(value: Any, keys: set[str]) -> None:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ArtifactReuseError("expected exactly: " + ", ".join(sorted(keys)))


def _sha(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ArtifactReuseError(field + " must be a full lowercase Git SHA")
    return value


def _digest(value: Any) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ArtifactReuseError("SHA-256 is invalid")
    return value


def _version(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"(?:[1-9]|1[0-9])\.(?:[0-9]|1[0-9])\.(?:[0-9]|1[0-9])", value):
        raise ArtifactReuseError("product version is invalid")
    return value


def _git(root: Path, *args: str) -> bytes:
    result = subprocess.run(["git", *args], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise ArtifactReuseError("Git evidence unavailable: " + " ".join(args[:2]))
    return result.stdout


def _head(root: Path) -> str:
    top = Path(_git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    if top != root:
        raise ArtifactReuseError("root must be the Git worktree top level")
    return _sha(_git(root, "rev-parse", "--verify", "HEAD^{commit}").decode().strip(), "HEAD")


def _safe_doc_test_path(path: str) -> bool:
    if not path or path.startswith("/") or any(part in {"", ".", ".."} for part in path.split("/")):
        return False
    if path == "README.md":
        return True
    if not path.startswith(_ALLOWED_PREFIXES):
        return False
    return not any(word in path.lower() for word in _FORBIDDEN)


def _changed_paths(root: Path, before: str, after: str) -> list[str] | None:
    try:
        for sha in (before, after):
            _git(root, "cat-file", "-e", sha + "^{commit}")
        raw = _git(root, "diff", "--no-renames", "--name-only", "-z", before, after)
        return [p.decode("utf-8") for p in raw.split(b"\0") if p]
    except (ArtifactReuseError, UnicodeDecodeError):
        return None


def _dirty_paths(root: Path) -> list[str]:
    paths: set[str] = set()
    for args in (("diff", "--no-renames", "--name-only", "-z", "HEAD"),
                 ("ls-files", "--others", "--exclude-standard", "-z")):
        for part in _git(root, *args).split(b"\0"):
            if part:
                try:
                    paths.add(part.decode("utf-8"))
                except UnicodeDecodeError as error:
                    raise ArtifactReuseError("non-UTF-8 worktree path") from error
    return sorted(paths)


def _require_clean_product(root: Path) -> None:
    if any(not _safe_doc_test_path(p) and not p.startswith(".rag_index/") for p in _dirty_paths(root)):
        raise ArtifactReuseError("working tree has dirty product or unknown paths")


def _git_mode(root: Path, sha: str, path: str) -> str | None:
    raw = _git(root, "ls-tree", "-z", sha, "--", path)
    for item in raw.split(b"\0"):
        if item and item.split(b"\t", 1)[1].decode("utf-8") == path:
            return item.split(b" ", 1)[0].decode("ascii")
    return None


def _build_manifest(root: Path, source: str) -> str:
    raw = _git(root, "ls-tree", "-r", "-z", source)
    entries = []
    for item in raw.split(b"\0"):
        if not item:
            continue
        metadata, name = item.split(b"\t", 1)
        path = name.decode("utf-8")
        if not _safe_doc_test_path(path):
            entries.append([path, *metadata.decode("ascii").split(" ")])
    return hashlib.sha256(_encode(entries)).hexdigest()


def _safe_file(root: Path, name: Any) -> Path:
    if not isinstance(name, str) or not name or name.startswith("/") or any(p in {"", ".", ".."} for p in name.split("/")):
        raise ArtifactReuseError("input path must be repository-relative")
    path = root / name
    if not path.is_file() or not registry._safe_path_components(path):
        raise ArtifactReuseError("input file is missing, non-regular, or symlinked")
    return path


def _runtime_files(root: Path, paths: Any) -> list[dict[str, Any]]:
    if (not isinstance(paths, list) or not paths or len(paths) > 64 or
            any(not isinstance(p, str) for p in paths) or len(set(paths)) != len(paths)):
        raise ArtifactReuseError("runtimePaths must be a unique non-empty list of at most 64 paths")
    result = []
    for name in paths:
        path = _safe_file(root, name)
        size, digest = registry._stream_local_bytes(path)
        result.append({"path": name, "size": size, "sha256": digest})
    return sorted(result, key=lambda p: p["path"])


def _provenance(root: Path, value: Any, *, verify_only: bool = False) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not isinstance(value.get("architecture"), str) or not _TOKEN.fullmatch(value["architecture"]):
        raise ArtifactReuseError("architecture attestation is required")
    signer = value.get("signer")
    if not isinstance(signer, Mapping):
        raise ArtifactReuseError("signer attestation is required")
    if signer.get("kind") == "unsigned":
        _fields(signer, {"kind"})
        result_signer = {"kind": "unsigned"}
    elif signer.get("kind") == "certificate":
        if verify_only:
            _fields(signer, {"kind", "path", "sha256"})
        else:
            _fields(signer, {"kind", "path"})
        _, digest = registry._stream_local_bytes(_safe_file(root, signer["path"]))
        result_signer = {"kind": "certificate", "path": signer["path"], "sha256": digest}
    else:
        raise ArtifactReuseError("signer must be unsigned or a certificate path")
    result = {"architecture": value["architecture"], "signer": result_signer}
    if verify_only:
        _fields(value, {"architecture", "signer", "evidenceClass"})
        if value["evidenceClass"] != "attested-metadata":
            raise ArtifactReuseError("provenance evidence class is invalid")
    else:
        _fields(value, {"architecture", "signer"})
    return {**result, "evidenceClass": "attested-metadata"}


def _validate_provenance(root: Path, value: Any, *, verify_only: bool = False) -> None:
    _provenance(root, value, verify_only=verify_only)


def _current_inputs(root: Path, source: str, runtime_paths: Any, provenance: Any) -> dict[str, Any]:
    version_file = _safe_file(root, "gradle.properties")
    versions = re.findall(r"^vpnControlVersion=(.+)$", version_file.read_text(encoding="utf-8"), re.M)
    if len(versions) != 1:
        raise ArtifactReuseError("canonical product version unavailable")
    return {"buildManifestSha256": _build_manifest(root, source), "runtimeFiles": _runtime_files(root, runtime_paths),
            "version": _version(versions[0]), "provenance": _provenance(root, provenance,
            verify_only=isinstance(provenance, Mapping) and provenance.get("evidenceClass") == "attested-metadata")}


def _packages(root: Path, references: Any, source: str) -> list[dict[str, Any]]:
    if not isinstance(references, list) or not references or len(references) > 16:
        raise ArtifactReuseError("packages must be a non-empty list of at most 16 references")
    frozen = []
    for reference in references:
        _fields(reference, {"artifactId", "locationId"})
        result = registry.verify_artifact(root, reference["artifactId"], reference["locationId"])
        artifact = result["artifact"]
        if result["verification"] != "verified" or artifact.get("sourceSha") != source:
            raise ArtifactReuseError("package must be verified local evidence from sourceSha")
        frozen.append({**reference, **{key: artifact[key] for key in
                       ("artifactKind", "platform", "sha256", "size", "sourceSha")}})
    _mixed(frozen)
    return sorted(frozen, key=lambda p: p["artifactId"])


def _mixed(packages: list[Mapping[str, Any]]) -> None:
    if len({p["artifactId"] for p in packages}) != len(packages) or len({(p["platform"], p["artifactKind"]) for p in packages}) != len(packages) or len({p["sourceSha"] for p in packages}) != 1:
        raise ArtifactReuseError("artifact set has duplicate or mixed packages")


def _encode(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _set_id(record: Mapping[str, Any]) -> str:
    return "artifact-set-" + hashlib.sha256(_encode(record)).hexdigest()


def _set_directory(root: Path) -> Path:
    registry._prepare_registry(root)
    directory = root / ".rag_index" / "native-artifact-sets"
    registry._ensure_private_directory(directory)
    return directory


def _set_path(directory: Path, set_id: Any) -> Path:
    if not isinstance(set_id, str) or not re.fullmatch(r"artifact-set-[0-9a-f]{64}", set_id):
        raise ArtifactReuseError("artifactSetId is invalid")
    return directory / (set_id + ".json")


def _read_set(path: Path) -> dict[str, Any]:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            raw = source.read(65537)
        if not stat.S_ISREG(info.st_mode) or len(raw) > 65536:
            raise ArtifactReuseError("artifact set record is unsafe or oversized")
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict) or not isinstance(value.get("artifactSetId"), str) or value["artifactSetId"] + ".json" != path.name:
            raise ArtifactReuseError("artifact set record identity is invalid")
        return value
    except (OSError, UnicodeDecodeError, ValueError, TypeError) as error:
        raise ArtifactReuseError("artifact set record is unavailable or corrupt") from error


def _store_set(root: Path, frozen: Mapping[str, Any]) -> None:
    directory = _set_directory(root)
    path = _set_path(directory, frozen["artifactSetId"])
    encoded = _encode(frozen)
    if len(encoded) > 65536:
        raise ArtifactReuseError("artifact set record is oversized")
    with registry._locked(directory):
        if path.exists() or path.is_symlink():
            if _read_set(path) != frozen:
                raise ArtifactReuseError("artifact set ID conflicts with stored evidence")
        else:
            registry._exclusive_write(path, encoded)


def _load_set(root: Path, reference: str | Mapping[str, Any]) -> dict[str, Any]:
    set_id = reference.get("artifactSetId") if isinstance(reference, Mapping) else reference
    directory = _set_directory(root)
    with registry._locked(directory):
        stored = _read_set(_set_path(directory, set_id))
    if isinstance(reference, Mapping) and reference != stored:
        raise ArtifactReuseError("caller artifact set differs from immutable stored evidence")
    return stored

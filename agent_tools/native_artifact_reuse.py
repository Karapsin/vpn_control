"""Conservative, content-bound evidence for reusing registered native packages.

A reuse decision never changes an artifact's original source identity.  It is a
local decision only; CI must still verify the current commit's exact SHA.
"""
from __future__ import annotations

import ast
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
    from . import dispatch_source_closure as closures
except ImportError:  # MCP server script-style import
    import native_artifact_registry as registry  # type: ignore[no-redef]
    import dispatch_source_closure as closures  # type: ignore[no-redef]


class ArtifactReuseError(ValueError):
    """The proposed artifact set has incomplete or unsafe evidence."""


_SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
# Byte-cache reuse only (artifact_reuse_check): which dirty or changed paths a frozen package may be reused across.
# Acceptance equivalence is scoped to executed inputs instead (_ScopedInputs).
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


def artifact_set_verify_readonly(root: str | Path, artifact_set: str | Mapping[str, Any]) -> dict[str, Any]:
    """Verify a frozen set without registry creation, cleanup, migration, or locks.

    A verified set also names the product version it was frozen with, so a caller can compare it.
    """
    root = _root(root)
    try:
        artifact_set = _load_set_readonly(root, artifact_set)
        _fields(artifact_set, {"artifactSetId", "schemaVersion", "sourceSha", "productInputs", "packages"})
        if type(artifact_set["schemaVersion"]) is not int or artifact_set["schemaVersion"] != 1 or artifact_set["artifactSetId"] != _set_id(
                {key: artifact_set[key] for key in ("schemaVersion", "sourceSha", "productInputs", "packages")}):
            raise ArtifactReuseError("artifact set identity is invalid")
        source = _sha(artifact_set["sourceSha"], "sourceSha")
        inputs = artifact_set["productInputs"]
        _fields(inputs, {"buildManifestSha256", "runtimeFiles", "version", "provenance"})
        _digest(inputs["buildManifestSha256"]); _version(inputs["version"])
        _validate_provenance(root, inputs["provenance"], verify_only=True)
        packages = artifact_set["packages"]
        if not isinstance(packages, list) or not packages or packages != sorted(packages, key=lambda p: p["artifactId"]):
            raise ArtifactReuseError("package list is invalid")
        _mixed(packages); checked = []
        for package in packages:
            _fields(package, {"artifactId", "locationId", "artifactKind", "platform", "sha256", "size", "sourceSha"})
            result = registry.verify_artifact_readonly(root, package["artifactId"], package["locationId"])
            artifact = result["artifact"]
            expected = {key: artifact[key] for key in ("artifactKind", "platform", "sha256", "size", "sourceSha")}
            if result["verification"] != "verified" or artifact["sourceSha"] != source or any(package[key] != expected[key] for key in expected):
                raise ArtifactReuseError("registered package bytes or identity changed")
            checked.append({"artifactId": package["artifactId"], "verification": "verified"})
        runtime = inputs["runtimeFiles"]
        if not isinstance(runtime, list) or not runtime or runtime != sorted(runtime, key=lambda p: p["path"]):
            raise ArtifactReuseError("runtime file list is invalid")
        if _runtime_files(root, [item["path"] for item in runtime]) != runtime or _provenance(root, inputs["provenance"], verify_only=True) != inputs["provenance"]:
            raise ArtifactReuseError("runtime or signer bytes changed")
    except (ArtifactReuseError, registry.NativeArtifactRegistryError, KeyError, TypeError, ValueError, OSError) as error:
        return {"verification": "mismatch", "reason": str(error)}
    return {"verification": "verified", "packages": checked, "originalSourceSha": source, "productVersion": inputs["version"]}


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
            "attestation": provenance,
            "nativeAdmissionReady": decision != "rebuild-required" and
                verified["verification"] == "verified" and not missing_checks,
            "missingChecks": missing_checks, "ciRequired": True}


def acceptance_equivalence_check(root: str | Path, artifact_set_id: str,
                                 original_source_sha: str, target_source_sha: str) -> dict[str, Any]:
    """Derive a committed-source-only proof usable by the acceptance ledger.

    This is deliberately narrower than byte-cache reuse.  It accepts no caller
    paths or diff claims, never changes registry provenance, and refuses a dirty
    checkout because a receipt for a commit cannot be inferred from loose files.
    """
    return _acceptance_equivalence_check(root, artifact_set_id, original_source_sha, target_source_sha, readonly=False)


def acceptance_equivalence_check_readonly(root: str | Path, artifact_set_id: str,
                                          original_source_sha: str, target_source_sha: str) -> dict[str, Any]:
    """Replay equivalence evidence without registry housekeeping or locks."""
    return _acceptance_equivalence_check(root, artifact_set_id, original_source_sha, target_source_sha, readonly=True)


def _acceptance_equivalence_check(root: str | Path, artifact_set_id: str,
                                  original_source_sha: str, target_source_sha: str, *, readonly: bool) -> dict[str, Any]:
    root = _root(root)
    original = _sha(original_source_sha, "originalSourceSHA")
    target = _sha(target_source_sha, "targetSourceSHA")
    if _head(root) != target:
        raise ArtifactReuseError("targetSourceSHA must be checked-out HEAD")
    if _dirty_paths(root):
        raise ArtifactReuseError("equivalence target checkout must be fully clean")
    frozen = _load_set_readonly(root, artifact_set_id) if readonly else _load_set(root, artifact_set_id)
    if frozen.get("sourceSha") != original:
        raise ArtifactReuseError("artifact set source does not match native receipt")
    verified = artifact_set_verify_readonly(root, frozen) if readonly else artifact_set_verify(root, frozen)
    if verified.get("verification") != "verified":
        raise ArtifactReuseError("artifact set or current bytes are not verified")
    scoped = _ScopedInputs(root, original, target)
    entries = _equivalence_diff(root, original, target, scoped)
    if not entries:
        classes: list[str] = []
    else:
        classes = sorted({entry["class"] for entry in entries})
    if any(entry["class"] in _EXECUTED for entry in entries):
        raise ArtifactReuseError("commit diff is not eligible for acceptance equivalence")
    # The executed inputs of both commits, compared byte for byte by Git object: none may differ.
    executed = scoped.executed_paths()
    product_before = _equivalence_product_tree(root, original, executed)
    product_after = _equivalence_product_tree(root, target, executed)
    if product_before != product_after:
        raise ArtifactReuseError("product tree differs across equivalence target")
    obligations = ["exact-sha-ci"]
    if any(kind in {"test", "fixture", "metadata", "agent-tool"} for kind in classes):
        obligations.append("changed-tool-tests")
    canonical = [{key: entry[key] for key in ("status", "oldMode", "newMode", "path", "class")}
                 for entry in entries]
    # Git traversal and byte streaming can take long enough for another actor to
    # move the checkout.  A proof is for this exact target commit only.
    final_verified = artifact_set_verify_readonly(root, frozen) if readonly else artifact_set_verify(root, frozen)
    if final_verified.get("verification") != "verified":
        raise ArtifactReuseError("artifact set or current bytes changed during equivalence verification")
    if _head(root) != target or _dirty_paths(root):
        raise ArtifactReuseError("equivalence target changed during verification")
    return {"schemaVersion": 1, "artifactSetId": frozen["artifactSetId"],
            "originalSourceSHA": original, "targetSourceSHA": target,
            "immutableArtifactIDs": [item["artifactId"] for item in frozen["packages"]],
            "productTreeSha256": product_before,
            "diffSha256": hashlib.sha256(_encode(canonical)).hexdigest(),
            "changedPaths": canonical, "requiredCurrentChecks": obligations}


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


def _equivalence_diff(root: Path, before: str, after: str, scoped: "_ScopedInputs | None" = None) -> list[dict[str, str]]:
    """Return a canonical, mode-sensitive Git diff or fail closed.

    Each path's class is what the two commits' executed inputs make it (_ScopedInputs): an executed class ends a link.
    """
    for sha in (before, after):
        _git(root, "cat-file", "-e", sha + "^{commit}")
    scoped = scoped if scoped is not None else _ScopedInputs(root, before, after)
    rename_status = _git(root, "diff", "-M", "--name-status", "-z", before, after).split(b"\0")
    if any(item.startswith((b"R", b"C")) for item in rename_status[::2] if item):
        raise ArtifactReuseError("Git equivalence diff contains a rename or copy")
    raw = _git(root, "diff", "--no-renames", "--raw", "-z", before, after)
    parts = raw.split(b"\0")
    entries: list[dict[str, str]] = []
    index = 0
    while index < len(parts) - 1:
        metadata = parts[index]
        if not metadata:
            index += 1
            continue
        if index + 1 >= len(parts):
            raise ArtifactReuseError("Git equivalence diff is malformed")
        path_bytes = parts[index + 1]
        index += 2
        try:
            fields = metadata.decode("ascii").split()
            path = path_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ArtifactReuseError("Git equivalence diff contains a non-UTF-8 path") from error
        if len(fields) != 5 or not fields[0].startswith(":") or fields[4] not in {"A", "M", "D"}:
            raise ArtifactReuseError("Git equivalence diff has unsupported status")
        old_mode, new_mode = fields[0][1:], fields[1]
        if old_mode == "120000" or new_mode == "120000" or old_mode != new_mode and fields[4] == "M":
            raise ArtifactReuseError("Git equivalence diff changes an unsafe mode")
        entries.append({"status": fields[4], "oldMode": old_mode, "newMode": new_mode,
                        "path": path, "class": scoped.classify(path)})
    return entries


# Native-evidence equivalence is scoped to what a recorded scenario executed (TEST-007): the product build inputs, the
# files a scenario bundle ships to the guest, and the host-side driver and classifier executed inputs (imports, by-name
# loads, with_name sources) with the resources they read. A change to any of them ends a link; tests, fixtures, selector
# metadata, docs and unrelated tools do not. The sets are derived from each commit's own files: the bundle table, the
# Python sources, the Gradle settings.
_EXECUTED = frozenset({"product", "bundle", "host-tool", "rejected"})
_BUNDLE_MODULE = "agent_tools/native_scenario_bundle.py"  # Its _SCENARIOS table is the manifest of every scenario bundle.
_BUNDLE_TABLE = "_SCENARIOS"
# The APIs of native evidence: a module that freezes or verifies a scenario bundle, journals a scenario execution, reads
# or writes the acceptance matrix, or proves equivalence is a host-side driver or classifier. Their importers are the roots.
_HOST_ANCHORS = ("agent_tools/native_scenario_bundle.py", "agent_tools/native_scenario_execution.py",
                 "agent_tools/native_acceptance_matrix.py", "agent_tools/native_artifact_reuse.py")
# The test selector: the sibling files it names are its own metadata, which no scenario reads.
_SELECTOR_MODULE = "agent_tools/affected_agent_tests.py"
# The MCP route's launcher: the server registration and the agent_tools files it names, and the files those name.
_MCP_REGISTRATION = ".mcp.json"
_TOOL_PATH = re.compile(rb"agent_tools/[A-Za-z0-9_][A-Za-z0-9_./-]*")
_TOOLS, _TOOL_TESTS, _TOOL_FIXTURES = "agent_tools/", "agent_tools/tests/", "agent_tools/tests/fixtures/"
_SETTINGS = "settings.gradle.kts"
_INCLUDE = re.compile(r"\binclude\s*\(([^)]*)\)")
_PROJECT = re.compile(r"\"(:[A-Za-z0-9_.:-]+)\"")
_SOURCE_DIR = re.compile(r"srcDir\(\s*rootProject\.file\(\s*\"([^\"]+)\"\s*\)\s*\)")
_SOURCE_SET = re.compile(r"getByName\(\s*\"([A-Za-z0-9_]+)\"\s*\)")


def _test_set(name: str) -> bool:
    """A Gradle or Kotlin Multiplatform test source set: test, androidTest, desktopTest, commonTest, androidUnitTest."""
    return name == "test" or name.endswith("Test")


def _unsafe_path(path: str) -> bool:
    return not path or path.startswith("/") or any(part in {"", ".", ".."} for part in path.split("/"))


def _tree_entries(root: Path, source: str) -> dict[str, tuple[str, str, str]]:
    entries: dict[str, tuple[str, str, str]] = {}
    for item in _git(root, "ls-tree", "-r", "-z", "--full-tree", source).split(b"\0"):
        if not item:
            continue
        metadata, name = item.split(b"\t", 1)
        try:
            path = name.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ArtifactReuseError("Git tree contains a non-UTF-8 path") from error
        mode, kind, oid = metadata.decode("ascii").split(" ")
        entries[path] = (mode, kind, oid)
    return entries


def _blobs(root: Path, oids: set[str], cache: dict[str, bytes]) -> None:
    """Read Git blobs by object ID in one batch into cache; a missing object fails closed."""
    wanted = sorted(oid for oid in oids if oid not in cache)
    if not wanted:
        return
    result = subprocess.run(["git", "cat-file", "--batch"], cwd=root, input=("\n".join(wanted) + "\n").encode("ascii"),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise ArtifactReuseError("Git evidence unavailable: cat-file --batch")
    raw, offset = result.stdout, 0
    for oid in wanted:
        end = raw.index(b"\n", offset)
        header = raw[offset:end].decode("ascii").split(" ")
        if len(header) != 3 or header[0] != oid or header[1] != "blob":
            raise ArtifactReuseError("Git evidence unavailable: blob " + oid)
        size = int(header[2])
        cache[oid] = raw[end + 1:end + 1 + size]
        offset = end + 1 + size + 1


def _syntax(source: bytes, path: str) -> ast.AST:
    try:
        return ast.parse(source, filename=path)
    except (SyntaxError, ValueError) as error:
        raise ArtifactReuseError("executed-input analysis cannot parse " + path) from error


class _ExecutedInputs:
    """The executed inputs of one commit, from its own files: product build inputs, bundle files and host closure."""

    def __init__(self, root: Path, source: str, cache: dict[str, Any]):
        self.root, self.cache = root, cache
        self.tree = _tree_entries(root, source)
        self.modules = {self._dotted(path): path for path in self.tree
                        if path.startswith(_TOOLS) and not path.startswith(_TOOL_TESTS) and path.endswith(".py")}
        self.bundle = self._bundle_files()
        self.selector = self._sibling_names(_SELECTOR_MODULE) if _SELECTOR_MODULE in self.tree else set()
        self.host = self._host_closure()
        self.projects, self.test_directories = self._gradle()

    @staticmethod
    def _dotted(path: str) -> str:
        parts = path[len(_TOOLS):-len(".py")].split("/")
        return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)

    def _bytes(self, paths: list[str]) -> dict[str, bytes]:
        blobs = self.cache.setdefault("blobs", {})
        _blobs(self.root, {self.tree[path][2] for path in paths}, blobs)
        return {path: blobs[self.tree[path][2]] for path in paths}

    def _parsed(self, path: str) -> ast.AST:
        trees = self.cache.setdefault("syntax", {})
        oid = self.tree[path][2]
        if oid not in trees:
            trees[oid] = _syntax(self._bytes([path])[path], path)
        return trees[oid]

    def _bundle_files(self) -> set[str]:
        if _BUNDLE_MODULE not in self.tree:
            return set()
        for node in ast.walk(self._parsed(_BUNDLE_MODULE)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
            if any(isinstance(target, ast.Name) and target.id == _BUNDLE_TABLE for target in targets) and node.value is not None:
                try:
                    table = ast.literal_eval(node.value)
                except ValueError as error:
                    raise ArtifactReuseError("scenario bundle manifest is not a literal table") from error
                if (not isinstance(table, dict) or not all(isinstance(files, tuple) and all(isinstance(item, str) and not _unsafe_path(item)
                                                                                            for item in files) for files in table.values())):
                    raise ArtifactReuseError("scenario bundle manifest is invalid")
                return {item for files in table.values() for item in files}
        raise ArtifactReuseError("scenario bundle manifest is unavailable")

    def _summary(self, path: str) -> tuple[Any, ...]:
        """One walk of a module (dispatch_source_closure.Scan): its import statements (level, module, names; level -1 a
        plain import), string literals, modules it loads by name, and with_name / with_suffix arguments."""
        summaries = self.cache.setdefault("summaries", {})
        oid = self.tree[path][2]
        if oid not in summaries:
            scan = closures.Scan(self._parsed(path))
            imports = []
            for node in scan.imports:
                if isinstance(node, ast.Import):
                    imports.extend((-1, alias.name, ()) for alias in node.names)
                else:
                    imports.append((node.level, node.module or "", tuple(alias.name for alias in node.names)))
            summaries[oid] = (tuple(imports), frozenset(scan.strings), frozenset(scan.loaded), frozenset(scan.with_name),
                              frozenset(scan.with_suffix))
        return summaries[oid]

    def _imports(self, path: str) -> set[str]:
        """The agent_tools modules one module imports, at any depth of its body, package or script style."""
        dotted = self._dotted(path).split(".")
        package = dotted if path.endswith("/__init__.py") else dotted[:-1]
        names: set[str] = set()
        for level, module, aliases in self._summary(path)[0]:
            parts = module.split(".") if module else []
            if level < 0:
                names.update(".".join(parts[:index]) for index in range(1, len(parts) + 1))
                names.add(".".join([*package, *parts]))
                continue
            prefixes = ([[*(package[:len(package) - (level - 1)] if level > 1 else package), *parts]] if level
                        else [parts, [*package, *parts]])
            for prefix in prefixes:
                names.add(".".join(prefix))
                names.update(".".join([*prefix, alias]) for alias in aliases)
        # A module loaded by name (the MCP server's _VM_NATIVE_ADAPTERS and _agent_module, import_module, a source
        # session's load) runs exactly like an imported one, and so does a sibling source named by with_name.
        names.update(self._summary(path)[2])
        directory = path.rsplit("/", 1)[0] + "/"
        names.update(self._dotted(directory + value) for value in self._summary(path)[3]
                     if value.endswith(".py") and directory + value in self.tree)
        resolved = set()
        for name in names:
            name = name[len("agent_tools."):] if name.startswith("agent_tools.") else name
            if name in self.modules:
                resolved.add(self.modules[name])
        return resolved

    def _sibling_names(self, path: str) -> set[str]:
        """Tracked non-Python files a module names by literal: a sibling's file name or an agent_tools path."""
        directory = path.rsplit("/", 1)[0] + "/"
        # The module's own resource by suffix (readiness_vm_dispatch.json beside readiness_vm_dispatch.py).
        found = {path[:-len(".py")] + suffix for suffix in self._summary(path)[4]
                 if path[:-len(".py")] + suffix in self.tree and not (path[:-len(".py")] + suffix).endswith((".py", ".md"))}
        for value in self._summary(path)[1]:
            for candidate in (directory + value, value):
                if (candidate.startswith(_TOOLS) and not candidate.startswith(_TOOL_TESTS) and candidate in self.tree
                        and not candidate.endswith((".py", ".md"))):
                    found.add(candidate)
        return found

    def _mcp_launcher(self) -> set[str]:
        """The files the MCP server registration names under agent_tools, and those its non-Python files name in turn."""
        named: set[str] = set()
        pending = [_MCP_REGISTRATION] if _MCP_REGISTRATION in self.tree else []
        while pending:
            for match in _TOOL_PATH.findall(self._bytes([pending.pop()]).popitem()[1]):
                path = match.decode("ascii").rstrip("./")
                if path in self.tree and path not in named and not path.startswith(_TOOL_TESTS) and not path.endswith(".md"):
                    named.add(path)
                    if not path.endswith(".py"):
                        pending.append(path)
        return named

    def _host_closure(self) -> set[str]:
        anchors = {path for path in _HOST_ANCHORS if path in self.tree}
        launcher = self._mcp_launcher()
        names = tuple(path[len(_TOOLS):-len(".py")].rsplit("/", 1)[-1].encode() for path in anchors)
        # An import names the module in its text, so only those modules are parsed to find the anchors' importers.
        mentions = self._bytes(sorted(path for path in self.modules.values()))
        roots = (set(anchors) | {path for path in launcher if path in self.modules.values()}
                 | {path for path, raw in mentions.items() if any(name in raw for name in names) and self._imports(path) & anchors})
        closure, pending = set(), sorted(roots)
        while pending:
            path = pending.pop()
            if path in closure:
                continue
            closure.add(path)
            pending.extend(sorted(self._imports(path) - closure))
        resources = {item for path in closure for item in self._sibling_names(path)} - self.selector
        return closure | resources | launcher

    def _gradle(self) -> tuple[tuple[str, ...], set[str]]:
        """Included project directories, and repository directories only test source sets add (srcDir)."""
        if _SETTINGS not in self.tree:
            return (), set()
        settings = self._bytes([_SETTINGS])[_SETTINGS].decode("utf-8", "replace")
        projects = sorted({name.strip(":").replace(":", "/") + "/" for block in _INCLUDE.findall(settings)
                           for name in _PROJECT.findall(block)})
        uses: dict[str, set[bool]] = {}
        scripts = [project + "build.gradle.kts" for project in projects if project + "build.gradle.kts" in self.tree]
        for raw in self._bytes(scripts).values():
            for line in raw.decode("utf-8", "replace").splitlines():
                for directory in _SOURCE_DIR.findall(line):
                    sets = _SOURCE_SET.findall(line)
                    uses.setdefault(directory.strip("/") + "/", set()).add(bool(sets) and all(_test_set(name) for name in sets))
        return tuple(projects), {directory for directory, tests in uses.items() if tests == {True}}

    def classify(self, path: str) -> str:
        if _unsafe_path(path):
            return "rejected"
        if path in self.bundle:
            return "bundle"
        if path in self.host:
            return "host-tool"
        project = next((item for item in self.projects if path.startswith(item)), None)
        if path.startswith(("docs/", "agent_docs/")) or path.endswith(".md") and project is None:
            return "docs"
        if path.startswith(_TOOLS):
            return ("fixture" if path.startswith(_TOOL_FIXTURES) else "test" if path.startswith(_TOOL_TESTS)
                    else "metadata" if path in self.selector else "agent-tool")
        parts = path.split("/")
        if (path.startswith("tests/") or path.startswith(tuple(self.test_directories))
                or path.startswith("scripts/") and parts[-1].startswith("test_") and parts[-1].endswith(".py")
                or project is not None and path[len(project):].startswith("src/") and len(path[len(project):].split("/")) > 2
                and _test_set(path[len(project):].split("/")[1])):
            return "test"
        return "product"


class _ScopedInputs:
    """Both commits' executed inputs: a path is executed when either commit executes it."""

    def __init__(self, root: Path, before: str, after: str):
        cache: dict[str, Any] = {}
        self.sides = (_ExecutedInputs(root, before, cache), _ExecutedInputs(root, after, cache))

    def classify(self, path: str) -> str:
        classes = [side.classify(path) for side in self.sides]
        return next((name for name in classes if name in _EXECUTED), classes[1])

    def executed_paths(self) -> list[str]:
        paths = {path for side in self.sides for path in side.tree}
        return sorted(path for path in paths if self.classify(path) in _EXECUTED)


def _equivalence_product_tree(root: Path, source: str, executed: list[str] | None = None) -> str:
    """The digest of one commit's executed inputs: path, mode, type and object of each one present."""
    tree = _tree_entries(root, source)
    paths = executed if executed is not None else _ScopedInputs(root, source, source).executed_paths()
    return hashlib.sha256(_encode([[path, *tree[path]] for path in paths if path in tree])).hexdigest()


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


def _load_set_readonly(root: Path, reference: str | Mapping[str, Any]) -> dict[str, Any]:
    """Read a current immutable set without invoking the writer-side directory helper."""
    set_id = reference.get("artifactSetId") if isinstance(reference, Mapping) else reference
    try:
        registry._readonly_private_directory(root / ".rag_index")
        directory = root / ".rag_index" / "native-artifact-sets"
        registry._readonly_private_directory(directory)
        stored = _read_set_readonly(_set_path(directory, set_id))
    except registry.NativeArtifactRegistryError as error:
        raise ArtifactReuseError("artifact set record is unavailable or unsafe") from error
    if isinstance(reference, Mapping) and reference != stored:
        raise ArtifactReuseError("caller artifact set differs from immutable stored evidence")
    return stored


def _read_set_readonly(path: Path) -> dict[str, Any]:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as source:
            before = os.fstat(source.fileno())
            raw = source.read(65537)
            after = os.fstat(source.fileno())
        named = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != 0o600 or
                before.st_nlink != 1 or len(raw) > 65536 or not _same_generation(before, after) or
                not _same_generation(before, named) or len(raw) != before.st_size):
            raise ArtifactReuseError("artifact set record is unsafe or changed")
        value = json.loads(raw.decode("utf-8"))
        if (not isinstance(value, dict) or type(value.get("schemaVersion")) is not int or value.get("schemaVersion") != 1 or
                not isinstance(value.get("artifactSetId"), str) or value["artifactSetId"] + ".json" != path.name):
            raise ArtifactReuseError("artifact set record identity is invalid")
        return value
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        if isinstance(error, ArtifactReuseError):
            raise
        raise ArtifactReuseError("artifact set record is unavailable or corrupt") from error


def _same_generation(first: os.stat_result, second: os.stat_result) -> bool:
    return (first.st_dev, first.st_ino, first.st_mode, first.st_uid, first.st_gid, first.st_nlink,
            first.st_size, first.st_mtime_ns, first.st_ctime_ns) == (
            second.st_dev, second.st_ino, second.st_mode, second.st_uid, second.st_gid, second.st_nlink,
            second.st_size, second.st_mtime_ns, second.st_ctime_ns)

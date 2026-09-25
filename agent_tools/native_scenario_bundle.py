"""Freeze the small, allowlisted Python inputs for native test scenarios.

This module deliberately prepares source only.  It neither installs packages nor
starts VMs, VPNs, or the scenario driver.  The publisher/executor binds the
returned manifest digest to its own transfer and execution receipts.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile


SCHEMA_VERSION = 1
MANIFEST_NAME = "native-scenario-manifest.json"
_SCENARIOS = {
    "linux-public-update-driver": (
        "scripts/test_linux_public_install.py",
        "scripts/linux_fixture_auth.py",
        "scripts/arch_public_update.py",
        "scripts/rpm_public_update.py",
        "scripts/prepare_desktop_update_fixture.py",
        "scripts/fixture_environment.py",
        "scripts/macos_packaging_jdk_preflight.py",
        "scripts/native_fixture_run.sh",
    ),
    "desktop-update-entrypoint": (
        "scripts/prepare_desktop_update_fixture.py",
        "scripts/fixture_environment.py",
        "scripts/macos_packaging_jdk_preflight.py",
    ),
    "linux-scheduled-refresh-driver": (
        "scripts/integration/linux_scheduled_refresh_scenario.py",
        "scripts/integration/socks_http_fixture.py",
        "scripts/native_fixture_preflight.py",
        "scripts/native_fixture_run.sh",
    ),
}


class NativeScenarioBundleError(ValueError):
    """The requested bundle is unsafe, incomplete, or no longer immutable."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise NativeScenarioBundleError(message)


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular_snapshot(path: Path, *, copy_to: Path | None = None) -> dict[str, object]:
    """Hash one regular source through a no-follow descriptor, optionally copying it.

    The descriptor pins the opened inode while bytes are read.  A replacement of
    the path cannot turn a captured file into a symlink or a different inode.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise NativeScenarioBundleError("Scenario source is missing or unsafe: " + str(path)) from error
    target = None
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode), "Scenario source is missing or unsafe: " + str(path))
        if copy_to is not None:
            target = os.open(copy_to, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
            if target is not None:
                offset = 0
                while offset < len(chunk):
                    offset += os.write(target, chunk[offset:])
        after = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino, before.st_mode, before.st_size,
                    before.st_mtime_ns, before.st_ctime_ns)
        _require(identity == (after.st_dev, after.st_ino, after.st_mode, after.st_size,
                              after.st_mtime_ns, after.st_ctime_ns),
                 "Scenario source changed during capture: " + str(path))
        return {"sha256": digest.hexdigest(), "sizeBytes": size, "identity": identity}
    finally:
        if target is not None:
            os.close(target)
        os.close(descriptor)


def _canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _safe_source(root: Path, relative: str) -> Path:
    candidate = root / relative
    _require(candidate.is_relative_to(root), "Scenario source escapes repository root")
    try:
        parent = root
        for component in Path(relative).parts[:-1]:
            parent /= component
            parent_info = parent.lstat()
            _require(stat.S_ISDIR(parent_info.st_mode) and not stat.S_ISLNK(parent_info.st_mode),
                     "Scenario source ancestry is unsafe: " + relative)
        info = candidate.lstat()
    except FileNotFoundError as error:
        raise NativeScenarioBundleError("Scenario source is missing or unsafe: " + relative) from error
    _require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode),
             "Scenario source is missing or unsafe: " + relative)
    return candidate


def _bundle_file(bundle: Path, relative: str) -> Path:
    """Resolve an allowlisted relative path only through regular private ancestors."""
    current = bundle
    for component in Path(relative).parts[:-1]:
        current /= component
        info = current.lstat()
        _require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
                 "Bundle file ancestry is unsafe: " + relative)
    return bundle / relative


def _source_snapshot(root: Path, files: tuple[str, ...]) -> list[dict[str, object]]:
    snapshot = []
    for relative in files:
        source = _safe_source(root, relative)
        snapshot.append({"path": relative, **_regular_snapshot(source)})
    return snapshot


def _validate_scenario(scenario_id: str) -> tuple[str, ...]:
    _require(isinstance(scenario_id, str) and scenario_id in _SCENARIOS,
             "Native scenario is not allowlisted")
    return _SCENARIOS[scenario_id]


def _isolated_import(bundle: Path, entrypoint: str) -> None:
    """Import the staged driver without letting checkout or caller imports satisfy it."""
    command = (
        "import importlib.util,pathlib,sys;"
        "entrypoint=pathlib.Path(sys.argv[1]);"
        "sys.path.insert(0,str(entrypoint.parent.parent));"
        "sys.path.insert(0,str(entrypoint.parent));"
        "spec=importlib.util.spec_from_file_location('native_scenario_driver',entrypoint);"
        "module=importlib.util.module_from_spec(spec);"
        "spec.loader.exec_module(module)"
    )
    with tempfile.TemporaryDirectory(prefix="native-scenario-import-") as foreign_cwd:
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", command, str(bundle / entrypoint)],
            cwd=foreign_cwd, env={"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True, text=True, check=False, timeout=30,
        )
    if result.returncode:
        detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "no diagnostic"
        raise NativeScenarioBundleError("Staged scenario import preflight failed: " + detail)


def prepare_bundle(root: str | Path, scenario_id: str, output_directory: str | Path) -> dict[str, object]:
    """Create an exclusive immutable snapshot of one canonical scenario's source files."""
    repository = Path(root).resolve(strict=True)
    _require(repository.is_dir(), "Repository root is invalid")
    files = _validate_scenario(scenario_id)
    destination = Path(os.path.abspath(output_directory))
    parent = destination.parent.resolve(strict=True)
    destination = parent / destination.name
    _require(destination.name not in ("", ".", ".."), "Bundle destination is invalid")
    try:
        destination.mkdir(mode=0o700)
    except FileExistsError as error:
        raise NativeScenarioBundleError("Bundle destination must be a fresh directory") from error
    stage = None
    try:
        before = _source_snapshot(repository, files)
        stage = Path(tempfile.mkdtemp(prefix="native-scenario-stage-", dir=parent))
        os.chmod(stage, 0o700)
        for entry in before:
            source = _safe_source(repository, str(entry["path"]))
            target = stage / str(entry["path"])
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            copied = _regular_snapshot(source, copy_to=target)
            target_info = target.lstat()
            _require(stat.S_ISREG(target_info.st_mode) and not stat.S_ISLNK(target_info.st_mode) and
                     copied["sizeBytes"] == entry["sizeBytes"] and copied["sha256"] == entry["sha256"],
                     "Scenario source changed during capture: " + str(entry["path"]))
        after = _source_snapshot(repository, files)
        _require(before == after, "Scenario source changed during capture")
        manifest = {
            "schemaVersion": SCHEMA_VERSION,
            "scenarioId": scenario_id,
            "files": [{key: entry[key] for key in ("path", "sha256", "sizeBytes")} for entry in before],
        }
        manifest_bytes = _canonical_bytes(manifest)
        (stage / MANIFEST_NAME).write_bytes(manifest_bytes)
        os.chmod(stage / MANIFEST_NAME, 0o600)
        _isolated_import(stage, files[0])
        os.replace(stage / "scripts", destination / "scripts")
        os.replace(stage / MANIFEST_NAME, destination / MANIFEST_NAME)
        stage.rmdir()
    except Exception:
        if stage is not None:
            shutil.rmtree(stage, ignore_errors=True)
        try:
            destination.rmdir()
        except OSError:
            pass
        raise
    return {"directory": str(destination), "manifest": MANIFEST_NAME,
            "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "scenarioId": scenario_id, "files": manifest["files"]}


def verify_bundle(root: str | Path, path: str | Path, expected_manifest_sha256: str) -> dict[str, object]:
    """Verify an already frozen bundle against its exact allowlisted inventory."""
    repository = Path(root).resolve(strict=True)
    lexical = Path(os.path.abspath(path))
    try:
        info = lexical.lstat()
        parent_info = lexical.parent.lstat()
    except FileNotFoundError as error:
        raise NativeScenarioBundleError("Bundle directory is unsafe") from error
    _require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and
             stat.S_ISDIR(parent_info.st_mode) and not stat.S_ISLNK(parent_info.st_mode),
             "Bundle directory is unsafe")
    bundle = lexical.resolve(strict=True)
    _require(repository.is_dir() and bundle.is_dir(), "Bundle directory is unsafe")
    _require(isinstance(expected_manifest_sha256, str) and len(expected_manifest_sha256) == 64,
             "Expected manifest digest is invalid")
    manifest_path = bundle / MANIFEST_NAME
    _require(manifest_path.is_file() and not manifest_path.is_symlink(), "Bundle manifest is missing or unsafe")
    raw = manifest_path.read_bytes()
    actual_digest = hashlib.sha256(raw).hexdigest()
    _require(actual_digest == expected_manifest_sha256, "Bundle manifest digest differs")
    try:
        manifest = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeScenarioBundleError("Bundle manifest is invalid") from error
    _require(_canonical_bytes(manifest) == raw, "Bundle manifest is not canonical")
    _require(isinstance(manifest, dict) and manifest.get("schemaVersion") == SCHEMA_VERSION,
             "Bundle manifest schema is invalid")
    scenario_id = manifest.get("scenarioId")
    files = _validate_scenario(scenario_id)
    entries = manifest.get("files")
    _require(isinstance(entries, list) and len(entries) == len(files), "Bundle manifest files are invalid")
    expected_paths = set(files)
    actual_paths = []
    for entry in entries:
        _require(isinstance(entry, dict) and set(entry) == {"path", "sha256", "sizeBytes"},
                 "Bundle manifest entry is invalid")
        relative, digest, size = entry["path"], entry["sha256"], entry["sizeBytes"]
        _require(isinstance(relative, str) and relative in expected_paths and Path(relative).as_posix() == relative,
                 "Bundle manifest path is not allowlisted")
        _require(isinstance(digest, str) and len(digest) == 64 and all(c in "0123456789abcdef" for c in digest),
                 "Bundle manifest file digest is invalid")
        _require(type(size) is int and size >= 0, "Bundle manifest file size is invalid")
        actual_paths.append(relative)
        file_path = _bundle_file(bundle, relative)
        info = file_path.lstat()
        _require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_size == size and
                 _hash(file_path) == digest, "Bundle file differs: " + relative)
    _require(set(actual_paths) == expected_paths and len(set(actual_paths)) == len(actual_paths),
             "Bundle manifest does not describe the exact scenario inventory")
    actual_files = {item.relative_to(bundle).as_posix() for item in bundle.rglob("*") if item.is_file()}
    _require(actual_files == expected_paths | {MANIFEST_NAME}, "Bundle contains unexpected files")
    return {"directory": str(bundle), "manifest": MANIFEST_NAME,
            "manifestSha256": actual_digest, "scenarioId": scenario_id, "files": entries}

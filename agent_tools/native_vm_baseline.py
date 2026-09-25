"""Private, versioned native VM baselines from configured, stopped fixtures.

The MCP owner constructs providers from its private inventory and trusted read-only
observers. Requests select an owned source ID and a safe new name; they cannot
supply admission booleans, paths, commands, or receipts. This module never starts
or stops a VM. A failed capture keeps its intent and partial bytes for inspection.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Callable, Mapping

_NAME = re.compile(r"^[a-z][a-z0-9-]{2,39}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_PROVIDER_NAME = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
_CHUNK = 1024 * 1024


class VmBaselineError(ValueError):
    """An observation, path, baseline, or provider result is unsafe."""


def _need(ok: bool, message: str) -> None:
    if not ok:
        raise VmBaselineError(message)


def _name(value: Any) -> str:
    _need(isinstance(value, str) and _NAME.fullmatch(value) is not None, "unsafe VM baseline identity")
    return value


def _sha(value: Any, label: str) -> str:
    _need(isinstance(value, str) and _SHA.fullmatch(value) is not None, f"{label} must be an exact SHA-256")
    return value


def _fingerprint(value: Any) -> dict[str, str]:
    _need(isinstance(value, Mapping) and bool(value) and len(value) <= 32, "dependency fingerprint is empty or unbounded")
    result: dict[str, str] = {}
    for key, digest in value.items():
        _need(isinstance(key, str) and _NAME.fullmatch(key) is not None, "dependency fingerprint key is unsafe")
        result[key] = _sha(digest, "dependency fingerprint")
    return dict(sorted(result.items()))


def _safe_path(path: Path, root: Path, *, exists: bool, kind: str | None = None) -> Path:
    """Reject symlinks lexically before resolve; check every existing ancestor."""
    _need(path.is_absolute() and root.is_absolute(), "VM path must be absolute")
    _need(not any(part in (".", "..") for part in path.parts), "VM path traversal is unsafe")
    root_real = root.resolve(strict=True)
    _need(root_real == root and root.is_dir() and not root.is_symlink(), "owned VM root is unsafe")
    _need(path == root or root in path.parents, "VM path escapes owned root")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            continue
        _need(not stat.S_ISLNK(mode), "VM path contains a symlink")
    if exists:
        _need(path.exists(), "VM path is missing")
        if kind == "file":
            _need(path.is_file(), "VM path is not a regular file")
        elif kind == "dir":
            _need(path.is_dir(), "VM path is not a directory")
    else:
        _need(not path.exists() and not path.is_symlink(), "VM destination already exists")
    return path


def _file_hash(path: Path) -> tuple[int, str]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            _need(stat.S_ISREG(before.st_mode), "baseline contains a non-regular file")
            digest = hashlib.sha256()
            size = 0
            while chunk := stream.read(_CHUNK):
                digest.update(chunk)
                size += len(chunk)
            after = os.fstat(stream.fileno())
            _need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                  (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) and size == before.st_size,
                  "VM file changed while hashing")
            return size, digest.hexdigest()
    except OSError as error:
        raise VmBaselineError("VM file cannot be hashed safely") from error


def _tree_hash(root: Path) -> str:
    """Stable streamed tree identity; rejects symlinks and special files."""
    _need(root.is_dir() and not root.is_symlink(), "baseline tree is missing or unsafe")
    digest = hashlib.sha256()
    entries = 0
    for directory, names, files in os.walk(root, followlinks=False, onerror=_walk_error):
        names.sort()
        files.sort()
        base = Path(directory)
        for name in names + files:
            entries += 1
            child = base / name
            info = os.lstat(child)
            _need(info.st_uid == os.getuid() and info.st_mode & 0o022 == 0,
                  "baseline tree contains unowned or writable bytes")
            relative = child.relative_to(root).as_posix()
            _need(len(relative) <= 4096 and "\x00" not in relative, "baseline tree path is unsafe")
            if stat.S_ISDIR(info.st_mode):
                item = ["dir", relative]
            elif stat.S_ISREG(info.st_mode):
                size, sha = _file_hash(child)
                item = ["file", relative, size, sha]
            else:
                raise VmBaselineError("baseline tree contains a symlink or special file")
            digest.update(json.dumps(item, separators=(",", ":")).encode() + b"\n")
    _need(entries > 0, "baseline tree is empty")
    return digest.hexdigest()


def _walk_error(error: OSError) -> None:
    raise VmBaselineError("baseline tree cannot be enumerated safely") from error


def _run(argv: tuple[str, ...]) -> None:
    try:
        result = subprocess.run(argv, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3600)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise VmBaselineError("fixed VM provider operation failed") from error
    _need(result.returncode == 0, "fixed VM provider operation failed")


@dataclass(frozen=True)
class SourceBinding:
    source_id: str
    path: Path
    generation: str
    provider_name: str  # Tart VM name, or fixed QEMU source ID; never request supplied.


@dataclass(frozen=True)
class SourceObservation:
    """Fresh facts from a trusted observer owned by the MCP provider adapter."""
    source_id: str
    generation: str
    path: Path
    owned: bool
    stopped: bool
    quiescent: bool
    installer_job: str  # Only 'terminal' or 'none' is admissible.
    access_receipt: str
    dependency_receipt: str
    fingerprint: Mapping[str, str]


class Provider:
    kind: str

    def __init__(self, *, source_root: Path, sources: Mapping[str, SourceBinding],
                 observe: Callable[[str], SourceObservation], runner: Callable[[tuple[str, ...]], None] = _run):
        self.source_root = Path(source_root)
        _safe_path(self.source_root, self.source_root, exists=True, kind="dir")
        owner = os.stat(self.source_root, follow_symlinks=False)
        _need(owner.st_uid == os.getuid() and owner.st_mode & 0o022 == 0,
              "provider source root is writable by another user")
        self.sources = dict(sources)
        self.observe = observe
        self.runner = runner

    def admitted(self, source_id: str) -> tuple[SourceBinding, SourceObservation]:
        _name(source_id)
        binding = self.sources.get(source_id)
        _need(isinstance(binding, SourceBinding) and binding.source_id == source_id,
              "source is not in the configured provider inventory")
        _name(binding.generation)
        _need(isinstance(binding.provider_name, str) and _PROVIDER_NAME.fullmatch(binding.provider_name) is not None,
              "configured provider name is unsafe")
        source_kind = "dir" if self.kind == "tart" else "file"
        path = _safe_path(Path(binding.path), self.source_root, exists=True, kind=source_kind)
        observation = self.observe(source_id)
        _need(isinstance(observation, SourceObservation), "provider observation is unavailable")
        _need((observation.source_id, observation.generation, Path(observation.path)) ==
              (source_id, binding.generation, path), "provider source generation or path changed")
        _need(observation.owned is True and observation.stopped is True and observation.quiescent is True,
              "source is not authoritatively owned, stopped, and quiescent")
        _need(observation.installer_job in ("terminal", "none"), "installer job is active or unknown")
        _sha(observation.access_receipt, "access receipt")
        _sha(observation.dependency_receipt, "dependency receipt")
        _fingerprint(observation.fingerprint)
        return binding, observation

    def source_hash(self, path: Path) -> str:
        return _tree_hash(path) if self.kind == "tart" else _file_hash(path)[1]


class TartProvider(Provider):
    kind = "tart"

    def __init__(self, *, source_root: Path, sources: Mapping[str, SourceBinding],
                 observe: Callable[[str], SourceObservation], runner: Callable[[tuple[str, ...]], None] = _run):
        super().__init__(source_root=source_root, sources=sources, observe=observe, runner=runner)

    def clone(self, source_name: str, destination_name: str) -> None:
        _need(isinstance(source_name, str) and _PROVIDER_NAME.fullmatch(source_name) is not None and
              isinstance(destination_name, str) and _PROVIDER_NAME.fullmatch(destination_name) is not None,
              "Tart clone name is unsafe")
        self.runner(("tart", "clone", source_name, destination_name))


class QemuProvider(Provider):
    kind = "qemu"

    @staticmethod
    def inspect_flat_qcow2(path: Path) -> None:
        """Only independent qcow2 sources; no backing chain can go stale."""
        try:
            result = subprocess.run(("qemu-img", "info", "--output=json", str(path)),
                                    check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
            data = json.loads(result.stdout) if result.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
            raise VmBaselineError("QEMU source format cannot be verified") from error
        _need(isinstance(data, dict) and data.get("format") == "qcow2" and
              not data.get("backing-filename") and not data.get("full-backing-filename"),
              "QEMU baseline requires an independent qcow2 without a backing chain")

    def copy(self, source: Path, destination: Path) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                                getattr(os, "O_NONBLOCK", 0))
        except OSError as error:
            raise VmBaselineError("QEMU source cannot be opened safely") from error
        try:
            info = os.fstat(source_fd)
            _need(stat.S_ISREG(info.st_mode), "QEMU source is not a regular file")
            target_fd = os.open(destination, flags, 0o400)
            try:
                with os.fdopen(source_fd, "rb") as origin, os.fdopen(target_fd, "wb") as target:
                    source_fd = -1
                    while chunk := origin.read(_CHUNK):
                        target.write(chunk)
                    target.flush()
                    os.fsync(target.fileno())
                after = os.stat(source, follow_symlinks=False)
                _need((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) ==
                      (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
                      "QEMU source changed during baseline copy")
            except BaseException:
                if target_fd >= 0:
                    try:
                        os.close(target_fd)
                    except OSError:
                        pass
                raise
        except OSError as error:
            raise VmBaselineError("QEMU baseline copy failed") from error
        finally:
            if source_fd >= 0:
                os.close(source_fd)

    def overlay(self, backing: Path, destination: Path) -> None:
        self.runner(("qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(backing), str(destination)))


class BaselineManager:
    def __init__(self, *, root: Path, providers: Mapping[str, Provider]):
        self.root = Path(root)
        _safe_path(self.root, self.root, exists=True, kind="dir")
        private = os.stat(self.root, follow_symlinks=False)
        _need(private.st_uid == os.getuid() and private.st_mode & 0o077 == 0,
              "baseline store must be owned and private")
        _need(set(providers) <= {"tart", "qemu"} and all(
            isinstance(p, Provider) and p.kind == kind for kind, p in providers.items()),
            "baseline provider configuration is invalid")
        self.providers = dict(providers)

    def _provider(self, kind: Any) -> Provider:
        _need(isinstance(kind, str) and kind in self.providers, "baseline provider is not configured")
        return self.providers[kind]

    def _baseline_dir(self, kind: str, name: str) -> Path:
        return self.root / "baselines" / kind / _name(name)

    def capture(self, *, provider: str, source_id: str, baseline: str, generation: str) -> dict[str, Any]:
        typed = self._provider(provider)
        _name(baseline)
        _name(generation)
        binding, observed = typed.admitted(source_id)
        _need(generation == binding.generation, "requested source generation is stale")
        folder = self._baseline_dir(provider, baseline)
        folder.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _safe_path(folder, self.root, exists=False)
        folder.mkdir(mode=0o700)
        intent = {"version": 1, "provider": provider, "sourceId": source_id,
                  "generation": generation, "baseline": baseline, "state": "capture-pending"}
        _write_new(folder / "intent.json", intent)
        # Two-phase admission: no provider effect occurs until this second observation.
        _, fresh = typed.admitted(source_id)
        _need(fresh == observed, "provider observation changed before baseline capture")
        source = Path(binding.path)
        before = typed.source_hash(source)
        if provider == "tart":
            assert isinstance(typed, TartProvider)
            dest_name = "vcb-" + baseline
            dest = typed.source_root / dest_name
            _safe_path(dest, typed.source_root, exists=False)
            _need(typed.admitted(source_id)[1] == fresh, "provider observation changed immediately before clone")
            typed.clone(binding.provider_name, dest_name)
            _safe_path(dest, typed.source_root, exists=True, kind="dir")
            captured = _tree_hash(dest)
            _seal_tree(dest)
        else:
            assert isinstance(typed, QemuProvider)
            _need(source.suffix == ".qcow2", "QEMU source must be qcow2")
            typed.inspect_flat_qcow2(source)
            dest = folder / "disk.qcow2"
            _need(typed.admitted(source_id)[1] == fresh, "provider observation changed immediately before copy")
            typed.copy(source, dest)
            typed.inspect_flat_qcow2(dest)
            captured = _file_hash(dest)[1]
            _need(captured == before, "QEMU baseline bytes differ from source")
        _need(typed.source_hash(source) == before, "VM source changed during capture")
        _, after = typed.admitted(source_id)
        _need(after == fresh, "provider observation changed during baseline capture")
        raw = {"version": 1, "provider": provider, "baseline": baseline, "sourceId": source_id,
               "generation": generation, "sourcePath": str(source), "sourceSha256": before,
               "baselinePath": str(dest), "baselineSha256": captured,
               "accessReceipt": fresh.access_receipt, "dependencyReceipt": fresh.dependency_receipt,
               "fingerprint": _fingerprint(fresh.fingerprint)}
        manifest = {**raw, "manifestSha256": _digest_json(raw)}
        _write_new(folder / "manifest.json", manifest)
        os.chmod(folder / "manifest.json", 0o400)
        os.chmod(folder, 0o500)
        return manifest

    def verify(self, value: Mapping[str, Any]) -> dict[str, Any]:
        _need(isinstance(value, Mapping) and value.get("version") == 1, "baseline manifest schema is invalid")
        manifest = dict(value)
        claimed = manifest.pop("manifestSha256", None)
        _need(_sha(claimed, "manifest hash") == _digest_json(manifest), "baseline manifest changed")
        kind = manifest.get("provider")
        typed = self._provider(kind)
        name = _name(manifest.get("baseline"))
        source_id = _name(manifest.get("sourceId"))
        _name(manifest.get("generation"))
        folder = self._baseline_dir(kind, name)
        path = folder / "manifest.json"
        _safe_path(path, self.root, exists=True, kind="file")
        _need(stat.S_IMODE(os.stat(folder, follow_symlinks=False).st_mode) == 0o500 and
              stat.S_IMODE(os.stat(path, follow_symlinks=False).st_mode) == 0o400,
              "baseline manifest is no longer sealed")
        _need(_read_json(path) == value, "baseline manifest is not registered")
        binding, observed = typed.admitted(source_id)
        _need(manifest.get("generation") == binding.generation and manifest.get("sourcePath") == str(binding.path),
              "baseline source generation is stale")
        _need(typed.source_hash(Path(binding.path)) == manifest.get("sourceSha256"),
              "baseline source bytes changed")
        _need(manifest.get("accessReceipt") == observed.access_receipt and
              manifest.get("dependencyReceipt") == observed.dependency_receipt and
              manifest.get("fingerprint") == _fingerprint(observed.fingerprint),
              "baseline access or dependency provenance changed")
        baseline_path = Path(manifest.get("baselinePath", ""))
        if kind == "tart":
            expected = typed.source_root / ("vcb-" + name)
            _need(baseline_path == expected, "Tart baseline path changed")
            _safe_path(baseline_path, typed.source_root, exists=True, kind="dir")
            content = _tree_hash(baseline_path)
            _assert_sealed_tree(baseline_path)
        else:
            expected = folder / "disk.qcow2"
            _need(baseline_path == expected, "QEMU baseline path changed")
            _safe_path(baseline_path, self.root, exists=True, kind="file")
            assert isinstance(typed, QemuProvider)
            typed.inspect_flat_qcow2(baseline_path)
            _need(stat.S_IMODE(os.stat(baseline_path, follow_symlinks=False).st_mode) == 0o400,
                  "QEMU baseline is no longer sealed")
            content = _file_hash(baseline_path)[1]
        _need(content == manifest.get("baselineSha256"), "baseline bytes changed")
        return dict(value)

    def restore(self, value: Mapping[str, Any], *, destination: str) -> dict[str, Any]:
        manifest = self.verify(value)
        kind = manifest["provider"]
        typed = self._provider(kind)
        name = _name(destination)
        folder = self.root / "restores" / kind / name
        folder.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _safe_path(folder, self.root, exists=False)
        folder.mkdir(mode=0o700)
        _write_new(folder / "intent.json", {"version": 1, "provider": kind, "destination": name,
                                            "baselineSha256": manifest["manifestSha256"], "state": "restore-pending"})
        # Reverify immediately before the provider operation, including fresh provenance.
        self.verify(value)
        baseline_path = Path(manifest["baselinePath"])
        if kind == "tart":
            assert isinstance(typed, TartProvider)
            dest_name = "vcr-" + name
            dest = typed.source_root / dest_name
            _safe_path(dest, typed.source_root, exists=False)
            typed.clone("vcb-" + manifest["baseline"], dest_name)
            _safe_path(dest, typed.source_root, exists=True, kind="dir")
            _unseal_tree(dest)
        else:
            assert isinstance(typed, QemuProvider)
            dest = folder / "disk.qcow2"
            _safe_path(dest, self.root, exists=False)
            typed.overlay(baseline_path, dest)
            _safe_path(dest, self.root, exists=True, kind="file")
        result = {"version": 1, "provider": kind, "destination": name, "path": str(dest),
                  "baselineManifestSha256": manifest["manifestSha256"], "state": "disposable-created"}
        _write_new(folder / "result.json", result)
        return result


def _digest_json(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _write_new(path: Path, value: Mapping[str, Any]) -> None:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    _need(len(payload) <= 8192, "baseline record is too large")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise VmBaselineError("baseline record cannot be written exclusively") from error


def _read_json(path: Path) -> Any:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as stream:
            _need(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "baseline record is not regular")
            data = stream.read(8193)
        _need(len(data) <= 8192, "baseline record is too large")
        return json.loads(data)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VmBaselineError("baseline record cannot be read safely") from error


def _seal_tree(root: Path) -> None:
    """Make a completed Tart clone private and read-only before publishing it."""
    for directory, names, files in os.walk(root, topdown=False, followlinks=False, onerror=_walk_error):
        base = Path(directory)
        for name in files:
            child = base / name
            _need(stat.S_ISREG(os.lstat(child).st_mode), "Tart clone contains an unsafe file")
            os.chmod(child, 0o400, follow_symlinks=False)
        for name in names:
            child = base / name
            _need(stat.S_ISDIR(os.lstat(child).st_mode), "Tart clone contains an unsafe directory")
            os.chmod(child, 0o500, follow_symlinks=False)
        os.chmod(base, 0o500, follow_symlinks=False)


def _unseal_tree(root: Path) -> None:
    """A disposable Tart clone must be writable while its source stays sealed."""
    for directory, names, files in os.walk(root, topdown=False, followlinks=False, onerror=_walk_error):
        base = Path(directory)
        for name in files:
            child = base / name
            _need(stat.S_ISREG(os.lstat(child).st_mode), "Tart restore contains an unsafe file")
            os.chmod(child, 0o600, follow_symlinks=False)
        for name in names:
            child = base / name
            _need(stat.S_ISDIR(os.lstat(child).st_mode), "Tart restore contains an unsafe directory")
            os.chmod(child, 0o700, follow_symlinks=False)
        os.chmod(base, 0o700, follow_symlinks=False)


def _assert_sealed_tree(root: Path) -> None:
    for directory, names, files in os.walk(root, followlinks=False, onerror=_walk_error):
        base = Path(directory)
        _need(stat.S_IMODE(os.lstat(base).st_mode) == 0o500, "Tart baseline directory is no longer sealed")
        for name in names:
            child = base / name
            _need(stat.S_ISDIR(os.lstat(child).st_mode), "Tart baseline contains an unsafe directory")
        for name in files:
            child = base / name
            _need(stat.S_ISREG(os.lstat(child).st_mode) and stat.S_IMODE(os.lstat(child).st_mode) == 0o400,
                  "Tart baseline file is no longer sealed")

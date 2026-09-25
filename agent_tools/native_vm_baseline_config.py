"""Configured, read-only admission for local native VM baseline operations.

The private host inventory selects sources. A separately produced preparation
receipt binds source bytes, generation, access/dependency evidence and installer
job state. This adapter validates it and reobserves the provider; it does not
produce readiness receipts, start/stop VMs, or infer missing evidence as success.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Mapping

try:
    from . import native_vm_baseline as baseline, ssh_transport
except ImportError:  # MCP script fallback
    import native_vm_baseline as baseline  # type: ignore[no-redef]
    import ssh_transport  # type: ignore[no-redef]

_SHA = re.compile(r"^[0-9a-f]{64}$")
_MAX_FILE = 1_048_576
_SOURCE_FIELDS = {"provider", "sourceRoot", "sourcePath", "generation", "providerName",
                  "preparationReceiptPath", "accessReceiptPath", "dependencyReceiptPath",
                  "installerJobReceiptPath"}


class BaselineConfigError(baseline.VmBaselineError):
    pass


def _need(value: bool, message: str) -> None:
    if not value:
        raise BaselineConfigError(message)


def _sha(value: Any, name: str) -> str:
    _need(isinstance(value, str) and _SHA.fullmatch(value) is not None, f"{name} is not an exact SHA-256")
    return value


def _absolute(value: Any) -> Path:
    _need(isinstance(value, str) and value.startswith("/") and "\x00" not in value,
          "configured baseline path is unsafe")
    _need(not any(part in (".", "..", "") for part in value.split("/")[1:]),
          "configured baseline path contains traversal")
    path = Path(value)
    current = Path("/")
    for part in path.parts[1:]:
        current /= part
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            continue
        _need(not stat.S_ISLNK(mode), "configured baseline path contains a symlink")
    return path


def _private_bytes(path: Path) -> bytes:
    path = _absolute(str(path))
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                  stat.S_IMODE(info.st_mode) == 0o600,
                  "baseline proof must be an owned private regular file")
            data = stream.read(_MAX_FILE + 1)
            _need(len(data) <= _MAX_FILE, "baseline proof is too large")
            return data
    except OSError as error:
        raise BaselineConfigError("baseline proof is missing or unreadable") from error


def _private_json(path: Path) -> tuple[Mapping[str, Any], str]:
    data = _private_bytes(path)
    try:
        value = json.loads(data, object_pairs_hook=ssh_transport._reject_duplicate_keys)
    except (json.JSONDecodeError, UnicodeError, ssh_transport.SshConfigError) as error:
        raise BaselineConfigError("baseline proof is invalid JSON") from error
    _need(isinstance(value, dict), "baseline proof must be an object")
    return value, hashlib.sha256(data).hexdigest()


def _fixed_tart_stopped(name: str) -> bool:
    try:
        completed = subprocess.run(("tart", "list", "--format", "json"), check=False,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        _need(completed.returncode == 0 and len(completed.stdout) <= _MAX_FILE,
              "Tart list observation is unavailable")
        values = json.loads(completed.stdout)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        raise BaselineConfigError("Tart list observation is unavailable") from error
    _need(isinstance(values, list), "Tart list observation is malformed")
    matches = [item for item in values if isinstance(item, dict) and item.get("Name") == name]
    _need(len(matches) == 1, "configured Tart source is missing or ambiguous")
    state = matches[0].get("State")
    _need(isinstance(state, str), "Tart source state is unknown")
    return state.lower() == "stopped"


def _fixed_qemu_stopped(source: Path) -> bool:
    """Reject a QEMU process holding this source inode; uncertain census fails."""
    expected = os.stat(source, follow_symlinks=False)
    if sys.platform.startswith("linux"):
        try:
            entries = os.listdir("/proc")
        except OSError as error:
            raise BaselineConfigError("QEMU process inventory is unavailable") from error
        for entry in entries:
            if not entry.isdigit():
                continue
            pid = int(entry)
            process = Path("/proc") / entry
            try:
                name = (process / "comm").read_text(encoding="ascii").strip()
            except FileNotFoundError:
                continue
            except (OSError, UnicodeError) as error:
                raise BaselineConfigError("QEMU process inventory is incomplete") from error
            if not name.startswith("qemu-system-"):
                continue
            try:
                before = _linux_start_ticks(process)
                descriptors = os.listdir(process / "fd")
                for descriptor in descriptors:
                    try:
                        info = os.stat(process / "fd" / descriptor)
                    except FileNotFoundError:
                        continue
                    if (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino):
                        return False
                after = _linux_start_ticks(process)
                _need(before is not None and before == after, "QEMU process generation changed")
            except OSError as error:
                raise BaselineConfigError("QEMU file-descriptor observation is incomplete") from error
        return True
    if sys.platform == "darwin":
        try:
            listed = subprocess.run(("ps", "-axo", "pid=,comm="), check=False,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise BaselineConfigError("QEMU process inventory is unavailable") from error
        _need(listed.returncode == 0 and len(listed.stdout) <= 8 * _MAX_FILE,
              "QEMU process inventory is incomplete")
        for line in listed.stdout.decode("utf-8", errors="replace").splitlines():
            parts = line.strip().split(None, 1)
            _need(len(parts) == 2 and parts[0].isdigit(), "QEMU process inventory is malformed")
            pid, command = parts
            if not Path(command).name.startswith("qemu-system-"):
                continue
            before = _mac_start_time(pid)
            try:
                opened = subprocess.run(("lsof", "-Fpn", "-p", pid), check=False,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            except (OSError, subprocess.TimeoutExpired) as error:
                raise BaselineConfigError("QEMU open-file observation is unavailable") from error
            _need(opened.returncode == 0 and len(opened.stdout) <= 8 * _MAX_FILE,
                  "QEMU open-file observation is incomplete")
            for field in opened.stdout.decode("utf-8", errors="replace").splitlines():
                if not field.startswith("n/"):
                    continue
                try:
                    info = os.stat(field[1:])
                except (OSError, ValueError):
                    continue  # A socket or unrelated transient path.
                if (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino):
                    return False
            _need(before and before == _mac_start_time(pid), "QEMU process generation changed")
        return True
    raise BaselineConfigError("QEMU stopped observation is unsupported on this coordinator")


def _linux_start_ticks(process: Path) -> int | None:
    try:
        raw = (process / "stat").read_text(encoding="ascii")
        return int(raw.rsplit(")", 1)[1].split()[19])
    except (OSError, ValueError, IndexError, UnicodeError):
        return None


def _mac_start_time(pid: str) -> str:
    try:
        result = subprocess.run(("ps", "-p", pid, "-o", "lstart="), check=False,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BaselineConfigError("QEMU process generation is unavailable") from error
    _need(result.returncode == 0, "QEMU process generation is unavailable")
    return result.stdout.decode("ascii", errors="replace").strip()


def _job_gone(value: Mapping[str, Any]) -> bool:
    state = value.get("state")
    if state == "none":
        _need(set(value) == {"schemaVersion", "sourceId", "generation", "sourceSha256", "state"},
              "no-job receipt has unsupported fields")
        return True
    _need(state == "terminal" and set(value) ==
          {"schemaVersion", "sourceId", "generation", "sourceSha256", "state", "pid", "exitCode"},
          "installer job is active, unknown, or malformed")
    pid = value["pid"]
    _need(type(pid) is int and pid > 0 and type(value["exitCode"]) is int,
          "terminal installer job identity is invalid")
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError as error:
        raise BaselineConfigError("installer job process status is unknown") from error
    return False  # Even a reused PID blocks conservatively.


def _proofs(entry: Mapping[str, Any], source_id: str, provider: str,
            generation: str, source_path: Path, source_sha: str) -> tuple[str, str, Mapping[str, str], str]:
    paths = {key: _absolute(entry[key]) for key in ("preparationReceiptPath", "accessReceiptPath",
                                                   "dependencyReceiptPath", "installerJobReceiptPath")}
    records = {key: _private_json(path) for key, path in paths.items()}
    prep, _ = records["preparationReceiptPath"]
    access, access_sha = records["accessReceiptPath"]
    dependency, dependency_sha = records["dependencyReceiptPath"]
    job, job_sha = records["installerJobReceiptPath"]
    identity = {"sourceId": source_id, "generation": generation, "sourceSha256": source_sha}
    for record in (access, dependency, job):
        _need(record.get("schemaVersion") == 1 and all(record.get(k) == v for k, v in identity.items()),
              "baseline proof does not bind exact source bytes and generation")
    _need(access.get("state") == "ready" and set(access) ==
          {"schemaVersion", "sourceId", "generation", "sourceSha256", "state", "evidencePath", "evidenceSha256"},
          "access readiness proof is absent or malformed")
    _need(_evidence_hash(_absolute(access.get("evidencePath"))) == _sha(access.get("evidenceSha256"), "access evidence"),
          "access evidence bytes changed")
    _need(dependency.get("state") == "ready" and set(dependency) ==
          {"schemaVersion", "sourceId", "generation", "sourceSha256", "state", "evidencePath", "evidenceSha256", "fingerprint"},
          "dependency readiness proof is absent or malformed")
    _need(_evidence_hash(_absolute(dependency.get("evidencePath"))) == _sha(dependency.get("evidenceSha256"), "dependency evidence"),
          "dependency evidence bytes changed")
    fingerprint = baseline._fingerprint(dependency.get("fingerprint"))
    _need(_job_gone(job), "installer job is still present or unknown")
    _need(set(prep) == {"schemaVersion", "provider", "sourceId", "generation", "sourcePath",
                          "sourceSha256", "accessReceiptSha256", "dependencyReceiptSha256",
                          "installerJobReceiptSha256"} and prep.get("schemaVersion") == 1 and
          prep.get("provider") == provider and prep.get("sourcePath") == str(source_path) and
          all(prep.get(k) == v for k, v in identity.items()) and
          prep.get("accessReceiptSha256") == access_sha and
          prep.get("dependencyReceiptSha256") == dependency_sha and
          prep.get("installerJobReceiptSha256") == job_sha,
          "preparation receipt does not bind verified readiness and job evidence")
    return access_sha, dependency_sha, fingerprint, job["state"]


def _configured_providers(root: Path | str) -> tuple[Path, dict[str, baseline.Provider]]:
    checkout = Path(root).resolve(strict=True)
    inventory, _ = _private_json(checkout / ssh_transport.CONFIG_FILENAME)
    _need(inventory.get("schemaVersion") == 1 and isinstance(inventory.get("hosts"), dict),
          "private VM inventory schema is invalid")
    config = inventory.get("nativeBaselines")
    _need(isinstance(config, dict) and set(config) == {"schemaVersion", "sources"} and
          config.get("schemaVersion") == 1 and isinstance(config.get("sources"), dict) and config["sources"],
          "native baselines are not configured")
    catalog: dict[str, dict[str, Any]] = {}
    for source_id, entry in config["sources"].items():
        baseline._name(source_id)
        _need(isinstance(entry, dict) and set(entry) == _SOURCE_FIELDS, "baseline source config is malformed")
        kind = entry["provider"]
        _need(kind in ("tart", "qemu"), "baseline provider is unsupported")
        source_root = _absolute(entry["sourceRoot"])
        source_path = _absolute(entry["sourcePath"])
        _need(source_path.parent == source_root and source_path != source_root,
              "baseline source must be a direct child of its owned root")
        baseline._name(entry["generation"])
        _need(isinstance(entry["providerName"], str) and baseline._PROVIDER_NAME.fullmatch(entry["providerName"]) is not None,
              "baseline provider name is unsafe")
        if kind == "tart":
            _need(source_path.name == entry["providerName"], "Tart source path and VM name disagree")
        catalog[source_id] = {"entry": entry, "kind": kind, "source_root": source_root,
                              "source_path": source_path}
    providers: dict[str, baseline.Provider] = {}
    for kind in ("tart", "qemu"):
        selected = {key: val for key, val in catalog.items() if val["kind"] == kind}
        if not selected:
            continue
        roots = {val["source_root"] for val in selected.values()}
        _need(len(roots) == 1, "one provider must use one owned source root")
        source_root = next(iter(roots))
        sources = {source_id: baseline.SourceBinding(source_id, val["source_path"],
                                                     val["entry"]["generation"], val["entry"]["providerName"])
                   for source_id, val in selected.items()}

        def observe(source_id: str, *, selected=selected, kind=kind, source_root=source_root):
            value = selected[source_id]
            entry = value["entry"]
            source_path = value["source_path"]
            baseline._safe_path(source_path, source_root, exists=True,
                                kind="dir" if kind == "tart" else "file")
            source_stat = os.stat(source_path, follow_symlinks=False)
            _need(source_stat.st_uid == os.getuid() and source_stat.st_mode & 0o022 == 0,
                  "configured source is unowned or writable by another user")
            stopped = _fixed_tart_stopped(entry["providerName"]) if kind == "tart" else _fixed_qemu_stopped(source_path)
            _need(stopped, "configured source VM is running or state is unknown")
            if kind == "qemu":
                baseline.QemuProvider.inspect_flat_qcow2(source_path)
            source_sha = baseline._tree_hash(source_path) if kind == "tart" else baseline._file_hash(source_path)[1]
            access_sha, dependency_sha, fingerprint, job_state = _proofs(
                entry, source_id, kind, entry["generation"], source_path, source_sha)
            return baseline.SourceObservation(source_id, entry["generation"], source_path,
                                              True, stopped, True, job_state,
                                              access_sha, dependency_sha, fingerprint)

        constructor = baseline.TartProvider if kind == "tart" else baseline.QemuProvider
        providers[kind] = constructor(source_root=source_root, sources=sources, observe=observe)
    return checkout, providers


def configured_manager(root: Path | str, *, create_store: bool = False) -> baseline.BaselineManager:
    checkout, providers = _configured_providers(root)
    store = checkout / ".rag_index" / "native-vm-baselines"
    if create_store:
        store.parent.mkdir(mode=0o700, exist_ok=True)
        store.mkdir(mode=0o700, exist_ok=True)
    else:
        _need(store.is_dir() and not store.is_symlink(), "baseline store does not exist")
    return baseline.BaselineManager(root=store, providers=providers)


def handle(root: Path | str, action: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    _need(isinstance(inputs, Mapping), "baseline inputs must be an object")
    if action == "baseline-preflight":
        _need(set(inputs) == {"provider", "sourceId"}, "baseline preflight fields are invalid")
        _, providers = _configured_providers(root)
        kind = inputs["provider"]
        _need(isinstance(kind, str) and kind in providers, "baseline provider is not configured")
        provider = providers[kind]
        binding, observation = provider.admitted(inputs["sourceId"])
        return {"ready": True, "provider": provider.kind, "sourceId": binding.source_id,
                "generation": binding.generation, "sourcePath": str(binding.path),
                "sourceSha256": provider.source_hash(binding.path),
                "accessReceiptSha256": observation.access_receipt,
                "dependencyReceiptSha256": observation.dependency_receipt}
    if action == "baseline-capture":
        _need(set(inputs) == {"provider", "sourceId", "baseline", "generation"},
              "baseline capture fields are invalid")
        manager = configured_manager(root, create_store=True)
        return manager.capture(provider=inputs["provider"], source_id=inputs["sourceId"],
                               baseline=inputs["baseline"], generation=inputs["generation"])
    if action == "baseline-verify":
        _need(set(inputs) == {"manifest"}, "baseline verify fields are invalid")
        return configured_manager(root).verify(inputs["manifest"])
    if action == "baseline-restore":
        _need(set(inputs) == {"manifest", "destination"}, "baseline restore fields are invalid")
        return configured_manager(root).restore(inputs["manifest"], destination=inputs["destination"])
    raise BaselineConfigError("baseline action is unsupported")


def _evidence_hash(path: Path) -> str:
    path = _absolute(str(path))
    try:
        info = os.lstat(path)
    except OSError as error:
        raise BaselineConfigError("baseline evidence file is missing") from error
    _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o022 == 0,
          "baseline evidence file is not owned and stable")
    return baseline._file_hash(path)[1]

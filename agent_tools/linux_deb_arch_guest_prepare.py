"""One-shot preparation admission for fixed disposable Ubuntu and Arch roles.

This module owns immutable host intent, source/package preflight, frozen
transfer inputs, and the receipt schema. A guest effect requires the reviewed
fixed remote driver to be injected; absent it, start blocks before any journal
or guest effect. Status never retries a submission whose response was lost.
"""

from __future__ import annotations

from dataclasses import dataclass
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import io
from typing import Any, Mapping, Protocol
from uuid import UUID

from . import linux_deb_arch_acceptance as acceptance


_SHA = re.compile(r"[0-9a-f]{40}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ARTIFACT = re.compile(r"sha256-[0-9a-f]{64}\Z")
_REQUEST_ARTIFACTS = {"fixtureReceipt", "basePackage", "targetPackage", "bundleManifest"}
_KINDS = {"fixtureReceipt": "fixture-receipt", "basePackage": "package",
          "targetPackage": "package", "bundleManifest": "native-scenario-manifest"}
_JOURNAL = Path(".rag_index/linux-deb-arch-guest-prepare")


class GuestPreparationError(ValueError):
    pass


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise GuestPreparationError(reason)


def _uuid(value: Any) -> bool:
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except (TypeError, ValueError):
        return False


@dataclass(frozen=True)
class Request:
    profile: str
    distribution: str
    correlation_id: str
    source_sha: str
    artifact_ids: Mapping[str, str]
    guest_role: str
    guest_port: int

    @classmethod
    def parse(cls, raw: Mapping[str, Any]) -> "Request":
        _need(isinstance(raw, Mapping) and set(raw) ==
              {"profile", "distribution", "correlationId", "sourceSha", "artifactIds"},
              "Guest preparation request fields are not exact")
        _need(isinstance(raw["profile"], str) and isinstance(raw["distribution"], str),
              "Guest preparation role is not fixed")
        key = (raw["profile"], raw["distribution"])
        _need(key in acceptance._ROLES, "Guest preparation role is not fixed")
        _need(_uuid(raw["correlationId"]) and isinstance(raw["sourceSha"], str) and
              _SHA.fullmatch(raw["sourceSha"]) is not None,
              "Guest preparation source or correlation is invalid")
        artifacts = raw["artifactIds"]
        _need(isinstance(artifacts, Mapping) and set(artifacts) == _REQUEST_ARTIFACTS and
              all(isinstance(value, str) and _ARTIFACT.fullmatch(value) for value in artifacts.values()),
              "Guest preparation artifacts are not exact")
        role, port = acceptance._ROLES[key]
        return cls(key[0], key[1], raw["correlationId"], raw["sourceSha"],
                   dict(sorted(artifacts.items())), role, port)

    def public_mapping(self) -> dict[str, Any]:
        return {"profile": self.profile, "distribution": self.distribution,
                "correlationId": self.correlation_id, "sourceSha": self.source_sha,
                "artifactIds": dict(self.artifact_ids), "guestRole": self.guest_role,
                "guestPort": self.guest_port}


def preflight(root: Path | str, request: Request) -> dict[str, Any]:
    """Read only: bind frozen package inputs before any QEMU or guest step."""
    root = Path(root).resolve(strict=True)
    head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                          capture_output=True, text=True, timeout=10, check=False)
    _need(head.returncode == 0 and head.stdout.strip() == request.source_sha,
          "Guest preparation source differs from HEAD")
    dirty = subprocess.run(["git", "--no-optional-locks", "-c", "core.fsmonitor=false",
                            "-c", "core.untrackedCache=false", "-C", str(root),
                            "status", "--porcelain=v1",
                            "--untracked-files=all"], capture_output=True, text=True,
                           timeout=10, check=False)
    _need(dirty.returncode == 0 and dirty.stdout == "", "Guest preparation source is dirty")
    captured = {key: acceptance._verified_artifact(root, identifier, _KINDS[key], request.source_sha)
                for key, identifier in request.artifact_ids.items()}
    fixture = acceptance._fixture(request, captured)
    acceptance._bundle(captured)
    _need(request.distribution in ("ubuntu", "arch") and request.guest_role in
          ("ubuntu-fresh", "ubuntu-update", "arch-update", "arch-rollback"),
          "Guest preparation role differs")
    return {"inputsVerified": True, "sourceSha": request.source_sha, "guestRole": request.guest_role,
            "guestPort": request.guest_port, "fixture": fixture,
            "artifactIds": dict(request.artifact_ids), "nativeActionAllowed": False}


def _file_digest(path: Path, maximum: int) -> tuple[int, str]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        _need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
              0 < before.st_size <= maximum, "Preparation package file is unsafe")
        digest = hashlib.sha256()
        size = 0
        while block := os.read(fd, 1024 * 1024):
            digest.update(block)
            size += len(block)
        after = os.fstat(fd)
        _need(size == before.st_size and
              (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
              (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
              "Preparation package changed")
        return size, digest.hexdigest()
    finally:
        os.close(fd)


def _read_exact(path: Path, expected_sha256: str, maximum: int) -> bytes:
    """Read one immutable local artifact through a no-follow descriptor."""
    _need(isinstance(expected_sha256, str) and _HASH.fullmatch(expected_sha256) is not None,
          "Preparation expected digest is invalid")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        _need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
              0 < before.st_size <= maximum, "Preparation transfer file is unsafe")
        content = bytearray()
        while chunk := os.read(fd, min(1024 * 1024, before.st_size + 1 - len(content))):
            content.extend(chunk)
            _need(len(content) <= maximum, "Preparation transfer file exceeds bound")
        after = os.fstat(fd)
        _need(len(content) == before.st_size and
              (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
              (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) and
              hashlib.sha256(content).hexdigest() == expected_sha256,
              "Preparation transfer file changed")
        return bytes(content)
    finally:
        os.close(fd)


def _tracked_bytes(root: Path, source_sha: str, relative: str) -> bytes:
    _need(re.fullmatch(r"(?:scripts|agent_tools)/[A-Za-z0-9_.-]+", relative) is not None,
          "Preparation tracked script path is invalid")
    committed = subprocess.run(["git", "-C", str(root), "show", source_sha + ":" + relative],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               timeout=15, check=False)
    _need(committed.returncode == 0 and 0 < len(committed.stdout) <= 1_000_000,
          "Preparation tracked script is unavailable")
    return _read_exact(root / relative, hashlib.sha256(committed.stdout).hexdigest(), 1_000_000)


def scoped_fixture_receipt(request: Request, original_raw: bytes,
                           paths: Mapping[str, Path]) -> dict[str, Any]:
    """Derive a truthful one-family server receipt from exact registered bytes."""
    _need(isinstance(original_raw, bytes) and 0 < len(original_raw) <= 256 * 1024 and
          hashlib.sha256(original_raw).hexdigest() ==
          request.artifact_ids["fixtureReceipt"].removeprefix("sha256-"),
          "Preparation original receipt bytes differ")
    try:
        original = json.loads(original_raw)
    except (ValueError, UnicodeError) as error:
        raise GuestPreparationError("Preparation original receipt is invalid") from error
    _need(isinstance(original, Mapping) and isinstance(original.get("builds"), list) and
          len(original["builds"]) == 2 and isinstance(original.get("manifest"), Mapping),
          "Preparation fixture receipt is invalid")
    kind = "deb" if request.distribution == "ubuntu" else "arch-bundle"
    scoped = copy.deepcopy(dict(original))
    for index, label in enumerate(("basePackage", "targetPackage")):
        build = scoped["builds"][index]
        assets = build.get("assets") if isinstance(build, Mapping) else None
        matches = [asset for asset in assets if isinstance(asset, Mapping) and
                   asset.get("packageType") == kind] if isinstance(assets, list) else []
        _need(len(matches) == 1, "Preparation fixture package family is ambiguous")
        asset = matches[0]
        size, digest = _file_digest(paths[label], 1024 * 1024 * 1024)
        _need(size == asset.get("sizeBytes") and digest == asset.get("sha256") and
              request.artifact_ids[label] == "sha256-" + digest,
              "Preparation fixture package bytes differ")
        build["assets"] = [asset]
    _need(original["manifest"].get("assets") == original["builds"][1].get("assets"),
          "Preparation original target manifest differs")
    scoped["manifest"]["assets"] = scoped["builds"][1]["assets"]
    scoped["derivedFrom"] = {"scope": kind + "-only",
                             "sourceSha": request.source_sha,
                             "derivedFromArtifactId": request.artifact_ids["fixtureReceipt"],
                             "derivedFromSha256": hashlib.sha256(original_raw).hexdigest(),
                             "basePackageArtifactId": request.artifact_ids["basePackage"],
                             "targetPackageArtifactId": request.artifact_ids["targetPackage"]}
    return scoped


def worker_intent_bytes(request: Request, fixture: Mapping[str, Any],
                        trust_store_sha256: str | None,
                        harness_sha256: str | None) -> bytes:
    """Canonical immutable input for the separate public native scenario worker."""
    value = {"profile": request.profile, "distribution": request.distribution,
             "guestRole": request.guest_role, "correlationId": request.correlation_id,
             "sourceSha": request.source_sha,
             "sourceFingerprint": fixture["sourceFingerprint"],
             "targetVersion": fixture["targetVersion"],
             "targetSha256": request.artifact_ids["targetPackage"].removeprefix("sha256-"),
             "fixtureReceiptArtifactId": request.artifact_ids["fixtureReceipt"],
             "trustStoreSha256": trust_store_sha256,
             "harnessSha256": harness_sha256}
    _need(all(isinstance(value[key], str) and _HASH.fullmatch(value[key]) for key in
              ("sourceFingerprint", "targetSha256")), "Preparation worker identity is invalid")
    _need((trust_store_sha256 is None) == (request.profile == "fresh-deb-dependencies") and
          (trust_store_sha256 is None or _HASH.fullmatch(trust_store_sha256) is not None),
          "Preparation trust binding is invalid")
    _need((harness_sha256 is None) == (request.profile == "fresh-deb-dependencies") and
          (harness_sha256 is None or _HASH.fullmatch(harness_sha256) is not None),
          "Preparation harness binding is invalid")
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def transfer_bundle(root: Path | str, request: Request,
                    admitted: Mapping[str, Any]) -> tuple[bytes, dict[str, Any]]:
    """Build a bounded, deterministic, hash-inventoried transfer; no remote effect."""
    root = Path(root).resolve(strict=True)
    _need(admitted.get("inputsVerified") is True and admitted.get("sourceSha") == request.source_sha
          and admitted.get("guestRole") == request.guest_role and
          admitted.get("artifactIds") == request.artifact_ids and
          isinstance(admitted.get("fixture"), Mapping), "Preparation transfer is not admitted")
    captured = {key: acceptance._verified_artifact(root, identifier, _KINDS[key], request.source_sha)
                for key, identifier in request.artifact_ids.items()}
    fixture = acceptance._fixture(request, captured)
    _need(fixture == admitted["fixture"], "Preparation fixture changed after admission")
    acceptance._bundle(captured)
    original = captured["fixtureReceipt"]["path"].read_bytes()
    scoped = scoped_fixture_receipt(request, original,
                                    {key: captured[key]["path"] for key in ("basePackage", "targetPackage")})
    package_kind = "deb" if request.distribution == "ubuntu" else "arch-bundle"
    target_asset = [entry for entry in scoped["manifest"]["assets"]
                    if entry.get("packageType") == package_kind]
    base_asset = [entry for entry in scoped["builds"][0]["assets"]
                  if entry.get("packageType") == package_kind]
    _need(len(target_asset) == 1 and isinstance(target_asset[0].get("fileName"), str) and
          re.fullmatch(r"[A-Za-z0-9_.-]{1,160}", target_asset[0]["fileName"]) is not None and
          target_asset[0]["fileName"] not in {".", ".."},
          "Preparation target package name is unsafe")
    _need(len(base_asset) == 1 and isinstance(base_asset[0].get("fileName"), str) and
          re.fullmatch(r"[A-Za-z0-9_.-]{1,160}", base_asset[0]["fileName"]) is not None and
          base_asset[0]["fileName"] not in {".", ".."},
          "Preparation base package name is unsafe")
    extension = "deb" if request.distribution == "ubuntu" else "tar.gz"
    target_bytes = _read_exact(captured["targetPackage"]["path"],
                               request.artifact_ids["targetPackage"].removeprefix("sha256-"),
                               1024 * 1024 * 1024)
    base_bytes = _read_exact(captured["basePackage"]["path"],
                             request.artifact_ids["basePackage"].removeprefix("sha256-"),
                             1024 * 1024 * 1024)
    scoped_raw = (json.dumps(scoped, sort_keys=True, separators=(",", ":")) + "\n").encode()
    files: dict[str, bytes] = {
        "guest/base." + extension: base_bytes,
        "guest/target." + extension: target_bytes,
        "guest/fixture/fixture-receipt.json": scoped_raw,
        "guest/fixture/packages/base/" + base_asset[0]["fileName"]: base_bytes,
        "guest/fixture/packages/target/" + target_asset[0]["fileName"]: target_bytes,
        "host/prepare_linux_install_vm.py": _tracked_bytes(root, request.source_sha,
                                                             "scripts/prepare_linux_install_vm.py"),
        "host/fixture_environment.py": _tracked_bytes(root, request.source_sha,
                                                       "scripts/fixture_environment.py"),
        "host/worker.py": _tracked_bytes(root, request.source_sha,
                                         "agent_tools/linux_deb_arch_guest_prepare_remote.py"),
        "guest/agent_tools/linux_deb_arch_guest_prepare_remote.py":
            _tracked_bytes(root, request.source_sha, "agent_tools/linux_deb_arch_guest_prepare_remote.py"),
        "guest/agent_tools/linux_deb_arch_native_driver.py":
            _tracked_bytes(root, request.source_sha, "agent_tools/linux_deb_arch_native_driver.py"),
        "guest/agent_tools/linux_deb_arch_rollback.py":
            _tracked_bytes(root, request.source_sha, "agent_tools/linux_deb_arch_rollback.py"),
    }
    for extra in ("macos_packaging_jdk_preflight.py", "rpm_public_update.py",
                  "install_arch_desktop_update.sh"):
        files["guest/scripts/" + extra] = _tracked_bytes(root, request.source_sha,
                                                          "scripts/" + extra)
    bundle = json.loads(captured["bundleManifest"]["path"].read_bytes())
    stage = captured["bundleManifest"]["path"].parent
    for entry in bundle["files"]:
        relative = entry["path"]
        source = stage / relative
        size, digest = _file_digest(source, 1_000_000)
        _need(size == entry["sizeBytes"] and digest == entry["sha256"],
              "Preparation native script changed")
        files["guest/" + relative] = _read_exact(source, entry["sha256"], 1_000_000)
    inventory = {name: {"sizeBytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
                 for name, content in sorted(files.items())}
    manifest = {"schemaVersion": 1, "correlationId": request.correlation_id,
                "sourceSha": request.source_sha, "sourceFingerprint": fixture["sourceFingerprint"],
                "guestRole": request.guest_role, "guestPort": request.guest_port,
                "artifactIds": dict(request.artifact_ids), "files": inventory}
    files["transfer-manifest.json"] = (json.dumps(manifest, sort_keys=True,
                                                    separators=(",", ":")) + "\n").encode()
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, content in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o400
            info.mtime = 0
            archive.addfile(info, io.BytesIO(content))
    raw = output.getvalue()
    _need(len(raw) <= 3 * 1024 * 1024 * 1024, "Preparation transfer exceeds bound")
    return raw, manifest


def inspect_arch_base_bundle(path: Path, expected_sha: str, installer_sha: str) -> dict[str, Any]:
    """Reject archive traversal, links and an unrecognized installer before root extraction."""
    _need(isinstance(expected_sha, str) and _HASH.fullmatch(expected_sha) is not None and
          isinstance(installer_sha, str) and _HASH.fullmatch(installer_sha) is not None,
          "Arch bundle expected digest is invalid")
    size, digest = _file_digest(path, 1024 * 1024 * 1024)
    _need(digest == expected_sha, "Arch base bundle bytes differ")
    names: set[str] = set()
    installer = None
    expanded = 0
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            name = member.name.removeprefix("./")
            parts = Path(name).parts
            _need(bool(parts) and parts[0] == "vpn-control-arch-update" and
                  not name.startswith("/") and ".." not in parts and name not in names and
                  (member.isfile() or member.isdir() or member.issym()) and
                  member.size <= 1024 * 1024 * 1024,
                  "Arch base bundle member is unsafe")
            if member.issym():
                target = Path(member.linkname)
                _need(not target.is_absolute() and ".." not in target.parts,
                      "Arch base bundle link is unsafe")
            if member.isfile():
                expanded += member.size
                _need(expanded <= 4 * 1024 * 1024 * 1024,
                      "Arch base bundle expansion exceeds bound")
                if name == "vpn-control-arch-update/install.sh":
                    source = archive.extractfile(member)
                    _need(source is not None and member.size <= 1024 * 1024,
                          "Arch base installer is unsafe")
                    installer = hashlib.sha256(source.read(member.size + 1)).hexdigest()
            names.add(name)
            _need(len(names) <= 100_000, "Arch base bundle inventory exceeds bound")
    _need(installer == installer_sha and
          "vpn-control-arch-update/app/bin/vpn-control" in names and
          "vpn-control-arch-update/sing-box" in names,
          "Arch base bundle installer or launcher differs")
    return {"archiveSha256": digest, "archiveSize": size,
            "installerSha256": installer_sha, "memberCount": len(names)}


def validate_receipt(request: Request, receipt: Mapping[str, Any], fixture: Mapping[str, Any],
                     guest: Mapping[str, Any], *, guest_manifest_artifact_id: str,
                     worker_intent_sha256: str, native_worker_sha256: str,
                     rollback_worker_sha256: str) -> dict[str, Any]:
    """Check exactly the native facts consumed by the acceptance adapter."""
    _need(isinstance(receipt, Mapping) and isinstance(guest, Mapping) and
          isinstance(fixture, Mapping), "Preparation evidence is absent")
    keys = {"schemaVersion", "host", "profile", "distribution", "guestRole", "sourceSha",
            "sourceFingerprint", "correlationId", "guestManifestArtifactId",
            "fixtureReceiptArtifactId", "basePackageArtifactId", "targetPackageArtifactId",
            "bundleManifestArtifactId", "qemu", "baseline", "fixture", "publicCli", "safety",
            "stage", "workerIntentSha256", "state"}
    keys.update({"nativeWorkerSha256", "rollbackWorkerSha256"})
    _need(set(receipt) == keys and receipt.get("schemaVersion") == 1 and
          receipt.get("host") == "archlinux" and receipt.get("profile") == request.profile and
          receipt.get("distribution") == request.distribution and
          receipt.get("guestRole") == request.guest_role and
          receipt.get("sourceSha") == request.source_sha and
          receipt.get("sourceFingerprint") == fixture.get("sourceFingerprint") and
          receipt.get("correlationId") == request.correlation_id and receipt.get("state") == "ready" and
          isinstance(guest_manifest_artifact_id, str) and
          _ARTIFACT.fullmatch(guest_manifest_artifact_id) is not None and
          receipt.get("guestManifestArtifactId") == guest_manifest_artifact_id and
          isinstance(worker_intent_sha256, str) and
          _HASH.fullmatch(worker_intent_sha256) is not None and
          receipt.get("workerIntentSha256") == worker_intent_sha256 and
          isinstance(native_worker_sha256, str) and _HASH.fullmatch(native_worker_sha256) is not None and
          isinstance(rollback_worker_sha256, str) and _HASH.fullmatch(rollback_worker_sha256) is not None and
          receipt.get("nativeWorkerSha256") == native_worker_sha256 and
          receipt.get("rollbackWorkerSha256") == rollback_worker_sha256 and
          all(receipt.get(label + "ArtifactId") == request.artifact_ids[label] for label in
              ("fixtureReceipt", "basePackage", "targetPackage", "bundleManifest")),
          "Preparation receipt source or artifacts differ")
    qemu = {"pid": guest.get("qemuPid"), "startTicks": guest.get("qemuStartTicks"),
            "diskDevice": guest.get("diskDevice"), "diskInode": guest.get("diskInode"),
            "sshPort": guest.get("sshPort"), "tree": guest.get("tree")}
    _need(receipt.get("qemu") == qemu and all(type(qemu[name]) is int and qemu[name] > 0
          for name in ("pid", "startTicks", "diskDevice", "diskInode", "sshPort")) and
          qemu["tree"] == "/home/kardinal/vpn-control-install-vm-parity-" + request.guest_role,
          "Preparation QEMU generation differs")
    baseline, safety = receipt.get("baseline"), receipt.get("safety")
    _need(isinstance(baseline, Mapping) and set(baseline) ==
          {"installedBaseVersion", "installedPackageSha256", "codeFingerprint",
           "cleanPackageDatabase", "xdgUtilsAbsent", "desktopDirectoryAbsent"} and
          baseline.get("cleanPackageDatabase") is True and
          safety == {"ownerRuntimeOff": True, "protectedJobsTerminal": True,
                     "rootOwnedStage": True}, "Preparation safety is incomplete")
    if request.profile == "fresh-deb-dependencies":
        _need(all(baseline[key] is None for key in
                  ("installedBaseVersion", "installedPackageSha256", "codeFingerprint")) and
              baseline["xdgUtilsAbsent"] is True and baseline["desktopDirectoryAbsent"] is True and
              receipt.get("fixture") is None and receipt.get("publicCli") is None and
              receipt.get("stage") == "/var/lib/vpn-control-parity/ubuntu-fresh",
              "Fresh DEB preparation is not clean")
    else:
        server = receipt.get("fixture")
        _need(baseline.get("installedBaseVersion") == fixture.get("baseVersion") and
              baseline.get("installedPackageSha256") ==
              request.artifact_ids["basePackage"].removeprefix("sha256-") and
              baseline.get("codeFingerprint") == fixture.get("codeFingerprint") and
              baseline.get("xdgUtilsAbsent") is None and
              baseline.get("desktopDirectoryAbsent") is None and
              receipt.get("stage") == "/var/lib/vpn-control-parity/" + request.guest_role and
          receipt.get("publicCli") ==
              {"polkitReady": True, "ptyReady": True, "credentialReady": True} and
              isinstance(server, Mapping) and set(server) ==
              {"serverPid", "serverStartTicks", "readySha256", "manifestSha256",
               "certificateSha256", "trustStoreSha256", "publicFixtureSha256"} and
              all(type(server[name]) is int and server[name] > 0 for name in
                  ("serverPid", "serverStartTicks")) and
              all(isinstance(server[name], str) and _HASH.fullmatch(server[name]) for name in
                  ("readySha256", "manifestSha256", "certificateSha256", "trustStoreSha256",
                   "publicFixtureSha256")),
              "Update preparation is not exact")
    return dict(receipt)


class FixedDriver(Protocol):
    def submit(self, request: Request, admitted: Mapping[str, Any]) -> Mapping[str, Any]: ...
    def status(self, request: Request) -> Mapping[str, Any]: ...


def _journal_dir(root: Path, *, create: bool) -> Path | None:
    index = root / ".rag_index"
    path = root / _JOURNAL
    if create:
        index.mkdir(mode=0o700, exist_ok=True)
    if not index.exists() and not index.is_symlink():
        return None
    parent = index.lstat()
    _need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid() and
          stat.S_IMODE(parent.st_mode) == 0o700,
          "Preparation journal ancestor is unsafe")
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
    if not path.exists():
        return None
    info = path.lstat()
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
          stat.S_IMODE(info.st_mode) == 0o700, "Preparation journal is unsafe")
    return path


def _read(root: Path, correlation: str) -> dict[str, Any] | None:
    directory = _journal_dir(root, create=False)
    if directory is None:
        return None
    path = directory / (correlation + ".json")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
              stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 8192,
              "Preparation intent journal is unsafe")
        raw = os.read(fd, info.st_size + 1)
        _need(len(raw) == info.st_size, "Preparation intent journal changed")
        value = json.loads(raw)
        _need(isinstance(value, dict) and value.get("correlationId") == correlation,
              "Preparation intent journal differs")
        return value
    finally:
        os.close(fd)


def _save(root: Path, value: Mapping[str, Any]) -> None:
    directory = _journal_dir(root, create=True)
    assert directory is not None
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(directory / (value["correlationId"] + ".json"),
                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _claim_role(root: Path, request: Request) -> bool:
    """Permanently reserve one fixed guest role before its first effect."""
    directory = _journal_dir(root, create=True)
    assert directory is not None
    path = directory / (request.guest_role + ".claim")
    raw = (json.dumps({"guestRole": request.guest_role,
                       "correlationId": request.correlation_id},
                      sort_keys=True, separators=(",", ":")) + "\n").encode()
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return True


def _role_claim_matches(root: Path, request: Request) -> bool:
    directory = _journal_dir(root, create=False)
    if directory is None:
        return False
    try:
        fd = os.open(directory / (request.guest_role + ".claim"),
                     os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return False
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 512):
            return False
        raw = os.read(fd, info.st_size + 1)
        return (len(raw) == info.st_size and json.loads(raw) ==
                {"guestRole": request.guest_role, "correlationId": request.correlation_id})
    except (OSError, ValueError, TypeError):
        return False
    finally:
        os.close(fd)


class Adapter:
    """Journal before an injected fixed driver and never replay an unknown."""

    def __init__(self, root: Path | str, *, driver: FixedDriver | None = None):
        self.root = Path(root).resolve(strict=True)
        self.driver = driver

    def start(self, raw: Mapping[str, Any]) -> dict[str, Any]:
        request = Request.parse(raw)
        if _read(self.root, request.correlation_id) is not None:
            return {"state": "unknown", "correlationId": request.correlation_id,
                    "reason": "already-journaled", "replayAllowed": False}
        admitted = preflight(self.root, request)
        if self.driver is None:
            return {"state": "blocked", "correlationId": request.correlation_id,
                    "reason": "fixed-guest-executor-unavailable", "replayAllowed": False}
        if not _claim_role(self.root, request):
            return {"state": "blocked", "correlationId": request.correlation_id,
                    "reason": "guest-role-already-claimed", "replayAllowed": False}
        _save(self.root, request.public_mapping())
        try:
            result = self.driver.submit(request, admitted)
            if (isinstance(result, Mapping) and result.get("state") == "submitted" and
                    result.get("correlationId") == request.correlation_id):
                return {"state": "submitted", "correlationId": request.correlation_id,
                        "replayAllowed": False}
        except (OSError, ValueError, RuntimeError):
            pass
        return {"state": "unknown", "correlationId": request.correlation_id,
                "replayAllowed": False}

    def status(self, correlation: str) -> dict[str, Any]:
        _need(_uuid(correlation), "Preparation status correlation is invalid")
        stored = _read(self.root, correlation)
        if stored is None or self.driver is None:
            return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
        request = Request.parse({key: stored[key] for key in
            ("profile", "distribution", "correlationId", "sourceSha", "artifactIds")})
        _need(request.public_mapping() == stored, "Preparation journal intent differs")
        if not _role_claim_matches(self.root, request):
            return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
        try:
            result = self.driver.status(request)
        except (OSError, ValueError, RuntimeError):
            result = None
        if (not isinstance(result, Mapping) or result.get("correlationId") != correlation or
                result.get("sourceSha") != request.source_sha or
                result.get("guestRole") != request.guest_role or
                result.get("artifactIds") != request.artifact_ids or
                result.get("state") not in ("running", "failed", "unknown", "ready")):
            return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
        if result["state"] == "ready":
            if (result.get("liveReady") is not True or
                    not isinstance(result.get("guestManifestArtifactId"), str) or
                    _ARTIFACT.fullmatch(result["guestManifestArtifactId"]) is None or
                    not isinstance(result.get("preparationReceiptArtifactId"), str) or
                    _ARTIFACT.fullmatch(result["preparationReceiptArtifactId"]) is None):
                return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
            return {"state": "ready", "correlationId": correlation,
                    "guestManifestArtifactId": result["guestManifestArtifactId"],
                    "preparationReceiptArtifactId": result["preparationReceiptArtifactId"],
                    "replayAllowed": False}
        reported = {"state": result["state"], "correlationId": correlation,
                    "replayAllowed": False}
        if result["state"] in {"failed", "unknown"}:
            for field in ("phase", "reason"):
                value = result.get(field)
                if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", value):
                    reported[field] = value
        return reported

    def collect(self, correlation: str) -> dict[str, Any]:
        return self.status(correlation)

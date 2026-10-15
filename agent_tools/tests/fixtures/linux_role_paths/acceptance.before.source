"""Fail-closed, one-shot admission for disposable DEB and Arch package cases.

This layer binds immutable package evidence, a single new guest role and a
durable correlation before a native driver may submit work. No historical VM
tree is a valid role. The default driver is deliberately unavailable until a
fixed, independently reviewed guest transport is supplied.
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
from typing import Any, Callable, Mapping, Protocol
import uuid

try:
    from . import native_artifact_registry
except ImportError:  # pragma: no cover - direct MCP fallback
    import native_artifact_registry  # type: ignore[no-redef]

from scripts.version_metadata import parse_version


_ARTIFACT = re.compile(r"sha256-[0-9a-f]{64}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ROLES = {
    ("fresh-deb-dependencies", "ubuntu"): ("ubuntu-fresh", 2330),
    ("package-update", "ubuntu"): ("ubuntu-update", 2331),
    ("package-update", "arch"): ("arch-update", 2332),
    ("arch-rollback", "arch"): ("arch-rollback", 2333),
}
_ARTIFACT_KEYS = {"guestManifest", "preparationReceipt", "fixtureReceipt", "basePackage", "targetPackage", "bundleManifest"}
_KINDS = {"guestManifest": "guest-manifest", "fixtureReceipt": "fixture-receipt",
          "preparationReceipt": "linux-guest-preparation", "basePackage": "package",
          "targetPackage": "package", "bundleManifest": "native-scenario-manifest"}
_JOURNAL = Path(".rag_index/native-linux-deb-arch")
_BUNDLE_FILES = {
    "scripts/test_linux_public_install.py", "scripts/linux_fixture_auth.py",
    "scripts/arch_public_update.py", "scripts/prepare_desktop_update_fixture.py",
    "scripts/fixture_environment.py", "scripts/native_fixture_run.sh",
}


class LinuxDebArchAcceptanceError(ValueError):
    pass


@dataclass(frozen=True)
class Intent:
    profile: str
    distribution: str
    correlation_id: str
    source_sha: str
    artifact_ids: Mapping[str, str]
    guest_role: str
    guest_port: int

    @classmethod
    def parse(cls, value: Mapping[str, Any]) -> "Intent":
        if not isinstance(value, Mapping) or set(value) != {"profile", "distribution", "correlationId", "sourceSha", "artifactIds"}:
            raise LinuxDebArchAcceptanceError("DEB/Arch request fields are not exact")
        if not isinstance(value["profile"], str) or not isinstance(value["distribution"], str):
            raise LinuxDebArchAcceptanceError("DEB/Arch profile and distribution are invalid")
        key = (value["profile"], value["distribution"])
        if key not in _ROLES:
            raise LinuxDebArchAcceptanceError("DEB/Arch profile and distribution are not paired")
        try:
            canonical = str(uuid.UUID(value["correlationId"])) == value["correlationId"]
        except (TypeError, ValueError, AttributeError):
            canonical = False
        if not canonical or not isinstance(value["sourceSha"], str) or not _SHA.fullmatch(value["sourceSha"]):
            raise LinuxDebArchAcceptanceError("DEB/Arch source or correlation is invalid")
        artifacts = value["artifactIds"]
        if (not isinstance(artifacts, Mapping) or set(artifacts) != _ARTIFACT_KEYS
                or any(not isinstance(item, str) or not _ARTIFACT.fullmatch(item) for item in artifacts.values())):
            raise LinuxDebArchAcceptanceError("DEB/Arch immutable artifact set is invalid")
        role, port = _ROLES[key]
        return cls(key[0], key[1], value["correlationId"], value["sourceSha"], dict(sorted(artifacts.items())), role, port)

    def public_mapping(self) -> dict[str, Any]:
        return {"profile": self.profile, "distribution": self.distribution,
                "correlationId": self.correlation_id, "sourceSha": self.source_sha,
                "artifactIds": dict(self.artifact_ids), "guestRole": self.guest_role,
                "guestPort": self.guest_port}


def _verified_artifact(root: Path, artifact_id: str, kind: str, source_sha: str) -> dict[str, Any]:
    verified = native_artifact_registry.verify_artifact(root, artifact_id)
    record, location = verified.get("artifact", {}), verified.get("location", {})
    if (verified.get("verification") != "verified" or record.get("platform") != "linux"
            or record.get("artifactKind") != kind or record.get("sourceSha") != source_sha
            or location.get("evidenceClass") != "local-verified"):
        raise LinuxDebArchAcceptanceError("DEB/Arch artifact bytes or provenance are unavailable")
    path = Path(location["localPath"])
    if not path.is_file() or path.is_symlink():
        raise LinuxDebArchAcceptanceError("DEB/Arch artifact path is unsafe")
    return {"record": record, "path": path}


def _json_artifact(captured: Mapping[str, Any], maximum: int) -> dict[str, Any]:
    path = captured["path"]
    if path.stat().st_size > maximum:
        raise LinuxDebArchAcceptanceError("DEB/Arch metadata artifact is oversized")
    try:
        value = json.loads(path.read_bytes())
    except (OSError, ValueError, UnicodeError) as error:
        raise LinuxDebArchAcceptanceError("DEB/Arch metadata artifact is invalid") from error
    if not isinstance(value, dict):
        raise LinuxDebArchAcceptanceError("DEB/Arch metadata artifact is not an object")
    return value


def _asset(build: Mapping[str, Any], package_type: str) -> dict[str, Any]:
    assets = build.get("assets")
    matches = [item for item in assets if isinstance(item, dict) and item.get("packageType") == package_type] if isinstance(assets, list) else []
    if len(matches) != 1:
        raise LinuxDebArchAcceptanceError("DEB/Arch fixture package type is ambiguous")
    return matches[0]


def _fixture(intent: Intent, captured: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    receipt = _json_artifact(captured["fixtureReceipt"], 256 * 1024)
    builds = receipt.get("builds")
    if (receipt.get("schemaVersion") != 1 or receipt.get("testOnly") is not True
            or receipt.get("productionTrustChanged") is not False
            or receipt.get("architecture") != "x86_64" or not isinstance(builds, list) or len(builds) != 2):
        raise LinuxDebArchAcceptanceError("DEB/Arch fixture receipt is invalid")
    base, target = builds
    fingerprint = receipt.get("sourceFingerprint")
    if (not isinstance(base, dict) or not isinstance(target, dict)
            or not isinstance(fingerprint, str) or not _HASH.fullmatch(fingerprint)
            or base.get("label") != "base" or target.get("label") != "target"
            or base.get("sourceFingerprint") != fingerprint or target.get("sourceFingerprint") != fingerprint
            or base.get("codeFingerprint") != target.get("codeFingerprint")):
        raise LinuxDebArchAcceptanceError("DEB/Arch fixture source or code identity differs")
    try:
        if not parse_version(base["version"]) < parse_version(target["version"]):
            raise ValueError()
    except (KeyError, ValueError, TypeError) as error:
        raise LinuxDebArchAcceptanceError("DEB/Arch fixture version order is invalid") from error
    package_type = "deb" if intent.distribution == "ubuntu" else "arch-bundle"
    for label, build in (("basePackage", base), ("targetPackage", target)):
        asset = _asset(build, package_type)
        record = captured[label]["record"]
        if (asset.get("sha256") != record.get("sha256") or asset.get("sizeBytes") != record.get("size")
                or record.get("sourceFingerprint") != fingerprint):
            raise LinuxDebArchAcceptanceError("DEB/Arch package differs from same-source fixture receipt")
    for item in captured.values():
        recorded = item["record"].get("sourceFingerprint")
        if recorded is not None and recorded != fingerprint:
            raise LinuxDebArchAcceptanceError("DEB/Arch artifact source fingerprint differs")
    return {"sourceFingerprint": fingerprint, "baseVersion": base["version"],
            "targetVersion": target["version"], "codeFingerprint": base["codeFingerprint"],
            "packageType": package_type}


def _guest_manifest(intent: Intent, captured: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    value = _json_artifact(captured["guestManifest"], 8192)
    required = {"schemaVersion", "host", "profile", "distribution", "guestRole", "sourceSha",
                "tree", "sshPort", "qemuPid", "qemuStartTicks", "diskDevice", "diskInode", "pristine"}
    expected_tree = "/home/kardinal/vpn-control-install-vm-parity-" + intent.guest_role
    if (set(value) != required or value.get("schemaVersion") != 1 or value.get("host") != "archlinux"
            or value.get("profile") != intent.profile or value.get("distribution") != intent.distribution
            or value.get("guestRole") != intent.guest_role or value.get("sourceSha") != intent.source_sha
            or value.get("tree") != expected_tree or value.get("sshPort") != intent.guest_port
            or value.get("pristine") is not True
            or any(type(value.get(key)) is not int or value[key] <= 0 for key in
                   ("qemuPid", "qemuStartTicks", "diskDevice", "diskInode"))):
        raise LinuxDebArchAcceptanceError("DEB/Arch guest manifest is not a fresh fixed role")
    return value


def _preparation(intent: Intent, captured: Mapping[str, Mapping[str, Any]],
                 fixture: Mapping[str, Any], guest: Mapping[str, Any]) -> dict[str, Any]:
    value = _json_artifact(captured["preparationReceipt"], 16384)
    required = {"schemaVersion", "host", "profile", "distribution", "guestRole", "sourceSha",
                "sourceFingerprint", "correlationId", "guestManifestArtifactId", "fixtureReceiptArtifactId",
                "basePackageArtifactId", "targetPackageArtifactId", "bundleManifestArtifactId",
                "qemu", "baseline", "fixture", "publicCli", "safety", "stage", "state",
                "workerIntentSha256", "nativeWorkerSha256", "rollbackWorkerSha256"}
    artifact_fields = {"guestManifestArtifactId": "guestManifest", "fixtureReceiptArtifactId": "fixtureReceipt",
                       "basePackageArtifactId": "basePackage", "targetPackageArtifactId": "targetPackage",
                       "bundleManifestArtifactId": "bundleManifest"}
    expected_qemu = {"pid": guest["qemuPid"], "startTicks": guest["qemuStartTicks"],
                     "diskDevice": guest["diskDevice"], "diskInode": guest["diskInode"],
                     "sshPort": guest["sshPort"], "tree": guest["tree"]}
    if (set(value) != required or value.get("schemaVersion") != 1 or value.get("host") != "archlinux"
            or value.get("profile") != intent.profile or value.get("distribution") != intent.distribution
            or value.get("guestRole") != intent.guest_role or value.get("sourceSha") != intent.source_sha
            or value.get("sourceFingerprint") != fixture["sourceFingerprint"]
            or value.get("correlationId") != intent.correlation_id or value.get("state") != "ready"
            or any(value.get(field) != intent.artifact_ids[key] for field, key in artifact_fields.items())
            or value.get("qemu") != expected_qemu):
        raise LinuxDebArchAcceptanceError("DEB/Arch preparation does not bind this source and guest")
    baseline, safety = value.get("baseline"), value.get("safety")
    if (not isinstance(baseline, Mapping) or set(baseline) != {"installedBaseVersion", "installedPackageSha256",
            "codeFingerprint", "cleanPackageDatabase", "xdgUtilsAbsent", "desktopDirectoryAbsent"}
            or baseline.get("cleanPackageDatabase") is not True or not isinstance(safety, Mapping)
            or safety != {"ownerRuntimeOff": True, "protectedJobsTerminal": True, "rootOwnedStage": True}):
        raise LinuxDebArchAcceptanceError("DEB/Arch preparation safety is incomplete")
    worker_intent = {"profile": intent.profile, "distribution": intent.distribution,
                     "guestRole": intent.guest_role, "correlationId": intent.correlation_id,
                     "sourceSha": intent.source_sha, "sourceFingerprint": fixture["sourceFingerprint"],
                     "targetVersion": fixture["targetVersion"],
                     "targetSha256": captured["targetPackage"]["record"]["sha256"],
                     "fixtureReceiptArtifactId": intent.artifact_ids["fixtureReceipt"],
                     "harnessSha256": None if intent.profile == "fresh-deb-dependencies" else
                     _harness_sha(captured),
                     "trustStoreSha256": None if intent.profile == "fresh-deb-dependencies" else
                     (value["fixture"].get("trustStoreSha256") if isinstance(value.get("fixture"), Mapping)
                      else None)}
    worker_raw = (json.dumps(worker_intent, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if value.get("workerIntentSha256") != hashlib.sha256(worker_raw).hexdigest():
        raise LinuxDebArchAcceptanceError("DEB/Arch prepared worker intent differs")
    for field, name in (("nativeWorkerSha256", "linux_deb_arch_native_driver.py"),
                        ("rollbackWorkerSha256", "linux_deb_arch_rollback.py")):
        if value.get(field) != _frozen_source_sha(intent.source_sha, name):
            raise LinuxDebArchAcceptanceError("DEB/Arch staged worker differs from frozen source")
    if intent.profile == "fresh-deb-dependencies":
        if (any(baseline[key] is not None for key in ("installedBaseVersion", "installedPackageSha256", "codeFingerprint"))
                or baseline["xdgUtilsAbsent"] is not True or baseline["desktopDirectoryAbsent"] is not True
                or value.get("fixture") is not None or value.get("publicCli") is not None
                or value.get("stage") != "/var/lib/vpn-control-parity/ubuntu-fresh"):
            raise LinuxDebArchAcceptanceError("Fresh DEB preparation is not clean")
    else:
        expected_stage = "/var/lib/vpn-control-parity/" + intent.guest_role
        public_cli, server = value.get("publicCli"), value.get("fixture")
        if (baseline.get("installedBaseVersion") != fixture["baseVersion"]
                or baseline.get("installedPackageSha256") != captured["basePackage"]["record"]["sha256"]
                or baseline.get("codeFingerprint") != fixture["codeFingerprint"]
                or baseline.get("xdgUtilsAbsent") is not None or baseline.get("desktopDirectoryAbsent") is not None
                or value.get("stage") != expected_stage
                or public_cli != {"polkitReady": True, "ptyReady": True, "credentialReady": True}
                or not isinstance(server, Mapping) or set(server) != {"serverPid", "serverStartTicks",
                    "readySha256", "manifestSha256", "certificateSha256", "trustStoreSha256",
                    "publicFixtureSha256"}
                or any(type(server[key]) is not int or server[key] <= 0 for key in ("serverPid", "serverStartTicks"))
                or any(not isinstance(server[key], str) or not _HASH.fullmatch(server[key]) for key in
                       ("readySha256", "manifestSha256", "certificateSha256", "trustStoreSha256",
                        "publicFixtureSha256"))):
            raise LinuxDebArchAcceptanceError("DEB/Arch update preparation is not exact")
    return value


def _frozen_source_sha(source_sha: str, name: str) -> str:
    if name not in {"linux_deb_arch_native_driver.py", "linux_deb_arch_rollback.py"}:
        raise LinuxDebArchAcceptanceError("Unknown frozen DEB/Arch worker")
    try:
        raw = subprocess.check_output(("git", "show", source_sha + ":agent_tools/" + name),
                                      cwd=Path(__file__).resolve().parent.parent,
                                      stderr=subprocess.DEVNULL, timeout=15)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise LinuxDebArchAcceptanceError("Frozen DEB/Arch worker unavailable") from exc
    if len(raw) > 1_000_000:
        raise LinuxDebArchAcceptanceError("Frozen DEB/Arch worker is oversized")
    return hashlib.sha256(raw).hexdigest()


def _bundle(captured: Mapping[str, Mapping[str, Any]]) -> None:
    manifest = _json_artifact(captured["bundleManifest"], 64 * 1024)
    files = manifest.get("files")
    if (manifest.get("schemaVersion") != 1 or manifest.get("scenarioId") != "linux-public-update-driver"
            or not isinstance(files, list) or not 1 <= len(files) <= 32):
        raise LinuxDebArchAcceptanceError("DEB/Arch native bundle manifest is invalid")
    stage = captured["bundleManifest"]["path"].parent
    found: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "sizeBytes"}:
            raise LinuxDebArchAcceptanceError("DEB/Arch native bundle entry is invalid")
        relative = entry["path"]
        if (not isinstance(relative, str) or not re.fullmatch(r"scripts/[A-Za-z0-9_.-]+", relative)
                or relative in found or not isinstance(entry["sha256"], str)
                or not _HASH.fullmatch(entry["sha256"])
                or type(entry["sizeBytes"]) is not int or not 0 < entry["sizeBytes"] <= 1_000_000):
            raise LinuxDebArchAcceptanceError("DEB/Arch native bundle file identity is invalid")
        found.add(relative)
        file = stage / relative
        if (any(part.is_symlink() for part in (stage, file.parent, file))
                or not file.is_file() or file.stat().st_size != entry["sizeBytes"]):
            raise LinuxDebArchAcceptanceError("DEB/Arch native bundle file is absent or unsafe")
        if hashlib.sha256(file.read_bytes()).hexdigest() != entry["sha256"]:
            raise LinuxDebArchAcceptanceError("DEB/Arch native bundle bytes differ")
    if not _BUNDLE_FILES <= found:
        raise LinuxDebArchAcceptanceError("DEB/Arch required native harness is absent")


def _harness_sha(captured: Mapping[str, Mapping[str, Any]]) -> str:
    files = _json_artifact(captured["bundleManifest"], 64 * 1024).get("files", [])
    matches = [item.get("sha256") for item in files if isinstance(item, Mapping)
               and item.get("path") == "scripts/test_linux_public_install.py"]
    if len(matches) != 1 or not isinstance(matches[0], str) or not _HASH.fullmatch(matches[0]):
        raise LinuxDebArchAcceptanceError("DEB/Arch harness digest is unavailable")
    return matches[0]


def preflight(root: Path | str, intent: Intent, live_observer: Callable[[Intent, Mapping[str, Any]], Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Read-only source, package, guest-role and live generation admission."""
    root = Path(root).resolve()
    try:
        head = subprocess.check_output(("git", "rev-parse", "HEAD"), cwd=root, text=True,
                                       stderr=subprocess.DEVNULL).strip()
        if head != intent.source_sha:
            raise LinuxDebArchAcceptanceError("DEB/Arch source SHA is no longer HEAD")
        dirty = subprocess.check_output(("git", "status", "--porcelain=v1", "--untracked-files=all"),
                                        cwd=root, text=True, stderr=subprocess.DEVNULL)
        if dirty:
            raise LinuxDebArchAcceptanceError("DEB/Arch source tree is not frozen clean")
        captured = {key: _verified_artifact(root, identifier, _KINDS[key], intent.source_sha)
                    for key, identifier in intent.artifact_ids.items()}
        fixture = _fixture(intent, captured)
        _bundle(captured)
        guest = _guest_manifest(intent, captured)
        preparation = _preparation(intent, captured, fixture, guest)
        if live_observer is None:
            raise LinuxDebArchAcceptanceError("DEB/Arch fixed live guest observer is unavailable")
        observed = live_observer(intent, guest, preparation)
        if (not isinstance(observed, Mapping) or observed.get("ready") is not True
                or observed.get("qemuPid") != guest["qemuPid"]
                or observed.get("qemuStartTicks") != guest["qemuStartTicks"]
                or observed.get("diskDevice") != guest["diskDevice"]
                or observed.get("diskInode") != guest["diskInode"]
                or observed.get("ownerRuntimeOff") is not True
                or observed.get("packageProcessesOff") is not True
                or observed.get("protectedJobsTerminal") is not True
                or observed.get("profileUnused") is not True):
            raise LinuxDebArchAcceptanceError("DEB/Arch live guest admission is incomplete")
        return {"ready": True, "profile": intent.profile, "guestRole": intent.guest_role,
                "sourceSha": intent.source_sha, "fixture": fixture, "guest": guest,
                "preparation": preparation, "harnessSha256": (
                    None if intent.profile == "fresh-deb-dependencies" else _harness_sha(captured)),
                "nativeActionAllowed": False}
    except (OSError, subprocess.CalledProcessError, KeyError, TypeError, ValueError,
            native_artifact_registry.NativeArtifactRegistryError) as error:
        return {"ready": False, "profile": intent.profile, "guestRole": intent.guest_role,
                "reason": str(error) if isinstance(error, LinuxDebArchAcceptanceError) else "admission-unavailable",
                "nativeActionAllowed": False}


class Driver(Protocol):
    def submit(self, intent: Intent, admission: Mapping[str, Any]) -> Mapping[str, Any]: ...
    def status(self, intent: Intent) -> Mapping[str, Any]: ...


def _private_dir(path: Path) -> None:
    for directory in (path.parent, path):
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise LinuxDebArchAcceptanceError("DEB/Arch journal directory is not private")


def _exclusive(path: Path, value: Mapping[str, Any]) -> None:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


class Adapter:
    """Expose preflight/start/status/collect without ever accepting a command."""

    def __init__(self, root: Path | str, *, driver: Driver | None = None,
                 admit: Callable[[Intent], Mapping[str, Any]] | None = None):
        self.root = Path(root).resolve()
        self.directory = self.root / _JOURNAL
        self.driver = driver
        self.admit = admit or (lambda intent: preflight(self.root, intent))

    def preflight(self, request: Mapping[str, Any]) -> dict[str, Any]:
        return dict(self.admit(Intent.parse(request)))

    def _read(self, correlation: str) -> Intent | None:
        try:
            if str(uuid.UUID(correlation)) != correlation:
                raise ValueError()
            path = self.directory / (correlation + ".json")
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 8192:
                return None
            value = json.loads(path.read_bytes())
            if set(value) != {"profile", "distribution", "correlationId", "sourceSha", "artifactIds", "guestRole", "guestPort"}:
                return None
            intent = Intent.parse({key: value[key] for key in ("profile", "distribution", "correlationId", "sourceSha", "artifactIds")})
            if intent.guest_role != value["guestRole"] or intent.guest_port != value["guestPort"]:
                return None
            claim = self.directory / (intent.guest_role + ".claim")
            claim_info = claim.lstat()
            if (not stat.S_ISREG(claim_info.st_mode) or claim_info.st_uid != os.getuid()
                    or stat.S_IMODE(claim_info.st_mode) != 0o600 or claim_info.st_size > 512):
                return None
            if json.loads(claim.read_bytes()) != {"guestRole": intent.guest_role, "correlationId": correlation}:
                return None
            return intent
        except (OSError, ValueError, TypeError, KeyError):
            return None

    @staticmethod
    def _unknown(correlation: str, reason: str = "outcome-unknown") -> dict[str, Any]:
        return {"state": "unknown", "correlationId": correlation, "reason": reason, "replayAllowed": False}

    def start(self, request: Mapping[str, Any]) -> dict[str, Any]:
        intent = Intent.parse(request)
        existing = self._read(intent.correlation_id)
        if existing is not None:
            if existing != intent:
                return self._unknown(intent.correlation_id, "correlation-intent-mismatch")
            return self.status(intent.correlation_id)
        if (self.directory / (intent.correlation_id + ".json")).exists():
            return self._unknown(intent.correlation_id, "journal-incomplete")
        admitted = dict(self.admit(intent))
        if admitted.get("ready") is not True or self.driver is None:
            return {"state": "blocked", "correlationId": intent.correlation_id,
                    "reason": admitted.get("reason", "fixed-native-driver-unavailable"), "replayAllowed": False}
        _private_dir(self.directory)
        try:
            _exclusive(self.directory / (intent.guest_role + ".claim"),
                       {"guestRole": intent.guest_role, "correlationId": intent.correlation_id})
        except FileExistsError:
            return {"state": "blocked", "correlationId": intent.correlation_id,
                    "reason": "guest-already-claimed", "replayAllowed": False}
        try:
            _exclusive(self.directory / (intent.correlation_id + ".json"), intent.public_mapping())
        except FileExistsError:
            return self._unknown(intent.correlation_id, "correlation-already-journaled")
        try:
            result = self.driver.submit(intent, admitted)
            if isinstance(result, Mapping) and result.get("correlationId") == intent.correlation_id and result.get("state") == "submitted":
                return {"state": "submitted", "correlationId": intent.correlation_id, "replayAllowed": False}
        except (OSError, ValueError, RuntimeError):
            pass
        return self._unknown(intent.correlation_id)

    def status(self, correlation: str) -> dict[str, Any]:
        intent = self._read(correlation)
        if intent is None or self.driver is None:
            return self._unknown(correlation, "journal-or-driver-unavailable")
        try:
            result = self.driver.status(intent)
        except (OSError, ValueError, RuntimeError):
            return self._unknown(correlation)
        if not isinstance(result, Mapping) or result.get("correlationId") != correlation:
            return self._unknown(correlation, "correlation-mismatch")
        if (result.get("sourceSha") != intent.source_sha or result.get("artifactIds") != intent.artifact_ids
                or result.get("guestRole") != intent.guest_role or result.get("guestPort") != intent.guest_port):
            return self._unknown(correlation, "source-or-guest-mismatch")
        state = result.get("state")
        if state == "terminal":
            try:
                captured = {key: _verified_artifact(self.root, intent.artifact_ids[key], _KINDS[key],
                                                   intent.source_sha)
                            for key in ("fixtureReceipt", "basePackage", "targetPackage",
                                        "guestManifest", "preparationReceipt", "bundleManifest")}
                fixture = _fixture(intent, captured)
                _bundle(captured)
                guest = _guest_manifest(intent, captured)
                _preparation(intent, captured, fixture, guest)
                expected_generation = {"pid": guest["qemuPid"], "startTicks": guest["qemuStartTicks"],
                                       "diskDevice": guest["diskDevice"], "diskInode": guest["diskInode"]}
                if (result.get("sourceFingerprint") != fixture["sourceFingerprint"]
                        or result.get("targetVersion") != fixture["targetVersion"]
                        or result.get("guestGeneration") != expected_generation):
                    return self._unknown(correlation, "terminal-fixture-or-generation-mismatch")
            except (OSError, TypeError, ValueError, KeyError,
                    native_artifact_registry.NativeArtifactRegistryError):
                return self._unknown(correlation, "terminal-artifact-revalidation-unavailable")
        if state == "running":
            return {"state": "running", "correlationId": correlation, "replayAllowed": False}
        if state != "terminal" or type(result.get("exitCode")) is not int:
            return self._unknown(correlation)
        if intent.profile == "fresh-deb-dependencies":
            transaction = result.get("packageTransaction")
            if (result["exitCode"] != 0 or not isinstance(transaction, Mapping)
                    or transaction.get("manager") != "apt" or transaction.get("exitCode") != 0
                    or transaction.get("beforeXdgUtilsAbsent") is not True
                    or transaction.get("beforeDesktopDirectoryAbsent") is not True
                    or transaction.get("afterXdgUtilsInstalled") is not True
                    or transaction.get("afterDesktopDirectoryPresent") is not True
                    or transaction.get("dpkgAuditClean") is not True
                    or transaction.get("onlyExpectedPackagesAdded") is not True
                    or result.get("launcherVersionMatched") is not True):
                return self._unknown(correlation, "dependency-acquisition-unverified")
            return {"state": "terminal", "correlationId": correlation, "profile": intent.profile,
                    "result": "dependencies-installed", "replayAllowed": False}
        protected, public, accepted = (result.get("protectedReceipt"),
                                       result.get("replacementRecoveryObservation"), result.get("accepted"))
        if (not all(isinstance(item, Mapping) for item in (protected, public, accepted))
                or type(protected.get("sequence")) is not int or protected["sequence"] < 1
                or protected.get("version") != 1
                or not isinstance(protected.get("jobId"), str) or not protected["jobId"]
                or not isinstance(accepted.get("data"), Mapping)
                or not isinstance(public.get("data"), Mapping)
                or accepted.get("schemaVersion") != 1 or accepted.get("code") != "ACCEPTED"
                or accepted.get("ok") is not True or accepted.get("final") is not False
                or accepted.get("data", {}).get("jobId") != protected["jobId"]
                or not accepted.get("data", {}).get("handoffReady")
                or public.get("schemaVersion") != 1 or public.get("final") is not True
                or public.get("data", {}).get("jobId") != protected["jobId"]
                or not all(isinstance(accepted.get(field), str) and accepted[field] for field in
                           ("controllerId", "requestId", "operationId"))
                or public.get("operationId") != accepted["operationId"]
                or public.get("controllerId") == accepted["controllerId"]
                or public.get("data", {}).get("originControllerId") != accepted["controllerId"]
                or public.get("data", {}).get("originRequestId") != accepted["requestId"]):
            return self._unknown(correlation, "terminal-correlation-incomplete")
        if intent.profile == "arch-rollback":
            rollback = result.get("rollback")
            valid = (result["exitCode"] != 0 and protected.get("phase") == "FAILED"
                     and protected.get("code") == "RUNTIME_FAILED" and public.get("ok") is False
                     and public.get("code") == "RUNTIME_FAILED"
                     and isinstance(rollback, Mapping) and rollback.get("baseTreeRestored") is True
                     and rollback.get("failedReplacementRemoved") is True
                     and rollback.get("inodeTraceMatched") is True)
        else:
            valid = (result["exitCode"] == 0 and protected.get("phase") == "SUCCEEDED"
                     and protected.get("code") == "OK" and public.get("ok") is True
                     and public.get("code") == "OK" and result.get("sameSourceRecoveryProven") is True
                     and result.get("productionTrustedInstallSucceeded") is True)
        if not valid:
            return self._unknown(correlation, "terminal-outcome-unverified")
        return {"state": "terminal", "correlationId": correlation, "profile": intent.profile,
                "jobId": protected["jobId"], "result": "rollback-restored" if intent.profile == "arch-rollback" else "installed",
                "replayAllowed": False}

    def collect(self, correlation: str) -> dict[str, Any]:
        return self.status(correlation)


def fixed_readonly_adapter(root: Path | str) -> Adapter:
    """Production preflight/status wiring; native start remains disabled."""
    try:
        from .linux_deb_arch_transport import FixedLiveObserver
    except ImportError:  # pragma: no cover - direct MCP fallback
        from linux_deb_arch_transport import FixedLiveObserver  # type: ignore[no-redef]
    observer = FixedLiveObserver(root)
    return Adapter(root, admit=lambda intent: preflight(root, intent, live_observer=observer))

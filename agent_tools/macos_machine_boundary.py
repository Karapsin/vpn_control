"""Trusted Mac-only boundary for a reviewed Tart machine acceptance campaign.

Only exact local source/package checks are implemented here. Guest observation,
public submission and secure UI are supplied by an internal native provider,
never by MCP request fields. The provider interface contains no credential or
arbitrary-command argument. The campaign gate journals before provider mutation.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from . import macos_machine_acceptance as gate


_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_VERSION = re.compile(r"[1-9][0-9]*\.[0-9]+\.[0-9]+\Z")


class MacMachineBoundaryError(ValueError):
    pass


@dataclass(frozen=True)
class NativeCampaign:
    correlation_id: str
    scenario: str
    source_sha: str
    fixture_receipt_artifact_id: str
    base_dmg_artifact_id: str
    target_dmg_artifact_id: str
    controller_id: str
    owner_pid: int
    owner_start_ticks: int
    boot_session_uuid: str
    reservation_id: str


@dataclass(frozen=True)
class VerifiedPair:
    source_sha: str
    source_fingerprint: str
    fixture_receipt_artifact_id: str
    base_dmg_artifact_id: str
    target_dmg_artifact_id: str


@dataclass(frozen=True)
class NativeTerminalQuery:
    source_sha: str
    scenario: str
    operation_id: str
    job_id: str
    app: str
    guest_root: str
    prior_owner_pid: int
    prior_owner_start_ticks: int
    boot_session_uuid: str
    reservation_id: str
    prior_controller_id: str


class NativeProvider(Protocol):
    """Internal reviewed native owner; no password, paths or shell input."""
    def observe_admission(self, vm_name: str, source_sha: str, pair: VerifiedPair | None = None) -> Mapping[str, Any]: ...
    def submit_public(self, vm_name: str, campaign: NativeCampaign) -> Mapping[str, Any]: ...
    def observe_prompt(self, vm_name: str, job_id: str, operation_id: str) -> Mapping[str, Any]: ...
    def authorize_visible_prompt(self, vm_name: str, job_id: str, operation_id: str) -> None: ...
    def observe_terminal(self, vm_name: str, query: NativeTerminalQuery) -> Mapping[str, Any]: ...


def _run_git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(["git", "--no-optional-locks", "-c", "core.fsmonitor=false",
                                "-c", "core.untrackedCache=false", *arguments], cwd=root,
                               env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
                               capture_output=True, text=True, timeout=15, check=False)
    if completed.returncode != 0 or len(completed.stdout) > 1024 * 1024:
        raise MacMachineBoundaryError("Exact Git source is unavailable.")
    return completed.stdout.strip()


def _sha256(path: Path, expected_size: int) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size != expected_size:
            raise MacMachineBoundaryError("Frozen Mac artifact size changed.")
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
        after = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != \
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise MacMachineBoundaryError("Frozen Mac artifact changed during read.")
        current = os.stat(path, follow_symlinks=False)
        if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) != \
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
            raise MacMachineBoundaryError("Frozen Mac artifact path changed during read.")
        return digest.hexdigest()


def _fixed_file(root: Path, relative: Path) -> Path:
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise MacMachineBoundaryError("Mac fixture ancestor is unsafe.")
    return current / relative.name


class MacMachineBoundary:
    """Bind a fixed ignored fixture pair and trusted Tart provider to the gate."""

    def __init__(self, repository_root: Path, provider: NativeProvider):
        self.root = Path(repository_root).resolve(strict=True)
        self.provider = provider

    def current_source_sha(self) -> str:
        value = _run_git(self.root, "rev-parse", "HEAD")
        if not _HEX40.fullmatch(value):
            raise MacMachineBoundaryError("Git HEAD is not an exact source SHA.")
        return value

    def source_tree_clean(self) -> bool:
        return not bool(_run_git(self.root, "status", "--porcelain=v1", "--untracked-files=normal"))

    def _pair(self, request: Mapping[str, Any]) -> dict[str, Any]:
        source = request["sourceSha"]
        fixed = self.root / ".runtime" / "parity-evidence" / "continuation-macos" / ("fixture-" + source[:7])
        summary_path = _fixed_file(self.root, fixed.relative_to(self.root) / "reviewed-package-summary.json")
        try:
            fd = os.open(summary_path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > 16384:
                    raise ValueError()
                summary_bytes = stream.read(16385)
                after = os.fstat(stream.fileno())
                if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != \
                        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                    raise ValueError()
                current = os.stat(summary_path, follow_symlinks=False)
                if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != \
                        (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns):
                    raise ValueError()
            if len(summary_bytes) > 16384:
                raise ValueError()
            summary = json.loads(summary_bytes)
        except (OSError, ValueError, TypeError) as error:
            raise MacMachineBoundaryError("Exact Mac fixture summary is unavailable.") from error
        if summary.get("sourceSha") != source or summary.get("sourceFingerprint") != request["sourceFingerprint"] or \
                summary.get("testOnly") is not True or summary.get("productionTrustChanged") is not False or \
                summary.get("architecture") != "arm64" or summary.get("workflowConclusion") != "success":
            raise MacMachineBoundaryError("Mac fixture provenance changed.")
        if summary.get("fixtureReceiptSha256") != request["fixtureReceiptArtifactId"][7:]:
            raise MacMachineBoundaryError("Mac fixture receipt identity changed.")
        receipt = _fixed_file(self.root, fixed.relative_to(self.root) / "pair" / "fixture-receipt.json")
        receipt_size = receipt.stat().st_size
        if not 0 < receipt_size <= 16384 or _sha256(receipt, receipt_size) != summary.get("fixtureReceiptSha256"):
            raise MacMachineBoundaryError("Mac fixture receipt changed.")
        for label in ("base", "target"):
            record = summary.get("packages", {}).get(label)
            if not isinstance(record, Mapping):
                raise MacMachineBoundaryError("Mac package evidence is unavailable.")
            version = record.get("version")
            if not isinstance(version, str) or not _VERSION.fullmatch(version):
                raise MacMachineBoundaryError("Mac package version is invalid.")
            name = f"vpn-control-{version}.dmg"
            expected = _fixed_file(self.root, fixed.relative_to(self.root) / "pair" / "packages" / label / name)
            if (record.get("localPath") != str(expected) or record.get("version") != version or
                    record.get("artifactId") != request[f"{label}DmgArtifactId"] or
                    record.get("mainJarSha256") != request[f"{label}JarSha256"] or
                    record.get("codesignDeepStrict") != "pass" or
                    type(record.get("size")) is not int or not 0 < record["size"] < 512 * 1024 * 1024):
                raise MacMachineBoundaryError("Exact Mac package record changed.")
            if _sha256(expected, record["size"]) != request[f"{label}DmgArtifactId"][7:]:
                raise MacMachineBoundaryError("Exact Mac DMG bytes changed.")
        if _sha256(summary_path, len(summary_bytes)) != hashlib.sha256(summary_bytes).hexdigest():
            raise MacMachineBoundaryError("Mac fixture summary changed during pair admission.")
        return VerifiedPair(source, request["sourceFingerprint"], request["fixtureReceiptArtifactId"],
                            request["baseDmgArtifactId"], request["targetDmgArtifactId"])

    def admission(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        pair = self._pair(request)
        observed = self.provider.observe_admission(gate.VM_NAME, request["sourceSha"], pair)
        if not isinstance(observed, Mapping):
            raise MacMachineBoundaryError("Tart guest observation is unavailable.")
        return observed

    def submit(self, request: Mapping[str, Any], admission: Mapping[str, Any]) -> Mapping[str, Any]:
        if self.current_source_sha() != request["sourceSha"] or not self.source_tree_clean():
            raise MacMachineBoundaryError("Source changed before public submission.")
        pair = self._pair(request)
        fresh = gate._admit(request, self.provider.observe_admission(gate.VM_NAME, request["sourceSha"], pair))
        if fresh != admission:
            raise MacMachineBoundaryError("Tart campaign changed before public submission.")
        campaign = NativeCampaign(request["correlationId"], request["scenario"], request["sourceSha"],
                                  request["fixtureReceiptArtifactId"], request["baseDmgArtifactId"],
                                  request["targetDmgArtifactId"], admission["controllerId"],
                                  admission["ownerPid"], admission["ownerStartTicks"],
                                  admission["bootSessionUuid"], admission["reservationId"])
        return self.provider.submit_public(gate.VM_NAME, campaign)

    def prompt(self, request: Mapping[str, Any], operation: Mapping[str, Any]) -> Mapping[str, Any]:
        return self.provider.observe_prompt(gate.VM_NAME, operation["jobId"], operation["operationId"])

    def secure_authorize(self, request: Mapping[str, Any], operation: Mapping[str, Any]) -> None:
        self.provider.authorize_visible_prompt(gate.VM_NAME, operation["jobId"], operation["operationId"])

    def terminal(self, request: Mapping[str, Any], operation: Mapping[str, Any]) -> Mapping[str, Any]:
        admission = operation["admission"]
        query = NativeTerminalQuery(request["sourceSha"], request["scenario"],
                                    operation["operationId"], operation["jobId"],
                                    admission["app"], admission["guestRoot"],
                                    admission["ownerPid"], admission["ownerStartTicks"],
                                    admission["bootSessionUuid"], admission["reservationId"],
                                    admission["controllerId"])
        return self.provider.observe_terminal(gate.VM_NAME, query)

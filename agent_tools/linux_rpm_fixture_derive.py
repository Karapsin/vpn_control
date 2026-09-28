"""Derive a truthful RPM-only transfer from a verified same-source hosted fixture.

The hosted receipt remains unchanged. Missing DEB and Arch bytes are excluded
explicitly from a separate receipt used only by the fixed Fedora RPM harness.
"""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
import tempfile
from typing import Any
from zipfile import ZipFile


_SHA = re.compile(r"[0-9a-f]{40}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_VERSION = re.compile(r"[1-9][0-9]*\.[0-9]+\.[0-9]+\Z")


def _require(value: bool, reason: str) -> None:
    if not value:
        raise ValueError(reason)


def _file(path: Path, maximum: int) -> bytes:
    info = path.lstat()
    _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and 0 < info.st_size <= maximum,
             "Fixture input is missing or unsafe")
    raw = path.read_bytes()
    after = path.lstat()
    _require(len(raw) == info.st_size and
             (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
             "Fixture input changed during derivation")
    return raw


def _digest(path: Path, expected_size: int) -> str:
    info = path.lstat()
    _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
             info.st_size == expected_size and 0 < expected_size <= 1024 * 1024 * 1024,
             "RPM input is missing or unsafe")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    after = path.lstat()
    _require((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
             "RPM input changed during derivation")
    return digest.hexdigest()


def _json(raw: bytes, name: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeError, ValueError) as error:
        raise ValueError(f"Invalid {name}") from error
    _require(isinstance(value, dict), f"Invalid {name}")
    return value


def derive(directory: Path | str, output: Path | str, *, source_sha: str,
           hosted_artifact_id: int, hosted_zip: Path | str,
           verification_receipt: Path | str) -> dict[str, Any]:
    """Write an explicit RPM-only receipt and tar after validating source bytes."""
    _require(isinstance(source_sha, str) and bool(_SHA.fullmatch(source_sha)), "Invalid source SHA")
    _require(type(hosted_artifact_id) is int and hosted_artifact_id > 0, "Invalid hosted artifact ID")
    directory, output = Path(directory), Path(output)
    _require(directory.is_dir() and not directory.is_symlink() and not output.exists() and not output.is_symlink(),
             "Fixture directory or output is unsafe")
    parent = output.parent.resolve(strict=True)
    parent_info = parent.lstat()
    _require(stat.S_ISDIR(parent_info.st_mode) and parent_info.st_uid == os.getuid() and
             not parent_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH), "Derivation output parent is unsafe")
    hosted_zip = Path(hosted_zip)
    zip_info = hosted_zip.lstat()
    _require(stat.S_ISREG(zip_info.st_mode) and zip_info.st_uid == os.getuid() and
             0 < zip_info.st_size <= 1024 * 1024 * 1024, "Hosted ZIP is unsafe")
    zip_digest = _digest(hosted_zip, zip_info.st_size)
    verification_raw = _file(Path(verification_receipt), 1024 * 1024)
    verification = _json(verification_raw, "independent verification")
    _require(verification.get("verification") == "independently-verified" and
             verification.get("artifactId") == hosted_artifact_id and
             verification.get("artifactZipSha256") == zip_digest and
             verification.get("sourceHead") == source_sha and
             isinstance(verification.get("correlationId"), str),
             "Hosted verification receipt does not bind this archive")
    for part in (directory / "packages", directory / "packages/base", directory / "packages/target"):
        info = part.lstat()
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(), "Fixture package ancestry is unsafe")
    snapshot_raw = _file(directory / "snapshot.json", 1024 * 1024)
    plan_raw = _file(directory / "build-plan.json", 1024 * 1024)
    original_raw = _file(directory / "fixture-receipt.json", 1024 * 1024)
    snapshot, plan, original = (_json(snapshot_raw, "snapshot"), _json(plan_raw, "build plan"),
                                _json(original_raw, "original receipt"))
    fingerprint = snapshot.get("sourceFingerprint")
    _require(snapshot.get("schemaVersion") == plan.get("schemaVersion") == original.get("schemaVersion") == 1
             and snapshot.get("sourceHead") == source_sha
             and isinstance(fingerprint, str) and bool(_HASH.fullmatch(fingerprint))
             and verification.get("sourceFingerprint") == fingerprint
             and plan.get("sourceFingerprint") == original.get("sourceFingerprint") == fingerprint
             and plan.get("platform") == "linux" and plan.get("architecture") == "x86_64"
             and plan.get("packageFamily") == "default" and plan.get("testOnly") is True
             and plan.get("productionTrustChanged") is False
             and original.get("testOnly") is True and original.get("productionTrustChanged") is False,
             "Hosted source and fixture identity disagree")
    builds = original.get("builds")
    _require(isinstance(builds, list) and len(builds) == 2 and
             isinstance(original.get("manifest"), dict), "Hosted build records are invalid")
    scoped = copy.deepcopy(original)
    excluded: dict[str, list[str]] = {}
    files: list[tuple[str, Path, int]] = []
    expected_digests: dict[str, tuple[int, str]] = {}
    codes: list[str] = []
    for index, label in enumerate(("base", "target")):
        build = builds[index]
        _require(isinstance(build, dict) and build.get("label") == label and
                 isinstance(build.get("version"), str) and bool(_VERSION.fullmatch(build["version"]))
                 and build.get("sourceFingerprint") == fingerprint and
                 isinstance(build.get("codeFingerprint"), str) and bool(_HASH.fullmatch(build["codeFingerprint"]))
                 and isinstance(build.get("mainJarSha256"), str) and bool(_HASH.fullmatch(build["mainJarSha256"]))
                 and isinstance(build.get("assets"), list), "Hosted build identity is invalid")
        codes.append(build["codeFingerprint"])
        assets = build["assets"]
        rpms = [asset for asset in assets if isinstance(asset, dict) and asset.get("packageType") == "rpm"]
        _require(len(rpms) == 1 and all(isinstance(asset, dict) for asset in assets),
                 "Hosted RPM asset list is invalid")
        asset = rpms[0]
        name = f"vpn-control-{build['version']}-1.x86_64.rpm"
        _require(asset.get("fileName") == name and asset.get("displayVersion") == build["version"]
                 and asset.get("platform") == "linux" and
                 type(asset.get("sizeBytes")) is int and
                 isinstance(asset.get("sha256"), str) and bool(_HASH.fullmatch(asset["sha256"])),
                 "Hosted RPM identity is invalid")
        path = directory / "packages" / label / name
        _require(_digest(path, asset["sizeBytes"]) == asset["sha256"], "Hosted RPM bytes disagree with receipt")
        _require(verification.get(label + "RpmSha256") == asset["sha256"],
                 "Independent verification RPM digest differs")
        member = f"packages/{label}/{name}"
        files.append((member, path, asset["sizeBytes"]))
        expected_digests[member] = (asset["sizeBytes"], asset["sha256"])
        scoped["builds"][index]["assets"] = [copy.deepcopy(asset)]
        excluded[label] = [other.get("fileName", "invalid") for other in assets if other is not asset]
    _require(codes[0] == codes[1], "Base and target code fingerprints differ")
    _require(original["manifest"].get("assets") == builds[1]["assets"],
             "Original target manifest does not bind hosted assets")
    expected_zip = {"snapshot.json": (len(snapshot_raw), hashlib.sha256(snapshot_raw).hexdigest()),
                    "build-plan.json": (len(plan_raw), hashlib.sha256(plan_raw).hexdigest()),
                    "fixture-receipt.json": (len(original_raw), hashlib.sha256(original_raw).hexdigest()),
                    **expected_digests}
    allowed_extra = {"fixture-verification.json", "base-build.log", "target-build.log"}
    with ZipFile(hosted_zip) as archive:
        members = archive.infolist()
        names = {item.filename for item in members}
        _require(len(names) == len(members) and set(expected_zip) <= names and names - set(expected_zip) <= allowed_extra,
                 "Hosted ZIP inventory is not the verified fixture")
        for member in members:
            _require(stat.S_ISREG(member.external_attr >> 16) and 0 < member.file_size <= 1024 * 1024 * 1024,
                     "Hosted ZIP member is unsafe")
            if member.filename in expected_zip:
                digest = hashlib.sha256()
                count = 0
                with archive.open(member) as source:
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        count += len(block); digest.update(block)
                _require((count, digest.hexdigest()) == expected_zip[member.filename],
                         "Hosted ZIP bytes differ from extracted fixture")
    zip_after = hosted_zip.lstat()
    _require((zip_info.st_dev, zip_info.st_ino, zip_info.st_size, zip_info.st_mtime_ns, zip_info.st_ctime_ns) ==
             (zip_after.st_dev, zip_after.st_ino, zip_after.st_size, zip_after.st_mtime_ns, zip_after.st_ctime_ns)
             and _digest(hosted_zip, zip_info.st_size) == zip_digest,
             "Hosted ZIP changed during derivation")
    scoped["manifest"]["assets"] = copy.deepcopy(scoped["builds"][1]["assets"])
    provenance = {"scope": "rpm-only", "evidenceScope": "locally-verified-hosted-archive",
                  "sourceShaFromSnapshot": source_sha, "hostedArtifactIdClaim": hosted_artifact_id,
                  "verificationReceiptSha256": hashlib.sha256(verification_raw).hexdigest(),
                  "hostedZipSha256": zip_digest,
                  "sourceFingerprint": fingerprint,
                  "originalReceiptSha256": hashlib.sha256(original_raw).hexdigest(),
                  "snapshotSha256": hashlib.sha256(snapshot_raw).hexdigest(),
                  "buildPlanSha256": hashlib.sha256(plan_raw).hexdigest(),
                  "excludedAssetNames": excluded}
    scoped["derivedFrom"] = provenance
    receipt_raw = (json.dumps(scoped, sort_keys=True, separators=(",", ":")) + "\n").encode()
    staged = Path(tempfile.mkdtemp(prefix=".rpm-only-", dir=parent))
    try:
        receipt_path = staged / "fixture-receipt.json"
        receipt_path.write_bytes(receipt_raw)
        os.chmod(receipt_path, 0o600)
        archive = staged / "source-fixture.tar"
        with tarfile.open(archive, "w") as target:
            for name, source, size in [("fixture-receipt.json", receipt_path, len(receipt_raw)), *files]:
                info = tarfile.TarInfo(name)
                info.size = size
                info.mode = 0o400
                info.mtime = 0
                with source.open("rb") as stream:
                    target.addfile(info, stream)
        expected_tar = {"fixture-receipt.json": (len(receipt_raw), hashlib.sha256(receipt_raw).hexdigest()),
                        **expected_digests}
        with tarfile.open(archive, "r:") as built:
            members = built.getmembers()
            _require({item.name for item in members} == set(expected_tar) and len(members) == len(expected_tar),
                     "Derived tar inventory changed")
            for member in members:
                _require(member.isfile(), "Derived tar member is unsafe")
                digest = hashlib.sha256(); count = 0
                with built.extractfile(member) as source:
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        count += len(block); digest.update(block)
                _require((count, digest.hexdigest()) == expected_tar[member.name],
                         "Derived tar bytes differ from verified RPM inputs")
        os.chmod(archive, 0o600)
        result = {**provenance, "derivedReceiptSha256": hashlib.sha256(receipt_raw).hexdigest(),
                  "sourceFixtureSha256": _digest(archive, archive.stat().st_size),
                  "sourceFixtureSize": archive.stat().st_size}
        evidence = staged / "derivation.json"
        evidence.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
        os.chmod(evidence, 0o600)
        # mkdir reserves the name without replacement. Transfer through the
        # pinned directory fd; a swapped path never becomes our publication.
        output.mkdir(mode=0o700)
        reserved = output.lstat()
        _require(stat.S_ISDIR(reserved.st_mode) and reserved.st_uid == os.getuid() and
                 not list(output.iterdir()), "Derivation output reservation changed")
        directory_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            held = os.fstat(directory_fd)
            _require((held.st_dev, held.st_ino) == (reserved.st_dev, reserved.st_ino),
                     "Derivation output reservation changed")
            # A published directory is usable only after this marker is gone.
            # Failed or interrupted publication stays visibly incomplete.
            marker_fd = os.open(".incomplete", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                0o600, dir_fd=directory_fd)
            os.close(marker_fd)
            for name in ("fixture-receipt.json", "source-fixture.tar", "derivation.json"):
                os.rename(staged / name, name, dst_dir_fd=directory_fd)
            current = output.lstat()
            _require((held.st_dev, held.st_ino) == (current.st_dev, current.st_ino),
                     "Derivation output reservation changed")
            staged.rmdir()
            os.unlink(".incomplete", dir_fd=directory_fd)
        finally:
            os.close(directory_fd)
        return result
    except BaseException:
        if staged.exists():
            shutil.rmtree(staged)
        # Never recursively remove a published path: another same-UID actor
        # could replace it between an identity check and path-based deletion.
        # Leave any reserved partial directory as fail-closed forensic state.
        raise

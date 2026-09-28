#!/usr/bin/env python3
"""Verify exact-source Linux base/target RPM fixture artifact provenance."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import uuid

from version_metadata import parse_version


SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _load(directory, name):
    path = directory / name
    _require(path.is_file() and not path.is_symlink(), f"Missing or unsafe {name}")
    return json.loads(path.read_text(encoding="utf-8"))


def _rpm_query(path):
    result = subprocess.run(
        ["rpm", "-qp", "--qf", "%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n", str(path)],
        text=True, capture_output=True, check=True)
    fields = result.stdout.strip().split("\t")
    _require(len(fields) == 4, "RPM header has unexpected fields")
    return tuple(fields)


def verify_fixture(directory, source_sha, base_version, target_version, correlation_id, rpm_query=None):
    directory = Path(directory).resolve(strict=True)
    try:
        _require(str(uuid.UUID(correlation_id)) == correlation_id, "Invalid correlationId")
    except (ValueError, AttributeError) as error:
        raise ValueError("Invalid correlationId") from error
    _require(bool(SHA.fullmatch(source_sha)), "Invalid source HEAD")
    base_parts = parse_version(base_version)
    target_parts = parse_version(target_version)
    _require(base_parts < target_parts, "Base version must precede target version")
    snapshot = _load(directory, "snapshot.json")
    plan = _load(directory, "build-plan.json")
    receipt = _load(directory, "fixture-receipt.json")
    _require(snapshot.get("schemaVersion") == plan.get("schemaVersion") == receipt.get("schemaVersion") == 1,
             "Fixture schema version mismatch")
    _require(snapshot.get("sourceHead") == source_sha, "Fixture source HEAD mismatch")
    fingerprint = snapshot.get("sourceFingerprint")
    _require(isinstance(fingerprint, str) and DIGEST.fullmatch(fingerprint), "Source fingerprint invalid")
    _require(plan.get("sourceFingerprint") == receipt.get("sourceFingerprint") == fingerprint,
             "Same-source fingerprint mismatch")
    _require(plan.get("testOnly") is True and receipt.get("testOnly") is True and
             plan.get("productionTrustChanged") is False and receipt.get("productionTrustChanged") is False,
             "Fixture trust policy mismatch")
    _require(plan.get("platform") == "linux" and plan.get("packageFamily") == "default" and
             plan.get("architecture") == receipt.get("architecture") == "x86_64",
             "Linux RPM fixture platform mismatch")
    expected = [("base", base_version), ("target", target_version)]
    stages = plan.get("stages")
    builds = receipt.get("builds")
    _require(isinstance(stages, list) and isinstance(builds, list) and len(stages) == len(builds) == 2,
             "Fixture must have exactly two versions")
    code_fingerprints = []
    rpm_hashes = []
    for index, (label, version) in enumerate(expected):
        _require(stages[index].get("label") == builds[index].get("label") == label and
                 stages[index].get("version") == builds[index].get("version") == version,
                 "Fixture stage version mismatch")
        record = builds[index]
        _require(record.get("sourceFingerprint") == fingerprint, "Build source fingerprint mismatch")
        code = record.get("codeFingerprint")
        _require(isinstance(code, str) and DIGEST.fullmatch(code), "Build code fingerprint invalid")
        code_fingerprints.append(code)
        assets = record.get("assets")
        _require(isinstance(assets, list), "Missing fixture assets")
        rpms = [asset for asset in assets if asset.get("packageType") == "rpm"]
        _require(len(rpms) == 1, "Expected exactly one RPM for each version")
        asset = rpms[0]
        filename = f"vpn-control-{version}-1.x86_64.rpm"
        _require(asset.get("fileName") == filename, "RPM filename/version mismatch")
        path = directory / "packages" / label / filename
        _require(all(not ancestor.is_symlink() for ancestor in (directory / "packages", path.parent, path)) and
                 path.is_file() and path.parent.parent == directory / "packages",
                 "RPM path escaped fixture")
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        _require(asset.get("sizeBytes") == len(data) and asset.get("sha256") == digest,
                 "RPM bytes disagree with receipt")
        query = rpm_query or _rpm_query
        _require(tuple(query(path)) == ("vpn-control", version, "1", "x86_64"),
                 "RPM header NEVRA mismatch")
        rpm_hashes.append(digest)
    _require(code_fingerprints[0] == code_fingerprints[1], "Base and target code fingerprint mismatch")
    return {"schemaVersion": 1, "testOnly": True, "correlationId": correlation_id,
            "sourceHead": source_sha,
            "sourceFingerprint": fingerprint, "codeFingerprint": code_fingerprints[0],
            "baseVersion": base_version, "targetVersion": target_version,
            "baseRpmSha256": rpm_hashes[0], "targetRpmSha256": rpm_hashes[1]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--base-version", required=True)
    parser.add_argument("--target-version", required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = verify_fixture(args.directory, args.source_sha, args.base_version, args.target_version,
                            args.correlation_id)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()

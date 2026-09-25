#!/usr/bin/env python3
"""Record redacted signing evidence for an immutable macOS DMG fixture pair."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
import plistlib
import re
import subprocess
import tempfile


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def signing_configured() -> bool:
    return bool(os.environ.get("VPN_CONTROL_MACOS_SIGNING_CERTIFICATE_BASE64"))


def parse_codesign_metadata(output: str) -> dict[str, object]:
    fields: dict[str, object] = {"authorities": []}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if not separator:
            continue
        if key == "Authority":
            fields["authorities"].append(value)
        elif key in {"Identifier", "TeamIdentifier", "CDHash", "Signature"}:
            fields[key[0].lower() + key[1:]] = value
    return fields


def require_configured_developer_signature(metadata: dict[str, object]) -> None:
    identity = os.environ.get("VPN_CONTROL_MACOS_SIGNING_IDENTITY", "")
    authorities = metadata.get("authorities")
    require(metadata.get("signature") != "adhoc", "Configured signing policy produced an ad hoc signature")
    require(isinstance(authorities, list) and identity in authorities,
            "Configured signing policy did not produce the requested Developer ID authority")
    configured_team = os.environ.get("VPN_CONTROL_MACOS_NOTARIZATION_TEAM_ID", "")
    if configured_team:
        require(metadata.get("teamIdentifier") == configured_team,
                "Configured signing policy produced an unexpected team identifier")


@dataclass(frozen=True)
class Attachment:
    volume_device: str
    image_device: str
    mount: Path


def attach_dmg(dmg: Path, mount: Path) -> Attachment:
    result = subprocess.run(
        ["hdiutil", "attach", str(dmg), "-nobrowse", "-readonly", "-mountpoint", str(mount), "-plist"],
        check=True,
        capture_output=True,
    )
    document = plistlib.loads(result.stdout)
    entities = document.get("system-entities")
    require(isinstance(entities, list), "DMG attachment did not provide system entities")
    mount = mount.resolve(strict=True)
    matches = [entry for entry in entities if isinstance(entry, dict) and entry.get("mount-point") == str(mount)]
    require(len(matches) == 1 and isinstance(matches[0].get("dev-entry"), str), "DMG attachment identity is ambiguous")
    volume_device = matches[0]["dev-entry"]
    image_devices = [entry.get("dev-entry") for entry in entities if isinstance(entry, dict) and
                     isinstance(entry.get("dev-entry"), str) and volume_device.startswith(entry["dev-entry"] + "s")]
    require(len(image_devices) == 1, "DMG attachment parent identity is ambiguous")
    return Attachment(volume_device, image_devices[0], mount)


def app_in_mount(attachment: Attachment) -> Path:
    apps = sorted(attachment.mount.glob("*.app"))
    require(len(apps) == 1 and apps[0].is_dir() and not apps[0].is_symlink() and
            apps[0].resolve(strict=True).parent == attachment.mount, "DMG must contain exactly one app bundle")
    return apps[0]


def attachment_state(dmg: Path, attachment: Attachment) -> str:
    result = subprocess.run(["hdiutil", "info", "-plist"], check=True, capture_output=True)
    images = plistlib.loads(result.stdout).get("images")
    if not isinstance(images, list):
        return "malformed-image-list"
    expected_path = str(dmg.resolve(strict=True))
    matches = [image for image in images if isinstance(image, dict) and image.get("image-path") == expected_path]
    if not matches:
        return "absent"
    if len(matches) != 1:
        return "ambiguous-image"
    image = matches[0]
    entities = image.get("system-entities")
    if image.get("writeable") is not False or not isinstance(entities, list):
        return "malformed-image"
    devices = [entry.get("dev-entry") for entry in entities if isinstance(entry, dict)]
    if attachment.image_device not in devices:
        return "image-device-changed"
    mounts = [entry for entry in entities if isinstance(entry, dict) and isinstance(entry.get("mount-point"), str)]
    if any(entry.get("mount-point") != str(attachment.mount) for entry in mounts):
        return "unrelated-mounted-volume"
    owned = [entry for entry in mounts if entry.get("mount-point") == str(attachment.mount)]
    if not owned:
        return "image-attached-without-owned-volume"
    if len(owned) != 1 or owned[0].get("dev-entry") != attachment.volume_device:
        return "volume-device-changed"
    return "owned-mounted"


def detach_with_retries(device: str, mount: Path) -> None:
    for _ in range(5):
        if subprocess.run(["hdiutil", "detach", device, "-quiet"], check=False,
                          capture_output=True).returncode == 0:
            return
    raise RuntimeError("DMG could not be detached; device=" + device + "; mounted fixture preserved at " + str(mount))


def cleanup_attachment(dmg: Path, attachment: Attachment) -> None:
    state = attachment_state(dmg, attachment)
    require(state == "owned-mounted", "DMG attachment identity changed before cleanup: " + state)
    detach_with_retries(attachment.volume_device, attachment.mount)
    state = attachment_state(dmg, attachment)
    if state == "image-attached-without-owned-volume":
        detach_with_retries(attachment.image_device, attachment.mount)
        state = attachment_state(dmg, attachment)
    require(state == "absent", "DMG attachment changed after detach: " + state)
    try:
        attachment.mount.rmdir()
    except OSError as error:
        raise RuntimeError("DMG mountpoint could not be removed after detach; empty fixture preserved at " +
                           str(attachment.mount)) from error


def inspect_dmg(dmg: Path, expected_hash: str, configured: bool) -> dict[str, object]:
    require(sha256(dmg) == expected_hash, "DMG changed from fixture receipt")
    mount = Path(tempfile.mkdtemp(prefix="vpn-control-macos-signing-", dir="/private/tmp"))
    attachment: Attachment | None = None
    failure: BaseException | None = None
    try:
        attachment = attach_dmg(dmg, mount)
        app = app_in_mount(attachment)
        verify = subprocess.run(
            ["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app)],
            text=True,
            capture_output=True,
        )
        metadata_result = subprocess.run(["codesign", "-dv", "--verbose=4", str(app)], text=True, capture_output=True)
        signed = verify.returncode == 0
        metadata = parse_codesign_metadata(metadata_result.stderr)
        if configured:
            require(signed, "Configured signing policy did not produce a verifiable app bundle")
            require_configured_developer_signature(metadata)
        record: dict[str, object] = {
            "dmgFileName": dmg.name,
            "dmgSha256": expected_hash,
            "signed": signed,
            "configuredSigning": configured,
        }
        if signed:
            record.update(metadata)
        return record
    except BaseException as error:
        failure = error
        raise
    finally:
        if attachment is not None:
            try:
                cleanup_attachment(dmg, attachment)
            except BaseException as cleanup_error:
                if failure is None:
                    raise
                raise RuntimeError(str(failure) + "; additionally, DMG cleanup failed: " +
                                   str(cleanup_error)) from cleanup_error
        elif failure is None:
            try:
                mount.rmdir()
            except OSError as error:
                raise RuntimeError("DMG mountpoint could not be removed after attachment failure; fixture preserved at " +
                                   str(mount)) from error


def record(directory: Path) -> dict[str, object]:
    directory = directory.resolve(strict=True)
    receipt = json.loads((directory / "fixture-receipt.json").read_text(encoding="utf-8"))
    plan = json.loads((directory / "build-plan.json").read_text(encoding="utf-8"))
    require(receipt.get("testOnly") is True and plan.get("platform") == "macos", "Not a macOS test-only fixture")
    require(receipt.get("sourceFingerprint") == plan.get("sourceFingerprint"), "Fixture source fingerprint mismatch")
    builds = receipt.get("builds")
    require(isinstance(builds, list) and len(builds) == 2, "Fixture must contain base and target builds")
    require([build.get("label") if isinstance(build, dict) else None for build in builds] == ["base", "target"],
            "Fixture stages must be exactly base then target")
    require(builds[0].get("codeFingerprint") == builds[1].get("codeFingerprint"), "Fixture code fingerprints differ")
    packages = directory / "packages"
    require(packages.is_dir() and not packages.is_symlink() and packages.resolve(strict=True).parent == directory,
            "Fixture packages root escaped its directory")
    configured = signing_configured()
    records = []
    for build in builds:
        assets = build.get("assets")
        require(isinstance(assets, list) and len(assets) == 1, "Each fixture stage must contain one DMG")
        asset = assets[0]
        require(asset.get("packageType") == "dmg" and asset.get("architecture") == plan.get("architecture"), "Fixture asset metadata is invalid")
        label, filename = build["label"], asset.get("fileName")
        require(isinstance(filename, str) and re.fullmatch(r"[A-Za-z0-9_.+-]+\.dmg", filename) is not None,
                "Fixture DMG filename is unsafe")
        stage = packages / label
        require(stage.is_dir() and not stage.is_symlink() and stage.resolve(strict=True).parent == packages.resolve(strict=True),
                "Fixture stage path escaped its packages root")
        package = stage / filename
        require(package.is_file() and not package.is_symlink() and package.resolve(strict=True).parent == stage.resolve(strict=True),
                "Fixture DMG escaped its stage")
        entry = inspect_dmg(package, str(asset.get("sha256")), configured)
        entry.update({"label": build["label"], "version": build["version"], "codeFingerprint": build["codeFingerprint"]})
        records.append(entry)
    evidence = {
        "schemaVersion": 1,
        "testOnly": True,
        "sourceFingerprint": receipt["sourceFingerprint"],
        "architecture": plan["architecture"],
        "configuredSigning": configured,
        "packages": records,
    }
    output = directory / "signing-metadata.json"
    require(not output.is_symlink() and output.parent == directory, "Signing metadata output escaped fixture directory")
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    record(args.directory)


if __name__ == "__main__":
    main()

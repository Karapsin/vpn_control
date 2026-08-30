#!/usr/bin/env python3
"""Assemble versioned GitHub Release assets and the updater manifest."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil


REPOSITORY_URL = "https://github.com/Karapsin/vpn_control"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--incoming", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--build-number", type=int, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--mac-architecture", required=True)
    return parser.parse_args()


def one(root: Path, suffix: str) -> Path:
    matches = sorted(root.rglob(f"*{suffix}"))
    if len(matches) != 1:
        raise SystemExit(f"Expected one {suffix} under {root}, found {matches}")
    return matches[0]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def assemble(args: argparse.Namespace) -> None:
    if args.build_number <= 0:
        raise SystemExit("Build number must be positive")
    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise SystemExit(f"Release output directory is not empty: {output}")

    mac_arch = args.mac_architecture.strip().lower()
    mac_arch = "arm64" if mac_arch in {"arm64", "aarch64"} else "x86_64"
    incoming = args.incoming
    version = args.version
    specs = [
        (one(incoming / "vpn-control-android-release-apk", ".apk"), f"vpn-control-android-arm64-v{version}.apk", "android", "arm64", "apk", version),
        (one(incoming / "vpn-control-windows-installers", ".msi"), f"vpn-control-windows-x86_64-v{version}.msi", "windows", "x86_64", "msi", version),
        (one(incoming / "vpn-control-windows-installers", ".exe"), f"vpn-control-windows-x86_64-v{version}.exe", None, None, None, version),
        (one(incoming / "vpn-control-linux-packages", ".deb"), f"vpn-control-linux-x86_64-v{version}.deb", "linux", "x86_64", "deb", version),
        (one(incoming / "vpn-control-linux-packages", ".rpm"), f"vpn-control-linux-x86_64-v{version}.rpm", "linux", "x86_64", "rpm", version),
        (one(incoming / "vpn-control-linux-packages", ".tar.gz"), f"vpn-control-arch-x86_64-v{version}.tar.gz", "linux", "x86_64", "arch-bundle", version),
        (one(incoming / "vpn-control-macos-package", ".dmg"), f"vpn-control-macos-{mac_arch}-v{version}.dmg", "macos", mac_arch, "dmg", f"1.0.{args.build_number}"),
    ]
    assets = []
    for source, name, platform, architecture, package_type, display_version in specs:
        target = output / name
        shutil.copy2(source, target)
        if platform is not None:
            assets.append(
                {
                    "platform": platform,
                    "architecture": architecture,
                    "packageType": package_type,
                    "displayVersion": display_version,
                    "fileName": name,
                    "downloadUrl": f"{REPOSITORY_URL}/releases/download/{args.tag}/{name}",
                    "sha256": sha256(target),
                    "sizeBytes": target.stat().st_size,
                }
            )

    manifest = {
        "schemaVersion": 1,
        "buildNumber": args.build_number,
        "releaseTag": args.tag,
        "releaseNotesUrl": f"{REPOSITORY_URL}/releases/tag/{args.tag}",
        "assets": assets,
    }
    (output / "update-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    checksum_lines = [f"{sha256(path)}  {path.name}" for path in sorted(output.iterdir())]
    (output / "SHA256SUMS.txt").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    assemble(parse_args())

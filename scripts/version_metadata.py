#!/usr/bin/env python3
"""Read and validate VPN Control's canonical four-part version."""

from __future__ import annotations

import argparse
from pathlib import Path
import re


VERSION_PATTERN = re.compile(r"^vpnControlVersion=([^\s]+)$", re.MULTILINE)
MAX_COMPONENT = 19


def parse_version(value: str) -> tuple[int, int, int, int]:
    parts = value.strip().split(".")
    if len(parts) != 4 or any(not part.isdigit() for part in parts):
        raise ValueError("Version must have four numeric parts")
    numbers = tuple(int(part) for part in parts)
    if any(number < 0 or number > MAX_COMPONENT for number in numbers):
        raise ValueError("Version components must be between 0 and 19")
    return numbers  # type: ignore[return-value]


def read_version(repository: Path) -> str:
    text = (repository / "gradle.properties").read_text(encoding="utf-8")
    match = VERSION_PATTERN.search(text)
    if match is None:
        raise ValueError("gradle.properties is missing vpnControlVersion")
    value = match.group(1)
    parse_version(value)
    return value


def build_number(parts: tuple[int, int, int, int]) -> int:
    value = 0
    for part in parts:
        value = value * 20 + part
    if value <= 0:
        raise ValueError("Version build number must be positive")
    return value


def desktop_package_version(parts: tuple[int, int, int, int]) -> str:
    major, minor, patch, build = parts
    return f"{major}.{minor}.{patch * 20 + build}"


def macos_package_version(parts: tuple[int, int, int, int]) -> str:
    major, minor, patch, build = parts
    return f"1.{major * 20 + minor}.{patch * 20 + build}"


def metadata(repository: Path) -> dict[str, str]:
    version = read_version(repository)
    parts = parse_version(version)
    return {
        "version": version,
        "build-number": str(build_number(parts)),
        "desktop-package-version": desktop_package_version(parts),
        "macos-package-version": macos_package_version(parts),
        "tag": f"v{version}",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
    )
    parser.add_argument(
        "--field",
        choices=("version", "build-number", "desktop-package-version", "macos-package-version", "tag"),
        default="version",
    )
    args = parser.parse_args()
    print(metadata(args.repository.resolve())[args.field])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

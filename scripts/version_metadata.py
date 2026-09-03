#!/usr/bin/env python3
"""Read and validate VPN Control's canonical product version."""

from __future__ import annotations

import argparse
from pathlib import Path
import re


VERSION_PATTERN = re.compile(r"^vpnControlVersion=([^\s]+)$", re.MULTILINE)
MAX_COMPONENT = 19


def parse_version(value: str) -> tuple[int, int, int]:
    parts = value.strip().split(".")
    if len(parts) != 3 or any(not part.isdigit() for part in parts):
        raise ValueError("Version must have three numeric parts")
    numbers = tuple(int(part) for part in parts)
    if numbers[0] < 1 or any(number < 0 or number > MAX_COMPONENT for number in numbers):
        raise ValueError("Version major must be 1..19 and other components must be 0..19")
    return numbers  # type: ignore[return-value]


def read_version(repository: Path) -> str:
    text = (repository / "gradle.properties").read_text(encoding="utf-8")
    match = VERSION_PATTERN.search(text)
    if match is None:
        raise ValueError("gradle.properties is missing vpnControlVersion")
    value = match.group(1)
    parse_version(value)
    return value


def build_number(parts: tuple[int, int, int]) -> int:
    value = 0
    for part in parts:
        value = value * 20 + part
    # Preserve monotonic ordering over legacy four-part builds by reserving the
    # retired fourth base-20 component as zero. This is an internal build ID,
    # never a platform-specific product version.
    value *= 20
    if value <= 0:
        raise ValueError("Version build number must be positive")
    return value


def product_version(parts: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in parts)


def metadata(repository: Path) -> dict[str, str]:
    version = read_version(repository)
    parts = parse_version(version)
    return {
        "version": version,
        "build-number": str(build_number(parts)),
        # Compatibility field names remain available to packaging scripts, but
        # their values are the one canonical product version on every platform.
        "desktop-package-version": product_version(parts),
        "macos-package-version": product_version(parts),
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

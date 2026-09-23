#!/usr/bin/env python3
"""Verify declared private QEMU assets before a VM process can be started."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import stat
import sys
from typing import Iterable


class AssetPreflightError(ValueError):
    """A declared QEMU asset cannot safely be used."""


def _relative_path(value: str) -> PurePosixPath:
    if (not value or "\\" in value or PureWindowsPath(value).drive
            or any(part in {"", ".", ".."} for part in value.split("/"))):
        raise AssetPreflightError("invalid asset path")
    relative = PurePosixPath(value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise AssetPreflightError("invalid asset path")
    return relative


def _digest(value: str) -> str:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise AssetPreflightError("invalid SHA-256 digest")
    return value


def _declaration(value: str) -> tuple[PurePosixPath, str]:
    path, delimiter, expected = value.rpartition("=")
    if not delimiter:
        raise AssetPreflightError("asset must be relative/path=lowercase-sha256")
    return _relative_path(path), _digest(expected)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _asset_file(root: Path, relative: PurePosixPath) -> Path:
    """Return a regular non-symlink file after checking each lexical component."""
    current = root
    for component in relative.parts:
        current /= component
        try:
            details = current.lstat()
        except FileNotFoundError as error:
            raise AssetPreflightError(f"asset is missing: {relative.as_posix()}") from error
        if stat.S_ISLNK(details.st_mode):
            raise AssetPreflightError(f"asset path contains a symbolic link: {relative.as_posix()}")
    if not stat.S_ISREG(current.lstat().st_mode):
        raise AssetPreflightError(f"asset is not a regular file: {relative.as_posix()}")
    return current


def verify_assets(root: Path, declarations: Iterable[str]) -> list[dict[str, object]]:
    """Validate all declared assets and return deterministic bounded metadata."""
    try:
        root_details = root.lstat()
    except FileNotFoundError as error:
        raise AssetPreflightError("asset root is not a directory") from error
    if stat.S_ISLNK(root_details.st_mode) or not stat.S_ISDIR(root_details.st_mode):
        raise AssetPreflightError("asset root is not a directory")

    requested = [_declaration(value) for value in declarations]
    if not requested:
        raise AssetPreflightError("at least one --asset is required")
    requested.sort(key=lambda item: item[0].as_posix())
    if any(left[0] == right[0] for left, right in zip(requested, requested[1:])):
        raise AssetPreflightError("duplicate asset path")

    metadata = []
    for relative, expected in requested:
        path = _asset_file(root, relative)
        actual = _sha256(path)
        if actual != expected:
            raise AssetPreflightError(f"asset digest mismatch: {relative.as_posix()}")
        metadata.append({"path": relative.as_posix(), "sha256": actual, "bytes": path.stat().st_size})
    return metadata


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="private QEMU asset root")
    parser.add_argument("--asset", action="append", default=[], metavar="RELATIVE_PATH=SHA256",
                        help="required private asset (repeatable)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        assets = verify_assets(args.root, args.asset)
    except (AssetPreflightError, OSError) as error:
        print(f"QEMU asset preflight failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"status": "ok", "assets": assets}, separators=(",", ":"), sort_keys=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

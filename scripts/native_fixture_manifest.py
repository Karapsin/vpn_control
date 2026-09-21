#!/usr/bin/env python3
"""Write deterministic SHA-256 manifests for disposable native-fixture roots."""

import argparse
import hashlib
from pathlib import Path, PurePosixPath, PureWindowsPath
import re


_MANIFEST_LINE = re.compile(r"([0-9a-f]{64})  (.+)")


def sha256(path: Path) -> str:
    """Return the SHA-256 digest of one regular file."""
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _root(root: Path) -> Path:
    root = root.absolute()
    if not root.is_dir():
        raise ValueError(f"Manifest root is not a directory: {root}")
    return root


def _manifest_relative_name(name: str) -> PurePosixPath:
    if "\n" in name or "\r" in name:
        raise ValueError("SHA-256 manifest filenames cannot contain a newline")
    if "\\" in name or PureWindowsPath(name).drive:
        raise ValueError("SHA-256 manifest filenames cannot use Windows path syntax")
    relative = PurePosixPath(name)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("SHA-256 manifest contains an invalid filename")
    return relative


def _relative_name(root: Path, path: Path) -> str:
    try:
        name = path.relative_to(root).as_posix()
    except ValueError as error:
        raise ValueError(f"Manifest file escapes root: {path}") from error
    _manifest_relative_name(name)
    return name


def _unlinked_path_below_root(root: Path, path: Path) -> Path:
    """Resolve an in-root path only after rejecting every lexical symlink component."""
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise ValueError(f"Manifest file escapes root: {path}") from error
    if not relative.parts or any(part in {".", ".."} for part in relative.parts):
        raise ValueError(f"Manifest file escapes root: {path}")
    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"Manifest paths cannot contain symbolic links: {current}")
    try:
        path.resolve(strict=False).relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"Manifest file escapes root: {path}") from error
    return path


def _output_path(root: Path, output: Path) -> Path:
    output = output if output.is_absolute() else root / output
    output = _unlinked_path_below_root(root, output)
    if output.is_symlink() or (output.exists() and not output.is_file()):
        raise ValueError(f"Manifest output is not a regular file: {output}")
    return output


def _manifest_files(root: Path, output: Path) -> list[tuple[str, Path]]:
    files = []
    for path in root.rglob("*"):
        if path == output:
            continue
        if path.is_symlink():
            raise ValueError(f"Manifest inputs cannot be symbolic links: {path}")
        if path.is_file():
            path = _unlinked_path_below_root(root, path)
            files.append((_relative_name(root, path), path))
    return sorted(files, key=lambda item: item[0])


def verify_manifest(root: Path, manifest: Path) -> None:
    """Require every manifest entry to name an in-root file with its recorded digest."""
    root = _root(root)
    manifest = _output_path(root, manifest)
    text = manifest.read_text(encoding="utf-8")
    if not text.endswith("\n"):
        raise ValueError("SHA-256 manifest must end with a newline")
    lines = [] if text == "\n" else text.splitlines()
    for line in lines:
        match = _MANIFEST_LINE.fullmatch(line)
        if match is None:
            raise ValueError("SHA-256 manifest contains an invalid entry")
        expected, name = match.groups()
        relative = _manifest_relative_name(name)
        path = _unlinked_path_below_root(root, root.joinpath(*relative.parts))
        if path == manifest:
            raise ValueError("SHA-256 manifest must not include itself")
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"SHA-256 manifest entry is not a regular file: {name}")
        if sha256(path) != expected:
            raise ValueError(f"SHA-256 manifest digest mismatch: {name}")


def write_manifest(root: Path, output: Path = Path("SHA256SUMS.txt")) -> Path:
    """Write and verify a deterministic sha256sum-compatible manifest below *root*."""
    root = _root(root)
    output = _output_path(root, output)
    lines = [f"{sha256(path)}  {name}" for name, path in _manifest_files(root, output)]
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    verify_manifest(root, output)
    return output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="fixture directory to hash")
    parser.add_argument(
        "--output", type=Path, default=Path("SHA256SUMS.txt"),
        help="manifest path relative to --root (default: SHA256SUMS.txt)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    print(write_manifest(args.root, args.output))


if __name__ == "__main__":
    main()

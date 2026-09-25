#!/usr/bin/env python3
"""Verify native-fixture archive metadata and restored-tree manifests.

Directory byte sizes are filesystem-specific and are intentionally excluded from
comparison.  Every other recorded field, including executable mode bits, must
match exactly.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import stat
import tarfile
from typing import Any, Iterable, Mapping

try:  # Direct script execution is the normal repository workflow.
    from native_fixture_manifest import sha256
except ModuleNotFoundError:  # Permit reusable imports from the repository root.
    from scripts.native_fixture_manifest import sha256


_ENTRY_TYPES = {"directory", "file", "symlink"}


def _relative(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("manifest entry path must be a non-empty string")
    # Validate lexical components before PurePosixPath can normalize them.
    if value.startswith("/") or any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError(f"manifest entry path is unsafe: {value!r}")
    path = PurePosixPath(value)
    return path.as_posix()


def _portable_mode(mode: int, description: str) -> str:
    if mode & ~0o777:
        raise ValueError(f"{description} has unsupported special mode bits")
    return f"{mode:03o}"


def _mode(value: object) -> str:
    if not isinstance(value, str) or len(value) != 3 or any(char not in "01234567" for char in value):
        raise ValueError("manifest entry mode must be a three-digit octal string")
    return value


def _entry(entry: object) -> dict[str, Any]:
    if not isinstance(entry, dict):
        raise ValueError("manifest entry must be an object")
    result = dict(entry)
    result["rel"] = _relative(result.get("rel"))
    result["mode"] = _mode(result.get("mode"))
    kind = result.get("type")
    if kind not in _ENTRY_TYPES:
        raise ValueError("manifest entry has an unsupported type")
    if not isinstance(result.get("size"), int) or result["size"] < 0:
        raise ValueError("manifest entry size must be a non-negative integer")
    if kind == "file":
        digest = result.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError("file manifest entry requires a lowercase SHA-256")
    elif "sha256" in result:
        raise ValueError("only file manifest entries may have SHA-256")
    if kind == "symlink":
        target = result.get("target")
        if not isinstance(target, str) or not target:
            raise ValueError("symlink manifest entry requires a target")
    elif "target" in result:
        raise ValueError("only symlink manifest entries may have a target")
    return result


def load_manifest(path: str) -> dict[str, dict[str, Any]]:
    """Load a schema-1 manifest and reject duplicate or malformed entries."""
    document = json.loads(open(path, encoding="utf-8").read())
    if not isinstance(document, dict) or document.get("schema") != 1 or not isinstance(document.get("entries"), list):
        raise ValueError("manifest must be a schema-1 object with entries")
    entries: dict[str, dict[str, Any]] = {}
    for value in document["entries"]:
        entry = _entry(value)
        if entry["rel"] in entries:
            raise ValueError(f"manifest has duplicate entry: {entry['rel']}")
        entries[entry["rel"]] = entry
    return entries


def manifest_tree(root: Path, original_path: str | None = None) -> dict[str, Any]:
    """Create a schema-1 manifest for one restored tree without following links."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"manifest root is not a real directory: {root}")
    root = root.resolve()
    entries: list[dict[str, Any]] = []
    for path in [root, *sorted(root.rglob("*"), key=lambda item: item.as_posix())]:
        metadata = path.lstat()
        relative = root.name if path == root else f"{root.name}/{path.relative_to(root).as_posix()}"
        mode = _portable_mode(stat.S_IMODE(metadata.st_mode), f"manifest tree entry: {path}")
        if stat.S_ISDIR(metadata.st_mode):
            entries.append({"rel": relative, "type": "directory", "mode": mode, "size": metadata.st_size})
        elif stat.S_ISREG(metadata.st_mode):
            entries.append({"rel": relative, "type": "file", "mode": mode, "size": metadata.st_size, "sha256": sha256(path)})
        elif stat.S_ISLNK(metadata.st_mode):
            entries.append({"rel": relative, "type": "symlink", "mode": mode, "size": metadata.st_size, "target": path.readlink().as_posix()})
        else:
            raise ValueError(f"manifest tree has unsupported entry: {path}")
    return {"schema": 1, "originalPath": original_path or str(root), "entries": entries}


def write_tree_manifest(root: Path, output: Path, original_path: str | None = None) -> None:
    """Write a deterministic schema-1 manifest for *root*."""
    output.write_text(json.dumps(manifest_tree(root, original_path), sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def _comparable(entry: Mapping[str, Any]) -> dict[str, Any]:
    """Return metadata whose preservation is portable and required."""
    fields = {"rel", "type", "mode"}
    if entry["type"] == "file":
        fields.update({"size", "sha256"})
    elif entry["type"] == "symlink":
        fields.update({"size", "target"})
    # Directory allocation size varies across APFS, ext4, and extraction order.
    return {field: entry[field] for field in fields}


def compare_manifests(expected: Mapping[str, Mapping[str, Any]], actual: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """Return deterministic differences, ignoring directory byte sizes only."""
    differences: list[str] = []
    for name in sorted(set(expected) | set(actual)):
        if name not in expected:
            differences.append(f"unexpected entry: {name}")
        elif name not in actual:
            differences.append(f"missing entry: {name}")
        elif _comparable(expected[name]) != _comparable(actual[name]):
            differences.append(f"metadata mismatch: {name}")
    return differences


def _tar_name(name: str) -> str:
    return _relative(name[:-1] if name.endswith("/") else name)


def _tar_type(member: tarfile.TarInfo) -> str:
    if member.isdir():
        return "directory"
    if member.isreg():
        return "file"
    if member.islnk():
        return "hardlink"
    if member.issym():
        return "symlink"
    raise ValueError(f"archive contains unsupported member type: {member.name}")


def archive_header_entries(path: str) -> dict[str, dict[str, Any]]:
    """Read portable tar header metadata without extracting the archive."""
    entries: dict[str, dict[str, Any]] = {}
    with tarfile.open(path, "r:") as archive:
        for member in archive.getmembers():
            name = _tar_name(member.name)
            if name in entries:
                raise ValueError(f"archive has duplicate member: {name}")
            kind = _tar_type(member)
            entry: dict[str, Any] = {"rel": name, "type": kind, "mode": _portable_mode(member.mode, f"archive member: {name}")}
            if kind == "file":
                entry["size"] = member.size
            elif kind == "hardlink":
                entry["target"] = _tar_name(member.linkname)
            elif kind == "symlink":
                entry["target"] = member.linkname
            entries[name] = entry
    def resolve_hardlink(name: str, seen: set[str]) -> dict[str, Any]:
        entry = entries[name]
        if entry["type"] != "hardlink":
            return entry
        target = entry["target"]
        if target not in entries or target in seen:
            raise ValueError(f"archive hard link has an invalid target: {name}")
        source = resolve_hardlink(target, seen | {name})
        if source["type"] != "file":
            raise ValueError(f"archive hard link does not target a file: {name}")
        return {"rel": name, "type": "file", "mode": entry["mode"], "size": source["size"]}
    return {name: resolve_hardlink(name, set()) for name in entries}


def compare_archive_headers(manifest: Mapping[str, Mapping[str, Any]], headers: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """Require archive paths, types, modes, and file sizes to match a manifest."""
    differences: list[str] = []
    for name in sorted(set(manifest) | set(headers)):
        if name not in manifest:
            differences.append(f"unexpected archive member: {name}")
        elif name not in headers:
            differences.append(f"missing archive member: {name}")
        else:
            expected = manifest[name]
            actual = headers[name]
            fields = {"rel", "type", "mode"}
            if expected["type"] == "file":
                fields.add("size")
            elif expected["type"] == "symlink":
                fields.add("target")
            if any(expected.get(field) != actual.get(field) for field in fields):
                differences.append(f"archive header mismatch: {name}")
    return differences


def _emit(differences: Iterable[str]) -> int:
    failures = list(differences)
    print(json.dumps({"ok": not failures, "differences": failures}, sort_keys=True))
    return 0 if not failures else 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    compare = commands.add_parser("compare", help="compare restored and source manifests")
    compare.add_argument("expected")
    compare.add_argument("actual")
    headers = commands.add_parser("headers", help="compare tar headers to a source manifest")
    headers.add_argument("manifest")
    headers.add_argument("archive")
    write = commands.add_parser("write", help="write a schema-1 tree manifest")
    write.add_argument("root", type=Path)
    write.add_argument("output", type=Path)
    write.add_argument("--original-path")
    args = parser.parse_args()
    if args.command == "compare":
        raise SystemExit(_emit(compare_manifests(load_manifest(args.expected), load_manifest(args.actual))))
    if args.command == "headers":
        raise SystemExit(_emit(compare_archive_headers(load_manifest(args.manifest), archive_header_entries(args.archive))))
    write_tree_manifest(args.root, args.output, args.original_path)


if __name__ == "__main__":
    main()

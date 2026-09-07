#!/usr/bin/env python3
"""Build-input and artifact checks for the fixed Windows NativeAOT helpers.

This tool is deliberately data-only: it neither elevates nor launches helper binaries.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path


PRODUCT_NAMES = {"vpn-control-install-helper.exe", "vpn-control-vpn-broker.exe"}
TEST_MARKERS = ("test", "probe")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_guest_destination(candidate: Path, expected_leaf: str) -> Path:
    """Accept only the named disposable guest root, never a sibling guest."""
    if not expected_leaf or "/" in expected_leaf or "\\" in expected_leaf:
        raise ValueError("expected guest destination leaf rejected")
    resolved = candidate.resolve()
    if resolved.name != expected_leaf:
        raise ValueError("guest destination identity rejected")
    return resolved


def _rva_offset(data: bytes, pe_offset: int, rva: int) -> int:
    sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    section = pe_offset + 24 + optional_size
    for index in range(sections):
        offset = section + index * 40
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", data, offset + 8)
        if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
            return raw_offset + rva - virtual_address
    raise ValueError("PE RVA is outside every section")


def _ascii_at(data: bytes, offset: int) -> str:
    end = data.find(b"\0", offset)
    if end < offset:
        raise ValueError("PE import name is unterminated")
    return data[offset:end].decode("ascii", "strict").lower()


def _imports(data: bytes, pe_offset: int, directory_index: int, delay: bool = False) -> list[str]:
    optional = pe_offset + 24
    rva, size = struct.unpack_from("<II", data, optional + 112 + directory_index * 8)
    if not rva and not size:
        return []
    if not rva or not size:
        raise ValueError("PE import directory is incomplete")
    offset = _rva_offset(data, pe_offset, rva)
    imports: list[str] = []
    descriptor_size = 32 if delay else 20
    while True:
        if offset + descriptor_size > len(data):
            raise ValueError("PE import directory is truncated")
        if not any(data[offset:offset + descriptor_size]):
            return sorted(set(imports))
        name_rva = struct.unpack_from("<I", data, offset + (4 if delay else 12))[0]
        if not name_rva:
            raise ValueError("PE import descriptor has no DLL name")
        imports.append(_ascii_at(data, _rva_offset(data, pe_offset, name_rva)))
        offset += descriptor_size


def pe_metadata(path: Path, allowed_imports: set[str] | None = None) -> dict[str, object]:
    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError(f"{path}: expected PE MZ header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError(f"{path}: expected PE signature")
    machine, sections, _, _, _, optional_size, _ = struct.unpack_from("<HHIIIHH", data, pe_offset + 4)
    if machine != 0x8664:
        raise ValueError(f"{path}: expected AMD64 PE, got machine {machine:#x}")
    optional = pe_offset + 24
    if optional + optional_size > len(data) or struct.unpack_from("<H", data, optional)[0] != 0x20B:
        raise ValueError(f"{path}: expected PE32+ optional header")
    # IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR is entry 14 in the PE32+ data directory.
    directories = optional + 112
    clr_rva, clr_size = struct.unpack_from("<II", data, directories + 14 * 8)
    if clr_rva or clr_size:
        raise ValueError(f"{path}: CLR header present; NativeAOT output required")
    imports = _imports(data, pe_offset, 1)
    delay_imports = _imports(data, pe_offset, 13, delay=True)
    observed = set(imports + delay_imports)
    if allowed_imports is not None:
        unexpected = sorted(observed - allowed_imports)
        if unexpected:
            raise ValueError(f"{path}: imports outside allowlist: {', '.join(unexpected)}")
    lower = data.lower()
    forbidden = [needle.decode("ascii") for needle in (b"mscoree.dll", b"coreclr.dll", b"hostfxr.dll") if needle in lower]
    if forbidden:
        raise ValueError(f"{path}: forbidden CLR import/name: {', '.join(forbidden)}")
    return {"machine": "AMD64", "sections": sections, "clrHeader": False, "imports": imports, "delayImports": delay_imports}


def source_manifest(paths: list[Path]) -> dict[str, object]:
    if not paths:
        raise ValueError("at least one source input is required")
    resolved = sorted({path.resolve() for path in paths}, key=lambda item: str(item))
    if any(not path.is_file() for path in resolved):
        missing = next(path for path in resolved if not path.is_file())
        raise ValueError(f"source input missing: {missing}")
    records = [{"path": str(path), "sha256": sha256(path), "sizeBytes": path.stat().st_size} for path in resolved]
    fingerprint = hashlib.sha256(json.dumps(records, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"schemaVersion": 1, "inputs": records, "fingerprint": fingerprint}


def validate_output(output: Path, manifest: Path, allowed_imports: set[str]) -> dict[str, object]:
    if output.name not in PRODUCT_NAMES or any(marker in output.name.lower() for marker in TEST_MARKERS):
        raise ValueError(f"product output name rejected: {output.name}")
    if not allowed_imports:
        raise ValueError("an explicit import allowlist is required")
    metadata = pe_metadata(output, allowed_imports)
    result = {"schemaVersion": 1, "artifacts": [{"name": output.name, "sha256": sha256(output), "sizeBytes": output.stat().st_size, **metadata}]}
    manifest.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def fixture_transfer_target(candidate: Path, expected_leaf: str, fixture_name: str) -> Path:
    root = validate_guest_destination(candidate, expected_leaf)
    if Path(fixture_name).name != fixture_name or not fixture_name:
        raise ValueError("fixture leaf rejected")
    return root / "transfer" / fixture_name


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sources = sub.add_parser("sources")
    sources.add_argument("--output", type=Path, required=True)
    sources.add_argument("inputs", type=Path, nargs="+")
    verify = sub.add_parser("verify-product")
    verify.add_argument("--output", type=Path, required=True)
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--allowed-import", action="append", required=True)
    destination = sub.add_parser("validate-destination")
    destination.add_argument("--expected-leaf", required=True)
    destination.add_argument("candidate", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "sources":
            record = source_manifest(args.inputs)
            args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        elif args.command == "verify-product":
            record = validate_output(args.output, args.manifest, {name.lower() for name in args.allowed_import})
        else:
            record = {"destination": str(validate_guest_destination(args.candidate, args.expected_leaf))}
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"windows_native_helpers: {error}", file=sys.stderr)
        return 2
    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

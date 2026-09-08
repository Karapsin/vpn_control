#!/usr/bin/env python3
"""Build-input and artifact checks for the fixed Windows NativeAOT helpers.

This tool is deliberately data-only: it neither elevates nor launches helper binaries.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path


PRODUCT_NAMES = {"vpn-control-install-helper.exe", "vpn-control-vpn-broker.exe"}
TEST_MARKERS = ("test", "probe")
IMPORT_POLICY = Path(__file__).resolve().parent.parent / "desktopApp/native/windows/import-policy.json"
SYSTEM32_DEPENDENT_LOAD_FLAGS = 0x800


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


def _rva_offset(data: bytes, pe_offset: int, rva: int, length: int = 1) -> int:
    sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    section = pe_offset + 24 + optional_size
    matches = []
    for index in range(sections):
        offset = section + index * 40
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", data, offset + 8)
        delta = rva - virtual_address
        if 0 <= delta and length > 0 and delta + length <= min(raw_size, max(virtual_size, raw_size)):
            candidate = raw_offset + delta
            if candidate + length <= len(data):
                matches.append(candidate)
    if len(matches) != 1:
        raise ValueError("PE RVA does not identify one complete file-backed section range")
    return matches[0]


def _ascii_at(data: bytes, pe_offset: int, rva: int) -> str:
    offset = _rva_offset(data, pe_offset, rva)
    end = data.find(b"\0", offset)
    if end < offset or _rva_offset(data, pe_offset, rva, end - offset + 1) != offset:
        raise ValueError("PE import name is unterminated within its section")
    value = data[offset:end].decode("ascii", "strict").lower()
    if not value.endswith(".dll") or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-_." for character in value):
        raise ValueError("PE import name is not a DLL leaf")
    return value


def _imports(data: bytes, pe_offset: int, directory_index: int, delay: bool = False) -> list[str]:
    optional = pe_offset + 24
    rva, size = struct.unpack_from("<II", data, optional + 112 + directory_index * 8)
    if not rva and not size:
        return []
    if not rva or not size:
        raise ValueError("PE import directory is incomplete")
    offset = _rva_offset(data, pe_offset, rva, size)
    end = offset + size
    imports: list[str] = []
    descriptor_size = 32 if delay else 20
    while True:
        if offset + descriptor_size > end:
            raise ValueError("PE import directory is truncated")
        if not any(data[offset:offset + descriptor_size]):
            return sorted(set(imports))
        if delay and struct.unpack_from("<I", data, offset)[0] != 1:
            raise ValueError("PE delay import descriptor must use relative addresses")
        name_rva = struct.unpack_from("<I", data, offset + (4 if delay else 12))[0]
        if not name_rva:
            raise ValueError("PE import descriptor has no DLL name")
        imports.append(_ascii_at(data, pe_offset, name_rva))
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
    if optional_size < 240 or optional + optional_size > len(data) or struct.unpack_from("<H", data, optional)[0] != 0x20B:
        raise ValueError(f"{path}: expected PE32+ optional header")
    if not 1 <= sections <= 96 or optional + optional_size + sections * 40 > len(data):
        raise ValueError(f"{path}: expected a complete PE section table")
    directory_count = struct.unpack_from("<I", data, optional + 108)[0]
    if directory_count < 15 or 112 + directory_count * 8 > optional_size:
        raise ValueError(f"{path}: expected complete PE data directories")
    # IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR is entry 14 in the PE32+ data directory.
    directories = optional + 112
    clr_rva, clr_size = struct.unpack_from("<II", data, directories + 14 * 8)
    if clr_rva or clr_size:
        raise ValueError(f"{path}: CLR header present; NativeAOT output required")
    load_rva, load_size = struct.unpack_from("<II", data, directories + 10 * 8)
    dependent_flags = None
    if load_rva and load_size >= 80:
        load_offset = _rva_offset(data, pe_offset, load_rva, load_size)
        structure_size = struct.unpack_from("<I", data, load_offset)[0]
        if not 80 <= structure_size <= load_size:
            raise ValueError(f"{path}: incomplete PE load configuration")
        dependent_flags = struct.unpack_from("<H", data, load_offset + 78)[0]
    if dependent_flags != SYSTEM32_DEPENDENT_LOAD_FLAGS:
        raise ValueError(f"{path}: emitted PE must restrict dependent loads to System32 (0x800)")
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
    return {"machine": "AMD64", "sections": sections, "clrHeader": False, "imports": imports,
            "delayImports": delay_imports, "dependentLoadFlags": dependent_flags}


def import_policy(name: str) -> dict[str, object]:
    root = json.loads(IMPORT_POLICY.read_text(encoding="utf-8"))
    if root.get("schemaVersion") != 1 or name not in root.get("roles", {}):
        raise ValueError(f"no reviewed loader policy for product: {name}")
    policy = root["roles"][name]
    if (policy.get("dependentLoadFlags") != SYSTEM32_DEPENDENT_LOAD_FLAGS or
            policy.get("minimumWindowsBuild", 0) < 14393):
        raise ValueError("reviewed loader policy must require System32 dependent loading")
    for kind in ("imports", "delayImports"):
        names = policy.get(kind)
        if (not isinstance(names, list) or len(names) != len(set(names)) or any(
                not isinstance(value, str) or not value.endswith(".dll") or any(
                    character not in "abcdefghijklmnopqrstuvwxyz0123456789-_." for character in value)
                for value in names)):
            raise ValueError("reviewed loader policy requires exact lowercase DLL names")
    return policy


def _manifest_tree(data: bytes):
    text = data.decode("utf-8-sig", "strict")
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ValueError("loader manifest declarations are not permitted")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as error:
        raise ValueError("loader manifest is not valid XML") from error

    def canonical(element):
        return (element.tag, tuple(sorted(element.attrib.items())), (element.text or "").strip(),
                tuple(canonical(child) for child in element), (element.tail or "").strip())
    return canonical(root)


def manifest_metadata(path: Path, expected: Path) -> dict[str, object]:
    data = path.read_bytes()
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    rva, size = struct.unpack_from("<II", data, pe_offset + 24 + 112 + 2 * 8)
    if not rva or size < 16:
        raise ValueError("embedded loader manifest resource is required")
    base = _rva_offset(data, pe_offset, rva, size)

    def resource_offset(relative, length):
        if relative < 0 or length < 1 or relative + length > size:
            raise ValueError("loader manifest resource directory is truncated")
        return base + relative

    def entries(relative):
        offset = resource_offset(relative, 16)
        names, identifiers = struct.unpack_from("<HH", data, offset + 12)
        count = names + identifiers
        resource_offset(relative, 16 + count * 8)
        return [struct.unpack_from("<II", data, offset + 16 + index * 8) for index in range(count)]

    def directory(relative, identifier):
        matches = [target for name, target in entries(relative) if name == identifier]
        if len(matches) != 1 or not matches[0] & 0x80000000:
            raise ValueError("one exact embedded loader manifest resource is required")
        return matches[0] & 0x7FFFFFFF

    language_entries = entries(directory(directory(0, 24), 1))
    if len(language_entries) != 1 or language_entries[0][0] & 0x80000000 or language_entries[0][1] & 0x80000000:
        raise ValueError("loader manifest must have one unambiguous language resource")
    offset = resource_offset(language_entries[0][1], 16)
    manifest_rva, manifest_size, _, reserved = struct.unpack_from("<IIII", data, offset)
    if reserved:
        raise ValueError("loader manifest resource has reserved flags")
    manifest_offset = _rva_offset(data, pe_offset, manifest_rva, manifest_size)
    manifest_bytes = data[manifest_offset:manifest_offset + manifest_size]
    if _manifest_tree(manifest_bytes) != _manifest_tree(expected.read_bytes()):
        raise ValueError("embedded loader manifest differs from the reviewed application manifest")
    return {"manifestResourceId": 1, "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "manifestSourceSha256": sha256(expected)}


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


def artifact_manifest(output: Path, allowed_imports: set[str] | None = None) -> dict[str, object]:
    if output.is_symlink() or not output.is_file():
        raise ValueError("native helper must be a regular file")
    if output.name not in PRODUCT_NAMES or any(marker in output.name.lower() for marker in TEST_MARKERS):
        raise ValueError(f"product output name rejected: {output.name}")
    policy = import_policy(output.name)
    reviewed_imports = set(policy["imports"] + policy["delayImports"])
    if allowed_imports is not None and not allowed_imports.issubset(reviewed_imports):
        raise ValueError("caller imports are outside the reviewed loader policy")
    metadata = pe_metadata(output, reviewed_imports if allowed_imports is None else allowed_imports)
    if set(metadata["imports"]) - set(policy["imports"]) or set(metadata["delayImports"]) - set(policy["delayImports"]):
        raise ValueError("PE import kind is outside the reviewed loader policy")
    expected_manifest = (IMPORT_POLICY.parent / policy["manifest"]).resolve()
    if not expected_manifest.is_relative_to(IMPORT_POLICY.parent):
        raise ValueError("reviewed loader manifest path is outside the native helper sources")
    metadata.update(manifest_metadata(output, expected_manifest))
    return {"schemaVersion": 1, "policySha256": sha256(IMPORT_POLICY), "artifacts": [
        {"name": output.name, "sha256": sha256(output), "sizeBytes": output.stat().st_size,
         "minimumWindowsBuild": policy["minimumWindowsBuild"], "operations": policy["operations"], **metadata}]}


def validate_output(output: Path, manifest: Path, allowed_imports: set[str] | None = None) -> dict[str, object]:
    result = artifact_manifest(output, allowed_imports)
    manifest.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def verified_product(output: Path, manifest: Path) -> dict[str, object]:
    if manifest.is_symlink() or not manifest.is_file():
        raise ValueError("native helper manifest must be a regular file")
    record = json.loads(manifest.read_text(encoding="utf-8"))
    if record != artifact_manifest(output):
        raise ValueError("native helper manifest disagrees with captured bytes or reviewed policy")
    return record


def image_native_directory(image: Path) -> Path:
    for directory in (image, image / "app"):
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError("native helpers require a prepared regular application directory")
    return image / "app" / "native" / "windows-amd64"


def inspect_image(image: Path) -> dict[str, object]:
    directory = image_native_directory(image)
    for parent in (directory.parent, directory):
        if parent.is_symlink() or not parent.is_dir():
            raise ValueError("prepared application native helpers are missing or redirected")
    return verified_product(directory / "vpn-control-install-helper.exe", directory / "native-helpers.json")


def stage_product(output: Path, manifest: Path, image: Path) -> dict[str, object]:
    record = verified_product(output, manifest)
    directory = image_native_directory(image)
    if directory.parent.is_symlink():
        raise ValueError("prepared application native directory is redirected")
    directory.parent.mkdir(exist_ok=True)
    if directory.exists() or directory.is_symlink():
        if inspect_image(image) != record:
            raise ValueError("prepared application already contains different native helpers")
        return record
    temporary = Path(tempfile.mkdtemp(prefix=".windows-amd64-", dir=directory.parent))
    try:
        with output.open("rb") as source, (temporary / output.name).open("xb") as target:
            shutil.copyfileobj(source, target, 1024 * 1024)
        (temporary / "native-helpers.json").write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        # Check the bytes actually captured, not just the earlier source observation.
        if artifact_manifest(temporary / output.name) != record:
            raise ValueError("native helper changed during application staging")
        os.rename(temporary, directory)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return inspect_image(image)


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
    verify.add_argument("--allowed-import", action="append", help="Further restrict the reviewed product import policy")
    stage = sub.add_parser("stage-product")
    stage.add_argument("--output", type=Path, required=True)
    stage.add_argument("--manifest", type=Path, required=True)
    stage.add_argument("--app-image", type=Path, required=True)
    inspect = sub.add_parser("inspect-image")
    inspect.add_argument("--app-image", type=Path, required=True)
    destination = sub.add_parser("validate-destination")
    destination.add_argument("--expected-leaf", required=True)
    destination.add_argument("candidate", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "sources":
            record = source_manifest(args.inputs)
            args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        elif args.command == "verify-product":
            allowed = None if args.allowed_import is None else {name.lower() for name in args.allowed_import}
            record = validate_output(args.output, args.manifest, allowed)
        elif args.command == "stage-product":
            record = stage_product(args.output, args.manifest, args.app_image)
        elif args.command == "inspect-image":
            record = inspect_image(args.app_image)
        else:
            record = {"destination": str(validate_guest_destination(args.candidate, args.expected_leaf))}
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"windows_native_helpers: {error}", file=sys.stderr)
        return 2
    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Set the generated launchers' process code page before Windows package signing.

Windows 10 1903+ honors this per-process manifest. No system locale is changed.
JDK 17/21 jpackage otherwise converts wide arguments through the legacy ACP.
"""
import argparse
import ctypes
import os
from pathlib import Path
import stat
import struct
import xml.etree.ElementTree as ET

ASM1 = "urn:schemas-microsoft-com:asm.v1"
ASM3 = "urn:schemas-microsoft-com:asm.v3"
UTF8_NS = "http://schemas.microsoft.com/SMI/2019/WindowsSettings"


def utf8_manifest(content: bytes) -> bytes:
    if b"<!DOCTYPE" in content.upper() or b"<!ENTITY" in content.upper():
        raise ValueError("Unexpected manifest declaration")
    root = ET.fromstring(content)
    if root.tag != f"{{{ASM1}}}assembly":
        raise ValueError("Unexpected launcher manifest root")
    privilege = root.findall(f".//{{{ASM3}}}requestedExecutionLevel")
    if len(privilege) != 1 or privilege[0].get("level") != "asInvoker" or privilege[0].get("uiAccess", "false") != "false":
        raise ValueError("Launcher must retain non-elevated asInvoker execution")
    applications = root.findall(f"{{{ASM3}}}application")
    if len(applications) > 1:
        raise ValueError("Ambiguous manifest application")
    application = applications[0] if applications else ET.SubElement(root, f"{{{ASM3}}}application")
    settings = application.findall(f"{{{ASM3}}}windowsSettings")
    if len(settings) > 1:
        raise ValueError("Ambiguous Windows settings")
    setting = settings[0] if settings else ET.SubElement(application, f"{{{ASM3}}}windowsSettings")
    existing = setting.findall(f"{{{UTF8_NS}}}activeCodePage")
    if len(existing) > 1:
        raise ValueError("Ambiguous code page")
    page = existing[0] if existing else ET.SubElement(setting, f"{{{UTF8_NS}}}activeCodePage")
    page.text = "UTF-8"
    ET.register_namespace("", ASM1)
    ET.register_namespace("asmv3", ASM3)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def require_unsigned_pe(pe: bytes) -> None:
    if len(pe) < 26 or pe[:4] != b"PE\0\0":
        raise ValueError("Invalid PE header")
    magic = struct.unpack_from("<H", pe, 24)[0]
    certificate = {0x10B: 24 + 96 + 32, 0x20B: 24 + 112 + 32}.get(magic)
    if certificate is None or len(pe) < certificate + 8 or any(struct.unpack_from("<II", pe, certificate)):
        raise ValueError("Unsupported, truncated or already signed launcher")


def verify_manifest(content: bytes) -> None:
    utf8_manifest(content)  # Also validate structure and non-elevated execution.
    root = ET.fromstring(content)
    pages = root.findall(f"{{{ASM3}}}application/{{{ASM3}}}windowsSettings/{{{UTF8_NS}}}activeCodePage")
    if len(pages) != 1 or pages[0].text != "UTF-8":
        raise ValueError("Launcher is missing its per-process UTF-8 code page")


def patch_launcher(path: Path, verify_only: bool = False) -> None:
    if os.name != "nt":
        raise RuntimeError("Launcher resource updates require Windows")
    if path.is_symlink() or not path.is_file():
        raise ValueError("Expected generated launcher file")
    # Do not invalidate an already signed launcher. Packaging signs after this step.
    with path.open("rb") as stream:
        header = stream.read(64)
        if header[:2] != b"MZ" or len(header) != 64:
            raise ValueError("Invalid PE launcher")
        stream.seek(struct.unpack_from("<I", header, 60)[0])
        pe = stream.read(176)
    if not verify_only:
        require_unsigned_pe(pe)

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.c_void_p
    word = ctypes.c_ushort
    dword = ctypes.c_uint32
    callback_type = ctypes.WINFUNCTYPE(ctypes.c_int, pointer, pointer, pointer, word, ctypes.c_ssize_t)
    signatures = {
        "LoadLibraryExW": ([ctypes.c_wchar_p, pointer, dword], pointer),
        "FreeLibrary": ([pointer], ctypes.c_int),
        "EnumResourceLanguagesW": ([pointer, pointer, pointer, callback_type, ctypes.c_ssize_t], ctypes.c_int),
        "FindResourceExW": ([pointer, pointer, pointer, word], pointer),
        "SizeofResource": ([pointer, pointer], dword),
        "LoadResource": ([pointer, pointer], pointer),
        "LockResource": ([pointer], pointer),
        "BeginUpdateResourceW": ([ctypes.c_wchar_p, ctypes.c_int], pointer),
        "UpdateResourceW": ([pointer, pointer, pointer, word, pointer, dword], ctypes.c_int),
        "EndUpdateResourceW": ([pointer, ctypes.c_int], ctypes.c_int),
    }
    for name, (arguments, result) in signatures.items():
        function = getattr(kernel, name)
        function.argtypes, function.restype = arguments, result

    def checked(value):
        if not value:
            raise ctypes.WinError(ctypes.get_last_error())
        return value

    module = checked(kernel.LoadLibraryExW(str(path), None, 2))
    manifests = {}
    try:
        languages = []
        callback = callback_type(lambda _module, _type, _name, language, _param: languages.append(language) or 1)
        checked(kernel.EnumResourceLanguagesW(module, 24, 1, callback, 0))
        if not languages:
            raise ValueError("Launcher has no application manifest")
        for language in languages:
            resource = checked(kernel.FindResourceExW(module, 24, 1, language))
            size = checked(kernel.SizeofResource(module, resource))
            if size > 1024 * 1024:
                raise ValueError("Unexpected manifest size")
            address = checked(kernel.LockResource(checked(kernel.LoadResource(module, resource))))
            content = ctypes.string_at(address, size)
            if verify_only:
                verify_manifest(content)
            else:
                manifests[language] = utf8_manifest(content)
    finally:
        checked(kernel.FreeLibrary(module))

    if verify_only:
        return

    original_mode = path.stat().st_mode
    path.chmod(original_mode | stat.S_IWRITE)
    update = None
    try:
        update = checked(kernel.BeginUpdateResourceW(str(path), False))
        for language, content in manifests.items():
            buffer = ctypes.create_string_buffer(content)
            checked(kernel.UpdateResourceW(update, 24, 1, language, buffer, len(content)))
        completed, update = update, None
        checked(kernel.EndUpdateResourceW(completed, False))
    finally:
        if update:
            kernel.EndUpdateResourceW(update, True)
        path.chmod(original_mode)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-image", type=Path, required=True)
    parser.add_argument("--verify-only", action="store_true", help="Read-only validation, also safe after signing or MSI extraction")
    args = parser.parse_args()
    for name in ("vpn-control.exe", "vpn-control-cli.exe"):
        patch_launcher(args.app_image.resolve() / name, args.verify_only)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Fail closed before Android AVD tools can select a different SDK root."""
import argparse
import json
import os
import sys
import xml.etree.ElementTree as element_tree
from pathlib import Path


class PreflightError(ValueError):
    """A local SDK/AVD layout is not safe to launch."""


def _resolved_directory(value: str, label: str) -> Path:
    candidate = Path(value).expanduser()
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise PreflightError(f"{label} does not exist: {candidate}") from error
    if not resolved.is_dir():
        raise PreflightError(f"{label} is not a directory: {resolved}")
    return resolved


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _tool_under_sdk(sdk_root: Path, relative_path: str, label: str) -> Path:
    configured = sdk_root / relative_path
    try:
        resolved = configured.resolve(strict=True)
    except OSError as error:
        raise PreflightError(f"{label} is missing under SDK root: {configured}") from error
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise PreflightError(f"{label} is not executable: {resolved}")
    if not _under(resolved, sdk_root):
        raise PreflightError(
            f"{label} resolves outside intended SDK root: {configured} -> {resolved} (SDK {sdk_root})"
        )
    return resolved


def _executable_tool(sdk_root: Path, relative_path: str, label: str) -> Path:
    configured = sdk_root / relative_path
    try:
        resolved = configured.resolve(strict=True)
    except OSError as error:
        raise PreflightError(f"{label} is missing under SDK root: {configured}") from error
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise PreflightError(f"{label} is not executable: {resolved}")
    return resolved


def _system_image_metadata(sdk_root: Path, system_image: str) -> Path:
    parts = system_image.split(";")
    if (len(parts) != 4 or parts[0] != "system-images" or
            any(not part or part in {".", ".."} or "/" in part or "\\" in part for part in parts)):
        raise PreflightError("System image must be an exact SDK package such as system-images;android-29;google_apis;x86_64")
    metadata = sdk_root.joinpath(*parts) / "package.xml"
    if not metadata.is_file():
        raise PreflightError(f"System image metadata is missing: {metadata}")
    try:
        document = element_tree.parse(metadata).getroot()
    except element_tree.ParseError as error:
        raise PreflightError(f"System image metadata is invalid: {metadata}") from error
    packages = [element for element in document.iter()
                if element.tag.rsplit("}", 1)[-1] == "localPackage"]
    if len(packages) != 1:
        raise PreflightError(f"System image metadata has missing or ambiguous localPackage identity: {metadata}")
    package = packages[0].attrib.get("path")
    if not package:
        raise PreflightError(f"System image metadata has missing or ambiguous localPackage identity: {metadata}")
    if package != system_image:
        raise PreflightError(f"System image metadata names {package!r}, expected {system_image!r}: {metadata}")
    return metadata


def safe_emulator_environment(sdk_root: str, avd_home: str, system_image: str | None = None) -> dict:
    """Validate an existing emulator's inputs without invoking AVD creation tools."""
    actual_sdk = _resolved_directory(sdk_root, "SDK root")
    actual_avd_home = _resolved_directory(avd_home, "AVD home")
    # The emulator executable may deliberately be a shared-SDK symlink.  It does
    # not derive the package manager root, unlike avdmanager, so retain its exact
    # resolved executable while pinning all SDK and AVD environment variables.
    emulator = _executable_tool(actual_sdk, "emulator/emulator", "emulator")
    metadata = _system_image_metadata(actual_sdk, system_image) if system_image else None
    environment = {
        "ANDROID_HOME": str(actual_sdk),
        "ANDROID_SDK_ROOT": str(actual_sdk),
        "ANDROID_AVD_HOME": str(actual_avd_home),
    }
    result = {
        "sdkRoot": str(actual_sdk),
        "avdHome": str(actual_avd_home),
        "emulator": str(emulator),
        "environment": environment,
    }
    if metadata is not None:
        result["systemImage"] = system_image
        result["systemImageMetadata"] = str(metadata)
    return result


def safe_avd_environment(sdk_root: str, avd_home: str, system_image: str | None = None) -> dict:
    """Also admit avdmanager before creating or managing AVDs."""
    result = safe_emulator_environment(sdk_root, avd_home, system_image)
    result["avdmanager"] = str(_tool_under_sdk(
        Path(result["sdkRoot"]), "cmdline-tools/latest/bin/avdmanager", "avdmanager"))
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk-root", required=True, help="intended Android SDK root")
    parser.add_argument("--avd-home", required=True, help="private AVD directory")
    parser.add_argument("--system-image", help="exact package, for example system-images;android-29;google_apis;x86_64")
    parser.add_argument("--launch-only", action="store_true", help="validate an existing emulator without admitting avdmanager")
    arguments = parser.parse_args(argv)
    try:
        preflight = safe_emulator_environment if arguments.launch_only else safe_avd_environment
        print(json.dumps(preflight(arguments.sdk_root, arguments.avd_home, arguments.system_image), sort_keys=True))
    except PreflightError as error:
        print(f"Android AVD SDK preflight failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

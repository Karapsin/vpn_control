#!/usr/bin/env python3
"""Build and verify a DEB from the prepared image with one resource directory.

Compose 1.7.3 appends its own --resource-dir after freeArgs. An explicit invocation
keeps the maintainer hook effective without modifying the image or package bytes.
This only builds an archive; it never installs one.
"""
import argparse
import io
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile


METADATA_OPTIONS = {
    "vendor": "--vendor", "description": "--description", "copyright": "--copyright",
    "license_file": "--license-file", "icon": "--icon", "maintainer": "--linux-deb-maintainer",
    "category": "--linux-app-category", "menu_group": "--linux-menu-group",
    "install_dir": "--install-dir", "release": "--linux-app-release",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def package_arguments(java_home, image, destination, resources, name, package_name, version, metadata, shortcut=False):
    command = [str(java_home / "bin/jpackage"), "--type", "deb", "--app-image", str(image),
               "--dest", str(destination), "--name", name, "--linux-package-name", package_name,
               "--app-version", version, "--resource-dir", str(resources)]
    for key, option in METADATA_OPTIONS.items():
        value = metadata.get(key)
        if value is not None and str(value):
            command.extend([option, str(value)])
    if shortcut:
        command.append("--linux-shortcut")
    return command


def verify_postinst(control_archive, template, package_name):
    require(len(control_archive) <= 4 * 1024 * 1024, "Unexpectedly large generated DEB control archive")
    with tarfile.open(fileobj=io.BytesIO(control_archive), mode="r:*") as archive:
        candidates = [entry for entry in archive.getmembers() if entry.name in ("postinst", "./postinst")]
        require(len(candidates) == 1 and candidates[0].isfile() and candidates[0].mode & 0o111,
                "DEB must contain exactly one executable regular postinst")
        require(candidates[0].size <= 1024 * 1024, "Unexpectedly large generated maintainer hook")
        with archive.extractfile(candidates[0]) as source:
            actual = source.read().decode("utf-8")
    require(template.count("DESKTOP_COMMANDS_INSTALL") == 1, "Template must retain desktop registration")
    prefix, suffix = template.replace("APPLICATION_PACKAGE", package_name).split("DESKTOP_COMMANDS_INSTALL")
    require(actual.startswith(prefix) and actual.endswith(suffix),
            "Generated DEB omitted or replaced the custom postinst resource")
    registration = actual[len(prefix):len(actual) - len(suffix)]
    require("xdg-desktop-menu install " in registration and "DESKTOP_COMMANDS_INSTALL" not in actual,
            "Generated DEB omitted desktop registration")
    return actual


def verify_deb(package, resources, package_name, version, release="1", run_command=subprocess.run):
    fields = run_command(["dpkg-deb", "-f", str(package), "Package", "Version", "Architecture"],
                         check=True, capture_output=True).stdout.decode("utf-8")
    values = dict(line.split(": ", 1) for line in fields.splitlines())
    expected_arch = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine())
    require(values == {"Package": package_name, "Version": version + "-" + release, "Architecture": expected_arch},
            "Generated DEB package identity disagrees with the requested native package")
    control = run_command(["dpkg-deb", "--ctrl-tarfile", str(package)], check=True, capture_output=True).stdout
    verify_postinst(control, (resources / "postinst").read_text(), package_name)


def package(java_home, image, destination, resources, name, package_name, version, metadata,
            shortcut=False, run_command=subprocess.run):
    require(platform.system() == "Linux", "DEB packages require a native Linux build")
    image, resources = image.resolve(strict=True), resources.resolve(strict=True)
    header = (image / "bin" / name).read_bytes()[:64]
    expected_machine = {"x86_64": 62, "aarch64": 183, "arm64": 183}.get(platform.machine())
    require(header[:6] == b"\x7fELF\x02\x01" and expected_machine is not None
            and int.from_bytes(header[18:20], "little") == expected_machine,
            "Prepared public launcher architecture must match the native build host")
    require((resources / "postinst").is_file(), "Missing Linux maintainer resource")
    require(not destination.is_symlink(), "Package destination must not be a symlink")
    destination.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".vpn-deb-", dir=destination.parent))
    command = package_arguments(java_home, image, staging, resources, name, package_name, version, metadata, shortcut)
    try:
        run_command(command, check=True)
        artifacts = list(staging.glob("*.deb"))
        require(len(artifacts) == 1 and artifacts[0].is_file() and not artifacts[0].is_symlink(),
                "Expected exactly one generated DEB")
        artifact = artifacts[0]
        verify_deb(artifact, resources, package_name, version, str(metadata.get("release") or "1"), run_command)
        target = destination / artifact.name
        os.replace(artifact, target)
        shutil.rmtree(staging)
        return target
    except Exception as failure:
        raise RuntimeError("DEB build or verification failed; retained generated evidence at " + str(staging)) from failure


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--app-image", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--resources", type=Path, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--package-name", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--shortcut", action="store_true")
    for key in METADATA_OPTIONS:
        parser.add_argument("--" + key.replace("_", "-"))
    args = parser.parse_args()
    print(package(args.java_home, args.app_image, args.destination, args.resources, args.name, args.package_name,
                  args.version, {key: getattr(args, key) for key in METADATA_OPTIONS}, args.shortcut))


if __name__ == "__main__":
    main()

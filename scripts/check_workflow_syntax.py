#!/usr/bin/env python3
"""Run a pinned actionlint binary without relying on host-installed tools."""

from __future__ import annotations

import argparse
import errno
import hashlib
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile


VERSION = "1.7.12"
RELEASE = f"https://github.com/rhysd/actionlint/releases/download/v{VERSION}"
DOWNLOAD_ATTEMPTS = 3
DOWNLOAD_BACKOFF_SECONDS = 1
ASSETS = {
    ("Linux", "x86_64"): ("actionlint_1.7.12_linux_amd64.tar.gz", "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"),
    ("Linux", "aarch64"): ("actionlint_1.7.12_linux_arm64.tar.gz", "325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6"),
    ("Darwin", "x86_64"): ("actionlint_1.7.12_darwin_amd64.tar.gz", "5b44c3bc2255115c9b69e30efc0fecdf498fdb63c5d58e17084fd5f16324c644"),
    ("Darwin", "arm64"): ("actionlint_1.7.12_darwin_arm64.tar.gz", "aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f"),
    ("Windows", "amd64"): ("actionlint_1.7.12_windows_amd64.zip", "6e7241b51e6817ea6a047693d8e6fed13b31819c9a0dd6c5a726e1592d22f6e9"),
    ("Windows", "arm64"): ("actionlint_1.7.12_windows_arm64.zip", "cadcf7ea4efe3a68728893813643cebe1185e5b1d4be5b96245f65c9a4d5ea41"),
}


def normalized_machine(system: str, machine: str) -> str:
    machine = machine.lower()
    if machine in {"amd64", "x86_64"}:
        return "amd64" if system == "Windows" else "x86_64"
    if machine in {"aarch64", "arm64"}:
        return "arm64" if system in {"Darwin", "Windows"} else "aarch64"
    return machine


def asset_for(system: str | None = None, machine: str | None = None) -> tuple[str, str]:
    system = system or platform.system()
    key = (system, normalized_machine(system, machine or platform.machine()))
    try:
        return ASSETS[key]
    except KeyError as error:
        supported = ", ".join(f"{name}/{arch}" for name, arch in sorted(ASSETS))
        raise RuntimeError(f"actionlint {VERSION} has no pinned asset for {key[0]}/{key[1]}; supported: {supported}") from error


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def cache_root() -> Path:
    return Path(__file__).resolve().parent.parent / ".runtime" / "tool-cache" / f"actionlint-{VERSION}"


def retryable_transport_error(error: OSError) -> bool:
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(reason, (ConnectionResetError, TimeoutError)):
        return True
    return isinstance(reason, OSError) and reason.errno in {
        errno.ECONNABORTED,
        errno.ECONNRESET,
        errno.EPIPE,
        errno.ETIMEDOUT,
    }


def download(url: str, destination: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": f"vpn-control-actionlint/{VERSION}"})
    for attempt in range(DOWNLOAD_ATTEMPTS):
        staged_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent, delete=False) as staged:
                staged_path = Path(staged.name)
                with urllib.request.urlopen(request, timeout=30) as response:
                    shutil.copyfileobj(response, staged)
            os.replace(staged_path, destination)
            return
        except OSError as error:
            if staged_path is not None:
                staged_path.unlink(missing_ok=True)
            if not retryable_transport_error(error) or attempt == DOWNLOAD_ATTEMPTS - 1:
                suffix = f" after {DOWNLOAD_ATTEMPTS} attempts" if retryable_transport_error(error) else ""
                raise RuntimeError(f"could not download pinned actionlint from {url}{suffix}: {error}") from error
            time.sleep(DOWNLOAD_BACKOFF_SECONDS * (attempt + 1))


def publish_archive(root: Path, archive: Path, staged: Path) -> None:
    staged_archive: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix=f".{archive.name}.", suffix=".tmp", dir=root, delete=False) as output:
            staged_archive = Path(output.name)
            with staged.open("rb") as source:
                shutil.copyfileobj(source, output)
        os.replace(staged_archive, archive)
    finally:
        if staged_archive is not None:
            staged_archive.unlink(missing_ok=True)


def executable_bytes(archive: Path, is_zip: bool, executable_name: str) -> bytes:
    if is_zip:
        with zipfile.ZipFile(archive) as contents:
            return contents.read(executable_name)
    with tarfile.open(archive, "r:gz") as contents:
        member = contents.getmember(executable_name)
        stream = contents.extractfile(member)
        if stream is None:
            raise RuntimeError(f"pinned actionlint archive {archive.name} did not contain {executable_name}")
        return stream.read()


def install_executable(root: Path, executable: Path, contents: bytes) -> None:
    with tempfile.NamedTemporaryFile(prefix=f".{executable.name}.", suffix=".tmp", dir=root, delete=False) as staged:
        staged.write(contents)
        staged_path = Path(staged.name)
    if os.name != "nt":
        staged_path.chmod(staged_path.stat().st_mode | 0o111)
    os.replace(staged_path, executable)


def actionlint_path() -> Path:
    asset, expected_hash = asset_for()
    root = cache_root()
    executable = root / ("actionlint.exe" if platform.system() == "Windows" else "actionlint")
    archive = root / asset
    if archive.is_file() and sha256(archive) == expected_hash:
        try:
            expected_executable = executable_bytes(archive, asset.endswith(".zip"), executable.name)
        except (KeyError, tarfile.TarError, zipfile.BadZipFile) as error:
            raise RuntimeError(f"pinned actionlint archive {asset} could not provide {executable.name}: {error}") from error
        if executable.is_file() and sha256(executable) == hashlib.sha256(expected_executable).hexdigest():
            return executable
        install_executable(root, executable, expected_executable)
        return executable

    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="actionlint-", dir=root) as temporary:
        staged = Path(temporary) / asset
        download(f"{RELEASE}/{asset}", staged)
        actual_hash = sha256(staged)
        if actual_hash != expected_hash:
            raise RuntimeError(f"actionlint checksum mismatch for {asset}: expected {expected_hash}, got {actual_hash}")
        try:
            expected_executable = executable_bytes(staged, asset.endswith(".zip"), executable.name)
        except (KeyError, tarfile.TarError, zipfile.BadZipFile) as error:
            raise RuntimeError(f"pinned actionlint archive {asset} could not provide {executable.name}: {error}") from error
        publish_archive(root, archive, staged)
        install_executable(root, executable, expected_executable)
    return executable


def run_actionlint(paths: list[Path]) -> subprocess.CompletedProcess[str]:
    executable = actionlint_path()
    command = [str(executable), "-shellcheck=", "-pyflakes=", *(str(path) for path in paths)]
    try:
        return subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False, timeout=60)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"actionlint exceeded the 60-second limit while checking workflows; command: {' '.join(command)}") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path, help="Workflow files; defaults to every .github/workflows YAML file")
    args = parser.parse_args()
    workflows = Path(__file__).resolve().parent.parent / ".github" / "workflows"
    paths = args.paths or sorted((*workflows.glob("*.yml"), *workflows.glob("*.yaml")))
    try:
        result = run_actionlint(paths)
    except RuntimeError as error:
        print(f"workflow syntax check failed: {error}", file=sys.stderr)
        return 2
    if result.stdout:
        print(result.stdout, end="")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())

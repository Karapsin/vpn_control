"""Fixture-only native environment checks; never used by product packaging."""
import re
import os
import subprocess
import tarfile
from pathlib import Path


def require_jdk17(java=None, runner=subprocess.run, environment=None):
    """Validate the JVM Gradle will use, preferring JAVA_HOME over PATH."""
    environment = os.environ if environment is None else environment
    if java is None:
        executable = "java.exe" if os.name == "nt" else "java"
        java = str(Path(environment["JAVA_HOME"]) / "bin" / executable) if environment.get("JAVA_HOME") else executable
    result = runner([java, "-version"], text=True, capture_output=True, check=False)
    text = result.stdout + result.stderr
    match = re.search(r'(?:openjdk|java) version "(\d+)(?:[._][^"]*)?"', text)
    if result.returncode or match is None or match.group(1) != "17":
        raise ValueError("Native fixture build requires JDK 17: " + (text.splitlines() or ["no version output"])[0])
    return text.splitlines()[0]


def extract_readonly_archive(archive, destination):
    """Extract fixture inputs, deferring directory modes until children exist."""
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError("Use a new fixture extraction destination")
    destination.mkdir(mode=0o700)
    def fixture_filter(member, path):
        filtered = tarfile.data_filter(member, path)
        if filtered is not None and (member.isdir() or member.isfile()):
            # The data filter deliberately makes files owner-writable and
            # ignores directory modes. Frozen fixture inputs must stay frozen.
            filtered.mode = member.mode & 0o777
        return filtered
    with tarfile.open(archive, "r:gz") as bundle:
        # extractall defers directory metadata; extracting one member at a time
        # applies 0500 before its children and fails for an ordinary user.
        bundle.extractall(destination, filter=fixture_filter)


def validate_qemu_argv(argv):
    try:
        serial = argv[argv.index("-serial") + 1]
    except (ValueError, IndexError) as error:
        raise ValueError("QEMU launch is missing serial backend") from error
    if not serial.startswith("file:"):
        raise ValueError("QEMU serial backend must use file:")

"""Trust setup primitives for disposable Android HTTPS fixtures."""

import re
import subprocess
from pathlib import Path


def android_ca_store_filename(certificate: Path) -> str:
    """Return the legacy Android CA-store filename for a PEM certificate."""
    result = subprocess.run(
        ["openssl", "x509", "-in", str(certificate), "-noout", "-subject_hash_old"],
        check=True,
        text=True,
        capture_output=True,
    )
    subject_hash = result.stdout.strip()
    if not re.fullmatch(r"[0-9a-fA-F]{8}", subject_hash):
        raise ValueError("OpenSSL returned an invalid legacy subject hash")
    return f"{subject_hash.lower()}.0"


def zygote_bind_mount_argv(zygote_pid: str, source: str, target: str) -> list[str]:
    """Build an argv-only zygote mount-namespace bind command."""
    if not isinstance(zygote_pid, str) or not zygote_pid.isdecimal() or int(zygote_pid) < 1:
        raise ValueError("Fixture zygote PID must be positive decimal text")
    if not isinstance(source, str) or not source.startswith("/"):
        raise ValueError("Fixture bind source must be absolute")
    if not isinstance(target, str) or not target.startswith("/"):
        raise ValueError("Fixture bind target must be absolute")
    return ["nsenter", "-t", zygote_pid, "-m", "--", "mount", "--bind", source, target]

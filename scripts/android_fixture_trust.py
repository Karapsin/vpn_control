"""Trust setup primitives for disposable Android HTTPS fixtures."""

import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ANDROID_CACERTS_DIRECTORY_MODE = 0o755
ANDROID_CACERTS_FILE_MODE = 0o644
PRIVATE_FIXTURE_DIRECTORY_MODE = 0o700


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


def certificate_validity_epochs(certificate: Path) -> tuple[int, int]:
    """Read a certificate's UTC validity interval without exposing its contents."""
    result = subprocess.run(
        ["openssl", "x509", "-in", str(certificate), "-noout", "-startdate", "-enddate"],
        check=True,
        text=True,
        capture_output=True,
    )
    values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    try:
        not_before_text = values["notBefore"]
        not_after_text = values["notAfter"]
        if not (not_before_text.endswith(" GMT") and not_after_text.endswith(" GMT")):
            raise ValueError("OpenSSL validity must use GMT")
        not_before = datetime.strptime(not_before_text, "%b %d %H:%M:%S %Y GMT")
        not_after = datetime.strptime(not_after_text, "%b %d %H:%M:%S %Y GMT")
    except (KeyError, ValueError) as error:
        raise ValueError("OpenSSL returned invalid certificate validity") from error
    return int(not_before.replace(tzinfo=timezone.utc).timestamp()), int(
        not_after.replace(tzinfo=timezone.utc).timestamp()
    )


def require_device_time_within_certificates(
    device_epoch: int, ca_certificate: Path, leaf_certificate: Path
) -> None:
    """Reject a fixture when its recorded device time is outside either certificate window."""
    if isinstance(device_epoch, bool) or not isinstance(device_epoch, int):
        raise ValueError("Fixture device epoch must be an integer")
    for certificate in (ca_certificate, leaf_certificate):
        not_before, not_after = certificate_validity_epochs(certificate)
        if not not_before <= device_epoch < not_after:
            raise RuntimeError("Fixture certificate is not valid at the recorded device time")


def require_android_certificate_store_layout(
    private_parent_mode: int,
    mounted_store_mode: int,
    certificate_mode: int,
    observed_label: str,
    expected_baseline_label: str,
) -> None:
    """Require a private host fixture and an app-readable Android mounted store."""
    if private_parent_mode != PRIVATE_FIXTURE_DIRECTORY_MODE:
        raise RuntimeError("Fixture private parent must be 0700")
    if (
        mounted_store_mode != ANDROID_CACERTS_DIRECTORY_MODE
        or certificate_mode != ANDROID_CACERTS_FILE_MODE
    ):
        raise RuntimeError("Mounted Android certificate store must be 0755 with 0644 certificates")
    if not isinstance(expected_baseline_label, str) or not expected_baseline_label:
        raise ValueError("Expected Android certificate-store label must be text")
    if observed_label != expected_baseline_label:
        raise RuntimeError("Mounted Android certificate store has an unexpected SELinux label")


def secure_private_fixture_files(paths: list[Path]) -> None:
    """Restrict supplied regular files without changing any directory's search bit."""
    validated = list(paths)
    for path in validated:
        if not isinstance(path, Path) or path.is_symlink() or not path.is_file():
            raise ValueError("Fixture private mode accepts only regular non-symlink files")
    for path in validated:
        path.chmod(0o600)


def zygote_bind_mount_argv(zygote_pid: str, source: str, target: str) -> list[str]:
    """Build an argv-only zygote mount-namespace bind command."""
    if not isinstance(zygote_pid, str) or not zygote_pid.isdecimal() or int(zygote_pid) < 1:
        raise ValueError("Fixture zygote PID must be positive decimal text")
    if not isinstance(source, str) or not source.startswith("/"):
        raise ValueError("Fixture bind source must be absolute")
    if not isinstance(target, str) or not target.startswith("/"):
        raise ValueError("Fixture bind target must be absolute")
    return ["nsenter", "-t", zygote_pid, "-m", "--", "mount", "--bind", source, target]

"""Mint short-lived, local-only TLS material for the disposable Android fixture.

This is deliberately separate from fixture serving, artifact registration, device
trust and endpoint admission.  It creates no network listener and never receives
an APK path.  It validates the semantic fields of an already verified APK plan,
but does not inspect artifact bytes, signer files, or Git state itself; the caller
must perform that source and artifact provenance preflight before later lifecycle
steps consume its receipt.
"""

from __future__ import annotations

import datetime as datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import uuid
from typing import Any, Callable


_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_SHA = re.compile(r"[0-9a-f]{64}")
_ARTIFACT = re.compile(r"sha256-[0-9a-f]{64}")
_MAX_VALIDITY_SECONDS = 24 * 60 * 60
_NAMES = ("ca-key.pem", "ca.pem", "leaf-key.pem", "leaf.pem", "receipt.json")


class FixtureTlsMintError(ValueError):
    """A local mint was rejected or could not be durably published."""


def _generation(info: os.stat_result) -> list[int]:
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            stat.S_IMODE(info.st_mode), info.st_uid, info.st_nlink]


def _same_generation(first: os.stat_result, second: os.stat_result) -> bool:
    return _generation(first) == _generation(second)


def _same_directory_identity(first: os.stat_result, second: os.stat_result) -> bool:
    """Directory timestamps and link count legitimately change when a child is created."""
    return (first.st_dev, first.st_ino, stat.S_IMODE(first.st_mode), first.st_uid) == (
        second.st_dev, second.st_ino, stat.S_IMODE(second.st_mode), second.st_uid)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _require_private_directory(path: Path) -> tuple[int, os.stat_result]:
    if not path.is_absolute() or path.is_symlink():
        raise FixtureTlsMintError("TLS mint parent is not an absolute non-symlink directory")
    try:
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise FixtureTlsMintError("TLS mint parent cannot be opened") from error
    opened = os.fstat(descriptor)
    if (not stat.S_ISDIR(before.st_mode) or not stat.S_ISDIR(opened.st_mode) or
            before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != 0o700 or
            not _same_directory_identity(before, opened)):
        os.close(descriptor)
        raise FixtureTlsMintError("TLS mint parent is not a private stable directory")
    return descriptor, opened


def _require_parent_name(parent: Path, parent_info: os.stat_result, descriptor: int) -> None:
    try:
        named = parent.lstat()
    except OSError as error:
        raise FixtureTlsMintError("TLS mint parent name disappeared") from error
    opened = os.fstat(descriptor)
    if not _same_directory_identity(parent_info, named) or not _same_directory_identity(parent_info, opened):
        raise FixtureTlsMintError("TLS mint parent was replaced")


def _require_child_name(parent_fd: int, name: str, child_info: os.stat_result, child_fd: int) -> None:
    try:
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as error:
        raise FixtureTlsMintError("TLS mint output directory name disappeared") from error
    opened = os.fstat(child_fd)
    if (not _same_directory_identity(child_info, named) or
            not _same_directory_identity(child_info, opened)):
        raise FixtureTlsMintError("TLS mint output directory was replaced")


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise OSError("short private fixture write")
        offset += written


def _write_once(directory_fd: int, name: str, data: bytes) -> dict[str, Any]:
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                         0o600, dir_fd=directory_fd)
    try:
        _write_all(descriptor, data)
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or stat.S_IMODE(opened.st_mode) != 0o600 or
                opened.st_uid != os.getuid() or opened.st_nlink != 1 or opened.st_size != len(data)):
            raise FixtureTlsMintError("TLS mint file safety check failed")
        reread = b""
        reader = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
        try:
            read_info = os.fstat(reader)
            if not _same_generation(opened, read_info):
                raise FixtureTlsMintError("TLS mint file changed before readback")
            while len(reread) <= len(data):
                part = os.read(reader, min(65536, len(data) + 1 - len(reread)))
                if not part:
                    break
                reread += part
            after = os.fstat(reader)
            if not _same_generation(read_info, after) or reread != data:
                raise FixtureTlsMintError("TLS mint file readback differs")
        finally:
            os.close(reader)
        return {"sha256": _sha(data), "bytes": len(data), "generation": _generation(opened)}
    finally:
        os.close(descriptor)


def _verify_named_file(directory_fd: int, name: str, expected: dict[str, Any]) -> None:
    """Reopen the named entry after all writes; a held directory FD alone is insufficient."""
    try:
        descriptor = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
    except OSError as error:
        raise FixtureTlsMintError("TLS mint named file is unavailable") from error
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or stat.S_IMODE(opened.st_mode) != 0o600 or
                opened.st_uid != os.getuid() or opened.st_nlink != 1 or
                _generation(opened) != expected["generation"]):
            raise FixtureTlsMintError("TLS mint named file was replaced")
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 65536)
            if not block:
                break
            chunks.append(block)
        after = os.fstat(descriptor)
        content = b"".join(chunks)
        if (_generation(after) != expected["generation"] or len(content) != expected["bytes"] or
                _sha(content) != expected["sha256"]):
            raise FixtureTlsMintError("TLS mint named file readback differs")
        try:
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as error:
            raise FixtureTlsMintError("TLS mint named file disappeared after readback") from error
        if _generation(named) != expected["generation"]:
            raise FixtureTlsMintError("TLS mint named file entry was replaced")
    finally:
        os.close(descriptor)


def _plan_facts(plan: dict[str, Any]) -> dict[str, Any]:
    required = {"sourceSha", "baseArtifactId", "baseVersion", "baseCode", "baseSignerSha256",
                "targetArtifactId", "targetVersion", "targetCode", "targetSha256", "targetSize"}
    required_verified = required | {"endpoint", "deviceMutationAllowed"}
    if set(plan) != required_verified:
        raise FixtureTlsMintError("TLS mint requires the exact verified APK plan shape")
    if (not isinstance(plan["sourceSha"], str) or not re.fullmatch(r"[0-9a-f]{40}", plan["sourceSha"]) or
            any(not isinstance(plan[key], str) or not _ARTIFACT.fullmatch(plan[key])
                for key in ("baseArtifactId", "targetArtifactId")) or
            any(not isinstance(plan[key], str) or not _SHA.fullmatch(plan[key])
                for key in ("baseSignerSha256", "targetSha256")) or
            any(not isinstance(plan[key], str) or _version(plan[key]) is None
                for key in ("baseVersion", "targetVersion")) or
            any(type(plan[key]) is not int or plan[key] <= 0 for key in ("baseCode", "targetCode", "targetSize")) or
            plan["targetArtifactId"] != "sha256-" + plan["targetSha256"] or
            plan["baseCode"] != _version_code(_version(plan["baseVersion"])) or
            plan["targetCode"] != _version_code(_version(plan["targetVersion"])) or
            _version(plan["targetVersion"]) <= _version(plan["baseVersion"]) or
            plan["deviceMutationAllowed"] is not False):
        raise FixtureTlsMintError("TLS mint APK plan facts are invalid")
    try:
        from agent_tools import android_native_fixture
    except ImportError:
        import android_native_fixture
    if plan["endpoint"] != android_native_fixture.endpoint_contract():
        raise FixtureTlsMintError("TLS mint endpoint facts are not the verified fixture contract")
    facts = {key: plan[key] for key in sorted(required)}
    canonical = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {**facts, "planSha256": _sha(canonical)}


def _version(value: str) -> tuple[int, int, int] | None:
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]*\.[0-9]+\.[0-9]+", value):
        return None
    major, minor, patch = (int(part) for part in value.split("."))
    if not 1 <= major <= 19 or not 0 <= minor <= 19 or not 0 <= patch <= 19:
        return None
    return major, minor, patch


def _version_code(value: tuple[int, int, int] | None) -> int:
    if value is None:
        return -1
    major, minor, patch = value
    return ((major * 20 + minor) * 20 + patch) * 20


def mint(parent: Path | str, campaign_id: str, plan: dict[str, Any], *,
         validity_seconds: int = 6 * 60 * 60,
         now: datetime.datetime | None = None,
         uuid_factory: Callable[[], uuid.UUID] = uuid.uuid4,
         after_directory_create: Callable[[Path], None] | None = None) -> dict[str, Any]:
    """Create an immutable, short-lived local CA/leaf set and a nonsecret receipt.

    The only public values returned are fingerprints, lengths, generations, SANs and
    source-bound APK facts.  The returned directory is private and contains keys.
    """
    if not isinstance(campaign_id, str) or not _UUID.fullmatch(campaign_id):
        raise FixtureTlsMintError("TLS mint requires a canonical campaign UUID")
    if type(validity_seconds) is not int or not 60 <= validity_seconds <= _MAX_VALIDITY_SECONDS:
        raise FixtureTlsMintError("TLS mint validity must be a short positive test interval")
    facts = _plan_facts(plan)
    clock = now or datetime.datetime.now(datetime.timezone.utc)
    if clock.tzinfo is None:
        raise FixtureTlsMintError("TLS mint clock must be timezone-aware")
    clock = clock.astimezone(datetime.timezone.utc)
    parent_path = Path(parent)
    parent_fd, parent_info = _require_private_directory(parent_path)
    name = "android-fixture-tls-" + str(uuid_factory())
    if not _UUID.fullmatch(name.removeprefix("android-fixture-tls-")):
        os.close(parent_fd)
        raise FixtureTlsMintError("TLS mint UUID factory returned an invalid value")
    child_fd = None
    created = False
    try:
        _require_parent_name(parent_path, parent_info, parent_fd)
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        created = True
        child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        child_info = os.fstat(child_fd)
        if (not stat.S_ISDIR(child_info.st_mode) or stat.S_IMODE(child_info.st_mode) != 0o700 or
                child_info.st_uid != os.getuid()):
            raise FixtureTlsMintError("TLS mint output directory is unsafe")
        # Persist the create-only directory entry before generating private keys.
        os.fsync(parent_fd)
        if after_directory_create is not None:
            after_directory_create(parent_path / name)
        _require_parent_name(parent_path, parent_info, parent_fd)
        _require_child_name(parent_fd, name, child_info, child_fd)
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        not_after = clock + datetime.timedelta(seconds=validity_seconds)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "VPN Control Disposable Fixture CA")])
        leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        ca_cert = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
                   .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(clock).not_valid_after(not_after)
                   .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                   .sign(ca_key, hashes.SHA256()))
        leaf_cert = (x509.CertificateBuilder().subject_name(leaf_name).issuer_name(ca_name)
                     .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
                     .not_valid_before(clock).not_valid_after(not_after)
                     .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                     .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.DNSName("github.com"),
                         x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                     .sign(ca_key, hashes.SHA256()))
        private = serialization.PrivateFormat.PKCS8
        encryption = serialization.NoEncryption()
        files = {
            "ca-key.pem": ca_key.private_bytes(serialization.Encoding.PEM, private, encryption),
            "ca.pem": ca_cert.public_bytes(serialization.Encoding.PEM),
            "leaf-key.pem": leaf_key.private_bytes(serialization.Encoding.PEM, private, encryption),
            "leaf.pem": leaf_cert.public_bytes(serialization.Encoding.PEM),
        }
        details = {key: _write_once(child_fd, key, value) for key, value in files.items()}
        receipt = {"schema": 1, "kind": "android-disposable-fixture-tls", "campaignId": campaign_id,
                   "testOnly": True, "validitySeconds": validity_seconds,
                   "notBefore": clock.isoformat().replace("+00:00", "Z"),
                   "notAfter": not_after.isoformat().replace("+00:00", "Z"),
                   "leafSubjectAltNames": ["DNS:localhost", "DNS:github.com", "IP:127.0.0.1"],
                   "sourceFacts": facts, "files": details}
        receipt_bytes = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        receipt_detail = _write_once(child_fd, "receipt.json", receipt_bytes)
        os.fsync(child_fd)
        os.fsync(parent_fd)
        _require_parent_name(parent_path, parent_info, parent_fd)
        _require_child_name(parent_fd, name, child_info, child_fd)
        for filename, detail in {**details, "receipt.json": receipt_detail}.items():
            _verify_named_file(child_fd, filename, detail)
        _require_parent_name(parent_path, parent_info, parent_fd)
        _require_child_name(parent_fd, name, child_info, child_fd)
        return {"directory": str(parent_path / name), "receipt": {**receipt, "receipt": receipt_detail}}
    except Exception:
        # Preserve the private, create-only capsule as failure evidence.  Cleanup
        # cannot distinguish an injected name from an owned file after a failed
        # publication, so it must never unlink fixed names speculatively.
        raise
    finally:
        if child_fd is not None:
            os.close(child_fd)
        os.close(parent_fd)

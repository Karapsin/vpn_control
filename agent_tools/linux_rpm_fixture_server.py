"""Fixed Fedora RPM fixture endpoint admission for the public launcher.

The server lifecycle is separate. This guard never creates a certificate,
trust store, server, or owner; missing evidence blocks the public harness.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import time
from typing import Any, Mapping
from uuid import UUID


_HASH = re.compile(r"[0-9a-f]{64}\Z")


def host_endpoint_ready(_root: Path | str, _intent: Any, _source_fingerprint: str) -> bool:
    """Hold public submission until a journaled server lifecycle route exists.

    A READY JSON alone is not a safe host authorization: the later route must
    verify live guest owner, TLS probe and exact artifact binding before this
    function can admit a correlation. This checkpoint deliberately has no
    enabling branch.
    """
    return False
def _private_json(path: Path, *, readonly: bool = False,
                  include_digest: bool = False) -> dict[str, Any] | tuple[dict[str, Any], str]:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise ValueError("fixture endpoint unavailable") from error
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) not in ((0o400, 0o600) if readonly else (0o600,))
                or not 0 < info.st_size <= 1024 * 1024):
            raise ValueError("fixture endpoint evidence unsafe")
        raw = os.read(fd, info.st_size + 1)
        after = os.fstat(fd)
        current = path.lstat()
        if (len(raw) != info.st_size or
                (info.st_dev, info.st_ino, info.st_size) !=
                (after.st_dev, after.st_ino, after.st_size) or
                (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)):
            raise ValueError("fixture endpoint evidence changed")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("fixture endpoint evidence invalid")
        return (value, hashlib.sha256(raw).hexdigest()) if include_digest else value
    except (OSError, ValueError, TypeError) as error:
        raise ValueError("fixture endpoint unavailable") from error
    finally:
        os.close(fd)


def _digest(path: Path, *, maximum: int) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or not 0 < before.st_size <= maximum):
            raise ValueError("fixture endpoint file unsafe")
        digest = hashlib.sha256()
        while block := os.read(fd, 1024 * 1024):
            digest.update(block)
        after = os.fstat(fd)
        current = path.lstat()
        if ((before.st_dev, before.st_ino, before.st_size) !=
                (after.st_dev, after.st_ino, after.st_size) or
                (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino)):
            raise ValueError("fixture endpoint file changed")
        return digest.hexdigest()
    finally:
        os.close(fd)


def _uuid(value: Any) -> bool:
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except (ValueError, TypeError):
        return False


def _certificate(path: Path) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or not 0 < info.st_size <= 65536):
            raise ValueError("fixture endpoint certificate unsafe")
        raw = os.read(fd, info.st_size + 1)
        if len(raw) != info.st_size:
            raise ValueError("fixture endpoint certificate changed")
    finally:
        os.close(fd)
    text = raw.decode("ascii")
    match = re.search(r"-----BEGIN CERTIFICATE-----\s+([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----", text)
    if match is None:
        raise ValueError("fixture endpoint certificate invalid")
    der = ssl.PEM_cert_to_DER_cert(match.group())
    try:
        dates = subprocess.run(["openssl", "x509", "-noout", "-dates"], input=raw,
                               capture_output=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("fixture endpoint certificate dates unavailable") from error
    if dates.returncode or dates.stderr or len(dates.stdout) > 512:
        raise ValueError("fixture endpoint certificate dates unavailable")
    try:
        lines = dates.stdout.decode("ascii").splitlines()
    except UnicodeError as error:
        raise ValueError("fixture endpoint certificate dates invalid") from error
    if len(lines) != 2 or not lines[0].startswith("notBefore=") or not lines[1].startswith("notAfter="):
        raise ValueError("fixture endpoint certificate dates invalid")
    now = time.time()
    try:
        valid = (ssl.cert_time_to_seconds(lines[0].removeprefix("notBefore=")) <= now <=
                 ssl.cert_time_to_seconds(lines[1].removeprefix("notAfter=")))
    except ValueError as error:
        raise ValueError("fixture endpoint certificate dates invalid") from error
    if not valid:
        raise ValueError("fixture endpoint certificate expired")
    if _digest(path, maximum=65536) != hashlib.sha256(raw).hexdigest():
        raise ValueError("fixture endpoint certificate changed")
    return hashlib.sha256(der).hexdigest()


def _process_identity(pid: int, start: str, *, proc_root: Path) -> bool:
    if type(pid) is not int or pid <= 1 or not isinstance(start, str):
        return False
    try:
        boot = (proc_root / "sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        if not _uuid(boot):
            return False
        state = (proc_root / str(pid) / "stat").read_text(encoding="ascii").rsplit(")", 1)[1].split()
        status = (proc_root / str(pid) / "status").read_text(encoding="ascii")
        uid_rows = [line.split()[1:] for line in status.splitlines() if line.startswith("Uid:")]
        return (state[0] != "Z" and start == f"linux:{boot}:{int(state[19])}" and len(uid_rows) == 1 and
                len(uid_rows[0]) == 4 and all(int(uid) == os.getuid() for uid in uid_rows[0]))
    except (OSError, ValueError, IndexError):
        return False


def _owns_loopback_port(pid: int, port: int, *, proc_root: Path) -> bool:
    try:
        target = f"0100007F:{port:04X}"
        sockets = set()
        for line in (proc_root / "net/tcp").read_text(encoding="ascii").splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 10 and fields[1] == target and fields[3] == "0A":
                sockets.add(fields[9])
        if len(sockets) != 1:
            return False
        descriptors = list((proc_root / str(pid) / "fd").iterdir())
        if len(descriptors) > 1024:
            return False
        return any(os.readlink(entry) == f"socket:[{next(iter(sockets))}]" for entry in descriptors)
    except (OSError, ValueError):
        return False


def admit_endpoint(job: Path | str, stage: Path | str, intent: Mapping[str, Any],
                   *, proc_root: Path = Path("/proc")) -> dict[str, str]:
    """Bind one live server, probe, manifest, certificate and trust store.

    The caller must supply this exact environment to the harness and its app
    children. The path roots are the fixed private job/stage created by the RPM
    transfer worker, never request-controlled locations.
    """
    job, stage = Path(job), Path(stage)
    if not isinstance(intent, Mapping) or not _uuid(intent.get("correlationId")):
        raise ValueError("fixture endpoint unavailable")
    correlation = intent["correlationId"]
    ready = _private_json(job / "fixture-server-ready.json")
    binding = _private_json(job / "fixture-endpoint-binding.json")
    probe = _private_json(stage / "fixture" / "probe-events" / (correlation + ".json"))
    trust = stage / "fixture-truststore.p12"
    trust_digest = _digest(trust, maximum=1024 * 1024)
    certificate_digest_from_file = _certificate(stage / "fixture-certificate.pem")
    receipt = stage / "fixture" / "fixture-receipt.json"
    receipt_value, receipt_digest = _private_json(receipt, readonly=True, include_digest=True)
    manifest = ready.get("manifest")
    if not isinstance(manifest, dict):
        raise ValueError("fixture endpoint unavailable")
    body = json.dumps(manifest, separators=(",", ":")).encode()
    manifest_digest = hashlib.sha256(body).hexdigest()
    try:
        port = ready["port"]
        certificate_digest = ready["peerCertificateSha256"]
        source_fingerprint = intent["sourceFingerprint"]
        expected_target = intent["expectedTargetVersion"]
        assets = manifest["assets"]
        rpm = assets[0]
        valid = (type(port) is int and 1 <= port <= 65535 and
                 _uuid(ready.get("serverInstanceId")) and
                 _process_identity(ready.get("serverPid"), ready.get("serverProcessStartIdentity"),
                                   proc_root=proc_root) and
                 _owns_loopback_port(ready.get("serverPid"), port, proc_root=proc_root) and
                 ready.get("sourceFingerprint") == source_fingerprint and
                 receipt_value.get("sourceFingerprint") == source_fingerprint and
                 receipt_value.get("manifest") == manifest and
                 ready.get("fixtureReceiptSha256") == receipt_digest and
                 ready.get("manifestSha256") == manifest_digest and
                 isinstance(certificate_digest, str) and _HASH.fullmatch(certificate_digest) and
                 certificate_digest_from_file == certificate_digest and
                 binding == {"schemaVersion": 1, "correlationId": correlation,
                             "serverInstanceId": ready["serverInstanceId"],
                             "peerCertificateSha256": certificate_digest,
                             "trustStoreSha256": trust_digest,
                             "fixtureReceiptSha256": receipt_digest} and
                 manifest.get("schemaVersion") == 1 and len(assets) == 1 and
                 rpm.get("packageType") == "rpm" and rpm.get("displayVersion") == expected_target and
                 rpm.get("sha256") == intent.get("artifactIds", {}).get("targetPackage", "").removeprefix("sha256-") and
                 rpm.get("downloadUrl", "").startswith("https://github.com/") and
                 probe == {"schemaVersion": 1, "correlationId": correlation,
                           "serverInstanceId": ready["serverInstanceId"],
                           "connectAccepted": True, "tlsSucceeded": True,
                           "exactManifestGet": True, "manifestSha256": manifest_digest,
                           "peerCertificateSha256": certificate_digest,
                           "servedBytes": len(body)})
    except (KeyError, TypeError, AttributeError):
        valid = False
    if not valid:
        raise ValueError("fixture endpoint unavailable")
    if "JAVA_TOOL_OPTIONS" in os.environ:
        raise ValueError("fixture endpoint inherited Java options")
    return {"JAVA_TOOL_OPTIONS": " ".join((
        "-Dhttps.proxyHost=127.0.0.1", f"-Dhttps.proxyPort={port}",
        "-Dhttp.proxyHost=127.0.0.1", f"-Dhttp.proxyPort={port}",
        f"-Djavax.net.ssl.trustStore={trust}", "-Djavax.net.ssl.trustStoreType=PKCS12"))}

"""Fixed Fedora fixture HTTPS server worker and read-only observer.

This file is transferred as verified bytes by the journaled host route. It is
run only from that route's private, source-bound server job. It never installs
an RPM, changes system trust, or starts a VPN/runtime.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from typing import Any


MANIFEST_URL = "https://github.com/Karapsin/vpn_control/releases/latest/download/update-manifest.json"
_HEX = re.compile(r"[0-9a-f]{64}\Z")

_MAKE_TRUST_JAVA = r'''import java.io.*;
import java.security.*;
import java.security.cert.*;
public class MakeTrust {
 public static void main(String[] args) throws Exception {
  if(args.length!=2) throw new IllegalArgumentException();
  var cert=CertificateFactory.getInstance("X.509").generateCertificate(new FileInputStream(args[0]));
  var store=KeyStore.getInstance("PKCS12"); store.load(null,null);
  store.setCertificateEntry("vpn-control-fixture",cert);
  try(var out=new FileOutputStream(args[1])) { store.store(out,"fixtureonly".toCharArray()); }
  var check=KeyStore.getInstance("PKCS12");
  try(var in=new FileInputStream(args[1])) { check.load(in,"fixtureonly".toCharArray()); }
  if(check.size()!=1 || !check.isCertificateEntry("vpn-control-fixture")) throw new IllegalStateException();
 }
}'''

_PROBE_JAVA = r'''import java.io.*;
import java.net.*;
import java.security.*;
import javax.net.ssl.*;
public class FixtureProbe {
 static String hex(byte[] bytes) { var out=new StringBuilder(); for(byte b:bytes) out.append(String.format("%02x",b&255)); return out.toString(); }
 public static void main(String[] args) throws Exception {
  if(args.length!=3) throw new IllegalArgumentException();
  var connection=(HttpsURLConnection)new URL("https://github.com/Karapsin/vpn_control/releases/latest/download/update-manifest.json").openConnection();
  connection.setConnectTimeout(10000); connection.setReadTimeout(10000);
  connection.setRequestProperty("X-Vpn-Control-Probe-Id",args[0]);
  if(connection.getResponseCode()!=200) throw new IllegalStateException("manifest status");
  var cert=connection.getServerCertificates()[0];
  byte[] body; try(var in=connection.getInputStream()) { body=in.readNBytes(1048577); }
  if(body.length>1048576 || !hex(MessageDigest.getInstance("SHA-256").digest(body)).equals(args[1])) throw new IllegalStateException("manifest digest");
  if(!hex(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded())).equals(args[2])) throw new IllegalStateException("certificate digest");
  System.out.println(args[1]);
 }
}'''


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def _private_file(path: Path, maximum: int = 1024 * 1024, *, readonly: bool = False) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        modes = (0o400, 0o600) if readonly else (0o600,)
        _require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
                 stat.S_IMODE(before.st_mode) in modes and 0 < before.st_size <= maximum,
                 "server job file unsafe")
        raw = os.read(fd, before.st_size + 1)
        after = os.fstat(fd)
        path_now = path.lstat()
        _require(len(raw) == before.st_size and
                 (before.st_dev, before.st_ino, before.st_size) ==
                 (after.st_dev, after.st_ino, after.st_size) and
                 (before.st_dev, before.st_ino) == (path_now.st_dev, path_now.st_ino),
                 "server job file changed")
        return raw
    finally:
        os.close(fd)


def _private_json(path: Path, *, readonly: bool = False) -> dict[str, Any]:
    value = json.loads(_private_file(path, readonly=readonly))
    _require(isinstance(value, dict), "server job JSON invalid")
    return value


def _durable(path: Path, value: dict[str, Any]) -> None:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _hash(path: Path, maximum: int) -> str:
    return hashlib.sha256(_private_file(path, maximum, readonly=True)).hexdigest()


def _verified_guard(stage: Path, expected_sha: str) -> dict[str, Any]:
    _require(isinstance(expected_sha, str) and _HEX.fullmatch(expected_sha) is not None,
             "server guard digest invalid")
    raw = _private_file(stage / "agent_tools" / "linux_rpm_fixture_server.py", readonly=True)
    _require(hashlib.sha256(raw).hexdigest() == expected_sha, "server guard changed")
    namespace: dict[str, Any] = {"__name__": "linux_rpm_fixture_server_guard"}
    exec(compile(raw, "<verified-linux-rpm-fixture-server>", "exec"), namespace)
    return namespace


def _run(argv: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False,
                            env={key: value for key, value in os.environ.items()
                                 if key not in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS")})
    _require(result.returncode == 0, "fixture server prerequisite failed")
    return result


def _probe_trust_password_property() -> list[str]:
    # Fixed test-only password for a store containing only the public fixture CA.
    return ["-Djavax.net.ssl.trustStorePassword=fixtureonly"]


def _java_probe(job: Path, argv: list[str]) -> None:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False,
                                env={key: value for key, value in os.environ.items()
                                     if key not in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS")})
        if result.returncode != 0:
            stderr = result.stderr or ""
            if "SSLHandshakeException" in stderr:
                kind = "tls-handshake"
            elif "manifest digest" in stderr:
                kind = "manifest-digest"
            elif "certificate digest" in stderr:
                kind = "certificate-digest"
            elif "ConnectException" in stderr or "SocketTimeoutException" in stderr:
                kind = "connection"
            elif "error: " in stderr:
                kind = "java-compile"
            else:
                kind = "java-failed"
            _durable(job / "worker-failure.json", {"schemaVersion": 1,
                "phase": "java-probe", "exceptionType": "ValueError", "failureKind": kind})
            raise ValueError("fixture server Java probe failed")
    except Exception as error:
        if not (job / "worker-failure.json").exists():
            _durable(job / "worker-failure.json", {"schemaVersion": 1,
                "phase": "java-probe", "exceptionType": type(error).__name__})
        raise


def _open_private_server_log(path: Path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    return os.fdopen(fd, "wb")


def _isolated_script_argv(script: Path, *arguments: str) -> list[str]:
    """Run one verified staged script with only its staged sibling import path."""
    runner = ("import runpy,sys; "
              "from pathlib import Path; "
              "script=Path(sys.argv[1]).resolve(strict=True); "
              "sys.path.insert(0,str(script.parent)); "
              "sys.argv=[str(script),*sys.argv[2:]]; "
              "runpy.run_path(str(script),run_name='__main__')")
    return [sys.executable, "-I", "-B", "-c", runner, str(script), *arguments]


def _check_job(job: Path) -> tuple[dict[str, Any], Path]:
    _require(job.is_absolute() and job.name and re.fullmatch(r"[0-9a-f-]{36}", job.name) is not None and
             job.parent.name == "linux-rpm-fixture-server-jobs", "server job path invalid")
    for path in (job.parent, job, job / "stage"):
        info = path.lstat()
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
                 stat.S_IMODE(info.st_mode) == 0o700, "server job directory unsafe")
    intent = _private_json(job / "intent.json")
    _require(intent.get("correlationId") == job.name and intent.get("host") == "fedora2328" and
             intent.get("environment") == "fedora2328", "server job identity invalid")
    return intent, job / "stage"


def prepare(job: Path) -> None:
    """Prepare a test-only TLS endpoint and one Java 17 probe, then return."""
    intent, stage = _check_job(job)
    fixture = stage / "fixture"
    receipt_raw = _private_file(fixture / "fixture-receipt.json", readonly=True)
    receipt = json.loads(receipt_raw)
    manifest = receipt.get("manifest") if isinstance(receipt, dict) else None
    _require(isinstance(manifest, dict) and receipt.get("sourceFingerprint") == intent["sourceFingerprint"] and
             isinstance(manifest.get("assets"), list) and len(manifest["assets"]) == 1,
             "server fixture receipt differs")
    rpm = manifest["assets"][0]
    _require(isinstance(rpm, dict) and rpm.get("packageType") == "rpm" and
             rpm.get("sha256") == intent["artifactIds"]["targetPackage"].removeprefix("sha256-") and
             rpm.get("displayVersion") == intent["expectedTargetVersion"],
             "server target RPM differs")
    rpm_path = fixture / "packages" / "target" / rpm["fileName"]
    _require(_hash(rpm_path, 1024 * 1024 * 1024) == rpm["sha256"], "server target RPM changed")
    cert = stage / "fixture-certificate.pem"
    key = stage / "fixture-private-key.pem"
    trust = stage / "fixture-truststore.p12"
    _run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
          "-keyout", str(key), "-out", str(cert), "-days", "2", "-subj", "/CN=github.com",
          "-addext", "subjectAltName=DNS:github.com"], timeout=30)
    for path in (cert, key):
        path.chmod(0o600)
    from ssl import PEM_cert_to_DER_cert
    cert_digest = hashlib.sha256(PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
    java_trust = stage / "MakeTrust.java"
    java_trust.write_text(_MAKE_TRUST_JAVA)
    java_trust.chmod(0o600)
    _run(["java", str(java_trust), str(cert), str(trust)], timeout=60)
    trust.chmod(0o600)
    _require(0 < trust.stat().st_size < 1024 * 1024, "fixture trust store unavailable")
    ready = job / "fixture-server-ready.json"
    script = stage / "scripts" / "prepare_desktop_update_fixture.py"
    log = job / "fixture-server.log"
    with _open_private_server_log(log) as output:
        server = subprocess.Popen([*_isolated_script_argv(script, "serve"),
                                   "--directory", str(fixture), "--certificate", str(cert),
                                   "--private-key", str(key), "--ready-file", str(ready),
                                   "--confirm-owned-disposable-guest"], stdin=subprocess.DEVNULL,
                                  stdout=output, stderr=output, start_new_session=True)
    _durable(job / "server-process.json", {"pid": server.pid, "correlationId": intent["correlationId"]})
    deadline = time.monotonic() + 30
    while not ready.exists() and time.monotonic() < deadline:
        _require(server.poll() is None, "fixture server exited before READY")
        time.sleep(0.1)
    _require(ready.exists(), "fixture server READY unavailable")
    ready_value = _private_json(ready)
    _require(ready_value.get("serverPid") == server.pid and
             ready_value.get("sourceFingerprint") == intent["sourceFingerprint"] and
             ready_value.get("fixtureReceiptSha256") == hashlib.sha256(receipt_raw).hexdigest() and
             ready_value.get("peerCertificateSha256") == cert_digest,
             "fixture server READY identity differs")
    body = json.dumps(manifest, separators=(",", ":")).encode()
    expected_manifest = hashlib.sha256(body).hexdigest()
    _require(ready_value.get("manifestSha256") == expected_manifest, "fixture manifest READY differs")
    probe_java = stage / "FixtureProbe.java"
    probe_java.write_text(_PROBE_JAVA)
    probe_java.chmod(0o600)
    _java_probe(job, ["java", "-Dhttps.proxyHost=127.0.0.1",
          f"-Dhttps.proxyPort={ready_value['port']}",
          f"-Djavax.net.ssl.trustStore={trust}",
          "-Djavax.net.ssl.trustStoreType=PKCS12",
          *_probe_trust_password_property(),
          str(probe_java), intent["correlationId"], expected_manifest, cert_digest])
    binding = {"schemaVersion": 1, "correlationId": intent["correlationId"],
               "serverInstanceId": ready_value["serverInstanceId"],
               "peerCertificateSha256": cert_digest,
               "trustStoreSha256": _hash(trust, 1024 * 1024),
               "fixtureReceiptSha256": hashlib.sha256(receipt_raw).hexdigest()}
    _durable(job / "fixture-endpoint-binding.json", binding)
    guard = _verified_guard(stage, intent["fileHashes"]["agent_tools/linux_rpm_fixture_server.py"]["sha256"])["admit_endpoint"]
    guard(job, stage, intent)
    _durable(job / "server-receipt.json", {"schemaVersion": 1, "state": "ready",
        "correlationId": intent["correlationId"], "sourceSha": intent["sourceSha"],
        "publicIntentSha256": intent["publicIntentSha256"],
        "sourceFixtureArtifactId": intent["artifactIds"]["sourceFixture"],
        "targetPackageArtifactId": intent["artifactIds"]["targetPackage"],
        "serverPid": server.pid, "serverProcessStartIdentity": ready_value["serverProcessStartIdentity"],
        "serverInstanceId": ready_value["serverInstanceId"],
        "manifestSha256": expected_manifest, "peerCertificateSha256": cert_digest})


def observe(job: Path, expected_guard_sha: str) -> dict[str, Any]:
    """Read only: no repair, restart, removal, or trust mutation."""
    try:
        intent, stage = _check_job(job)
        _require(intent["fileHashes"]["agent_tools/linux_rpm_fixture_server.py"]["sha256"] ==
                 expected_guard_sha, "server guard host binding differs")
        receipt = _private_json(job / "server-receipt.json")
        _require(receipt.get("state") == "ready" and
                 receipt.get("correlationId") == intent["correlationId"] and
                 receipt.get("sourceSha") == intent["sourceSha"] and
                 receipt.get("publicIntentSha256") == intent["publicIntentSha256"] and
                 receipt.get("sourceFixtureArtifactId") == intent["artifactIds"]["sourceFixture"] and
                 receipt.get("targetPackageArtifactId") == intent["artifactIds"]["targetPackage"],
                 "server receipt differs")
        guard = _verified_guard(stage, expected_guard_sha)["admit_endpoint"]
        environment = guard(job, stage, intent)
        _require("JAVA_TOOL_OPTIONS" in environment, "server proxy unavailable")
        ready = _private_json(job / "fixture-server-ready.json")
        _require(receipt.get("serverPid") == ready.get("serverPid") and
                 receipt.get("serverProcessStartIdentity") == ready.get("serverProcessStartIdentity") and
                 receipt.get("serverInstanceId") == ready.get("serverInstanceId") and
                 receipt.get("manifestSha256") == ready.get("manifestSha256") and
                 receipt.get("peerCertificateSha256") == ready.get("peerCertificateSha256"),
                 "server READY differs")
        return {"state": "ready", "correlationId": intent["correlationId"],
                "sourceSha": intent["sourceSha"], "publicIntentSha256": intent["publicIntentSha256"],
                "serverPid": receipt["serverPid"], "serverProcessStartIdentity": receipt["serverProcessStartIdentity"],
                "serverInstanceId": receipt["serverInstanceId"],
                "manifestSha256": receipt["manifestSha256"],
                "peerCertificateSha256": receipt["peerCertificateSha256"], "replayAllowed": False}
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return {"state": "unknown", "correlationId": job.name, "replayAllowed": False}


def main() -> None:
    if sys.argv[1:2] == ["prepare"] and len(sys.argv) != 3:
        raise SystemExit(64)
    if sys.argv[1:2] == ["status"] and len(sys.argv) != 4:
        raise SystemExit(64)
    if sys.argv[1:2] not in (["prepare"], ["status"]):
        raise SystemExit(64)
    job = Path(sys.argv[2])
    if sys.argv[1] == "prepare":
        try:
            prepare(job)
        except BaseException:
            # No replay or automatic process stop: retain exact job state.
            raise SystemExit(1)
    else:
        print(json.dumps(observe(job, sys.argv[3]), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()

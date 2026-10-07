"""Source-bound Android native package and local endpoint fixture admission.

This module prepares evidence only. Device trust, reverse mappings, public CLI
mutations, and PackageInstaller sessions belong to the native acceptance owner.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import select
import socket
import socketserver
import ssl
import stat
import subprocess
import tempfile
import threading
from typing import Any

BASE_ARTIFACT_ID = "sha256-75e0e9fc2804373b174e16e82310d62e9815c9cf51aa7ed603466cf64ca9c4eb"
DEVICE_HTTPS_PORT = 18080
DEVICE_SOCKS_PORT = 18081
FIXTURE_HOST = "localhost"
_SHA = re.compile(r"[0-9a-f]{40}")
_ARTIFACT = re.compile(r"sha256-[0-9a-f]{64}")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_VERSION = re.compile(r"(0?[1-9]|1[0-9])\.(0|[1-9]|1[0-9])\.(0|[1-9]|1[0-9])")


def _version(value: str) -> tuple[int, int, int]:
    if not isinstance(value, str) or not _VERSION.fullmatch(value) or value.startswith("0") and value[1:2] != ".":
        raise ValueError("Android fixture requires canonical base-20 version")
    parts = tuple(int(part) for part in value.split("."))
    if str(parts[0]) != value.split(".")[0]:
        raise ValueError("Android fixture requires canonical base-20 version")
    return parts


def _version_code(version: tuple[int, int, int]) -> int:
    return ((version[0] * 20 + version[1]) * 20 + version[2]) * 20


def _next_version(base: tuple[int, int, int], source: tuple[int, int, int]) -> tuple[int, int, int]:
    if source > base:
        return source
    encoded = (base[0] * 20 + base[1]) * 20 + base[2] + 1
    major, rest = divmod(encoded, 400)
    minor, patch = divmod(rest, 20)
    if major > 19:
        raise ValueError("Android fixture version range is exhausted")
    return major, minor, patch


def _head(root: Path) -> str:
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                          capture_output=True, text=True, timeout=10).stdout.strip()


def _clean(root: Path) -> bool:
    return not subprocess.run(["git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
                               "--no-optional-locks", "status", "--porcelain", "--untracked-files=normal"],
                              cwd=root, check=True, capture_output=True, text=True,
                              timeout=10, env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"}).stdout.strip()


def _git_common_dir(root: Path) -> Path:
    """Resolve the common Git directory without making a repository mutation."""
    try:
        result = subprocess.run(["git", "rev-parse", "--git-common-dir"], cwd=root,
                                check=False, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("Android fixture source repository is unavailable") from error
    common = result.stdout.strip()
    if result.returncode != 0 or not common or "\n" in common:
        raise ValueError("Android fixture source repository is unavailable")
    path = Path(common)
    if not path.is_absolute():
        path = root / path
    return path.resolve()


def _source_root(coordinator: Path, source_root: Path | str | None) -> Path:
    """Allow a clean linked worktree while coordinator-owned evidence stays put."""
    if source_root is None:
        return coordinator
    supplied = Path(source_root)
    if supplied.is_symlink():
        raise ValueError("Android fixture source root is unusable")
    try:
        candidate = supplied.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ValueError("Android fixture source root is unusable") from error
    if not candidate.is_dir() or _git_common_dir(candidate) != _git_common_dir(coordinator):
        raise ValueError("Android fixture source root is not the coordinator repository")
    return candidate


def _source_matches(root: Path, source_sha: str) -> None:
    if (not isinstance(source_sha, str) or not _SHA.fullmatch(source_sha) or
            _head(root) != source_sha or not _clean(root)):
        raise ValueError("Android fixture source SHA differs from checkout")


def _artifact(root: Path, artifact_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        from agent_tools import android_package_install, native_artifact_registry
    except ImportError:
        import android_package_install
        import native_artifact_registry
    if not isinstance(artifact_id, str) or not _ARTIFACT.fullmatch(artifact_id):
        raise ValueError("Android fixture requires exact artifact ID")
    verified = native_artifact_registry.verify_artifact(root, artifact_id)
    item = verified.get("artifact", {})
    location = verified.get("location", {})
    if (verified.get("verification") != "verified" or item.get("platform") != "android" or
            item.get("artifactKind") != "apk" or item.get("sha256") != artifact_id[7:] or
            not isinstance(location.get("localPath"), str)):
        raise ValueError("Android fixture artifact bytes are not verified")
    package = android_package_install._inspect_apk(root, Path(location["localPath"]))
    return item, package


def endpoint_contract() -> dict[str, Any]:
    """Fixed device-visible ports; guest setup must admit TLS trust and reverses."""
    return {
        "httpsPort": DEVICE_HTTPS_PORT,
        "socksPort": DEVICE_SOCKS_PORT,
        "tlsHost": FIXTURE_HOST,
        "healthUrl": f"https://{FIXTURE_HOST}:{DEVICE_HTTPS_PORT}/health",
        "trafficUrl": f"https://{FIXTURE_HOST}:{DEVICE_HTTPS_PORT}/traffic",
        "subscriptionUrl": f"https://{FIXTURE_HOST}:{DEVICE_HTTPS_PORT}/subscription",
        "location": f"socks://127.0.0.1:{DEVICE_SOCKS_PORT}#NativeFixture",
        "requiredCertificateSan": "DNS:localhost",
        "reverseMappingsRequired": [DEVICE_HTTPS_PORT, DEVICE_SOCKS_PORT],
        "trustSetup": "separately admitted disposable-emulator fixture CA",
        "trafficProof": "SOCKS connected event plus HTTPS path event while app runtime is running",
        "installerTargetAdmitted": False,
    }


def prepare_requirements(root: Path | str, source_sha: str, base_artifact_id: str = BASE_ARTIFACT_ID, *,
                         source_root: Path | str | None = None) -> dict[str, Any]:
    """Bind a future target build to an exact checkout and verified installed base."""
    root = Path(root).resolve(strict=True)
    source = _source_root(root, source_root)
    _source_matches(source, source_sha)
    base, package = _artifact(root, base_artifact_id)
    source_line = re.search(r"(?m)^vpnControlVersion=([^\s]+)$",
                            (source / "gradle.properties").read_text(encoding="utf-8"))
    if not source_line:
        raise ValueError("Android fixture source version is unavailable")
    current = _version(source_line.group(1))
    installed = _version(package["version"])
    if (package["code"] != _version_code(installed) or package["abi"] != "x86_64" or
            package["debuggable"] is not False or package["package"] != "com.kardinal.vpncontrol"):
        raise ValueError("Android fixture installed base identity is invalid")
    target = _next_version(installed, current)
    target_version = ".".join(map(str, target))
    return {
        "sourceSha": source_sha,
        "baseArtifactId": base_artifact_id,
        "baseSourceSha": base.get("sourceSha"),
        "baseVersion": package["version"],
        "baseCode": package["code"],
        "baseSignerSha256": package["signerSha256"],
        "targetVersion": target_version,
        "targetCode": _version_code(target),
        "targetBuildArgs": [":app:assembleNativeFixture", f"-PvpnControlVersion={target_version}"],
        "endpoint": endpoint_contract(),
        "deviceMutationAllowed": False,
    }


def verify_target(root: Path | str, requirements: dict[str, Any], target_artifact_id: str, *,
                  source_root: Path | str | None = None) -> dict[str, Any]:
    """Accept only exact-source, higher-version, same-signer nondebuggable APK."""
    root = Path(root).resolve(strict=True)
    source = _source_root(root, source_root)
    try:
        _source_matches(source, requirements.get("sourceSha"))
    except ValueError as error:
        raise ValueError("Android fixture source SHA changed") from error
    fresh = prepare_requirements(root, requirements["sourceSha"], requirements["baseArtifactId"],
                                 source_root=source)
    if fresh != requirements:
        raise ValueError("Android fixture opening package plan changed")
    target, package = _artifact(root, target_artifact_id)
    if (target.get("sourceSha") != requirements.get("sourceSha") or
            package.get("package") != "com.kardinal.vpncontrol" or package.get("abi") != "x86_64" or
            package.get("debuggable") is not False or
            package.get("signerSha256") != requirements.get("baseSignerSha256") or
            package.get("version") != requirements.get("targetVersion") or
            package.get("code") != requirements.get("targetCode")):
        raise ValueError("Android fixture target is not a compatible exact-source update")
    return {**requirements, "targetArtifactId": target_artifact_id, "targetSha256": target["sha256"],
            "targetSize": target["size"], "deviceMutationAllowed": False}


def write_private_plan(path: Path | str, plan: dict[str, Any]) -> None:
    """Publish a no-overwrite plan; it is evidence, never a mutation permit."""
    path = Path(path)
    if not path.is_absolute() or not path.name or path.name in (".", ".."):
        raise ValueError("Android fixture plan requires absolute private path")
    for ancestor in (path.parent, *path.parent.parents):
        if stat.S_ISLNK(ancestor.lstat().st_mode):
            raise ValueError("Android fixture plan has symlink ancestry")
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        parent = os.fstat(parent_fd)
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o077:
            raise ValueError("Android fixture plan directory is not private")
        descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                             0o600, dir_fd=parent_fd)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(plan, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _exact(connection: socket.socket, count: int) -> bytes:
    result = b""
    while len(result) < count:
        part = connection.recv(count - len(result))
        if not part:
            raise ConnectionError("truncated SOCKS request")
        result += part
    return result


def _socks_target(connection: socket.socket) -> tuple[str, int]:
    """Accept only a no-auth CONNECT to the fixed device-visible HTTPS port."""
    if _exact(connection, 2) != b"\x05\x01" or _exact(connection, 1) != b"\x00":
        raise ValueError("SOCKS greeting is not no-auth")
    connection.sendall(b"\x05\x00")
    version, command, reserved, address_type = _exact(connection, 4)
    if (version, command, reserved) != (5, 1, 0):
        raise ValueError("SOCKS request is not CONNECT")
    if address_type == 3:
        host = _exact(connection, _exact(connection, 1)[0]).decode("ascii", "strict")
    elif address_type == 1:
        host = socket.inet_ntoa(_exact(connection, 4))
    else:
        raise ValueError("SOCKS address type is not admitted")
    port = int.from_bytes(_exact(connection, 2), "big")
    if host not in ("localhost", "127.0.0.1") or port != DEVICE_HTTPS_PORT:
        raise ValueError("SOCKS target is not the fixed HTTPS fixture")
    return host, port


class _HttpHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        response = {
            "/health": (204, b""),
            "/traffic": (200, b"vpn-control-native-fixture\n"),
            "/subscription": (200, (endpoint_contract()["location"] + "\n").encode("ascii")),
        }.get(self.path)
        if response is None or self.headers.get("Host") not in (
                f"localhost:{DEVICE_HTTPS_PORT}", f"127.0.0.1:{DEVICE_HTTPS_PORT}"):
            self.send_error(404)
            return
        status, body = response
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)
        self.server.record({"transport": "https", "path": self.path, "status": status})

    def log_message(self, _format: str, *args: object) -> None:
        return


class _SocksHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(5)
        try:
            _socks_target(self.request)
            with socket.create_connection(("127.0.0.1", self.server.https_port), timeout=5) as upstream:
                self.request.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
                self.server.record({"transport": "socks", "event": "connected"})
                while True:
                    readable, _, _ = select.select((self.request, upstream), (), (), 5)
                    if not readable:
                        return
                    for source in readable:
                        chunk = source.recv(65536)
                        if not chunk:
                            return
                        (upstream if source is self.request else self.request).sendall(chunk)
        except (ConnectionError, OSError, ValueError):
            self.server.record({"transport": "socks", "event": "rejected"})


class _EndpointServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True

    def record(self, event: dict[str, Any]) -> None:
        with self.event_lock:
            record = {"campaignId": self.campaign_id, **event}
            self.events.append(record)
            if self.events_path is not None:
                descriptor = os.open(self.events_path, os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0))
                try:
                    info = os.fstat(descriptor)
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                        raise ValueError("Android fixture event journal changed")
                    os.write(descriptor, (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode())
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)


def _stable_tls_bytes(path: Path, *, private: bool) -> tuple[bytes, tuple[int, int, int, int]]:
    """Read one regular file through no-follow and bind its inode, mode and bytes."""
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or
                before.st_size > 1_048_576 or (private and before.st_mode & 0o077)):
            raise ValueError("Android fixture TLS input is not an owned private regular file")
        data = os.read(descriptor, 1_048_577)
        after = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino, before.st_size, stat.S_IMODE(before.st_mode))
        if (before.st_dev, before.st_ino, before.st_size, stat.S_IMODE(before.st_mode)) != (
                after.st_dev, after.st_ino, after.st_size, stat.S_IMODE(after.st_mode)) or len(data) != before.st_size:
            raise ValueError("Android fixture TLS input changed while read")
        visible = path.lstat()
        if stat.S_ISLNK(visible.st_mode) or (visible.st_dev, visible.st_ino) != identity[:2]:
            raise ValueError("Android fixture TLS path changed while read")
        return data, identity
    finally:
        os.close(descriptor)


class LocalEndpoint:
    """Loopback-only HTTPS/SOCKS fixture; caller owns certificate trust and ADB reverses."""

    def __init__(self, certificate: Path, private_key: Path, campaign_id: str, events_path: Path | None = None):
        if not isinstance(campaign_id, str) or not _UUID.fullmatch(campaign_id):
            raise ValueError("Android fixture requires exact campaign UUID")
        self.certificate = Path(certificate)
        self.private_key = Path(private_key)
        self.campaign_id = campaign_id
        self.events_path = Path(events_path) if events_path is not None else None
        self.https: _EndpointServer | None = None
        self.socks: _EndpointServer | None = None
        self.threads: list[threading.Thread] = []
        self.started_servers: list[_EndpointServer] = []
        self.events: list[dict[str, Any]] = []
        self.lock = threading.Lock()
        self._tls_directory: tempfile.TemporaryDirectory[str] | None = None
        self._ever_started = False

    def start(self) -> dict[str, Any]:
        if self._ever_started:
            raise ValueError("Android fixture campaign cannot be restarted")
        self._ever_started = True
        try:
            if self.events_path is not None:
                write_private_plan(self.events_path, {"campaignId": self.campaign_id, "event": "epoch-start"})
            certificate, certificate_id = _stable_tls_bytes(self.certificate, private=False)
            private_key, key_id = _stable_tls_bytes(self.private_key, private=True)
            self._tls_directory = tempfile.TemporaryDirectory(prefix="android-native-tls-")
            frozen = Path(self._tls_directory.name)
            for name, data in (("certificate.pem", certificate), ("private-key.pem", private_key)):
                descriptor = os.open(frozen / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as output:
                    output.write(data)
                    output.flush()
                    os.fsync(output.fileno())
            decoded = ssl._ssl._test_decode_cert(str(frozen / "certificate.pem"))
            if ("DNS", "localhost") not in decoded.get("subjectAltName", ()):
                raise ValueError("Android fixture TLS certificate requires DNS:localhost")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(frozen / "certificate.pem"), str(frozen / "private-key.pem"))
            if ((_stable_tls_bytes(self.certificate, private=False) != (certificate, certificate_id)) or
                    (_stable_tls_bytes(self.private_key, private=True) != (private_key, key_id))):
                raise ValueError("Android fixture TLS input changed during SSL loading")
            self.https = _EndpointServer(("127.0.0.1", 0), _HttpHandler)
            self.https.events = self.events
            self.https.event_lock = self.lock
            self.https.campaign_id = self.campaign_id
            self.https.events_path = self.events_path
            self.https.socket = context.wrap_socket(self.https.socket, server_side=True)
            self.socks = _EndpointServer(("127.0.0.1", 0), _SocksHandler)
            self.socks.events = self.events
            self.socks.event_lock = self.lock
            self.socks.campaign_id = self.campaign_id
            self.socks.events_path = self.events_path
            self.socks.https_port = self.https.server_address[1]
            for server in (self.https, self.socks):
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                self.threads.append(thread)
                self.started_servers.append(server)
        except BaseException:
            self.stop()
            raise
        return {"campaignId": self.campaign_id, "host": "127.0.0.1", "hostHttpsPort": self.https.server_address[1],
                "hostSocksPort": self.socks.server_address[1],
                "certificateSha256": hashlib.sha256(certificate).hexdigest(),
                "privateKeySha256": hashlib.sha256(private_key).hexdigest(),
                "deviceContract": endpoint_contract()}

    def stop(self) -> None:
        for server in self.started_servers:
            server.shutdown()
        for server in (self.socks, self.https):
            if server is not None:
                server.server_close()
        for thread in self.threads:
            thread.join(timeout=2)
        self.socks = self.https = None
        self.threads = []
        self.started_servers = []
        if self._tls_directory is not None:
            self._tls_directory.cleanup()
            self._tls_directory = None

    def event_counts(self) -> dict[str, int]:
        """Expose bounded proof without request bytes, URLs beyond fixed paths, or credentials."""
        with self.lock:
            events = [event for event in self.events if event.get("campaignId") == self.campaign_id]
        return {
            "campaignId": self.campaign_id,
            "socksConnected": sum(event.get("transport") == "socks" and event.get("event") == "connected" for event in events),
            "socksRejected": sum(event.get("transport") == "socks" and event.get("event") == "rejected" for event in events),
            "health": sum(event.get("transport") == "https" and event.get("path") == "/health" and event.get("status") == 204 for event in events),
            "traffic": sum(event.get("transport") == "https" and event.get("path") == "/traffic" and event.get("status") == 200 for event in events),
            "subscription": sum(event.get("transport") == "https" and event.get("path") == "/subscription" and event.get("status") == 200 for event in events),
        }

    def __enter__(self) -> "LocalEndpoint":
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()


def serve_campaign(certificate: Path, private_key: Path, campaign_id: str,
                   ready_path: Path, events_path: Path, stopped_path: Path) -> None:
    """Retained worker entrypoint; its parent journals before launching this process."""
    import signal
    waiter = threading.Event()
    with LocalEndpoint(certificate, private_key, campaign_id, events_path) as endpoint:
        ready = {"campaignId": campaign_id, "pid": os.getpid(), "state": "running",
                 "endpoint": {"hostHttpsPort": endpoint.https.server_address[1],
                              "hostSocksPort": endpoint.socks.server_address[1]},
                 "certificateSha256": hashlib.sha256(_stable_tls_bytes(certificate, private=False)[0]).hexdigest()}
        try:
            ready["startTicks"] = int(Path(f"/proc/{os.getpid()}/stat").read_text().split(") ", 1)[1].split()[19])
        except (OSError, IndexError, ValueError):
            raise RuntimeError("Android fixture process identity unavailable")
        signal.signal(signal.SIGTERM, lambda *_: waiter.set())
        signal.signal(signal.SIGINT, lambda *_: waiter.set())
        write_private_plan(ready_path, ready)
        waiter.wait()
    write_private_plan(stopped_path, {"campaignId": campaign_id, "state": "stopped",
                                      "eventCounts": endpoint.event_counts()})


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("serve",))
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--ready", type=Path, required=True)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--stopped", type=Path, required=True)
    args = parser.parse_args()
    serve_campaign(args.certificate, args.private_key, args.campaign_id,
                   args.ready, args.events, args.stopped)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

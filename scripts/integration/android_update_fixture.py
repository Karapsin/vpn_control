#!/usr/bin/env python3
"""Isolated HTTPS update fixture; never connects or forwards to an upstream host.

Only root's positively identified disposable emulator may trust its temporary CA.
The production GitHub URL, APK signer, package ID and manifest checks remain intact.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socketserver
import ssl
import subprocess
import sys
import tempfile
import time

MANIFEST_PATH = "/Karapsin/vpn_control/releases/latest/download/update-manifest.json"
APK_PATH = "/Karapsin/vpn_control/releases/download/disposable-session-fixture/update.apk"
READY_SCHEMA_VERSION = 1


class FixtureReadinessError(RuntimeError):
    def __init__(self, receipt):
        super().__init__("Android update fixture did not become ready")
        self.receipt = receipt


class ReadyFileIncomplete(ValueError):
    pass


def make_manifest(apk: Path, version: str, build: int):
    digest = hashlib.sha256()
    with apk.open("rb") as source:
        for block in iter(lambda: source.read(65536), b""):
            digest.update(block)
    return {
        "schemaVersion": 1, "buildNumber": build, "releaseTag": "disposable-session-fixture",
        "releaseNotesUrl": "https://github.com/Karapsin/vpn_control/releases/tag/disposable-session-fixture",
        "assets": [{"platform": "android", "architecture": "arm64-v8a", "packageType": "apk",
                    "displayVersion": version, "fileName": "update.apk", "downloadUrl": "https://github.com" + APK_PATH,
                    "sha256": digest.hexdigest(), "sizeBytes": apk.stat().st_size}],
    }


def select_resource(method: str, target: str, host: str):
    if method != "GET" or host.lower() not in ("github.com", "github.com:443"):
        return None
    if target == MANIFEST_PATH:
        return "manifest"
    if target == APK_PATH:
        return "apk"
    return None


def fixture_environment(environment=None):
    """Return the isolated child environment used by the retained fixture process."""
    result = dict(os.environ if environment is None else environment)
    result.pop("DYLD_INSERT_LIBRARIES", None)
    result["PATH"] = os.defpath
    return result


def read_ready_file(path: Path, manifest: dict):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ReadyFileIncomplete("Fixture ready file is still being published") from error
    except OSError as error:
        raise ReadyFileIncomplete("Fixture ready file disappeared during publication") from error
    if not isinstance(value, dict) or set(value) != {"port", "manifest"} or value["manifest"] != manifest:
        raise ValueError("Fixture ready file does not match the launched fixture")
    port = value["port"]
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("Fixture ready file has an invalid port")
    return port


def _write_receipt(path: Path, receipt: dict):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(receipt, output, sort_keys=True)
        output.write("\n")


def publish_ready_file(path: Path, manifest: dict, port: int):
    """Atomically publish one complete, private ready record without replacing evidence."""
    directory = path.parent
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=directory)
    temporary_path = Path(temporary)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump({"port": port, "manifest": manifest}, output)
            output.flush()
            os.fsync(output.fileno())
        # link is an atomic no-overwrite publication in the same directory; replace would
        # allow an old receipt to be silently overwritten by a later fixture attempt.
        os.link(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def _stop_fixture(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def launch_supervised_fixture(apk: Path, version: str, build_number: int, certificate: Path, private_key: Path,
                              ready_file: Path, log_file: Path, receipt_file: Path, timeout_seconds: float = 15,
                              environment=None, fixture_script: Path | None = None):
    """Launch a retained fixture and certify its exact ready record before device setup.

    Any failure writes a terminal receipt with the child exit status and retained log path.
    The child gets a new session so a short-lived command wrapper cannot silently remove it.
    """
    if timeout_seconds <= 0:
        raise ValueError("Fixture readiness timeout must be positive")
    for path in (ready_file, log_file, receipt_file):
        if path.exists():
            raise ValueError("Fixture evidence path already exists")
    expected_manifest = make_manifest(apk, version, build_number)
    script = fixture_script or Path(__file__).resolve()
    command = [
        sys.executable, str(script), "--apk", str(apk), "--version", version,
        "--build-number", str(build_number), "--certificate", str(certificate),
        "--private-key", str(private_key), "--ready-file", str(ready_file),
    ]
    log_descriptor = os.open(log_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(log_descriptor, "wb") as log:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
            env=fixture_environment(environment), start_new_session=True,
        )
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        exit_code = process.poll()
        if exit_code is not None:
            receipt = {
                "schemaVersion": READY_SCHEMA_VERSION, "state": "exited", "pid": process.pid,
                "exitCode": exit_code, "readyFile": str(ready_file), "logFile": str(log_file),
            }
            _write_receipt(receipt_file, receipt)
            raise FixtureReadinessError(receipt)
        if ready_file.exists():
            try:
                port = read_ready_file(ready_file, expected_manifest)
            except ReadyFileIncomplete:
                time.sleep(0.05)
                continue
            except ValueError:
                _stop_fixture(process)
                receipt = {
                    "schemaVersion": READY_SCHEMA_VERSION, "state": "invalid-ready", "pid": process.pid,
                    "exitCode": process.returncode, "readyFile": str(ready_file), "logFile": str(log_file),
                }
                _write_receipt(receipt_file, receipt)
                raise FixtureReadinessError(receipt)
            if process.poll() is None:
                receipt = {
                    "schemaVersion": READY_SCHEMA_VERSION, "state": "ready", "pid": process.pid,
                    "port": port, "readyFile": str(ready_file), "logFile": str(log_file),
                }
                _write_receipt(receipt_file, receipt)
                return process
        time.sleep(0.05)
    _stop_fixture(process)
    receipt = {
        "schemaVersion": READY_SCHEMA_VERSION, "state": "timeout", "pid": process.pid,
        "exitCode": process.returncode, "readyFile": str(ready_file), "logFile": str(log_file),
    }
    _write_receipt(receipt_file, receipt)
    raise FixtureReadinessError(receipt)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--build-number", type=int, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--ready-file", type=Path, required=True)
    parser.add_argument("--supervise", action="store_true")
    parser.add_argument("--log-file", type=Path)
    parser.add_argument("--receipt-file", type=Path)
    parser.add_argument("--ready-timeout-seconds", type=float, default=15)
    args = parser.parse_args()
    if args.supervise:
        if args.log_file is None or args.receipt_file is None:
            parser.error("--supervise requires --log-file and --receipt-file")
        try:
            launch_supervised_fixture(args.apk, args.version, args.build_number, args.certificate, args.private_key,
                                      args.ready_file, args.log_file, args.receipt_file, args.ready_timeout_seconds)
        except (FixtureReadinessError, ValueError) as error:
            if isinstance(error, FixtureReadinessError):
                print(json.dumps(error.receipt, sort_keys=True))
            else:
                print(json.dumps({"schemaVersion": READY_SCHEMA_VERSION, "state": "preflight-failed",
                                  "reason": str(error)}, sort_keys=True))
            return 1
        print(args.receipt_file.read_text(encoding="utf-8"), end="")
        return 0
    manifest = make_manifest(args.apk, args.version, args.build_number)
    body = json.dumps(manifest, separators=(",", ":")).encode()
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(args.certificate, args.private_key)

    class Handler(socketserver.BaseRequestHandler):
        def header(self):
            data = bytearray()
            while not data.endswith(b"\r\n\r\n"):
                value = self.request.recv(1)
                if not value:
                    raise EOFError
                data.extend(value)
                if len(data) > 16384:
                    raise ValueError("Oversized request header")
            lines = data.decode("ascii").split("\r\n")
            method, target, _ = lines[0].split(" ")
            headers = dict(line.split(":", 1) for line in lines[1:] if ":" in line)
            host = next((value.strip() for key, value in headers.items() if key.lower() == "host"), "")
            return method, target, host

        def handle(self):
            self.request.settimeout(60)
            try:
                method, target, _ = self.header()
                if method != "CONNECT" or target.lower() != "github.com:443":
                    self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                    return
                self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                self.request = tls.wrap_socket(self.request, server_side=True)
                resource = select_resource(*self.header())
                if resource is None:
                    self.request.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    return
                length = len(body) if resource == "manifest" else args.apk.stat().st_size
                self.request.sendall(("HTTP/1.1 200 OK\r\nContent-Length: " + str(length) +
                                      "\r\nConnection: close\r\n\r\n").encode())
                if resource == "manifest":
                    self.request.sendall(body)
                else:
                    with args.apk.open("rb") as source:
                        for block in iter(lambda: source.read(65536), b""):
                            self.request.sendall(block)
                print(json.dumps({"served": resource, "bytes": length}), flush=True)
            except (OSError, EOFError, ValueError):
                print('{"request":"closed-or-rejected"}', flush=True)

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = False

    with Server(("127.0.0.1", 0), Handler) as server:
        publish_ready_file(args.ready_file, manifest, server.server_address[1])
        server.serve_forever()


if __name__ == "__main__":
    raise SystemExit(main())

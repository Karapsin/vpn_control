#!/usr/bin/env python3
"""Isolated HTTPS update fixture; never connects or forwards to an upstream host.

Only root's positively identified disposable emulator may trust its temporary CA.
The production GitHub URL, APK signer, package ID and manifest checks remain intact.
"""
import argparse
import hashlib
import json
from pathlib import Path
import socketserver
import ssl

MANIFEST_PATH = "/Karapsin/vpn_control/releases/latest/download/update-manifest.json"
APK_PATH = "/Karapsin/vpn_control/releases/download/disposable-session-fixture/update.apk"


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--build-number", type=int, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--ready-file", type=Path, required=True)
    args = parser.parse_args()
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
        with args.ready_file.open("x") as output:
            json.dump({"port": server.server_address[1], "manifest": manifest}, output)
        server.serve_forever()


if __name__ == "__main__":
    main()

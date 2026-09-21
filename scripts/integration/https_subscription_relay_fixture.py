#!/usr/bin/env python3
"""One-source loopback HTTPS subscription and SOCKS relay fixture."""

from __future__ import annotations

import argparse
import http.server
import ipaddress
import json
import os
import socket
import ssl
import threading
import time
from pathlib import Path

try:
    from .socks_http_fixture import FixtureServer
except ImportError:  # Direct script execution keeps the fixture self-contained.
    from socks_http_fixture import FixtureServer


TLS_HANDSHAKE_TIMEOUT_SECONDS = 0.25
HTTP_IO_TIMEOUT_SECONDS = 3


class _SubscriptionHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path != self.server.subscription_path:  # type: ignore[attr-defined]
            self.send_error(404)
            return
        body = self.server.subscription_body.encode("utf-8")  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        pass


class _TlsThreadingHTTPServer(http.server.ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], handler: type[http.server.BaseHTTPRequestHandler], context: ssl.SSLContext) -> None:
        super().__init__(address, handler)
        self._context = context

    def get_request(self):
        connection, address = self.socket.accept()
        connection.settimeout(TLS_HANDSHAKE_TIMEOUT_SECONDS)
        try:
            tls_connection = self._context.wrap_socket(connection, server_side=True)
        except BaseException:
            connection.close()
            raise
        tls_connection.settimeout(HTTP_IO_TIMEOUT_SECONDS)
        return tls_connection, address


def _localhost_tls_server(context: ssl.SSLContext) -> _TlsThreadingHTTPServer:
    addresses = socket.getaddrinfo(
        "localhost", 0, type=socket.SOCK_STREAM
    )
    if not addresses or any(not ipaddress.ip_address(item[4][0]).is_loopback for item in addresses):
        raise OSError("localhost must resolve exclusively to loopback addresses")
    family, _socket_type, _protocol, _canonical_name, address = addresses[0]

    class LocalhostTlsServer(_TlsThreadingHTTPServer):
        address_family = family

    return LocalhostTlsServer(address, _SubscriptionHandler, context)


class HttpsSubscriptionRelayFixture:
    """Starts an HTTPS listener and relay whose published endpoints are derived from live sockets."""

    def __init__(self, certificate: Path, private_key: Path, readiness_file: Path, token: str,
                 subscription_path: str = "/subscription") -> None:
        if not subscription_path.startswith("/"):
            raise ValueError("subscription path must start with /")
        self.certificate = certificate
        self.private_key = private_key
        self.readiness_file = readiness_file
        self.token = token
        self.subscription_path = subscription_path
        self.https_server: http.server.ThreadingHTTPServer | None = None
        self.relay_server: FixtureServer | None = None
        self._https_thread: threading.Thread | None = None
        self._relay_thread: threading.Thread | None = None

    def start(self) -> dict[str, object]:
        if self.https_server is not None:
            raise RuntimeError("fixture is already running")
        if self.readiness_file.exists():
            raise FileExistsError(f"readiness file already exists: {self.readiness_file}")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.certificate, self.private_key)
        https = _localhost_tls_server(context)
        try:
            https_port = https.server_address[1]
            relay = FixtureServer("127.0.0.1", 0, self.token, forward_host="localhost", forward_port=https_port)
            relay_port = relay.server_address[1]
            https.subscription_path = self.subscription_path  # type: ignore[attr-defined]
            https.subscription_body = f"socks://127.0.0.1:{relay_port}\n"  # type: ignore[attr-defined]
            self.https_server, self.relay_server = https, relay
            self._https_thread = threading.Thread(target=https.serve_forever, daemon=True)
            self._relay_thread = threading.Thread(target=relay.serve_forever, daemon=True)
            self._https_thread.start()
            self._relay_thread.start()
            readiness = self.readiness()
            self._publish_readiness(readiness)
            return readiness
        except BaseException:
            https.server_close()
            self.stop()
            raise

    def readiness(self) -> dict[str, object]:
        if self.https_server is None or self.relay_server is None:
            raise RuntimeError("fixture is not running")
        if self._https_thread is None or self._relay_thread is None or not self._https_thread.is_alive() or not self._relay_thread.is_alive():
            raise RuntimeError("fixture listener stopped before readiness publication")
        https_port = self.https_server.server_address[1]
        relay_port = self.relay_server.server_address[1]
        if self.relay_server._forward_host != "localhost" or self.relay_server._forward_port != https_port:
            raise RuntimeError("relay forwarding target does not match the HTTPS listener")
        return {
            "source": f"https://localhost:{https_port}{self.subscription_path}",
            "httpsHost": "localhost",
            "httpsPort": https_port,
            "advertisedSocksHost": "127.0.0.1",
            "advertisedSocksPort": relay_port,
            "relayPort": relay_port,
            "forwardHost": "localhost",
            "forwardPort": https_port,
        }

    def _publish_readiness(self, readiness: dict[str, object]) -> None:
        self.readiness_file.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self.readiness_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(readiness, output, separators=(",", ":"))
            output.write("\n")

    def stop(self, timeout: float = 3) -> None:
        for server in (self.relay_server, self.https_server):
            if server is not None:
                server.shutdown()
                server.server_close()
        for thread in (self._relay_thread, self._https_thread):
            if thread is not None:
                thread.join(timeout)
                if thread.is_alive():
                    raise RuntimeError("fixture server did not stop within the bounded timeout")
        self.https_server = self.relay_server = None
        self._https_thread = self._relay_thread = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--ready-file", type=Path, required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--subscription-path", default="/subscription")
    parser.add_argument("--serve-for-seconds", type=float)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    fixture = HttpsSubscriptionRelayFixture(args.certificate, args.private_key, args.ready_file, args.token, args.subscription_path)
    fixture.start()
    try:
        if args.serve_for_seconds is None:
            while True:
                time.sleep(1)
        else:
            time.sleep(args.serve_for_seconds)
    except KeyboardInterrupt:
        pass
    finally:
        fixture.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

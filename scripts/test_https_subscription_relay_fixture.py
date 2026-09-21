#!/usr/bin/env python3

from __future__ import annotations

import json
import socket
import ssl
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import urlparse

from integration.https_subscription_relay_fixture import HttpsSubscriptionRelayFixture


class HttpsSubscriptionRelayFixtureTest(unittest.TestCase):
    def create_certificate_pair(self, directory: Path) -> tuple[Path, Path]:
        certificate = directory / "certificate.pem"
        private_key = directory / "private.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
            "-keyout", str(private_key), "-out", str(certificate),
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return certificate, private_key

    def test_live_fixture_derives_every_endpoint_after_binding_and_forwards_subscription(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            certificate, private_key = self.create_certificate_pair(root)
            readiness_file = root / "ready.json"
            stale_socket = socket.socket()
            stale_socket.bind(("127.0.0.1", 0))
            retired_port = stale_socket.getsockname()[1]
            fixture = HttpsSubscriptionRelayFixture(certificate, private_key, readiness_file, "ignored")
            try:
                readiness = fixture.start()
                self.assertEqual(readiness, json.loads(readiness_file.read_text(encoding="utf-8")))
                self.assertNotEqual(retired_port, readiness["advertisedSocksPort"], "a retired hand-assembled port must not leak into the fixture")
                self.assertEqual(readiness["advertisedSocksPort"], readiness["relayPort"])
                self.assertEqual(readiness["httpsPort"], readiness["forwardPort"])
                source = urlparse(readiness["source"])
                self.assertEqual(source.hostname, readiness["forwardHost"])
                self.assertEqual(source.port, readiness["forwardPort"])
                expected = f"socks://{readiness['advertisedSocksHost']}:{readiness['relayPort']}\n".encode()
                self.assertEqual(expected, self.fetch_tls(certificate, source.hostname, source.port))
                self.assertEqual(expected, self.fetch_via_socks(certificate, readiness["relayPort"], source.hostname, source.port))
            finally:
                stale_socket.close()
                fixture.stop()

    def test_readiness_file_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            certificate, private_key = self.create_certificate_pair(root)
            readiness_file = root / "ready.json"
            readiness_file.write_text("prior evidence\n", encoding="utf-8")
            fixture = HttpsSubscriptionRelayFixture(certificate, private_key, readiness_file, "ignored")
            with self.assertRaises(FileExistsError):
                fixture.start()
            self.assertEqual("prior evidence\n", readiness_file.read_text(encoding="utf-8"))
            self.assertIsNone(fixture.https_server)
            self.assertIsNone(fixture.relay_server)

    def test_stop_is_bounded_when_a_client_withholds_tls_handshake(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            certificate, private_key = self.create_certificate_pair(root)
            fixture = HttpsSubscriptionRelayFixture(certificate, private_key, root / "ready.json", "ignored")
            fixture.start()
            readiness = fixture.readiness()
            client = socket.create_connection((readiness["httpsHost"], readiness["httpsPort"]), timeout=3)
            try:
                started = time.monotonic()
                fixture.stop(timeout=1)
                self.assertLess(time.monotonic() - started, 2)
            finally:
                client.close()

    def test_tls_peer_that_withholds_an_http_request_is_closed_after_the_io_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            certificate, private_key = self.create_certificate_pair(root)
            fixture = HttpsSubscriptionRelayFixture(certificate, private_key, root / "ready.json", "ignored")
            fixture.start()
            readiness = fixture.readiness()
            context = ssl.create_default_context(cafile=str(certificate))
            try:
                with socket.create_connection((readiness["httpsHost"], readiness["httpsPort"]), timeout=3) as connection:
                    with context.wrap_socket(connection, server_hostname=readiness["httpsHost"]) as tls:
                        tls.settimeout(4)
                        started = time.monotonic()
                        self.assertEqual(b"", tls.recv(1))
                        self.assertGreaterEqual(time.monotonic() - started, 2.5)
            finally:
                fixture.stop()

    def fetch_tls(self, certificate: Path, host: str, port: int) -> bytes:
        context = ssl.create_default_context(cafile=str(certificate))
        with socket.create_connection((host, port), timeout=3) as connection:
            with context.wrap_socket(connection, server_hostname=host) as tls:
                tls.sendall(b"GET /subscription HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                return http_body(receive_until_close(tls))

    def fetch_via_socks(self, certificate: Path, relay_port: int, host: str, https_port: int) -> bytes:
        encoded_host = host.encode("ascii")
        with socket.create_connection(("127.0.0.1", relay_port), timeout=3) as connection:
            connection.sendall(b"\x05\x01\x00")
            self.assertEqual(b"\x05\x00", receive_exact(connection, 2))
            connection.sendall(b"\x05\x01\x00\x03" + bytes((len(encoded_host),)) + encoded_host + https_port.to_bytes(2, "big"))
            self.assertEqual(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00", receive_exact(connection, 10))
            context = ssl.create_default_context(cafile=str(certificate))
            with context.wrap_socket(connection, server_hostname=host) as tls:
                tls.sendall(b"GET /subscription HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                return http_body(receive_until_close(tls))


def receive_exact(connection: socket.socket, size: int) -> bytes:
    response = bytearray()
    while len(response) < size:
        chunk = connection.recv(size - len(response))
        if not chunk:
            raise ConnectionError("peer closed before the expected SOCKS response")
        response.extend(chunk)
    return bytes(response)


def receive_until_close(connection: socket.socket) -> bytes:
    response = bytearray()
    while True:
        chunk = connection.recv(4096)
        if not chunk:
            return bytes(response)
        response.extend(chunk)


def http_body(response: bytes) -> bytes:
    head, separator, body = response.partition(b"\r\n\r\n")
    if separator != b"\r\n\r\n" or not head.startswith(b"HTTP/1.0 200") and not head.startswith(b"HTTP/1.1 200"):
        raise AssertionError(response)
    return body


if __name__ == "__main__":
    unittest.main()

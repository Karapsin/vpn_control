#!/usr/bin/env python3

from __future__ import annotations

import json
import socket
import socketserver
import re
import shlex
import tempfile
import threading
import time
import unittest
from unittest import mock
from pathlib import Path

from integration.socks_http_fixture import RELAY_MAX_PENDING_BYTES, FixtureServer, SocksHttpFixtureHandler


REPOSITORY = Path(__file__).resolve().parents[1]


class SocksHttpFixtureTest(unittest.TestCase):
    def test_forward_resolution_preserves_ipv6_fallback_and_loopback_rejection(self) -> None:
        ipv6 = (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("::1", 443, 0, 0))
        ipv4 = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443))
        external = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.1", 443))
        for addresses, expected in [([ipv6, ipv4], ipv4), ([ipv6], ipv6)]:
            with self.subTest(addresses=addresses), mock.patch("socket.getaddrinfo", return_value=addresses):
                self.assertEqual(expected, SocksHttpFixtureHandler._owned_loopback_address("localhost", 443))
        with mock.patch("socket.getaddrinfo", return_value=[ipv4, external]), self.assertRaises(OSError):
            SocksHttpFixtureHandler._owned_loopback_address("localhost", 443)

    def test_held_socks_tunnel_does_not_starve_a_second_http_tunnel(self) -> None:
        """A persistent continuity stream must not serialize later TUN probes."""
        with tempfile.TemporaryDirectory() as directory:
            transcript = Path(directory) / "concurrent.ndjson"
            server, thread = start_fixture(transcript)
            try:
                with socket.create_connection(server.server_address, timeout=3) as held:
                    held.sendall(b"\x05\x01\x00")
                    self.assertEqual(b"\x05\x00", receive_exact(held, 2))
                    held.sendall(b"\x05\x01\x00\x01\xc6\x12\x00\x01\x00\x50")
                    self.assertEqual(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00", receive_exact(held, 10))
                    # Keep this connection open without payload: a serial fixture blocks in recv.
                    with socket.create_connection(server.server_address, timeout=3) as probe:
                        probe.settimeout(1)
                        probe.sendall(b"\x05\x01\x00")
                        self.assertEqual(b"\x05\x00", receive_exact(probe, 2))
                        probe.sendall(b"\x05\x01\x00\x01\xc6\x12\x00\x01\x00\x50")
                        self.assertEqual(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00", receive_exact(probe, 10))
                        probe.sendall(b"GET /probe HTTP/1.1\r\nHost: 198.18.0.1\r\n\r\n")
                        self.assertTrue(receive_until_close(probe).endswith(b"fixture-token"))
                self.assertTrue(thread.is_alive())
            finally:
                stop_fixture(server, thread)

    def test_exact_reader_stops_on_peer_eof(self) -> None:
        class ClosedPeer:
            calls = 0

            def recv(self, _size: int) -> bytes:
                self.calls += 1
                if self.calls > 1:
                    raise AssertionError("An EOF must not be read repeatedly")
                return b""

        with self.assertRaises(ConnectionError):
            receive_exact(ClosedPeer(), 2)

    def test_udp_rejection_preserves_a_subsequent_tcp_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            transcript = Path(directory) / "requests.ndjson"
            server, thread = start_fixture(transcript)
            try:
                with socket.create_connection(server.server_address, timeout=3) as client:
                    client.sendall(b"\x05\x01\x00")
                    self.assertEqual(b"\x05\x00", receive_exact(client, 2))
                    client.sendall(b"\x05\x03\x00\x01" + b"\x00" * 6)
                    self.assertEqual(b"\x05\x07\x00\x01" + b"\x00" * 6, receive_exact(client, 10))
                with socket.create_connection(server.server_address, timeout=3) as client:
                    client.sendall(b"\x05\x01\x00")
                    self.assertEqual(b"\x05\x00", receive_exact(client, 2))
                    client.sendall(b"\x05\x01\x00\x01\xc6\x12\x00\x01\x00\x50")
                    self.assertEqual(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00", receive_exact(client, 10))
                    client.sendall(b"GET /after-udp HTTP/1.1\r\nHost: 198.18.0.1\r\n\r\n")
                    self.assertTrue(receive_until_close(client).endswith(b"fixture-token"))
                events = read_transcript(transcript, minimum_events=6)
                self.assertEqual(2, sum(event.get("event") == "greeting" for event in events))
                self.assertEqual(1, sum(event.get("event") == "connect" for event in events))
                self.assertTrue(thread.is_alive())
            finally:
                stop_fixture(server, thread)

    def test_android_probe_uses_api29_and_api35_toybox_flags_with_bounded_eof(self) -> None:
        source = (REPOSITORY / "app/src/androidTest/java/com/kardinal/vpncontrol/data/FullVpnLifecycleInstrumentedTest.kt").read_text(encoding="utf-8")
        command = re.search(r'const val SHELL_TCP_PROBE = "([^"]+)"', source)
        self.assertIsNotNone(command)
        argv = shlex.split(command.group(1))
        self.assertEqual(["toybox", "nc"], argv[:2])
        # Use the intersection of recorded API29/API35 toybox nc flags: API29
        # lacks -n/-z. Connect, idle-read and EOF waits must all be finite.
        supported = {"-4", "-w", "-W", "-q"}
        self.assertFalse(set(arg for arg in argv[2:] if arg.startswith("-")) - supported)
        for option in ("-w", "-W", "-q"):
            self.assertIn(option, argv)
            self.assertEqual("5", argv[argv.index(option) + 1])
        self.assertEqual(["203.0.113.1", "80"], argv[-2:])

    def test_android_probe_uses_vpn_covered_shell_and_self_contained_fixture(self) -> None:
        release_manifest = (REPOSITORY / "app/src/main/AndroidManifest.xml").read_text(encoding="utf-8")
        lifecycle_test = (
            REPOSITORY
            / "app/src/androidTest/java/com/kardinal/vpncontrol/data/FullVpnLifecycleInstrumentedTest.kt"
        ).read_text(encoding="utf-8")
        workflow = (REPOSITORY / ".github/workflows/vpn-integration.yml").read_text(encoding="utf-8")

        self.assertIn("AndroidSocksHttpFixture", lifecycle_test)
        self.assertIn('executeShellCommand("id -u")', lifecycle_test)
        self.assertIn("toybox nc", lifecycle_test)
        self.assertIn("awaitDestination", lifecycle_test)
        self.assertNotIn("android-socks-ready", workflow)
        self.assertNotIn("usesCleartextTraffic", release_manifest)

    def test_fixture_completes_socks_handshake_and_returns_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            transcript = Path(directory) / "greetings.ndjson"
            server, thread = start_fixture(transcript)
            try:
                with socket.create_connection(server.server_address, timeout=3) as client:
                    client.sendall(b"\x05\x01\x00")
                    self.assertEqual(b"\x05\x00", receive_exact(client, 2))
                    client.sendall(b"\x05\x01\x00\x01\xc6\x12\x00\x01\x00\x50")
                    self.assertEqual(b"\x05\x00", receive_exact(client, 2))
                    receive_exact(client, 8)
                    client.sendall(b"GET /probe HTTP/1.1\r\nHost: 198.18.0.1\r\n\r\n")
                    response = receive_until_close(client)
                self.assertIn(b"HTTP/1.1 200 OK", response)
                self.assertTrue(response.endswith(b"fixture-token"))
                self.assertIn({"event": "methods", "offered": [0]}, read_transcript(transcript))
            finally:
                stop_fixture(server, thread)

    def test_fixture_forwards_tls_bytes_only_to_its_owned_loopback_destination(self) -> None:
        received = bytearray()

        class EchoHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                payload = self.request.recv(4096)
                received.extend(payload)
                self.request.sendall(payload)

        upstream = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        server = FixtureServer(
            "127.0.0.1",
            0,
            "fixture-token",
            forward_host="127.0.0.1",
            forward_port=upstream.server_address[1],
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        tls_bytes = b"\x16\x03\x03\x00\x05hello"
        try:
            with socket.create_connection(server.server_address, timeout=3) as client:
                client.sendall(b"\x05\x01\x00")
                self.assertEqual(b"\x05\x00", receive_exact(client, 2))
                client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + upstream.server_address[1].to_bytes(2, "big"))
                self.assertEqual(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00", receive_exact(client, 10))
                client.sendall(tls_bytes)
                self.assertEqual(tls_bytes, receive_exact(client, len(tls_bytes)))
            with socket.create_connection(server.server_address, timeout=3) as client:
                client.sendall(b"\x05\x01\x00")
                self.assertEqual(b"\x05\x00", receive_exact(client, 2))
                denied_port = 1 if upstream.server_address[1] == 65_535 else upstream.server_address[1] + 1
                client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + denied_port.to_bytes(2, "big"))
                self.assertEqual(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00", receive_exact(client, 10))
            self.assertEqual(tls_bytes, bytes(received))
        finally:
            stop_fixture(server, thread)
            upstream.shutdown()
            upstream.server_close()
            upstream_thread.join(timeout=3)

    def test_fixture_drains_large_duplex_transfer_after_client_half_close(self) -> None:
        payload = b"\x16\x03\x03" + b"x" * (2 * 1024 * 1024)
        ready = b"upstream-ready"

        class SlowEchoHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                self.request.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
                self.request.sendall(ready)
                received = bytearray()
                while True:
                    chunk = self.request.recv(4096)
                    if not chunk:
                        break
                    received.extend(chunk)
                    time.sleep(0.0005)
                for start in range(0, len(received), 4096):
                    self.request.sendall(received[start:start + 4096])
                    time.sleep(0.0005)

        upstream = socketserver.ThreadingTCPServer(("127.0.0.1", 0), SlowEchoHandler)
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        server = FixtureServer("127.0.0.1", 0, "fixture-token", forward_host="127.0.0.1", forward_port=upstream.server_address[1])
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with socket.create_connection(server.server_address, timeout=10) as client:
                client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                client.sendall(b"\x05\x01\x00")
                self.assertEqual(b"\x05\x00", receive_exact(client, 2))
                client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + upstream.server_address[1].to_bytes(2, "big"))
                self.assertEqual(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00", receive_exact(client, 10))
                self.assertEqual(ready, receive_exact(client, len(ready)))
                client.sendall(payload)
                client.shutdown(socket.SHUT_WR)
                self.assertEqual(payload, receive_until_close(client))
        finally:
            stop_fixture(server, thread)
            upstream.shutdown()
            upstream.server_close()
            upstream_thread.join(timeout=3)

    def test_fixture_propagates_upstream_eof_after_its_response_has_already_drained(self) -> None:
        response = b"upstream-response"
        release_eof = threading.Event()

        class ResponseThenEofHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                self.request.sendall(response)
                if not release_eof.wait(3):
                    raise AssertionError("test did not release the upstream EOF")
                self.request.shutdown(socket.SHUT_WR)

        upstream = socketserver.ThreadingTCPServer(("127.0.0.1", 0), ResponseThenEofHandler)
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        server = FixtureServer("127.0.0.1", 0, "fixture-token", forward_host="127.0.0.1", forward_port=upstream.server_address[1])
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with socket.create_connection(server.server_address, timeout=3) as client:
                client.sendall(b"\x05\x01\x00")
                self.assertEqual(b"\x05\x00", receive_exact(client, 2))
                client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + upstream.server_address[1].to_bytes(2, "big"))
                self.assertEqual(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00", receive_exact(client, 10))
                self.assertEqual(response, receive_exact(client, len(response)))
                release_eof.set()
                client.settimeout(0.5)
                self.assertEqual(b"", client.recv(1), "upstream EOF must promptly half-close the client")
        finally:
            stop_fixture(server, thread)
            upstream.shutdown()
            upstream.server_close()
            upstream_thread.join(timeout=3)

    def test_fixture_bounds_pending_bytes_when_the_upstream_stalls_then_completes(self) -> None:
        release_read = threading.Event()
        received = bytearray()
        received_complete = threading.Event()
        payload = b"\x16\x03\x03" + b"x" * (8 * RELAY_MAX_PENDING_BYTES)

        class StalledUpstreamHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                if not release_read.wait(3):
                    raise AssertionError("test did not release the stalled upstream")
                while True:
                    chunk = self.request.recv(65_536)
                    if not chunk:
                        received_complete.set()
                        return
                    received.extend(chunk)

        upstream = socketserver.ThreadingTCPServer(("127.0.0.1", 0), StalledUpstreamHandler)
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        server = FixtureServer("127.0.0.1", 0, "fixture-token", forward_host="127.0.0.1", forward_port=upstream.server_address[1])
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        sender_errors: list[BaseException] = []
        try:
            with socket.create_connection(server.server_address, timeout=3) as client:
                client.sendall(b"\x05\x01\x00")
                self.assertEqual(b"\x05\x00", receive_exact(client, 2))
                client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + upstream.server_address[1].to_bytes(2, "big"))
                self.assertEqual(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00", receive_exact(client, 10))

                def send_payload() -> None:
                    try:
                        client.sendall(payload)
                    except BaseException as error:
                        sender_errors.append(error)

                sender = threading.Thread(target=send_payload, daemon=True)
                sender.start()
                deadline = time.monotonic() + 3
                while server.maximum_relay_pending_bytes < RELAY_MAX_PENDING_BYTES and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertLessEqual(server.maximum_relay_pending_bytes, RELAY_MAX_PENDING_BYTES)
                self.assertEqual(RELAY_MAX_PENDING_BYTES, server.maximum_relay_pending_bytes)
                release_read.set()
                sender.join(timeout=5)
                self.assertFalse(sender.is_alive(), "bounded relay must resume the paused reader")
                self.assertEqual([], sender_errors)
                client.shutdown(socket.SHUT_WR)
                self.assertEqual(b"", receive_until_close(client))
            self.assertTrue(received_complete.wait(3))
            self.assertEqual(payload, bytes(received))
        finally:
            release_read.set()
            stop_fixture(server, thread)
            upstream.shutdown()
            upstream.server_close()
            upstream_thread.join(timeout=3)

    def test_forward_connect_failure_closes_the_unconnected_upstream_socket(self) -> None:
        client, request = socket.socketpair()
        handler = SocksHttpFixtureHandler.__new__(SocksHttpFixtureHandler)
        handler.request = request
        upstream = mock.Mock()
        upstream.connect.side_effect = OSError("fixture connect failure")
        try:
            with mock.patch.object(SocksHttpFixtureHandler, "_owned_loopback_address", return_value=(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 1))), \
                    mock.patch("integration.socks_http_fixture.socket.socket", return_value=upstream):
                handler._forward_to_owned_destination("127.0.0.1", 1)
            self.assertEqual(b"\x05\x05\x00\x01" + b"\x00" * 6, receive_exact(client, 10))
            upstream.close.assert_called_once_with()
        finally:
            client.close()
            request.close()

    def test_fixture_records_partial_greeting_without_authentication_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            transcript = Path(directory) / "greetings.ndjson"
            server, thread = start_fixture(transcript)
            try:
                with socket.create_connection(server.server_address, timeout=3) as client:
                    client.sendall(b"\x05")
                    client.shutdown(socket.SHUT_WR)
                    receive_until_close(client)
                self.assertEqual([{"event": "greeting", "first_read_bytes": 1}], read_transcript(transcript))
            finally:
                stop_fixture(server, thread)

    def test_fixture_rejects_auth_only_greeting_when_authentication_is_not_configured(self) -> None:
        server = FixtureServer("127.0.0.1", 0, "fixture-token")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with socket.create_connection(server.server_address, timeout=3) as client:
                client.sendall(b"\x05\x01\x02")
                self.assertEqual(b"\x05\xff", receive_exact(client, 2))
        finally:
            stop_fixture(server, thread)

    def test_fixture_authenticates_configured_username_password_without_recording_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            transcript = Path(directory) / "greetings.ndjson"
            server = FixtureServer("127.0.0.1", 0, "fixture-token", transcript, "fixture-user", "fixture-pass")
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with socket.create_connection(server.server_address, timeout=3) as client:
                    client.sendall(b"\x05\x01\x02")
                    self.assertEqual(b"\x05\x02", receive_exact(client, 2))
                    client.sendall(b"\x01\x0cfixture-user\x0cfixture-pass")
                    self.assertEqual(b"\x01\x00", receive_exact(client, 2))
                    client.sendall(b"\x05\x01\x00\x01\xc6\x12\x00\x01\x00\x50")
                    self.assertEqual(b"\x05\x00", receive_exact(client, 2))
                    receive_exact(client, 8)
                self.assertEqual(
                    [
                        {"event": "greeting", "first_read_bytes": 2},
                        {"event": "methods", "offered": [2]},
                        {"event": "auth", "accepted": True},
                        {"event": "connect", "reached": True},
                        {"event": "tunnel_payload", "kind": "eof"},
                    ],
                    read_transcript(transcript, minimum_events=5),
                )
            finally:
                stop_fixture(server, thread)

    def test_fixture_rejects_wrong_configured_credentials_without_recording_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            transcript = Path(directory) / "greetings.ndjson"
            server = FixtureServer("127.0.0.1", 0, "fixture-token", transcript, "fixture-user", "fixture-pass")
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with socket.create_connection(server.server_address, timeout=3) as client:
                    client.sendall(b"\x05\x01\x02")
                    self.assertEqual(b"\x05\x02", receive_exact(client, 2))
                    client.sendall(b"\x01\x0cfixture-user\x0awrong-pass")
                    self.assertEqual(b"\x01\x01", receive_exact(client, 2))
                self.assertEqual(
                    [
                        {"event": "greeting", "first_read_bytes": 2},
                        {"event": "methods", "offered": [2]},
                        {"event": "auth", "accepted": False},
                    ],
                    read_transcript(transcript, minimum_events=3),
                )
            finally:
                stop_fixture(server, thread)


def receive_exact(connection: socket.socket, size: int) -> bytes:
    received = bytearray()
    while len(received) < size:
        chunk = connection.recv(size - len(received))
        if not chunk:
            raise ConnectionError("SOCKS peer closed before the expected response")
        received.extend(chunk)
    return bytes(received)


def receive_until_close(connection: socket.socket) -> bytes:
    received = bytearray()
    while True:
        chunk = connection.recv(4096)
        if not chunk:
            return bytes(received)
        received.extend(chunk)


def start_fixture(transcript: Path) -> tuple[FixtureServer, threading.Thread]:
    server = FixtureServer("127.0.0.1", 0, "fixture-token", transcript)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def stop_fixture(server: FixtureServer, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=3)


def read_transcript(transcript: Path, minimum_events: int = 1) -> list[dict[str, object]]:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if transcript.exists():
            events = [json.loads(line) for line in transcript.read_text(encoding="utf-8").splitlines()]
            if len(events) >= minimum_events:
                return events
        time.sleep(0.01)
    return [json.loads(line) for line in transcript.read_text(encoding="utf-8").splitlines()]


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3

from __future__ import annotations

import json
import socket
import re
import shlex
import tempfile
import threading
import time
import unittest
from pathlib import Path

from integration.socks_http_fixture import FixtureServer


REPOSITORY = Path(__file__).resolve().parents[1]


class SocksHttpFixtureTest(unittest.TestCase):
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

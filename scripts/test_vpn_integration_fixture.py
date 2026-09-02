#!/usr/bin/env python3

from __future__ import annotations

import socket
import threading
import unittest

from integration.socks_http_fixture import FixtureServer


class SocksHttpFixtureTest(unittest.TestCase):
    def test_fixture_completes_socks_handshake_and_returns_token(self) -> None:
        server = FixtureServer("127.0.0.1", 0, "fixture-token")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
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
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


def receive_exact(connection: socket.socket, size: int) -> bytes:
    received = bytearray()
    while len(received) < size:
        received.extend(connection.recv(size - len(received)))
    return bytes(received)


def receive_until_close(connection: socket.socket) -> bytes:
    received = bytearray()
    while True:
        chunk = connection.recv(4096)
        if not chunk:
            return bytes(received)
        received.extend(chunk)


if __name__ == "__main__":
    unittest.main()

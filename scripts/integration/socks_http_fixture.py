#!/usr/bin/env python3
"""Local SOCKS5 fixture that returns a fixed HTTP response without direct egress."""

from __future__ import annotations

import argparse
import socket
import socketserver
from pathlib import Path


class SocksHttpFixtureHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        connection = self.request
        connection.settimeout(10)
        version, methods = self._read_exact(2)
        if version != 5:
            raise ValueError(f"unsupported SOCKS version: {version}")
        self._read_exact(methods)
        connection.sendall(b"\x05\x00")

        version, command, _reserved, address_type = self._read_exact(4)
        if version != 5 or command != 1:
            connection.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return
        self._read_destination(address_type)
        connection.sendall(b"\x05\x00\x00\x01" + b"\x7f\x00\x00\x01\x00\x00")

        request = bytearray()
        while b"\r\n\r\n" not in request and len(request) < 65_536:
            chunk = connection.recv(4096)
            if not chunk:
                break
            request.extend(chunk)
        token = self.server.response_token.encode("utf-8")  # type: ignore[attr-defined]
        response = (
            b"HTTP/1.1 200 OK\r\n"
            + f"Content-Length: {len(token)}\r\n".encode("ascii")
            + b"Content-Type: text/plain\r\nConnection: close\r\n\r\n"
            + token
        )
        connection.sendall(response)

    def _read_destination(self, address_type: int) -> None:
        if address_type == 1:
            self._read_exact(4)
        elif address_type == 3:
            self._read_exact(self._read_exact(1)[0])
        elif address_type == 4:
            self._read_exact(16)
        else:
            raise ValueError(f"unsupported SOCKS address type: {address_type}")
        self._read_exact(2)

    def _read_exact(self, size: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < size:
            chunk = self.request.recv(size - len(chunks))
            if not chunk:
                raise ConnectionError("SOCKS client closed the fixture connection")
            chunks.extend(chunk)
        return bytes(chunks)


class FixtureServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, host: str, port: int, response_token: str) -> None:
        self.response_token = response_token
        super().__init__((host, port), SocksHttpFixtureHandler)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--token", required=True)
    parser.add_argument("--ready-file", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    with FixtureServer("127.0.0.1", args.port, args.token) as server:
        args.ready_file.write_text(f"{server.server_address[1]}\n", encoding="utf-8")
        server.serve_forever(poll_interval=0.1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

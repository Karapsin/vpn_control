#!/usr/bin/env python3
"""Local SOCKS5 fixture that returns a fixed HTTP response without direct egress."""

from __future__ import annotations

import argparse
import ipaddress
import json
import select
import socket
import socketserver
import threading
from pathlib import Path


RELAY_MAX_PENDING_BYTES = 1024 * 1024


class SocksHttpFixtureHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        connection = self.request
        connection.settimeout(10)
        greeting = bytearray(connection.recv(2))
        self.server.record_greeting_first_read(len(greeting))  # type: ignore[attr-defined]
        if not greeting:
            return
        if len(greeting) < 2:
            try:
                greeting.extend(self._read_exact(2 - len(greeting)))
            except ConnectionError:
                return
        version, methods = greeting
        if version != 5:
            raise ValueError(f"unsupported SOCKS version: {version}")
        offered_methods = self._read_exact(methods)
        self.server.record_offered_methods(offered_methods)  # type: ignore[attr-defined]
        selected_method = self.server.select_authentication_method(offered_methods)  # type: ignore[attr-defined]
        connection.sendall(bytes((5, selected_method)))
        if selected_method == 255:
            return
        if selected_method == 2 and not self._authenticate_username_password():
            return

        version, command, _reserved, address_type = self._read_exact(4)
        if version != 5 or command != 1:
            connection.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return
        destination_host, destination_port = self._read_destination(address_type)
        if self.server.should_forward(destination_host, destination_port):  # type: ignore[attr-defined]
            self._forward_to_owned_destination(destination_host, destination_port)
            return
        if self.server.has_forwarding:  # type: ignore[attr-defined]
            connection.sendall(b"\x05\x02\x00\x01" + b"\x00" * 6)
            return
        self.server.record_connect_reached()  # type: ignore[attr-defined]
        connection.sendall(b"\x05\x00\x00\x01" + b"\x7f\x00\x00\x01\x00\x00")

        request = bytearray()
        recorded_payload_kind = False
        while b"\r\n\r\n" not in request and len(request) < 65_536:
            chunk = connection.recv(4096)
            if not chunk:
                if not recorded_payload_kind:
                    self.server.record_tunnel_payload_kind("eof")  # type: ignore[attr-defined]
                break
            if not recorded_payload_kind:
                self.server.record_tunnel_payload_kind(self._tunnel_payload_kind(chunk))  # type: ignore[attr-defined]
                recorded_payload_kind = True
            request.extend(chunk)
        token = self.server.response_token.encode("utf-8")  # type: ignore[attr-defined]
        response = (
            b"HTTP/1.1 200 OK\r\n"
            + f"Content-Length: {len(token)}\r\n".encode("ascii")
            + b"Content-Type: text/plain\r\nConnection: close\r\n\r\n"
            + token
        )
        connection.sendall(response)

    def _authenticate_username_password(self) -> bool:
        version, username_size = self._read_exact(2)
        if version != 1:
            return False
        username = self._read_exact(username_size)
        password = self._read_exact(self._read_exact(1)[0])
        accepted = self.server.accepts_username_password(username, password)  # type: ignore[attr-defined]
        self.server.record_authentication_result(accepted)  # type: ignore[attr-defined]
        self.request.sendall(bytes((1, 0 if accepted else 1)))
        return accepted

    @staticmethod
    def _tunnel_payload_kind(payload: bytes) -> str:
        if payload[:2] == b"\x16\x03" or payload[:1] == b"\x80":
            return "tls"
        if payload.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ")):
            return "http"
        return "other"

    def _forward_to_owned_destination(self, host: str, port: int) -> None:
        upstream: socket.socket | None = None
        try:
            family, socket_type, protocol, _canonical_name, address = self._owned_loopback_address(host, port)
            upstream = socket.socket(family, socket_type, protocol)
            upstream.settimeout(10)
            upstream.connect(address)
        except OSError:
            if upstream is not None:
                upstream.close()
            self.request.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
            return
        with upstream:
            self.server.record_connect_reached()  # type: ignore[attr-defined]
            self.request.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            self._relay(upstream)

    @staticmethod
    def _owned_loopback_address(host: str, port: int) -> tuple[int, int, int, str, tuple[object, ...]]:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(item[4][0]).is_loopback for item in addresses):
            raise OSError("forwarding destination is not loopback")
        # Match the HTTPS fixture listener when localhost resolves to both
        # families; explicit IPv6-only loopback destinations remain supported.
        return next((item for item in addresses if item[0] == socket.AF_INET), addresses[0])

    def _relay(self, upstream: socket.socket) -> None:
        peers = (self.request, upstream)
        for peer in peers:
            peer.setblocking(False)
        readable_peers = set(peers)
        pending = {peer: bytearray() for peer in peers}
        close_after_flush: set[socket.socket] = set()
        while readable_peers or any(pending.values()):
            writable_peers = tuple(peer for peer, buffered in pending.items() if buffered)
            readable_candidates = tuple(
                source for source in readable_peers
                if len(pending[upstream if source is self.request else self.request]) < RELAY_MAX_PENDING_BYTES
            )
            readable, writable, _ = select.select(readable_candidates, writable_peers, (), 10)
            if not readable and not writable:
                return
            for source in readable:
                destination = upstream if source is self.request else self.request
                try:
                    payload = source.recv(min(65_536, RELAY_MAX_PENDING_BYTES - len(pending[destination])))
                except BlockingIOError:
                    continue
                if not payload:
                    readable_peers.discard(source)
                    close_after_flush.add(destination)
                    if not pending[destination]:
                        try:
                            destination.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        close_after_flush.discard(destination)
                    continue
                self.server.record_tunnel_payload_kind(self._tunnel_payload_kind(payload))  # type: ignore[attr-defined]
                pending[destination].extend(payload)
                self.server.record_relay_pending(len(pending[destination]))  # type: ignore[attr-defined]
            for destination in writable:
                try:
                    sent = destination.send(pending[destination])
                except BlockingIOError:
                    continue
                if sent:
                    del pending[destination][:sent]
                if not pending[destination] and destination in close_after_flush:
                    try:
                        destination.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    close_after_flush.discard(destination)

    def _read_destination(self, address_type: int) -> tuple[str, int]:
        if address_type == 1:
            host = socket.inet_ntoa(self._read_exact(4))
        elif address_type == 3:
            host = self._read_exact(self._read_exact(1)[0]).decode("ascii")
        elif address_type == 4:
            host = socket.inet_ntop(socket.AF_INET6, self._read_exact(16))
        else:
            raise ValueError(f"unsupported SOCKS address type: {address_type}")
        return host, int.from_bytes(self._read_exact(2), "big")

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

    def __init__(
        self,
        host: str,
        port: int,
        response_token: str,
        transcript_file: Path | None = None,
        username: str | None = None,
        password: str | None = None,
        forward_host: str | None = None,
        forward_port: int | None = None,
    ) -> None:
        if (username is None) != (password is None):
            raise ValueError("SOCKS fixture authentication requires both username and password")
        if username == "" or password == "":
            raise ValueError("SOCKS fixture authentication values must not be empty")
        if (forward_host is None) != (forward_port is None):
            raise ValueError("SOCKS forwarding requires both host and port")
        if forward_host is not None and forward_host not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("SOCKS forwarding is limited to loopback destinations")
        if forward_port is not None and not 1 <= forward_port <= 65_535:
            raise ValueError("SOCKS forwarding requires a valid destination port")
        self.response_token = response_token
        self.transcript_file = transcript_file
        self._username = username.encode("utf-8") if username is not None else None
        self._password = password.encode("utf-8") if password is not None else None
        self._forward_host = forward_host
        self._forward_port = forward_port
        self._transcript_lock = threading.Lock()
        self.maximum_relay_pending_bytes = 0
        super().__init__((host, port), SocksHttpFixtureHandler)

    @property
    def has_forwarding(self) -> bool:
        return self._forward_host is not None

    def should_forward(self, host: str, port: int) -> bool:
        if not self.has_forwarding:
            return False
        return host == self._forward_host and port == self._forward_port

    def record_greeting_first_read(self, byte_count: int) -> None:
        self._record_transcript({"event": "greeting", "first_read_bytes": byte_count})

    def record_offered_methods(self, methods: bytes) -> None:
        self._record_transcript({"event": "methods", "offered": list(methods)})

    def select_authentication_method(self, offered_methods: bytes) -> int:
        if self._username is None:
            return 0 if 0 in offered_methods else 255
        return 2 if 2 in offered_methods else 255

    def accepts_username_password(self, username: bytes, password: bytes) -> bool:
        return username == self._username and password == self._password

    def record_authentication_result(self, accepted: bool) -> None:
        self._record_transcript({"event": "auth", "accepted": accepted})

    def record_connect_reached(self) -> None:
        self._record_transcript({"event": "connect", "reached": True})

    def record_tunnel_payload_kind(self, kind: str) -> None:
        self._record_transcript({"event": "tunnel_payload", "kind": kind})

    def record_relay_pending(self, byte_count: int) -> None:
        with self._transcript_lock:
            self.maximum_relay_pending_bytes = max(self.maximum_relay_pending_bytes, byte_count)

    def _record_transcript(self, event: dict[str, object]) -> None:
        if self.transcript_file is None:
            return
        with self._transcript_lock:
            with self.transcript_file.open("a", encoding="utf-8") as output:
                output.write(json.dumps(event, separators=(",", ":")) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--token", required=True)
    parser.add_argument("--ready-file", type=Path, required=True)
    parser.add_argument("--transcript-file", type=Path)
    parser.add_argument("--username-file", type=Path)
    parser.add_argument("--password-file", type=Path)
    parser.add_argument("--forward-host")
    parser.add_argument("--forward-port", type=int)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if (args.username_file is None) != (args.password_file is None):
        raise SystemExit("--username-file and --password-file must be provided together")
    username = args.username_file.read_text(encoding="utf-8").rstrip("\r\n") if args.username_file else None
    password = args.password_file.read_text(encoding="utf-8").rstrip("\r\n") if args.password_file else None
    with FixtureServer(
        "127.0.0.1", args.port, args.token, args.transcript_file, username, password,
        args.forward_host, args.forward_port,
    ) as server:
        args.ready_file.write_text(f"{server.server_address[1]}\n", encoding="utf-8")
        server.serve_forever(poll_interval=0.1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

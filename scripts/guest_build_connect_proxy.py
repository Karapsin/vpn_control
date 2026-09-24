#!/usr/bin/env python3
"""Task-scoped, raw HTTP CONNECT relay for one admitted guest build.

The relay has no TLS server role: after CONNECT admission it only copies bytes.
It is deliberately limited to the three Gradle repositories declared by this
project and one exact guest peer.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import selectors
import socket
import socketserver
import ssl
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable

DEFAULT_DESTINATIONS = frozenset({
    "dl.google.com:443",
    "plugins.gradle.org:443",
    "repo.maven.apache.org:443",
})
POM_URL = "https://dl.google.com/dl/android/maven2/com/android/tools/build/gradle/8.7.3/gradle-8.7.3.pom"
MAX_HEADER_BYTES = 8192
MAX_CONNECTIONS = 32
MAX_TUNNEL_BUFFER_BYTES = 256 * 1024
IDLE_SECONDS = 15.0
CONNECT_SECONDS = 10.0


class RelayError(ValueError):
    pass


class TunnelError(RelayError):
    def __init__(self, bytes_to_upstream: int, bytes_to_client: int):
        super().__init__("opaque tunnel failed")
        self.bytes_to_upstream = bytes_to_upstream
        self.bytes_to_client = bytes_to_client


class ProbeError(RuntimeError):
    pass


def atomic_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("x", encoding="utf-8") as output:
        json.dump(value, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
    temporary.replace(path)


def private_unicast(value: str, *, label: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise RelayError(f"{label} must be an IP address") from error
    if (address.version != 4 or not address.is_private or address.is_loopback or address.is_unspecified or
            address.is_multicast or address.is_link_local):
        raise RelayError(f"{label} must be a private non-loopback unicast address")
    return str(address)


def parse_connect_header(connection: socket.socket) -> tuple[str, bytes]:
    data = bytearray()
    while True:
        marker = data.find(b"\r\n\r\n")
        if marker >= 0:
            if marker + 4 > MAX_HEADER_BYTES:
                raise RelayError("CONNECT header exceeds limit")
            header, initial_tunnel_bytes = bytes(data[:marker + 4]), bytes(data[marker + 4:])
            break
        if len(data) >= MAX_HEADER_BYTES:
            raise RelayError("CONNECT header exceeds limit")
        chunk = connection.recv(min(1024, MAX_HEADER_BYTES - len(data)))
        if not chunk:
            raise RelayError("CONNECT header ended early")
        data.extend(chunk)
    try:
        lines = header.decode("ascii").split("\r\n")[:-2]
        method, target, protocol = lines[0].split(" ")
    except (UnicodeDecodeError, IndexError, ValueError) as error:
        raise RelayError("CONNECT header is malformed") from error
    hosts = [line.split(":", 1)[1].strip().lower() for line in lines[1:]
             if line.lower().startswith("host:") and ":" in line]
    normalized = target.lower()
    expected_host = normalized.rsplit(":", 1)[0] if normalized.endswith(":443") else normalized
    valid_host_value = lambda host: host == normalized or host == expected_host
    valid_host = ((len(hosts) <= 1 and (not hosts or valid_host_value(hosts[0])))
                  if protocol == "HTTP/1.0" else len(hosts) == 1 and valid_host_value(hosts[0]))
    if method != "CONNECT" or protocol not in ("HTTP/1.0", "HTTP/1.1") or not valid_host:
        raise RelayError("CONNECT method or Host is invalid")
    return normalized, initial_tunnel_bytes


def send_rejection(connection: socket.socket) -> None:
    try:
        connection.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    except OSError:
        pass


def send_capacity_rejection(connection: socket.socket) -> None:
    try:
        connection.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        # Windows can abort a peer that is waiting for this response when close()
        # discards its already-queued CONNECT request.  Half-close the response
        # direction and discard currently pending input before releasing the socket.
        connection.shutdown(socket.SHUT_WR)
        connection.setblocking(False)
        remaining = MAX_HEADER_BYTES
        while remaining:
            try:
                chunk = connection.recv(min(65536, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
            except (BlockingIOError, InterruptedError):
                break
    except OSError:
        pass
    finally:
        connection.close()


def relay_opaque(client: socket.socket, upstream: socket.socket, initial_client_bytes: bytes = b"",
                 idle_seconds: float = IDLE_SECONDS) -> tuple[int, int]:
    """Copy bytes in both directions without parsing or terminating TLS."""
    transferred_to_upstream = 0
    transferred_to_client = 0
    selector: selectors.BaseSelector | None = None
    try:
        selector = selectors.DefaultSelector()
        for value in (client, upstream):
            value.setblocking(False)
        to_upstream = bytearray(initial_client_bytes)
        to_client = bytearray()
        client_open = True
        upstream_open = True
        upstream_write_closed = False
        client_write_closed = False

        def update_interest() -> None:
            desired = {
                client: ((selectors.EVENT_READ if client_open and len(to_upstream) < MAX_TUNNEL_BUFFER_BYTES else 0) |
                         (selectors.EVENT_WRITE if to_client else 0)),
                upstream: ((selectors.EVENT_READ if upstream_open and len(to_client) < MAX_TUNNEL_BUFFER_BYTES else 0) |
                           (selectors.EVENT_WRITE if to_upstream else 0)),
            }
            registered = selector.get_map()
            for value, events in desired.items():
                if events:
                    if value in registered:
                        selector.modify(value, events)
                    else:
                        selector.register(value, events)
                elif value in registered:
                    selector.unregister(value)

        def close_drained_writes() -> None:
            nonlocal upstream_write_closed, client_write_closed
            if not client_open and not to_upstream and not upstream_write_closed:
                upstream.shutdown(socket.SHUT_WR)
                upstream_write_closed = True
            if not upstream_open and not to_client and not client_write_closed:
                client.shutdown(socket.SHUT_WR)
                client_write_closed = True

        while True:
            close_drained_writes()
            if not client_open and not upstream_open and not to_upstream and not to_client:
                return transferred_to_upstream, transferred_to_client
            update_interest()
            events = selector.select(idle_seconds)
            if not events:
                raise RelayError("tunnel idle timeout")
            for key, ready in events:
                source = key.fileobj
                if ready & selectors.EVENT_READ:
                    try:
                        pending = to_upstream if source is client else to_client
                        chunk = source.recv(min(65536, MAX_TUNNEL_BUFFER_BYTES - len(pending)))
                    except BlockingIOError:
                        chunk = None
                    if chunk == b"":
                        if source is client:
                            client_open = False
                        else:
                            upstream_open = False
                    elif chunk:
                        (to_upstream if source is client else to_client).extend(chunk)
                if ready & selectors.EVENT_WRITE:
                    pending = to_client if source is client else to_upstream
                    try:
                        sent = source.send(pending)
                    except BlockingIOError:
                        continue
                    del pending[:sent]
                    if source is upstream:
                        transferred_to_upstream += sent
                    else:
                        transferred_to_client += sent
    except (OSError, RelayError) as error:
        raise TunnelError(transferred_to_upstream, transferred_to_client) from error
    finally:
        if selector is not None:
            selector.close()


def default_upstream(destination: str) -> socket.socket:
    host, port = destination.rsplit(":", 1)
    return socket.create_connection((host, int(port)), timeout=CONNECT_SECONDS)


def handle_connection(connection: socket.socket, peer: tuple[str, int], expected_peer: str,
                      emit: Callable[[dict[str, object]], None],
                      upstream_factory: Callable[[str], socket.socket] = default_upstream) -> None:
    """Enforce peer and destination admission before copying opaque tunnel bytes."""
    connection.settimeout(IDLE_SECONDS)
    established = False
    try:
        if peer[0] != expected_peer:
            emit({"event": "rejected", "stage": "peer"})
            send_rejection(connection)
            return
        destination, initial_tunnel_bytes = parse_connect_header(connection)
        if destination not in DEFAULT_DESTINATIONS:
            emit({"event": "rejected", "stage": "destination"})
            send_rejection(connection)
            return
        try:
            upstream = upstream_factory(destination)
        except OSError:
            emit({"event": "upstream_failed", "destination": destination})
            send_rejection(connection)
            return
        with upstream:
            connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            established = True
            sent, received = relay_opaque(connection, upstream, initial_tunnel_bytes)
            emit({"event": "closed", "destination": destination,
                  "bytesToUpstream": sent, "bytesToClient": received})
    except TunnelError as error:
        emit({"event": "tunnel_error", "destination": destination,
              "bytesToUpstream": error.bytes_to_upstream,
              "bytesToClient": error.bytes_to_client})
    except (OSError, RelayError):
        emit({"event": "rejected", "stage": "header-or-tunnel"})
        if not established:
            send_rejection(connection)
    finally:
        connection.close()


class BoundedConnectServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = False
    daemon_threads = True

    def __init__(self, bind_address: str, guest_peer: str, emit: Callable[[dict[str, object]], None],
                 upstream_factory: Callable[[str], socket.socket] = default_upstream):
        self.guest_peer = guest_peer
        self.emit = emit
        self.upstream_factory = upstream_factory
        self._permits = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__((bind_address, 0), _Handler)

    def process_request(self, request, client_address):  # type: ignore[no-untyped-def]
        if not self._permits.acquire(blocking=False):
            self.emit({"event": "rejected", "stage": "concurrency"})
            send_capacity_rejection(request)
            return
        thread = threading.Thread(target=self._process_with_permit, args=(request, client_address), daemon=True)
        thread.start()

    def _process_with_permit(self, request, client_address):  # type: ignore[no-untyped-def]
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._permits.release()


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: BoundedConnectServer = self.server  # type: ignore[assignment]
        handle_connection(self.request, self.client_address, server.guest_peer, server.emit,
                          server.upstream_factory)


def proxy_url(host: str, port: int) -> str:
    return f"http://[{host}]:{port}" if ":" in host else f"http://{host}:{port}"


def probe_pom(proxy_host: str, proxy_port: int, *, timeout: float = CONNECT_SECONDS,
              opener: Callable[..., object] | None = None) -> int:
    """Fetch the fixed AGP POM through the relay using normal certificate validation."""
    private_unicast(proxy_host, label="proxy host")
    if not 1 <= proxy_port <= 65535 or timeout <= 0:
        raise ProbeError("proxy port and timeout must be positive")
    opener = opener or urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy_url(proxy_host, proxy_port),
                                     "https": proxy_url(proxy_host, proxy_port)}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    request = urllib.request.Request(POM_URL, method="GET")
    try:
        with opener.open(request, timeout=timeout) as response:  # type: ignore[union-attr]
            status = response.getcode()
    except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError) as error:
        raise ProbeError("POM probe did not complete") from error
    if status != 200:
        raise ProbeError("POM probe returned non-200 status")
    return status


def run_server(bind_address: str, guest_peer: str, ready_file: Path, terminal_file: Path) -> int:
    bind = private_unicast(bind_address, label="bind address")
    peer = private_unicast(guest_peer, label="guest peer")
    event_count = 0

    def emit(event: dict[str, object]) -> None:
        nonlocal event_count
        event_count += 1
        print(json.dumps(event, sort_keys=True, separators=(",", ":")), flush=True)

    with BoundedConnectServer(bind, peer, emit) as server:
        atomic_json(ready_file, {"bindAddress": bind, "guestPeer": peer,
                                 "port": server.server_address[1], "ownerPid": os.getpid(),
                                 "destinations": sorted(DEFAULT_DESTINATIONS)})
        code = 0
        try:
            server.serve_forever(poll_interval=0.2)
        except KeyboardInterrupt:
            code = 0
        finally:
            server.shutdown()
            atomic_json(terminal_file, {"exit": code, "ownerPid": os.getpid(),
                                        "eventCount": event_count})
    return code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    serve = commands.add_parser("serve")
    serve.add_argument("--bind-address", required=True)
    serve.add_argument("--guest-peer", required=True)
    serve.add_argument("--ready-file", type=Path, required=True)
    serve.add_argument("--terminal-file", type=Path, required=True)
    probe = commands.add_parser("probe-pom")
    probe.add_argument("--proxy-host", required=True)
    probe.add_argument("--proxy-port", type=int, required=True)
    probe.add_argument("--timeout-seconds", type=float, default=CONNECT_SECONDS)
    args = parser.parse_args()
    try:
        if args.action == "serve":
            return run_server(args.bind_address, args.guest_peer, args.ready_file, args.terminal_file)
        status = probe_pom(args.proxy_host, args.proxy_port, timeout=args.timeout_seconds)
        print(json.dumps({"ok": True, "status": status, "urlHost": "dl.google.com"}, separators=(",", ":")))
        return 0
    except (RelayError, ProbeError) as error:
        print(json.dumps({"ok": False, "error": type(error).__name__}, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

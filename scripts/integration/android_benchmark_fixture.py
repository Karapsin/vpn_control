#!/usr/bin/env python3
"""Persistent host-side SOCKS relay used by Android benchmark fixtures."""

from __future__ import annotations

import argparse
import json
import queue
import select
import socket
import socketserver
import subprocess
import sys
import threading
from pathlib import Path


class RelayUnavailable(RuntimeError):
    pass


STALL_TIMEOUT_SECONDS = 45


def socks5_connect_frame(host: str, port: int) -> bytes:
    """Return the no-auth SOCKS5 greeting and CONNECT request for ``host``."""
    encoded_host = host.encode("ascii")
    if not 1 <= len(encoded_host) <= 255:
        raise ValueError("SOCKS probe host must contain 1 to 255 ASCII bytes")
    if not 1 <= port <= 65535:
        raise ValueError("SOCKS probe port must be in 1..65535")
    return (
        b"\x05\x01\x00\x05\x01\x00\x03"
        + bytes((len(encoded_host),))
        + encoded_host
        + port.to_bytes(2, "big")
    )


def android_shell_socks_probe_command(
    host: str,
    relay_port: int,
    *,
    target_port: int = 443,
    keep_stdin_seconds: int = 2,
    idle_seconds: int = 3,
) -> str:
    """Build a bounded UID 2000 SOCKS probe that retains stdin for its reply.

    ``toybox nc -q`` exits after stdin EOF and can hide a valid SOCKS handshake.
    Keeping the pipe open explicitly lets the device receive both SOCKS replies.
    """
    if not 1 <= relay_port <= 65535:
        raise ValueError("SOCKS relay port must be in 1..65535")
    if keep_stdin_seconds < 1 or idle_seconds < 1:
        raise ValueError("SOCKS probe timeouts must be positive")
    octal_frame = "".join(f"\\{byte:03o}" for byte in socks5_connect_frame(host, target_port))
    return (
        f"{{ printf '{octal_frame}'; sleep {keep_stdin_seconds}; }} | "
        f"toybox nc -W {idle_seconds} -w {idle_seconds} 127.0.0.1 {relay_port}"
    )


def run_android_shell_socks_probe(
    adb: str,
    serial: str,
    host: str,
    relay_port: int,
    *,
    target_port: int = 443,
    keep_stdin_seconds: int = 2,
    idle_seconds: int = 3,
) -> subprocess.CompletedProcess[bytes]:
    """Run the retained-stdin SOCKS probe through public ADB shell transport."""
    command = android_shell_socks_probe_command(
        host,
        relay_port,
        target_port=target_port,
        keep_stdin_seconds=keep_stdin_seconds,
        idle_seconds=idle_seconds,
    )
    return subprocess.run(
        [adb, "-s", serial, "exec-out", "sh", "-c", command],
        capture_output=True,
        timeout=keep_stdin_seconds + idle_seconds + 2,
    )


class AndroidBenchmarkRelay:
    """Owns a relay process and proves it remains live before device work starts."""

    def __init__(self, port: int = 0, allowed_hosts: tuple[str, ...] = ("chatgpt.com", "1.1.1.1"),
                 ready_timeout: float = 3, command: list[str] | None = None) -> None:
        self.port = port
        self.allowed_hosts = allowed_hosts
        self.ready_timeout = ready_timeout
        self.command = command
        self.process: subprocess.Popen[str] | None = None

    def start(self) -> int:
        command = self.command or [sys.executable, str(Path(__file__).resolve()), "serve", "--port", str(self.port)]
        if self.command is None:
            command.extend(item for host in self.allowed_hosts for item in ("--allow-host", host))
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert self.process.stdout is not None
        stdout = self.process.stdout
        ready_lines: queue.Queue[str] = queue.Queue(maxsize=1)
        threading.Thread(target=lambda: ready_lines.put(stdout.readline()), daemon=True).start()
        try:
            line = ready_lines.get(timeout=self.ready_timeout).strip()
        except queue.Empty as error:
            self.stop()
            raise RelayUnavailable(f"relay did not publish a ready record within {self.ready_timeout} seconds") from error
        try:
            ready = json.loads(line)
            self.port = int(ready["port"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            self.stop()
            raise RelayUnavailable(f"relay did not publish a valid ready record: {line!r}") from error
        self.assert_live()
        return self.port

    def assert_live(self) -> None:
        if self.process is None or self.process.poll() is not None:
            raise RelayUnavailable("relay process is not alive")
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=1):
                pass
        except OSError as error:
            raise RelayUnavailable(f"relay listener is unavailable on {self.port}") from error

    def stop(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        if self.process.stdout is not None:
            self.process.stdout.close()
        if self.process.stderr is not None:
            self.process.stderr.close()
        self.process = None

    def __enter__(self) -> "AndroidBenchmarkRelay":
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()


class SocksHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            if self._exact(1) != b"\x05":
                return
            self._exact(self._exact(1)[0])
            self.request.sendall(b"\x05\x00")
            version, command, _, address_type = self._exact(4)
            if (version, command) != (5, 1):
                return
            host = self._host(address_type)
            port = int.from_bytes(self._exact(2), "big")
            if host not in self.server.allowed_hosts:
                self.request.sendall(b"\x05\x02\x00\x01" + b"\0" * 6)
                return
            if self.server.stall_after_handshake:
                self.server.record("stalled", host=host, port=port)
                self.request.sendall(b"\x05\x00\x00\x01\x7f\0\0\1\0\0")
                self.request.settimeout(STALL_TIMEOUT_SECONDS)
                while self.request.recv(65536):
                    pass
                return
            with socket.create_connection((host, port), timeout=10) as peer:
                self.server.record("connected", host=host, port=port)
                self.request.sendall(b"\x05\x00\x00\x01\x7f\0\0\1\0\0")
                self._forward(peer)
        except (ConnectionError, OSError):
            return

    def _host(self, address_type: int) -> str:
        if address_type == 1:
            return socket.inet_ntoa(self._exact(4))
        if address_type == 3:
            return self._exact(self._exact(1)[0]).decode("ascii")
        if address_type == 4:
            return socket.inet_ntop(socket.AF_INET6, self._exact(16))
        raise ConnectionError()

    def _forward(self, peer: socket.socket) -> None:
        while True:
            readable, _, _ = select.select((self.request, peer), (), (), 10)
            if not readable:
                return
            for source in readable:
                chunk = source.recv(65536)
                if not chunk:
                    return
                (peer if source is self.request else self.request).sendall(chunk)

    def _exact(self, count: int) -> bytes:
        data = b""
        while len(data) < count:
            chunk = self.request.recv(count - len(data))
            if not chunk:
                raise ConnectionError()
            data += chunk
        return data


class RelayServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def record(self, event: str, **fields: object) -> None:
        if self.events_path is not None:
            with self.events_path.open("a") as events:
                events.write(json.dumps({"event": event, **fields}) + "\n")


def serve(port: int, allowed_hosts: tuple[str, ...], events_path: Path | None, stall_after_handshake: bool,
          exit_after_ready: bool) -> int:
    with RelayServer(("127.0.0.1", port), SocksHandler) as server:
        server.allowed_hosts = set(allowed_hosts)
        server.events_path = events_path
        server.stall_after_handshake = stall_after_handshake
        print(json.dumps({"event": "ready", "port": server.server_address[1]}), flush=True)
        if exit_after_ready:
            return 0
        server.serve_forever(poll_interval=0.1)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    subcommands = parser.add_subparsers(dest="command", required=True)
    serve_parser = subcommands.add_parser("serve")
    serve_parser.add_argument("--port", type=int, required=True)
    serve_parser.add_argument("--allow-host", action="append", default=[])
    serve_parser.add_argument("--events", type=Path)
    serve_parser.add_argument("--stall-after-handshake", action="store_true")
    serve_parser.add_argument("--exit-after-ready", action="store_true")
    probe_parser = subcommands.add_parser("shell-probe")
    probe_parser.add_argument("--host", required=True)
    probe_parser.add_argument("--port", type=int, required=True, help="loopback SOCKS relay port")
    probe_parser.add_argument("--target-port", type=int, default=443, help="SOCKS CONNECT destination port")
    probe_parser.add_argument("--keep-stdin-seconds", type=int, default=2)
    probe_parser.add_argument("--idle-seconds", type=int, default=3)
    args = parser.parse_args()
    if args.command == "shell-probe":
        print(android_shell_socks_probe_command(
            args.host,
            args.port,
            target_port=args.target_port,
            keep_stdin_seconds=args.keep_stdin_seconds,
            idle_seconds=args.idle_seconds,
        ))
        return 0
    allowed_hosts = tuple(args.allow_host) or ("chatgpt.com", "1.1.1.1")
    return serve(args.port, allowed_hosts, args.events, args.stall_after_handshake, args.exit_after_ready)


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
import json
import re
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlsplit

from scripts.integration.android_benchmark_fixture import (
    AndroidBenchmarkRelay,
    RelayUnavailable,
    SocksHandler,
    android_shell_socks_probe_command,
    run_android_shell_socks_probe,
    socks5_connect_frame,
)


FIXTURE = Path(__file__).with_name("integration") / "android_benchmark_fixture.py"
ANDROID_BENCHMARK_SETTINGS = (
    Path(__file__).resolve().parents[1]
    / "shared/model/src/commonMain/kotlin/com/kardinal/vpncontrol/model/Models.kt"
)


def recv_exact(client: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = client.recv(count - len(data))
        if not chunk:
            raise ConnectionError("socket closed before full frame arrived")
        data += chunk
    return data


def android_default_benchmark_host() -> str:
    source = ANDROID_BENCHMARK_SETTINGS.read_text(encoding="utf-8")
    match = re.search(r'const val DEFAULT_TEST_URL = "([^"]+)"', source)
    if match is None:
        raise AssertionError("Android benchmark default validation URL is missing")
    host = urlsplit(match.group(1)).hostname
    if host is None:
        raise AssertionError("Android benchmark default validation URL has no host")
    return host


def relay_connect(host: str, allowed_hosts: tuple[str, ...]) -> tuple[bytes, list[tuple[str, int]]]:
    client, request = socket.socketpair()
    upstream, peer = socket.socketpair()
    client.settimeout(2)
    calls: list[tuple[str, int]] = []

    def connect(target: tuple[str, int], timeout: float) -> socket.socket:
        calls.append(target)
        return upstream

    server = SimpleNamespace(allowed_hosts=set(allowed_hosts), stall_after_handshake=False, record=lambda *_args, **_kwargs: None)
    with patch("scripts.integration.android_benchmark_fixture.socket.create_connection", side_effect=connect):
        handler = threading.Thread(target=SocksHandler, args=(request, ("fixture", 0), server), daemon=True)
        handler.start()
        try:
            client.sendall(b"\x05\x01\x00")
            if recv_exact(client, 2) != b"\x05\x00":
                raise AssertionError("relay rejected SOCKS no-authentication greeting")
            encoded_host = host.encode("ascii")
            client.sendall(b"\x05\x01\x00\x03" + bytes((len(encoded_host),)) + encoded_host + (443).to_bytes(2, "big"))
            reply = recv_exact(client, 10)
        finally:
            client.close()
            peer.close()
            handler.join(timeout=1)
            request.close()
            upstream.close()
            if handler.is_alive():
                raise AssertionError("relay handler did not stop after fixture sockets closed")
    return reply, calls


class AndroidBenchmarkFixtureTest(unittest.TestCase):
    def test_retained_stdin_socks_probe_frames_connect_without_q_early_exit(self) -> None:
        frame = socks5_connect_frame("chatgpt.com", 443)
        self.assertEqual(frame, b"\x05\x01\x00\x05\x01\x00\x03\x0bchatgpt.com\x01\xbb")

        command = android_shell_socks_probe_command("chatgpt.com", 19111)
        self.assertEqual(
            command,
            "{ printf '\\005\\001\\000\\005\\001\\000\\003\\013\\143\\150\\141\\164\\147\\160\\164"
            "\\056\\143\\157\\155\\001\\273'; sleep 2; } | toybox nc -W 3 -w 3 127.0.0.1 19111",
        )
        encoded_frame = command.split("printf '", 1)[1].split("';", 1)[0]
        decoded_frame = bytes(
            int(encoded_frame[index + 1:index + 4], 8)
            for index in range(0, len(encoded_frame), 4)
        )
        self.assertEqual(decoded_frame, socks5_connect_frame("chatgpt.com", 443))
        self.assertTrue(command.endswith("127.0.0.1 19111"))
        self.assertNotIn("-q", command)

    def test_public_adb_probe_executes_retained_stdin_command(self) -> None:
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=b"\x05\x00", stderr=b"")
        with patch("scripts.integration.android_benchmark_fixture.subprocess.run", return_value=completed) as run:
            result = run_android_shell_socks_probe("adb", "emulator-5596", "chatgpt.com", 19111)

        self.assertIs(result, completed)
        self.assertEqual(run.call_args.kwargs, {"capture_output": True, "timeout": 7})
        command = run.call_args.args[0]
        self.assertEqual(command[:5], ["adb", "-s", "emulator-5596", "exec-out", "sh"])
        self.assertIn("sleep 2", command[-1])
        self.assertNotIn("-q", command[-1])

    def test_shell_probe_cli_exposes_the_retained_stdin_builder(self) -> None:
        result = subprocess.run(
            [sys.executable, str(FIXTURE), "shell-probe", "--host", "chatgpt.com", "--port", "19111"],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(result.stdout.strip(), android_shell_socks_probe_command("chatgpt.com", 19111))

    def test_stall_keeps_authorized_socks_connection_open_after_initial_tls_bytes(self) -> None:
        client, request = socket.socketpair()
        client.settimeout(0.15)
        events: list[tuple[str, dict[str, object]]] = []
        server = SimpleNamespace(
            allowed_hosts={"chatgpt.com"},
            stall_after_handshake=True,
            record=lambda event, **fields: events.append((event, fields)),
        )
        handler = threading.Thread(target=SocksHandler, args=(request, ("fixture", 0), server), daemon=True)
        handler.start()
        try:
            client.sendall(b"\x05\x01\x00")
            self.assertEqual(recv_exact(client, 2), b"\x05\x00")
            host = b"chatgpt.com"
            client.sendall(b"\x05\x01\x00\x03" + bytes((len(host),)) + host + (443).to_bytes(2, "big"))
            self.assertEqual(recv_exact(client, 10)[:2], b"\x05\x00")
            client.sendall(b"\x16\x03\x01\x00\x01")
            self.assertTrue(handler.is_alive())
            with self.assertRaises(socket.timeout):
                client.recv(1)
            self.assertEqual(events, [("stalled", {"host": "chatgpt.com", "port": 443})])
        finally:
            client.close()
            handler.join(timeout=1)
            request.close()
        self.assertFalse(handler.is_alive(), "stalled handler did not close after peer disconnect")

    def test_default_allowlist_admits_android_benchmark_target_and_rejects_unlisted_egress(self) -> None:
        allowed_hosts = AndroidBenchmarkRelay().allowed_hosts
        benchmark_reply, benchmark_calls = relay_connect(android_default_benchmark_host(), allowed_hosts)
        self.assertEqual(b"\x05\x00", benchmark_reply[:2])
        self.assertEqual([(android_default_benchmark_host(), 443)], benchmark_calls)

        rejected_reply, rejected_calls = relay_connect("unlisted.fixture.invalid", allowed_hosts)
        self.assertEqual(b"\x05\x02", rejected_reply[:2])
        self.assertEqual([], rejected_calls)

    def test_ready_guard_rejects_parent_loss_after_ready_record(self) -> None:
        process = subprocess.Popen(
            [sys.executable, str(FIXTURE), "serve", "--port", "0", "--exit-after-ready"],
            stdout=subprocess.PIPE,
            text=True,
        )
        assert process.stdout is not None
        ready = json.loads(process.stdout.readline())
        process.wait(timeout=3)
        process.stdout.close()
        relay = AndroidBenchmarkRelay(int(ready["port"]))
        relay.process = process
        with self.assertRaises(RelayUnavailable):
            relay.assert_live()

    def test_live_guard_proves_listener_from_separate_process(self) -> None:
        with AndroidBenchmarkRelay() as relay:
            relay.assert_live()
            probe = "import socket,sys; socket.create_connection(('127.0.0.1', int(sys.argv[1])), 1).close()"
            result = subprocess.run([sys.executable, "-c", probe, str(relay.port)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            relay.assert_live()

    def test_relay_context_survives_delay_and_second_socks_exchange_then_stops(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            events = Path(temporary_directory) / "events.ndjson"
            command = [
                sys.executable,
                str(FIXTURE),
                "serve",
                "--port",
                "0",
                "--allow-host",
                "chatgpt.com",
                "--events",
                str(events),
                "--stall-after-handshake",
            ]
            relay = AndroidBenchmarkRelay(command=command)
            owned_process: subprocess.Popen[str] | None = None
            with relay:
                assert relay.process is not None
                owned_process = relay.process
                frame = socks5_connect_frame("chatgpt.com", 443)
                for _ in range(2):
                    with socket.create_connection(("127.0.0.1", relay.port), timeout=1) as client:
                        client.sendall(frame)
                        self.assertEqual(
                            recv_exact(client, 12),
                            b"\x05\x00\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00",
                        )
                    if _ == 0:
                        time.sleep(0.05)
                        relay.assert_live()
            assert owned_process is not None
            self.assertIsNotNone(owned_process.poll())
            self.assertEqual(
                [json.loads(line)["event"] for line in events.read_text(encoding="utf-8").splitlines()],
                ["stalled", "stalled"],
            )

    def test_ready_guard_rejects_process_that_stalls_before_ready(self) -> None:
        relay = AndroidBenchmarkRelay(
            ready_timeout=0.1,
            command=[sys.executable, "-c", "import time; time.sleep(60)"],
        )
        with self.assertRaisesRegex(RelayUnavailable, "within"):
            relay.start()
        self.assertIsNone(relay.process)

    def test_target_forwarding_does_not_require_socks_observed_dns(self) -> None:
        class Echo(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                self.request.sendall(recv_exact(self.request, len(payload)))

        payload = b"target-without-dns"
        with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo) as target:
            target.allow_reuse_address = True
            thread = __import__("threading").Thread(target=target.handle_request, daemon=True)
            thread.start()
            with AndroidBenchmarkRelay(allowed_hosts=("127.0.0.1",)) as relay:
                with socket.create_connection(("127.0.0.1", relay.port), timeout=1) as client:
                    client.sendall(b"\x05\x01\x00")
                    self.assertEqual(recv_exact(client, 2), b"\x05\x00")
                    request = b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + target.server_address[1].to_bytes(2, "big")
                    client.sendall(request)
                    self.assertEqual(recv_exact(client, 10)[:2], b"\x05\x00")
                    client.sendall(payload)
                    self.assertEqual(recv_exact(client, len(payload)), payload)
            thread.join(timeout=1)


if __name__ == "__main__":
    unittest.main()

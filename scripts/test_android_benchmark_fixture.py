#!/usr/bin/env python3
import json
import socket
import socketserver
import subprocess
import sys
import unittest
from pathlib import Path

from scripts.integration.android_benchmark_fixture import AndroidBenchmarkRelay, RelayUnavailable


FIXTURE = Path(__file__).with_name("integration") / "android_benchmark_fixture.py"


def recv_exact(client: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = client.recv(count - len(data))
        if not chunk:
            raise ConnectionError("socket closed before full frame arrived")
        data += chunk
    return data


class AndroidBenchmarkFixtureTest(unittest.TestCase):
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

#!/usr/bin/env python3
import socket
import http.client
import sys
import threading
import time
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import guest_build_connect_proxy as subject


SOCKET_TIMEOUT_SECONDS = 1


def recv_exact(connection, size: int) -> bytes:
    received = bytearray()
    while len(received) < size:
        chunk = connection.recv(size - len(received))
        if not chunk:
            raise AssertionError(f"socket closed after {len(received)} of {size} expected bytes")
        received.extend(chunk)
    return bytes(received)


def recv_headers(connection) -> bytes:
    received = bytearray()
    while b"\r\n\r\n" not in received:
        chunk = connection.recv(256)
        if not chunk:
            raise AssertionError("socket closed before the HTTP response headers")
        received.extend(chunk)
    return bytes(received)


class RelayTest(unittest.TestCase):
    def socket_pair_tunnel(self, request: bytes, peer="10.0.0.2"):
        client, relay_client = socket.socketpair()
        relay_upstream, upstream = socket.socketpair()
        client.settimeout(SOCKET_TIMEOUT_SECONDS)
        upstream.settimeout(SOCKET_TIMEOUT_SECONDS)
        events = []
        thread = threading.Thread(
            target=subject.handle_connection,
            args=(relay_client, (peer, 32100), "10.0.0.2", events.append, lambda _: relay_upstream),
            daemon=True,
        )
        thread.start()
        client.sendall(request)
        return client, relay_upstream, upstream, thread, events

    def test_rejects_other_peer_before_reading_a_header(self):
        class UnreadableConnection:
            def __init__(self): self.sent = bytearray(); self.closed = False
            def settimeout(self, timeout): pass
            def recv(self, size): raise AssertionError("peer rejection must precede header read")
            def sendall(self, value): self.sent.extend(value)
            def close(self): self.closed = True
        connection = UnreadableConnection()
        events = []
        subject.handle_connection(connection, ("10.0.0.3", 9), "10.0.0.2", events.append)
        self.assertEqual([{"event": "rejected", "stage": "peer"}], events)
        self.assertIn(b"403 Forbidden", connection.sent)
        self.assertTrue(connection.closed)

    def test_rejects_unlisted_destination(self):
        request = b"CONNECT example.invalid:443 HTTP/1.1\r\nHost: example.invalid:443\r\n\r\n"
        client, relay_upstream, upstream, thread, events = self.socket_pair_tunnel(request)
        try:
            self.assertIn(b"403 Forbidden", recv_headers(client))
            thread.join(1)
            self.assertFalse(thread.is_alive())
            self.assertEqual([{"event": "rejected", "stage": "destination"}], events)
        finally:
            client.close()
            relay_upstream.close()
            upstream.close()

    def test_tunnels_tls_bytes_unchanged_without_termination(self):
        request = b"CONNECT dl.google.com:443 HTTP/1.1\r\nHost: dl.google.com:443\r\n\r\n"
        client, relay_upstream, upstream, thread, events = self.socket_pair_tunnel(request)
        tls_record = b"\x16\x03\x03\x00\x04test"
        response = b"\x16\x03\x03\x00\x03ok!"
        try:
            self.assertEqual(b"HTTP/1.1 200 Connection Established\r\n\r\n",
                             recv_exact(client, len(b"HTTP/1.1 200 Connection Established\r\n\r\n")))
            client.sendall(tls_record)
            self.assertEqual(tls_record, recv_exact(upstream, len(tls_record)))
            upstream.sendall(response)
            self.assertEqual(response, recv_exact(client, len(response)))
            client.shutdown(socket.SHUT_WR)
            upstream.shutdown(socket.SHUT_WR)
            thread.join(1)
            self.assertFalse(thread.is_alive())
            self.assertEqual("closed", events[-1]["event"])
            self.assertEqual(len(tls_record), events[-1]["bytesToUpstream"])
            self.assertEqual(len(response), events[-1]["bytesToClient"])
        finally:
            client.close()
            relay_upstream.close()
            upstream.close()

    def test_accepts_stdlib_http10_tunnel_request(self):
        client, relay_client = socket.socketpair()
        relay_upstream, upstream = socket.socketpair()
        events = []
        thread = threading.Thread(
            target=subject.handle_connection,
            args=(relay_client, ("10.0.0.2", 32100), "10.0.0.2", events.append,
                  lambda _: relay_upstream),
            daemon=True,
        )
        connection = http.client.HTTPConnection("relay.invalid")
        connection.set_tunnel("dl.google.com", 443)
        connection._http_vsn = 10
        connection._http_vsn_str = "HTTP/1.0"
        connection._tunnel_headers = {}
        connection.sock = client
        client.settimeout(SOCKET_TIMEOUT_SECONDS)
        upstream.settimeout(SOCKET_TIMEOUT_SECONDS)
        thread.start()
        try:
            connection._tunnel()
            tls_record = b"\x16\x03\x03\x00\x04test"
            client.sendall(tls_record)
            self.assertEqual(tls_record, recv_exact(upstream, len(tls_record)))
        finally:
            client.close()
            upstream.close()
            thread.join(1)

    def test_preserves_tls_bytes_coalesced_with_connect_header(self):
        request = b"CONNECT dl.google.com:443 HTTP/1.1\r\nHost: dl.google.com:443\r\n\r\n"
        tls_record = b"\x16\x03\x03\x00\x04test"
        client, relay_upstream, upstream, thread, _ = self.socket_pair_tunnel(request + tls_record)
        upstream.settimeout(1)
        try:
            self.assertEqual(b"HTTP/1.1 200 Connection Established\r\n\r\n",
                             recv_exact(client, len(b"HTTP/1.1 200 Connection Established\r\n\r\n")))
            self.assertEqual(tls_record, recv_exact(upstream, len(tls_record)))
            client.shutdown(socket.SHUT_WR)
            upstream.shutdown(socket.SHUT_WR)
            thread.join(1)
            self.assertFalse(thread.is_alive())
        finally:
            client.close()
            upstream.close()

    def test_drains_large_transfer_when_upstream_reads_slowly(self):
        request = b"CONNECT dl.google.com:443 HTTP/1.1\r\nHost: dl.google.com:443\r\n\r\n"
        client, relay_upstream, upstream, thread, _ = self.socket_pair_tunnel(request)
        payload = b"x" * (512 * 1024)
        writer_errors = []

        def write_payload():
            try:
                client.sendall(payload)
                client.shutdown(socket.SHUT_WR)
            except OSError as error:
                writer_errors.append(error)

        writer = threading.Thread(target=write_payload, daemon=True)
        try:
            self.assertEqual(b"HTTP/1.1 200 Connection Established\r\n\r\n",
                             recv_exact(client, len(b"HTTP/1.1 200 Connection Established\r\n\r\n")))
            relay_upstream.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
            writer.start()
            time.sleep(0.05)
            upstream.settimeout(2)
            received = bytearray()
            while len(received) < len(payload):
                chunk = upstream.recv(65536)
                self.assertTrue(chunk, "relay closed before draining the queued transfer")
                received.extend(chunk)
            self.assertEqual(payload, bytes(received))
            writer.join(1)
            self.assertFalse(writer.is_alive())
            self.assertEqual([], writer_errors)
            upstream.shutdown(socket.SHUT_WR)
            thread.join(1)
            self.assertFalse(thread.is_alive())
        finally:
            client.close()
            upstream.close()

    def test_never_reads_beyond_remaining_tunnel_buffer_room(self):
        class RecordingSocket:
            def __init__(self, value):
                self.value = value
                self.recv_sizes = []
            def fileno(self): return self.value.fileno()
            def setblocking(self, enabled): self.value.setblocking(enabled)
            def recv(self, size):
                self.recv_sizes.append(size)
                return self.value.recv(size)
            def send(self, value): return self.value.send(value)
            def shutdown(self, how): self.value.shutdown(how)

        class GatedUpstream(RecordingSocket):
            def __init__(self, value, gate):
                super().__init__(value)
                self.gate = gate
            def send(self, value):
                if not self.gate.is_set():
                    raise BlockingIOError()
                return super().send(value)

        client, relay_client = socket.socketpair()
        relay_upstream, upstream = socket.socketpair()
        gate = threading.Event()
        relay_client = RecordingSocket(relay_client)
        relay_upstream = GatedUpstream(relay_upstream, gate)
        old_limit = subject.MAX_TUNNEL_BUFFER_BYTES
        subject.MAX_TUNNEL_BUFFER_BYTES = 8
        def relay():
            subject.relay_opaque(relay_client, relay_upstream, b"x" * 7, idle_seconds=1)
        thread = threading.Thread(target=relay, daemon=True)
        thread.start()
        try:
            client.sendall(b"ab")
            deadline = time.monotonic() + 1
            while not relay_client.recv_sizes and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual([1], relay_client.recv_sizes)
            gate.set()
            client.shutdown(socket.SHUT_WR)
            upstream.shutdown(socket.SHUT_WR)
            thread.join(1)
            self.assertFalse(thread.is_alive())
        finally:
            subject.MAX_TUNNEL_BUFFER_BYTES = old_limit
            client.close()
            upstream.close()
            relay_client.value.close()
            relay_upstream.value.close()

    def test_tunnel_failure_after_connect_does_not_append_plaintext_rejection(self):
        class FailingUpstream:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def close(self): pass
            def setblocking(self, enabled): raise OSError("synthetic tunnel failure")

        request = b"CONNECT dl.google.com:443 HTTP/1.1\r\nHost: dl.google.com:443\r\n\r\n"
        client, relay_client = socket.socketpair()
        events = []
        thread = threading.Thread(
            target=subject.handle_connection,
            args=(relay_client, ("10.0.0.2", 1), "10.0.0.2", events.append,
                  lambda _: FailingUpstream()),
            daemon=True,
        )
        thread.start()
        client.sendall(request)
        client.settimeout(1)
        try:
            self.assertEqual(b"HTTP/1.1 200 Connection Established\r\n\r\n",
                             recv_exact(client, len(b"HTTP/1.1 200 Connection Established\r\n\r\n")))
            self.assertEqual(b"", client.recv(256))
            self.assertEqual([{"event": "rejected", "stage": "header-or-tunnel"}], events)
        finally:
            client.close()
            thread.join(1)

    def test_header_limit_is_bounded(self):
        client, relay_client = socket.socketpair()
        events = []
        thread = threading.Thread(
            target=subject.handle_connection,
            args=(relay_client, ("10.0.0.2", 1), "10.0.0.2", events.append), daemon=True,
        )
        thread.start()
        try:
            client.settimeout(SOCKET_TIMEOUT_SECONDS)
            try:
                client.sendall(b"A" * (subject.MAX_HEADER_BYTES + 1))
            except BrokenPipeError:
                # The relay may reject once it has received the bounded prefix.
                pass
            self.assertIn(b"403 Forbidden", recv_headers(client))
            thread.join(1)
            self.assertFalse(thread.is_alive())
            self.assertEqual([{"event": "rejected", "stage": "header-or-tunnel"}], events)
        finally:
            client.close()


class ProbeTest(unittest.TestCase):
    def test_probe_rejects_non_200_before_build(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def getcode(self): return 503
        class Opener:
            def open(self, request, timeout):
                self.request, self.timeout = request, timeout
                return Response()
        with self.assertRaisesRegex(subject.ProbeError, "non-200"):
            subject.probe_pom("10.0.0.1", 4444, opener=Opener())

    def test_probe_rejects_timeout_before_build(self):
        class Opener:
            def open(self, request, timeout):
                raise TimeoutError("synthetic")
        with self.assertRaisesRegex(subject.ProbeError, "did not complete"):
            subject.probe_pom("10.0.0.1", 4444, opener=Opener())

    def test_probe_builds_https_handler_with_default_certificate_context(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def getcode(self): return 200
        class Opener:
            def open(self, request, timeout):
                self.request, self.timeout = request, timeout
                return Response()
        context = object()
        opener = Opener()
        with mock.patch.object(subject.ssl, "create_default_context", return_value=context) as create_context, \
             mock.patch.object(subject.urllib.request, "HTTPSHandler", return_value=object()) as https_handler, \
             mock.patch.object(subject.urllib.request, "build_opener", return_value=opener):
            self.assertEqual(200, subject.probe_pom("10.0.0.1", 4444))
        create_context.assert_called_once_with()
        https_handler.assert_called_once_with(context=context)
        self.assertEqual(subject.POM_URL, opener.request.full_url)



class AdmissionTest(unittest.TestCase):
    def test_rejects_wildcard_loopback_and_public_bind_or_peer(self):
        for value in ("0.0.0.0", "127.0.0.1", "8.8.8.8"):
            with self.subTest(value=value), self.assertRaises(subject.RelayError):
                subject.private_unicast(value, label="bind address")
        self.assertEqual("10.0.0.2", subject.private_unicast("10.0.0.2", label="guest peer"))


if __name__ == "__main__":
    unittest.main()

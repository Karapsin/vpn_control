#!/usr/bin/env python3
"""Socket-level regression for bounded read-only QGA observations."""

import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from native_fixture_qga import QgaObservationUnknown, QgaProtocolError, QgaReadOnlyClient


@unittest.skipIf(os.name == "nt", "AF_UNIX QGA transport is unavailable on Windows")
class NativeFixtureQgaTest(unittest.TestCase):
    def _listener(self, directory: str):
        path = str(Path(directory) / "qga.sock")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(path)
        listener.listen(4)
        return path, listener

    def test_old_blocking_reader_stays_live_but_bounded_client_closes_and_releases_next_client(self):
        with tempfile.TemporaryDirectory() as directory:
            path, listener = self._listener(directory)
            first_closed = threading.Event()
            next_served = threading.Event()

            def server():
                first, _ = listener.accept()
                first.recv(4096)  # QGA receives the request but deliberately never replies.
                while first.recv(4096):
                    pass
                first.close()
                first_closed.set()
                second, _ = listener.accept()
                second.recv(4096)
                while second.recv(4096):
                    pass
                second.close()
                next_served.set()
                third, _ = listener.accept()
                sync = json.loads(third.recv(4096)[1:])
                third.sendall(b"\xff" + json.dumps({"return": sync["arguments"]["id"]}).encode() + b"\n")
                third.recv(4096)
                third.sendall(b'{"return":{"exited":true}}\n')
                third.close()
                listener.close()

            thread = threading.Thread(target=server, daemon=True)
            thread.start()
            old_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            old_socket.connect(path)
            old_socket.sendall(b'{"execute":"guest-exec-status","arguments":{"pid":1}}\n')
            old_reader = old_socket.makefile("rb")
            blocked = threading.Thread(target=old_reader.readline, daemon=True)
            blocked.start()
            time.sleep(0.05)
            self.assertTrue(blocked.is_alive(), "RED: makefile.readline remains live after wrapper timeout")
            old_socket.shutdown(socket.SHUT_RDWR)
            old_socket.close()
            blocked.join(1)
            old_reader.close()
            self.assertTrue(first_closed.wait(1), "old collector cleanup should release its QGA session")

            with self.assertRaises(QgaObservationUnknown) as observed:
                QgaReadOnlyClient(path, timeout_seconds=0.08).guest_exec_status(6501856)
            self.assertEqual("guest-exec-status", observed.exception.operation["execute"])
            self.assertEqual(6501856, observed.exception.operation["arguments"]["pid"])
            self.assertTrue(next_served.wait(1), "bounded timeout must close the QGA session")
            self.assertEqual({"exited": True}, QgaReadOnlyClient(path, timeout_seconds=0.5).guest_exec_status(2))
            thread.join(1)

    def test_response_bounds_partial_json_and_qga_errors_are_rejected(self):
        cases = [(b'{"return":"' + b"x" * 200 + b'"}\n', QgaProtocolError, 128),
                 (b'{"return":', QgaObservationUnknown, 128),
                 (b'{"error":{"class":"GenericError"}}\n', QgaProtocolError, 128)]
        for response, error_type, limit in cases:
            with self.subTest(response=response):
                with tempfile.TemporaryDirectory() as directory:
                    path, listener = self._listener(directory)
                    received, thread_errors = [], []
                    def server():
                        connection = None
                        try:
                            connection, _ = listener.accept()
                            request = connection.recv(4096)
                            sync = json.loads(request[1:])
                            connection.sendall(b"\xff" + json.dumps({"return": sync["arguments"]["id"]}).encode() + b"\n")
                            received.append(json.loads(connection.recv(4096)))
                            connection.sendall(response)
                        except BrokenPipeError:
                            pass  # The bounded client is expected to close first on an invalid response.
                        except BaseException as error:
                            thread_errors.append(error)
                        finally:
                            if connection is not None:
                                connection.close()
                            listener.close()
                    thread = threading.Thread(target=server, daemon=True)
                    thread.start()
                    with self.assertRaises(error_type):
                        QgaReadOnlyClient(path, timeout_seconds=0.5, max_response_bytes=limit).guest_exec_status(7)
                    thread.join(1)
                    self.assertFalse(thread.is_alive(), "fake QGA did not finish")
                    self.assertEqual([], thread_errors)
                    self.assertEqual([{"execute": "guest-exec-status", "arguments": {"pid": 7}}], received)

    def test_read_only_file_api_and_invalid_mutation_modes(self):
        with self.assertRaises(ValueError):
            QgaReadOnlyClient("/unused").guest_file_open("C:/evidence.txt", "wb")
        with tempfile.TemporaryDirectory() as directory:
            path, listener = self._listener(directory)
            received = []
            def server():
                connection, _ = listener.accept()
                for index, value in enumerate(("handle", {"buf-b64": "YQ=="}, {})):
                    sync = connection.recv(4096)
                    sync_command = json.loads(sync[1:])
                    connection.sendall(b"\xff" + json.dumps({"return": sync_command["arguments"]["id"]}).encode() + b"\n")
                    received.append(json.loads(connection.recv(4096)))
                    connection.sendall((json.dumps({"return": value}) + "\n").encode())
                    connection.close()
                    if index < 2:
                        connection, _ = listener.accept()
                connection.close(); listener.close()
            thread = threading.Thread(target=server, daemon=True); thread.start()
            with QgaReadOnlyClient(path) as client:
                handle = client.guest_file_open("C:/evidence.txt")
                self.assertEqual({"buf-b64": "YQ=="}, client.guest_file_read(handle, 1))
                self.assertEqual({}, client.guest_file_close(handle))
            thread.join(1)
            self.assertEqual(["guest-file-open", "guest-file-read", "guest-file-close"], [item["execute"] for item in received])

    def test_context_closes_owned_handle_after_read_failure(self):
        failure = RuntimeError("read failed")
        with patch.object(QgaReadOnlyClient, "_call", side_effect=[17, failure, {}]) as call:
            with self.assertRaisesRegex(RuntimeError, "read failed"):
                with QgaReadOnlyClient("/unused") as client:
                    handle = client.guest_file_open("C:/receipt.json")
                    client.guest_file_read(handle, 1024)
            self.assertEqual("guest-file-close", call.call_args.args[0])
            self.assertEqual({"handle": 17}, call.call_args.args[1])
            self.assertEqual(3, call.call_count)

    def test_uncertain_close_is_not_replayed_and_does_not_mask_primary_failure(self):
        unknown = QgaObservationUnknown({"execute": "guest-file-close"}, "lost response")
        with patch.object(QgaReadOnlyClient, "_call", side_effect=[17, unknown]) as call:
            with self.assertRaisesRegex(RuntimeError, "primary") as raised:
                with QgaReadOnlyClient("/unused") as client:
                    client.guest_file_open("C:/receipt.json")
                    raise RuntimeError("primary")
            client.close()
            self.assertEqual(2, call.call_count)
            self.assertTrue(client.cleanup_errors)

    def test_synchronization_discards_stale_response_before_issued_status(self):
        with tempfile.TemporaryDirectory() as directory:
            path, listener = self._listener(directory)
            def server():
                connection, _ = listener.accept()
                sync = json.loads(connection.recv(4096)[1:])
                # This is a queued answer from a prior client, not our status.
                connection.sendall(b'{"return":{"exited":false}}\n')
                connection.sendall(b"\xff" + json.dumps({"return": sync["arguments"]["id"]}).encode() + b"\n")
                issued = json.loads(connection.recv(4096))
                self.assertEqual({"execute": "guest-exec-status", "arguments": {"pid": 9}}, issued)
                connection.sendall(b'{"return":{"exited":true}}\n')
                connection.close(); listener.close()
            thread = threading.Thread(target=server, daemon=True); thread.start()
            with patch("native_fixture_qga.secrets.randbits", return_value=42):
                self.assertEqual({"exited": True}, QgaReadOnlyClient(path).guest_exec_status(9))
            thread.join(1)

    def test_rejects_nonfinite_timeout_and_boolean_counts(self):
        for timeout in (float("inf"), float("nan"), True):
            with self.subTest(timeout=timeout):
                with self.assertRaises(ValueError):
                    QgaReadOnlyClient("/unused", timeout_seconds=timeout)
        with self.assertRaises(ValueError):
            QgaReadOnlyClient("/unused").guest_file_read("h", True)

    def test_fragmented_requested_response_is_reassembled_after_sync(self):
        with tempfile.TemporaryDirectory() as directory:
            path, listener = self._listener(directory)
            thread_errors = []
            def server():
                connection = None
                try:
                    connection, _ = listener.accept()
                    sync = json.loads(connection.recv(4096)[1:])
                    connection.sendall(b"\xff" + json.dumps({"return": sync["arguments"]["id"]}).encode() + b"\n")
                    self.assertEqual({"execute": "guest-exec-status", "arguments": {"pid": 3}}, json.loads(connection.recv(4096)))
                    connection.sendall(b'{"ret')
                    connection.sendall(b'urn":{"exited":true}}\n')
                except BaseException as error:
                    thread_errors.append(error)
                finally:
                    if connection is not None:
                        connection.close()
                    listener.close()
            thread = threading.Thread(target=server, daemon=True); thread.start()
            self.assertEqual({"exited": True}, QgaReadOnlyClient(path).guest_exec_status(3))
            thread.join(1)
            self.assertFalse(thread.is_alive())
            self.assertEqual([], thread_errors)


if __name__ == "__main__":
    unittest.main()

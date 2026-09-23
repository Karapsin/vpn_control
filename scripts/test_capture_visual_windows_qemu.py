#!/usr/bin/env python3
"""Regression coverage for QMP capability negotiation used by visual VM tools."""

from __future__ import annotations

import importlib.util
import json
import queue
import socket
import tempfile
import threading
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "capture_visual_windows_qemu.py"


def load_module():
    specification = importlib.util.spec_from_file_location("capture_visual_windows_qemu", MODULE_PATH)
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "requires Unix-domain sockets")
class QmpClientTest(unittest.TestCase):
    def _server(self, socket_path: Path, handler):
        failures: queue.Queue[BaseException] = queue.Queue()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(socket_path))
        listener.listen(1)
        listener.settimeout(2)

        def run() -> None:
            try:
                connection, _ = listener.accept()
                connection.settimeout(2)
                with connection, connection.makefile("rwb", buffering=0) as stream:
                    handler(stream)
            except BaseException as error:
                failures.put(error)
            finally:
                listener.close()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return thread, failures

    @staticmethod
    def _request(stream):
        line = stream.readline()
        if not line:
            raise AssertionError("client closed QMP connection")
        return json.loads(line)

    @staticmethod
    def _write(stream, message):
        stream.write(json.dumps(message).encode("utf-8") + b"\n")

    def test_negotiates_capabilities_before_key_and_ignores_events(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as directory:
            socket_path = Path(directory) / "qmp.sock"

            def handler(stream):
                self._write(stream, {"QMP": {"version": {}}})
                capabilities = self._request(stream)
                self.assertEqual({"execute": "qmp_capabilities"}, capabilities)
                self._write(stream, {"event": "STOP"})
                self._write(stream, {"return": {}})
                key = self._request(stream)
                self.assertEqual(
                    {
                        "execute": "human-monitor-command",
                        "arguments": {"command-line": "sendkey a"},
                    },
                    key,
                )
                self._write(stream, {"event": "RESUME"})
                self._write(stream, {"return": ""})

            thread, failures = self._server(socket_path, handler)
            client = module.QmpClient(socket_path)
            try:
                client.send_key("a")
            finally:
                client.close()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            if not failures.empty():
                raise failures.get_nowait()

    def test_surfaces_server_error_for_key_after_capabilities(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as directory:
            socket_path = Path(directory) / "qmp.sock"

            def handler(stream):
                self._write(stream, {"QMP": {"version": {}}})
                self.assertEqual({"execute": "qmp_capabilities"}, self._request(stream))
                self._write(stream, {"return": {}})
                key = self._request(stream)
                self.assertEqual("human-monitor-command", key["execute"])
                self._write(stream, {"error": {"class": "CommandNotFound", "desc": "rejected"}})

            thread, failures = self._server(socket_path, handler)
            client = module.QmpClient(socket_path)
            try:
                with self.assertRaisesRegex(module.CaptureError, "human-monitor-command failed"):
                    client.send_key("a")
            finally:
                client.close()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            if not failures.empty():
                raise failures.get_nowait()


if __name__ == "__main__":
    unittest.main()

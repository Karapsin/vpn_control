#!/usr/bin/env python3
"""Fast checks for strict packaged CLI output verification (not native evidence)."""
import json
import subprocess
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_packaged_cli import envelope, stream_records, verify_stream_records, interrupt_stream


class EnvelopeTest(unittest.TestCase):
    def result(self, *, code="OK", ok=True, exit_code=0, stderr="", suffix=""):
        return subprocess.CompletedProcess([], exit_code,
            json.dumps({"schemaVersion": 1, "code": code, "ok": ok}) + suffix, stderr)

    def test_success_and_action_failure_exit_codes(self):
        self.assertEqual("OK", envelope(self.result())["code"])
        failure = self.result(code="NOT_FOUND", ok=False, exit_code=1)
        self.assertEqual("NOT_FOUND", envelope(failure, 1, "NOT_FOUND")["code"])

    def test_rejects_stderr_and_exit_mismatch(self):
        for result in (self.result(stderr="launcher failed"), self.result(exit_code=1),
                       self.result(ok=False), self.result(code="NOT_FOUND")):
            with self.subTest(result=result), self.assertRaises(AssertionError):
                envelope(result)

    def test_rejects_noise_and_multiple_json_documents(self):
        for suffix in ("launcher noise", '\n{"code":"OK"}'):
            with self.subTest(suffix=suffix), self.assertRaises(json.JSONDecodeError):
                envelope(self.result(suffix=suffix))


class StreamTest(unittest.TestCase):
    def row(self, **changes):
        return dict(schemaVersion=1, code="OK", ok=True, final=False, controllerId="owner", **changes)

    def test_ndjson_preserves_unicode_and_waits_for_complete_lines(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "stream.out"
            path.write_bytes('{"message":"東京"}\n{"unfinished":'.encode("utf-8"))
            self.assertEqual([{"message": "東京"}], stream_records(path))

    def test_rejects_unbounded_noise_and_invalid_utf8(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "stream.out"
            for content, maximum, error in ((b"12345", 4, AssertionError),
                                             (b"noise\n", 20, json.JSONDecodeError),
                                             (b'"\xff"\n', 20, UnicodeDecodeError)):
                path.write_bytes(content)
                with self.subTest(content=content), self.assertRaises(error):
                    stream_records(path, maximum)

    def test_requires_live_success_from_same_owner(self):
        row = self.row()
        verify_stream_records([row], "owner")
        for changes in ({"final": True}, {"ok": False}, {"controllerId": "replacement"},
                        {"code": "CONFLICT"}, {"schemaVersion": 2}):
            with self.subTest(changes=changes), self.assertRaises(AssertionError):
                verify_stream_records([dict(row, **changes)], "owner")

    def test_posix_interrupt_checks_exit130_without_terminating_owner(self):
        process = mock.Mock()
        process.poll.return_value = None
        process.wait.return_value = 130
        with mock.patch("test_packaged_cli.os.name", "posix"):
            interrupt_stream(process)
        process.send_signal.assert_called_once()
        process.terminate.assert_not_called()
        process.wait.assert_called_once_with(timeout=10)

    def test_windows_interrupt_uses_isolated_helper_for_exact_child(self):
        process = mock.Mock(pid=321)
        process.poll.return_value = None
        process.wait.return_value = 130
        with mock.patch("test_packaged_cli.os", SimpleNamespace(name="nt")), \
                mock.patch.object(subprocess, "CREATE_NO_WINDOW", 0x08000000, create=True), \
                mock.patch("test_packaged_cli.subprocess.run", return_value=subprocess.CompletedProcess([], 0)) as run:
            interrupt_stream(process)
        arguments, options = run.call_args
        self.assertEqual(["--interrupt-test-console", "321"], arguments[0][-2:])
        self.assertEqual(0x08000000, options["creationflags"])
        self.assertEqual(subprocess.DEVNULL, options["stdin"])
        self.assertEqual(10, options["timeout"])
        process.send_signal.assert_not_called()
        process.terminate.assert_not_called()


if __name__ == "__main__":
    unittest.main()

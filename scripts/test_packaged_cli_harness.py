#!/usr/bin/env python3
"""Fast checks for strict packaged CLI output verification (not native evidence)."""
import json
import os
import subprocess
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_packaged_cli import (envelope, stream_records, verify_stream_records, interrupt_stream,
                               large_routing_fixture, verify_routing_export, implicit_owner_smoke, smoke)


class StaticLaunchFailureTest(unittest.TestCase):
    def test_help_failure_preserves_bounded_launcher_diagnostics(self):
        result = subprocess.CompletedProcess([], 137, "unexpected stdout", "launch failed " + "x" * 10000)
        with tempfile.TemporaryDirectory() as directory:
            launcher = Path(directory) / "launcher"
            launcher.touch()
            with mock.patch("test_packaged_cli.subprocess.run", return_value=result) as run:
                with self.assertRaises(AssertionError) as failure:
                    smoke(launcher, "2.1.3")
        message = str(failure.exception)
        self.assertIn("exit=137", message)
        self.assertIn("unexpected stdout", message)
        self.assertIn("launch failed", message)
        self.assertLess(len(message), 9000)
        self.assertEqual(1, run.call_count)


class ImplicitOwnerTest(unittest.TestCase):
    def test_bootstrap_is_verified_and_only_its_owner_is_quit(self):
        calls = []
        def invoke(workspace, *args):
            calls.append(args)
            data = {"runtimeRunning": False} if args[-1] == "status" else {"validation.batch-size": 9}
            return subprocess.CompletedProcess([], 0, json.dumps({"schemaVersion": 1, "code": "OK",
                "ok": True, "final": True, "controllerId": "owner", "configurationRevision": 1, "data": data}), "")
        with tempfile.TemporaryDirectory() as root:
            implicit_owner_smoke(Path(root), invoke)
        self.assertEqual(("--json", "settings", "set", "validation.batch-size", "9"), calls[0])
        self.assertEqual(("--json", "--controller-id", "owner", "quit"), calls[-1])

    def test_failed_bootstrap_still_attempts_non_starting_cleanup(self):
        calls = []
        def invoke(workspace, *args):
            calls.append(args)
            return subprocess.CompletedProcess([], 2, json.dumps({"schemaVersion": 1,
                "code": "UNAVAILABLE", "ok": False}), "")
        with tempfile.TemporaryDirectory() as root, self.assertRaises(AssertionError):
            implicit_owner_smoke(Path(root), invoke)
        self.assertEqual(("--json", "quit"), calls[-1])


class LargeTransferTest(unittest.TestCase):
    def test_real_fixture_exceeds_ten_mib_and_contains_valid_length_domains(self):
        rules, content = large_routing_fixture()
        self.assertGreater(len(content.encode("utf-8")), 10 * 1024 * 1024)
        self.assertEqual(rules, json.loads(content)["rules"])
        self.assertEqual(56000, len(rules["direct_domain_suffixes"]))
        self.assertTrue(all(len(domain) <= 253 and all(len(label) <= 63 for label in domain.split("."))
                            for domain in rules["direct_domain_suffixes"]))

    def test_export_verifier_checks_content_count_and_private_permissions(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "東京 output.json"
            rules, content = large_routing_fixture(2)
            path.write_text(content, encoding="utf-8")
            path.chmod(0o600)
            size = path.stat().st_size
            self.assertEqual(32, len(verify_routing_export(path, rules, size)))
            with self.assertRaises(AssertionError):
                verify_routing_export(path, rules, size + 1)
            with self.assertRaises(AssertionError):
                verify_routing_export(path, dict(rules, ignore_rules=True), size)
            if os.name != "nt":
                path.chmod(0o644)
                with self.assertRaises(AssertionError):
                    verify_routing_export(path, rules, size)


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

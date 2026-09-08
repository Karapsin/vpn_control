#!/usr/bin/env python3
import importlib.util
import argparse
import contextlib
import io
import shlex
from unittest import mock
import unittest
from pathlib import Path


PATH = Path(__file__).with_name("macos_fixture_frontend.py")
SPEC = importlib.util.spec_from_file_location("macos_fixture_frontend", PATH)
subject = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(subject)


class MacosFixtureFrontendTest(unittest.TestCase):
    def test_close_command_targets_only_the_explicit_positive_pid_close_button(self):
        command = subject.close_command("admin@192.168.64.3", "501", "admin", 44198)
        self.assertEqual(command[:5], ["ssh", "-o", "BatchMode=yes", "--", "admin@192.168.64.3"])
        remote = shlex.split(command[5])
        self.assertEqual(remote[:9], ["sudo", "-n", "launchctl", "asuser", "501", "sudo", "-n", "-u", "admin"])
        self.assertEqual(remote[-2:], ["--", "44198"])
        script = subject.close_script()
        self.assertIn("whose unix id is targetPid", script)
        self.assertIn('whose description is "close button"', script)
        self.assertNotIn("frontmost", script)
        self.assertNotIn("every window", script)

    def test_close_command_rejects_missing_or_nonpositive_identity(self):
        for args in [
            ("", "501", "admin", 1),
            ("-oProxyCommand=bad", "501", "admin", 1),
            ("guest", "0", "admin", 1),
            ("guest", "not-a-uid", "admin", 1),
            ("guest", "501", "", 1),
            ("guest", "501", "admin", 0),
            ("guest", "501", "admin", -1),
        ]:
            with self.assertRaises(ValueError):
                subject.close_command(*args)

    def test_pid_parser_rejects_nonpositive_values(self):
        self.assertEqual(44198, subject.positive_pid("44198"))
        for value in ("0", "-1", "pid"):
            with self.assertRaises(argparse.ArgumentTypeError):
                subject.positive_pid(value)

    def test_main_has_a_python_timeout_for_a_hung_guest_launcher(self):
        with mock.patch.object(subject.subprocess, "run", side_effect=subject.subprocess.TimeoutExpired([], 30)):
            with mock.patch("sys.argv", ["fixture", "--guest", "admin@guest", "--uid", "501", "--user", "admin", "--pid", "9"]):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    self.assertEqual(124, subject.main())
                self.assertEqual("outcome unknown; inspect guest before retry\n", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()

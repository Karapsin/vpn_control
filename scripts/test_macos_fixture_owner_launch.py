#!/usr/bin/env python3
import pathlib
import shlex
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

import macos_fixture_owner_launch as subject


class MacosFixtureOwnerLaunchTest(unittest.TestCase):
    def test_requires_the_active_console_user_and_gui_session(self):
        self.assertEqual(subject.require_aqua_session("admin", "501", "admin\n", "501\n", 0), 501)
        with self.assertRaises(ValueError):
            subject.require_aqua_session("admin", "501", "root\n", "0\n", 0)
        with self.assertRaises(ValueError):
            subject.require_aqua_session("admin", "501", "admin\n", "502\n", 0)

    def test_preflight_checks_console_identity_and_exact_gui_domain(self):
        command = subject.preflight_command("admin@192.168.64.3", "501")
        self.assertEqual(command[:5], ["ssh", "-o", "BatchMode=yes", "--", "admin@192.168.64.3"])
        self.assertIn("/usr/bin/stat -f", command[-1])
        self.assertIn("launchctl print gui/501", command[-1])

    def test_remote_posix_paths_stay_absolute_under_a_windows_host_model(self):
        with mock.patch.object(subject, "PurePosixPath", wraps=pathlib.PurePosixPath) as posix_path:
            command = subject.owner_command("admin@192.168.64.3", "501", "admin",
                                            "/Applications/fresh/vpn-control.app/Contents/MacOS/vpn-control",
                                            "/Users/admin/fresh", {})
        self.assertEqual(posix_path.call_count, 2)
        self.assertIn("/Applications/fresh", command[-1])

    def test_main_launches_only_after_exact_aqua_preflight(self):
        calls = [
            SimpleNamespace(stdout="admin\n501\n", returncode=0),
            SimpleNamespace(returncode=0),
        ]
        with mock.patch.object(subject.subprocess, "run", side_effect=calls) as run, \
             mock.patch.object(sys, "argv", ["owner", "launch", "--guest", "admin@guest", "--uid", "501", "--user", "admin", "--launcher", "/Applications/fresh/vpn-control.app/Contents/MacOS/vpn-control", "--workspace", "/Users/admin/work space", "--java-tool-options=-Dhttps.proxyPort=61234"]):
            self.assertEqual(subject.main(), 0)
        self.assertEqual(run.call_count, 2)
        parsed = shlex.split(run.call_args_list[1].args[0][-1])
        self.assertEqual(parsed, ["sudo", "-n", "launchctl", "asuser", "501", "sudo", "-n", "-u", "admin", "/usr/bin/env", "JAVA_TOOL_OPTIONS=-Dhttps.proxyPort=61234", "/Applications/fresh/vpn-control.app/Contents/MacOS/vpn-control", "--state-dir", "/Users/admin/work space", "serve"])

    def test_main_rejects_console_mismatch_before_owner_launch(self):
        with mock.patch.object(subject.subprocess, "run", return_value=SimpleNamespace(stdout="root\n0\n", returncode=0)) as run, \
             mock.patch.object(sys, "argv", ["owner", "launch", "--guest", "admin@guest", "--uid", "501", "--user", "admin", "--launcher", "/Applications/fresh/vpn-control.app/Contents/MacOS/vpn-control", "--workspace", "/Users/admin/work"]):
            with self.assertRaises(ValueError):
                subject.main()
        self.assertEqual(run.call_count, 1)

    def test_builds_explicit_aqua_asuser_owner_command(self):
        command = subject.owner_command("admin@192.168.64.3", "501", "admin",
                                        "/Applications/fresh/vpn-control.app/Contents/MacOS/vpn-control",
                                        "/Users/admin/fresh workspace", {"JAVA_TOOL_OPTIONS": "-Dhttps.proxyPort=61234"})
        self.assertEqual(command[:5], ["ssh", "-o", "BatchMode=yes", "--", "admin@192.168.64.3"])
        remote = command[-1]
        self.assertIn("sudo -n launchctl asuser 501 sudo -n -u admin", remote)
        self.assertIn("/usr/bin/env", remote)
        self.assertIn("--state-dir", remote)
        self.assertIn("fresh workspace", remote)
        self.assertNotIn("nohup", remote)

    def test_rejects_nonpositive_or_option_like_identity_fields(self):
        for args in [
            ("-guest", "501", "admin", "/Applications/a", "/Users/admin/w", {}),
            ("admin@host", "0", "admin", "/Applications/a", "/Users/admin/w", {}),
            ("admin@host", "501", "-admin", "/Applications/a", "/Users/admin/w", {}),
            ("admin@host", "501", "admin", "relative", "/Users/admin/w", {}),
        ]:
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    subject.owner_command(*args)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Fast deterministic tests for the strict jpackage launcher preflight."""
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from test_jpackage_launcher import LauncherPreflightError, require_clean_launcher, run_command, run_preflight


class JpackageLauncherHarnessTest(unittest.TestCase):
    def test_arch_launcher_child_abort_is_rejected_even_when_parent_exits_zero(self):
        legacy = subprocess.CompletedProcess(
            ["launcher-preflight"], 0, "JPACKAGE_LAUNCHER_OK\n",
            "pure virtual method called\nterminate called without an active exception\n",
        )
        with self.assertRaisesRegex(LauncherPreflightError, "empty stderr"):
            require_clean_launcher(legacy)

    def test_clean_temurin_style_result_is_accepted(self):
        require_clean_launcher(subprocess.CompletedProcess(
            ["launcher-preflight"], 0, "JPACKAGE_LAUNCHER_OK\n", ""))

    def test_bad_exit_or_output_is_rejected(self):
        for result in (
            subprocess.CompletedProcess([], 1, "JPACKAGE_LAUNCHER_OK\n", ""),
            subprocess.CompletedProcess([], 0, "other\n", ""),
        ):
            with self.subTest(result=result), self.assertRaises(LauncherPreflightError):
                require_clean_launcher(result)

    def test_process_start_error_preserves_command_context(self):
        with mock.patch("test_jpackage_launcher.subprocess.run", side_effect=FileNotFoundError("missing")):
            with self.assertRaisesRegex(LauncherPreflightError, "Cannot execute jpackage"):
                run_command(["jpackage"])

    def test_timeout_is_bounded_and_reported(self):
        with mock.patch("test_jpackage_launcher.subprocess.run", side_effect=subprocess.TimeoutExpired(["jpackage"], 60)):
            with self.assertRaisesRegex(LauncherPreflightError, "Timed out after 60s: jpackage"):
                run_command(["jpackage"])

    def test_pipeline_failure_stops_before_launcher_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            jdk = Path(directory)
            for name in ("java", "javac", "jar", "jpackage"):
                path = jdk / "bin" / name
                path.parent.mkdir(exist_ok=True)
                path.touch()
            calls = []
            def runner(command, **_options):
                calls.append(command)
                if command[0].endswith("java"):
                    return subprocess.CompletedProcess(command, 0, "", 'openjdk version "17.0.20.1"')
                if command[0].endswith("jar"):
                    return subprocess.CompletedProcess(command, 1, "", "jar failed")
                return subprocess.CompletedProcess(command, 0, "", "")
            with mock.patch("test_jpackage_launcher.sys.platform", "linux"):
                with self.assertRaisesRegex(LauncherPreflightError, "JDK command failed"):
                    run_preflight(jdk, runner=runner)
            self.assertEqual(3, len(calls))


if __name__ == "__main__":
    unittest.main()

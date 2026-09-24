#!/usr/bin/env python3
"""Regression tests for the bounded native fixture completion runner."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent
RUNNER = ROOT / "native_fixture_run.sh"


@unittest.skipIf(os.name == "nt", "POSIX subprocess execution is unavailable on Windows")
class NativeFixtureRunTest(unittest.TestCase):
    def run_runner(self, directory: Path, child: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/sh", str(RUNNER), "--pid-file", str(directory / "child.pid"),
             "--exit-file", str(directory / "child.exit"), "--", "/bin/sh", str(child), *args],
            text=True,
            capture_output=True,
            check=False,
        )

    @staticmethod
    def write_child(directory: Path, body: str) -> Path:
        child = directory / "child.sh"
        child.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        return child

    def test_real_zero_exit_records_child_pid_and_terminal_zero(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            completed = self.run_runner(directory, self.write_child(directory, "exit 0\n"))
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertGreater(int((directory / "child.pid").read_text()), 0)
            self.assertEqual("0\n", (directory / "child.exit").read_text())

    def test_real_nonzero_exit_keeps_terminal_marker_after_legacy_set_e_loss(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            child = self.write_child(directory, "exit 7\n")
            legacy = directory / "legacy-set-e.sh"
            legacy.write_text("#!/bin/sh\nset -e\n\"$@\"\nprintf '%s\\n' $? > \"$MARKER\"\n", encoding="utf-8")
            legacy_marker = directory / "legacy.exit"
            legacy_result = subprocess.run(
                ["/bin/sh", str(legacy), "/bin/sh", str(child)], text=True, capture_output=True,
                env={**os.environ, "MARKER": str(legacy_marker)}, check=False,
            )
            self.assertEqual(7, legacy_result.returncode)
            self.assertFalse(legacy_marker.exists(), "legacy set -e skips the terminal marker")

            completed = self.run_runner(directory, child)
            self.assertEqual(7, completed.returncode)
            self.assertEqual("7\n", (directory / "child.exit").read_text())

    def test_malformed_python_launcher_is_prelaunch_failure_without_adb_or_lost_receipt(self):
        """Execution-wrapper regression, not Android product/install coverage."""
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            malformed = directory / "generated-launcher.py"
            malformed.write_text(
                "import subprocess\n"
                "subprocess.run([__import__('os').environ['ADB'], 'install', '-r', 'target.apk'])\n"
                "if True print('generated launcher parse failure')\n",
                encoding="utf-8",
            )
            adb_marker = directory / "adb-invoked"
            fake_adb = directory / "adb"
            fake_adb.write_text("#!/bin/sh\ntouch \"$ADB_MARKER\"\n", encoding="utf-8")
            fake_adb.chmod(0o700)
            environment = {**os.environ, "ADB": str(fake_adb), "ADB_MARKER": str(adb_marker)}

            # The historical unwrapped form exposes a parse failure but has no
            # durable terminal receipt for a later observer to classify.
            unwrapped_exit = directory / "unwrapped.exit"
            unwrapped = subprocess.run(
                [sys.executable, str(malformed)], text=True, capture_output=True,
                env=environment, check=False,
            )
            self.assertNotEqual(0, unwrapped.returncode)
            self.assertFalse(unwrapped_exit.exists(), "unwrapped launcher has no terminal receipt")
            self.assertFalse(adb_marker.exists(), "malformed launcher must fail before ADB execution")

            checked_exit = directory / "checked.exit"
            checked_pid = directory / "checked.pid"
            checked = subprocess.run(
                ["/bin/sh", str(RUNNER), "--pid-file", str(checked_pid),
                 "--exit-file", str(checked_exit), "--", sys.executable, str(malformed)],
                text=True, capture_output=True, env=environment, check=False,
            )
            self.assertNotEqual(0, checked.returncode)
            self.assertGreater(int(checked_pid.read_text()), 0)
            self.assertEqual(f"{checked.returncode}\n", checked_exit.read_text())
            self.assertFalse(adb_marker.exists(), "checked runner must retain prelaunch failure before ADB")

    def test_exact_argv_preserves_spaces_without_shell_evaluation(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            observed = directory / "argv.txt"
            child = self.write_child(directory, "printf '<%s>\\n' \"$@\" > \"$OBSERVED\"\n")
            argument = "two words; $(not executed)"
            completed = subprocess.run(
                ["/bin/sh", str(RUNNER), "--pid-file", str(directory / "child.pid"),
                 "--exit-file", str(directory / "child.exit"), "--", "/bin/sh", str(child), argument],
                text=True, capture_output=True, env={**os.environ, "OBSERVED": str(observed)}, check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertEqual(f"<{argument}>\n", observed.read_text())

    def test_preexisting_receipt_refuses_to_start_child(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            started = directory / "started"
            child = self.write_child(directory, "touch \"$STARTED\"\n")
            (directory / "child.exit").write_text("previous\n", encoding="utf-8")
            completed = subprocess.run(
                ["/bin/sh", str(RUNNER), "--pid-file", str(directory / "child.pid"),
                 "--exit-file", str(directory / "child.exit"), "--", "/bin/sh", str(child)],
                text=True, capture_output=True, env={**os.environ, "STARTED": str(started)}, check=False,
            )
            self.assertEqual(64, completed.returncode)
            self.assertFalse(started.exists())
            self.assertEqual("previous\n", (directory / "child.exit").read_text())

    def test_symlink_receipt_is_refused_without_overwriting_its_target(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            started = directory / "started"
            target = directory / "target"
            target.write_text("keep\n", encoding="utf-8")
            child = self.write_child(directory, "touch \"$STARTED\"\n")
            (directory / "child.exit").symlink_to(target)
            completed = subprocess.run(
                ["/bin/sh", str(RUNNER), "--pid-file", str(directory / "child.pid"),
                 "--exit-file", str(directory / "child.exit"), "--", "/bin/sh", str(child)],
                text=True, capture_output=True, env={**os.environ, "STARTED": str(started)}, check=False,
            )
            self.assertEqual(64, completed.returncode)
            self.assertFalse(started.exists())
            self.assertEqual("keep\n", target.read_text())

    def test_live_pid_reservation_refuses_competing_launch_before_its_child_starts(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            release = directory / "release"
            starts = directory / "starts"
            child = self.write_child(
                directory, "printf 'started\\n' >> \"$STARTS\"\n"
                "while [ ! -e \"$RELEASE\" ]; do sleep 0.01; done\n",
            )
            command = ["/bin/sh", str(RUNNER), "--pid-file", str(directory / "child.pid"),
                       "--exit-file", str(directory / "child.exit"), "--", "/bin/sh", str(child)]
            environment = {**os.environ, "RELEASE": str(release), "STARTS": str(starts)}
            first = subprocess.Popen(command, text=True, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.PIPE, env=environment)
            try:
                for _ in range(100):
                    if (directory / "child.pid").exists() and starts.exists():
                        break
                    if first.poll() is not None:
                        self.fail(first.stderr.read())
                    import time
                    time.sleep(0.01)
                self.assertTrue((directory / "child.pid").exists())
                competing = subprocess.run(command, text=True, capture_output=True,
                                           env=environment, check=False)
                self.assertEqual(64, competing.returncode)
                self.assertEqual(["started"], starts.read_text().splitlines())
                release.touch()
                self.assertEqual(0, first.wait(timeout=5))
            finally:
                if first.poll() is None:
                    release.touch()
                    first.wait(timeout=5)
                first.stderr.close()

    def test_exit_marker_is_absent_while_child_is_live(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            release = directory / "release"
            child = self.write_child(directory, "while [ ! -e \"$RELEASE\" ]; do sleep 0.01; done\n")
            runner = subprocess.Popen(
                ["/bin/sh", str(RUNNER), "--pid-file", str(directory / "child.pid"),
                 "--exit-file", str(directory / "child.exit"), "--", "/bin/sh", str(child)],
                text=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                env={**os.environ, "RELEASE": str(release)},
            )
            try:
                for _ in range(100):
                    if (directory / "child.pid").exists():
                        break
                    if runner.poll() is not None:
                        self.fail(runner.stderr.read())
                    import time
                    time.sleep(0.01)
                self.assertTrue((directory / "child.pid").exists())
                self.assertFalse((directory / "child.exit").exists())
                release.touch()
                self.assertEqual(0, runner.wait(timeout=5))
                self.assertEqual("0\n", (directory / "child.exit").read_text())
            finally:
                if runner.poll() is None:
                    release.touch()
                    runner.wait(timeout=5)
                runner.stderr.close()


if __name__ == "__main__":
    unittest.main()

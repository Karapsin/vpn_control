"""Behavioral regression for release hygiene failure aggregation."""
import shutil
import subprocess
import unittest
from pathlib import Path


class HygieneRunnerTest(unittest.TestCase):
    def run_shell(self, commands):
        source = Path(__file__).with_name("check_release_hygiene.sh").read_text()
        start = source.index("run_check() {")
        end = source.index("\n}\n", start) + 3
        script = "set -euo pipefail\nfailed_checks=()\n" + source[start:end] + "\n" + commands
        shell = shutil.which("bash")
        self.assertIsNotNone(shell, "Release hygiene requires Bash")
        return subprocess.run([shell, "-c", script], text=True, capture_output=True, timeout=10)

    def test_failure_retained_and_later_check_runs(self):
        result = self.run_shell("run_check bash -c 'exit 7'\nrun_check printf 'LATER_CHECK_RAN\\n'\n"
                                "printf 'FAILURES=%s\\n' \"${#failed_checks[@]}\"\n"
                                "test ${#failed_checks[@]} -eq 0")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("LATER_CHECK_RAN", result.stdout)
        self.assertIn("FAILURES=1", result.stdout)
        self.assertIn("7", result.stderr)

    def test_success_does_not_record_failure(self):
        result = self.run_shell("run_check true\ntest ${#failed_checks[@]} -eq 0")
        self.assertEqual(0, result.returncode, result.stderr)

    def test_cancellation_stops_before_followup_check(self):
        result = self.run_shell("run_check bash -c 'exit 130'\nprintf 'MUST_NOT_RUN'")
        self.assertEqual(130, result.returncode)
        self.assertNotIn("MUST_NOT_RUN", result.stdout)


if __name__ == "__main__":
    unittest.main()

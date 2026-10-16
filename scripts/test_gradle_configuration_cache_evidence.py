#!/usr/bin/env python3
"""Check complete Gradle probe diagnostics without executing Gradle or a network request."""
import contextlib
import io
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import test_gradle_configuration_cache as cache

if Path(cache.__file__).resolve() != ROOT / "scripts/test_gradle_configuration_cache.py":
    raise RuntimeError("Configuration-cache probe must come from this physical checkout")


class ConfigurationCacheEvidenceTests(unittest.TestCase):
    @contextlib.contextmanager
    def results(self, *outcomes):
        iterator = iter(outcomes)
        def run(*args, **kwargs):
            self.assertEqual((cache.COMMAND,), args)
            self.assertEqual({"cwd": cache.ROOT, "capture_output": True,
                              "text": True, "timeout": 180}, kwargs)
            outcome = next(iterator)
            if isinstance(outcome, BaseException):
                raise outcome
            code, stdout, stderr = outcome
            return subprocess.CompletedProcess(cache.COMMAND, code, stdout, stderr)
        with mock.patch.object(cache.subprocess, "run", side_effect=run) as invocation:
            yield invocation

    def streams(self, phase):
        # Synthetic prefix details exercise retention, not a claimed historical
        # HTTP/backend cause. The original E resolver cause remains unknown.
        stdout = phase + "_STDOUT_BEGIN\n" + "o" * 12000 + "\nSTDOUT_END"
        stderr = phase + "_EARLY_RESOLVER_DETAIL\n" + "e" * 12000 + "\nSTDERR_END"
        return stdout, stderr

    def test_first_failure_retains_both_complete_streams_without_retry(self):
        stdout, stderr = self.streams("FIRST")
        with self.results((17, stdout, stderr)) as invocation:
            with self.assertRaisesRegex(AssertionError, "First configuration-cache probe failed") as error:
                cache.main()
        self.assertEqual(1, invocation.call_count)
        self.assertIn("FIRST_EARLY_RESOLVER_DETAIL", str(error.exception))
        self.assertIn(stderr, str(error.exception))
        self.assertIn(stdout, str(error.exception))

    def test_second_failure_retains_both_complete_streams_without_retry(self):
        stdout, stderr = self.streams("SECOND")
        with self.results((0, "Configuration cache entry stored.", ""),
                          (23, stdout, stderr)) as invocation:
            with self.assertRaisesRegex(AssertionError, "Second configuration-cache probe failed") as error:
                cache.main()
        self.assertEqual(2, invocation.call_count)
        self.assertIn("SECOND_EARLY_RESOLVER_DETAIL", str(error.exception))
        self.assertIn(stderr, str(error.exception))
        self.assertIn(stdout, str(error.exception))

    def test_success_without_reuse_still_refuses_and_retains_complete_streams(self):
        stdout, stderr = self.streams("NO_REUSE")
        with self.results((0, "Configuration cache entry stored.", ""),
                          (0, stdout, stderr)) as invocation:
            with self.assertRaisesRegex(AssertionError, "Second task graph did not reuse") as error:
                cache.main()
        self.assertEqual(2, invocation.call_count)
        self.assertIn(stderr, str(error.exception))
        self.assertIn(stdout, str(error.exception))

    def test_success_requires_two_original_probes_and_reuse_marker(self):
        self.assertEqual([str(ROOT / ("gradlew.bat" if cache.os.name == "nt" else "gradlew")),
                          "--configuration-cache", "--configuration-cache-problems=fail",
                          ":desktopApp:compileKotlin", "--dry-run"], cache.COMMAND)
        output = io.StringIO()
        with self.results((0, "Configuration cache entry stored.", ""),
                          (0, "Reusing configuration cache.", "")) as invocation:
            with contextlib.redirect_stdout(output):
                cache.main()
        self.assertEqual(2, invocation.call_count)
        self.assertRegex(output.getvalue(), r"^Gradle configuration cache reused: first=\d+\.\d{2}s second=\d+\.\d{2}s\n$")

    def test_original_probe_timeout_propagates_once(self):
        timeout = subprocess.TimeoutExpired(cache.COMMAND, 180, output="partial", stderr="timeout detail")
        with self.results(timeout) as invocation:
            with self.assertRaises(subprocess.TimeoutExpired) as error:
                cache.main()
        self.assertIs(timeout, error.exception)
        self.assertEqual(1, invocation.call_count)


if __name__ == "__main__":
    unittest.main()

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from native_python_tests import native_python_request


class NativePythonTestsTest(unittest.TestCase):
    def run_fixture(self, tool_directory, body):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "test_native_probe.py").write_text(
                "import os, unittest\nclass Probe(unittest.TestCase):\n    def test_probe(self):\n        " + body + "\n", encoding="utf-8"
            )
            request = native_python_request(sys.executable, str(directory), [tool_directory], ["test_native_probe"])
            return subprocess.run([request["path"], *request["arg"]], text=True, capture_output=True)

    def test_windows_backslash_path_reaches_child_without_literal_interpretation(self):
        tool = r"C:\fixture\portable-git\bin"
        result = self.run_fixture(tool, "self.assertTrue(os.environ['PATH'].startswith(" + repr(tool + os.pathsep) + "))")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(1, json.loads(result.stdout)["executed"])

    def test_quotes_unicode_and_spaces_are_data_and_parent_environment_is_unchanged(self):
        before = dict(os.environ)
        tool = "C:\\fixture space\\owner's 工具\\bin"
        result = self.run_fixture(tool, "self.assertTrue(os.environ['PATH'].startswith(" + repr(tool + os.pathsep) + "))")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(before, dict(os.environ))

    def test_generated_test_source_does_not_depend_on_windows_default_encoding(self):
        original = Path.write_text
        def windows_write(path, data, encoding=None, **kwargs):
            return original(path, data, encoding=encoding or "cp1252", **kwargs)
        with patch.object(Path, "write_text", windows_write):
            result = self.run_fixture("tools", "self.assertEqual('工具', '工具')")
        self.assertEqual(0, result.returncode, result.stderr)

    def test_control_characters_are_rejected_before_any_launch(self):
        for invalid in ("C:\\fixture\bin", "bad\npath", "bad\x00path", "bad\x7fpath"):
            with self.subTest(invalid=repr(invalid)), self.assertRaises(ValueError):
                native_python_request(sys.executable, "tests", [invalid], ["test_probe"])

    def test_failed_test_keeps_nonzero_exit_and_stderr_evidence(self):
        result = self.run_fixture("tools", "self.fail('native failure evidence')")
        self.assertEqual(1, result.returncode)
        self.assertIn("native failure evidence", result.stderr)
        self.assertEqual(1, json.loads(result.stdout)["failures"])

    def test_explicit_skip_is_serializable_and_preserves_its_reason(self):
        result = self.run_fixture("tools", "self.skipTest('requires POSIX mode bits')")
        self.assertEqual(0, result.returncode, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(0, receipt["executed"])
        self.assertEqual([["test_native_probe.Probe.test_probe", "requires POSIX mode bits"]], receipt["skipped"])

    def test_empty_suite_is_not_reported_as_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            (Path(temporary) / "test_empty.py").write_text("# No tests\n", encoding="utf-8")
            request = native_python_request(sys.executable, temporary, [], ["test_empty"])
            result = subprocess.run([request["path"], *request["arg"]], text=True, capture_output=True)
            self.assertEqual(1, result.returncode)
            self.assertEqual(0, json.loads(result.stdout)["selected"])

    def test_missing_or_option_like_test_names_are_rejected(self):
        for modules in ([], ["-v"], ["test_probe;print(1)"]):
            with self.subTest(modules=modules), self.assertRaises(ValueError):
                native_python_request(sys.executable, "tests", [], modules)


if __name__ == "__main__":
    unittest.main()

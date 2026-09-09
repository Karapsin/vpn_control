import subprocess
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from native_jvm_tests import run_native_jvm_tests


def java_tool(name):
    home = os.environ.get("JAVA_HOME")
    if home:
        return str(Path(home) / "bin" / (name + (".exe" if os.name == "nt" else "")))
    return shutil.which(name)


class NativeJvmTestsTest(unittest.TestCase):
    def test_successful_probe_preserves_test_failure_and_literal_arguments(self):
        calls = []
        dependency = "fixture's 工具/tests.jar"
        def run(argv, **kwargs):
            calls.append(argv)
            if "NativeJvmPreflight" in argv:
                return subprocess.CompletedProcess(argv, 0, "VPN_CONTROL_JVM_PREFLIGHT_OK\n", "")
            return subprocess.CompletedProcess(argv, 1, "JUnit failure", "retained evidence")
        result = run_native_jvm_tests("fixture java", ["probe classes"], [dependency], ["fixture.Test$Nested"], runner=run)
        self.assertEqual("tests", result["phase"])
        self.assertEqual(1, result["exitCode"])
        self.assertEqual("retained evidence", result["stderr"])
        self.assertEqual(0, result["preflight"]["exitCode"])
        self.assertEqual(["fixture java", "-cp", "probe classes", "NativeJvmPreflight", "fixture java", dependency], calls[0])
        self.assertIn(dependency, calls[1])
        self.assertEqual("fixture.Test$Nested", calls[1][-1])

    def test_invalid_or_empty_selections_fail_before_launch(self):
        def must_not_run(*args, **kwargs):
            self.fail("Invalid request launched Java")
        for tests in ([], ["-Dtest=value"], ["test\nName"], ["test;injected"]):
            with self.subTest(tests=tests), self.assertRaises(ValueError):
                run_native_jvm_tests("java", ["probe"], ["tests.jar"], tests, runner=must_not_run)

    def test_failed_native_path_probe_stops_before_junit(self):
        calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            if "NativeJvmPreflight" in argv:
                return subprocess.CompletedProcess(argv, 1, "", "AccessDeniedException: retained Windows Temp Java")
            return subprocess.CompletedProcess(argv, 0, "OK (24 tests)", "")
        result = run_native_jvm_tests("java", ["probe"], ["tests.jar"], ["fixture.Test"], runner=run)
        self.assertEqual("preflight", result["phase"])
        self.assertEqual(1, result["exitCode"])
        self.assertIn("AccessDeniedException", result["stderr"])
        self.assertEqual(1, len(calls))
        self.assertNotIn("org.junit.runner.JUnitCore", calls[0])

    def test_missing_probe_success_receipt_stops_before_junit(self):
        calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, "", "")
        result = run_native_jvm_tests("java", ["probe"], ["tests.jar"], ["fixture.Test"], runner=run)
        self.assertEqual("preflight", result["phase"])
        self.assertNotEqual(0, result["exitCode"])
        self.assertEqual(1, len(calls))


@unittest.skipUnless(java_tool("java") and (os.environ.get("VPN_CONTROL_NATIVE_JVM_PROBE_CLASSES") or java_tool("javac")),
                     "Native Java plus a compiler or verified frozen probe required")
class NativeJvmPreflightTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.java = java_tool("java")
        frozen = os.environ.get("VPN_CONTROL_NATIVE_JVM_PROBE_CLASSES")
        cls.probe_directory = Path(frozen) if frozen else cls.directory
        if frozen:
            if not (cls.probe_directory / "NativeJvmPreflight.class").is_file():
                raise RuntimeError("Verified frozen native probe class is missing")
            return
        result = subprocess.run([java_tool("javac"), "--release", "17", "-d", str(cls.directory),
                                 str(Path(__file__).with_name("NativeJvmPreflight.java"))], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stderr)

    def probe(self, image, dependency):
        return subprocess.run([self.java, "-cp", str(self.probe_directory), "NativeJvmPreflight", image, str(dependency)],
                              capture_output=True, text=True)

    def test_actual_self_and_readable_dependency(self):
        dependency = self.directory / "readable fixture.jar"
        dependency.write_bytes(b"inert read probe")
        result = self.probe(self.java, dependency)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("VPN_CONTROL_JVM_PREFLIGHT_OK\n", result.stdout)

    def test_missing_dependency_is_a_preflight_failure(self):
        result = self.probe(self.java, self.directory / "missing.jar")
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn("VPN_CONTROL_JVM_PREFLIGHT_OK", result.stdout)

    def test_other_image_is_rejected(self):
        other = self.directory / "other.exe"
        other.write_bytes(b"unrelated image")
        result = self.probe(str(other), self.directory)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("differs from the selected interpreter", result.stderr)


if __name__ == "__main__":
    unittest.main()

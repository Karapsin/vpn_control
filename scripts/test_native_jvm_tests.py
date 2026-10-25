import subprocess
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from native_jvm_tests import run_native_jvm_tests


def java_tool(name):
    home = os.environ.get("JAVA_HOME")
    if home:
        return str(Path(home) / "bin" / (name + (".exe" if os.name == "nt" else "")))
    if name == "javac":
        selected = java_tool("java")
        if selected:
            sibling = Path(selected).resolve().with_name("javac.exe" if os.name == "nt" else "javac")
            if sibling.is_file() and sibling.resolve().parent == Path(selected).resolve().parent and os.access(sibling, os.X_OK):
                return str(sibling)
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


class NativeJvmCompilerSelectionTests(unittest.TestCase):
    @unittest.skipUnless(os.name=='posix' and java_tool('java') and Path(java_tool('java')).resolve().with_name('javac').is_file(),
                         'actual selected JDK compiler and POSIX shim boundary required')
    def test_whole_before_mixed_path_stub_red_selected_jdk_compiler_native_green(self):
        import hashlib,json,types
        folder=Path(__file__).parent/'tests/fixtures/readiness_test_seams'
        records=json.loads((folder/'provenance.json').read_bytes())['sourceSha256']
        for name,digest in records.items():
            self.assertEqual(digest,hashlib.sha256((folder/name).read_bytes()).hexdigest())
        selected=Path(java_tool('java')).resolve()
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);(root/'java').symlink_to(selected)
            stub=root/'javac';stub.write_text('#!/bin/sh\nprintf "%s\\n" "Unable to locate a Java Runtime" >&2\nexit 1\n');stub.chmod(0o700)
            with mock.patch.dict(os.environ,{'JAVA_HOME':'','VPN_CONTROL_NATIVE_JVM_PROBE_CLASSES':'','PATH':str(root)+os.pathsep+os.environ.get('PATH','')}):
                source=folder/'test_native_jvm_tests.py.before.source'
                old=types.ModuleType('retained_mixed_jvm_tools');old.__file__=__file__
                exec(compile(source.read_bytes(),str(source),'exec'),vars(old))
                self.assertEqual(str(stub),old.java_tool('javac'))
                result=unittest.TestResult();unittest.defaultTestLoader.loadTestsFromTestCase(old.NativeJvmPreflightTest).run(result)
                self.assertEqual(1,len(result.errors));self.assertIn('Unable to locate a Java Runtime',result.errors[0][1])
                self.assertEqual(str(selected.with_name('javac')),java_tool('javac'))
                result=unittest.TestResult();unittest.defaultTestLoader.loadTestsFromTestCase(NativeJvmPreflightTest).run(result)
                self.assertEqual(3,result.testsRun);self.assertTrue(result.wasSuccessful(),str(result.errors)+str(result.failures));self.assertFalse(result.skipped)


if __name__ == "__main__":
    unittest.main()

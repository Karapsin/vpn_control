import subprocess
import sys
from pathlib import Path
import tempfile
import unittest

from macos_packaging_jdk_preflight import preflight


class MacosPackagingJdkPreflightTest(unittest.TestCase):
    def fixture(self, vendor="Eclipse Adoptium", version="17.0.20.1", architecture="aarch64", *, properties=None, exit_code=0):
        directory = tempfile.TemporaryDirectory()
        home = Path(directory.name) / "temurin.jdk" / "Contents" / "Home"
        java = home / "bin" / "java"
        java.parent.mkdir(parents=True)
        lines = properties if properties is not None else (
            "    java.vendor = " + vendor,
            "    java.version = " + version,
            "    os.arch = " + architecture,
        )
        java.write_text("import sys\n" + "\n".join("print(" + repr(line) + ")" for line in lines) +
                        "\nraise SystemExit(" + repr(exit_code) + ")\n", encoding="utf-8")
        return directory, home

    @staticmethod
    def python_runner(arguments, **kwargs):
        return subprocess.run([sys.executable, *arguments], **kwargs)

    def test_invokes_selected_java_with_exact_property_arguments_and_scrubs_launch_options(self):
        temporary, home = self.fixture()
        self.addCleanup(temporary.cleanup)
        calls = []
        def run(arguments, **kwargs):
            calls.append((arguments, kwargs["env"]))
            return subprocess.CompletedProcess(arguments, 0, "    java.vendor = Eclipse Adoptium\n    java.version = 17.0.20.1\n    os.arch = aarch64\n")
        result = preflight(home, "arm64", run=run,
                           environment={"JAVA_TOOL_OPTIONS": "-Djava.vendor=forged", "KEEP": "yes"}, system=lambda: "Darwin")
        self.assertEqual("Eclipse Adoptium", result["vendor"])
        self.assertEqual([[str(home / "bin" / "java"), "-XshowSettings:properties", "-version"]], [call[0] for call in calls])
        self.assertNotIn("JAVA_TOOL_OPTIONS", calls[0][1])
        self.assertEqual("yes", calls[0][1]["KEEP"])

    def test_rejects_real_upstream_homebrew_failure_shape(self):
        temporary, home = self.fixture(vendor="Homebrew")
        self.addCleanup(temporary.cleanup)
        with self.assertRaisesRegex(ValueError, "Homebrew JDK"):
            preflight(home, "arm64", run=self.python_runner, system=lambda: "Darwin")

    def test_rejects_wrong_major_and_native_architecture(self):
        for version, architecture, expected in (("21.0.1", "aarch64", "JDK 17"), ("17.0.20.1", "x86_64", "architecture")):
            with self.subTest(version=version, architecture=architecture):
                temporary, home = self.fixture(version=version, architecture=architecture)
                self.addCleanup(temporary.cleanup)
                with self.assertRaisesRegex(ValueError, expected):
                    preflight(home, "arm64", run=self.python_runner, system=lambda: "Darwin")

    def test_rejects_missing_selected_jvm_properties(self):
        temporary, home = self.fixture(properties=("    java.vendor = Eclipse Adoptium", "    os.arch = aarch64"))
        self.addCleanup(temporary.cleanup)
        with self.assertRaisesRegex(ValueError, "properties are incomplete"):
            preflight(home, "arm64", run=self.python_runner, system=lambda: "Darwin")

    def test_rejects_nonzero_selected_jvm_probe(self):
        temporary, home = self.fixture(exit_code=7)
        self.addCleanup(temporary.cleanup)
        with self.assertRaisesRegex(ValueError, "property probe failed"):
            preflight(home, "arm64", run=self.python_runner, system=lambda: "Darwin")

    def test_rejects_non_macos_before_running_selected_java(self):
        temporary, home = self.fixture()
        self.addCleanup(temporary.cleanup)
        with self.assertRaisesRegex(ValueError, "requires Darwin"):
            preflight(home, "arm64", system=lambda: "Linux")


if __name__ == "__main__":
    unittest.main()

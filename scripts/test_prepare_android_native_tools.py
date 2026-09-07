#!/usr/bin/env python3
"""Regression coverage for Android native-tool resolution without mutating an SDK."""
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "prepare_android_native_tools.sh"


@unittest.skipUnless(os.name == "posix", "requires POSIX shell execution")
class PrepareAndroidNativeToolsTest(unittest.TestCase):
    def run_script(self, environment, script=SCRIPT):
        return subprocess.run(
            ["/bin/bash", str(script)], cwd=ROOT, text=True, capture_output=True,
            env=environment,
        )

    def configured_sdk(self, variable):
        temporary = tempfile.TemporaryDirectory(prefix="android sdk path ")
        sdk = pathlib.Path(temporary.name) / "SDK with spaces"
        tool = sdk / "cmdline-tools" / "latest" / "bin" / "sdkmanager"
        tool.parent.mkdir(parents=True)
        output = pathlib.Path(temporary.name) / "arguments.txt"
        tool.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$SDKMANAGER_LOG\"\n")
        tool.chmod(0o755)
        return temporary, output, {
            variable: str(sdk),
            "PATH": "/usr/bin:/bin",  # deliberately excludes sdkmanager
            "SDKMANAGER_LOG": str(output),
        }

    def test_former_raw_sdkmanager_ignores_configured_sdk_when_path_lacks_tool(self):
        temporary, _, environment = self.configured_sdk("ANDROID_HOME")
        with temporary:
            legacy = pathlib.Path(temporary.name) / "former-body.sh"
            legacy.write_text('#!/bin/sh\nsdkmanager "ndk;28.2.13676358" "cmake;3.22.1"\n')
            legacy.chmod(0o755)
            result = self.run_script(environment, legacy)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("sdkmanager", result.stderr)

    def test_android_home_sdkmanager_with_spaces_is_used_when_path_lacks_sdkmanager(self):
        temporary, output, environment = self.configured_sdk("ANDROID_HOME")
        with temporary:
            result = self.run_script(environment)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(["ndk;28.2.13676358", "cmake;3.22.1"], output.read_text().splitlines())

    def test_android_sdk_root_sdkmanager_with_spaces_is_used_when_path_lacks_sdkmanager(self):
        temporary, output, environment = self.configured_sdk("ANDROID_SDK_ROOT")
        with temporary:
            result = self.run_script(environment)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(["ndk;28.2.13676358", "cmake;3.22.1"], output.read_text().splitlines())

    def test_path_sdkmanager_is_the_fallback(self):
        with tempfile.TemporaryDirectory(prefix="android sdk path fallback ") as temporary:
            directory = pathlib.Path(temporary)
            tool = directory / "sdkmanager"
            output = directory / "arguments.txt"
            tool.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$SDKMANAGER_LOG\"\n")
            tool.chmod(0o755)
            environment = {"PATH": f"{directory}:/usr/bin:/bin", "SDKMANAGER_LOG": str(output)}
            result = self.run_script(environment)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(["ndk;28.2.13676358", "cmake;3.22.1"], output.read_text().splitlines())

    def test_missing_sdkmanager_has_actionable_error(self):
        with tempfile.TemporaryDirectory(prefix="android sdk missing ") as temporary:
            environment = {"ANDROID_SDK_ROOT": temporary, "PATH": "/usr/bin:/bin"}
            result = self.run_script(environment)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("sdkmanager", result.stderr)
            self.assertIn("ANDROID_SDK_ROOT", result.stderr)


if __name__ == "__main__":
    unittest.main()

"""Configure the real desktop Gradle task graph without an Android SDK."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class DesktopSdkIndependenceTest(unittest.TestCase):
    def test_desktop_graph_does_not_resolve_android_sdk(self):
        repository = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory(prefix="vpn-desktop-no-sdk-") as directory:
            root = Path(directory)
            # Copy build inputs, not local.properties, credentials or generated
            # outputs. Keep the real Android build definition in the project.
            paths = ["settings.gradle.kts", "build.gradle.kts", "gradle.properties",
                     "gradlew", "gradlew.bat", "app/build.gradle.kts",
                     "desktopApp/build.gradle.kts", "shared/model/build.gradle.kts",
                     "shared/core/build.gradle.kts", "shared/storage-api/build.gradle.kts",
                     "shared/ui/build.gradle.kts"]
            for relative in paths:
                source, target = repository / relative, root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
            shutil.copytree(repository / "gradle", root / "gradle")
            environment = dict(os.environ)
            for name in list(environment):
                if name.startswith("VPN_CONTROL_ANDROID_") or name in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
                    del environment[name]
            # Even a machine with a default SDK must not accidentally satisfy
            # this check. An explicit unavailable path exposes eager SDK reads.
            environment["ANDROID_HOME"] = str(root / "sdk-does-not-exist")
            environment["ANDROID_SDK_ROOT"] = environment["ANDROID_HOME"]
            launcher = "gradlew.bat" if os.name == "nt" else "./gradlew"
            result = subprocess.run([launcher, "--console=plain",
                                     ":desktopApp:compileKotlin", "--dry-run"], cwd=root,
                                    env=environment, capture_output=True, text=True, timeout=300)
            self.assertEqual(0, result.returncode, (result.stdout + result.stderr)[-12000:])
            self.assertIn(":desktopApp:compileKotlin SKIPPED", result.stdout)


if __name__ == "__main__":
    unittest.main()

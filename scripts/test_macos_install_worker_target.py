import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "prepare_macos_install_worker.sh"
SOURCE_DIRECTORY = REPO_ROOT / "scripts" / "native"
TARGETS = {
    "arm64": ("arm64", "11.0"),
    "x86_64": ("amd64", "10.13"),
}


class MacosInstallWorkerTargetTest(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        scripts = root / "scripts"
        scripts.mkdir()
        shutil.copy2(SCRIPT, scripts / SCRIPT.name)
        shutil.copytree(SOURCE_DIRECTORY, scripts / "native")
        return temporary, root

    @staticmethod
    def write_executable(path, text):
        path.write_text(text, encoding="utf-8")
        path.chmod(0o755)

    def test_pins_each_worker_to_its_packaged_minimum_despite_host_environment(self):
        for architecture, (resource_architecture, minimum) in TARGETS.items():
            with self.subTest(architecture=architecture):
                temporary, root = self.fixture()
                self.addCleanup(temporary.cleanup)
                tools = root / "tools"
                tools.mkdir()
                capture = root / "capture.json"
                self.write_executable(tools / "uname", """#!/usr/bin/env python3
import os
import sys

print('Darwin' if sys.argv[1:] == ['-s'] else os.environ['FAKE_ARCH'])
""")
                self.write_executable(tools / "xcrun", """#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

arguments = sys.argv[1:]
Path(os.environ['CAPTURE']).write_text(json.dumps({
    'arguments': arguments,
    'deploymentTarget': os.environ.get('MACOSX_DEPLOYMENT_TARGET'),
}), encoding='utf-8')
Path(arguments[arguments.index('-o') + 1]).touch()
""")
                environment = os.environ | {
                    "PATH": str(tools) + os.pathsep + os.environ["PATH"],
                    "CAPTURE": str(capture),
                    "FAKE_ARCH": architecture,
                    "MACOSX_DEPLOYMENT_TARGET": "26.0",
                }
                subprocess.run(["bash", str(root / "scripts" / SCRIPT.name)], check=True, env=environment)
                recorded = json.loads(capture.read_text(encoding="utf-8"))
                self.assertEqual("26.0", recorded["deploymentTarget"])
                self.assertEqual("clang", recorded["arguments"][0])
                self.assertIn(f"-mmacosx-version-min={minimum}", recorded["arguments"])
                self.assertNotIn(
                    f"-mmacosx-version-min={TARGETS['x86_64' if architecture == 'arm64' else 'arm64'][1]}",
                    recorded["arguments"],
                )
                self.assertTrue((root / f"desktopApp/src/main/resources/bin/darwin-{resource_architecture}/vpn-control-install-worker").is_file())

    @staticmethod
    def macho_minimum(inspection):
        for command, field in (("LC_BUILD_VERSION", "minos"), ("LC_VERSION_MIN_MACOSX", "version")):
            match = re.search(rf"cmd {command}.*?{field} (\d+\.\d+)", inspection, re.DOTALL)
            if match:
                return command, match.group(1)
        excerpts = []
        lines = inspection.splitlines()
        for index, line in enumerate(lines):
            if "LC_BUILD_VERSION" in line or "LC_VERSION_MIN_MACOSX" in line:
                excerpts.extend(lines[index:index + 6])
        raise AssertionError("Mach-O deployment load command missing: " + " | ".join(excerpts or lines[:8]))

    @unittest.skipUnless(platform.system() == "Darwin", "requires macOS compiler and Mach-O inspection")
    def test_actual_host_compile_has_its_packaged_launcher_minimum(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        subprocess.run(["bash", str(root / "scripts" / SCRIPT.name)], check=True)
        architecture = subprocess.run(["uname", "-m"], check=True, capture_output=True, text=True).stdout.strip()
        resource_architecture, minimum = TARGETS[architecture]
        helper = root / f"desktopApp/src/main/resources/bin/darwin-{resource_architecture}/vpn-control-install-worker"
        self.assertTrue(helper.is_file())
        inspection = subprocess.run(
            ["xcrun", "otool", "-l", str(helper)], check=True, capture_output=True, text=True
        ).stdout
        command, actual = self.macho_minimum(inspection)
        self.assertEqual(minimum, actual, f"{helper} ({architecture}, {command})")


if __name__ == "__main__":
    unittest.main()

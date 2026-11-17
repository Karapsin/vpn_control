#!/usr/bin/env python3
"""Package scripts run release hygiene once locally and never when CI passes --skip-release-hygiene.

Each script runs in an owned temporary root whose helpers are stubs: the
hygiene stub counts its runs, Gradle and runtime preparation succeed without
work, and the package outputs are fixed files. The a34e07cb beforeimages ran
hygiene twice for one Linux package (script and Arch bundle) and had no flag.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "scripts/tests/fixtures/package_release_hygiene"
SCRIPTS = ("package_linux_desktop.sh", "package_arch_desktop_update.sh", "package_macos_desktop.sh")


def before(name):
    provenance = json.loads((FIXTURES / "provenance.json").read_text(encoding="utf-8"))
    row = next(item for item in provenance["files"] if item["sourcePath"] == "scripts/" + name)
    raw = (FIXTURES / row["path"]).read_bytes()
    if len(raw) != row["sourceBytes"] or hashlib.sha256(raw).hexdigest() != row["sourceSha256"]:
        raise ValueError("Preserved package script changed: " + name)
    return raw


def bash_reads_lists():
    """The Linux packager reads file lists with mapfile (bash 4+); hosted macOS runs `bash` 3.2."""
    try:
        return subprocess.run(["bash", "-c", "mapfile -t lines < /dev/null"], capture_output=True,
                              timeout=30, check=False).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


LINUX_PACKAGER_SHELL = os.name != "nt" and bash_reads_lists()
NO_LINUX_PACKAGER_SHELL = "the Linux packager needs bash 4 (mapfile); this host's bash is older"


def executable(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


@unittest.skipIf(os.name == "nt", "the Linux and macOS package scripts are POSIX shell programs")
class PackageReleaseHygieneTests(unittest.TestCase):
    sources = None

    def source(self, name):
        return (self.sources or {}).get(name) or (ROOT / "scripts" / name).read_bytes()

    def root(self):
        temporary = tempfile.TemporaryDirectory(prefix="package-hygiene-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        for name in SCRIPTS:
            executable(root / "scripts" / name, self.source(name).decode("utf-8"))
        marker = root / "hygiene-runs"
        executable(root / "scripts/check_release_hygiene.sh", "#!/usr/bin/env bash\necho run >> '%s'\n" % marker)
        for name in ("prepare_sing_box_desktop_runtime.sh", "prepare_sing_box_macos_runtime.sh",
                     "prepare_macos_install_worker.sh", "setup_macos_signing.sh"):
            executable(root / "scripts" / name, "#!/usr/bin/env bash\ntrue\n")
        executable(root / "scripts/install_arch_desktop_update.sh", "#!/usr/bin/env bash\ntrue\n")
        executable(root / "scripts/version_metadata.py", "print('2.2.18')\n")
        executable(root / "gradlew", "#!/usr/bin/env bash\ntrue\n")
        output = root / "desktopApp/build/compose/binaries/main"
        for relative in ("deb/vpn-control.deb", "dmg/vpn-control.dmg"):
            (output / relative).parent.mkdir(parents=True, exist_ok=True)
            (output / relative).write_text("package")
        executable(output / "app/vpn-control/bin/vpn-control", "#!/usr/bin/env bash\n")
        executable(root / "desktopApp/src/main/resources/bin/linux-amd64/sing-box", "#!/usr/bin/env bash\n")
        tools = root / "bin"
        executable(tools / "java", "#!/usr/bin/env bash\ntrue\n")
        executable(tools / "sha256sum", "#!/usr/bin/env bash\necho checksum\n")
        return root, marker

    def runs(self, name, *args):
        root, marker = self.root()
        env = {key: value for key, value in os.environ.items() if not key.startswith("VPN_CONTROL_")}
        env["PATH"] = str(root / "bin") + os.pathsep + env.get("PATH", os.defpath)
        result = subprocess.run(["bash", str(root / "scripts" / name), *args], cwd=root, env=env,
                                capture_output=True, text=True, timeout=60)
        count = len(marker.read_text().splitlines()) if marker.exists() else 0
        return result, count

    @unittest.skipUnless(LINUX_PACKAGER_SHELL, NO_LINUX_PACKAGER_SHELL)
    def test_linux_package_runs_hygiene_once_locally_and_never_with_the_ci_flag(self):
        result, count = self.runs("package_linux_desktop.sh", "--skip-tests", "--skip-package-regression-tests")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(1, count, "a local Linux package runs release hygiene exactly once")
        result, count = self.runs("package_linux_desktop.sh", "--skip-release-hygiene", "--skip-tests",
                                  "--skip-package-regression-tests")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(0, count, "CI runs Linux release hygiene once in Fast Checks")

    def test_arch_bundle_keeps_hygiene_alone_and_skips_it_on_request(self):
        result, count = self.runs("package_arch_desktop_update.sh", "--skip-build")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(1, count)
        result, count = self.runs("package_arch_desktop_update.sh", "--skip-release-hygiene", "--skip-build")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(0, count)
        result, count = self.runs("package_arch_desktop_update.sh", "--unknown")
        self.assertEqual(2, result.returncode)
        self.assertEqual(0, count)

    @unittest.skipUnless(platform.system() == "Darwin", "the macOS packager refuses other hosts first")
    def test_macos_package_runs_hygiene_once_locally_and_never_with_the_ci_flag(self):
        result, count = self.runs("package_macos_desktop.sh", "--skip-tests", "--skip-package-regression-tests")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(1, count)
        result, count = self.runs("package_macos_desktop.sh", "--skip-release-hygiene", "--skip-tests",
                                  "--skip-package-regression-tests")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(0, count)

    @unittest.skipUnless(LINUX_PACKAGER_SHELL, NO_LINUX_PACKAGER_SHELL)
    def test_a34e07cb_scripts_ran_linux_hygiene_twice_and_had_no_ci_flag(self):
        # RED on the whole preserved scripts: the same positives fail. GREEN above.
        records = {}
        for name in ("test_linux_package_runs_hygiene_once_locally_and_never_with_the_ci_flag",
                     "test_arch_bundle_keeps_hygiene_alone_and_skips_it_on_request"):
            case = type(self)(name)
            case.sources = {script: before(script) for script in SCRIPTS}
            result = unittest.TestResult()
            case.run(result)
            records[name] = [next(line for line in reversed(text.splitlines()) if line.strip())
                             for unused, text in result.failures + result.errors]
        print(json.dumps({"event": "package-hygiene-causal", "before": records}, sort_keys=True))
        self.assertIn("1 != 2", " ".join(records["test_linux_package_runs_hygiene_once_locally_and_never_with_the_ci_flag"]))
        self.assertEqual(1, len(records["test_arch_bundle_keeps_hygiene_alone_and_skips_it_on_request"]))

    def test_ci_package_jobs_pass_the_flag_where_hygiene_already_ran(self):
        workflows = ROOT / ".github/workflows"
        linux = (workflows / "linux-desktop.yml").read_text(encoding="utf-8")
        macos = (workflows / "macos-desktop.yml").read_text(encoding="utf-8")
        windows = (workflows / "windows-desktop.yml").read_text(encoding="utf-8")
        self.assertIn("run: ./scripts/package_linux_desktop.sh --skip-release-hygiene --skip-tests", linux)
        self.assertIn("run: ./scripts/package_macos_desktop.sh --skip-release-hygiene", macos)
        self.assertEqual(1, macos.split("  package-macos-desktop:", 1)[1].count("run: ./scripts/check_release_hygiene.sh"))
        package = windows.split("  package-windows-desktop:", 1)[1]
        self.assertEqual(1, windows.count("run: ./scripts/check_release_hygiene.sh"))
        self.assertIn(".\\scripts\\package_windows_desktop.ps1 -SkipTests -SkipReleaseHygiene", package)


if __name__ == "__main__":
    unittest.main()

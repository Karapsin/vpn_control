"""Unprivileged maintainer-hook regression; all filesystem effects stay in tmp."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


REPO = Path(__file__).resolve().parents[1]
RESOURCE = REPO / "desktopApp/packaging/linux/postinst"
# The current JDK 17 default hook, reduced to its unchanged configure semantics.
DEFAULT = '''#!/bin/sh
set -e
case "$1" in
configure)
DESKTOP_COMMANDS_INSTALL
;;
abort-upgrade|abort-remove|abort-deconfigure) ;;
*) exit 1 ;;
esac
exit 0
'''


def posix_shell():
    if os.name == "nt":
        raise unittest.SkipTest("postinst hook execution requires a POSIX shell")
    return "/bin/sh"


class LinuxPackagePostinstTest(unittest.TestCase):
    def test_deb_task_tracks_and_passes_resource_directory(self):
        build = (REPO / "desktopApp/build.gradle.kts").read_text()
        self.assertIn("hostOs.isLinux && targetFormat == TargetFormat.Deb", build)
        self.assertIn('project.file("packaging/linux")', build)
        self.assertIn("inputs.dir(debResources)", build)
        self.assertIn('"--resources", debResources.absolutePath', build)
        self.assertIn('scripts/package_linux_deb.py', build)
        self.assertEqual(1, RESOURCE.read_text().count("DESKTOP_COMMANDS_INSTALL"))

    def run_hook(self, *, desktop=False, action="configure", registration_exit=0, race_directory=False):
        shell = posix_shell()
        with tempfile.TemporaryDirectory(prefix="vpn-postinst-") as temp:
            root = Path(temp)
            menu = root / "usr/share/desktop-directories"
            menu.parent.mkdir(parents=True)
            if desktop:
                menu.mkdir(parents=True)
                menu.chmod(0o750)
            marker = root / "registered"
            # Reproduce xdg-desktop-menu's system menu-directory prerequisite.
            command = f'''test -d '{menu}' || {{ echo 'No writable system menu directory found' >&2; exit 3; }}
test -w '{menu}' || exit 3
touch '{marker}'
(exit {registration_exit})'''
            hook = RESOURCE.read_text() if RESOURCE.exists() else DEFAULT
            hook = hook.replace("/usr/share/desktop-directories", str(menu))
            hook = hook.replace("DESKTOP_COMMANDS_INSTALL", command)
            if race_directory:
                # Another package creates the menu directory after the hook's
                # initial existence check. Exercise the real creation command.
                shim = f'''install() {{ command mkdir -m 0750 '{menu}'; command install "$@"; }}
mkdir() {{ command mkdir -m 0750 '{menu}'; command mkdir "$@"; }}
'''
                hook = hook.replace("set -e\n", "set -e\n" + shim, 1)
            script = root / "postinst"
            script.write_text(hook)
            result = subprocess.run([shell, str(script), action], capture_output=True, text=True,
                                    env={"PATH": os.environ["PATH"]}, timeout=10)
            return result, marker.exists(), menu.stat().st_mode & 0o777 if menu.exists() else None

    def test_headless_configure_registers_desktop_entry(self):
        result, registered, mode = self.run_hook()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(registered)
        self.assertEqual(0o755, mode)

    def test_existing_desktop_directory_is_preserved(self):
        result, registered, mode = self.run_hook(desktop=True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(registered)
        self.assertEqual(0o750, mode)

    def test_concurrently_created_directory_keeps_its_existing_mode(self):
        result, registered, mode = self.run_hook(race_directory=True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(registered)
        self.assertEqual(0o750, mode)

    def test_registration_failure_is_not_silenced(self):
        result, _, _ = self.run_hook(desktop=True, registration_exit=17)
        self.assertEqual(17, result.returncode)

    def test_abort_does_not_register_or_create_directories(self):
        result, registered, mode = self.run_hook(action="abort-upgrade")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(registered)
        self.assertIsNone(mode)

    def test_unknown_action_fails(self):
        self.assertNotEqual(0, self.run_hook(action="unexpected")[0].returncode)

    def test_windows_skips_only_posix_hook_execution(self):
        # This executes the real runner. The former implementation proceeded
        # to subprocess creation; the current eligibility guard stops first.
        with patch.object(os, "name", "nt"):
            with self.assertRaises(unittest.SkipTest):
                self.run_hook()


if __name__ == "__main__":
    unittest.main()

"""Run the DMG smoke shell with an inert mount and controlled detach failures."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(os.name == "posix", "requires the package shell")
class MacPackageCleanupTest(unittest.TestCase):
    def scenario(self, failures, smoke_exit=0, force_succeeds=False, identity_matches=True, extra_mount=False):
        temporary = tempfile.TemporaryDirectory(prefix="mac cleanup-東京-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        commands = root / "commands"
        commands.mkdir()
        mount = root / "mount"
        dmg = root / "fixture.dmg"
        dmg.touch()
        script = Path(__file__).with_name("test_macos_desktop_package.sh").resolve()
        stub = commands / "stub"
        stub.write_text("#!" + sys.executable + "\n" + r'''
import json, os, pathlib, plistlib, shutil, sys
root = pathlib.Path(os.environ["CLEANUP_FIXTURE"])
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with (root / "calls").open("a") as log:
    log.write(json.dumps([name, *args]) + "\n")
mount = root / "mount"
if name == "uname": print("Darwin")
elif name == "mktemp":
    mount.mkdir()
    print(mount)
elif name == "hdiutil":
    if args[0] == "attach":
        assert args[args.index("-mountpoint") + 1] == str(mount)
        assert "-readonly" in args and "-nobrowse" in args and "-plist" in args
        app = mount / "fixture.app/Contents"
        (app / "MacOS").mkdir(parents=True)
        (app / "app").mkdir()
        (app / "Info.plist").touch()
        (app / "app/main.jar").touch()
        executable = app / "MacOS/fixture"
        executable.touch()
        executable.chmod(0o700)
        plistlib.dump({"system-entities": [{"dev-entry": "/dev/disk777s1", "mount-point": str(mount)}]}, sys.stdout.buffer)
    elif args[0] == "info":
        expected_mount = str(mount) if os.environ["IDENTITY_MATCHES"] == "true" else str(root / "other-mount")
        entities = [{"dev-entry": "/dev/disk777s1", "mount-point": expected_mount}]
        if os.environ["EXTRA_MOUNT"] == "true": entities.append({"dev-entry": "/dev/disk777s2", "mount-point": str(root / "other-volume")})
        plistlib.dump({"images": [{"image-path": str((root / "fixture.dmg").resolve()), "writeable": False,
            "system-entities": entities}]}, sys.stdout.buffer)
    else:
        assert args[1] == "/dev/disk777s1"
        forced = args[2:] == ["-force", "-quiet"]
        assert forced or args[2:] == ["-quiet"]
        counter = root / "detach-count"
        count = int(counter.read_text()) + 1 if counter.exists() else 1
        counter.write_text(str(count))
        if not forced and count <= int(os.environ["DETACH_FAILURES"]): sys.exit(1)
        if forced and os.environ["FORCE_SUCCEEDS"] != "true": sys.exit(1)
        shutil.rmtree(mount / "fixture.app")  # Simulate successful unmount, never an actual mount.
elif name == "plutil":
    print("2.1.5" if args[1] == "CFBundleShortVersionString" else "fixture")
elif name == "jar": print("bin/darwin-arm64/sing-box")
elif name == "python3":
    if args[0].endswith("version_metadata.py"): print("2.1.5")
    elif args[0] == "-c": os.execv(sys.executable, [sys.executable, *args])
    else: sys.exit(int(os.environ["SMOKE_EXIT"]))
elif name == "rm":
    assert args[-1] == str(mount)
    if (mount / "fixture.app").exists():
        (root / "unsafe-recursive-removal").touch()
        sys.exit(1)
    mount.rmdir()
elif name == "rmdir":
    assert args == [str(mount)]
    mount.rmdir()
elif name == "sleep": pass
else: raise AssertionError(name)
''')
        stub.chmod(0o700)
        for command in ("uname", "mktemp", "hdiutil", "plutil", "jar", "python3", "rm", "rmdir", "sleep"):
            (commands / command).symlink_to(stub)
        environment = dict(os.environ, PATH=str(commands) + os.pathsep + os.environ["PATH"],
                           CLEANUP_FIXTURE=str(root), DETACH_FAILURES=str(failures), SMOKE_EXIT=str(smoke_exit),
                           FORCE_SUCCEEDS=str(force_succeeds).lower(), IDENTITY_MATCHES=str(identity_matches).lower(),
                           EXTRA_MOUNT=str(extra_mount).lower())
        environment.pop("VPN_CONTROL_MACOS_SIGNING_IDENTITY", None)
        result = subprocess.run([shutil.which("bash"), str(script), str(dmg)], env=environment,
                                capture_output=True, text=True, timeout=15)
        calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()]
        return root, result, calls

    def test_busy_detach_is_retried_before_removing_empty_mount_directory(self):
        root, result, calls = self.scenario(failures=1)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(2, sum(call[:2] == ["hdiutil", "detach"] for call in calls))
        self.assertFalse((root / "unsafe-recursive-removal").exists())
        self.assertFalse((root / "mount").exists())

    def test_persistent_busy_mount_is_preserved_and_not_reported_as_success(self):
        root, result, calls = self.scenario(failures=100)
        self.assertNotEqual(0, result.returncode)
        self.assertFalse((root / "unsafe-recursive-removal").exists())
        self.assertTrue((root / "mount/fixture.app").exists())
        self.assertNotIn("macOS DMG smoke passed", result.stdout)
        self.assertIn("preserved", result.stderr)
        detach = [call for call in calls if call[:2] == ["hdiutil", "detach"]]
        self.assertEqual(6, len(detach))
        self.assertEqual(["hdiutil", "detach", "/dev/disk777s1", "-force", "-quiet"], detach[-1])

    def test_owned_read_only_image_uses_its_captured_device_for_one_forced_detach_after_retries(self):
        root, result, calls = self.scenario(failures=5, force_succeeds=True)
        self.assertEqual(0, result.returncode, result.stderr)
        detach = [call for call in calls if call[:2] == ["hdiutil", "detach"]]
        self.assertEqual([["hdiutil", "detach", "/dev/disk777s1", "-quiet"]] * 5 +
                         [["hdiutil", "detach", "/dev/disk777s1", "-force", "-quiet"]], detach)
        self.assertFalse((root / "mount").exists())
        self.assertFalse((root / "unsafe-recursive-removal").exists())

    def test_identity_mismatch_preserves_mount_without_detaching_or_forcing(self):
        root, result, calls = self.scenario(failures=5, force_succeeds=True, identity_matches=False)
        self.assertNotEqual(0, result.returncode)
        self.assertTrue((root / "mount/fixture.app").exists())
        self.assertFalse(any(call[:2] == ["hdiutil", "detach"] for call in calls))
        self.assertIn("identity changed", result.stderr)

    def test_extra_volume_from_same_image_blocks_detach_and_force(self):
        root, result, calls = self.scenario(failures=5, force_succeeds=True, extra_mount=True)
        self.assertNotEqual(0, result.returncode)
        self.assertTrue((root / "mount/fixture.app").exists())
        self.assertFalse(any(call[:2] == ["hdiutil", "detach"] for call in calls))

    def test_smoke_failure_still_detaches_without_masking_failure(self):
        root, result, calls = self.scenario(failures=0, smoke_exit=7)
        self.assertEqual(7, result.returncode, result.stderr)
        self.assertFalse((root / "mount").exists())
        self.assertFalse((root / "unsafe-recursive-removal").exists())
        self.assertEqual(1, sum(call[:2] == ["hdiutil", "detach"] for call in calls))


if __name__ == "__main__":
    unittest.main()

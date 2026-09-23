import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from android_avd_sdk_preflight import PreflightError, safe_avd_environment
from test_fixture_environment import symlink_probe_available


IMAGE = "system-images;android-29;google_apis;x86_64"


def executable(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nset -eu\n" + body)
    path.chmod(0o700)


def add_image(sdk: Path, package: str = IMAGE) -> None:
    metadata = sdk.joinpath(*package.split(";")) / "package.xml"
    metadata.parent.mkdir(parents=True, exist_ok=True)
    metadata.write_text(f'<localPackage path="{package}"/>')


def add_sdk_tools(sdk: Path, avdmanager_body: str = "exit 0") -> None:
    executable(sdk / "cmdline-tools/latest/bin/avdmanager", avdmanager_body)
    executable(sdk / "emulator/emulator", "exit 0")


class AndroidAvdSdkPreflightTest(unittest.TestCase):
    def test_copied_tools_and_private_avd_home_return_complete_launch_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sdk, avd_home = root / "user-sdk", root / "private-avds"
            add_sdk_tools(sdk)
            add_image(sdk)
            avd_home.mkdir()

            result = safe_avd_environment(str(sdk), str(avd_home), IMAGE)

            self.assertEqual(str(sdk.resolve()), result["environment"]["ANDROID_HOME"])
            self.assertEqual(str(sdk.resolve()), result["environment"]["ANDROID_SDK_ROOT"])
            self.assertEqual(str(avd_home.resolve()), result["environment"]["ANDROID_AVD_HOME"])
            self.assertEqual(str((sdk / "cmdline-tools/latest/bin/avdmanager").resolve()), result["avdmanager"])
            self.assertEqual(str((sdk / "emulator/emulator").resolve()), result["emulator"])

    def test_shared_sdk_emulator_symlink_is_allowed_with_explicit_sdk_and_avd_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            if not symlink_probe_available(root):
                self.skipTest("symlink creation is unavailable on this platform")
            sdk, shared, avd_home = root / "private-sdk", root / "shared-sdk", root / "private-avds"
            add_sdk_tools(sdk)
            executable(shared / "emulator/emulator", "exit 0")
            (sdk / "emulator/emulator").unlink()
            (sdk / "emulator/emulator").symlink_to(shared / "emulator/emulator")
            add_image(sdk)
            avd_home.mkdir()

            result = safe_avd_environment(str(sdk), str(avd_home), IMAGE)

            self.assertEqual(str((shared / "emulator/emulator").resolve()), result["emulator"])
            self.assertEqual(str(sdk.resolve()), result["environment"]["ANDROID_HOME"])
            self.assertEqual(str(avd_home.resolve()), result["environment"]["ANDROID_AVD_HOME"])

    def test_exact_system_image_requires_matching_package_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sdk, avd_home = root / "sdk", root / "avds"
            add_sdk_tools(sdk)
            avd_home.mkdir()
            with self.assertRaisesRegex(PreflightError, "metadata is missing"):
                safe_avd_environment(str(sdk), str(avd_home), IMAGE)
            add_image(sdk)
            (sdk / "system-images/android-29/google_apis/x86_64/package.xml").write_text(
                '<localPackage path="system-images;android-35;google_apis;x86_64"/>'
            )
            with self.assertRaisesRegex(PreflightError, "metadata names"):
                safe_avd_environment(str(sdk), str(avd_home), IMAGE)

    def test_namespaced_repository_metadata_and_direct_local_package_are_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sdk, avd_home = root / "sdk", root / "avds"
            add_sdk_tools(sdk)
            metadata = sdk.joinpath(*IMAGE.split(";")) / "package.xml"
            metadata.parent.mkdir(parents=True)
            metadata.write_text(
                '<sdk:sdk-repository xmlns:sdk="http://schemas.android.com/sdk/android/repo/repository2/01">'
                f'<localPackage path="{IMAGE}"/></sdk:sdk-repository>'
            )
            avd_home.mkdir()
            self.assertEqual(str(metadata.resolve()), safe_avd_environment(str(sdk), str(avd_home), IMAGE)["systemImageMetadata"])

    def test_system_image_rejects_missing_or_ambiguous_metadata_identity_and_parent_component(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sdk, avd_home = root / "sdk", root / "avds"
            add_sdk_tools(sdk)
            metadata = sdk.joinpath(*IMAGE.split(";")) / "package.xml"
            metadata.parent.mkdir(parents=True)
            avd_home.mkdir()
            for document in (
                "<sdk-repository/>",
                f'<sdk-repository><localPackage path="{IMAGE}"/><localPackage path="{IMAGE}"/></sdk-repository>',
            ):
                metadata.write_text(document)
                with self.subTest(document=document), self.assertRaisesRegex(PreflightError, "missing or ambiguous"):
                    safe_avd_environment(str(sdk), str(avd_home), IMAGE)
            with self.assertRaisesRegex(PreflightError, "exact SDK package"):
                safe_avd_environment(str(sdk), str(avd_home), "system-images;android-29;..;x86_64")

    def test_cli_is_read_only_and_emits_launch_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sdk, avd_home = root / "sdk", root / "avds"
            add_sdk_tools(sdk)
            add_image(sdk)
            avd_home.mkdir()
            result = subprocess.run(
                [sys.executable, str(Path(__file__).with_name("android_avd_sdk_preflight.py")),
                 "--sdk-root", str(sdk), "--avd-home", str(avd_home), "--system-image", IMAGE],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            environment = json.loads(result.stdout)["environment"]
            self.assertEqual(str(avd_home.resolve()), environment["ANDROID_AVD_HOME"])

    def test_symlinked_avdmanager_is_rejected_before_any_sdk_tool_can_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            if not symlink_probe_available(root):
                self.skipTest("symlink creation is unavailable on this platform")
            sdk, foreign, avd_home = root / "user-sdk", root / "foreign-sdk", root / "private-avds"
            marker = root / "foreign-avdmanager-launched"
            add_sdk_tools(foreign, f'touch "{marker}"\nexit 0')
            executable(sdk / "emulator/emulator", "exit 0")
            target = foreign / "cmdline-tools/latest/bin/avdmanager"
            link = sdk / "cmdline-tools/latest/bin/avdmanager"
            link.parent.mkdir(parents=True)
            link.symlink_to(target)
            add_image(sdk)
            avd_home.mkdir()

            with self.assertRaisesRegex(PreflightError, "resolves outside intended SDK root"):
                safe_avd_environment(str(sdk), str(avd_home), IMAGE)

            self.assertFalse(marker.exists(), "preflight must reject before launching avdmanager")

    @unittest.skipIf(os.name == "nt", "requires POSIX executable shell wrappers")
    def test_real_wrapper_causality_sdkmanager_can_see_user_image_while_symlinked_avdmanager_cannot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            if not symlink_probe_available(root):
                self.skipTest("symlink creation is unavailable on this platform")
            sdk, foreign, avd_home = root / "user-sdk", root / "foreign-sdk", root / "private-avds"
            add_sdk_tools(foreign, 'derived="$(python3 -c \'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve().parents[3])\' "$0")"\n'
                                     f'test -f "$derived/{"/".join(IMAGE.split(";"))}/package.xml"')
            executable(sdk / "emulator/emulator", "exit 0")
            avd = sdk / "cmdline-tools/latest/bin/avdmanager"
            avd.parent.mkdir(parents=True)
            avd.symlink_to(foreign / "cmdline-tools/latest/bin/avdmanager")
            executable(sdk / "cmdline-tools/latest/bin/sdkmanager",
                       f'test -f "$2/{"/".join(IMAGE.split(";"))}/package.xml"')
            add_image(sdk)
            avd_home.mkdir()

            listed = subprocess.run([str(sdk / "cmdline-tools/latest/bin/sdkmanager"), "--sdk_root", str(sdk)], check=False)
            self.assertEqual(0, listed.returncode)
            wrong_root = subprocess.run([str(avd)], check=False)
            self.assertNotEqual(0, wrong_root.returncode)

            avd.unlink()
            add_sdk_tools(sdk, 'derived="$(python3 -c \'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve().parents[3])\' "$0")"\n'
                               f'test -f "$derived/{"/".join(IMAGE.split(";"))}/package.xml"')
            launch = safe_avd_environment(str(sdk), str(avd_home), IMAGE)
            correct_root = subprocess.run([launch["avdmanager"], "list", "avd"], env={**os.environ, **launch["environment"]}, check=False)
            self.assertEqual(0, correct_root.returncode)
            self.assertEqual(str(avd_home.resolve()), launch["environment"]["ANDROID_AVD_HOME"])


if __name__ == "__main__":
    unittest.main()

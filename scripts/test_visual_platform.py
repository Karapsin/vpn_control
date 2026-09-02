#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("visual_platform.py")
SPEC = importlib.util.spec_from_file_location("visual_platform", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
visual_platform = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = visual_platform
SPEC.loader.exec_module(visual_platform)


class VisualPlatformTest(unittest.TestCase):
    def test_manifest_routes_a_large_scene_set_to_each_platform(self) -> None:
        for platform in visual_platform.PLATFORMS:
            self.assertGreaterEqual(len(visual_platform.scenes_for(platform)), 50, platform)

    def test_hosted_capture_workflow_has_no_self_hosted_runner(self) -> None:
        workflow = (visual_platform.ROOT / ".github/workflows/visual-regression.yml").read_text(
            encoding="utf-8",
        )
        self.assertNotIn("self-hosted", workflow)
        for runner in ("ubuntu-24.04", "windows-2025", "macos-15"):
            self.assertIn(f"runs-on: {runner}", workflow)
        self.assertIn("name: Visual Capture", workflow)

    def test_hosted_fallback_cannot_replace_windows_secure_desktop(self) -> None:
        with mock.patch.object(
            visual_platform,
            "local_probe",
            return_value={"ready": False, "backend": "", "capabilities": [], "detail": "missing"},
        ):
            plan = visual_platform.capture_plan("windows")
        self.assertIn("windows-uac", plan["routes"]["blocked"])
        self.assertIn("main-disconnected", plan["routes"]["hosted"])
        self.assertFalse(plan["release_capable"])

    def test_ready_local_windows_vm_routes_every_scene_locally(self) -> None:
        with mock.patch.object(
            visual_platform,
            "local_probe",
            return_value={
                "ready": True,
                "backend": "qemu-windows",
                "capabilities": ["app", "native", "secure_desktop"],
                "detail": "",
            },
        ):
            plan = visual_platform.capture_plan("windows")
        self.assertFalse(plan["routes"]["hosted"])
        self.assertFalse(plan["routes"]["blocked"])
        self.assertTrue(plan["release_capable"])

    def test_android_bootstrap_dry_run_is_non_mutating(self) -> None:
        missing = {"ready": False, "backend": "", "capabilities": [], "detail": "missing"}
        with (
            mock.patch.object(visual_platform, "local_probe", return_value=missing),
            mock.patch.object(
                visual_platform,
                "bootstrap_commands",
                return_value=[["sdkmanager", "system-images;android-35;google_apis;x86_64"]],
            ),
            mock.patch.object(visual_platform, "_run") as run,
        ):
            result = visual_platform.bootstrap("android", dry_run=True)
        run.assert_not_called()
        self.assertIn("sdkmanager", result["commands"][0])

    def test_android_probe_requires_named_isolated_avd(self) -> None:
        with (
            mock.patch.object(visual_platform, "_android_tool", return_value="/sdk/tool"),
            mock.patch.object(visual_platform, "_android_avds", return_value={"some-personal-avd"}),
        ):
            probe = visual_platform.local_probe("android")
        self.assertFalse(probe["ready"])
        self.assertIn("vpn-control-visual-api35", probe["detail"])

    def test_android_start_never_reuses_unrelated_emulator(self) -> None:
        probe = {
            "ready": True,
            "backend": "android-emulator",
            "capabilities": ["app", "native"],
            "detail": "",
        }
        with (
            mock.patch.object(visual_platform, "local_probe", return_value=probe),
            mock.patch.object(visual_platform, "_android_tool", side_effect=lambda name: f"/sdk/{name}"),
            mock.patch.object(
                visual_platform,
                "_running_android_avds",
                return_value={"personal-avd": "emulator-5554"},
            ),
        ):
            result = visual_platform.start_platform("android", dry_run=True)
        self.assertTrue(result["started_by_agent"])
        self.assertIn("-avd vpn-control-visual-api35", result["command"])
        self.assertIn("-port 5580", result["command"])

    def test_windows_qemu_disk_is_not_ready_without_agent_marker(self) -> None:
        real_is_file = Path.is_file

        def is_file(path: Path) -> bool:
            if str(path).endswith("vpn-control-win11.qcow2"):
                return True
            if str(path).endswith("visual-vms/windows/READY"):
                return False
            return real_is_file(path)

        with (
            mock.patch.object(visual_platform.host_platform, "system", return_value="Darwin"),
            mock.patch.object(visual_platform.shutil, "which", return_value=None),
            mock.patch.object(visual_platform, "_which_any", return_value="/opt/qemu"),
            mock.patch.object(Path, "is_file", is_file),
        ):
            probe = visual_platform.local_probe("windows")
        self.assertFalse(probe["ready"])
        self.assertIn("has not passed", probe["detail"])

    def test_local_driver_requires_complete_requested_scene_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            completed = mock.Mock(returncode=0)
            with (
                mock.patch.object(visual_platform.subprocess, "run", return_value=completed),
                mock.patch.object(visual_platform, "_head_sha", return_value="a" * 40),
                mock.patch.object(
                    visual_platform,
                    "scenes_for",
                    return_value=[{"id": "one", "platforms": ["linux"], "geometry_required": False}],
                ),
            ):
                with self.assertRaises(visual_platform.VisualPlatformError):
                    visual_platform.run_local_driver("linux", "/opt/capture", output, ["one"])

    def test_capture_stamp_binds_files_and_exact_sha(self) -> None:
        sha = "a" * 40
        scenes = [{"id": "one", "platforms": ["linux"], "geometry_required": True}]
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            (output / "one.png").write_bytes(b"png")
            (output / "one.geometry.json").write_text("{}", encoding="utf-8")
            with mock.patch.object(visual_platform, "scenes_for", return_value=scenes):
                visual_platform.stamp_capture("linux", sha, "local", output, ["one"])
                paths = visual_platform.verify_capture_provenance("linux", sha, output)
                self.assertEqual([output / "capture-local.json"], paths)
                (output / "one.png").write_bytes(b"changed")
                with self.assertRaisesRegex(visual_platform.VisualPlatformError, "changed after stamping"):
                    visual_platform.verify_capture_provenance("linux", sha, output)

    def test_capture_provenance_rejects_other_sha(self) -> None:
        scenes = [{"id": "one", "platforms": ["linux"], "geometry_required": False}]
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            (output / "one.png").write_bytes(b"png")
            with mock.patch.object(visual_platform, "scenes_for", return_value=scenes):
                visual_platform.stamp_capture("linux", "a" * 40, "hosted", output, ["one"])
                with self.assertRaisesRegex(visual_platform.VisualPlatformError, "does not match target"):
                    visual_platform.verify_capture_provenance("linux", "b" * 40, output)

    def test_android_tool_discovers_repository_host_sdk_layout(self) -> None:
        with (
            mock.patch.object(visual_platform.shutil, "which", return_value=None),
            mock.patch.dict(os.environ, {"ANDROID_HOME": "/sdk"}, clear=True),
            mock.patch.object(Path, "is_file", return_value=True),
        ):
            self.assertEqual(
                str(Path("/sdk") / "platform-tools" / "adb"),
                visual_platform._android_tool("adb"),
            )

    def test_stop_never_touches_environment_that_predated_agent(self) -> None:
        with (
            mock.patch.object(
                visual_platform,
                "_read_state",
                return_value={
                    "platform": "windows",
                    "backend": "libvirt-windows",
                    "identifier": "vpn-control-win11",
                    "started_by_agent": False,
                },
            ),
            mock.patch.object(visual_platform, "_run") as run,
        ):
            result = visual_platform.stop_platform("windows")
        run.assert_not_called()
        self.assertFalse(result["stopped"])

    def test_stop_uses_scoped_vm_command_for_agent_owned_environment(self) -> None:
        state = {
            "platform": "windows",
            "backend": "libvirt-windows",
            "identifier": "vpn-control-win11",
            "started_by_agent": True,
        }
        with (
            mock.patch.object(visual_platform, "_read_state", return_value=state),
            mock.patch.object(visual_platform, "_run", return_value=mock.Mock(returncode=0, stderr="")) as run,
            mock.patch.object(Path, "unlink"),
        ):
            result = visual_platform.stop_platform("windows")
        run.assert_called_once_with(["virsh", "shutdown", "vpn-control-win11"], timeout=120, input_text=None)
        self.assertTrue(result["stopped"])

    def test_hosted_download_selects_exact_sha_title(self) -> None:
        sha = "a" * 40
        listed = mock.Mock(
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "databaseId": 7,
                        "displayTitle": f"Visual Capture / linux / {sha}",
                        "headSha": sha,
                        "status": "completed",
                        "conclusion": "success",
                        "url": "https://example.invalid/7",
                    },
                ],
            ),
            stderr="",
        )
        downloaded = mock.Mock(returncode=0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(visual_platform, "_run", side_effect=[listed, downloaded]) as run:
                result = visual_platform.download_hosted("linux", sha, Path(temporary))
        self.assertEqual(7, result["run_id"])
        self.assertTrue(
            any(value.startswith("visual-capture-linux-") for value in run.call_args_list[1].args[0]),
        )

    def test_hosted_dispatch_excludes_secure_desktop_scenes(self) -> None:
        sha = "a" * 40
        plan = {
            "routes": {
                "hosted": ["main-disconnected", "windows-window-frame"],
                "local": [],
                "blocked": ["windows-uac"],
            },
        }
        completed = mock.Mock(returncode=0, stdout="", stderr="")
        with (
            mock.patch.object(visual_platform, "capture_plan", return_value=plan),
            mock.patch.object(visual_platform, "_run", return_value=completed) as run,
        ):
            result = visual_platform.dispatch_hosted("windows", sha, "dev")
        flattened = run.call_args.args[0]
        scenes = next(value for value in flattened if value.startswith("scenes="))
        self.assertNotIn("windows-uac", scenes)
        self.assertEqual(2, result["scene_count"])


if __name__ == "__main__":
    unittest.main()

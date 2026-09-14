#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import visual_regression


MODULE_PATH = Path(__file__).with_name("visual_platform.py")
SPEC = importlib.util.spec_from_file_location("visual_platform", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
visual_platform = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = visual_platform
SPEC.loader.exec_module(visual_platform)

SELECTOR_PATH = Path(__file__).with_name("select_visual_scenes.py")
SELECTOR_SPEC = importlib.util.spec_from_file_location("select_visual_scenes", SELECTOR_PATH)
assert SELECTOR_SPEC is not None and SELECTOR_SPEC.loader is not None
select_visual_scenes = importlib.util.module_from_spec(SELECTOR_SPEC)
sys.modules[SELECTOR_SPEC.name] = select_visual_scenes
SELECTOR_SPEC.loader.exec_module(select_visual_scenes)

WINDOWS_QEMU_CAPTURE_PATH = Path(__file__).with_name("capture_visual_windows_qemu.py")
WINDOWS_QEMU_CAPTURE_SPEC = importlib.util.spec_from_file_location(
    "capture_visual_windows_qemu",
    WINDOWS_QEMU_CAPTURE_PATH,
)
assert WINDOWS_QEMU_CAPTURE_SPEC is not None and WINDOWS_QEMU_CAPTURE_SPEC.loader is not None
capture_visual_windows_qemu = importlib.util.module_from_spec(WINDOWS_QEMU_CAPTURE_SPEC)
sys.modules[WINDOWS_QEMU_CAPTURE_SPEC.name] = capture_visual_windows_qemu
WINDOWS_QEMU_CAPTURE_SPEC.loader.exec_module(capture_visual_windows_qemu)

MACOS_TART_CAPTURE_PATH = Path(__file__).with_name("capture_visual_macos_tart.py")
MACOS_TART_CAPTURE_SPEC = importlib.util.spec_from_file_location(
    "capture_visual_macos_tart",
    MACOS_TART_CAPTURE_PATH,
)
assert MACOS_TART_CAPTURE_SPEC is not None and MACOS_TART_CAPTURE_SPEC.loader is not None
capture_visual_macos_tart = importlib.util.module_from_spec(MACOS_TART_CAPTURE_SPEC)
sys.modules[MACOS_TART_CAPTURE_SPEC.name] = capture_visual_macos_tart
MACOS_TART_CAPTURE_SPEC.loader.exec_module(capture_visual_macos_tart)


def _posix_bash() -> str:
    """Return the Git Bash executable on Windows, never the WSL launcher."""
    if os.name != "nt":
        bash = shutil.which("bash")
        if bash:
            return bash
        raise AssertionError("bash is required to exercise the Android visual capture wrapper")
    candidates = []
    configured = os.environ.get("BASH", "").strip()
    if configured:
        candidates.append(Path(configured))
    for root_name in ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"):
        root = os.environ.get(root_name, "").strip()
        if root:
            candidates.extend((Path(root) / "Git" / "bin" / "bash.exe", Path(root) / "Git" / "usr" / "bin" / "bash.exe"))
    for candidate in candidates:
        if candidate.is_file() and "git" in str(candidate).lower():
            return str(candidate)
    raise AssertionError("Git Bash is required to exercise the Android visual capture wrapper on Windows")


def _shell_failure(completed: subprocess.CompletedProcess[str]) -> str:
    return (
        f"returncode={completed.returncode}; stdout={completed.stdout!r}; "
        f"stderr={completed.stderr!r}"
    )


class VisualPlatformTest(unittest.TestCase):
    def test_json_provenance_hash_is_independent_of_checkout_line_endings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            crlf = Path(temporary) / "crlf.json"
            lf = Path(temporary) / "lf.json"
            crlf.write_bytes(b'{\r\n  "b": 2,\r\n  "a": 1\r\n}\r\n')
            lf.write_text('{"a":1,"b":2}\n', encoding="utf-8")
            self.assertNotEqual(visual_platform._file_hash(crlf), visual_platform._file_hash(lf))
            self.assertEqual(visual_platform._json_hash(crlf), visual_platform._json_hash(lf))

    def test_desktop_scene_selection_keeps_app_and_native_capture_disjoint(self) -> None:
        manifest = visual_platform.ROOT / "visual-tests/scenes.json"
        for platform in ("linux", "windows", "macos"):
            app = select_visual_scenes.select_scene_ids(manifest, platform, "app")
            native = select_visual_scenes.select_scene_ids(manifest, platform, "native")
            expected = {str(scene["id"]) for scene in visual_platform.scenes_for(platform)}
            self.assertFalse(set(app) & set(native), platform)
            self.assertEqual(expected, set(app) | set(native), platform)
            self.assertGreaterEqual(len(native), 8, platform)

    def test_desktop_scene_selection_rejects_unknown_requested_scene(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown linux visual scenes"):
            select_visual_scenes.select_scene_ids(
                visual_platform.ROOT / "visual-tests/scenes.json",
                "linux",
                "app",
                "main-disconnected,not-a-scene",
            )

    def test_native_file_dialogs_use_an_empty_synthetic_directory(self) -> None:
        source = (
            visual_platform.ROOT
            / "desktopApp/src/test/kotlin/com/kardinal/vpncontrol/desktop/DesktopNativeVisualCaptureTest.kt"
        ).read_text(encoding="utf-8")
        self.assertIn('"vpn-control-visual-files"', source)
        self.assertIn("if (save) FileDialog.SAVE else FileDialog.LOAD", source)
        self.assertIn('check(completed.await(10, TimeUnit.SECONDS))', source)
        self.assertIn('check(!dialog.isShowing)', source)
        self.assertIn('System.getProperty("user.home"), ".vpn-control-visual-fixture"', source)
        self.assertIn('fixtureRoot.resolve("container").resolve("vpn-control-visual-files")', source)
        self.assertIn('if (platform == "macos")', source)
        self.assertIn('System.getProperty("java.io.tmpdir"), "vpn-control-visual-files"', source)

    def test_awt_tray_capture_fails_closed_until_the_menu_is_visible(self) -> None:
        source = (
            visual_platform.ROOT
            / "desktopApp/src/test/kotlin/com/kardinal/vpncontrol/desktop/DesktopNativeVisualCaptureTest.kt"
        ).read_text(encoding="utf-8")
        tray_source = (
            visual_platform.ROOT
            / "desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopTray.kt"
        ).read_text(encoding="utf-8")
        self.assertIn('sceneId.startsWith("linux-") -> bounds.width / 2 to 400', source)
        self.assertIn('sceneId.startsWith("windows-") -> bounds.width / 2 to 400', source)
        self.assertIn('sceneId.startsWith("macos-") -> bounds.width / 2 to 530', source)
        self.assertIn('it.name == "vpn-control-tray-menu" && it.isShowing', source)
        self.assertIn('checkNotNull(popup) { "VPN Control tray menu did not become visible for capture" }', source)
        self.assertIn('captureVisibleSurface(output, bounds)', source)
        self.assertIn('System.setProperty("vpn.control.trayPopupAutoHideMillis", "120000")', source)
        self.assertIn('System.getProperty("vpn.control.trayPopupAutoHideMillis")', tray_source)
        self.assertIn('.coerceIn(1_000, 120_000)', tray_source)

    def test_tart_driver_captures_menu_bar_surfaces_from_the_external_framebuffer(self) -> None:
        source = (visual_platform.ROOT / "scripts/capture_visual_macos_tart.py").read_text(
            encoding="utf-8",
        )
        self.assertIn('MENU_BAR_SCENES = ("macos-menu-bar-disconnected", "macos-menu-bar-connected")', source)
        self.assertIn("capture_external_framebuffer_scenes", source)

    def test_android_camera_capture_allows_for_cold_camera_startup(self) -> None:
        source = (
            visual_platform.ROOT
            / "app/src/androidTest/java/com/kardinal/vpncontrol/ui/VisualCaptureInstrumentedTest.kt"
        ).read_text(encoding="utf-8")
        self.assertIn('"android-camera-qr", "android-package-installer" -> 30_000L', source)

    def test_android_package_installer_allows_for_cold_startup(self) -> None:
        source = (
            visual_platform.ROOT
            / "app/src/androidTest/java/com/kardinal/vpncontrol/ui/VisualCaptureInstrumentedTest.kt"
        ).read_text(encoding="utf-8")
        self.assertIn('"android-camera-qr", "android-package-installer" -> 30_000L', source)

    def test_android_native_surface_stays_open_for_host_framebuffer_capture(self) -> None:
        source = (
            visual_platform.ROOT
            / "app/src/androidTest/java/com/kardinal/vpncontrol/ui/VisualCaptureInstrumentedTest.kt"
        ).read_text(encoding="utf-8")
        self.assertIn("waitForHostFramebufferCapture(sceneId, remoteOutput, instrumentation)", source)
        self.assertIn("NATIVE_HOST_CAPTURE_TIMEOUT_MILLIS = 60_000L", source)
        self.assertIn("NATIVE_SURFACE_SETTLE_MILLIS = 5_000L", source)
        self.assertIn("SystemClock.sleep(NATIVE_SURFACE_SETTLE_MILLIS)", source)
        self.assertIn('touch $remoteOutput/$sceneId.ready', source)
        self.assertIn('File(remoteOutput, "$sceneId.captured")', source)
        self.assertIn('onNodeWithTag("main-scroll"', source)

    def test_android_qr_capture_requires_visible_scanner_chrome(self) -> None:
        source = (
            visual_platform.ROOT
            / "app/src/androidTest/java/com/kardinal/vpncontrol/ui/VisualCaptureInstrumentedTest.kt"
        ).read_text(encoding="utf-8")
        activity = (
            visual_platform.ROOT / "app/src/main/java/com/kardinal/vpncontrol/QrCaptureActivity.kt"
        ).read_text(encoding="utf-8")
        layout = (
            visual_platform.ROOT / "app/src/main/res/layout/zxing_capture.xml"
        ).read_text(encoding="utf-8")
        self.assertIn('assertCameraScannerChrome(File(output, "$sceneId.png"))', source)
        self.assertIn("QR scanner chrome was not visible", source)
        self.assertIn("QR scanner visual capture leaked status-bar chrome", source)
        self.assertIn("override fun onWindowFocusChanged", activity)
        self.assertIn("override fun onResume", activity)
        self.assertIn("WindowManager.LayoutParams.FLAG_FULLSCREEN", activity)
        self.assertIn("View.SYSTEM_UI_FLAG_FULLSCREEN", activity)
        self.assertIn("window.setDecorFitsSystemWindows(false)", activity)
        self.assertIn("window.insetsController?.hide(WindowInsets.Type.statusBars())", activity)
        self.assertIn("FULLSCREEN_REASSERT_DELAYS_MILLIS", activity)
        self.assertIn('android:text="Scan QR code"', layout)
        self.assertIn("@drawable/qr_scanner_frame", layout)
        self.assertIn("QrCaptureActivity", source)
        self.assertIn("EXTRA_VISUAL_CAPTURE", source)

    def test_android_native_captures_reapply_the_frozen_system_fixture(self) -> None:
        source = (
            visual_platform.ROOT / "scripts/capture_visual_android.sh"
        ).read_text(encoding="utf-8")
        native_loop = source.split('for native_scene in "${native_scene_ids[@]}"; do', 1)[1]
        self.assertIn('command exit', native_loop)
        self.assertNotIn('command enter', native_loop)
        self.assertIn('$device_dir/$native_scene.ready', native_loop)
        self.assertIn('$device_dir/$native_scene.captured', native_loop)

    def test_android_qr_native_capture_retries_once_after_a_fail_closed_attempt(self) -> None:
        source = (visual_platform.ROOT / "scripts/capture_visual_android.sh").read_text(
            encoding="utf-8",
        )
        native_loop = source.split('for native_scene in "${native_scene_ids[@]}"; do', 1)[1]
        self.assertIn('[[ "$native_scene" == "android-camera-qr" ]] && max_capture_attempts=2', native_loop)
        self.assertIn('Retrying $native_scene after its first fail-closed capture attempt.', native_loop)
        self.assertIn('if [[ "$native_scene" == "android-camera-qr" ]]; then', native_loop)
        self.assertIn('am force-stop com.kardinal.vpncontrol', native_loop)
        self.assertIn('$device_dir/$native_scene.ready', native_loop)
        self.assertIn('$device_dir/$native_scene.captured', native_loop)

    def test_android_visual_fixture_resets_demo_mode_before_each_scene(self) -> None:
        source = (
            visual_platform.ROOT
            / "app/src/androidTest/java/com/kardinal/vpncontrol/ui/VisualCaptureInstrumentedTest.kt"
        ).read_text(encoding="utf-8")
        fixture = source.split("private fun freezeSystemUi", 1)[1]
        self.assertLess(fixture.index("command exit"), fixture.index("command enter"))
        self.assertGreaterEqual(fixture.count("command network -e airplane hide -e wifi show"), 2)
        self.assertIn("SystemClock.sleep(250L)", fixture)

    def test_android_settings_version_comes_from_visual_state(self) -> None:
        app_source = (
            visual_platform.ROOT / "app/src/main/java/com/kardinal/vpncontrol/ui/VpnControlApp.kt"
        ).read_text(encoding="utf-8")
        fixture_source = (
            visual_platform.ROOT
            / "app/src/androidTest/java/com/kardinal/vpncontrol/ui/VisualCaptureInstrumentedTest.kt"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "state.appUpdate.currentVersion.ifBlank { BuildConfig.VERSION_NAME }",
            app_source,
        )
        base_fixture = fixture_source.split("var state = MainUiState(", 1)[1].split(")\n    state = when", 1)[0]
        self.assertIn('currentVersion = "2.0.0"', base_fixture)

    def test_desktop_settings_version_comes_from_visual_state(self) -> None:
        app_source = (
            visual_platform.ROOT / "desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/Main.kt"
        ).read_text(encoding="utf-8")
        fixture_source = (
            visual_platform.ROOT
            / "desktopApp/src/test/kotlin/com/kardinal/vpncontrol/desktop/VisualCaptureTest.kt"
        ).read_text(encoding="utf-8")
        self.assertIn("state.appUpdate.currentVersion.ifBlank", app_source)
        self.assertIn("DesktopBuildInfo.current().displayVersion", app_source)
        base_fixture = fixture_source.split("var state = MainUiState(", 1)[1].split(")\n\n    state = when", 1)[0]
        self.assertIn('currentVersion = "2.0.0"', base_fixture)

    def test_android_visual_qr_exports_freeze_the_payload_timestamp(self) -> None:
        activity = (
            visual_platform.ROOT / "app/src/main/java/com/kardinal/vpncontrol/MainActivity.kt"
        ).read_text(encoding="utf-8")
        ui = (
            visual_platform.ROOT / "app/src/main/java/com/kardinal/vpncontrol/ui/VpnControlApp.kt"
        ).read_text(encoding="utf-8")
        self.assertIn('VISUAL_EXPORT_TIMESTAMP = "2023-11-14T22:13:20Z"', activity)
        self.assertIn("LocalVisualExportTimestamp provides", activity)
        self.assertIn("LocationConfigs.export(state.currentLocations, exportedAt)", ui)
        self.assertIn("RoutingRulesTransfer.export(", ui)

    def test_android_visual_fixture_waits_for_recreation_and_refreezes_system_ui(self) -> None:
        source = (
            visual_platform.ROOT
            / "app/src/androidTest/java/com/kardinal/vpncontrol/ui/VisualCaptureInstrumentedTest.kt"
        ).read_text(encoding="utf-8")
        self.assertIn("SystemClock.sleep(1_000L)", source)
        self.assertIn("freezeSystemUi(instrumentation)", source)
        self.assertIn('command clock -e hhmm 1200', source)
        self.assertIn('command network -e airplane hide -e wifi show', source)
        self.assertIn('command status -e volume hide', source)

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

    def test_android_task_avd_override_requires_a_complete_safe_pair(self) -> None:
        for environment in (
            {"VPN_CONTROL_VISUAL_ANDROID_AVD_NAME": "vpn-control-visual-task-cancelled"},
            {"VPN_CONTROL_VISUAL_ANDROID_PORT": "5600"},
            {
                "VPN_CONTROL_VISUAL_ANDROID_AVD_NAME": "vpn-control-visual-task-cancelled",
                "VPN_CONTROL_VISUAL_ANDROID_PORT": "5580",
            },
            {
                "VPN_CONTROL_VISUAL_ANDROID_AVD_NAME": "personal-avd",
                "VPN_CONTROL_VISUAL_ANDROID_PORT": "5600",
            },
            {
                "VPN_CONTROL_VISUAL_ANDROID_AVD_NAME": "vpn-control-visual-task-cancelled",
                "VPN_CONTROL_VISUAL_ANDROID_PORT": "5601",
            },
        ):
            with self.subTest(environment=environment), mock.patch.dict(os.environ, environment, clear=True):
                with self.assertRaisesRegex(visual_platform.VisualPlatformError, "Android visual task override"):
                    visual_platform.android_local_config()

    def test_android_task_avd_override_admits_an_isolated_even_port(self) -> None:
        environment = {
            "VPN_CONTROL_VISUAL_ANDROID_AVD_NAME": "vpn-control-visual-task-cancelled",
            "VPN_CONTROL_VISUAL_ANDROID_PORT": "5600",
        }
        with mock.patch.dict(os.environ, environment, clear=True):
            config = visual_platform.android_local_config()
        self.assertEqual("vpn-control-visual-task-cancelled", config["avd_name"])
        self.assertEqual(5600, config["emulator_port"])

    def test_android_task_avd_override_flows_through_probe_and_bootstrap(self) -> None:
        environment = {
            "VPN_CONTROL_VISUAL_ANDROID_AVD_NAME": "vpn-control-visual-task-cancelled",
            "VPN_CONTROL_VISUAL_ANDROID_PORT": "5600",
        }
        with (
            mock.patch.dict(os.environ, environment, clear=True),
            mock.patch.object(visual_platform, "_android_tool", return_value="/sdk/tool"),
            mock.patch.object(
                visual_platform,
                "_android_avds",
                return_value={"vpn-control-visual-task-cancelled"},
            ),
        ):
            probe = visual_platform.local_probe("android")
            commands = visual_platform.bootstrap_commands("android")
        self.assertTrue(probe["ready"])
        self.assertIn("vpn-control-visual-task-cancelled", commands[1])

    def test_android_start_does_not_adopt_a_foreign_avd_on_the_task_port(self) -> None:
        probe = {
            "ready": True,
            "backend": "android-emulator",
            "capabilities": ["app", "native"],
            "detail": "",
        }
        environment = {
            "VPN_CONTROL_VISUAL_ANDROID_AVD_NAME": "vpn-control-visual-task-cancelled",
            "VPN_CONTROL_VISUAL_ANDROID_PORT": "5600",
        }
        with (
            mock.patch.dict(os.environ, environment, clear=True),
            mock.patch.object(visual_platform, "local_probe", return_value=probe),
            mock.patch.object(visual_platform, "_android_tool", side_effect=lambda name: f"/sdk/{name}"),
            mock.patch.object(
                visual_platform,
                "_running_android_avds",
                return_value={"personal-avd": "emulator-5600"},
            ),
        ):
            result = visual_platform.start_platform("android", dry_run=True)
        self.assertTrue(result["started_by_agent"])
        self.assertIn("-avd vpn-control-visual-task-cancelled", result["command"])
        self.assertIn("-port 5600", result["command"])
        self.assertNotIn("personal-avd", result["command"])

    def test_android_capture_resolves_isolation_before_selecting_adb(self) -> None:
        script = (visual_platform.ROOT / "scripts/capture_visual_android.sh").read_text(
            encoding="utf-8",
        )
        self.assertIn("android-local-config", script)
        self.assertLess(script.index("android-local-config"), script.index("command -v adb"))
        self.assertIn('adb emu avd name', script)
        self.assertIn('"$expected_avd_name"', script)
        self.assertIn('"$adb_bin" -s "$emulator_serial"', script)

    def test_android_capture_binds_gradle_and_cleanup_to_verified_task_device(self) -> None:
        script = (visual_platform.ROOT / "scripts/capture_visual_android.sh").read_text(
            encoding="utf-8",
        )
        guard = script.index('[[ "$avd_name" == "$expected_avd_name" ]]')
        trap = script.index("trap restore_system_ui EXIT")
        gradle = script.index("./gradlew :app:connectedDebugAndroidTest")
        self.assertLess(guard, trap)
        self.assertIn('ANDROID_SERIAL="$emulator_serial" ./gradlew', script)
        self.assertLess(trap, gradle)

    def test_android_capture_preserves_hosted_serial_selection(self) -> None:
        script = (visual_platform.ROOT / "scripts/capture_visual_android.sh").read_text(
            encoding="utf-8",
        )
        self.assertIn('VPN_CONTROL_VISUAL_PROVIDER:-local', script)
        self.assertIn('emulator_serial="${ANDROID_SERIAL:?Android hosted visual capture requires ANDROID_SERIAL}"', script)
        self.assertIn('if [[ "$provider" == "hosted" ]]; then', script)

    def test_android_capture_rejects_a_foreign_avd_before_any_device_mutation(self) -> None:
        self._assert_foreign_avd_guard()

    def test_android_capture_rejects_stale_owned_geometry_before_any_mutation_or_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            log = temporary_path / "adb.log"
            fake_adb = temporary_path / "adb"
            fake_adb.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$*\" >> \"$ADB_LOG\"\n"
                "if [ \"$3 $4 $5\" = 'emu avd name' ]; then\n"
                "  printf 'vpn-control-visual-task-cancelled\\nOK\\n'\n"
                "elif [ \"$3 $4 $5 $6\" = 'shell dumpsys window displays' ]; then\n"
                "  cat <<'DUMP'\n"
                "displayId=0\n"
                "  mDisplayFrame=Rect(0, 0 - 1080, 2400)\n"
                "  mDisplayCutout=DisplayCutout{insets=Rect(0, 128 - 0, 0)}\n"
                "    InsetsSource id=1 type=statusBars frame=[0,0][1080,63] visible=true flags= sideHint=TOP\n"
                "DUMP\n"
                "fi\n",
                encoding="utf-8",
                newline="\n",
            )
            fake_adb.chmod(0o755)
            self.assertNotIn(b"\r\n", fake_adb.read_bytes())
            output = temporary_path / "output"
            environment = dict(os.environ)
            environment.update({
                "PATH": f"{temporary}{os.pathsep}{environment['PATH']}",
                "ADB_LOG": str(log),
                "VPN_CONTROL_VISUAL_ANDROID_AVD_NAME": "vpn-control-visual-task-cancelled",
                "VPN_CONTROL_VISUAL_ANDROID_PORT": "5600",
            })
            completed = subprocess.run(
                [_posix_bash(), "scripts/capture_visual_android.sh", str(output), "update-install-session-cancelled"],
                cwd=visual_platform.ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(0, completed.returncode, _shell_failure(completed))
            self.assertIn("shorter than its cutout", completed.stderr, _shell_failure(completed))
            self.assertEqual(
                [
                    "-s emulator-5600 emu avd name",
                    "-s emulator-5600 shell dumpsys window displays",
                ],
                log.read_text(encoding="utf-8").splitlines(),
                _shell_failure(completed),
            )
            self.assertFalse(output.exists())

    def test_android_capture_handles_native_python_crlf_before_any_device_mutation(self) -> None:
        self._assert_foreign_avd_guard(python_crlf=True)

    def test_android_capture_removes_native_python_crlf_from_scene_arguments_after_device_guard(self) -> None:
        """The Git Bash wrapper must not pass CRLF scene IDs to Gradle or stamping."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "mini-repo"
            scripts = root / "scripts"
            visual_tests = root / "visual-tests"
            scripts.mkdir(parents=True)
            visual_tests.mkdir()
            for name in ("capture_visual_android.sh", "select_visual_scenes.py", "android_visual_geometry.py"):
                shutil.copy2(visual_platform.ROOT / "scripts" / name, scripts / name)
            (visual_tests / "scenes.json").write_text(json.dumps({"scenes": [
                {"id": "app-scene", "platforms": ["android"], "geometry_required": True},
                {"id": "android-system-bars", "platforms": ["android"], "geometry_required": False},
            ]}), encoding="utf-8")
            stamp_log = root / "stamp-arguments.bin"
            gradle_log = root / "gradle-arguments.bin"
            (scripts / "visual_platform.py").write_text(
                "import json, os, pathlib, sys\n"
                "if sys.argv[1] == 'android-local-config':\n"
                "    print(json.dumps({'result': {'avd_name': 'vpn-control-visual-task-cancelled', 'emulator_port': 5600}}))\n"
                "elif sys.argv[1] == 'stamp':\n"
                "    pathlib.Path(os.environ['STAMP_LOG']).write_bytes('\\0'.join(sys.argv[2:]).encode())\n",
                encoding="utf-8",
                newline="\n",
            )
            fake_adb = root / "adb"
            fake_adb.write_text(
                "#!/bin/sh\n"
                "if [ \"$3 $4 $5\" = 'emu avd name' ]; then printf 'vpn-control-visual-task-cancelled\\nOK\\n'; fi\n"
                "if [ \"$3 $4 $5 $6\" = 'shell dumpsys window displays' ]; then cat <<'DUMP'\n"
                "displayId=0\n  mDisplayFrame=Rect(0, 0 - 1080, 2400)\n"
                "  mDisplayCutout=DisplayCutout{insets=Rect(0, 63 - 0, 0)}\n"
                "    InsetsSource id=1 type=statusBars frame=[0,0][1080,63] visible=true flags= sideHint=TOP\nDUMP\nfi\n"
                "if [ \"$3\" = pull ]; then mkdir -p \"$5\"; : > \"$5/app-scene.png\"; : > \"$5/app-scene.geometry.json\"; : > \"$5/android-system-bars.png\"; fi\n",
                encoding="utf-8",
                newline="\n",
            )
            fake_gradle = root / "gradlew"
            fake_gradle.write_text("#!/bin/sh\nprintf '%s\\0' \"$@\" >> \"$GRADLE_LOG\"\n", encoding="utf-8", newline="\n")
            fake_python = root / "python3"
            fake_python.write_text(
                "#!/bin/sh\n"
                "\"$REAL_PYTHON\" \"$@\" | \"$REAL_PYTHON\" -c "
                "'import sys; sys.stdout.buffer.write(sys.stdin.buffer.read().replace(b\"\\r\\n\", b\"\\n\").replace(b\"\\n\", b\"\\r\\n\"))'\n",
                encoding="utf-8",
                newline="\n",
            )
            for executable in (fake_adb, fake_gradle, fake_python):
                executable.chmod(0o755)
            output = root / "output"
            stale_scene_geometry = output / "android-system-bars.geometry.json"
            output.mkdir()
            stale_scene_geometry.write_bytes(b"stale")
            environment = dict(os.environ)
            environment.update({
                "PATH": f"{root}{os.pathsep}{environment['PATH']}",
                "REAL_PYTHON": Path(sys.executable).as_posix(),
                "GRADLE_LOG": str(gradle_log),
                "STAMP_LOG": str(stamp_log),
                "VPN_CONTROL_VISUAL_TARGET_SHA": "a" * 40,
            })
            completed = subprocess.run(
                [_posix_bash(), "scripts/capture_visual_android.sh", str(output)], cwd=root, env=environment,
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(0, completed.returncode, _shell_failure(completed))
            self.assertFalse(stale_scene_geometry.exists(), _shell_failure(completed))
            self.assertNotIn(b"\r", gradle_log.read_bytes(), _shell_failure(completed))
            self.assertNotIn(b"\r", stamp_log.read_bytes(), _shell_failure(completed))
            gradle_arguments = gradle_log.read_bytes().split(b"\0")
            for scene in (b"app-scene", b"android-system-bars"):
                self.assertIn(b"-Pandroid.testInstrumentationRunnerArguments.visualScenes=" + scene, gradle_arguments)
            stamp_arguments = stamp_log.read_bytes().split(b"\0")
            self.assertEqual(
                [b"app-scene", b"android-system-bars"],
                [stamp_arguments[index + 1] for index, argument in enumerate(stamp_arguments) if argument == b"--scene"],
            )

    def _assert_foreign_avd_guard(self, *, python_crlf: bool = False) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            log = temporary_path / "adb.log"
            fake_adb = temporary_path / "adb"
            fake_adb.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$*\" >> \"$ADB_LOG\"\n"
                "if [ \"$3 $4 $5\" = 'emu avd name' ]; then\n"
                "  printf 'foreign-avd\\nOK\\n'\n"
                "fi\n",
                encoding="utf-8",
                newline="\n",
            )
            fake_adb.chmod(0o755)
            self.assertNotIn(b"\r\n", fake_adb.read_bytes())
            environment = dict(os.environ)
            environment.update({
                "PATH": f"{temporary}{os.pathsep}{environment['PATH']}",
                "ADB_LOG": str(log),
                "VPN_CONTROL_VISUAL_ANDROID_AVD_NAME": "vpn-control-visual-task-cancelled",
                "VPN_CONTROL_VISUAL_ANDROID_PORT": "5600",
            })
            if python_crlf:
                fake_python = temporary_path / "python3"
                fake_python.write_text(
                    '#!/bin/sh\n'
                    '\"$REAL_PYTHON\" \"$@\" | \"$REAL_PYTHON\" -c '
                    "'import sys; sys.stdout.buffer.write(sys.stdin.buffer.read().replace(b\"\\r\\n\", b\"\\n\").replace(b\"\\n\", b\"\\r\\n\"))'\n",
                    encoding="utf-8", newline="\n",
                )
                fake_python.chmod(0o755)
                environment["REAL_PYTHON"] = Path(sys.executable).as_posix()
            completed = subprocess.run(
                [_posix_bash(), "scripts/capture_visual_android.sh", str(temporary_path / "output"), "update-install-session-cancelled"],
                cwd=visual_platform.ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(0, completed.returncode, _shell_failure(completed))
            self.assertTrue(log.is_file(), _shell_failure(completed))
            self.assertEqual(
                ["-s emulator-5600 emu avd name"],
                log.read_text(encoding="utf-8").splitlines(),
                _shell_failure(completed),
            )
            self.assertFalse((temporary_path / "output").exists())

    def test_android_capture_rejects_hosted_without_a_serial_before_adb(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            log = temporary_path / "adb.log"
            fake_adb = temporary_path / "adb"
            fake_adb.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$*\" >> \"$ADB_LOG\"\n",
                encoding="utf-8",
                newline="\n",
            )
            fake_adb.chmod(0o755)
            self.assertNotIn(b"\r\n", fake_adb.read_bytes())
            environment = dict(os.environ)
            environment.update({
                "PATH": f"{temporary}{os.pathsep}{environment['PATH']}",
                "ADB_LOG": str(log),
                "VPN_CONTROL_VISUAL_PROVIDER": "hosted",
            })
            environment.pop("ANDROID_SERIAL", None)
            environment.pop("VPN_CONTROL_VISUAL_ANDROID_AVD_NAME", None)
            environment.pop("VPN_CONTROL_VISUAL_ANDROID_PORT", None)
            completed = subprocess.run(
                [_posix_bash(), "scripts/capture_visual_android.sh", str(temporary_path / "output"), "update-install-session-cancelled"],
                cwd=visual_platform.ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(0, completed.returncode, _shell_failure(completed))
            self.assertIn("requires ANDROID_SERIAL", completed.stderr, _shell_failure(completed))
            self.assertFalse(log.exists())
            self.assertFalse((temporary_path / "output").exists())

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

    def test_started_vm_processes_are_detached_from_cli_session(self) -> None:
        source = (visual_platform.ROOT / "scripts/visual_platform.py").read_text(encoding="utf-8")
        self.assertIn("start_new_session=True", source)

    def test_android_capture_freezes_clock_and_uses_synchronous_framebuffer(self) -> None:
        script = (visual_platform.ROOT / "scripts/capture_visual_android.sh").read_text(
            encoding="utf-8",
        )
        fixture = (
            visual_platform.ROOT
            / "app/src/androidTest/java/com/kardinal/vpncontrol/ui/VisualCaptureInstrumentedTest.kt"
        ).read_text(encoding="utf-8")
        self.assertIn("settings put global sysui_demo_allowed 1", script)
        self.assertIn("command clock -e hhmm 1200", fixture)
        self.assertIn("command notifications -e visible false", fixture)
        self.assertIn("exec-out screencap -p", script)
        self.assertNotIn("emu screenrecord screenshot", script)

    def test_macos_start_dry_run_does_not_change_vm_configuration(self) -> None:
        probe = {
            "ready": True,
            "backend": "tart-macos",
            "capabilities": ["app", "native", "secure_desktop"],
            "detail": "",
        }
        stopped = mock.Mock(returncode=0, stdout="vpn-control-visual-macos stopped\n", stderr="")
        with (
            mock.patch.object(visual_platform, "local_probe", return_value=probe),
            mock.patch.object(visual_platform, "_run", return_value=stopped) as run,
        ):
            result = visual_platform.start_platform("macos", dry_run=True)
        run.assert_called_once_with(["tart", "list"], timeout=30)
        self.assertTrue(result["started_by_agent"])
        self.assertIn("tart run --no-graphics", result["command"])
        self.assertIn("--dir", result["command"])
        self.assertIn("vpn-control-visual-macos", result["command"])
        self.assertNotIn("--vnc", result["command"])

    def test_resource_denial_happens_before_tart_configuration_or_process_start(self) -> None:
        probe = {
            "ready": True,
            "backend": "tart-macos",
            "capabilities": ["app", "native", "secure_desktop"],
            "detail": "",
        }
        stopped = mock.Mock(returncode=0, stdout="vpn-control-visual-macos stopped\n", stderr="")
        with (
            mock.patch.object(visual_platform, "local_probe", return_value=probe),
            mock.patch.object(visual_platform, "_run", return_value=stopped) as run,
            mock.patch.object(visual_platform, "_tart_memory_mib", return_value=8192),
            mock.patch.object(
                visual_platform,
                "_admit_visual_start",
                side_effect=visual_platform.VisualPlatformError("visual VM start deferred: slot limit"),
            ),
            mock.patch.object(visual_platform.subprocess, "Popen") as popen,
        ):
            with self.assertRaisesRegex(visual_platform.VisualPlatformError, "slot limit"):
                visual_platform.start_platform("macos")
        popen.assert_not_called()
        self.assertFalse(any(call.args and call.args[0][:2] == ["tart", "set"] for call in run.call_args_list))

    def test_resource_parsers_accept_native_tart_and_libvirt_formats(self) -> None:
        self.assertEqual(8192, visual_platform._memory_mib("8388608 KiB"))
        self.assertEqual(4, visual_platform._memory_mib("4096 kB"))

        def tart_run(command, **_kwargs):
            if command[:3] == ["tart", "list", "--format"]:
                return mock.Mock(returncode=0, stdout='[{"Name":"fixture","State":"running"}]', stderr="")
            self.assertEqual(["tart", "get", "fixture", "--format", "json"], command)
            return mock.Mock(returncode=0, stdout='{"Memory":4096}', stderr="")

        with mock.patch.object(visual_platform, "_run", side_effect=tart_run):
            self.assertEqual([4096], visual_platform._tart_running_allocations())
        with mock.patch.object(
            visual_platform,
            "_run",
            return_value=mock.Mock(returncode=0, stdout="Max memory:     8388608 KiB\nUsed memory:    1048576 KiB\n", stderr=""),
        ):
            self.assertEqual(8192, visual_platform._libvirt_memory_mib("vpn-control-win11"))

    def test_malformed_resource_policy_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            policy = Path(temporary) / "resource-policy.json"
            for value, message in (('{"max_local_vms":"unbounded"}', "invalid max_local_vms"), ("[]", "JSON object"), ("null", "JSON object"), ('"bad"', "JSON object")):
                with self.subTest(value=value):
                    policy.write_text(value, encoding="utf-8")
                    with (
                        mock.patch.object(visual_platform, "RESOURCE_POLICY_PATH", policy),
                        mock.patch.dict(os.environ, {"VPN_CONTROL_VM_RESOURCE_POLICY": ""}, clear=False),
                    ):
                        with self.assertRaisesRegex(visual_platform.VisualPlatformError, message):
                            visual_platform._resource_policy()
            missing = Path(temporary) / "missing.json"
            with mock.patch.dict(os.environ, {"VPN_CONTROL_VM_RESOURCE_POLICY": str(missing)}, clear=False):
                with self.assertRaisesRegex(visual_platform.VisualPlatformError, "does not exist"):
                    visual_platform._resource_policy()

    def test_resource_reservation_rejects_same_platform_and_malformed_top_level(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reservations = root / "reservations.json"
            with (
                mock.patch.object(visual_platform, "RUNTIME_ROOT", root),
                mock.patch.object(visual_platform, "RESOURCE_RESERVATIONS_PATH", reservations),
                mock.patch.object(visual_platform, "RESOURCE_LOCK_PATH", root / "reservation.lock"),
                mock.patch.object(visual_platform, "_resource_lock", side_effect=contextlib.nullcontext),
                mock.patch.object(visual_platform.host_platform, "system", return_value="Linux"),
                mock.patch.object(visual_platform, "_host_memory_snapshot", return_value={
                    "physical_mib": 32768, "available_mib": 20000, "swap_used_mib": 0, "pressure_critical": False,
                }),
            ):
                visual_platform._admit_visual_start("windows", 4096)
                with self.assertRaisesRegex(visual_platform.VisualPlatformError, "already has a live or pending"):
                    visual_platform._admit_visual_start("windows", 4096)
                for invalid in ("[]", "null", '"bad"'):
                    reservations.write_text(invalid, encoding="utf-8")
                    with self.assertRaisesRegex(visual_platform.VisualPlatformError, "malformed VM reservations"):
                        visual_platform._read_reservations()

    def test_low_available_memory_denies_before_visual_start(self) -> None:
        probe = {"ready": True, "backend": "tart-macos", "capabilities": ["app"], "detail": ""}
        stopped = mock.Mock(returncode=0, stdout="vpn-control-visual-macos stopped\n", stderr="")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                mock.patch.object(visual_platform, "RUNTIME_ROOT", root),
                mock.patch.object(visual_platform, "RESOURCE_POLICY_PATH", root / "policy.json"),
                mock.patch.object(visual_platform, "RESOURCE_RESERVATIONS_PATH", root / "reservations.json"),
                mock.patch.object(visual_platform, "RESOURCE_LOCK_PATH", root / "reservation.lock"),
                mock.patch.object(visual_platform, "_resource_lock", side_effect=contextlib.nullcontext),
                mock.patch.object(visual_platform, "local_probe", return_value=probe),
                mock.patch.object(visual_platform, "_run", return_value=stopped) as run,
                mock.patch.object(visual_platform, "_tart_memory_mib", return_value=8192),
                mock.patch.object(visual_platform, "_tart_running_allocations", return_value=[]),
                mock.patch.object(visual_platform.host_platform, "system", return_value="Darwin"),
                mock.patch.object(visual_platform, "_host_memory_snapshot", return_value={
                    "physical_mib": 32768, "available_mib": 1024, "swap_used_mib": 0, "pressure_critical": False,
                }),
                mock.patch.object(visual_platform.subprocess, "Popen") as popen,
            ):
                with self.assertRaisesRegex(visual_platform.VisualPlatformError, "available host memory"):
                    visual_platform.start_platform("macos")
            popen.assert_not_called()
            self.assertFalse(any(call.args and call.args[0][:2] == ["tart", "set"] for call in run.call_args_list))

    def test_unsupported_lock_host_fails_before_reservation_or_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reservations = root / "reservations.json"
            with (
                mock.patch.object(visual_platform, "RUNTIME_ROOT", root),
                mock.patch.object(visual_platform, "RESOURCE_RESERVATIONS_PATH", reservations),
                mock.patch.object(visual_platform, "RESOURCE_LOCK_PATH", root / "reservation.lock"),
                mock.patch.object(visual_platform, "fcntl", None),
                mock.patch.object(visual_platform, "_host_memory_snapshot", return_value={
                    "physical_mib": 32768, "available_mib": 20000, "swap_used_mib": 0, "pressure_critical": False,
                }),
                mock.patch.object(visual_platform.host_platform, "system", return_value="Linux"),
            ):
                with self.assertRaisesRegex(visual_platform.VisualPlatformError, "locking is supported only"):
                    visual_platform._admit_visual_start("windows", 4096)
            self.assertFalse(reservations.exists())

    def test_macos_snapshot_uses_inactive_availability_estimate_and_exported_pressure_bits(self) -> None:
        physical = mock.Mock(returncode=0, stdout=str(32 * 1024 * 1024 * 1024) + "\n", stderr="")
        stats = mock.Mock(returncode=0, stdout=(
            "Mach Virtual Memory Statistics: (page size of 16384 bytes)\n"
            "Pages free: 500.\nPages inactive: 999999.\nPages speculative: 500.\nPages throttled: 0.\n"
        ), stderr="")
        swap = mock.Mock(returncode=0, stdout="total = 4096.00M  used = 5.00M  free = 4091.00M\n", stderr="")
        normal = mock.Mock(returncode=0, stdout="1\n", stderr="")
        with (
            mock.patch.object(visual_platform.host_platform, "system", return_value="Darwin"),
            mock.patch.object(visual_platform, "_run", side_effect=(physical, stats, swap, normal)),
        ):
            snapshot = visual_platform._host_memory_snapshot()
        self.assertEqual(15632, snapshot["available_mib"])
        self.assertEqual(5, snapshot["swap_used_mib"])
        self.assertFalse(snapshot["pressure_critical"])
        critical = mock.Mock(returncode=0, stdout="4\n", stderr="")
        with (
            mock.patch.object(visual_platform.host_platform, "system", return_value="Darwin"),
            mock.patch.object(visual_platform, "_run", side_effect=(physical, stats, swap, critical)),
        ):
            self.assertTrue(visual_platform._host_memory_snapshot()["pressure_critical"])

    def test_record_failure_after_popen_retains_provisional_reservation(self) -> None:
        probe = {"ready": True, "backend": "qemu-windows", "capabilities": ["secure_desktop"], "detail": ""}
        process = mock.Mock(pid=1234)
        with (
            mock.patch.object(visual_platform, "local_probe", return_value=probe),
            mock.patch.object(visual_platform, "_disk_user_pids", return_value=[]),
            mock.patch.object(visual_platform, "_admit_visual_start", return_value={}),
            mock.patch.object(visual_platform, "_bind_visual_reservation", side_effect=OSError("record failed")),
            mock.patch.object(visual_platform, "_release_visual_reservation") as release,
            mock.patch.object(visual_platform.subprocess, "Popen", return_value=process),
        ):
            with self.assertRaisesRegex(OSError, "record failed"):
                visual_platform.start_platform("windows")
        release.assert_not_called()

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

    def test_windows_qemu_secure_driver_uses_safe_run_dialog_key_sequence(self) -> None:
        qmp = mock.Mock()
        capture_visual_windows_qemu._type_command(
            qmp,
            "fs0:\\efi\\boot\\bootaa64.efi powershell -verb runas",
        )
        pressed = [call.args[0] for call in qmp.send_key.call_args_list]
        self.assertEqual("f", pressed[0])
        self.assertIn("spc", pressed)
        self.assertIn("minus", pressed)
        self.assertIn("shift-semicolon", pressed)
        self.assertIn("backslash", pressed)
        self.assertIn("dot", pressed)
        self.assertNotIn("meta_l-r", pressed)

    def test_windows_qemu_secure_driver_converts_framebuffer_without_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ppm = root / "frame.ppm"
            png = root / "frame.png"
            ppm.write_bytes(b"P6\n2 1\n255\n" + bytes((0, 1, 2, 253, 254, 255)))
            self.assertEqual((2, 1), capture_visual_windows_qemu.convert_ppm_to_png(ppm, png))
            self.assertTrue(png.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"))

    def test_windows_qemu_secure_driver_rejects_inactive_and_unchanged_frames(self) -> None:
        inactive = bytes(100 * 3)
        active = bytes((80, 120, 160)) * 100
        changed = active[: 50 * 3] + bytes((200, 200, 200)) * 50
        self.assertEqual(0.0, capture_visual_windows_qemu.visible_pixel_ratio(inactive))
        self.assertEqual(1.0, capture_visual_windows_qemu.visible_pixel_ratio(active))
        self.assertEqual(0.5, capture_visual_windows_qemu.changed_pixel_ratio(active, changed))
        with self.assertRaisesRegex(capture_visual_windows_qemu.CaptureError, "same non-empty"):
            capture_visual_windows_qemu.changed_pixel_ratio(active, b"")

    def test_windows_qemu_readiness_waits_through_boot_resolution(self) -> None:
        active = bytes((80, 120, 160)) * 100
        with (
            mock.patch.object(
                capture_visual_windows_qemu,
                "capture_qmp_pixels",
                side_effect=[
                    capture_visual_windows_qemu.CaptureError(
                        "Windows framebuffer is 1024x768; expected 1280x800",
                    ),
                    active,
                    active,
                ],
            ),
            mock.patch.object(capture_visual_windows_qemu.time, "sleep"),
        ):
            self.assertEqual(
                active,
                capture_visual_windows_qemu.wait_for_active_display(mock.Mock(), timeout_seconds=10),
            )

    def test_secure_desktop_drivers_validate_vnc_frame_dimensions(self) -> None:
        header = (
            b"\x89PNG\r\n\x1a\n"
            + b"\x00\x00\x00\rIHDR"
            + (1280).to_bytes(4, "big")
            + (800).to_bytes(4, "big")
        )
        with tempfile.TemporaryDirectory() as temporary:
            png = Path(temporary) / "frame.png"
            png.write_bytes(header)
            self.assertEqual((1280, 800), capture_visual_windows_qemu.png_size(png))
            self.assertEqual((1280, 800), capture_visual_macos_tart.png_size(png))

    def test_macos_secure_driver_rejects_blank_vnc_frames(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            black_ppm = root / "black.ppm"
            black_png = root / "black.png"
            visible_ppm = root / "visible.ppm"
            visible_png = root / "visible.png"
            black_ppm.write_bytes(b"P6\n10 10\n255\n" + bytes(10 * 10 * 3))
            visible_ppm.write_bytes(b"P6\n10 10\n255\n" + bytes((255, 255, 255)) * 100)
            capture_visual_windows_qemu.convert_ppm_to_png(black_ppm, black_png)
            capture_visual_windows_qemu.convert_ppm_to_png(visible_ppm, visible_png)

            self.assertEqual(0.0, capture_visual_macos_tart.visible_pixel_ratio(black_png))
            self.assertEqual(1.0, capture_visual_macos_tart.visible_pixel_ratio(visible_png))

    def test_macos_secure_driver_refreshes_guest_ip_after_vnc_route_failure(self) -> None:
        completed = subprocess.CompletedProcess(["vncdo"], 0, stdout="", stderr="")
        commands: list[list[str]] = []
        relay_addresses: list[str] = []

        @contextlib.contextmanager
        def relay(ip_address: str):
            relay_addresses.append(ip_address)
            yield f"{ip_address}-relay"

        def run(command: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
            del timeout
            commands.append(command)
            if command[0] == "vncdo" and "stale-ip-relay" in command:
                raise capture_visual_macos_tart.CaptureError("No route to host")
            if command[:2] == ["tart", "ip"]:
                return subprocess.CompletedProcess(command, 0, stdout="fresh-ip\n", stderr="")
            return completed

        with (
            mock.patch.object(capture_visual_macos_tart, "run_checked", side_effect=run),
            mock.patch.object(
                capture_visual_macos_tart,
                "vnc_command",
                side_effect=lambda server, *args: ["vncdo", server, *args],
            ),
            mock.patch.object(capture_visual_macos_tart, "local_vnc_relay", side_effect=relay),
            mock.patch.object(capture_visual_macos_tart.time, "sleep"),
        ):
            self.assertIs(
                completed,
                capture_visual_macos_tart.run_vnc_checked(
                    "stale-ip", "key", "esc", timeout=30
                ),
            )

        self.assertEqual("stale-ip-relay", commands[0][1])
        self.assertEqual(["tart", "ip", capture_visual_macos_tart.VM_NAME], commands[1])
        self.assertEqual("fresh-ip-relay", commands[2][1])
        self.assertEqual(["stale-ip", "fresh-ip"], relay_addresses)

    def test_macos_secure_driver_waits_for_vnc_route_after_reboot(self) -> None:
        probes = [
            capture_visual_macos_tart.CaptureError("No route to host"),
            subprocess.CompletedProcess(["nc"], 0, stdout="", stderr=""),
        ]
        with (
            mock.patch.object(
                capture_visual_macos_tart,
                "guest_ip",
                side_effect=["stale-ip", "fresh-ip"],
            ),
            mock.patch.object(capture_visual_macos_tart, "run_checked", side_effect=probes) as run,
            mock.patch.object(capture_visual_macos_tart.time, "sleep"),
        ):
            self.assertEqual("fresh-ip", capture_visual_macos_tart.wait_for_guest_vnc())

        self.assertEqual(
            [
                mock.call(["/usr/bin/nc", "-z", "-G", "3", "stale-ip", "5900"], timeout=5),
                mock.call(["/usr/bin/nc", "-z", "-G", "3", "fresh-ip", "5900"], timeout=5),
            ],
            run.call_args_list,
        )

    def test_macos_secure_driver_rejects_contaminated_guest_background(self) -> None:
        baseline_path = (
            capture_visual_macos_tart.ROOT
            / "visual-tests/baselines/macos/macos-install-confirmation.png"
        )
        baseline = visual_regression.PngImage(
            1280,
            800,
            bytes((64, 96, 128, 255)) * 1280 * 800,
        )
        with tempfile.TemporaryDirectory() as temporary:
            clean = Path(temporary) / "clean.png"
            contaminated = Path(temporary) / "contaminated.png"
            visual_regression.write_png(clean, baseline)
            pixels = bytearray(baseline.pixels)
            for y in range(35, 115):
                for x in range(920, 1260):
                    offset = (y * baseline.width + x) * 4
                    pixels[offset : offset + 4] = bytes((255, 255, 255, 255))
            visual_regression.write_png(
                contaminated,
                visual_regression.PngImage(baseline.width, baseline.height, bytes(pixels)),
            )

            with mock.patch.object(
                capture_visual_macos_tart,
                "read_png",
                side_effect=lambda path: baseline
                if path == baseline_path
                else visual_regression.read_png(path),
            ):
                self.assertEqual(0.0, capture_visual_macos_tart.background_changed_ratio(clean))
                self.assertGreater(
                    capture_visual_macos_tart.background_changed_ratio(contaminated),
                    0.0002,
                )

            sidebar_pixels = bytearray(baseline.pixels)
            for y in range(40, 100):
                for x in range(1260, 1280):
                    offset = (y * baseline.width + x) * 4
                    sidebar_pixels[offset : offset + 4] = bytes((220, 220, 220, 255))
            visual_regression.write_png(
                contaminated,
                visual_regression.PngImage(baseline.width, baseline.height, bytes(sidebar_pixels)),
            )
            self.assertGreater(
                capture_visual_macos_tart.right_edge_overlay_ratio(contaminated),
                0.01,
            )

    def test_macos_secure_driver_requires_the_expected_dialog_to_appear(self) -> None:
        baseline = visual_regression.PngImage(
            1280,
            800,
            bytes((64, 96, 128, 255)) * 1280 * 800,
        )
        with tempfile.TemporaryDirectory() as temporary:
            background = Path(temporary) / "background.png"
            dialog = Path(temporary) / "dialog.png"
            blank_pixels = bytearray(baseline.pixels)
            for y in range(115, 445):
                for x in range(500, 780):
                    offset = (y * baseline.width + x) * 4
                    blank_pixels[offset : offset + 4] = bytes((0, 0, 0, 255))
            visual_regression.write_png(
                background,
                visual_regression.PngImage(baseline.width, baseline.height, bytes(blank_pixels)),
            )
            visual_regression.write_png(dialog, baseline)

            self.assertEqual(
                0.0,
                capture_visual_macos_tart.foreground_changed_ratio(
                    background,
                    background,
                    "macos-install-confirmation",
                ),
            )
            self.assertGreater(
                capture_visual_macos_tart.foreground_changed_ratio(
                    dialog,
                    background,
                    "macos-install-confirmation",
                ),
                0.2,
            )

    def test_macos_secure_driver_never_launches_a_host_vnc_application(self) -> None:
        script = MACOS_TART_CAPTURE_PATH.read_text(encoding="utf-8")
        self.assertIn('"--nocursor"', script)
        self.assertIn('pause = "40"', script)
        self.assertIn("Screen Sharing's own control banner", script)
        self.assertIn("sudo date 0903120026.00", script)
        self.assertIn('SECURE_SCENES = ("macos-gatekeeper", "macos-install-confirmation")', script)
        self.assertIn("macOS VNC capture failed three times", script)
        self.assertIn("timeout=120", script)
        self.assertIn("kTCCServiceScreenCapture", script)
        self.assertIn("kTCCServiceAppleEvents", script)
        self.assertIn("CoreServicesUIAgent.app/Contents/MacOS/CoreServicesUIAgent$", script)
        self.assertIn('"824", "304", "click", "1"', script)
        self.assertIn('"699", "341", "click", "1"', script)
        self.assertIn('"pause", "20", "move", "1080", "70"', script)
        self.assertIn("Restarting Notification Center would replay the queued banner", script)
        self.assertIn("This recovery runs only after the clean-background", script)
        self.assertIn("sudo killall Finder", script)
        self.assertIn("killall Dock", script)
        self.assertIn('tell application \\"Finder\\" to close every window', script)
        self.assertIn("cannot alter macOS keyboard/pointer modality", script)
        self.assertIn("macOS guest still contains a window, notification, or permission surface", script)
        self.assertIn("macOS secure surface did not appear", script)
        self.assertIn("macOS secure scene failed after three launch attempts", script)
        self.assertIn("for launch_attempt in range(3)", script)
        self.assertIn("def reboot_guest", script)
        self.assertIn('"sudo", "/sbin/shutdown", "-r", "now"', script)
        self.assertIn("kern.boottime", script)
        self.assertIn("right_edge_overlay_ratio", script)
        self.assertIn("def capture_secure_frame", script)
        self.assertIn("same inactive-button state as the canonical fixture", script)
        self.assertIn("capture_after_notification_banner_dismiss(ip_address, screenshot)", script)
        self.assertIn("Clicking outside a secure authorization sheet dismisses it", script)
        self.assertIn('"pause", "2", "capture", str(output)', script)
        install_launch = script.index("process = open_install_confirmation(uid)")
        install_clock_restore = script.rindex("restore_guest_clock()", 0, install_launch)
        install_capture = script.index("capture_secure_frame(ip_address", install_launch)
        self.assertLess(install_clock_restore, install_launch)
        self.assertNotIn("freeze_guest_clock()", script[install_launch:install_capture])
        self.assertIn("ignored menu-bar region already removes", script)
        self.assertIn(".macos-dialog-exit", script)
        self.assertIn("capture_status=$?", script)
        self.assertIn("deadline = time.monotonic() + 180", script)
        self.assertNotIn("; status=$?", script)
        self.assertIn("git clone --no-local --no-checkout", script)
        self.assertIn('[[ "$name" =~ ^[0-9a-f]{40}$', script)
        self.assertIn('rm -rf -- "$candidate"', script)
        self.assertIn("less than 2 GiB free after pruning stale checkouts", script)
        self.assertIn("org.gradle.project.compose.desktop.packaging.checkJdkVendor=false", script)
        self.assertNotIn("open vnc://", script)

    def test_macos_framebuffer_driver_acknowledges_file_dialog_capture(self) -> None:
        script = MACOS_TART_CAPTURE_PATH.read_text(encoding="utf-8")
        self.assertIn('FILE_DIALOG_SCENES = ("macos-open-dialog", "macos-save-dialog")', script)
        self.assertIn("VPN_CONTROL_VISUAL_EXTERNAL_FRAMEBUFFER=1", script)
        self.assertIn('f"{scene_id}.png.captured"', script)
        self.assertIn('pause = "40"', script)

    def test_windows_qemu_start_exposes_scoped_control_sockets(self) -> None:
        script = (visual_platform.ROOT / "scripts/start_windows_visual_vm.sh").read_text(
            encoding="utf-8",
        )
        self.assertIn('unix:$runtime_dir/qmp.sock', script)
        self.assertIn('path=$guest_agent_socket', script)
        self.assertIn('hostfwd=tcp:127.0.0.1:2299-:22', script)
        self.assertIn('"${1:-}" == "--provision-drivers"', script)
        self.assertIn('file=$driver_iso,media=cdrom,readonly=on', script)
        self.assertIn('-display none', script)
        self.assertIn('-vnc 127.0.0.1:5', script)
        self.assertNotIn('-display cocoa', script)
        self.assertIn('lsof -t -- "$disk_path"', script)

    def test_qemu_start_reuses_a_ready_managed_vm_without_launching_another(self) -> None:
        probe = {"ready": True, "backend": "qemu-windows", "capabilities": ["secure_desktop"], "detail": ""}
        with (
            mock.patch.object(visual_platform, "local_probe", return_value=probe),
            mock.patch.object(visual_platform, "_disk_user_pids", return_value=[1234]),
            mock.patch.object(visual_platform, "_qmp_ready", return_value=True),
            mock.patch.object(visual_platform, "_read_state", return_value={}),
            mock.patch.object(visual_platform.subprocess, "Popen") as popen,
            mock.patch.object(visual_platform, "_write_state"),
        ):
            result = visual_platform.start_platform("windows")
        popen.assert_not_called()
        self.assertFalse(result["started_by_agent"])
        self.assertEqual(1234, result["pid"])

    def test_qemu_start_refuses_an_in_use_disk_without_qmp(self) -> None:
        probe = {"ready": True, "backend": "qemu-windows", "capabilities": ["secure_desktop"], "detail": ""}
        with (
            mock.patch.object(visual_platform, "local_probe", return_value=probe),
            mock.patch.object(visual_platform, "_disk_user_pids", return_value=[1234]),
            mock.patch.object(visual_platform, "_qmp_ready", return_value=False),
            mock.patch.object(visual_platform.subprocess, "Popen") as popen,
        ):
            with self.assertRaisesRegex(visual_platform.VisualPlatformError, "already in use"):
                visual_platform.start_platform("windows")
        popen.assert_not_called()

    def test_qemu_stop_uses_python_qmp_without_socat(self) -> None:
        state = {
            "platform": "windows", "backend": "qemu-windows", "identifier": "disk",
            "started_by_agent": True, "pid": 1234,
        }
        with (
            mock.patch.object(visual_platform, "_read_state", return_value=state),
            mock.patch.object(Path, "exists", return_value=True),
            mock.patch.object(visual_platform, "_qmp_execute") as execute,
            mock.patch.object(visual_platform, "_pid_running", return_value=False),
            mock.patch.object(Path, "unlink"),
        ):
            result = visual_platform.stop_platform("windows")
        execute.assert_called_once_with(visual_platform.RUNTIME_ROOT / "windows" / "qmp.sock", "system_powerdown")
        self.assertTrue(result["stopped"])

    def test_hosted_native_capture_freezes_platform_clocks(self) -> None:
        macos = (visual_platform.ROOT / "scripts/capture_visual_desktop.sh").read_text(
            encoding="utf-8",
        )
        windows = (visual_platform.ROOT / "scripts/capture_visual_desktop.ps1").read_text(
            encoding="utf-8",
        )
        self.assertIn("sudo date 0903120026.00", macos)
        self.assertIn('Set-Date -Date "2026-09-03T12:00:00"', windows)
        self.assertIn("WM_TIMECHANGE", windows)
        self.assertIn("Notify-SystemClockChanged", windows)
        self.assertIn("Dismiss-HostedVisualResidue", windows)
        add_type_start = windows.index('Add-Type @"', windows.index("function Notify-SystemClockChanged"))
        add_type_end = windows.index('"@', add_type_start)
        residue_start = windows.index("function Dismiss-HostedVisualResidue")
        self.assertGreater(residue_start, add_type_end)

    def test_hosted_macos_capture_disables_first_run_desktop_help(self) -> None:
        workflow = (visual_platform.ROOT / ".github/workflows/visual-regression.yml").read_text(
            encoding="utf-8",
        )
        macos = workflow.split("  macos:", 1)[1]
        self.assertIn(
            "defaults write com.apple.WindowManager EnableStandardClickToShowDesktop -bool false",
            macos,
        )

    def test_macos_native_capture_targets_screen_recording_allow_action(self) -> None:
        fixture = (
            visual_platform.ROOT
            / "desktopApp/src/test/kotlin/com/kardinal/vpncontrol/desktop/DesktopNativeVisualCaptureTest.kt"
        ).read_text(encoding="utf-8")
        self.assertIn("screen.height * 0.554", fixture)
        self.assertIn("preparePrivateWindowCapturePermission(bounds)", fixture)
        self.assertIn("Thread.sleep(5_000)", fixture)
        self.assertNotIn("screen.height * 0.516", fixture)

    def test_android_capture_requires_an_agent_owned_emulator(self) -> None:
        with mock.patch.object(
            visual_platform,
            "local_probe",
            return_value={"ready": False, "backend": "", "capabilities": [], "detail": "missing"},
        ):
            plan = visual_platform.capture_plan("android")
        self.assertFalse(plan["routes"]["hosted"])
        self.assertTrue(plan["routes"]["blocked"])
        workflow = (visual_platform.ROOT / ".github/workflows/visual-regression.yml").read_text(
            encoding="utf-8",
        )
        android = workflow.split("  android:", 1)[1].split("  linux:", 1)[0]
        self.assertIn("github.event_name == 'workflow_dispatch' && inputs.platform == 'android'", android)

    def test_exhaustive_vpn_workflow_guards_platform_prerequisites(self) -> None:
        workflow = (visual_platform.ROOT / ".github/workflows/vpn-integration.yml").read_text(
            encoding="utf-8",
        )
        linux = workflow.split("  linux-full-vpn:", 1)[1].split("  windows-full-vpn:", 1)[0]
        windows = workflow.split("  windows-full-vpn:", 1)[1].split("  android-full-vpn:", 1)[0]
        android = workflow.split("  android-full-vpn:", 1)[1]
        self.assertIn("iproute2", linux)
        self.assertIn(":desktopApp:createDistributable", windows)
        self.assertIn("set -eu", android)
        self.assertNotIn("set -euo pipefail", android)
        self.assertNotIn("socks_http_fixture.py", android)
        self.assertIn("FullVpnLifecycleInstrumentedTest", android)
        self.assertIn("script: >-", android)
        self.assertNotIn("script: |\n            set -eu", android)
        self.assertNotIn("fixture_pid", android)

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

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


class VisualPlatformTest(unittest.TestCase):
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
        self.assertIn("SystemClock.sleep(NATIVE_HOST_CAPTURE_HOLD_MILLIS)", source)
        self.assertIn("NATIVE_HOST_CAPTURE_HOLD_MILLIS = 2_000L", source)

    def test_android_qr_capture_requires_visible_scanner_chrome(self) -> None:
        source = (
            visual_platform.ROOT
            / "app/src/androidTest/java/com/kardinal/vpncontrol/ui/VisualCaptureInstrumentedTest.kt"
        ).read_text(encoding="utf-8")
        layout = (
            visual_platform.ROOT / "app/src/main/res/layout/zxing_capture.xml"
        ).read_text(encoding="utf-8")
        self.assertIn('assertCameraScannerChrome(File(output, "$sceneId.png"))', source)
        self.assertIn("QR scanner chrome was not visible", source)
        self.assertIn('android:text="Scan QR code"', layout)
        self.assertIn("@drawable/qr_scanner_frame", layout)
        self.assertIn("QrCaptureActivity", source)
        self.assertIn("EXTRA_VISUAL_CAPTURE", source)

    def test_android_native_captures_reapply_the_frozen_system_fixture(self) -> None:
        source = (
            visual_platform.ROOT / "scripts/capture_visual_android.sh"
        ).read_text(encoding="utf-8")
        native_loop = source.split('for native_scene in "${native_scene_ids[@]}"; do', 1)[1]
        self.assertIn('command clock -e hhmm 1200', native_loop)
        self.assertIn('command notifications -e visible false', native_loop)

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
        self.assertIn("settings put global sysui_demo_allowed 1", script)
        self.assertIn("command clock -e hhmm 1200", script)
        self.assertIn("command notifications -e visible false", script)
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

    def test_macos_secure_driver_rejects_contaminated_guest_background(self) -> None:
        baseline_path = (
            visual_platform.ROOT
            / "visual-tests/baselines/macos/macos-install-confirmation.png"
        )
        baseline = visual_regression.read_png(baseline_path)
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

            self.assertEqual(0.0, capture_visual_macos_tart.background_changed_ratio(clean))
            self.assertGreater(
                capture_visual_macos_tart.background_changed_ratio(contaminated),
                0.0002,
            )

            sidebar_pixels = bytearray(baseline.pixels)
            for y in range(130, 300):
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
        baseline_path = (
            visual_platform.ROOT
            / "visual-tests/baselines/macos/macos-install-confirmation.png"
        )
        baseline = visual_regression.read_png(baseline_path)
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
        self.assertIn("right_edge_overlay_ratio", script)
        self.assertIn("def capture_secure_frame", script)
        self.assertIn("same inactive-button state as the canonical fixture", script)
        self.assertIn(".macos-dialog-exit", script)
        self.assertIn("capture_status=$?", script)
        self.assertIn("deadline = time.monotonic() + 180", script)
        self.assertNotIn("; status=$?", script)
        self.assertIn("git clone --no-local --no-checkout", script)
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

    def test_hosted_native_capture_freezes_platform_clocks(self) -> None:
        macos = (visual_platform.ROOT / "scripts/capture_visual_desktop.sh").read_text(
            encoding="utf-8",
        )
        windows = (visual_platform.ROOT / "scripts/capture_visual_desktop.ps1").read_text(
            encoding="utf-8",
        )
        self.assertIn("sudo date 0903120026.00", macos)
        self.assertIn('Set-Date -Date "2026-09-03T12:00:00"', windows)

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

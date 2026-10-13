#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("visual_regression.py")
SPEC = importlib.util.spec_from_file_location("visual_regression", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
visual_regression = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = visual_regression
SPEC.loader.exec_module(visual_regression)


class VisualRegressionTest(unittest.TestCase):
    def test_repository_manifest_has_no_comparison_masks(self) -> None:
        manifest = visual_regression._load_manifest(visual_regression.DEFAULT_MANIFEST)
        for scene in manifest["scenes"]:
            with self.subTest(scene=scene["id"]):
                self.assertFalse(scene.get("ignore_regions"), scene["id"])
                self.assertFalse(any(scene.get("ignore_regions_by_platform", {}).values()), scene["id"])
                for platform in scene["platforms"]:
                    self.assertEqual([], visual_regression._scene_ignore_regions(scene, platform))

    def test_manifest_rejects_masks_on_every_platform_before_verify_or_record(self) -> None:
        for declaration in (
            {"ignore_regions": [[0, 0, 10, 10]]},
            {"ignore_regions_by_platform": {"linux": [[0, 0, 10, 10]]}},
            {"ignore_regions_by_platform": {"android": [[0, 0, 10, 10]]}},
        ):
            with self.subTest(declaration=declaration):
                manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
                scene = manifest["scenes"][0]
                scene.pop("ignore_regions", None)
                scene.pop("ignore_regions_by_platform", None)
                scene.update(declaration)
                self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
                for action in (self.verify, self.record):
                    with self.subTest(action=action.__name__):
                        with self.assertRaisesRegex(ValueError, "VISUAL-004"):
                            action()
                self.assertFalse((self.reports / "linux/report.json").exists())

    def test_empty_mask_metadata_keeps_full_image_comparison(self) -> None:
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        manifest["scenes"][0].update({
            "ignore_regions": [],
            "ignore_regions_by_platform": {"android": [], "linux": []},
        })
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertEqual(0, self.verify())
        report = json.loads((self.reports / "linux/report.json").read_text(encoding="utf-8"))
        self.assertEqual([], report["scenes"][0]["ignore_regions"])
        self.assertEqual(0, report["scenes"][0]["metrics"]["ignored_pixels"])
        self.assertEqual(10_000, report["scenes"][0]["metrics"]["compared_pixels"])

    def test_geometry_target_size_uses_capture_density(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            geometry = Path(temporary) / "scene.geometry.json"
            geometry.write_text(
                json.dumps(
                    {
                        "viewport": [400, 400],
                        "density": 2.0,
                        "elements": [
                            {
                                "id": "action",
                                "interactive": True,
                                "label": "Action",
                                "bounds": [0, 0, 90, 96],
                            },
                        ],
                    },
                ),
                encoding="utf-8",
            )
            errors = visual_regression.validate_geometry(geometry, ["action"])
        self.assertTrue(any("48x48 dp" in error for error in errors), errors)

    def test_repository_manifest_covers_every_supported_platform_and_os_surface(self) -> None:
        root = json.loads(visual_regression.DEFAULT_MANIFEST.read_text(encoding="utf-8"))
        scenes = root["scenes"]
        ids = [scene["id"] for scene in scenes]
        self.assertEqual(len(ids), len(set(ids)))
        for platform in ("android", "linux", "windows", "macos"):
            self.assertGreaterEqual(
                len([scene for scene in scenes if platform in scene["platforms"]]),
                50,
                platform,
            )
        for scene in scenes:
            required = scene.get("required_elements", [])
            self.assertEqual(len(required), len(set(required)), scene["id"])
            if scene.get("geometry_required", True):
                self.assertTrue(required, scene["id"])
        for identifier in (
            "android-vpn-consent",
            "android-package-installer",
            "linux-tray-awt-connected",
            "linux-tray-native-connected",
            "windows-uac",
            "windows-msi",
            "macos-dmg",
            "macos-gatekeeper",
        ):
            self.assertIn(identifier, ids)
        attributes = (visual_regression.ROOT / ".gitattributes").read_text(encoding="utf-8")
        self.assertIn("visual-tests/baselines/**/*.png filter=lfs", attributes)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.baselines = self.root / "baselines"
        self.actual = self.root / "actual"
        self.reports = self.root / "reports"
        self.manifest = self.root / "scenes.json"
        self.manifest.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "thresholds": {
                        "max_channel_delta": 8,
                        "max_changed_ratio": 0.0002,
                        "max_mean_channel_error": 0.25,
                    },
                    "scenes": [
                        {
                            "id": "main",
                            "platforms": ["linux"],
                            "required_elements": ["connect"],
                        },
                    ],
                },
            ),
            encoding="utf-8",
        )
        self.image = visual_regression.PngImage(100, 100, bytes((8, 17, 31, 255)) * 10_000)
        visual_regression.write_png(self.baselines / "linux/main.png", self.image)
        visual_regression.write_png(self.actual / "main.png", self.image)
        (self.actual / "main.geometry.json").write_text(
            json.dumps(
                {
                    "viewport": [100, 100],
                    "elements": [
                        {
                            "id": "connect",
                            "bounds": [10, 10, 70, 70],
                            "interactive": True,
                            "label": "Connect",
                        },
                    ],
                },
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def args(self) -> argparse.Namespace:
        return argparse.Namespace(
            platform="linux",
            manifest=self.manifest,
            baseline_dir=self.baselines,
            actual_dir=self.actual,
            report_dir=self.reports,
        )

    def verify(self) -> int:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return visual_regression.verify(self.args())

    def record(self) -> int:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return visual_regression.record(self.args())

    def test_identical_images_and_valid_geometry_pass(self) -> None:
        self.assertEqual(0, self.verify())
        report = json.loads((self.reports / "linux/report.json").read_text(encoding="utf-8"))
        self.assertTrue(report["passed"])
        self.assertTrue((self.reports / "linux/main.diff.png").is_file())
        self.assertTrue((self.reports / "linux/main.contact.png").is_file())

    def test_distortion_over_threshold_fails(self) -> None:
        pixels = bytearray(self.image.pixels)
        pixels[:400] = bytes((255, 255, 255, 255)) * 100
        visual_regression.write_png(
            self.actual / "main.png",
            visual_regression.PngImage(100, 100, bytes(pixels)),
        )
        self.assertEqual(1, self.verify())

    def test_png_difference_in_former_windows_taskbar_band_cannot_be_masked(self) -> None:
        # The original Windows native scenes excluded [0, 750, 1280, 800].
        baseline = visual_regression.PngImage(1280, 800, bytes((8, 17, 31, 255)) * 1_024_000)
        pixels = bytearray(baseline.pixels)
        for row in range(760, 768):
            start = (row * 1280 + 1200) * 4
            pixels[start : start + 32 * 4] = bytes((255, 255, 255, 255)) * 32
        baseline_path = self.root / "windows-native.baseline.png"
        actual_path = self.root / "windows-native.actual.png"
        visual_regression.write_png(baseline_path, baseline)
        visual_regression.write_png(actual_path, visual_regression.PngImage(1280, 800, bytes(pixels)))
        baseline = visual_regression.read_png(baseline_path)
        actual = visual_regression.read_png(actual_path)
        metrics, diff = visual_regression._compare(baseline, actual, 8)
        self.assertEqual(256, metrics["changed_pixels"])
        self.assertEqual(1_024_000, metrics["compared_pixels"])
        self.assertEqual(0, metrics["ignored_pixels"])
        self.assertGreater(metrics["changed_ratio"], 0.0002)
        offset = (760 * 1280 + 1200) * 4
        self.assertEqual(255, diff.pixels[offset])
        with self.assertRaisesRegex(ValueError, "VISUAL-004"):
            visual_regression._compare(baseline, actual, 8, [[0, 750, 1280, 800]])

    def test_native_scene_full_image_difference_fails_verification(self) -> None:
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        manifest["scenes"][0]["geometry_required"] = False
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        pixels = bytearray(self.image.pixels)
        for row in range(90, 100):
            start = row * 100 * 4
            pixels[start : start + 40] = bytes((255, 255, 255, 255)) * 10
        visual_regression.write_png(self.actual / "main.png", visual_regression.PngImage(100, 100, bytes(pixels)))
        self.assertEqual(1, self.verify())
        report = json.loads((self.reports / "linux/report.json").read_text(encoding="utf-8"))
        self.assertEqual(100, report["scenes"][0]["metrics"]["changed_pixels"])
        self.assertEqual(0, report["scenes"][0]["metrics"]["ignored_pixels"])
        self.assertEqual([], report["scenes"][0]["ignore_regions"])

    def test_scene_threshold_can_allow_bounded_native_surface_rasterization(self) -> None:
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        manifest["scenes"][0]["thresholds"] = {"max_changed_ratio": 0.002}
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        pixels = bytearray(self.image.pixels)
        pixels[:40] = bytes((255, 255, 255, 255)) * 10
        visual_regression.write_png(
            self.actual / "main.png",
            visual_regression.PngImage(100, 100, bytes(pixels)),
        )

        self.assertEqual(0, self.verify())
        report = json.loads((self.reports / "linux/report.json").read_text(encoding="utf-8"))
        self.assertEqual(0.002, report["scenes"][0]["thresholds"]["max_changed_ratio"])

    def test_malformed_mask_metadata_fails_closed(self) -> None:
        for declaration in (
            {"ignore_regions": False},
            {"ignore_regions": {}},
            {"ignore_regions_by_platform": []},
            {"ignore_regions_by_platform": {"linux": False}},
        ):
            with self.subTest(declaration=declaration):
                manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
                scene = manifest["scenes"][0]
                scene.pop("ignore_regions", None)
                scene.pop("ignore_regions_by_platform", None)
                scene.update(declaration)
                self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
                with self.assertRaises(ValueError):
                    self.verify()

    def test_dimension_mismatch_still_writes_diagnostic_contact_sheet(self) -> None:
        visual_regression.write_png(
            self.actual / "main.png",
            visual_regression.PngImage(90, 100, bytes((8, 17, 31, 255)) * 9_000),
        )
        self.assertEqual(1, self.verify())
        self.assertTrue((self.reports / "linux/main.diff.png").is_file())
        self.assertTrue((self.reports / "linux/main.contact.png").is_file())

    def test_clipped_or_unlabelled_interactive_element_fails(self) -> None:
        (self.actual / "main.geometry.json").write_text(
            json.dumps(
                {
                    "viewport": [100, 100],
                    "elements": [
                        {
                            "id": "connect",
                            "bounds": [-1, 10, 20, 30],
                            "interactive": True,
                            "label": "",
                        },
                    ],
                },
            ),
            encoding="utf-8",
        )
        self.assertEqual(1, self.verify())

    def test_missing_required_element_fails(self) -> None:
        (self.actual / "main.geometry.json").write_text(
            json.dumps({"viewport": [100, 100], "elements": []}),
            encoding="utf-8",
        )
        self.assertEqual(1, self.verify())

    def test_low_text_contrast_fails(self) -> None:
        (self.actual / "main.geometry.json").write_text(
            json.dumps(
                {
                    "viewport": [100, 100],
                    "elements": [
                        {
                            "id": "connect",
                            "bounds": [10, 10, 70, 70],
                            "interactive": True,
                            "label": "Connect",
                            "text": True,
                            "contrast_ratio": 2.5,
                        },
                    ],
                },
            ),
            encoding="utf-8",
        )
        self.assertEqual(1, self.verify())

    def test_record_rejects_incomplete_scene_set(self) -> None:
        (self.actual / "main.png").unlink()
        self.assertEqual(1, self.record())


if __name__ == "__main__":
    unittest.main()

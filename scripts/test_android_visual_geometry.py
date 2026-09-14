from __future__ import annotations

import io
import importlib.util
import sys
import unittest
from unittest import mock
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("android_visual_geometry.py")
SPEC = importlib.util.spec_from_file_location("android_visual_geometry", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
android_visual_geometry = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = android_visual_geometry
SPEC.loader.exec_module(android_visual_geometry)


PRIMARY_STALE = """\
  displayId=0
  WindowInsetsStateController
    InsetsState
      mDisplayFrame=Rect(0, 0 - 1080, 2400)
      mDisplayCutout=DisplayCutout{insets=Rect(0, 128 - 0, 0)}
        InsetsSource id=1 type=statusBars frame=[0,0][1080,63] visible=true flags= sideHint=TOP
"""

PRIMARY_FIXED = """\
  displayId=0
  WindowInsetsStateController
    InsetsState
      mDisplayFrame=Rect(0, 0 - 1080, 2400)
      mDisplayCutout=DisplayCutout{insets=Rect(0, 128 - 0, 0)}
        InsetsSource id=2 type=statusBars frame=[0,0][1080,128] visible=true flags= sideHint=TOP
"""

PRIMARY_NO_CUTOUT = """\
  displayId=0
  WindowInsetsStateController
    InsetsState
      mDisplayFrame=Rect(0, 0 - 1080, 2400)
      mDisplayCutout=DisplayCutout{insets=Rect(0, 0 - 0, 0)}
        InsetsSource id=3 type=statusBars frame=[0,0][1080,63] visible=true flags= sideHint=TOP
"""

PRIMARY_TRANSIENT = """\
  displayId=0
  WindowInsetsStateController
    InsetsState
      mDisplayFrame=Rect(0, 0 - 0, 0)
      mDisplayCutout=DisplayCutout{insets=Rect(0, 0 - 0, 0)}
        InsetsSource id=4 type=statusBars frame=[0,0][0,0] visible=false flags= sideHint=NONE
"""


class AndroidVisualGeometryTest(unittest.TestCase):
    def test_primary_cutout_taller_than_status_bar_requires_reboot(self) -> None:
        self.assertEqual(
            android_visual_geometry.REBOOT_REQUIRED,
            android_visual_geometry.classify_primary_display_geometry(PRIMARY_STALE),
        )

    def test_matching_primary_cutout_and_status_bar_is_ready(self) -> None:
        geometry = android_visual_geometry.parse_primary_display_geometry(PRIMARY_FIXED)
        self.assertEqual(1080, geometry.width)
        self.assertEqual(2400, geometry.height)
        self.assertEqual(128, geometry.cutout_top)
        self.assertEqual(128, geometry.status_bar_height)
        self.assertEqual(android_visual_geometry.READY, android_visual_geometry.classify_primary_display_geometry(PRIMARY_FIXED))

    def test_no_cutout_primary_display_is_ready(self) -> None:
        self.assertEqual(
            android_visual_geometry.READY,
            android_visual_geometry.classify_primary_display_geometry(PRIMARY_NO_CUTOUT),
        )

    def test_zero_sized_startup_frame_is_transient(self) -> None:
        self.assertEqual(
            android_visual_geometry.TRANSIENT,
            android_visual_geometry.classify_primary_display_geometry(PRIMARY_TRANSIENT),
        )

    def test_secondary_display_status_bar_is_ignored(self) -> None:
        dump = PRIMARY_FIXED + """\
  displayId=1
  WindowInsetsStateController
    InsetsState
      mDisplayFrame=Rect(0, 0 - 800, 600)
      mDisplayCutout=DisplayCutout{insets=Rect(0, 128 - 0, 0)}
        InsetsSource id=9 type=statusBars frame=[0,0][800,63] visible=true flags= sideHint=TOP
"""
        self.assertEqual(
            android_visual_geometry.READY,
            android_visual_geometry.classify_primary_display_geometry(dump),
        )

    def test_missing_primary_display_is_rejected(self) -> None:
        with self.assertRaisesRegex(android_visual_geometry.GeometryParseError, "primary displayId=0"):
            android_visual_geometry.parse_primary_display_geometry("displayId=1\n")

    def test_cli_accepts_ready_primary_geometry(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(sys, "stdin", io.StringIO(PRIMARY_FIXED)),
            mock.patch.object(sys, "stderr", stderr),
        ):
            self.assertEqual(0, android_visual_geometry.main())
        self.assertEqual("", stderr.getvalue())

    def test_cli_rejects_transient_primary_geometry(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(sys, "stdin", io.StringIO(PRIMARY_TRANSIENT)),
            mock.patch.object(sys, "stderr", stderr),
        ):
            self.assertEqual(3, android_visual_geometry.main())
        self.assertIn("still initializing", stderr.getvalue())

    def test_cli_rejects_stale_primary_geometry_without_rebooting(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(sys, "stdin", io.StringIO(PRIMARY_STALE)),
            mock.patch.object(sys, "stderr", stderr),
        ):
            self.assertEqual(4, android_visual_geometry.main())
        self.assertIn("reboot the validated owned AVD", stderr.getvalue())

    def test_cli_rejects_incomplete_primary_geometry(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(sys, "stdin", io.StringIO("displayId=0\n")),
            mock.patch.object(sys, "stderr", stderr),
        ):
            self.assertEqual(2, android_visual_geometry.main())
        self.assertIn("geometry is incomplete", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()

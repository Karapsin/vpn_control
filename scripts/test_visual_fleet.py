#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("visual_fleet.py")
SPEC = importlib.util.spec_from_file_location("visual_fleet", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
visual_fleet = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = visual_fleet
SPEC.loader.exec_module(visual_fleet)


class VisualFleetTest(unittest.TestCase):
    def test_manifest_routes_a_large_scene_set_to_each_platform(self) -> None:
        for platform in ("android", "linux", "windows", "macos"):
            self.assertGreaterEqual(
                len(visual_fleet.scenes_for(visual_fleet.DEFAULT_MANIFEST, platform)),
                50,
                platform,
            )

    def test_linux_preflight_accepts_enrolled_gui_host(self) -> None:
        environment = {
            "DISPLAY": ":99",
            "VPN_CONTROL_VISUAL_FLEET": "1",
            "VPN_CONTROL_VISUAL_CAPTURE_COMMAND": "/opt/vpn-control-visual/capture",
        }
        completed = mock.Mock(returncode=0)
        with (
            mock.patch.dict(os.environ, environment, clear=True),
            mock.patch.object(visual_fleet.host_platform, "system", return_value="Linux"),
            mock.patch.object(visual_fleet.shutil, "which", return_value="/usr/bin/tool"),
            mock.patch.object(visual_fleet.subprocess, "run", return_value=completed),
        ):
            self.assertEqual([], visual_fleet._check_host("linux"))

    def test_windows_vm_requires_explicit_linux_host_opt_in(self) -> None:
        environment = {
            "DISPLAY": ":99",
            "VPN_CONTROL_VISUAL_FLEET": "1",
            "VPN_CONTROL_VISUAL_CAPTURE_COMMAND": "/opt/vpn-control-visual/capture-windows-vm",
        }
        completed = mock.Mock(returncode=0)
        with (
            mock.patch.dict(os.environ, environment, clear=True),
            mock.patch.object(visual_fleet.host_platform, "system", return_value="Linux"),
            mock.patch.object(visual_fleet.shutil, "which", return_value="/usr/bin/tool"),
            mock.patch.object(visual_fleet.subprocess, "run", return_value=completed),
        ):
            self.assertTrue(any("requires windows" in error for error in visual_fleet._check_host("windows")))
            os.environ["VPN_CONTROL_VISUAL_WINDOWS_VM"] = "1"
            self.assertEqual([], visual_fleet._check_host("windows"))

    def test_fingerprint_records_driver_executable_without_arguments(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"VPN_CONTROL_VISUAL_CAPTURE_COMMAND": "/opt/capture --token secret"},
            clear=True,
        ):
            fingerprint = visual_fleet.machine_fingerprint("linux")
        self.assertEqual("/opt/capture", fingerprint["driver_executable"])
        self.assertNotIn("secret", str(fingerprint))


if __name__ == "__main__":
    unittest.main()

"""Installer-session UI states must remain capturable without invoking an installer."""
import json
from pathlib import Path
import unittest


class AndroidInstallVisualInventoryTest(unittest.TestCase):
    def test_all_session_outcomes_have_android_capture_and_status_geometry(self):
        root = Path(__file__).resolve().parents[1]
        manifest = json.loads((root / "visual-tests/scenes.json").read_text())
        scenes = {scene["id"]: scene for scene in manifest["scenes"]}
        fixture = (root / "app/src/androidTest/java/com/kardinal/vpncontrol/ui/VisualCaptureInstrumentedTest.kt").read_text()
        for suffix in ("preparing", "confirmation", "installed", "failed", "unknown"):
            name = "update-install-session-" + suffix
            self.assertEqual(["android"], scenes[name]["platforms"])
            self.assertIn("update-install-session", scenes[name]["required_elements"])
            self.assertIn("update-close", scenes[name]["required_elements"])
            self.assertIn('"' + name + '" ->', fixture)
        self.assertIn("update-install", scenes["update-install-session-confirmation"]["required_elements"])


if __name__ == "__main__":
    unittest.main()

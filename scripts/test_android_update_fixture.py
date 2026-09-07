from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.integration.android_update_fixture import APK_PATH, MANIFEST_PATH, make_manifest, select_resource


class AndroidUpdateFixtureTest(unittest.TestCase):
    def test_fixture_serves_only_exact_trusted_paths_without_forwarding(self):
        self.assertEqual("manifest", select_resource("GET", MANIFEST_PATH, "github.com"))
        self.assertEqual("apk", select_resource("GET", APK_PATH, "github.com:443"))
        for method, path, host in (("POST", APK_PATH, "github.com"), ("GET", "/", "github.com"),
                                   ("GET", APK_PATH, "github.com.attacker.invalid"),
                                   ("GET", "https://elsewhere.invalid/", "github.com")):
            self.assertIsNone(select_resource(method, path, host))

    def test_manifest_hashes_exact_artifact_and_keeps_production_trust_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            apk.write_bytes(b"abc")
            result = make_manifest(apk, "2.1.3", 16460)
        asset = result["assets"][0]
        self.assertEqual("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", asset["sha256"])
        self.assertEqual(3, asset["sizeBytes"])
        self.assertTrue(asset["downloadUrl"].startswith("https://github.com/Karapsin/vpn_control/"))
        self.assertEqual(16460, result["buildNumber"])


if __name__ == "__main__":
    unittest.main()

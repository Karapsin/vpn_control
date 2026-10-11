"""Exercise Git's Windows line-ending conversion on exact historical fixtures."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = (
    ("agent_tools/tests/fixtures/windows_cp117_recovery/short_socket_51538dad.source",
     "51538dad4c2fa6591384081f5a0aabacada1e752c1afd6a6ed50ebed9596663e"),
    ("agent_tools/tests/fixtures/android_proxy_os_history/retirement_3eed5a2e.source",
     "3eed5a2ecf544ab306e79847152145e1d78112bd5f40ec00f66a8638e0c40f7c"),
    ("agent_tools/tests/fixtures/android_component_legacy/provenance.json",
     "c4c4afe5b101f099f23bc80cc8dfb7e1d3febff7299ee53672128a0440806742"),
)
PINNED_FAMILIES = (
    "scripts/testdata/windows-persistent-ready-parser",
    "scripts/testdata/windows-persistent-taskroot",
)


class HistoricalFixtureCheckoutBytesTest(unittest.TestCase):
    def test_windows_checkout_preserves_exact_historical_bytes(self):
        fixtures = [(name, expected, None) for name, expected in FIXTURES]
        for family in PINNED_FAMILIES:
            pins = json.loads((ROOT / family / "fixture-pins.json").read_bytes())["files"]
            fixtures.extend((f"{family}/{name}", pin["sha256"], pin["bytes"])
                            for name, pin in pins.items())
        env = {key: value for key, value in os.environ.items()
               if not key.startswith("GIT_")}
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        with tempfile.TemporaryDirectory(prefix="fixture-checkout-") as directory:
            checkout = Path(directory)

            def git(*args):
                result = subprocess.run(
                    ["git", "-c", "core.autocrlf=true", "-c", "core.safecrlf=false", *args],
                    cwd=checkout, env=env, capture_output=True, timeout=20,
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))

            git("init", "--quiet")
            (checkout / ".gitattributes").write_bytes((ROOT / ".gitattributes").read_bytes())
            for name, expected, expected_bytes in fixtures:
                raw = (ROOT / name).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), expected)
                if expected_bytes is not None:
                    self.assertEqual(len(raw), expected_bytes)
                target = checkout / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
            control = "checkout-conversion-control.txt"
            (checkout / control).write_bytes(b"unprotected LF text\nsecond line\n")
            git("add", "--", ".gitattributes", control,
                *(name for name, _, _ in fixtures))
            for name, _, _ in fixtures:
                (checkout / name).unlink()
            (checkout / control).unlink()
            git("checkout-index", "--all")
            self.assertEqual((checkout / control).read_bytes(),
                             b"unprotected LF text\r\nsecond line\r\n")
            for name, expected, expected_bytes in fixtures:
                with self.subTest(fixture=name):
                    raw = (checkout / name).read_bytes()
                    self.assertEqual(hashlib.sha256(raw).hexdigest(), expected)
                    if expected_bytes is not None:
                        self.assertEqual(len(raw), expected_bytes)

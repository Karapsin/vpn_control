"""Exercise Git's Windows line-ending conversion on exact historical fixtures."""
import hashlib
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


class HistoricalFixtureCheckoutBytesTest(unittest.TestCase):
    def test_windows_checkout_preserves_exact_historical_bytes(self):
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
            for name, expected in FIXTURES:
                raw = (ROOT / name).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), expected)
                target = checkout / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
            git("add", "--", ".gitattributes", *(name for name, _ in FIXTURES))
            for name, _ in FIXTURES:
                (checkout / name).unlink()
            git("checkout-index", "--all")
            for name, expected in FIXTURES:
                with self.subTest(fixture=name):
                    self.assertEqual(hashlib.sha256((checkout / name).read_bytes()).hexdigest(),
                                     expected)

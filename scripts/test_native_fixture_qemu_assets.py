#!/usr/bin/env python3
"""Regression coverage for the private QEMU asset preflight.

The preflight is deliberately a file-only check: this test never invokes QEMU
or a guest.
"""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("native_fixture_qemu_assets.py")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class NativeFixtureQemuAssetsTest(unittest.TestCase):
    def run_preflight(self, root: Path, *assets: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(root), *(item for asset in assets for item in ("--asset", asset))],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_missing_vga_rom_is_red_then_matching_rom_is_green(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = digest(b"private vga rom")
            request = f"vgabios-stdvga.bin={expected}"

            missing = self.run_preflight(root, request)
            self.assertNotEqual(0, missing.returncode, "RED: a missing VGA ROM must block VM startup")
            self.assertIn("vgabios-stdvga.bin", missing.stderr)
            self.assertEqual("", missing.stdout)

            rom = root / "vgabios-stdvga.bin"
            rom.write_bytes(b"private vga rom")
            accepted = self.run_preflight(root, request)
            self.assertEqual(0, accepted.returncode, accepted.stderr)
            self.assertEqual(
                {"status": "ok", "assets": [{"path": "vgabios-stdvga.bin", "sha256": expected, "bytes": len(rom.read_bytes())}]},
                json.loads(accepted.stdout),
            )

    def test_changed_bytes_and_bad_relative_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            asset = root / "firmware" / "vgabios-stdvga.bin"
            asset.parent.mkdir()
            asset.write_bytes(b"known-good")
            request = f"firmware/vgabios-stdvga.bin={digest(asset.read_bytes())}"
            self.assertEqual(0, self.run_preflight(root, request).returncode)

            asset.write_bytes(b"changed")
            changed = self.run_preflight(root, request)
            self.assertNotEqual(0, changed.returncode)
            self.assertIn("digest mismatch", changed.stderr)

            for path in ("/absolute.bin", "../escape.bin", "nested/../escape.bin", "./asset.bin", r"nested\\asset.bin", "C:asset.bin"):
                with self.subTest(path=path):
                    rejected = self.run_preflight(root, f"{path}={digest(b'x')}")
                    self.assertNotEqual(0, rejected.returncode)
                    self.assertIn("invalid asset path", rejected.stderr)

    def test_symlink_escape_is_rejected_when_symlinks_are_available(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "private"
            root.mkdir()
            outside = Path(temporary) / "outside"
            outside.mkdir()
            target = outside / "vgabios-stdvga.bin"
            target.write_bytes(b"private-looking bytes")
            linked_parent = root / "firmware"
            try:
                linked_parent.symlink_to(outside, target_is_directory=True)
            except (NotImplementedError, OSError) as error:
                self.skipTest(f"symbolic links unavailable on this platform: {error}")

            rejected = self.run_preflight(
                root, f"firmware/vgabios-stdvga.bin={digest(target.read_bytes())}"
            )
            self.assertNotEqual(0, rejected.returncode)
            self.assertIn("symbolic link", rejected.stderr)


if __name__ == "__main__":
    unittest.main()

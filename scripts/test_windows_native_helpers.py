#!/usr/bin/env python3
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from windows_native_helpers import fixture_transfer_target, validate_guest_destination


TOOL = Path(__file__).with_name("windows_native_helpers.py")


def pe(machine=0x8664, clr=False, marker=b""):
    body = bytearray(0x200)
    body[:2] = b"MZ"
    body[0x3C:0x40] = (0x80).to_bytes(4, "little")
    body[0x80:0x84] = b"PE\0\0"
    body[0x84:0x86] = machine.to_bytes(2, "little")
    body[0x94:0x96] = (0xF0).to_bytes(2, "little")
    body[0x98:0x9A] = (0x20B).to_bytes(2, "little")
    if clr:
        body[0x98 + 112 + 14 * 8:0x98 + 112 + 14 * 8 + 8] = b"\x01\0\0\0\x08\0\0\0"
    return bytes(body) + marker


def import_pe(dll):
    body = bytearray(0x600)
    body[:2] = b"MZ"; body[0x3C:0x40] = (0x80).to_bytes(4, "little")
    body[0x80:0x84] = b"PE\0\0"; body[0x84:0x86] = (0x8664).to_bytes(2, "little"); body[0x86:0x88] = (1).to_bytes(2, "little")
    body[0x94:0x96] = (0xF0).to_bytes(2, "little"); body[0x98:0x9A] = (0x20B).to_bytes(2, "little")
    body[0x98 + 112 + 8:0x98 + 112 + 16] = (0x1000).to_bytes(4, "little") + (40).to_bytes(4, "little")
    section = 0x80 + 24 + 0xF0
    body[section:section + 8] = b".rdata\0\0"
    body[section + 8:section + 24] = (0x400).to_bytes(4, "little") + (0x1000).to_bytes(4, "little") + (0x400).to_bytes(4, "little") + (0x200).to_bytes(4, "little")
    body[0x200 + 12:0x200 + 16] = (0x1030).to_bytes(4, "little")
    body[0x230:0x230 + len(dll) + 1] = dll.encode("ascii") + b"\0"
    return bytes(body)


class WindowsNativeHelpersTest(unittest.TestCase):
    def run_tool(self, *args):
        return subprocess.run([sys.executable, str(TOOL), *map(str, args)], text=True, capture_output=True)

    def test_source_manifest_is_stable_and_hashed(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            source = root / "input.cs"; source.write_text("class Input {}", encoding="utf-8")
            result = self.run_tool("sources", "--output", root / "sources.json", source)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads((root / "sources.json").read_text())
            self.assertEqual(data["inputs"][0]["path"], str(source.resolve()))
            self.assertEqual(len(data["fingerprint"]), 64)

    def test_rejects_clr_and_test_product_artifacts(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            bad = root / "vpn-control-install-helper.exe"; bad.write_bytes(pe(clr=True))
            self.assertNotEqual(self.run_tool("verify-product", "--output", bad, "--manifest", root / "m.json", "--allowed-import", "kernel32.dll").returncode, 0)
            test = root / "vpn-control-broker-tests.exe"; test.write_bytes(pe())
            self.assertNotEqual(self.run_tool("verify-product", "--output", test, "--manifest", root / "m.json", "--allowed-import", "kernel32.dll").returncode, 0)

    def test_accepts_amd64_native_aot_shape(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            output = root / "vpn-control-install-helper.exe"; output.write_bytes(pe())
            result = self.run_tool("verify-product", "--output", output, "--manifest", root / "m.json", "--allowed-import", "kernel32.dll")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(json.loads((root / "m.json").read_text())["artifacts"][0]["clrHeader"])

    def test_fixture_target_guard_rejects_the_legacy_sibling(self):
        expected = "fresh-msi"
        legacy_target = Path("/guests/old-native")
        fixture = "native-aot-config-v2.zip"
        # Causal RED: the prior transfer calculation accepted the old guest and
        # formed exactly the destination that caused the observed HTTP 404.
        self.assertEqual(legacy_target / "transfer" / fixture, Path("/guests/old-native/transfer/native-aot-config-v2.zip"))
        with self.assertRaisesRegex(ValueError, "destination identity"):
            fixture_transfer_target(legacy_target, expected, fixture)
        self.assertEqual(fixture_transfer_target(Path("/guests/fresh-msi"), expected, fixture), Path("/guests/fresh-msi/transfer/native-aot-config-v2.zip"))

    def test_import_allowlist_is_enforced(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            output = root / "vpn-control-install-helper.exe"; output.write_bytes(import_pe("kernel32.dll"))
            accepted = self.run_tool("verify-product", "--output", output, "--manifest", root / "m.json", "--allowed-import", "kernel32.dll")
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            rejected = self.run_tool("verify-product", "--output", output, "--manifest", root / "m.json", "--allowed-import", "advapi32.dll")
            self.assertNotEqual(rejected.returncode, 0)

    def test_fixed_installer_helper_has_only_the_nonmutating_probe(self):
        source = (Path(__file__).parents[1] / "desktopApp/src/main/resources/windows-install-helper.cs").read_text(encoding="utf-8")
        self.assertIn('const string ValidateOnly = "validate-only"', source)
        self.assertIn('VPN_INSTALL_HELPER_VALIDATE_ONLY_OK', source)
        self.assertNotIn("Process.Start", source)
        self.assertNotIn("msiexec", source.lower())


if __name__ == "__main__":
    unittest.main()

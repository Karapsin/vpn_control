#!/usr/bin/env python3
import json
import hashlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from windows_native_helpers import fixture_transfer_target, validate_guest_destination, runtime_authority


TOOL = Path(__file__).with_name("windows_native_helpers.py")
MANIFEST = Path(__file__).parents[1] / "desktopApp/native/windows/InstallHelper/loader.manifest"
BROKER_MANIFEST = Path(__file__).parents[1] / "desktopApp/native/windows/VpnBroker/loader.manifest"


def pe(machine=0x8664, clr=False, marker=b"", dependent_flags=0x800, manifest=None):
    body = bytearray(0x1000)
    body[:2] = b"MZ"
    body[0x3C:0x40] = (0x80).to_bytes(4, "little")
    body[0x80:0x84] = b"PE\0\0"
    body[0x84:0x86] = machine.to_bytes(2, "little")
    body[0x86:0x88] = (1).to_bytes(2, "little")
    body[0x94:0x96] = (0xF0).to_bytes(2, "little")
    body[0x98:0x9A] = (0x20B).to_bytes(2, "little")
    body[0x98 + 108:0x98 + 112] = (16).to_bytes(4, "little")
    section = 0x80 + 24 + 0xF0
    body[section:section + 8] = b".rdata\0\0"
    body[section + 8:section + 24] = ((0xE00).to_bytes(4, "little") +
        (0x1000).to_bytes(4, "little") + (0xE00).to_bytes(4, "little") + (0x200).to_bytes(4, "little"))
    if dependent_flags is not None:
        directory = 0x98 + 112 + 10 * 8
        body[directory:directory + 8] = (0x1200).to_bytes(4, "little") + (0x140).to_bytes(4, "little")
        body[0x400:0x404] = (0x140).to_bytes(4, "little")
        body[0x400 + 78:0x400 + 80] = dependent_flags.to_bytes(2, "little")
    manifest = MANIFEST.read_bytes() if manifest is None else manifest
    resource_directory = 0x98 + 112 + 2 * 8
    body[resource_directory:resource_directory + 8] = ((0x1400).to_bytes(4, "little") +
        (0x80 + len(manifest)).to_bytes(4, "little"))
    for directory, identifier, target in ((0x600, 24, 0x80000020), (0x620, 1, 0x80000040), (0x640, 1033, 0x60)):
        body[directory + 14:directory + 16] = (1).to_bytes(2, "little")
        body[directory + 16:directory + 24] = identifier.to_bytes(4, "little") + target.to_bytes(4, "little")
    body[0x660:0x668] = (0x1480).to_bytes(4, "little") + len(manifest).to_bytes(4, "little")
    body[0x680:0x680 + len(manifest)] = manifest
    if clr:
        body[0x98 + 112 + 14 * 8:0x98 + 112 + 14 * 8 + 8] = b"\x01\0\0\0\x08\0\0\0"
    return bytes(body) + marker


def import_pe(dll, dependent_flags=0x800):
    body = bytearray(pe(dependent_flags=dependent_flags))
    body[0x98 + 112 + 8:0x98 + 112 + 16] = (0x1000).to_bytes(4, "little") + (40).to_bytes(4, "little")
    body[0x200 + 12:0x200 + 16] = (0x1030).to_bytes(4, "little")
    body[0x230:0x230 + len(dll) + 1] = dll.encode("ascii") + b"\0"
    return bytes(body)


class WindowsNativeHelpersTest(unittest.TestCase):
    def run_tool(self, *args):
        return subprocess.run([sys.executable, str(TOOL), *map(str, args)], text=True, capture_output=True)

    def verified_pair(self, directory):
        install = directory / "vpn-control-install-helper.exe"
        broker = directory / "vpn-control-vpn-broker.exe"
        install.write_bytes(pe())
        broker.write_bytes(pe(manifest=BROKER_MANIFEST.read_bytes()))
        runtime = directory / "sing-box.exe"
        runtime.write_bytes(pe())
        authority = directory / "authority.cs"
        runtime_authority(runtime, authority)
        manifest = directory / "native-helpers.json"
        result = self.run_tool("verify-product", "--output", install, "--output", broker,
                               "--manifest", manifest, "--runtime", runtime, "--authority-source", authority)
        self.assertEqual(0, result.returncode, result.stderr)
        return install, broker, manifest

    def image_with_runtime(self, image, contents=None):
        (image / "app").mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(image / "app/runtime.jar", "w") as jar:
            jar.writestr("bin/windows-amd64/sing-box.exe", pe() if contents is None else contents)

    def test_source_manifest_is_stable_and_hashed(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            source = root / "input.cs"; source.write_text("class Input {}", encoding="utf-8")
            result = self.run_tool("sources", "--output", root / "sources.json", source)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads((root / "sources.json").read_text())
            self.assertEqual(data["inputs"][0]["path"], str(source.resolve()))
            self.assertEqual(len(data["fingerprint"]), 64)

    def test_kotlin_broker_admission_fixture_matches_current_producer(self):
        resources = Path(__file__).parents[1] / "desktopApp/src/test/resources"
        expected = json.loads((resources / "windows-vpn-helper-producer-fixture.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            install = root / "vpn-control-install-helper.exe"
            broker = root / "vpn-control-vpn-broker.exe"
            runtime = root / "sing-box.exe"
            authority = root / "authority.cs"
            manifest = root / "native-helpers.json"
            install.write_bytes(pe())
            broker.write_bytes((resources / "windows-vpn-helper-producer-image.bin").read_bytes())
            runtime.write_bytes((resources / "windows-vpn-helper-producer-runtime.bin").read_bytes())
            generated = self.run_tool("runtime-authority", "--runtime", runtime, "--output", authority)
            self.assertEqual(0, generated.returncode, generated.stderr)
            result = self.run_tool("verify-product", "--output", install, "--output", broker,
                "--manifest", manifest, "--runtime", runtime, "--authority-source", authority)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(expected, json.loads(manifest.read_text(encoding="utf-8")))

    def test_runtime_authority_is_bound_to_prepared_amd64_bytes(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            runtime = root / "sing-box.exe"
            generated = root / "authority.cs"
            for contents in (pe(), pe(marker=b"changed-runtime")):
                runtime.write_bytes(contents)
                result = self.run_tool("runtime-authority", "--runtime", runtime, "--output", generated)
                self.assertEqual(0, result.returncode, result.stderr)
                expected = hashlib.sha256(contents).hexdigest()
                self.assertEqual(expected, json.loads(result.stdout)["runtimeSha256"])
                self.assertIn('internal const string Sha256 = "' + expected + '";', generated.read_text())
                self.assertNotIn(str(runtime), generated.read_text())

    def test_runtime_authority_rejects_missing_and_wrong_architecture_inputs(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            runtime = root / "sing-box.exe"
            generated = root / "authority.cs"
            self.assertNotEqual(0, self.run_tool("runtime-authority", "--runtime", runtime, "--output", generated).returncode)
            for contents in (b"not a PE", pe(machine=0xaa64), pe(machine=0x14c)):
                runtime.write_bytes(contents)
                result = self.run_tool("runtime-authority", "--runtime", runtime, "--output", generated)
                self.assertNotEqual(0, result.returncode, result.stdout)
                self.assertFalse(generated.exists())

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

    def test_stages_verified_helper_into_the_prepared_application(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            output, broker, manifest = self.verified_pair(root)
            image = root / "prepared application"
            self.image_with_runtime(image)
            result = self.run_tool("stage-product", "--output", output, "--output", broker, "--manifest", manifest,
                                   "--app-image", image)
            self.assertEqual(result.returncode, 0, result.stderr)
            staged = image / "app/native/windows-amd64"
            self.assertEqual((staged / output.name).read_bytes(), output.read_bytes())
            self.assertEqual((staged / broker.name).read_bytes(), broker.read_bytes())
            self.assertEqual(json.loads((staged / manifest.name).read_text()), json.loads(manifest.read_text()))
            inspected = self.run_tool("inspect-image", "--app-image", image)
            self.assertEqual(inspected.returncode, 0, inspected.stderr)

    def test_staging_rejects_broker_without_runtime_authority(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            output, broker, manifest = self.verified_pair(root)
            record = json.loads(manifest.read_text())
            record.pop("runtimeAuthority", None)
            manifest.write_text(json.dumps(record))
            image = root / "image"
            (image / "app").mkdir(parents=True)
            result = self.run_tool("stage-product", "--output", output, "--output", broker,
                                   "--manifest", manifest, "--app-image", image)
            self.assertNotEqual(0, result.returncode,
                                "A broker with no captured runtime binding was packaged")
            self.assertIn("runtime authority", result.stderr)
            self.assertFalse((image / "app/native/windows-amd64").exists())

    def test_staging_and_inspection_reject_replaced_or_ambiguous_runtime(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            output, broker, manifest = self.verified_pair(root)
            image = root / "image"
            args = ("stage-product", "--output", output, "--output", broker,
                    "--manifest", manifest, "--app-image", image)
            changed = bytearray(pe())
            changed[-1] ^= 1
            self.image_with_runtime(image, bytes(changed))
            result = self.run_tool(*args)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("runtime differs", result.stderr)
            self.assertFalse((image / "app/native/windows-amd64").exists())
            self.image_with_runtime(image)
            result = self.run_tool(*args)
            self.assertEqual(0, result.returncode, result.stderr)
            self.image_with_runtime(image, bytes(changed))
            self.assertNotEqual(0, self.run_tool("inspect-image", "--app-image", image).returncode)
            self.image_with_runtime(image)
            (image / "app/duplicate.jar").write_bytes((image / "app/runtime.jar").read_bytes())
            result = self.run_tool("inspect-image", "--app-image", image)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("ambiguous", result.stderr)

    def test_product_rejects_changed_compiled_authority_source(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            output, broker, manifest = self.verified_pair(root)
            original = manifest.read_bytes()
            (root / "authority.cs").write_text("class WrongAuthority {}")
            result = self.run_tool("verify-product", "--output", output, "--output", broker,
                                   "--manifest", manifest, "--runtime", root / "sing-box.exe",
                                   "--authority-source", root / "authority.cs")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("authority source disagrees", result.stderr)
            self.assertEqual(original, manifest.read_bytes())

    def test_product_rejects_invalid_runtime_authority_metadata(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            output, broker, manifest = self.verified_pair(root)
            original = json.loads(manifest.read_text())
            image = root / "image"
            self.image_with_runtime(image)
            for field, value in (("runtimeSizeBytes", True), ("runtimeSizeBytes", 63),
                                 ("runtimeSha256", "A" * 64), ("authoritySourceSha256", "0" * 64),
                                 ("unexpected", "extra")):
                with self.subTest(field=field, value=value):
                    record = json.loads(json.dumps(original))
                    record["runtimeAuthority"][field] = value
                    manifest.write_text(json.dumps(record))
                    result = self.run_tool("stage-product", "--output", output, "--output", broker,
                                           "--manifest", manifest, "--app-image", image)
                    self.assertNotEqual(0, result.returncode)
                    self.assertIn("runtime authority", result.stderr)
                    self.assertFalse((image / "app/native/windows-amd64").exists())

    def test_staging_rejects_package_without_the_fixed_vpn_broker(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            output = root / "vpn-control-install-helper.exe"
            output.write_bytes(pe())
            manifest = root / "native-helpers.json"
            self.assertEqual(self.run_tool("verify-product", "--output", output,
                                           "--manifest", manifest).returncode, 0)
            image = root / "image"
            (image / "app").mkdir(parents=True)
            result = self.run_tool("stage-product", "--output", output,
                                   "--manifest", manifest, "--app-image", image)
            self.assertNotEqual(0, result.returncode,
                                "A package missing the fixed VPN broker was accepted")
            self.assertFalse((image / "app/native/windows-amd64").exists())

    def test_rejects_changed_helper_or_manifest_before_staging(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            output, broker, manifest = self.verified_pair(root)
            image = root / "image"
            (image / "app").mkdir(parents=True)
            original_manifest = manifest.read_bytes()
            output.write_bytes(pe(marker=b"changed"))
            result = self.run_tool("stage-product", "--output", output, "--output", broker, "--manifest", manifest,
                                   "--app-image", image)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("manifest disagrees", result.stderr)
            self.assertFalse((image / "app/native/windows-amd64").exists())
            output.write_bytes(pe())
            record = json.loads(original_manifest)
            record["artifacts"][0]["operations"] = ["arbitrary-command"]
            manifest.write_text(json.dumps(record))
            result = self.run_tool("stage-product", "--output", output, "--output", broker, "--manifest", manifest,
                                   "--app-image", image)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("manifest disagrees", result.stderr)
            self.assertFalse((image / "app/native/windows-amd64").exists())

    def test_inspection_rejects_missing_and_modified_packaged_helpers(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            image = root / "image"
            native = image / "app/native/windows-amd64"
            native.mkdir(parents=True)
            result = self.run_tool("inspect-image", "--app-image", image)
            self.assertNotEqual(result.returncode, 0)
            output, broker, _ = self.verified_pair(native)
            for candidate in (output, broker):
                original = candidate.read_bytes()
                candidate.write_bytes(original + b"replaced-after-package")
                result = self.run_tool("inspect-image", "--app-image", image)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("manifest disagrees", result.stderr)
                candidate.write_bytes(original)
            broker.unlink()
            self.assertNotEqual(0, self.run_tool("inspect-image", "--app-image", image).returncode)

    def test_fixture_target_guard_rejects_the_legacy_sibling(self):
        expected = "fresh-msi"
        legacy_target = Path("/guests/old-native")
        fixture = "native-aot-config-v2.zip"
        # Causal RED: the prior transfer calculation accepted the old guest and
        # formed exactly the destination that caused the observed HTTP 404.
        self.assertEqual(legacy_target / "transfer" / fixture, Path("/guests/old-native/transfer/native-aot-config-v2.zip"))
        with self.assertRaisesRegex(ValueError, "destination identity"):
            fixture_transfer_target(legacy_target, expected, fixture)
        self.assertEqual(fixture_transfer_target(Path("/guests/fresh-msi"), expected, fixture), Path("/guests/fresh-msi/transfer/native-aot-config-v2.zip").resolve())

    def test_import_allowlist_is_enforced(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            output = root / "vpn-control-install-helper.exe"; output.write_bytes(import_pe("kernel32.dll"))
            accepted = self.run_tool("verify-product", "--output", output, "--manifest", root / "m.json", "--allowed-import", "kernel32.dll")
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            rejected = self.run_tool("verify-product", "--output", output, "--manifest", root / "m.json", "--allowed-import", "advapi32.dll")
            self.assertNotEqual(rejected.returncode, 0)

    def test_native_aot_without_system32_dependent_load_flags_is_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            output = root / "vpn-control-install-helper.exe"
            for flags in (None, 0, 0x1000, 0x1800):
                with self.subTest(flags=flags):
                    output.write_bytes(import_pe("kernel32.dll", dependent_flags=flags))
                    result = self.run_tool("verify-product", "--output", output, "--manifest", root / "m.json",
                                           "--allowed-import", "kernel32.dll")
                    self.assertNotEqual(0, result.returncode, "Unhardened PE was accepted: " + result.stdout)

    def test_caller_allowlist_cannot_approve_a_companion_dependency(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            output = root / "vpn-control-install-helper.exe"
            output.write_bytes(import_pe("vpn-user-plugin.dll"))
            result = self.run_tool("verify-product", "--output", output, "--manifest", root / "m.json",
                                   "--allowed-import", "vpn-user-plugin.dll")
            self.assertNotEqual(0, result.returncode, "Caller expanded the reviewed policy: " + result.stdout)

    def test_unreviewed_embedded_manifest_cannot_be_certified(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            output = root / "vpn-control-install-helper.exe"
            changed = MANIFEST.read_bytes().replace(b'level="asInvoker"', b'level="requireAdministrator"')
            output.write_bytes(pe(manifest=changed))
            result = self.run_tool("verify-product", "--output", output, "--manifest", root / "m.json")
            self.assertNotEqual(0, result.returncode, "Unreviewed execution manifest was accepted: " + result.stdout)

    def test_fixed_installer_helper_has_only_the_nonmutating_probe(self):
        source = (Path(__file__).parents[1] / "desktopApp/src/main/resources/windows-install-helper.cs").read_text(encoding="utf-8")
        self.assertIn('const string ValidateOnly = "validate-only"', source)
        self.assertIn('VPN_INSTALL_HELPER_VALIDATE_ONLY_OK', source)
        self.assertNotIn("Process.Start", source)
        self.assertNotIn("msiexec", source.lower())


if __name__ == "__main__":
    unittest.main()

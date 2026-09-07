"""Portable causal checks for the actual Arch base verifier."""
import hashlib
import json
from pathlib import Path
import shutil
import stat
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
import zipfile

from arch_public_update import verify_arch_bundle_base
from prepare_desktop_update_fixture import MAIN_CLASS, VERSION_RESOURCE, image_identity, version_build


class ArchBundleBaseTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="vpn-arch-verifier-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.image = self.root / "installed"
        app = self.image / "lib/app"
        app.mkdir(parents=True)
        (self.image / "bin").mkdir()
        self.launcher = self.image / "bin/vpn-control"
        self.launcher.write_bytes(b"ELF-fixture-never-executed")
        self.jar = app / "main.jar"
        with zipfile.ZipFile(self.jar, "w") as jar:
            jar.writestr(MAIN_CLASS, b"actual-fixture-class")
            jar.writestr(VERSION_RESOURCE, "displayVersion=2.1.3\nbuildNumber=" + str(version_build("2.1.3")) + "\n")
        (app / "vpn-control.cfg").write_text(
            "[Application]\napp.mainclass=com.kardinal.vpncontrol.desktop.MainKt\napp.classpath=$APPDIR/main.jar\n")
        identity = image_identity(self.image, "2.1.3")
        self.package = self.root / "packages/base/base.tar.gz"
        self.package.parent.mkdir(parents=True)
        runtime = self.root / "runtime"
        runtime.write_bytes(b"runtime-fixture-never-executed")
        with tarfile.open(self.package, "w:gz") as archive:
            archive.add(self.image, arcname="vpn-control-arch-update/app")
            archive.add(runtime, arcname="vpn-control-arch-update/sing-box")
        shutil.copyfile(runtime, self.image / "bin/sing-box")
        asset = {"fileName": self.package.name, "packageType": "arch-bundle", "platform": "linux",
                 "displayVersion": "2.1.3", "sizeBytes": self.package.stat().st_size,
                 "sha256": hashlib.sha256(self.package.read_bytes()).hexdigest()}
        base = {"label": "base", "version": "2.1.3", "sourceFingerprint": "a" * 64,
                "assets": [asset], **identity}
        target = {**base, "label": "target", "version": "2.1.4"}
        self.receipt = {"schemaVersion": 1, "testOnly": True, "productionTrustChanged": False,
                        "sourceFingerprint": "a" * 64, "builds": [base, target]}
        self.write_receipt()

    def write_receipt(self):
        (self.root / "fixture-receipt.json").write_text(json.dumps(self.receipt))

    def trusted_stat(self, path):
        # Preserve real file kinds/size: only model root ownership and private
        # modes so the test is portable and never needs privileged host writes.
        info = path.lstat()
        return SimpleNamespace(st_uid=0, st_mode=stat.S_IFMT(info.st_mode) | 0o755,
                               st_size=info.st_size)

    def verify(self, **options):
        return verify_arch_bundle_base(self.launcher, self.root,
                                       lstat=options.get("lstat", self.trusted_stat))

    def test_actual_jar_and_bundle_are_accepted_without_a_marker(self):
        result = self.verify()
        self.assertEqual(image_identity(self.image, "2.1.3")["mainJarSha256"], result["mainJarSha256"])
        self.assertFalse((self.image / "TEST-ONLY-INSTALL-FIXTURE.json").exists())

    def test_changed_installed_jar_is_rejected(self):
        data = bytearray(self.jar.read_bytes())
        data[-1] ^= 1
        self.jar.write_bytes(data)
        with self.assertRaisesRegex(RuntimeError, "Installed bytes differ"):
            self.verify()

    def test_changed_native_launcher_is_rejected(self):
        self.launcher.write_bytes(b"X" * self.launcher.stat().st_size)
        with self.assertRaisesRegex(RuntimeError, "Installed bytes differ"):
            self.verify()

    def test_changed_runtime_is_rejected(self):
        runtime = self.image / "bin/sing-box"
        runtime.write_bytes(b"X" * runtime.stat().st_size)
        with self.assertRaisesRegex(RuntimeError, "Installed bytes differ"):
            self.verify()

    def test_altered_archive_is_rejected_before_parsing(self):
        self.package.write_bytes(b"X" * self.package.stat().st_size)
        with self.assertRaisesRegex(RuntimeError, "bundle hash mismatch"):
            self.verify()

    def test_wrong_source_pair_is_rejected(self):
        self.receipt["builds"][1]["sourceFingerprint"] = "b" * 64
        self.write_receipt()
        with self.assertRaisesRegex(RuntimeError, "Mismatched source pair"):
            self.verify()

    def test_untrusted_ancestor_is_rejected(self):
        def insecure(path):
            info = self.trusted_stat(path)
            if path == self.image:
                info.st_mode |= 0o020
            return info
        with self.assertRaisesRegex(RuntimeError, "Untrusted installed"):
            self.verify(lstat=insecure)

    def test_directory_disguised_as_regular_file_is_rejected(self):
        def wrong_kind(path):
            info = self.trusted_stat(path)
            if path == self.image:
                info.st_mode = stat.S_IFREG | 0o755
            return info
        with self.assertRaisesRegex(RuntimeError, "Untrusted installed"):
            self.verify(lstat=wrong_kind)

    def test_unexpected_installed_file_is_rejected(self):
        (self.image / "lib/app/extra.jar").write_bytes(b"unlisted")
        with self.assertRaisesRegex(RuntimeError, "Unexpected or missing"):
            self.verify()

    def test_escaped_asset_name_is_rejected(self):
        self.receipt["builds"][0]["assets"][0]["fileName"] = "../base.tar.gz"
        self.write_receipt()
        with self.assertRaisesRegex(RuntimeError, "Wrong Arch base asset"):
            self.verify()


if __name__ == "__main__":
    unittest.main()

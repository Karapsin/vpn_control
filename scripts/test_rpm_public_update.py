"""Causal admission checks for RPM same-source public-update fixtures."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from rpm_public_update import verify_rpm_bundle_base


class RpmPublicUpdateAdmissionTest(unittest.TestCase):
    fingerprint = "a" * 64
    source_sha = "b" * 40
    identity = {"codeFingerprint": "c" * 64, "mainJar": "lib/app/main.jar", "mainJarSha256": "d" * 64}

    def fixture(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "pair"; package = root / "packages/base/vpn-control-2.1.16-1.x86_64.rpm"
        package.parent.mkdir(parents=True); package.write_bytes(b"frozen-rpm")
        asset = {"fileName": package.name, "packageType": "rpm", "platform": "linux", "displayVersion": "2.1.16",
                 "sizeBytes": package.stat().st_size, "sha256": hashlib.sha256(package.read_bytes()).hexdigest()}
        base = {"label": "base", "version": "2.1.16", "sourceFingerprint": self.fingerprint,
                "sourceSha": self.source_sha, "assets": [asset], **self.identity}
        target = {**base, "label": "target", "version": "2.1.17"}
        (root / "fixture-receipt.json").write_text(json.dumps({"schemaVersion": 1, "testOnly": True,
            "productionTrustChanged": False, "sourceFingerprint": self.fingerprint, "sourceSha": self.source_sha,
            "builds": [base, target]}))
        return root, package

    def runner(self, package, *, installed=None, expected_header="e" * 40, installed_header=None,
               verify="", owner="vpn-control\n"):
        expected = ("vpn-control", "0", "2.1.16", "1", "x86_64", expected_header)
        installed = installed or expected
        installed_header = installed_header or expected_header
        def run(arguments, **kwargs):
            if arguments[:3] == ["rpm", "--query", "--file"]: return subprocess.CompletedProcess(arguments, 0, owner, "")
            if arguments[:3] in (["rpm", "-qp", "--qf"], ["rpm", "-q", "--qf"]):
                value = expected if arguments[-1] == str(package) else (*installed[:5], installed_header)
                if "SHA1HEADER" in arguments[3]:
                    output = "\t".join(value)
                else:
                    output = "-".join(value[:1] + value[2:4]) + "." + value[4]
                return subprocess.CompletedProcess(arguments, 0, output + "\n", "")
            if arguments == ["rpm", "-V", "vpn-control"]: return subprocess.CompletedProcess(arguments, 0, verify, "")
            raise AssertionError(arguments)
        return run

    def verify(self, root, package, **options):
        return verify_rpm_bundle_base("/opt/vpn-control/bin/vpn-control", root, runner=self.runner(package, **options),
                                      identity=lambda image, version: self.identity, platform_name="linux")

    def test_rpm_pair_requires_the_exact_base_package_before_owner_startup(self):
        root, package = self.fixture()
        result = self.verify(root, package)
        self.assertEqual("rpm", result["packageType"])
        self.assertEqual(self.fingerprint, result["sourceFingerprint"])
        self.assertEqual(self.source_sha, result["sourceSha"])

    def test_changed_rpm_bytes_reject_before_any_rpm_query(self):
        root, package = self.fixture(); package.write_bytes(b"changed")
        with self.assertRaisesRegex(RuntimeError, "hash or size"):
            verify_rpm_bundle_base("/opt/vpn-control/bin/vpn-control", root,
                                   runner=lambda *args, **kwargs: self.fail("RPM query must not run"),
                                   identity=lambda *args: self.fail("identity must not run"), platform_name="linux")

    def test_source_sha_and_fingerprint_are_compared_as_distinct_fields(self):
        root, package = self.fixture(); receipt = json.loads((root / "fixture-receipt.json").read_text())
        receipt["builds"][1]["sourceSha"] = "e" * 40; (root / "fixture-receipt.json").write_text(json.dumps(receipt))
        with self.assertRaisesRegex(RuntimeError, "source SHA"):
            self.verify(root, package)

    def test_rejects_old_installed_nevra_before_image_identity(self):
        root, package = self.fixture()
        with self.assertRaisesRegex(RuntimeError, "NEVRA"):
            self.verify(root, package, installed=("vpn-control", "0", "2.1.15", "1", "x86_64", "e" * 40))

    def test_rejects_clean_same_nevra_rpm_with_different_frozen_header_before_verification(self):
        root, package = self.fixture()
        with self.assertRaisesRegex(RuntimeError, "header differs"):
            self.verify(root, package, installed_header="f" * 40)

    def test_rejects_dirty_installed_rpm_before_image_identity(self):
        root, package = self.fixture()
        with self.assertRaisesRegex(RuntimeError, "verification"):
            self.verify(root, package, verify="..5....T. /opt/vpn-control/lib/app/main.jar\n")

    def test_rejects_different_installed_image_after_clean_package_checks(self):
        root, package = self.fixture()
        with self.assertRaisesRegex(RuntimeError, "image differs"):
            verify_rpm_bundle_base("/opt/vpn-control/bin/vpn-control", root, runner=self.runner(package),
                                   identity=lambda image, version: {**self.identity, "mainJarSha256": "f" * 64}, platform_name="linux")


if __name__ == "__main__":
    unittest.main()

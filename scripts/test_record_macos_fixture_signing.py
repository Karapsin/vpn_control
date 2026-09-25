#!/usr/bin/env python3
"""Portable regression tests for macOS fixture signing evidence binding."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
import subprocess

from record_macos_fixture_signing import Attachment, cleanup_attachment, inspect_dmg, record


class MacosFixtureSigningRecordTest(unittest.TestCase):
    def fixture(self) -> Path:
        root = Path(tempfile.mkdtemp())
        packages = root / "packages"
        builds = []
        for label, version in (("base", "2.1.1"), ("target", "2.1.2")):
            output = packages / label
            output.mkdir(parents=True)
            package = output / f"vpn-control-{version}.dmg"
            package.write_bytes(label.encode())
            builds.append({
                "label": label,
                "version": version,
                "codeFingerprint": "c" * 64,
                "assets": [{"packageType": "dmg", "architecture": "arm64", "fileName": package.name,
                            "sha256": hashlib.sha256(package.read_bytes()).hexdigest()}],
            })
        (root / "build-plan.json").write_text(json.dumps({"platform": "macos", "architecture": "arm64",
                                                            "sourceFingerprint": "s" * 64}), encoding="utf-8")
        (root / "fixture-receipt.json").write_text(json.dumps({"testOnly": True, "sourceFingerprint": "s" * 64,
                                                                 "builds": builds}), encoding="utf-8")
        return root

    def test_records_both_hashed_dmg_stages_with_shared_identity(self):
        root = self.fixture()
        with patch("record_macos_fixture_signing.inspect_dmg", side_effect=lambda dmg, digest, configured: {
            "dmgFileName": dmg.name, "dmgSha256": digest, "signed": False, "configuredSigning": configured,
        }):
            evidence = record(root)
        self.assertEqual("s" * 64, evidence["sourceFingerprint"])
        self.assertEqual("arm64", evidence["architecture"])
        self.assertEqual(["base", "target"], [entry["label"] for entry in evidence["packages"]])
        self.assertTrue((root / "signing-metadata.json").is_file())

    def test_rejects_differing_executable_code_before_dmg_inspection(self):
        root = self.fixture()
        receipt = json.loads((root / "fixture-receipt.json").read_text())
        receipt["builds"][1]["codeFingerprint"] = "d" * 64
        (root / "fixture-receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
        with patch("record_macos_fixture_signing.inspect_dmg") as inspect:
            with self.assertRaisesRegex(ValueError, "code fingerprints differ"):
                record(root)
        inspect.assert_not_called()

    def test_malformed_app_after_owned_mount_runs_identity_safe_cleanup(self):
        root = self.fixture()
        dmg = root / "packages/base/vpn-control-2.1.1.dmg"
        attachment = Attachment("/dev/disk7s1", "/dev/disk7", root / "mount")
        with patch("record_macos_fixture_signing.sha256", return_value="a" * 64), \
             patch("record_macos_fixture_signing.tempfile.mkdtemp", return_value=str(attachment.mount)), \
             patch("record_macos_fixture_signing.attach_dmg", return_value=attachment), \
             patch("record_macos_fixture_signing.app_in_mount", side_effect=ValueError("bad app layout")), \
             patch("record_macos_fixture_signing.cleanup_attachment") as cleanup:
            with self.assertRaisesRegex(ValueError, "bad app layout"):
                inspect_dmg(dmg, "a" * 64, False)
        cleanup.assert_called_once_with(dmg, attachment)

    def test_detach_failure_is_reported_and_never_claims_cleanup_success(self):
        root = self.fixture()
        attachment = Attachment("/dev/disk7s1", "/dev/disk7", root / "mount")
        with patch("record_macos_fixture_signing.attachment_state", return_value="owned-mounted"), \
             patch("record_macos_fixture_signing.subprocess.run") as run:
            run.return_value.returncode = 1
            with self.assertRaisesRegex(RuntimeError, "could not be detached"):
                cleanup_attachment(root / "packages/base/vpn-control-2.1.1.dmg", attachment)
        self.assertFalse(any("-force" in call.args[0] for call in run.call_args_list))

    def test_configured_policy_rejects_an_ad_hoc_signature_after_codesign_verification(self):
        root = self.fixture()
        dmg = root / "packages/base/vpn-control-2.1.1.dmg"
        attachment = Attachment("/dev/disk7s1", "/dev/disk7", root / "mount")
        verified = subprocess.CompletedProcess([], 0, "", "")
        adhoc = subprocess.CompletedProcess([], 0, "", "Signature=adhoc\nIdentifier=fixture\n")
        with patch.dict("os.environ", {"VPN_CONTROL_MACOS_SIGNING_CERTIFICATE_BASE64": "configured",
                                        "VPN_CONTROL_MACOS_SIGNING_IDENTITY": "Developer ID Application: Fixture"}, clear=False), \
             patch("record_macos_fixture_signing.sha256", return_value="a" * 64), \
             patch("record_macos_fixture_signing.tempfile.mkdtemp", return_value=str(attachment.mount)), \
             patch("record_macos_fixture_signing.attach_dmg", return_value=attachment), \
             patch("record_macos_fixture_signing.app_in_mount", return_value=root / "fixture.app"), \
             patch("record_macos_fixture_signing.subprocess.run", side_effect=[verified, adhoc]), \
             patch("record_macos_fixture_signing.cleanup_attachment") as cleanup:
            with self.assertRaisesRegex(ValueError, "ad hoc signature"):
                inspect_dmg(dmg, "a" * 64, True)
        cleanup.assert_called_once_with(dmg, attachment)

    def test_rejects_receipt_traversal_and_symlinked_stage_before_inspection(self):
        root = self.fixture()
        receipt = json.loads((root / "fixture-receipt.json").read_text())
        receipt["builds"][0]["assets"][0]["fileName"] = "../target/vpn-control-2.1.2.dmg"
        (root / "fixture-receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
        with patch("record_macos_fixture_signing.inspect_dmg") as inspect:
            with self.assertRaisesRegex(ValueError, "filename is unsafe"):
                record(root)
        inspect.assert_not_called()

        root = self.fixture()
        stage = root / "packages/base"
        target = root / "outside"
        target.mkdir()
        shutil.rmtree(stage)
        stage.symlink_to(target, target_is_directory=True)
        with patch("record_macos_fixture_signing.inspect_dmg") as inspect:
            with self.assertRaisesRegex(ValueError, "stage path"):
                record(root)
        inspect.assert_not_called()


if __name__ == "__main__":
    unittest.main()

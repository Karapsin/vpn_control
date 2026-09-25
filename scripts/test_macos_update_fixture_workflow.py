#!/usr/bin/env python3
"""Static safety contract for the manual macOS same-source DMG fixture workflow."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent.parent
CALLER = ROOT / ".github/workflows/macos-desktop.yml"
REUSABLE = ROOT / ".github/workflows/macos-update-fixture.yml"
RECORDER = ROOT / "scripts/record_macos_fixture_signing.py"


class MacosUpdateFixtureWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.caller = CALLER.read_text(encoding="utf-8")
        cls.reusable = REUSABLE.read_text(encoding="utf-8")
        cls.recorder = RECORDER.read_text(encoding="utf-8")

    def test_registered_caller_keeps_ordinary_packages_and_gates_fixture_to_dev(self):
        self.assertIn("workflow_dispatch:\n    inputs:\n      fixture_base_version:", self.caller)
        guard = "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/dev' && inputs.fixture_base_version != ''"
        self.assertEqual(2, self.caller.count(guard))
        self.assertIn("if: github.event_name != 'workflow_dispatch' || inputs.fixture_base_version == ''", self.caller)

    def test_caller_validates_input_then_calls_same_sha_reusable_workflow(self):
        self.assertIn("from scripts.version_metadata import parse_version", self.caller)
        self.assertIn("uses: ./.github/workflows/macos-update-fixture.yml", self.caller)
        self.assertIn("needs: validate-macos-update-fixture", self.caller)
        self.assertIn("contents: read", self.caller)
        self.assertIn("base_version: ${{ inputs.fixture_base_version }}", self.caller)

    def test_reusable_fixture_uses_native_architecture_frozen_runtime_and_property_versions(self):
        for value in (
            "runs-on: macos-latest",
            "actions/setup-java@v4",
            'java-version: \"17\"',
            "gradle/actions/setup-gradle@v4",
            "./scripts/prepare_sing_box_macos_runtime.sh",
            "python3 scripts/version_metadata.py --field version",
            "--platform macos",
            "--confirm-owned-native-host-build",
            "scripts/record_macos_fixture_signing.py --directory",
            "VPN_CONTROL_MACOS_SIGNING_CERTIFICATE_BASE64",
        ):
            self.assertIn(value, self.reusable)
        self.assertIn("arm64) fixture_architecture=arm64", self.reusable)
        self.assertIn("x86_64) fixture_architecture=x86_64", self.reusable)
        self.assertNotIn("sed -i", self.reusable)
        self.assertNotIn("gradle.properties=", self.reusable)

    def test_upload_is_limited_to_test_pair_provenance_and_failure_has_no_success_receipt(self):
        for value in (
            "fixture-receipt.json", "snapshot.json", "build-plan.json", "signing-metadata.json",
            "base-build.log", "target-build.log", "packages/base/**", "packages/target/**",
        ):
            self.assertIn(value, self.reusable)
        failure = self.reusable.split("- name: Preserve failed build diagnostics", 1)[1]
        self.assertNotIn("fixture-receipt.json", failure)
        self.assertNotIn("packages/", failure)
        self.assertNotIn("release-publish", self.reusable)
        self.assertNotIn("refs/heads/main", self.reusable)

    def test_signing_recorder_binds_dmg_hash_source_code_architecture_and_policy(self):
        for value in (
            "DMG changed from fixture receipt", "fixture-receipt.json", "sourceFingerprint",
            "codeFingerprint", "configuredSigning", "codesign", "hdiutil", "architecture",
            "Configured signing policy did not produce a verifiable app bundle",
        ):
            self.assertIn(value, self.recorder)


if __name__ == "__main__":
    unittest.main()

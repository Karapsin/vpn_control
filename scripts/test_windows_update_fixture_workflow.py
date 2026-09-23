#!/usr/bin/env python3
"""Static safety contract for the manual Windows update-fixture workflow."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent.parent
CALLER = ROOT / ".github/workflows/windows-desktop.yml"
REUSABLE = ROOT / ".github/workflows/windows-update-fixture.yml"


class WindowsUpdateFixtureWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.caller = CALLER.read_text(encoding="utf-8")
        cls.reusable = REUSABLE.read_text(encoding="utf-8")

    def test_registered_caller_keeps_ordinary_packages_and_gates_fixture_to_dev(self):
        self.assertIn("workflow_dispatch:\n    inputs:\n      fixture_base_version:", self.caller)
        self.assertIn("push:\n    branches:\n      - dev", self.caller)
        self.assertIn("pull_request:", self.caller)
        fixture_guard = "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/dev' && inputs.fixture_base_version != ''"
        self.assertEqual(2, self.caller.count(fixture_guard))
        self.assertIn("if: github.event_name != 'workflow_dispatch' || inputs.fixture_base_version == ''", self.caller)

    def test_caller_validates_input_then_calls_local_reusable_workflow_at_its_sha(self):
        self.assertIn("FIXTURE_BASE_VERSION: ${{ inputs.fixture_base_version }}", self.caller)
        self.assertIn("from scripts.version_metadata import parse_version", self.caller)
        self.assertIn("uses: ./.github/workflows/windows-update-fixture.yml", self.caller)
        self.assertIn("needs: validate-windows-update-fixture", self.caller)
        self.assertIn("contents: read", self.caller)
        self.assertIn("base_version: ${{ inputs.fixture_base_version }}", self.caller)

    def test_uses_pinned_windows_packaging_prerequisites(self):
        for value in (
            "actions/setup-java@v4",
            'distribution: temurin',
            'java-version: "17"',
            "gradle/actions/setup-gradle@v4",
            "desktopApp/native/windows/toolchain.lock.json",
            "actions/setup-dotnet@v4",
            "choco install wixtoolset --no-progress -y",
            "./scripts/check_release_hygiene.sh",
            "scripts/test_windows_install_admission_diagnostic.py",
        ):
            self.assertIn(value, self.reusable)

    def test_reusable_workflow_freezes_runtime_and_builds_both_versions_from_fixture_cli(self):
        self.assertIn("workflow_call:\n    inputs:\n      base_version:", self.reusable)
        self.assertNotIn("workflow_dispatch:", self.reusable)
        self.assertIn(".\\scripts\\prepare_sing_box_desktop_runtime.ps1", self.reusable)
        self.assertIn("python scripts/version_metadata.py --field version", self.reusable)
        self.assertIn("scripts/prepare_desktop_update_fixture.py prepare", self.reusable)
        self.assertIn("--base-version $env:BASE_VERSION", self.reusable)
        self.assertIn("--target-version $TargetVersion", self.reusable)
        self.assertIn("--runtime desktopApp\\src\\main\\resources\\bin\\windows-amd64\\sing-box.exe", self.reusable)
        self.assertIn("--platform windows", self.reusable)
        self.assertIn("--architecture x86_64", self.reusable)
        self.assertIn("scripts/prepare_desktop_update_fixture.py build", self.reusable)
        self.assertIn("--confirm-owned-native-host-build", self.reusable)

    def test_runner_temp_is_initialized_in_a_step_not_job_environment(self):
        self.assertNotIn("FIXTURE_ROOT: ${{ runner.temp }}", self.reusable)
        self.assertIn("- name: Initialize fixture workspace", self.reusable)
        self.assertIn("Join-Path $env:RUNNER_TEMP \"vpn-control-windows-update-fixture\"", self.reusable)
        self.assertIn('"FIXTURE_ROOT=$FixtureRoot" | Out-File -FilePath $env:GITHUB_ENV', self.reusable)

    def test_failed_build_retains_diagnostics_without_claiming_pair_success(self):
        failure = self.reusable.split("- name: Preserve failed build diagnostics", 1)[1]
        self.assertIn("if: failure()", failure)
        self.assertIn("base-build.log", failure)
        self.assertIn("target-build.log", failure)
        self.assertNotIn("fixture-receipt.json", failure)
        self.assertNotIn("packages/", failure)

    def test_upload_is_limited_to_pair_and_hash_provenance(self):
        for value in (
            "actions/upload-artifact@v4",
            "vpn-control-windows-update-fixture-${{ github.sha }}",
            "fixture-receipt.json",
            "snapshot.json",
            "build-plan.json",
            "base-build.log",
            "target-build.log",
            "packages/base/**",
            "packages/target/**",
            "if-no-files-found: error",
        ):
            self.assertIn(value, self.reusable)
        self.assertNotIn("releases/", self.reusable)
        self.assertNotIn("release-publish", self.reusable)
        self.assertNotIn("refs/heads/main", self.reusable)



if __name__ == "__main__":
    unittest.main()

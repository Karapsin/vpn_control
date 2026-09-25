#!/usr/bin/env python3
"""Causal actionlint regression for GitHub's invalid runner context placement."""

from __future__ import annotations

import errno
import io
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
import urllib.error
import zipfile

import check_workflow_syntax


ROOT = Path(__file__).resolve().parent.parent
CALLER = ROOT / ".github/workflows/windows-desktop.yml"
REUSABLE = ROOT / ".github/workflows/windows-update-fixture.yml"
INITIALIZE_STEP = '''      - name: Initialize fixture workspace
        shell: pwsh
        run: |
          $FixtureRoot = Join-Path $env:RUNNER_TEMP "vpn-control-windows-update-fixture"
          "FIXTURE_ROOT=$FixtureRoot" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append

'''
INVALID_JOB_ENV = '''    env:
      BASE_VERSION: ${{ inputs.base_version }}
      FIXTURE_ROOT: ${{ runner.temp }}\\vpn-control-windows-update-fixture
'''


class ResetAfterPartialRead(io.BytesIO):
    def __init__(self, contents: bytes):
        super().__init__(contents)
        self.returned_partial = False

    def read(self, size: int = -1) -> bytes:
        if self.returned_partial:
            raise ConnectionResetError(errno.ECONNRESET, "connection reset")
        self.returned_partial = True
        return super().read(min(size, 7))


class WorkflowSyntaxTest(unittest.TestCase):
    def test_download_retries_connection_reset_then_atomically_publishes_valid_data(self):
        with tempfile.TemporaryDirectory(prefix="actionlint-download-") as temporary:
            destination = Path(temporary) / "actionlint.tar.gz"
            destination.write_bytes(b"previous verified archive")
            opener = mock.Mock(side_effect=[
                urllib.error.URLError(ConnectionResetError(errno.ECONNRESET, "connection reset")),
                io.BytesIO(b"valid archive bytes"),
            ])
            with mock.patch.object(check_workflow_syntax.urllib.request, "urlopen", opener), \
                 mock.patch("time.sleep") as sleep:
                check_workflow_syntax.download("https://example.invalid/actionlint", destination)

            self.assertEqual(b"valid archive bytes", destination.read_bytes())
            self.assertEqual(2, opener.call_count)
            sleep.assert_called_once_with(1)

    def test_download_discards_partial_bytes_before_retrying(self):
        with tempfile.TemporaryDirectory(prefix="actionlint-download-") as temporary:
            destination = Path(temporary) / "actionlint.tar.gz"
            destination.write_bytes(b"previous verified archive")
            opener = mock.Mock(side_effect=[
                ResetAfterPartialRead(b"partial untrusted archive"),
                io.BytesIO(b"valid archive bytes"),
            ])
            with mock.patch.object(check_workflow_syntax.urllib.request, "urlopen", opener), \
                 mock.patch("time.sleep"):
                check_workflow_syntax.download("https://example.invalid/actionlint", destination)

            self.assertEqual(b"valid archive bytes", destination.read_bytes())
            self.assertEqual(2, opener.call_count)

    def test_download_stops_after_bounded_connection_reset_retries(self):
        with tempfile.TemporaryDirectory(prefix="actionlint-download-") as temporary:
            destination = Path(temporary) / "actionlint.tar.gz"
            destination.write_bytes(b"previous verified archive")
            reset = urllib.error.URLError(ConnectionResetError(errno.ECONNRESET, "connection reset"))
            opener = mock.Mock(side_effect=[reset, reset, reset])
            with mock.patch.object(check_workflow_syntax.urllib.request, "urlopen", opener), \
                 mock.patch("time.sleep") as sleep:
                with self.assertRaisesRegex(RuntimeError, "after 3 attempts"):
                    check_workflow_syntax.download("https://example.invalid/actionlint", destination)

            self.assertEqual(b"previous verified archive", destination.read_bytes())
            self.assertEqual(3, opener.call_count)
            self.assertEqual(
                [mock.call(1), mock.call(2)],
                sleep.call_args_list,
            )

    def test_checksum_failure_does_not_retry_or_publish_archive(self):
        with tempfile.TemporaryDirectory(prefix="actionlint-cache-") as temporary:
            cache = Path(temporary)
            archive = "fixture.zip"
            cached_archive = cache / archive
            cached_archive.write_bytes(b"previous untrusted archive")
            downloader = mock.Mock(side_effect=lambda _url, destination: destination.write_bytes(b"invalid bytes"))
            with mock.patch.object(check_workflow_syntax, "asset_for", return_value=(archive, "0" * 64)), \
                 mock.patch.object(check_workflow_syntax, "cache_root", return_value=cache), \
                 mock.patch.object(check_workflow_syntax, "download", downloader), \
                 mock.patch("platform.system", return_value="Linux"):
                with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
                    check_workflow_syntax.actionlint_path()

            self.assertEqual(1, downloader.call_count)
            self.assertEqual(b"previous untrusted archive", cached_archive.read_bytes())

    def test_pins_official_assets_for_release_platforms(self):
        expected = {
            ("Linux", "x86_64"): "actionlint_1.7.12_linux_amd64.tar.gz",
            ("Darwin", "x86_64"): "actionlint_1.7.12_darwin_amd64.tar.gz",
            ("Darwin", "arm64"): "actionlint_1.7.12_darwin_arm64.tar.gz",
            ("Windows", "AMD64"): "actionlint_1.7.12_windows_amd64.zip",
            ("Windows", "ARM64"): "actionlint_1.7.12_windows_arm64.zip",
        }
        for platform, asset in expected.items():
            with self.subTest(platform=platform):
                selected, checksum = check_workflow_syntax.asset_for(*platform)
                self.assertEqual(asset, selected)
                self.assertEqual(64, len(checksum))

    def test_tampered_cached_executable_is_repaired_from_verified_archive(self):
        expected_binary = b"verified actionlint fixture"
        with tempfile.TemporaryDirectory(prefix="actionlint-cache-") as temporary:
            cache = Path(temporary)
            archive = cache / "fixture.zip"
            with zipfile.ZipFile(archive, "w") as contents:
                contents.writestr("actionlint", expected_binary)
            expected_hash = check_workflow_syntax.sha256(archive)
            executable = cache / "actionlint"
            executable.write_bytes(b"tampered binary")

            with mock.patch.object(check_workflow_syntax, "asset_for", return_value=(archive.name, expected_hash)), \
                 mock.patch.object(check_workflow_syntax, "cache_root", return_value=cache), \
                 mock.patch("platform.system", return_value="Linux"):
                repaired = check_workflow_syntax.actionlint_path()

            self.assertEqual(executable, repaired)
            self.assertEqual(expected_binary, repaired.read_bytes())

    def test_actionlint_timeout_has_actionable_error(self):
        with mock.patch.object(check_workflow_syntax, "actionlint_path", return_value=Path("/tmp/actionlint")), \
             mock.patch.object(check_workflow_syntax.subprocess, "run", side_effect=subprocess.TimeoutExpired(["actionlint"], 60)):
            with self.assertRaisesRegex(RuntimeError, "60-second limit"):
                check_workflow_syntax.run_actionlint([CALLER])

    def test_runner_temp_job_environment_is_rejected_and_fixed_workflows_pass(self):
        with tempfile.TemporaryDirectory(prefix="workflow-syntax-") as temporary:
            workflows = Path(temporary) / ".github/workflows"
            workflows.mkdir(parents=True)
            caller = workflows / CALLER.name
            reusable = workflows / REUSABLE.name
            shutil.copy2(CALLER, caller)
            invalid = REUSABLE.read_text(encoding="utf-8").replace(INITIALIZE_STEP, "")
            invalid = invalid.replace("    env:\n      BASE_VERSION: ${{ inputs.base_version }}\n", INVALID_JOB_ENV)
            self.assertNotEqual(REUSABLE.read_text(encoding="utf-8"), invalid)
            reusable.write_text(invalid, encoding="utf-8")

            red = check_workflow_syntax.run_actionlint([caller, reusable])
            self.assertNotEqual(0, red.returncode, red.stdout)
            self.assertIn("runner", red.stdout.lower())

        green = check_workflow_syntax.run_actionlint([CALLER, REUSABLE])
        self.assertEqual(0, green.returncode, green.stdout)


if __name__ == "__main__":
    unittest.main()

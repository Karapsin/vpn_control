#!/usr/bin/env python3
import stat
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

import macos_aqua_authorization_correlation as subject

JOB = "d5b9b029-36d1-495c-bdba-44d628e08a3d"
HOME = Path("/Users/Alice Doe")
WORKER = HOME / "Library/Application Support/vpn-control-install-inputs" / JOB / "vpn-control-install-worker"


class ProcessParserTest(unittest.TestCase):
    def test_parses_exact_quoted_worker_path_and_ignores_malformed_rows(self):
        raw = """nonsense
11 bad 501 ignored
12 1 501 /usr/bin/other --coordinate not-a-job nope
13 1 501 /usr/bin/osascript -e 'text -- still script' -- '/Users/Alice Doe/Library/Application Support/vpn-control-install-inputs/d5b9b029-36d1-495c-bdba-44d628e08a3d/vpn-control-install-worker' --coordinate d5b9b029-36d1-495c-bdba-44d628e08a3d 42
"""
        rows = subject.parse_ps(raw)
        self.assertEqual([row["pid"] for row in rows], [12, 13])
        metadata = type("Metadata", (), {"st_mode": stat.S_IFREG | 0o700, "st_uid": 501})()
        with mock.patch.object(Path, "lstat", return_value=metadata), mock.patch.object(subject.os, "getuid", return_value=501, create=True):
            self.assertEqual(subject.coordinator(rows[-1], HOME), {"osascriptPid": 13, "jobId": JOB, "ownerPid": 42})

    def test_observation_rejects_non_product_or_ambiguous_prompt(self):
        raw = """42 1 501 /Applications/vpn-control.app/Contents/MacOS/vpn-control --state-dir /tmp/w serve
43 1 0 /System/Library/CoreServices/SecurityAgent.app/Contents/MacOS/SecurityAgent
44 1 0 /System/Library/CoreServices/SecurityAgent.app/Contents/MacOS/SecurityAgent
45 1 501 /usr/bin/osascript -- /tmp/not-worker --coordinate d5b9b029-36d1-495c-bdba-44d628e08a3d 42
"""
        with mock.patch.object(subject.subprocess, "check_output", return_value=raw):
            observed = subject.observe(42, "/Applications/vpn-control.app/Contents/MacOS/vpn-control")
        self.assertEqual(observed, {"ownerMatches": 1, "securityAgentCount": 2, "coordinators": []})


class CorrelationAndRecoveryTest(unittest.TestCase):
    def test_candidate_requires_exact_single_signals_and_is_not_authorization(self):
        absent = subject.candidate_prompt_correlation({"securityAgentCount": 0}, {"ownerMatches": 1, "securityAgentCount": 1, "coordinators": []}, JOB)
        self.assertEqual(absent["reason"], "exact-coordinator-missing-or-ambiguous")
        malformed = subject.candidate_prompt_correlation({"securityAgentCount": 0}, {"ownerMatches": 1, "securityAgentCount": 1, "coordinators": [{}]}, JOB)
        self.assertEqual(malformed["reason"], "exact-coordinator-missing-or-ambiguous")
        candidate = subject.candidate_prompt_correlation({"securityAgentCount": 0}, {"ownerMatches": 1, "securityAgentCount": 1, "coordinators": [{"jobId": JOB, "osascriptPid": 3}]}, JOB)
        self.assertEqual(candidate["candidatePromptCorrelation"], True)
        self.assertNotIn("authorized", candidate)

    def test_public_recovery_requires_successful_envelope_and_preserves_unknown_installed(self):
        entry = {"jobId": JOB, "final": True, "phase": "succeeded", "code": "OK", "installed": None}
        bad = subject.public_recovery({"ok": False, "code": "OK", "final": True, "data": {"installations": [entry]}}, JOB)
        self.assertEqual(bad["reason"], "public-envelope-not-successful-final")
        value = subject.public_recovery({"ok": True, "code": "OK", "final": True, "data": {"installations": [entry]}}, JOB)
        self.assertIsNone(value["installed"])


class LaunchPortabilityTest(unittest.TestCase):
    def test_routine_suite_launches_without_unix_identity_api(self):
        # Windows has no os.getuid. Exercise the real test entry point under
        # that API surface on every host, without skipping the parser cases.
        result = subprocess.run(
            [sys.executable, "-c", "import os, runpy, sys; "
             "os.__dict__.pop('getuid', None); "
             "sys.argv = [sys.argv[1], 'ProcessParserTest', 'CorrelationAndRecoveryTest']; "
             "runpy.run_path(sys.argv[0], run_name='__main__')",
             str(Path(__file__).resolve())],
            cwd=Path(__file__).resolve().parent, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("Ran 4 tests", result.stderr)
        self.assertNotIn("skipped", result.stderr)


if __name__ == "__main__":
    unittest.main()

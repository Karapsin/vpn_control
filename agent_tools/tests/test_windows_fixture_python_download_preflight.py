"""Causal regressions for CP117's fixed Python.org HEAD preflight."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agent_tools import windows_fixture_python_download_preflight as preflight


REQUEST = {"host": "archlinux", "leaseId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
           "stageCorrelationId": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
           "serverCorrelationId": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
           "sourceSha": "d" * 40, "fixtureReceiptArtifactId": "sha256-" + "e" * 64,
           "baseMsiArtifactId": "sha256-" + "f" * 64, "targetMsiArtifactId": "sha256-" + "1" * 64}
DESCRIPTOR = (object(), SimpleNamespace(fixture_transfer_root=Path("/owned/arch/fixture-root")),
              ("windows-cp117", "/owned/cp117.qga", 4321, 98765, "S-1-5-21-1-2-3-1002"))


class PythonDownloadPreflightTests(unittest.TestCase):
    def test_pins_exact_official_url_checksum_and_read_only_head_script(self):
        self.assertEqual("https://www.python.org/ftp/python/3.13.15/python-3.13.15-amd64.exe", preflight._URL)
        self.assertEqual("edec09c4853aeae9ac36efb8c9f95b6b8e2fee65eee56d9767a8b7c69c574403", preflight._SHA256)
        self.assertIn("Method='HEAD'", preflight._POWERSHELL)
        self.assertIn("ServerCertificateValidationCallback", preflight._POWERSHELL)
        self.assertIn("return $errors -eq", preflight._POWERSHELL)
        self.assertNotIn("DownloadFile", preflight._POWERSHELL)
        self.assertNotIn("Start-Process", preflight._POWERSHELL)

    def test_projects_only_trusted_finite_endpoint_facts(self):
        good = {"version": 2, "classification": "reachable", "phase": "reachable", "tlsSha256": "a" * 64,
                "statusCode": 200, "contentLength": 29452944, "candidateCount": 0}
        self.assertEqual({"classification": "reachable", "phase": "reachable", "tlsSha256": "a" * 64,
                          "statusCode": 200, "contentLength": 29452944}, preflight._endpoint(good))
        for changed in ({**good, "tlsSha256": "unknown"}, {**good, "statusCode": 302}, {**good, "phase": "network-failed"},
                        {**good, "candidateCount": 1}, {**good, "contentLength": -1},
                        {**good, "path": r"C:\\secret"},
                        {"version": 2, "classification": "unknown", "phase": "network-failed", "tlsSha256": "unknown", "statusCode": 500, "contentLength": "unknown", "candidateCount": 0}):
            with self.subTest(changed=changed):
                self.assertIsNone(preflight._endpoint(changed))

    def test_empty_inventory_and_full_campaign_binding_precede_fixed_remote_head(self):
        response = {"state": "observed", "endpoint": {"version": 2, "classification": "unreachable", "phase": "http-status",
                    "tlsSha256": "a" * 64, "statusCode": 503, "contentLength": 0, "candidateCount": 0}}
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(preflight.server, "_request", return_value=REQUEST), \
             patch.object(preflight.server, "_python_candidates", return_value=[]) as candidates, \
             patch.object(preflight.server, "_admit_campaign") as admission, \
             patch.object(preflight.base, "_descriptor", return_value=DESCRIPTOR), \
             patch.object(preflight.base, "_remote", return_value=json.dumps(response).encode()) as remote:
            result = preflight.preflight(Path(directory), REQUEST)
        self.assertEqual("unreachable", result["classification"])
        self.assertEqual(0, result["candidateCount"])
        self.assertFalse(result["serverReady"])
        candidates.assert_called_once()
        self.assertEqual(2, admission.call_count)
        admission.assert_called_with(Path(directory).resolve(), REQUEST, require_credentials=True)
        self.assertEqual(preflight._REMOTE, remote.call_args.args[1])
        self.assertEqual(40, remote.call_args.args[4])
        self.assertEqual("/owned/arch/fixture-root", remote.call_args.args[2][0])
        self.assertIn(REQUEST["sourceSha"], remote.call_args.args[2])
        self.assertIn(REQUEST["leaseId"], remote.call_args.args[2])
        self.assertIn("/owned/cp117.qga", remote.call_args.args[2])

    def test_admission_failure_precedes_remote_head_and_is_projected_without_details(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(preflight.server, "_request", return_value=REQUEST), \
             patch.object(preflight.server, "_admit_campaign", side_effect=ValueError("sensitive campaign detail")), \
             patch.object(preflight.server, "_python_candidates", side_effect=AssertionError("must not inventory")), \
             patch.object(preflight.base, "_remote", side_effect=AssertionError("must not HEAD")):
            result = preflight.preflight(Path(directory), REQUEST)
        self.assertEqual("admission-failed", result["phase"])
        self.assertNotIn("sensitive", str(result))

    def test_descriptor_failure_precedes_remote_head_and_is_projected_without_details(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(preflight.server, "_request", return_value=REQUEST), \
             patch.object(preflight.server, "_python_candidates", return_value=[]), \
             patch.object(preflight.server, "_admit_campaign"), \
             patch.object(preflight.base, "_descriptor", side_effect=OSError("private descriptor path")), \
             patch.object(preflight.base, "_remote", side_effect=AssertionError("must not HEAD")):
            result = preflight.preflight(Path(directory), REQUEST)
        self.assertEqual("descriptor-failed", result["phase"])
        self.assertNotIn("private", str(result))

    def test_candidate_or_malformed_remote_response_fails_closed_without_head(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(preflight.server, "_request", return_value=REQUEST), \
             patch.object(preflight.server, "_python_candidates", return_value=[{"path": "fixed"}]), \
             patch.object(preflight.server, "_admit_campaign"), \
             patch.object(preflight.base, "_remote", side_effect=AssertionError("must not HEAD")):
            result = preflight.preflight(Path(directory), REQUEST)
        self.assertEqual("admission-failed", result["phase"])
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(preflight.server, "_request", return_value=REQUEST), \
             patch.object(preflight.server, "_python_candidates", return_value=[]), \
             patch.object(preflight.server, "_admit_campaign"), \
             patch.object(preflight.base, "_descriptor", return_value=DESCRIPTOR), \
             patch.object(preflight.base, "_remote", return_value=b'{bad'):
            result = preflight.preflight(Path(directory), REQUEST)
        self.assertEqual({"classification": "unknown", "phase": "response-invalid", "tlsSha256": "unknown", "statusCode": "unknown", "contentLength": "unknown"},
                         {name: result[name] for name in ("classification", "phase", "tlsSha256", "statusCode", "contentLength")})

    def test_observed_guest_exit_phase_remains_finite_and_redacted(self):
        value = {"version": 2, "classification": "unknown", "phase": "guest-script-exit",
                 "tlsSha256": "unknown", "statusCode": "unknown", "contentLength": "unknown", "candidateCount": 0}
        self.assertEqual("guest-script-exit", preflight._endpoint(value)["phase"])

    def test_observed_network_timeout_phase_remains_finite_and_redacted(self):
        value = {"version": 2, "classification": "unknown", "phase": "network-timeout",
                 "tlsSha256": "unknown", "statusCode": "unknown", "contentLength": "unknown", "candidateCount": 0}
        self.assertEqual("network-timeout", preflight._endpoint(value)["phase"])


if __name__ == "__main__":
    unittest.main()

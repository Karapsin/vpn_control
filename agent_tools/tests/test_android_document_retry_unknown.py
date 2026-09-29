"""Fail-closed proofs for one unknown pre-effect Android document retry."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from agent_tools import android_document_retry_unknown as unknown
from agent_tools import mcp_server


class AndroidDocumentRetryUnknownTest(unittest.TestCase):
    def test_remote_proof_rejects_any_transfer_or_phase(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); os.chmod(root, 0o700)
            correlation = "11111111-1111-4111-8111-111111111111"
            job = root / ("android-document-retry-job-" + correlation)
            job.mkdir(mode=0o700)
            intent = {"correlationId": correlation, "fixtureRoot": str(root)}
            def write(name, value):
                path = job / name
                path.write_text(json.dumps(value)); os.chmod(path, 0o600)
            write("intent.json", intent)
            write("identity.json", {"pid": 123, "startTicks": 456})
            write("result.json", {"state": "unknown", "reason": "command_failed"})
            def proof():
                completed = subprocess.run([sys.executable, "-I", "-B", "-c", unknown._PRE_EFFECT,
                    str(root), correlation, json.dumps(intent, sort_keys=True, separators=(",", ":")), "123", "456"],
                    capture_output=True, text=True, check=True, timeout=5)
                return json.loads(completed.stdout)
            self.assertTrue(proof()["ready"])
            write("transfer-first.json", {"requestId": "r"})
            self.assertFalse(proof()["ready"])
            (job / "transfer-first.json").unlink()
            write("phase.json", {"phase": "first_upload"})
            self.assertFalse(proof()["ready"])

    def test_remote_proof_rejects_type_changed_intent(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); os.chmod(root, 0o700)
            correlation = "11111111-1111-4111-8111-111111111111"
            job = root / ("android-document-retry-job-" + correlation)
            job.mkdir(mode=0o700)
            for name, value in (("intent.json", {"correlationId": correlation, "revision": False}),
                                ("identity.json", {"pid": 123, "startTicks": 456}),
                                ("result.json", {"state": "unknown", "reason": "command_failed"})):
                path = job / name
                path.write_text(json.dumps(value)); os.chmod(path, 0o600)
            expected = {"correlationId": correlation, "revision": 0}
            done = subprocess.run([sys.executable, "-I", "-B", "-c", unknown._PRE_EFFECT,
                str(root), correlation, json.dumps(expected), "123", "456"],
                capture_output=True, text=True, check=True, timeout=5)
            self.assertFalse(json.loads(done.stdout)["ready"])

    def test_categorical_command_probe_never_returns_raw_stderr(self):
        self.assertNotIn("stderrText", unknown._COMMAND_PROBE)
        self.assertIn("stderrNonempty", unknown._COMMAND_PROBE)

    def test_close_requires_all_independent_proofs(self):
        proof = {"terminal": True, "preEffect": True, "openingReadback": True,
                 "currentReadback": True, "sameRules": True, "sameHistory": True,
                 "publicOff": True, "sharedLease": True, "documentLease": True}
        self.assertTrue(unknown._no_effect_valid(proof))
        for key in proof:
            changed = dict(proof); changed[key] = False
            self.assertFalse(unknown._no_effect_valid(changed), key)

    def test_mcp_route_is_exact_and_never_claims_product_action(self):
        fields = {"unknownCorrelationId": "u", "openingReadbackCorrelationId": "o",
                  "currentReadbackCorrelationId": "c"}
        with mock.patch.object(unknown, "diagnose", return_value={"ok": True, "state": "observed",
                               "noEffectProven": False}) as diagnose:
            self.assertFalse(mcp_server._vm_workflow_impl("android-document-retry-unknown-diagnose",
                {**fields, "command": "id"})["ok"])
            result = mcp_server._vm_workflow_impl("android-document-retry-unknown-diagnose", fields)
            self.assertTrue(result["ok"])
            self.assertFalse(result["productAction"])
            diagnose.assert_called_once()
        with mock.patch.object(unknown, "close", return_value={"ok": True, "state": "closed"}) as close:
            result = mcp_server._vm_workflow_impl("android-document-retry-unknown-close", fields)
            self.assertTrue(result["ok"])
            self.assertFalse(result["productAction"])
            close.assert_called_once()

    def test_close_retains_leases_without_all_proofs_and_resumes_after_marker(self):
        correlation = "11111111-1111-4111-8111-111111111111"
        opening = "22222222-2222-4222-8222-222222222222"
        current = "33333333-3333-4333-8333-333333333333"
        old = {"host": "archlinux", "device": "api29", "packageSha256": "a" * 64,
               "expectedOwner": "44444444-4444-4444-8444-444444444444", "expectedRevision": 1}
        proof = {key: True for key in unknown._PROOF_KEYS}
        observed = {"ok": True, "state": "observed", "proof": proof,
                    "routingCanonicalSha256": "b" * 64, "currentOperationCount": 1}
        with (mock.patch.object(unknown, "diagnose", return_value={**observed,
                "proof": {**proof, "preEffect": False}}),
              mock.patch.object(unknown.android_document_retry, "_load", return_value=old),
              mock.patch.object(unknown, "_read_marker", return_value=None),
              mock.patch.object(unknown, "_write_marker") as write,
              mock.patch.object(unknown.android_document_retry, "_release_recovery_leases") as release):
            self.assertEqual(unknown.close(".", correlation, opening, current)["state"], "unknown")
            write.assert_not_called(); release.assert_not_called()
        with tempfile.TemporaryDirectory() as temp:
            with (mock.patch.object(unknown, "diagnose", return_value=observed),
                  mock.patch.object(unknown.android_document_retry, "_load", return_value=old),
                  mock.patch.object(unknown.android_document_retry, "_release_recovery_leases",
                                    side_effect=[False, True]) as release):
                first = unknown.close(temp, correlation, opening, current)
                self.assertEqual(first["state"], "unknown")
                marker = unknown._read_marker(temp, correlation)
                self.assertIsNotNone(marker)
                second = unknown.close(temp, correlation, opening, current)
                self.assertEqual(second["state"], "closed")
                self.assertEqual(release.call_count, 2)


if __name__ == "__main__":
    unittest.main()

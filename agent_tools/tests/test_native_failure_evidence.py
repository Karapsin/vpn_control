from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from agent_tools import native_failure_evidence as evidence


class NativeFailureEvidenceTest(unittest.TestCase):
    def values(self):
        return ({"tool": "vm_workflow", "action": "package", "sourceSha": "a" * 40,
                 "sourceFingerprint": "b" * 64, "artifactIds": ["sha256-abc"],
                 "environmentAlias": "linux", "operationCorrelation": "op-1"},
                {"classification": "terminalFailure", "errorCategory": "exit_nonzero",
                 "before": {"state": "running", "count": 1}, "after": {"state": "terminal", "category": "exit_nonzero"},
                 "observations": [{"state": "terminal", "count": 1}], "evidencePaths": ["/tmp/receipt.json"]})

    @unittest.skipIf(os.name == "nt", "requires POSIX private ownership")
    def test_durable_receipt_is_redacted_atomic_and_idempotent(self):
        with tempfile.TemporaryDirectory() as temp:
            context, result = self.values()
            first = evidence.record_failure(Path(temp), context, result)
            second = evidence.record_failure(Path(temp), context, result)
            self.assertEqual(first, second)
            stored = Path(first["evidencePath"])
            self.assertEqual(0o600, stored.stat().st_mode & 0o777)
            self.assertFalse(any(item.name.startswith(".tmp-") for item in stored.parent.iterdir()))
            contents = stored.read_text()
            self.assertIn("terminalFailure", contents)
            self.assertNotIn("secret", contents)
            self.assertEqual({"evidenceId", "evidencePath", "classification", "summaryCounts"}, set(first))

    @unittest.skipIf(os.name == "nt", "requires POSIX private ownership")
    def test_rejects_nested_secrets_urls_commands_and_corrupt_receipts_without_stdout(self):
        with tempfile.TemporaryDirectory() as temp:
            context, result = self.values()
            result["before"] = {"state": "running", "password": "secret"}
            with mock.patch("sys.stdout") as stdout:
                with self.assertRaises(evidence.NativeFailureEvidenceError): evidence.record_failure(Path(temp), context, result)
                stdout.write.assert_not_called()
            context, result = self.values(); result["evidencePaths"] = ["https://token.example/secret"]
            with self.assertRaises(evidence.NativeFailureEvidenceError): evidence.record_failure(Path(temp), context, result)
            context, result = self.values(); made = evidence.record_failure(Path(temp), context, result)
            Path(made["evidencePath"]).write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(evidence.NativeFailureEvidenceError, "corrupt"):
                evidence.record_failure(Path(temp), context, result)

    @unittest.skipIf(os.name == "nt", "requires POSIX private ownership")
    def test_unknown_is_preserved_and_interrupted_staging_is_not_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            context, result = self.values(); result["classification"] = "nativeUNKNOWN"
            made = evidence.record_failure(Path(temp), context, result)
            self.assertEqual("nativeUNKNOWN", json.loads(Path(made["evidencePath"]).read_text())["classification"])
            directory = Path(temp) / ".rag_index" / "native-failures"
            (directory / ".tmp-interrupted").write_text("partial", encoding="utf-8")
            again = evidence.record_failure(Path(temp), context, result)
            self.assertEqual(made, again)
            self.assertFalse((directory / ".tmp-interrupted").exists())

    def test_windows_is_explicitly_unsupported(self):
        context, result = self.values()
        with mock.patch.object(evidence.os, "name", "nt"):
            with self.assertRaisesRegex(evidence.NativeFailureEvidenceError, "Windows"):
                evidence.record_failure(Path("/tmp"), context, result)

"""Actual failed child output must retain the late causal test summary."""
import hashlib
import json
from pathlib import Path
import tempfile
from unittest import mock
import sys
import unittest
from agent_tools import mcp_server as server


class FailedCheckOutputTests(unittest.TestCase):
    def test_late_failure_survives_noisy_child_output(self):
        failure = 'AssertionError: causal late-check sentinel'
        text = ('setup ResourceWarning noise\n' * 1000 +
                'FAIL: causal_case\nTraceback (most recent call last):\n' +
                failure + '\nFAILED (failures=1)\n')
        command = [sys.executable, '-c',
                   'import sys;sys.stderr.write(' + repr(text) + ');sys.exit(1)']
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(server, "REPO_ROOT", Path(directory)):
            result = server._run_check_commands('agent_tools', 'focused', [command])
        self.assertFalse(result['ok'])
        output = result['command_results'][0]['stderr']
        self.assertIn(failure, output)
        self.assertIn('FAILED (failures=1)', output)
        self.assertLessEqual(len(output), server.MAX_OUTPUT_CHARS)


    def test_middle_failure_identity_and_exact_binary_streams_are_retained(self):
        raw = (b"AssertionError: " + b"x" * 10000 + b"\n" + b"prefix\n" * 3000 +
               b"FAIL: test_middle (fixture.Cases.test_middle)\n" +
               b"private failure body\xff\r\n" + b"tail\n" * 4000)
        command = [sys.executable, "-c",
                   "import sys;sys.stdout.buffer.write(b'out\\xff\\r\\n');"
                   "sys.stderr.buffer.write(" + repr(raw) + ");sys.exit(1)"]
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(server, "REPO_ROOT", Path(directory)):
            result = server._run_check_commands("agent_tools", "focused", [command])
            child = result["command_results"][0]
            self.assertFalse(result["ok"])
            self.assertNotIn("fixture.Cases.test_middle", child["stderr"])
            metadata = child["completionOutput"]
            self.assertEqual(["fixture.Cases.test_middle"], metadata["tests"]["identities"])
            capsule = Path(directory) / ".rag_index/check-runs" / metadata["runId"]
            self.assertEqual(raw, (capsule / "stderr.private").read_bytes())
            self.assertEqual(b"out\xff\r\n", (capsule / "stdout.private").read_bytes())
            self.assertEqual(hashlib.sha256(raw).hexdigest(), metadata["stderr"]["sha256"])
            self.assertEqual(metadata["returncode"], json.loads((capsule / "receipt.json").read_text())["returncode"])
            self.assertNotIn("private failure body", json.dumps(metadata))

    def test_retention_failure_blocks_successful_prepush_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = root / "receipt.json"
            with mock.patch.object(server, "REPO_ROOT", root), \
                    mock.patch.object(server, "RECEIPT_PATH", receipt), \
                    mock.patch.object(server, "_snapshot_fingerprint", return_value="a" * 64), \
                    mock.patch.object(server.check_output_retention, "retain_completed_output",
                                      side_effect=server.check_output_retention.RetentionError("raw_changed")):
                result = server._run_check_commands("agent_tools", "prepush", [[sys.executable, "-c", "pass"]])
            self.assertFalse(result["ok"])
            self.assertEqual(0, result["command_results"][0]["returncode"])
            self.assertEqual("raw_changed", result["command_results"][0]["retentionError"])
            self.assertFalse(receipt.exists())

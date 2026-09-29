"""Causal kernel move trace regression from the historical Arch rollback."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from agent_tools import linux_deb_arch_rollback as rollback


TRACE = Path(__file__).resolve().parents[2] / ".runtime/parity-evidence/checkpoint68/linux-rollback/guest-output/opt-inotify-trace.json"


class RollbackTraceTest(unittest.TestCase):
    def test_historical_kernel_trace_proves_original_inode_returned(self):
        if not TRACE.is_file():
            self.skipTest("Historical native receipt is unavailable in this checkout")
        trace = json.loads(TRACE.read_text())
        result = rollback.classify_move_trace(trace)
        self.assertTrue(result["inodeTraceMatched"])
        self.assertEqual(trace["initial"]["vpn-control"], result["originalObjectId"])
        self.assertNotEqual(result["originalObjectId"], result["replacementObjectId"])

    def test_missing_replacement_removal_cannot_claim_rollback(self):
        if not TRACE.is_file():
            self.skipTest("Historical native receipt is unavailable in this checkout")
        trace = json.loads(TRACE.read_text())
        changed = copy.deepcopy(trace)
        changed["events"] = [event for event in changed["events"]
                             if not (event.get("name") == "vpn-control" and event.get("mask", 0) & rollback.DELETE)]
        self.assertFalse(rollback.classify_move_trace(changed)["inodeTraceMatched"])

    def test_recovery_activation_failure_still_sends_public_quit(self):
        with tempfile.TemporaryDirectory() as temp:
            owner = mock.Mock()
            owner.poll.return_value = 1
            owner.returncode = 0
            calls = []
            def runner(argv, **kwargs):
                calls.append(argv)
                return mock.Mock(returncode=0)
            with mock.patch.object(rollback.subprocess, "Popen", return_value=owner):
                with self.assertRaisesRegex(ValueError, "owner exited"):
                    rollback._recover_owner(Path(temp), {}, {}, runner)
            self.assertEqual("quit", calls[-1][-1])
            owner.wait.assert_called_once()


if __name__ == "__main__":
    unittest.main()

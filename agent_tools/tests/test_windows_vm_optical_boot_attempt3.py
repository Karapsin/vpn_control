"""Causal guards for the fixed third optical attempt and second closure."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from agent_tools import windows_vm_optical_boot as boot
from agent_tools import windows_vm_optical_boot_attempt2 as second
from agent_tools import windows_vm_optical_boot_attempt3 as third


CORR = "323e4567-e89b-12d3-a456-426614174099"
CLOSE = "423e4567-e89b-12d3-a456-426614174099"


class WindowsOpticalThirdAttemptTest(unittest.TestCase):
    def test_status_keeps_historical_closure_when_current_disk_is_allocated(self):
        program = boot._program(boot.SECOND_CORRELATION, "status", attempt=2,
                                expected_closure=boot.FIRST_CLOSURE)
        first_source = program.split("def verify_first_closed(owner,media,disk):", 1)[1].split(
            "def verify_second_closed(", 1)[0]
        historical_source = program.split("def historical_closures(owner,media,disk):", 1)[1].split(
            "\ntry:\n owner=claim()", 1)[0]
        owner, media, stored_disk = {"qemuPid": 9}, {"sha256": "a" * 64}, {"allocatedGuestClusters": 0}
        expected = {"correlationId": boot.SECOND_CORRELATION, "owner": owner,
                    "media": media, "blankDisk": stored_disk}
        original = {**expected, "correlationId": boot.FIRST_CORRELATION}
        sample = {"state": "intent-only", "owner": owner, "media": media,
                  "blankDisk": stored_disk,
                  "qmpPeerChecks": {"pid": True, "uid": True, "startTicks": True, "claim": True}}
        marker = {"schemaVersion": 1, "originalCorrelationId": boot.FIRST_CORRELATION,
                  "closureCorrelationId": boot.FIRST_CLOSURE, "owner": owner,
                  "media": media, "blankDisk": stored_disk,
                  "sampleSha256": hashlib.sha256(json.dumps(sample, sort_keys=True).encode()).hexdigest(),
                  "sampleIntervalNs": 1_000_000_000}
        with tempfile.TemporaryDirectory() as root:
            current_intent = str(Path(root) / "optical-boot-attempt2-intent.json")
            Path(current_intent).write_text("durable second intent")
            prior_prefix = root + "/optical-boot-"
            records = {prior_prefix + "intent.json": original,
                       prior_prefix + "pre-effect-closed.json": marker}
            namespace = {"MODE": "status", "ATTEMPT": 2, "INTENT": current_intent,
                         "GUEST": root, "CORR": boot.SECOND_CORRELATION,
                         "FIRST_CLOSURE": boot.FIRST_CLOSURE, "os": os,
                         "hashlib": hashlib, "json": json,
                         "read": lambda path: records[path],
                         "expected": lambda *args: expected.copy(),
                         "blank_disk": lambda: self.fail("post-reset status must not demand blank disk")}
            exec("def verify_first_closed(owner,media,disk):" + first_source, namespace)
            exec("def historical_closures(owner,media,disk):" + historical_source, namespace)
            namespace["verify_first_closed"](owner, media, stored_disk)
            namespace["historical_closures"](owner, media, stored_disk)
            records[prior_prefix + "pre-effect-closed.json"] = {**marker, "sampleSha256": "f" * 64}
            with self.assertRaisesRegex(ValueError, "prior-closure-changed"):
                namespace["historical_closures"](owner, media, stored_disk)

    def test_third_paths_and_fixed_qmp_action_are_distinct(self):
        program = boot._program(CORR, "start", attempt=3, expected_closure=CLOSE)
        compile(program, "<third-optical>", "exec")
        self.assertIn("ATTEMPT=3", program)
        self.assertIn("'/optical-boot-attempt3-'", program)
        self.assertIn("verify_first_closed(owner,media,disk)", program)
        self.assertIn("verify_second_closed(owner,media,disk)", program)
        self.assertEqual(1, program.count("command('system_reset')"))
        self.assertEqual(1, program.count("command('send-key'"))
        action = program.split("elif MODE=='start':", 1)[1].split("else:raise ValueError('invalid-mode')", 1)[0]
        connect = action.index("sock,command=qmp_open(owner)")
        self.assertLess(action.index("verify_first_closed(owner,media,disk)"), connect)
        self.assertLess(action.index("verify_second_closed(owner,media,disk)"), connect)
        self.assertNotIn("verify_second_closed", action[connect:action.index("first=frame(", connect)])

    def test_remote_rejects_missing_changed_second_closure_and_orphan_reset(self):
        program = boot._program(CORR, "preflight", attempt=3, expected_closure=CLOSE)
        source = program.split("def verify_second_closed(owner,media,disk):", 1)[1].split("def phase_evidence(", 1)[0]
        # The helper precedes the top-level observation; isolate its body.
        source = source.split("\ntry:\n owner=claim()", 1)[0]
        owner, media, disk = {"qemuPid": 9}, {"sha256": "a" * 64}, {"allocatedGuestClusters": 0}
        expected = {"correlationId": CORR, "owner": owner, "media": media, "blankDisk": disk}
        original = {**expected, "correlationId": boot.SECOND_CORRELATION}
        sample = {"state": "intent-only", "owner": owner, "media": media, "blankDisk": disk,
                  "qmpPeerChecks": {"pid": True, "uid": True, "startTicks": True, "claim": True}}
        marker = {"schemaVersion": 1, "originalCorrelationId": boot.SECOND_CORRELATION,
                  "closureCorrelationId": CLOSE, "owner": owner, "media": media, "blankDisk": disk,
                  "sampleSha256": hashlib.sha256(json.dumps(sample, sort_keys=True).encode()).hexdigest(),
                  "sampleIntervalNs": 1_000_000_000}
        with tempfile.TemporaryDirectory() as root:
            guest = Path(root)
            intent = str(guest / "optical-boot-attempt2-intent.json")
            closed = str(guest / "optical-boot-attempt2-pre-effect-closed.json")
            records = {intent: original}
            namespace = {"ATTEMPT": 3, "MODE": "preflight", "GUEST": root,
                         "EXPECTED_CLOSURE": CLOSE, "os": os, "hashlib": hashlib, "json": json,
                         "read": lambda path: records[path], "expected": lambda *args: expected.copy(),
                         "qmp_handshake": lambda _: {"state": "ready", "phase": "complete",
                                                    "peerChecks": sample["qmpPeerChecks"]},
                         "claim": lambda: owner, "same_media": lambda _: True,
                         "blank_disk": lambda: disk}
            exec("def verify_second_closed(owner,media,disk):" + source, namespace)
            with self.assertRaises(KeyError):
                namespace["verify_second_closed"](owner, media, disk)
            records[closed] = {**marker, "sampleSha256": "f" * 64}
            with self.assertRaisesRegex(ValueError, "second-closure-changed"):
                namespace["verify_second_closed"](owner, media, disk)
            records[closed] = marker
            namespace["verify_second_closed"](owner, media, disk)
            (guest / "optical-boot-attempt2-reset.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "second-attempt-effect-observed"):
                namespace["verify_second_closed"](owner, media, disk)

    def test_second_closure_response_loss_never_replays(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(second, "_check"), \
                mock.patch.object(boot, "_remote", side_effect=subprocess.TimeoutExpired("ssh", 90)) as remote:
            path = second._intent(root, create=True)
            boot._save(path, boot.SECOND_CORRELATION,
                       second._payload(boot.SECOND_CORRELATION, boot.FIRST_CLOSURE))
            result = second.close_start(root, host="archlinux", closure_correlation_id=CLOSE)
            self.assertEqual("unknown", result["state"])
            self.assertFalse(result["replayAllowed"])
            with self.assertRaisesRegex(ValueError, "second closure intent exists"):
                second.close_start(root, host="archlinux", closure_correlation_id=CLOSE)
            self.assertEqual(1, remote.call_count)

    def test_third_requires_exact_local_second_closure_before_remote(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(boot, "_reservation"), \
                mock.patch.object(boot.setup, "status", return_value={"state": "running-observed"}), \
                mock.patch.object(boot, "_remote") as remote:
            boot._save(boot._intent(root, create=True), boot.FIRST_CORRELATION)
            boot._save(boot._close_intent(root, create=True), boot.FIRST_CLOSURE,
                       boot._close_payload(boot.FIRST_CLOSURE))
            boot._save(second._intent(root, create=True), boot.SECOND_CORRELATION,
                       second._payload(boot.SECOND_CORRELATION, boot.FIRST_CLOSURE))
            with self.assertRaises(FileNotFoundError):
                third.start(root, host="archlinux", correlation_id=CORR,
                            closure_correlation_id=CLOSE)
            remote.assert_not_called()
            boot._save(second._close_intent(root, create=True), CLOSE,
                       second._close_payload(CLOSE))
            with mock.patch.object(second, "close_status", return_value={"state": "unknown"}):
                with self.assertRaisesRegex(ValueError, "no terminal closure"):
                    third.start(root, host="archlinux", correlation_id=CORR,
                                closure_correlation_id=CLOSE)
            remote.assert_not_called()

    def test_third_response_loss_cannot_replay(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(third, "_check"), \
                mock.patch.object(boot, "_remote", side_effect=subprocess.TimeoutExpired("ssh", 90)) as remote:
            result = third.start(root, host="archlinux", correlation_id=CORR,
                                 closure_correlation_id=CLOSE)
            self.assertEqual("unknown", result["state"])
            self.assertFalse(result["replayAllowed"])
            with self.assertRaisesRegex(ValueError, "third-attempt intent exists"):
                third.start(root, host="archlinux", correlation_id=CORR,
                            closure_correlation_id=CLOSE)
            self.assertEqual(1, remote.call_count)


if __name__ == "__main__":
    unittest.main()

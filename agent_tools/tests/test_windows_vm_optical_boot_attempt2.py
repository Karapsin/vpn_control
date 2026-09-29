"""Causal admission and no-replay checks for the fixed second optical attempt."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import types
from unittest import mock

from agent_tools import windows_vm_optical_boot as boot
from agent_tools import windows_vm_optical_boot_attempt2 as second


CORR = "123e4567-e89b-12d3-a456-426614174099"
CLOSE = "223e4567-e89b-12d3-a456-426614174099"


class WindowsOpticalSecondAttemptTest(unittest.TestCase):
    def test_paths_and_qmp_effects_are_distinct_but_single(self):
        first = boot._program(boot.FIRST_CORRELATION, "start")
        again = boot._program(CORR, "start", attempt=2, expected_closure=CLOSE)
        for program in (first, again):
            compile(program, "<optical-attempt>", "exec")
            self.assertEqual(1, program.count("command('system_reset')"))
            self.assertEqual(1, program.count("command('send-key'"))
        self.assertIn("ATTEMPT=2", again)
        self.assertIn("EXPECTED_CLOSURE='" + CLOSE + "'", again)
        self.assertIn("verify_first_closed(owner,media,disk)", again)
        self.assertIn("'/optical-boot-attempt2-'", again)
        self.assertIn("'/optical-boot-'", first)

    def test_second_closure_proof_runs_before_action_qmp_client_opens(self):
        program = boot._program(CORR, "start", attempt=2, expected_closure=CLOSE)
        action = program.split("elif MODE=='start':", 1)[1].split("else:raise ValueError('invalid-mode')", 1)[0]
        intent = action.index("record(INTENT,expected(owner,media,disk))")
        proof = action.index("verify_first_closed(owner,media,disk)", intent)
        connect = action.index("sock,command=qmp_open(owner)", proof)
        frame = action.index("first=frame(PRE_FRAME,True,command)", connect)
        self.assertLess(intent, proof)
        self.assertLess(proof, connect)
        self.assertNotIn("verify_first_closed", action[connect:frame])
        self.assertIn("if claim()!=owner or not same_media(media) or blank_disk()!=disk", action[connect:frame])

    def test_remote_admission_rejects_missing_changed_closure_and_orphan_effect(self):
        program = boot._program(CORR, "preflight", attempt=2, expected_closure=CLOSE)
        source = program.split("def verify_first_closed(owner,media,disk):", 1)[1].split("\ntry:\n owner=claim()", 1)[0]
        owner = {"qemuPid": 9, "qemuStartTicks": 12}
        media = {"sha256": "a" * 64}
        disk = {"allocatedGuestClusters": 0}
        expected = {"correlationId": CORR, "owner": owner, "media": media, "blankDisk": disk}
        original = {**expected, "correlationId": boot.FIRST_CORRELATION}
        sample = {"state": "intent-only", "owner": owner, "media": media, "blankDisk": disk,
                  "qmpPeerChecks": {"pid": True, "uid": True, "startTicks": True, "claim": True}}
        marker = {"schemaVersion": 1, "originalCorrelationId": boot.FIRST_CORRELATION,
                  "closureCorrelationId": CLOSE, "owner": owner, "media": media, "blankDisk": disk,
                  "sampleSha256": hashlib.sha256(json.dumps(sample, sort_keys=True).encode()).hexdigest(),
                  "sampleIntervalNs": 1_000_000_000}
        with tempfile.TemporaryDirectory() as root:
            guest = Path(root)
            first_intent = str(guest / "optical-boot-intent.json")
            closed = str(guest / "optical-boot-pre-effect-closed.json")
            records = {first_intent: original}
            namespace = {"ATTEMPT": 2, "MODE": "preflight", "GUEST": root, "CLOSED": closed,
                         "FIRST_CLOSED": closed, "FIRST_CLOSURE": CLOSE,
                         "EXPECTED_CLOSURE": CLOSE, "os": os, "hashlib": hashlib, "json": json,
                         "read": lambda path: records[path], "expected": lambda *args: expected.copy(),
                         "qmp_handshake": lambda _: {"state": "ready", "phase": "complete",
                                                    "peerChecks": sample["qmpPeerChecks"]},
                         "claim": lambda: owner, "same_media": lambda _: True,
                         "blank_disk": lambda: disk}
            exec("def verify_first_closed(owner,media,disk):" + source, namespace)
            with self.assertRaises(KeyError):
                namespace["verify_first_closed"](owner, media, disk)
            records[closed] = {**marker, "closureCorrelationId": CORR}
            with self.assertRaisesRegex(ValueError, "first-closure-changed"):
                namespace["verify_first_closed"](owner, media, disk)
            records[closed] = marker
            namespace["verify_first_closed"](owner, media, disk)
            (guest / "optical-boot-reset.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "first-attempt-effect-observed"):
                namespace["verify_first_closed"](owner, media, disk)

    def test_missing_or_changed_local_closure_rejects_before_remote(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(boot, "_reservation"), \
                mock.patch.object(boot.setup, "status", return_value={"state": "running-observed"}), \
                mock.patch.object(boot, "_remote") as remote:
            original = boot._intent(root, create=True)
            boot._save(original, boot.FIRST_CORRELATION)
            with self.assertRaises(FileNotFoundError):
                second.start(root, host="archlinux", correlation_id=CORR,
                             closure_correlation_id=CLOSE)
            remote.assert_not_called()
            marker = boot._close_intent(root, create=True)
            boot._save(marker, CLOSE, boot._close_payload(CLOSE))
            with mock.patch.object(boot, "close_status", return_value={"state": "unknown"}):
                with self.assertRaisesRegex(ValueError, "no terminal closure"):
                    second.start(root, host="archlinux", correlation_id=CORR,
                                 closure_correlation_id=CLOSE)
            remote.assert_not_called()
            marker.write_text("{}")
            with self.assertRaisesRegex(ValueError, "intent changed"):
                second.start(root, host="archlinux", correlation_id=CORR,
                             closure_correlation_id=CLOSE)
            remote.assert_not_called()

    def test_response_loss_cannot_replay_second_intent(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(second, "_check"), \
                mock.patch.object(boot, "_remote", side_effect=subprocess.TimeoutExpired("ssh", 90)) as remote:
            result = second.start(root, host="archlinux", correlation_id=CORR,
                                  closure_correlation_id=CLOSE)
            self.assertEqual("unknown", result["state"])
            self.assertFalse(result["replayAllowed"])
            with self.assertRaisesRegex(ValueError, "second-attempt intent exists"):
                second.start(root, host="archlinux", correlation_id=CORR,
                             closure_correlation_id=CLOSE)
            self.assertEqual(1, remote.call_count)

    def test_phase_probe_identifies_second_qmp_client_failure_before_frame(self):
        program = boot._program(CORR, "phase-probe", attempt=2, expected_closure=CLOSE)
        source = program.split("elif MODE=='phase-probe':", 1)[1].split("elif MODE=='start':", 1)[0]
        output = []
        call_count = 0
        events = []
        owner, media, disk = {"qemuPid": 9}, {"sha256": "a" * 64}, {"allocatedGuestClusters": 0}
        def verify(*args):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise ValueError("first-closure-changed")
        class Sock:
            def close(self):
                events.append("close")
        namespace = {"validate_receipts": lambda *args: {"state": "intent-only"},
                     "os": types.SimpleNamespace(path=types.SimpleNamespace(lexists=lambda _: False)),
                     "PRE_FRAME": "/pre", "POST_FRAME": "/post", "owner": owner, "media": media,
                     "disk": disk, "verify_first_closed": verify,
                     "qmp_open": lambda _: (Sock(), lambda *args: events.append(args)),
                     "json": json, "CORR": CORR, "print": lambda value: output.append(json.loads(value))}
        exec("def probe():\n" + "".join(" " + line + "\n" for line in source.splitlines() if line), namespace)
        namespace["probe"]()
        self.assertEqual("phase-probed", output[0]["state"])
        self.assertEqual({"state": "unknown", "phase": "closure-with-qmp-open",
                          "reason": "first-closure-changed"}, output[0]["probe"])
        self.assertEqual(["close"], events)
        self.assertEqual(2, call_count)

    def test_phase_probe_requires_second_intent_and_never_replays(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(second, "_check"), \
                mock.patch.object(boot, "_remote") as remote:
            with self.assertRaises(FileNotFoundError):
                second.phase_probe(root, host="archlinux", correlation_id=CORR,
                                   closure_correlation_id=CLOSE)
            remote.assert_not_called()
            path = second._intent(root, create=True)
            boot._save(path, CORR, second._payload(CORR, CLOSE))
            remote.return_value = {"state": "phase-probed", "probe": {"state": "unknown",
                                   "phase": "closure-with-qmp-open", "reason": "first-closure-changed"}}
            result = second.phase_probe(root, host="archlinux", correlation_id=CORR,
                                        closure_correlation_id=CLOSE)
            self.assertFalse(result["replayAllowed"])
            self.assertFalse(result["nativeActionAllowed"])


if __name__ == "__main__":
    unittest.main()

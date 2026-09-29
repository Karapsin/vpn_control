"""Causal one-shot guards for neutral Windows Setup keyboard-page Next."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest import mock

from agent_tools import windows_vm_setup_keyboard_next as next_step


CORR = "823e4567-e89b-12d3-a456-426614174099"
OWNER = {"qemuPid": 9, "qemuStartTicks": 12, "diskDevice": 2, "diskInode": 3,
         "isoDevice": 4, "isoInode": 5}
PRIOR = {"state": "after-observed", "owner": OWNER,
         "frame": {"sha256": next_step.SETUP_FRAME_SHA256, "width": 1280,
                   "height": 800, "sizeBytes": 3072016}}


def ppm() -> bytes:
    return b"P6\n320 240\n255\n" + b"\x12\x34\x56" * (320 * 240)


def sealed(raw: bytes) -> dict:
    return {"state": "after-observed", "owner": OWNER,
            "frame": {"sha256": hashlib.sha256(raw).hexdigest(),
                      "width": 320, "height": 240, "sizeBytes": len(raw)}}


def evidence_root(root: str) -> None:
    for path in (Path(root) / ".runtime", Path(root) / ".runtime/parity-evidence",
                 Path(root) / ".runtime/parity-evidence/optical-boot-20260929"):
        path.mkdir(mode=0o700)


class WindowsSetupKeyboardNextTest(unittest.TestCase):
    def test_previous_language_receipt_and_keyboard_frame_have_distinct_pins(self):
        program = next_step._program("start", CORR, OWNER)
        self.assertIn("LANGUAGE_SETUP_FRAME_SHA='" + next_step.language.SETUP_FRAME_SHA256 + "'", program)
        self.assertIn("SETUP_FRAME_SHA='" + next_step.SETUP_FRAME_SHA256 + "'", program)
        self.assertIn("previous=setup_status(owner,media,disk)", program)
        self.assertIn("previous.get('state')!='after-observed'", program)
        with mock.patch.object(next_step.language, "status", return_value={**PRIOR, "frame": {"sha256": "f" * 64}}):
            with self.assertRaisesRegex(ValueError, "keyboard screen is not sealed"):
                next_step._check(".", "archlinux", CORR, 90)

    def test_action_is_one_return_with_exact_input_frame_and_no_other_input(self):
        program = next_step._program("start", CORR, OWNER)
        compile(program, "<keyboard-next>", "exec")
        action = program.split("KBD_ACTION='start'", 1)[1]
        self.assertEqual(1, action.count("command('send-key'"))
        self.assertIn("'data':'ret'", action)
        self.assertIn("before['sha256']!=SETUP_FRAME_SHA", action)
        self.assertIn("confirm['sha256']!=SETUP_FRAME_SHA", action)
        self.assertIn("record(KBD_KEY_INTENT", action)
        self.assertNotIn("system_reset", action)
        self.assertNotIn("'data':'spc'", action)
        self.assertNotIn("input-send-event", action)

    def test_changed_visible_frame_blocks_key_after_durable_intent(self):
        program = next_step._program("start", CORR, OWNER)
        source = program.split("elif KBD_ACTION=='start':", 1)[1].split("elif KBD_ACTION=='status':", 1)[0]
        calls = []
        class Sock:
            def close(self):
                calls.append("socket-close")
        def command(name, arguments=None):
            calls.append(name)
        def capture(path, enabled, qmp):
            calls.append("capture")
            return {"sha256": "f" * 64}
        namespace = {"keyboard_status": lambda *args: {"state": "absent"},
                     "record": lambda path, value: calls.append(path),
                     "keyboard_expected": lambda *args: {},
                     "qmp_open": lambda owner: (Sock(), command),
                     "claim": lambda: OWNER, "same_media": lambda _: True,
                     "frame": capture, "owner": OWNER, "media": {}, "disk": {}, "old": {},
                     "KBD_INTENT": "intent", "KBD_BEFORE_FRAME": "before-ppm",
                     "SETUP_FRAME_SHA": next_step.SETUP_FRAME_SHA256}
        exec("def action():\n" + "".join(" " + line + "\n" for line in source.splitlines() if line), namespace)
        with self.assertRaisesRegex(ValueError, "setup-visible-frame-changed"):
            namespace["action"]()
        self.assertEqual(["intent", "capture", "socket-close"], calls)

    def test_page_changes_after_key_intent_and_second_capture_blocks_return(self):
        program = next_step._program("start", CORR, OWNER)
        source = program.split("elif KBD_ACTION=='start':", 1)[1].split("elif KBD_ACTION=='status':", 1)[0]
        calls = []
        frames = iter((next_step.SETUP_FRAME_SHA256, "f" * 64))
        class Sock:
            def close(self):
                calls.append("socket-close")
        def command(name, arguments=None):
            calls.append(name)
        def capture(path, enabled, qmp):
            calls.append("capture")
            return {"sha256": next(frames)}
        namespace = {"keyboard_status": lambda *args: {"state": "absent"},
                     "record": lambda path, value: calls.append(path),
                     "keyboard_expected": lambda *args: {},
                     "qmp_open": lambda owner: (Sock(), command),
                     "claim": lambda: OWNER, "same_media": lambda _: True,
                     "frame": capture, "owner": OWNER, "media": {}, "disk": {}, "old": {},
                     "KBD_INTENT": "intent", "KBD_BEFORE_FRAME": "before-ppm",
                     "KBD_CONFIRM_FRAME": "confirm-ppm", "KBD_BEFORE": "before-receipt",
                     "KBD_KEY_INTENT": "key-intent", "SETUP_FRAME_SHA": next_step.SETUP_FRAME_SHA256,
                     "KBD_CORR": CORR}
        exec("def action():\n" + "".join(" " + line + "\n" for line in source.splitlines() if line), namespace)
        with self.assertRaisesRegex(ValueError, "setup-visible-frame-changed-before-key"):
            namespace["action"]()
        self.assertEqual(["intent", "capture", "before-receipt", "key-intent", "capture", "socket-close"], calls)

    def test_lost_start_response_cannot_replay_return(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(next_step, "_check", return_value=PRIOR), \
                mock.patch.object(next_step, "_remote_json", side_effect=subprocess.TimeoutExpired("ssh", 90)) as remote:
            result = next_step.start(root, host="archlinux", next_correlation_id=CORR)
            self.assertEqual("unknown", result["state"])
            self.assertFalse(result["replayAllowed"])
            with self.assertRaisesRegex(ValueError, "intent exists"):
                next_step.start(root, host="archlinux", next_correlation_id=CORR)
            self.assertEqual(1, remote.call_count)

    def test_receipt_order_and_empty_ack_never_claim_after_observed(self):
        program = next_step._program("status", CORR, OWNER)
        source = program.split("def keyboard_status(owner,media,disk):", 1)[1].split("\ntry:\n owner,media,disk,old=keyboard_source()", 1)[0]
        with tempfile.TemporaryDirectory() as root:
            paths = {name: str(Path(root) / name.lower()) for name in
                     ("KBD_INTENT", "KBD_BEFORE", "KBD_KEY_INTENT", "KBD_KEY_ACK", "KBD_AFTER",
                      "KBD_BEFORE_FRAME", "KBD_CONFIRM_FRAME", "KBD_AFTER_FRAME")}
            expected = {"schemaVersion": 1, "nextCorrelationId": CORR}
            records = {paths["KBD_INTENT"]: expected}
            namespace = {"os": os, **paths, "read": lambda path: records[path],
                         "keyboard_expected": lambda *args: expected,
                         "frame": lambda *args: {"sha256": next_step.SETUP_FRAME_SHA256},
                         "SETUP_FRAME_SHA": next_step.SETUP_FRAME_SHA256,
                         "owner": OWNER, "KBD_CORR": CORR}
            exec("def keyboard_status(owner,media,disk):" + source, namespace)
            Path(paths["KBD_INTENT"]).write_text("intent")
            self.assertEqual("intent-only", namespace["keyboard_status"](OWNER, {}, {})["state"])
            Path(paths["KBD_KEY_ACK"]).write_text("{}")
            with self.assertRaisesRegex(ValueError, "setup-receipt-order"):
                namespace["keyboard_status"](OWNER, {}, {})

    def test_sealed_after_frame_collects_private_image_and_tamper_fails(self):
        raw = ppm()
        with tempfile.TemporaryDirectory() as root, mock.patch.object(next_step, "status", return_value=sealed(raw)):
            evidence_root(root)
            with mock.patch.object(next_step.post, "_bounded_ssh", return_value=raw[:-1] + b"X"):
                self.assertEqual("unknown", next_step.collect(root, host="archlinux",
                                                               next_correlation_id=CORR)["state"])
            with mock.patch.object(next_step.post, "_bounded_ssh", return_value=raw):
                result = next_step.collect(root, host="archlinux", next_correlation_id=CORR)
                self.assertEqual("collected", result["state"])
                path = Path(result["imagePath"])
                self.assertEqual(0o600, path.stat().st_mode & 0o777)
                self.assertTrue(path.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"))


if __name__ == "__main__":
    unittest.main()

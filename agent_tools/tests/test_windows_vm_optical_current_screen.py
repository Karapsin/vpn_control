"""Causal one-shot and sealed-frame checks for the settled Windows screen observer."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from agent_tools import windows_vm_optical_current_screen as current


OBS = "723e4567-e89b-12d3-a456-426614174099"
OWNER = {"qemuPid": 9, "qemuStartTicks": 12, "diskDevice": 2, "diskInode": 3,
         "isoDevice": 4, "isoInode": 5}
PRIOR = {"state": "post-screen-observed", "owner": OWNER,
         "frameHashes": {"before": "a" * 64, "after": "b" * 64}}


def ppm() -> bytes:
    return b"P6\n320 240\n255\n" + b"\x12\x34\x56" * (320 * 240)


def sealed(raw: bytes) -> dict:
    return {"state": "observed", "owner": OWNER,
            "frame": {"sha256": hashlib.sha256(raw).hexdigest(),
                      "width": 320, "height": 240, "sizeBytes": len(raw)}}


def evidence_root(root: str) -> None:
    for path in (Path(root) / ".runtime", Path(root) / ".runtime/parity-evidence",
                 Path(root) / ".runtime/parity-evidence/optical-boot-20260929"):
        path.mkdir(mode=0o700)


class WindowsCurrentScreenTest(unittest.TestCase):
    def test_fixed_program_captures_one_frame_without_reset_or_key(self):
        program = current._program("start", OBS, OWNER)
        compile(program, "<windows-current-screen>", "exec")
        action = program.split("ACTION='start'", 1)[1]
        self.assertEqual(1, action.count("frame(CURRENT_FRAME,True,command)"))
        self.assertIn("historical_closures(owner,media,disk)", action)
        self.assertIn("post-screen-observed", action)
        self.assertIn("qmp_open(owner)", action)
        self.assertNotIn("system_reset", action)
        self.assertNotIn("send-key", action)
        self.assertNotIn("tesseract", action.lower())

    def test_remote_status_rejects_orphan_and_changed_receipt(self):
        program = current._program("status", OBS, OWNER)
        source = program.split("def current_status(owner,media,disk,after):", 1)[1].split("\ntry:\n owner,media,disk,after=", 1)[0]
        with tempfile.TemporaryDirectory() as root:
            intent = str(Path(root) / "intent.json")
            receipt = str(Path(root) / "receipt.json")
            frame = str(Path(root) / "frame.ppm")
            owner, media, disk, after = OWNER, {"sha256": "a" * 64}, {"allocatedGuestClusters": 0}, {"sha256": "b" * 64}
            expected = {"schemaVersion": 1, "observationCorrelationId": OBS,
                        "attemptCorrelationId": current.ATTEMPT_CORRELATION,
                        "closureCorrelationId": current.CLOSURE_CORRELATION,
                        "owner": owner, "media": media, "blankDisk": disk,
                        "previousPostSha256": after["sha256"]}
            frame_meta = {"sha256": "c" * 64, "width": 320, "height": 240, "sizeBytes": 100}
            records = {intent: expected}
            namespace = {"os": os, "CURRENT_INTENT": intent, "CURRENT_RECEIPT": receipt,
                         "CURRENT_FRAME": frame, "read": lambda path: records[path],
                         "current_expected": lambda *args: expected,
                         "frame": lambda *args: frame_meta, "OBS": OBS,
                         "CORR": current.ATTEMPT_CORRELATION}
            exec("def current_status(owner,media,disk,after):" + source, namespace)
            self.assertEqual("absent", namespace["current_status"](owner, media, disk, after)["state"])
            Path(frame).write_bytes(b"orphan")
            with self.assertRaisesRegex(ValueError, "orphan-current-evidence"):
                namespace["current_status"](owner, media, disk, after)
            Path(frame).unlink()
            Path(intent).write_text("private intent")
            self.assertEqual("intent-only", namespace["current_status"](owner, media, disk, after)["state"])
            Path(frame).write_bytes(b"unacknowledged")
            self.assertEqual("frame-uncertain", namespace["current_status"](owner, media, disk, after)["state"])
            Path(receipt).write_text("{}")
            records[receipt] = {"schemaVersion": 1, "observationCorrelationId": OBS,
                                "attemptCorrelationId": current.ATTEMPT_CORRELATION,
                                "owner": owner, "frame": {**frame_meta, "sha256": "f" * 64}}
            with self.assertRaisesRegex(ValueError, "current-receipt-changed"):
                namespace["current_status"](owner, media, disk, after)

    def test_lost_start_response_never_replays_observation(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(current, "_check", return_value=PRIOR), \
                mock.patch.object(current, "_remote_json", side_effect=subprocess.TimeoutExpired("ssh", 90)) as remote:
            result = current.start(root, host="archlinux", observation_correlation_id=OBS)
            self.assertEqual("unknown", result["state"])
            self.assertFalse(result["replayAllowed"])
            with self.assertRaisesRegex(ValueError, "intent exists"):
                current.start(root, host="archlinux", observation_correlation_id=OBS)
            self.assertEqual(1, remote.call_count)

    def test_sealed_current_frame_collects_private_png_and_tamper_fails(self):
        raw = ppm()
        with tempfile.TemporaryDirectory() as root, mock.patch.object(current, "status", return_value=sealed(raw)):
            evidence_root(root)
            with mock.patch.object(current.post, "_bounded_ssh", return_value=raw[:-1] + b"X"):
                result = current.collect(root, host="archlinux", observation_correlation_id=OBS)
                self.assertEqual("unknown", result["state"])
            with mock.patch.object(current.post, "_bounded_ssh", return_value=raw):
                result = current.collect(root, host="archlinux", observation_correlation_id=OBS)
                self.assertEqual("collected", result["state"])
                path = Path(result["imagePath"])
                self.assertEqual(0o600, path.stat().st_mode & 0o777)
                self.assertEqual(0o700, path.parent.stat().st_mode & 0o777)
                self.assertTrue(path.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"))
                with self.assertRaisesRegex(ValueError, "already exists"):
                    current.collect(root, host="archlinux", observation_correlation_id=OBS)

    def test_response_loss_does_not_claim_collected_image(self):
        raw = ppm()
        with tempfile.TemporaryDirectory() as root, mock.patch.object(current, "status", return_value=sealed(raw)), \
                mock.patch.object(current.post, "_bounded_ssh", side_effect=TimeoutError("lost")):
            evidence_root(root)
            result = current.collect(root, host="archlinux", observation_correlation_id=OBS)
            self.assertEqual("unknown", result["state"])
            self.assertFalse(list(Path(root).rglob("*.png")))


if __name__ == "__main__":
    unittest.main()

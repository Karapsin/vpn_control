"""Causal guards for read-only collection of the sealed third post-frame."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest import mock
import zlib

from agent_tools import windows_vm_optical_post_collect as collect


CORR = "523e4567-e89b-12d3-a456-426614174099"
CLOSE = "623e4567-e89b-12d3-a456-426614174099"
OWNER = {"qemuPid": 9, "qemuStartTicks": 12, "diskDevice": 2, "diskInode": 3,
         "isoDevice": 4, "isoInode": 5}


def ppm() -> bytes:
    return b"P6\n320 240\n255\n" + b"\x12\x34\x56" * (320 * 240)


def observed(raw: bytes) -> dict:
    return {"state": "post-screen-observed", "owner": OWNER,
            "frameHashes": {"before": "a" * 64, "after": hashlib.sha256(raw).hexdigest()}}


def evidence_root(root: str) -> None:
    for path in (Path(root) / ".runtime", Path(root) / ".runtime/parity-evidence",
                 Path(root) / ".runtime/parity-evidence/optical-boot-20260929"):
        path.mkdir(mode=0o700)


class WindowsOpticalPostCollectTest(unittest.TestCase):
    def test_remote_program_is_binary_read_only_and_binds_sealed_receipts(self):
        program = collect._program(CORR, CLOSE, OWNER)
        compile(program, "<post-frame>", "exec")
        action = program.split("EXPECTED_OWNER=", 1)[1]
        self.assertIn("owner!=EXPECTED_OWNER", action)
        self.assertIn("historical_closures(owner,media,disk)", action)
        self.assertIn("validate_receipts(owner,media,disk)", action)
        self.assertIn("post-screen-observed", action)
        self.assertIn("frame(POST_FRAME,False)", action)
        self.assertIn("claim()!=owner", action)
        self.assertNotIn("system_reset", action)
        self.assertNotIn("send-key", action)
        self.assertNotIn("screendump", action)

    def test_corrupt_ppm_digest_and_dimensions_are_rejected(self):
        raw = ppm()
        digest = hashlib.sha256(raw).hexdigest()
        self.assertEqual((320, 240), collect._ppm(raw, digest)[:2])
        with self.assertRaisesRegex(ValueError, "digest"):
            collect._ppm(raw[:-1] + b"X", digest)
        altered = b"P6\n320 241\n255\n" + raw.split(b"\n", 3)[3]
        with self.assertRaisesRegex(ValueError, "dimensions"):
            collect._ppm(altered, hashlib.sha256(altered).hexdigest())

    def test_matching_sealed_frame_publishes_private_png_once(self):
        raw = ppm()
        with tempfile.TemporaryDirectory() as root:
            evidence_root(root)
            with mock.patch.object(collect.third, "status", return_value=observed(raw)), \
                    mock.patch.object(collect, "_bounded_ssh", return_value=raw):
                result = collect.collect(root, host="archlinux", correlation_id=CORR,
                                         closure_correlation_id=CLOSE)
                self.assertEqual("collected", result["state"])
                path = Path(result["imagePath"])
                self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
                self.assertEqual(0o700, stat.S_IMODE(path.parent.stat().st_mode))
                png = path.read_bytes()
                self.assertTrue(png.startswith(b"\x89PNG\r\n\x1a\n"))
                self.assertEqual((320, 240), struct.unpack(">II", png[16:24]))
                self.assertEqual(result["pngSha256"], hashlib.sha256(png).hexdigest())
                with self.assertRaisesRegex(ValueError, "already exists"):
                    collect.collect(root, host="archlinux", correlation_id=CORR,
                                    closure_correlation_id=CLOSE)

    def test_tamper_or_response_loss_never_claims_collected(self):
        raw = ppm()
        with tempfile.TemporaryDirectory() as root:
            evidence_root(root)
            with mock.patch.object(collect.third, "status", return_value=observed(raw)), \
                    mock.patch.object(collect, "_bounded_ssh", return_value=raw[:-1] + b"X"):
                result = collect.collect(root, host="archlinux", correlation_id=CORR,
                                         closure_correlation_id=CLOSE)
                self.assertEqual("unknown", result["state"])
                self.assertFalse(list((Path(root) / collect.EVIDENCE).glob("*.png")))
            with mock.patch.object(collect.third, "status", return_value=observed(raw)), \
                    mock.patch.object(collect, "_bounded_ssh", side_effect=TimeoutError("lost response")):
                result = collect.collect(root, host="archlinux", correlation_id=CORR,
                                         closure_correlation_id=CLOSE)
                self.assertEqual("unknown", result["state"])
                self.assertFalse(list((Path(root) / collect.EVIDENCE).glob("*.png")))

    def test_unsealed_status_refuses_before_transport(self):
        with tempfile.TemporaryDirectory() as root, \
                mock.patch.object(collect.third, "status", return_value={"state": "intent-only"}), \
                mock.patch.object(collect, "_bounded_ssh") as fetch:
            with self.assertRaisesRegex(ValueError, "not sealed"):
                collect.collect(root, host="archlinux", correlation_id=CORR,
                                closure_correlation_id=CLOSE)
            fetch.assert_not_called()

    def test_short_local_write_keeps_partial_file_and_cannot_claim_collection(self):
        raw = ppm()
        with tempfile.TemporaryDirectory() as root:
            evidence_root(root)
            original_write = os.write
            calls = 0
            def broken(fd, data):
                nonlocal calls
                calls += 1
                return original_write(fd, bytes(data[:2])) if calls == 1 else 0
            with mock.patch.object(collect.third, "status", return_value=observed(raw)), \
                    mock.patch.object(collect, "_bounded_ssh", return_value=raw), \
                    mock.patch.object(collect.os, "write", side_effect=broken):
                with self.assertRaisesRegex(OSError, "short write"):
                    collect.collect(root, host="archlinux", correlation_id=CORR,
                                    closure_correlation_id=CLOSE)
            path = Path(root) / collect.EVIDENCE / ("post-" + CORR + ".png")
            self.assertEqual(2, path.stat().st_size)
            with mock.patch.object(collect.third, "status", return_value=observed(raw)), \
                    mock.patch.object(collect, "_bounded_ssh") as fetch:
                with self.assertRaisesRegex(ValueError, "already exists"):
                    collect.collect(root, host="archlinux", correlation_id=CORR,
                                    closure_correlation_id=CLOSE)
                fetch.assert_not_called()

    def test_swapped_parent_after_fetch_cannot_publish_or_claim_collected(self):
        raw = ppm()
        with tempfile.TemporaryDirectory() as root:
            evidence_root(root)
            original = Path(root) / ".runtime/parity-evidence/optical-boot-20260929"
            moved = original.with_name("optical-boot-20260929-moved")
            def swap(*args):
                original.rename(moved)
                original.symlink_to(moved, target_is_directory=True)
                return raw
            with mock.patch.object(collect.third, "status", return_value=observed(raw)), \
                    mock.patch.object(collect, "_bounded_ssh", side_effect=swap):
                with self.assertRaisesRegex(ValueError, "ancestor changed"):
                    collect.collect(root, host="archlinux", correlation_id=CORR,
                                    closure_correlation_id=CLOSE)
            self.assertFalse(list(moved.rglob("*.png")))


if __name__ == "__main__":
    unittest.main()

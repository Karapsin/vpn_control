import json
import os
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import native_fixture_signal as signal


class NativeFixtureSignalTest(unittest.TestCase):
    def test_partial_writes_never_expose_the_final_acknowledgment(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "release-ready"
            real_write = os.write
            observed = []

            def partial_write(descriptor, data):
                observed.append(destination.exists())
                self.assertFalse(destination.exists(), "Reader observed an incomplete final acknowledgment")
                return real_write(descriptor, data[:2])

            with patch.object(signal.os, "write", side_effect=partial_write):
                receipt = signal.publish_fixture_signal(destination)
            self.assertGreater(len(observed), 1)
            self.assertTrue(receipt["published"])
            self.assertEqual(b"continue\n", destination.read_bytes())
            self.assertEqual([destination], list(Path(directory).iterdir()))

    def test_existing_final_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "release-ready"
            destination.write_bytes(b"prior signal")
            before = destination.stat()
            receipt = signal.publish_fixture_signal(destination)
            self.assertIsNone(receipt["published"])
            self.assertEqual(b"prior signal", destination.read_bytes())
            self.assertEqual(before.st_ino, destination.stat().st_ino)
            self.assertEqual(before.st_mtime_ns, destination.stat().st_mtime_ns)
            self.assertIsNotNone(receipt["stagedPath"])
            self.assertEqual(b"continue\n", Path(receipt["stagedPath"]).read_bytes())

    def test_colliding_stage_is_preserved_without_claiming_its_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "release-ready"
            fixed = uuid.UUID("12345678-1234-1234-1234-123456789abc")
            stage = destination.with_name(f".{destination.name}.{fixed.hex}.pending")
            stage.write_bytes(b"another fixture owns this stage")
            before = stage.stat()
            with patch.object(signal.uuid, "uuid4", return_value=fixed):
                receipt = signal.publish_fixture_signal(destination)
            self.assertTrue(stage.exists(), "An unowned colliding stage was removed")
            self.assertEqual(b"another fixture owns this stage", stage.read_bytes())
            self.assertEqual(before.st_ino, stage.stat().st_ino)
            self.assertEqual(before.st_mtime_ns, stage.stat().st_mtime_ns)
            self.assertIs(receipt["published"], False)
            self.assertIsNone(receipt["stagedPath"])
            self.assertFalse(destination.exists())

    def test_write_failure_before_publication_leaves_no_final(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "release-ready"
            with patch.object(signal.os, "write", side_effect=OSError("inert write failure")):
                receipt = signal.publish_fixture_signal(destination)
            self.assertIs(receipt["published"], False)
            self.assertFalse(destination.exists())
            self.assertIsNone(receipt["stagedPath"])
            self.assertEqual([], list(Path(directory).iterdir()))

    def test_zero_progress_write_is_bounded_and_unpublished(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "release-ready"
            with patch.object(signal.os, "write", return_value=0) as write:
                receipt = signal.publish_fixture_signal(destination)
            self.assertEqual(1, write.call_count)
            self.assertIs(receipt["published"], False)
            self.assertFalse(destination.exists())

    def test_error_after_atomic_publication_remains_unknown_and_retains_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "release-ready"
            real_link = os.link

            def link_then_fail(source, target):
                real_link(source, target)
                raise OSError("inert response loss after atomic publication")

            with patch.object(signal.os, "link", side_effect=link_then_fail):
                receipt = signal.publish_fixture_signal(destination)
            self.assertIsNone(receipt["published"])
            self.assertTrue(os.path.samefile(receipt["stagedPath"], destination))
            self.assertEqual(b"continue\n", destination.read_bytes())

    def test_stage_cleanup_failure_preserves_known_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "retry-owned-cleanup"
            with patch.object(signal.os, "unlink", side_effect=PermissionError("inert cleanup failure")):
                receipt = signal.publish_fixture_signal(destination)
            self.assertIs(receipt["published"], True)
            self.assertIsNotNone(receipt["cleanupError"])
            self.assertTrue(os.path.samefile(receipt["stagedPath"], destination))
            self.assertEqual(b"retry\n", destination.read_bytes())
            retry = signal.publish_fixture_signal(destination)
            self.assertIsNone(retry["published"])
            self.assertEqual(b"retry\n", destination.read_bytes())

    def test_unknown_signal_name_is_rejected_without_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                signal.publish_fixture_signal(Path(directory) / "arbitrary-data")
            self.assertEqual([], list(Path(directory).iterdir()))

    def test_direct_cli_publishes_complete_signal_and_json_receipt(self):
        with tempfile.TemporaryDirectory(prefix="fixture signal Ю ") as directory:
            destination = Path(directory) / "release-ready"
            process = subprocess.run([sys.executable, str(Path(signal.__file__)), str(destination)],
                                     capture_output=True, text=True, encoding="utf-8", errors="replace")
            self.assertEqual(0, process.returncode, process.stderr)
            receipt = json.loads(process.stdout)
            self.assertIs(receipt["published"], True)
            self.assertIsNone(receipt["stagedPath"])
            self.assertEqual(b"continue\n", destination.read_bytes())


if __name__ == "__main__":
    unittest.main()

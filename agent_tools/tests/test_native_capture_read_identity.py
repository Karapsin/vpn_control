"""A terminal evidence read must not mistake access time for content drift."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from agent_tools.windows_diagnostic_authority_capture import _generation


class TerminalReadIdentityTest(unittest.TestCase):
    def test_actual_read_retains_content_generation_despite_access_time(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "terminal.json"
            raw = b'{"state":"ready"}\n'
            path.write_bytes(raw); path.chmod(0o600)
            # Establish a clearly old access time before opening the evidence.
            info = path.stat()
            os.utime(path, ns=(1_000_000_000, info.st_mtime_ns))
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                opening = os.fstat(fd)
                received = os.read(fd, len(raw) + 1)
                closing = os.fstat(fd); named = path.lstat()
                if opening.st_atime_ns == closing.st_atime_ns:
                    self.skipTest("filesystem does not update access time on read")
                # Reproduce the failed wrapper's whole-stat comparison, then
                # exercise the existing capture generation used by corrected
                # terminal observers. No replacement generation is adopted.
                self.assertNotEqual(opening, closing)
                self.assertEqual(_generation(opening), _generation(closing))
                self.assertEqual(_generation(opening), _generation(named))
                self.assertEqual(raw, received)
                self.assertEqual(hashlib.sha256(raw).digest(), hashlib.sha256(received).digest())
            finally:
                os.close(fd)


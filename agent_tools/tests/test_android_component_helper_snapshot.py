"""Causal native collector regression: reads may change only atime."""
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest

from agent_tools import android_component_successor as successor

FIXTURE = Path(__file__).parent / "fixtures/android_component_successor/helper.before.source"
FIXTURE_SHA = "0944c7f4f02f5c9fbe835351c3bf54b5fdc731e85c2be74192a38743a4f9a526"


@unittest.skipUnless(os.name == "posix", "The protected collector uses POSIX private files")
class ComponentHelperSnapshotTests(unittest.TestCase):
    def test_first_read_atime_change_does_not_reject_authentic_helper(self):
        self.assertEqual(hashlib.sha256(FIXTURE.read_bytes()).hexdigest(), FIXTURE_SHA)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            path = root / "helper.py"
            raw = b"answer=73\n"
            path.write_bytes(raw)
            path.chmod(0o600)
            os.utime(path, ns=(0, path.stat().st_mtime_ns))
            before = successor._pin(path.lstat())
            if os.environ.get("VPN_CONTROL_TEST_LEGACY_HELPER") == "1":
                namespace = {"root": root, "stat": stat, "os": os, "sys": sys,
                             "types": types, "hashlib": hashlib}
                exec(compile(FIXTURE.read_bytes(), str(FIXTURE), "exec"), namespace)
                module = namespace["load"](path.name, hashlib.sha256(raw).hexdigest())
            else:
                module = successor.load_private_module(path, hashlib.sha256(raw).hexdigest(), "retained_helper_control")
            self.assertEqual(module.answer, 73)
            self.assertEqual(successor._pin(path.lstat()), before)
            self.assertEqual(path.read_bytes(), raw)

    def test_changed_bytes_cannot_be_qualified_by_fresh_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            path = root / "helper.py"
            original = b"answer=73\n"
            path.write_bytes(b"answer=74\n")
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "successor_helper_changed"):
                successor.load_private_module(path, hashlib.sha256(original).hexdigest(), "retained_helper_control")


if __name__ == "__main__":
    unittest.main()

"""Physical source/registration modes from the Windows native caller refusal.

The authentic private whole caller beforeimage is retained in the task evidence.
The same positive below is also run against that caller's original admission
loop for actual RED; private fixture aliases and receipts are not copied here.
"""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_tools import windows_native_source_custody as current


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
                     "native provider source custody requires POSIX nofollow files")
class WindowsNativeSourceCustodyTests(unittest.TestCase):
    reader = staticmethod(current.source_pins)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.public = tuple(self.root / name for name in ("caller.py", "issuer.py", "listener.py"))
        for index, path in enumerate(self.public):
            path.write_bytes(("PUBLIC_SOURCE = " + str(index) + "\n").encode())
            path.chmod(0o644)
        self.registration = self.root / "registration.json"
        self.registration.write_bytes(b'{"provider":"raw-qemu-windows"}\n')
        self.registration.chmod(0o600)

    def test_public_helpers_and_private_registration_admit(self):
        try:
            pins = self.reader(self.public, self.registration)
        except (OSError, ValueError) as error:
            self.fail("ordinary public helper source was refused: " + str(error))
        self.assertEqual({str(path) for path in (*self.public, self.registration)}, set(pins))
        for path in (*self.public, self.registration):
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), pins[str(path)]["sha256"])
            self.assertEqual(path.stat().st_ino, pins[str(path)]["generation"][1])

    def test_owner_only_public_helpers_also_admit(self):
        for path in self.public:
            path.chmod(0o600)
        self.assertEqual(4, len(self.reader(self.public, self.registration)))

    def test_public_source_uses_native_source_bound_instead_of_metadata_bound(self):
        self.public[0].write_bytes(b"#" + b" " * (current._SOURCE_LIMIT - 2) + b"\n")
        try:
            pins = self.reader(self.public, self.registration)
        except (OSError, ValueError) as error:
            self.fail("bounded public source was refused as metadata: " + str(error))
        self.assertEqual(hashlib.sha256(self.public[0].read_bytes()).hexdigest(),
                         pins[str(self.public[0])]["sha256"])

    def test_source_overflow_and_metadata_overflow_still_refuse(self):
        self.public[0].write_bytes(b"#" + b" " * current._SOURCE_LIMIT)
        with self.assertRaisesRegex(ValueError, "fixture_file_unsafe"):
            self.reader(self.public, self.registration)
        self.public[0].write_bytes(b"# source\n")
        self.registration.write_bytes(b" " * 262145)
        with self.assertRaisesRegex(ValueError, "fixture_file_unsafe"):
            self.reader(self.public, self.registration)

    def test_private_registration_never_admits_public_mode(self):
        self.registration.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "fixture_file_unsafe"):
            self.reader(self.public, self.registration)

    def test_writable_public_source_is_refused(self):
        self.public[0].chmod(0o666)
        with self.assertRaisesRegex(ValueError, "fixture_file_unsafe"):
            self.reader(self.public, self.registration)

    def test_source_symlink_and_hardlink_are_refused(self):
        source = self.public[0]
        alias = self.root / "alias.py"
        alias.symlink_to(source)
        with self.assertRaisesRegex(ValueError, "windows_native_source_path"):
            self.reader((alias, *self.public[1:]), self.registration)
        alias.unlink()
        os.link(source, alias)
        with self.assertRaisesRegex(ValueError, "fixture_file_unsafe"):
            self.reader(self.public, self.registration)

    def test_replaced_source_fails_its_physical_generation_guard(self):
        original_read = os.read
        replaced = False

        def reading(descriptor, count):
            nonlocal replaced
            data = original_read(descriptor, count)
            if not replaced and os.fstat(descriptor).st_ino == self.public[0].stat().st_ino:
                replacement = self.root / "replacement.py"
                replacement.write_bytes(data)
                replacement.chmod(0o644)
                os.replace(replacement, self.public[0])
                replaced = True
            return data

        with patch.object(current.registry.os, "read", reading):
            with self.assertRaisesRegex(ValueError, "fixture_file_changed"):
                self.reader(self.public, self.registration)
        self.assertTrue(replaced)

    def test_duplicates_relative_paths_and_non_source_inputs_refuse(self):
        for public, registration in (((), self.registration),
                                     ((self.public[0], self.public[0]), self.registration),
                                     ((Path("relative.py"),), self.registration),
                                     ((self.registration,), self.registration),
                                     (self.public, self.public[0])):
            with self.subTest(public=public, registration=registration):
                with self.assertRaises((OSError, ValueError)):
                    self.reader(public, registration)


if __name__ == "__main__":
    unittest.main()

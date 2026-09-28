"""Portable process-level regressions for checkout check exclusion."""

import importlib
import errno
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from agent_tools import managed_check_lease as lease


ROOT = Path(__file__).resolve().parents[2]


class ManagedCheckLeaseTest(unittest.TestCase):
    def test_overlapping_process_is_rejected_and_exit_releases_lock(self):
        program = """import os, sys
from pathlib import Path
from agent_tools.managed_check_lease import acquire
with acquire(sys.argv[1]):
    Path(sys.argv[1], 'ready').write_text('locked')
    command = sys.stdin.readline().strip()
    if command == 'abrupt':
        os._exit(0)
"""
        for exit_mode in ("normal", "abrupt"):
            with self.subTest(exit_mode=exit_mode), tempfile.TemporaryDirectory() as directory:
                child = subprocess.Popen([sys.executable, "-c", program, directory], cwd=ROOT,
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    deadline = time.monotonic() + 10
                    while not (Path(directory) / "ready").exists() and child.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue((Path(directory) / "ready").exists(), "Child did not acquire its lock")
                    lock_path = Path(directory) / ".rag_index" / "managed-checks" / "lease.lock"
                    identity = lock_path.stat()
                    with self.assertRaises(lease.ManagedCheckLeaseError) as error:
                        with lease.acquire(directory):
                            self.fail("Overlapping validation acquired the checkout")
                    self.assertEqual("busy", error.exception.state)
                    stdout, stderr = child.communicate(exit_mode + "\n", timeout=10)
                    self.assertEqual(0, child.returncode, stdout + stderr)
                    with lease.acquire(directory):
                        self.assertEqual(identity.st_ino, lock_path.stat().st_ino)
                    self.assertTrue(lock_path.is_file())
                finally:
                    if child.poll() is None:
                        child.kill()
                    child.communicate(timeout=10)

    def test_exception_releases_descriptor_without_replacing_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "check failed"):
                with lease.acquire(directory):
                    raise RuntimeError("check failed")
            path = Path(directory) / ".rag_index" / "managed-checks" / "lease.lock"
            identity = path.stat()
            with lease.acquire(directory):
                self.assertEqual(identity.st_ino, path.stat().st_ino)

    def test_different_checkouts_can_run_independently(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            with lease.acquire(first), lease.acquire(second):
                pass

    def test_missing_lock_api_fails_closed_before_creating_state(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
                importlib, "import_module", side_effect=ModuleNotFoundError("unsupported")):
            with self.assertRaises(lease.ManagedCheckLeaseError) as error:
                with lease.acquire(directory):
                    self.fail("Missing native lock API admitted a check")
            self.assertEqual("unknown", error.exception.state)
            self.assertFalse((Path(directory) / ".rag_index").exists())

    def test_incomplete_lock_api_fails_closed_before_creating_state(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
                importlib, "import_module", return_value=object()):
            with self.assertRaises(lease.ManagedCheckLeaseError) as error:
                with lease.acquire(directory):
                    self.fail("Incomplete native lock API admitted a check")
            self.assertEqual("unknown", error.exception.state)
            self.assertFalse((Path(directory) / ".rag_index").exists())

    def test_unexpected_lock_failure_is_unknown_and_releases_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(lease, "_try_lock", side_effect=OSError("unsupported filesystem")):
                with self.assertRaises(lease.ManagedCheckLeaseError) as error:
                    with lease.acquire(directory):
                        self.fail("Uncertain lock failure admitted a check")
                self.assertEqual("unknown", error.exception.state)
            with lease.acquire(directory):
                pass

    def test_windows_lock_uses_one_nonblocking_byte_from_offset_zero(self):
        backend = SimpleNamespace(locking=mock.Mock(), LK_NBLCK=2)
        windows = SimpleNamespace(name="nt", lseek=mock.Mock(), SEEK_SET=0)
        with mock.patch.object(lease, "os", windows):
            lease._try_lock(7, backend)
        windows.lseek.assert_called_once_with(7, 0, 0)
        backend.locking.assert_called_once_with(7, 2, 1)

    def test_windows_contention_is_busy_but_unsupported_filesystem_is_unknown(self):
        windows = SimpleNamespace(name="nt", lseek=mock.Mock(), SEEK_SET=0)
        for code in (errno.EACCES, errno.EINVAL):
            backend = SimpleNamespace(locking=mock.Mock(side_effect=OSError(code, "lock failure")), LK_NBLCK=2)
            with self.subTest(code=code), mock.patch.object(lease, "os", windows):
                if code == errno.EACCES:
                    with self.assertRaises(lease.ManagedCheckLeaseError) as error:
                        lease._try_lock(7, backend)
                    self.assertEqual("busy", error.exception.state)
                else:
                    # acquire maps this native uncertainty to an unknown error.
                    with self.assertRaises(OSError):
                        lease._try_lock(7, backend)

    @unittest.skipUnless(os.name == "posix", "POSIX ownership boundary")
    def test_shared_readable_index_gets_private_lease_without_permission_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / ".rag_index"
            parent.mkdir(mode=0o755)
            parent.chmod(0o755)
            with lease.acquire(directory):
                self.assertEqual(0o755, parent.stat().st_mode & 0o777)
                self.assertEqual(0o700, (parent / "managed-checks").stat().st_mode & 0o777)
                self.assertEqual(0o600, (parent / "managed-checks" / "lease.lock").stat().st_mode & 0o777)

    @unittest.skipUnless(os.name == "posix", "POSIX ownership boundary")
    def test_nonprivate_lock_and_links_are_rejected(self):
        for unsafe in ("mode", "symlink", "hardlink"):
            with self.subTest(unsafe=unsafe), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                state = root / ".rag_index" / "managed-checks"
                state.mkdir(mode=0o700, parents=True)
                path = state / "lease.lock"
                if unsafe == "symlink":
                    target = root / "target"
                    target.touch(mode=0o600)
                    path.symlink_to(target)
                else:
                    path.touch(mode=0o644 if unsafe == "mode" else 0o600)
                    if unsafe == "hardlink":
                        os.link(path, root / "other-link")
                with self.assertRaises(lease.ManagedCheckLeaseError) as error:
                    with lease.acquire(root):
                        self.fail("Unsafe state admitted a check")
                self.assertEqual("unknown", error.exception.state)

    @unittest.skipUnless(os.name == "posix", "POSIX ownership boundary")
    def test_state_directory_cannot_redirect_or_allow_other_writers(self):
        for unsafe in ("symlink", "mode"):
            with self.subTest(unsafe=unsafe), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                state = root / ".rag_index"
                if unsafe == "symlink":
                    target = root / "elsewhere"
                    target.mkdir()
                    state.symlink_to(target)
                else:
                    state.mkdir()
                    state.chmod(0o777)
                with self.assertRaises(lease.ManagedCheckLeaseError) as error:
                    with lease.acquire(root):
                        self.fail("Unsafe state directory admitted a check")
                self.assertEqual("unknown", error.exception.state)


if __name__ == "__main__":
    unittest.main()

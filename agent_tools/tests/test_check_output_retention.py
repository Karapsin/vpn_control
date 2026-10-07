import hashlib
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid

from agent_tools import check_output_retention as retention


@unittest.skipUnless(os.name == "posix", "POSIX private descriptor capture")
class RetainTests(unittest.TestCase):
    def call(self, root, out=b"original", err=b"", **kwargs):
        return retention.retain_completed_output(root, label="prepush", returncode=1,
                                                stdout=out, stderr=err,
                                                source_fingerprint="a" * 64, **kwargs)

    def capsule(self, root):
        return next((Path(root) / ".rag_index" / "check-runs").iterdir())

    def test_actual_unittest_middle_failures_and_full_saved_bytes(self):
        class Failures(unittest.TestCase):
            def test_failure(self):
                self.fail("PRIVATE_FIXTURE_MESSAGE")
            def test_error(self):
                raise ValueError("PRIVATE_FIXTURE_MESSAGE")
        Failures.__qualname__ = "Failures"
        Failures.__module__ = "fixture_cases"
        output = io.StringIO()
        result = unittest.TextTestRunner(stream=output).run(unittest.defaultTestLoader.loadTestsFromTestCase(Failures))
        self.assertEqual((len(result.failures), len(result.errors)), (1, 1))
        body = b"x" * 200000 + b"\n" + output.getvalue().encode() + b"y" * 200000
        with tempfile.TemporaryDirectory() as root:
            record = self.call(root, err=body)
            self.assertEqual(set(record["tests"]["identities"]),
                             {"fixture_cases.Failures.test_failure", "fixture_cases.Failures.test_error"})
            self.assertNotIn("PRIVATE_FIXTURE_MESSAGE", str(record))
            path = self.capsule(root) / "stderr.private"
            self.assertEqual(path.read_bytes(), body)
            self.assertEqual(record["stderr"]["sha256"], hashlib.sha256(body).hexdigest())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_symlink_refuses_at_actual_base_branch_without_mutation_or_fd_leak(self):
        with tempfile.TemporaryDirectory() as root:
            index = Path(root) / ".rag_index"
            index.mkdir(mode=0o755)
            index.chmod(0o755)  # Establish this fixture independent of launcher umask.
            foreign = Path(root) / "foreign"
            foreign.mkdir(mode=0o755)
            foreign.chmod(0o755)
            (index / "check-runs").symlink_to(foreign)
            opened, closed, attempted = [], [], []
            real_open, real_close = os.open, os.close
            def opening(name, *args, **kwargs):
                attempted.append(str(name))
                fd = real_open(name, *args, **kwargs)
                opened.append(fd)
                return fd
            def closing(fd):
                closed.append(fd)
                return real_close(fd)
            with mock.patch.object(os, "open", side_effect=opening), mock.patch.object(os, "close", side_effect=closing):
                with self.assertRaises(OSError):
                    self.call(root)
            self.assertIn("check-runs", attempted)
            self.assertCountEqual(opened, closed)
            self.assertEqual(stat.S_IMODE(foreign.stat().st_mode), 0o755)
            self.assertEqual(list(foreign.iterdir()), [])

    def test_existing_public_index_is_supported_and_not_chmodded(self):
        with tempfile.TemporaryDirectory() as root:
            index = Path(root) / ".rag_index"
            index.mkdir(mode=0o755)
            index.chmod(0o755)  # Establish this fixture independent of launcher umask.
            self.call(root)
            self.assertEqual(stat.S_IMODE(index.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE((index / "check-runs").stat().st_mode), 0o700)

    def test_existing_capsule_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(retention.uuid, "uuid4", return_value=uuid.UUID(int=1)):
            self.call(root)
            receipt = (self.capsule(root) / "receipt.json").read_bytes()
            with self.assertRaises(FileExistsError):
                self.call(root, out=b"other")
            self.assertEqual((self.capsule(root) / "receipt.json").read_bytes(), receipt)

    def test_saved_bytes_and_late_population_drift_refuse(self):
        for stage in (1, 2, 3, "directory"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as root:
                real_sync = os.fsync
                regular = 0
                changed = False
                def sync(fd):
                    nonlocal regular, changed
                    real_sync(fd)
                    is_file = stat.S_ISREG(os.fstat(fd).st_mode)
                    if is_file:
                        regular += 1
                    ready = (Path(root) / ".rag_index" / "check-runs").exists()
                    if not ready or changed:
                        return
                    capsules = list((Path(root) / ".rag_index" / "check-runs").iterdir())
                    if not capsules:
                        return
                    capsule = capsules[0]
                    if ((is_file and regular == stage)
                            or (stage == "directory" and not is_file and (capsule / "receipt.json").exists())):
                        changed = True
                        target = capsule / "stdout.private"
                        if stage == 1:
                            target.write_bytes(b"changed")
                        elif stage == 2:
                            target.chmod(0o664)
                        else:
                            target.unlink()
                            target.write_bytes(b"original")
                with mock.patch.object(os, "fsync", side_effect=sync):
                    with self.assertRaises(retention.RetentionError):
                        self.call(root, err=b"error")
                self.assertTrue(changed)

    def test_projection_failure_preserves_raw_and_has_no_receipt(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(retention, "_tests", side_effect=ValueError("fixture projection")):
            with self.assertRaises(ValueError):
                self.call(root)
            capsule = self.capsule(root)
            self.assertEqual((capsule / "stdout.private").read_bytes(), b"original")
            self.assertFalse((capsule / "receipt.json").exists())

    def test_duplicate_headers_do_not_claim_cap_truncation(self):
        one = b"FAIL: test_x (pkg.Case.test_x)\n"
        result = retention._tests(one * 2)
        self.assertEqual((result["count"], result["total"], result["truncated"]), (1, 2, False))
        many = b"".join(("ERROR: test_%d (pkg.Case.test_%d)\n" % (i, i)).encode() for i in range(513))
        result = retention._tests(many)
        self.assertEqual((result["count"], result["total"], result["truncated"]), (512, 513, True))
        self.assertEqual(retention._tests(b"ERROR: test_x (pkg.Case.other)\n")["unparsedHeaders"], 1)

    def test_actual_public_index_fixtures_under_restrictive_child_umask(self):
        module = "agent_tools.tests.test_check_output_retention.RetainTests."
        names = [module + "test_existing_public_index_is_supported_and_not_chmodded",
                 module + "test_symlink_refuses_at_actual_base_branch_without_mutation_or_fd_leak"]
        code = "import os,unittest; os.umask(0o077); " + "suite=unittest.defaultTestLoader.loadTestsFromNames(" + repr(names) + "); " + "result=unittest.TextTestRunner().run(suite); raise SystemExit(not result.wasSuccessful())"
        result = subprocess.run([sys.executable, "-c", code], cwd=Path(__file__).resolve().parents[2],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Ran 2 tests", result.stderr)

    def test_unsupported_platform_is_finite_before_filesystem_work(self):
        with mock.patch.object(retention.os, "name", "nt"):
            with self.assertRaisesRegex(retention.RetentionError, "unsupported_private_retention"):
                self.call("unused")


@unittest.skipUnless(os.name == "posix", "POSIX held capture")
class ObservationTests(unittest.TestCase):
    def capture(self, **changes):
        return {"stdout": b"PRIVATE\x00\xff", "stderr": b"\r\n", "counts": {"stdout": 9, "stderr": 2},
                "eof": {"stdout": True, "stderr": True}, "returnCode": 3,
                "complete": True, "overflow": False, "timeout": False, "readError": False, **changes}

    def call(self, root, capture):
        return retention.retain_observation_capture(root, label="ssh-channel-status", capture=capture,
                                                    source_fingerprint="a" * 64)

    def test_partial_overflow_and_missing_terminal_are_truthfully_retained(self):
        for capture in (self.capture(returnCode=None, complete=False, timeout=True,
                                     eof={"stdout": False, "stderr": True}),
                        self.capture(complete=False, overflow=True, counts={"stdout": 100000, "stderr": 2}),
                        self.capture(complete=False, readError=True)):
            with self.subTest(capture=capture), tempfile.TemporaryDirectory() as root:
                value = self.call(root, capture)
                for key in ("counts", "eof", "returnCode", "complete", "overflow", "timeout", "readError"):
                    self.assertEqual(value[key], capture[key])
                self.assertNotIn("PRIVATE", str(value))
                self.assertNotIn("tests", value)
                capsule = Path(root) / ".rag_index" / "observation-runs" / value["runId"]
                self.assertEqual((capsule / "stdout.private").read_bytes(), capture["stdout"])
                self.assertEqual((capsule / "stderr.private").read_bytes(), capture["stderr"])

    def test_invalid_closed_capture_shapes_refuse_before_filesystem_work(self):
        bad = [{"complete": 1}, {"stdout": "private"}, {"returnCode": True}, {"pid": True},
               {"counts": {"stdout": 1, "stderr": 2}}, {"counts": {"stdout": 100, "stderr": 2}},
               {"eof": {"stdout": True}}, {"eof": {"stdout": False, "stderr": True}},
               {"private": "sentinel"}, {"timeout": True}]
        for change in bad:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as root:
                with self.assertRaisesRegex(retention.RetentionError, "input"):
                    self.call(root, self.capture(**change))
                self.assertEqual(list(Path(root).iterdir()), [])


    def test_observation_namespace_symlink_is_not_followed_or_chmodded(self):
        with tempfile.TemporaryDirectory() as root:
            index = Path(root) / ".rag_index"
            index.mkdir(mode=0o700)
            foreign = Path(root) / "foreign"
            foreign.mkdir(mode=0o755)
            foreign.chmod(0o755)
            (index / "observation-runs").symlink_to(foreign)
            with self.assertRaises(OSError):
                self.call(root, self.capture())
            self.assertEqual(stat.S_IMODE(foreign.stat().st_mode), 0o755)
            self.assertEqual(list(foreign.iterdir()), [])

    def test_observation_late_raw_replacement_refuses_original_receipt(self):
        with tempfile.TemporaryDirectory() as root:
            real_sync = os.fsync
            changed = False
            def sync(fd):
                nonlocal changed
                real_sync(fd)
                base = Path(root) / ".rag_index" / "observation-runs"
                if changed or not base.exists() or stat.S_ISREG(os.fstat(fd).st_mode):
                    return
                capsules = list(base.iterdir())
                if capsules and (capsules[0] / "receipt.json").exists():
                    changed = True
                    raw = capsules[0] / "stdout.private"
                    raw.unlink()
                    raw.write_bytes(self.capture()["stdout"])
            with mock.patch.object(os, "fsync", side_effect=sync):
                with self.assertRaisesRegex(retention.RetentionError, "raw_changed"):
                    self.call(root, self.capture())
            self.assertTrue(changed)


if __name__ == "__main__":
    unittest.main()

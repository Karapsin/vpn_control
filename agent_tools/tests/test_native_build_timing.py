"""Actual timing receipt path races; no native or product authority."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_tools import native_build_timing as timing


@unittest.skipUnless(hasattr(os, "getuid") and hasattr(os, "O_NOFOLLOW"), "POSIX private descriptor reader")
class NativeBuildTimingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.directory = self.root / ".rag_index" / "build-timings"
        self.directory.mkdir(parents=True)
        self.directory.parent.chmod(0o700)
        self.directory.chmod(0o700)
        self.path = self.directory / "gradle.json"
        self.record = {"schemaVersion": 1, "sourceSha": "a" * 40, "pipelineId": "linux-rpm",
                       "runId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "hostAlias": "archlinux",
                       "phase": "gradle", "startedMonotonicNs": 100, "finishedMonotonicNs": 1000100}
        self.raw = json.dumps(self.record).encode()
        self.path.write_bytes(self.raw)
        self.path.chmod(0o600)
        self.request = {k: self.record[k] for k in ("sourceSha", "pipelineId", "runId")}
        self.request["receipts"] = [{"path": ".rag_index/build-timings/gradle.json",
                                      "sha256": hashlib.sha256(self.raw).hexdigest()}]

    def report(self):
        return timing.report(self.root, self.record["sourceSha"], self.request)

    def after_read(self, mutation):
        original = os.fdopen
        class Stream:
            def __init__(inner, fd, mode):
                inner.real = original(fd, mode)
            def __enter__(inner):
                inner.real.__enter__()
                return inner
            def __exit__(inner, *args):
                return inner.real.__exit__(*args)
            def fileno(inner):
                return inner.real.fileno()
            def read(inner, limit):
                raw = inner.real.read(limit)
                mutation()
                return raw
        with patch.object(timing.os, "fdopen", Stream):
            with self.assertRaises(ValueError):
                self.report()

    def test_named_receipt_symlink_after_read(self):
        def mutate():
            self.path.unlink()
            self.path.symlink_to("/dev/null")
        self.after_read(mutate)

    def test_actual_last_parent_stat_unlink_refuses(self):
        original = os.stat
        observations = []
        changed = []
        def unlink_after_parent_observation(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if path == "build-timings" and kwargs.get("dir_fd") is not None:
                observations.append(True)
                if len(observations) == 2:
                    self.path.unlink()
                    changed.append(True)
            return result
        with patch.object(os, "stat", side_effect=unlink_after_parent_observation):
            with self.assertRaises(ValueError):
                self.report()
        self.assertEqual([True], changed)
        self.assertFalse(self.path.exists())

    def test_named_same_bytes_exchange_after_read(self):
        def mutate():
            replacement = self.directory / "replacement.json"
            replacement.write_bytes(self.raw)
            replacement.chmod(0o600)
            replacement.replace(self.path)
        self.after_read(mutate)

    def test_parent_replacement_preserving_receipt_inode(self):
        original_inode = self.path.stat().st_ino
        def mutate():
            saved = self.directory.with_name("original")
            self.directory.rename(saved)
            self.directory.mkdir(mode=0o700)
            (saved / self.path.name).rename(self.path)
            self.assertEqual(original_inode, self.path.stat().st_ino)
        self.after_read(mutate)

    def test_root_replacement_preserving_child_directory(self):
        def mutate():
            saved = self.root.with_name(self.root.name + "-original")
            self.root.rename(saved)
            self.addCleanup(lambda: saved.rmdir())
            self.root.mkdir(mode=0o700)
            (saved / ".rag_index").rename(self.root / ".rag_index")
        self.after_read(mutate)

    def test_parent_mode_drift_after_read(self):
        self.after_read(lambda: self.directory.chmod(0o755))

    def test_foreign_receipt_owner_is_refused(self):
        with patch.object(timing.os, "getuid", return_value=os.getuid() + 1):
            with self.assertRaises(ValueError):
                self.report()

    def test_content_mode_and_link_drift_after_read(self):
        for kind in ("content", "mode", "link"):
            with self.subTest(kind=kind):
                if kind == "content":
                    mutate = lambda: self.path.write_bytes(self.raw + b" ")
                elif kind == "mode":
                    mutate = lambda: self.path.chmod(0o644)
                else:
                    mutate = lambda: os.link(self.path, self.directory / "other.json")
                self.after_read(mutate)
                self.path.write_bytes(self.raw)
                self.path.chmod(0o600)

    def test_same_bytes_mtime_restored_detects_ctime(self):
        before = self.path.stat()
        def mutate():
            self.path.write_bytes(self.raw)
            os.utime(self.path, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.after_read(mutate)

    def test_unrelated_sibling_directory_does_not_invalidate_receipt(self):
        original = os.fdopen
        sibling = self.root / "unrelated-private-sibling"
        class Stream:
            def __init__(inner, fd, mode):
                inner.real = original(fd, mode)
            def __enter__(inner):
                inner.real.__enter__()
                return inner
            def __exit__(inner, *args):
                return inner.real.__exit__(*args)
            def fileno(inner):
                return inner.real.fileno()
            def read(inner, limit):
                raw = inner.real.read(limit)
                sibling.mkdir(mode=0o700)
                return raw
        before = self.root.stat()
        with patch.object(timing.os, "fdopen", Stream):
            result = self.report()
        self.assertEqual(1.0, result["totalMeasuredMs"])
        self.assertEqual(before.st_ino, self.root.stat().st_ino)
        self.assertTrue(sibling.is_dir())
        self.assertEqual(self.raw, self.path.read_bytes())
        self.assertFalse(result["nativeActionAllowed"])

    def test_clean_report_missing_phases_and_no_native_authority(self):
        result = self.report()
        self.assertEqual(1.0, result["totalMeasuredMs"])
        self.assertEqual("gradle", result["largestMeasuredPhase"])
        self.assertEqual(4, sum(p["state"] == "unmeasured" for p in result["phases"]))
        self.assertFalse(result["allPhasesMeasured"])
        self.assertFalse(result["nativeActionAllowed"])
        self.assertFalse(result["productAction"])
        self.assertEqual(self.raw, self.path.read_bytes())

    def test_initial_nonprivate_or_linked_receipt_is_refused(self):
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):
            self.report()
        self.path.chmod(0o600)
        os.link(self.path, self.directory / "other.json")
        with self.assertRaises(ValueError):
            self.report()

    def test_schema_owner_and_bounded_bytes_remain_required(self):
        for record in ({**self.record, "schemaVersion": True},
                       {**self.record, "finishedMonotonicNs": False},
                       {**self.record, "runId": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}):
            raw = json.dumps(record).encode()
            self.path.write_bytes(raw)
            self.request["receipts"][0]["sha256"] = hashlib.sha256(raw).hexdigest()
            with self.assertRaises(ValueError):
                self.report()
        self.path.write_bytes(b" " * 4097)
        self.request["receipts"][0]["sha256"] = hashlib.sha256(self.path.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):
            self.report()

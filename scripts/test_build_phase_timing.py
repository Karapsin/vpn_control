import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import subprocess

from build_phase_timing import PhaseRecorder
import build_phase_timing
from agent_tools import native_build_timing


class PhaseRecorderTest(unittest.TestCase):
    def recorder(self, root):
        return PhaseRecorder(root / ".rag_index/build-timings", "a" * 40,
                             "linux-fixture", "12345678-1234-4234-9234-123456789abc",
                             "fedora-builder")

    def test_windows_absent_posix_apis_still_publishes_acl_guarded_receipt(self):
        import prepare_desktop_update_fixture as fixture
        class WindowsOs:
            def __getattr__(self, name):
                if name in {"getuid", "geteuid", "O_DIRECTORY", "O_NOFOLLOW"}:
                    raise AttributeError(name)
                return getattr(os, name)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            recorder = self.recorder(root)
            with mock.patch.object(fixture, "os", WindowsOs()), \
                 mock.patch.object(fixture.platform, "system", return_value="Windows"), \
                 mock.patch.object(fixture, "require_windows_private_acl") as acl:
                reference = recorder.finish("gradle", "base", recorder.start())
            receipt = root / reference["path"]
            self.assertEqual(hashlib.sha256(receipt.read_bytes()).hexdigest(), reference["sha256"])
            self.assertEqual({root / ".rag_index", root / ".rag_index/build-timings", receipt},
                             {call.args[0] for call in acl.call_args_list})
            self.assertTrue(all(call.kwargs["private"] for call in acl.call_args_list))

    def test_windows_rejects_unsafe_acl_before_receipt_publication(self):
        import prepare_desktop_update_fixture as fixture
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            recorder = self.recorder(root)
            with mock.patch.object(fixture.platform, "system", return_value="Windows"), \
                 mock.patch.object(fixture, "require_windows_private_acl", side_effect=ValueError("unsafe ACL")):
                with self.assertRaisesRegex(ValueError, "unsafe ACL"):
                    recorder.finish("gradle", "base", recorder.start())
            self.assertFalse(list((root / ".rag_index").glob("**/*.json")))
            self.assertEqual([], recorder.references)

    @unittest.skipIf(os.name == "nt", "POSIX mode assertions are covered on POSIX hosts")
    def test_private_source_bound_monotonic_receipt_matches_report_schema(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            recorder = self.recorder(root)
            with mock.patch("prepare_desktop_update_fixture.time.monotonic_ns", return_value=2_000_000_000):
                reference = recorder.finish("gradle", "base", 1_000_000_000)
            path = root / reference["path"]
            self.assertEqual(0o700, path.parent.stat().st_mode & 0o777)
            self.assertEqual(0o700, path.parent.parent.stat().st_mode & 0o777)
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            raw = path.read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), reference["sha256"])
            self.assertEqual({"schemaVersion", "sourceSha", "pipelineId", "runId",
                              "hostAlias", "phase", "startedMonotonicNs",
                              "finishedMonotonicNs"}, set(json.loads(raw)))
            self.assertNotIn(b"command", raw)
            self.assertNotIn(b"secret", raw)
            report = native_build_timing.report(root, "a" * 40, {
                "sourceSha": "a" * 40, "pipelineId": "linux-fixture",
                "runId": "12345678-1234-4234-9234-123456789abc",
                "receipts": [reference]})
            self.assertEqual("gradle", report["largestMeasuredPhase"])
            self.assertFalse(report["allPhasesMeasured"])
            with mock.patch("prepare_desktop_update_fixture.time.monotonic_ns", return_value=2_000_000_000):
                with self.assertRaises(FileExistsError):
                    recorder.finish("gradle", "base", 1_000_000_000)
            self.assertEqual(1, len(recorder.references))

    @unittest.skipIf(os.name == "nt", "POSIX mode rejection is covered on POSIX hosts")
    def test_rejects_unsafe_directory_or_non_monotonic_phase(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            recorder = self.recorder(root)
            with mock.patch("prepare_desktop_update_fixture.time.monotonic_ns", return_value=100):
                for phase, start in (("bad", 1), ("gradle", 101), ("gradle", -1)):
                    with self.subTest(phase=phase, start=start), self.assertRaises(ValueError):
                        recorder.finish(phase, "base", start)
            private = root / ".rag_index"
            private.mkdir(mode=0o755)
            with mock.patch("prepare_desktop_update_fixture.time.monotonic_ns", return_value=200):
                with self.assertRaisesRegex(ValueError, "directory unsafe"):
                    recorder.finish("gradle", "base", 100)
            self.assertFalse((private / "build-timings").exists())

    @unittest.skipIf(os.name == "nt", "POSIX receipt publication is covered on POSIX hosts")
    def test_equal_clock_ticks_record_minimum_positive_duration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            recorder = self.recorder(root)
            with mock.patch("prepare_desktop_update_fixture.time.monotonic_ns", return_value=100):
                reference = recorder.finish("gradle", "base", recorder.start())
            record = json.loads((root / reference["path"]).read_text())
            self.assertEqual(100, record["startedMonotonicNs"])
            self.assertEqual(101, record["finishedMonotonicNs"])
            self.assertEqual(1, record["finishedMonotonicNs"] - record["startedMonotonicNs"])

    def test_invalid_source_and_identity_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / ".rag_index/build-timings"
            for source, pipeline, run in (("wrong", "linux-fixture", "12345678-1234-4234-9234-123456789abc"),
                                          ("a" * 40, "../../other", "12345678-1234-4234-9234-123456789abc"),
                                          ("a" * 40, "linux-fixture", "not-a-uuid")):
                with self.subTest(source=source, pipeline=pipeline, run=run), self.assertRaises(ValueError):
                    PhaseRecorder(directory, source, pipeline, run, "fedora-builder")

    @unittest.skipIf(os.name == "nt", "POSIX receipt publication is covered on POSIX hosts")
    def test_external_upload_phase_wraps_exact_command_and_only_success_emits(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = ["--directory", str(root / ".rag_index/build-timings"),
                    "--source-sha", "a" * 40, "--pipeline-id", "linux-fixture",
                    "--run-id", "12345678-1234-4234-9234-123456789abc",
                    "--host-alias", "linux-builder", "--phase", "upload",
                    "--sample", "target", "--", "transfer", "private-argument"]
            with mock.patch.object(build_phase_timing.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)) as run:
                self.assertEqual(1, build_phase_timing.main(args))
            run.assert_called_once_with(["transfer", "private-argument"], check=False)
            self.assertFalse((root / ".rag_index").exists())
            with mock.patch.object(build_phase_timing.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)), \
                 mock.patch("prepare_desktop_update_fixture.time.monotonic_ns", side_effect=[100, 200]), \
                 mock.patch("sys.stderr"):
                self.assertEqual(0, build_phase_timing.main(args))
            receipt = next((root / ".rag_index/build-timings").glob("*.json"))
            self.assertEqual("upload", json.loads(receipt.read_text())["phase"])
            self.assertNotIn("private-argument", receipt.read_text())


if __name__ == "__main__":
    unittest.main()

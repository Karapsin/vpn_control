"""Causal tests for protected worker transitions and bound rollback receipt."""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from agent_tools import macos_machine_evidence as subject
from agent_tools.macos_machine_receipts import MacReceiptError, ReceiptBinding


SOURCE = "a" * 40
CORR = "11111111-1111-4111-8111-111111111111"
JOB = "22222222-2222-4222-8222-222222222222"
OP = "33333333-3333-4333-8333-333333333333"
BOOT = "44444444-4444-4444-8444-444444444444"
BASE = (1, 3, "b" * 64)
CANDIDATE = (1, 4, "c" * 64)


def worker_events():
    names = ("base-observed", "candidate-armed", "base-moved-to-backup",
             "candidate-move-failed", "base-restored")
    return [{"jobId": JOB, "sequence": index, "type": name,
             "observedAtUnixMs": 100 + index, "device": identity[0],
             "inode": identity[1], "sha256": identity[2]}
            for index, (name, identity) in enumerate(zip(names,
                (BASE, CANDIDATE, BASE, CANDIDATE, BASE)))]


def binding():
    return ReceiptBinding(SOURCE, CORR, "rollback", JOB, OP, BOOT,
                          "env-owned123", "sha256-" + "d" * 64)


class MacMachineEvidenceTest(unittest.TestCase):
    def test_executable_protected_worker_reader_rejects_symlink_and_hardlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            parent = root / JOB
            parent.mkdir(mode=0o700)
            path = parent / "acceptance-events.jsonl"
            path.write_text("".join(json.dumps(event) + "\n" for event in worker_events()))
            path.chmod(0o600)
            code = subject._WORKER_READ.replace(
                "path=pathlib.Path('/Library/Application Support/vpn-control-install-jobs')/job/'acceptance-events.jsonl'",
                f"path=pathlib.Path({str(root)!r})/job/'acceptance-events.jsonl'")
            code = code.replace("info.st_uid!=0", f"info.st_uid not in (0,{os.getuid()})")
            code = code.replace("before.st_uid!=0", f"before.st_uid!={os.getuid()}")
            code = code.replace("info.st_mode&0o022", "False")
            args = ["python3", "-c", code, JOB]
            self.assertEqual(0, subprocess.run(args, capture_output=True).returncode)
            duplicate = parent / "duplicate.jsonl"; os.link(path, duplicate)
            self.assertNotEqual(0, subprocess.run(args, capture_output=True).returncode)
            duplicate.unlink(); path.rename(duplicate); path.symlink_to(duplicate)
            self.assertNotEqual(0, subprocess.run(args, capture_output=True).returncode)

    def test_historical_unknown_needs_reviewed_exact_file_baseline(self):
        observed = {"jobId": subject.LEGACY_JOB_ID, "protectedReceiptAbsent": True,
                    "package": {"device": 1, "inode": 2, "mode": 384, "size": 123,
                                "sha256": "a" * 64},
                    "worker": {"device": 1, "inode": 3, "mode": 448, "size": 456,
                               "sha256": "b" * 64}}
        self.assertFalse(subject.legacy_unknown_preserved(observed, None))
        baseline = {**deepcopy(observed), "reviewed": True}
        self.assertTrue(subject.legacy_unknown_preserved(observed, baseline))
        for changed in ({"protectedReceiptAbsent": False},
                        {"package": {**observed["package"], "inode": 4}},
                        {"worker": {**observed["worker"], "sha256": "c" * 64}}):
            with self.subTest(changed=changed):
                self.assertFalse(subject.legacy_unknown_preserved({**observed, **changed}, baseline))

    def test_protected_reader_uses_fixed_root_job_and_rejects_missing_or_malformed(self):
        calls = []
        def runner(argv, **_):
            calls.append(argv)
            output = [{"Name": "vpn-control-boot-control53", "Source": "local",
                       "Running": True, "State": "running"}] if argv[:2] == ["tart", "list"] else worker_events()
            return SimpleNamespace(returncode=0, stdout=json.dumps(output))
        self.assertEqual(5, len(subject.read_worker_events(JOB, runner=runner)))
        self.assertEqual(["tart", "exec", "vpn-control-boot-control53", "/usr/bin/sudo", "-n",
                          "/usr/bin/python3", "-c"], calls[1][:7])
        self.assertEqual(JOB, calls[1][-1])
        with self.assertRaises(MacReceiptError):
            subject.read_worker_events("../../etc/passwd", runner=runner)
        self.assertEqual(2, len(calls))

    def test_worker_transition_wrong_job_order_or_identity_rejects(self):
        subject.verify_worker_events(worker_events(), job_id=JOB, base=BASE, candidate=CANDIDATE)
        for index, field, value in ((0, "jobId", CORR), (1, "type", "candidate-ready"),
                                    (2, "inode", 99), (3, "sha256", "e" * 64),
                                    (4, "observedAtUnixMs", 102)):
            changed = deepcopy(worker_events()); changed[index][field] = value
            with self.subTest(index=index, field=field), self.assertRaises(MacReceiptError):
                subject.verify_worker_events(changed, job_id=JOB, base=BASE, candidate=CANDIDATE)
        with self.assertRaises(MacReceiptError):
            subject.verify_worker_events(worker_events()[:-1], job_id=JOB, base=BASE,
                                         candidate=CANDIDATE)

    def test_rollback_composition_requires_terminal_cleanup_and_binding(self):
        receipt = subject.compose_rollback_trace(binding(), worker_events(), base=BASE,
            candidate=CANDIDATE, cleanup_at_unix_ms=105,
            protected_code="PERSISTENCE_FAILED", public_code="PERSISTENCE_FAILED",
            fresh_stage_absent=True, fresh_backup_absent=True)
        self.assertEqual("rollback-trace", receipt["kind"])
        self.assertEqual([0, 1, 2, 3, 4, 5], [row["sequence"] for row in receipt["events"]])
        for changed in ({"cleanup_at_unix_ms": 104}, {"protected_code": "OK"},
                        {"public_code": "OK"}, {"fresh_stage_absent": False},
                        {"fresh_backup_absent": False}):
            options = {"base": BASE, "candidate": CANDIDATE, "cleanup_at_unix_ms": 105,
                       "protected_code": "PERSISTENCE_FAILED", "public_code": "PERSISTENCE_FAILED",
                       "fresh_stage_absent": True, "fresh_backup_absent": True, **changed}
            with self.subTest(changed=changed), self.assertRaises(MacReceiptError):
                subject.compose_rollback_trace(binding(), worker_events(), **options)


if __name__ == "__main__":
    unittest.main()

"""Causal validation of proposed Mac server-stop and rollback trace receipts."""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from agent_tools import macos_machine_receipts as subject


SOURCE = "a" * 40
CORRELATION = "11111111-1111-4111-8111-111111111111"
JOB = "22222222-2222-4222-8222-222222222222"
OPERATION = "33333333-3333-4333-8333-333333333333"
BOOT = "44444444-4444-4444-8444-444444444444"
INSTANCE = "55555555-5555-4555-8555-555555555555"
ARTIFACT = "sha256-" + "b" * 64
BASE = "c" * 64
READY = "d" * 64


def binding(scenario="rollback"):
    return subject.ReceiptBinding(SOURCE, CORRELATION, scenario, JOB, OPERATION,
                                  BOOT, "env-owned123", ARTIFACT)


def common(kind, scenario="rollback"):
    return {"schemaVersion": 1, "kind": kind, "sourceSha": SOURCE,
            "correlationId": CORRELATION, "scenario": scenario, "jobId": JOB,
            "operationId": OPERATION, "bootSessionUuid": BOOT,
            "reservationId": "env-owned123", "fixtureReceiptArtifactId": ARTIFACT}


def server():
    return {**common("server-stop"), "serverInstanceId": INSTANCE, "serverPid": 123,
            "serverProcessStartIdentity": "darwin:100:200", "readySha256": READY,
            "stopRequestCount": 1, "serverExitCode": 0, "stopReceiptFinal": True}


def trace():
    names = ("base-observed", "candidate-armed", "base-moved-to-backup",
             "candidate-move-failed", "base-restored", "candidate-cleaned")
    events = [{"sequence": index, "type": name, "observedAtUnixMs": index + 100,
               "device": 1 if index in (0, 2, 4) else 2,
               "inode": 3 if index in (0, 2, 4) else 11,
               "sha256": BASE if index in (0, 2, 4) else "e" * 64}
              for index, name in enumerate(names)]
    return {**common("rollback-trace"), "events": events, "finalBaseDevice": 1,
            "finalBaseInode": 3, "finalBaseJarSha256": BASE}


class MacMachineReceiptsTest(unittest.TestCase):
    def test_guest_reader_rejects_hardlink_and_post_read_mode_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            parent = root / "state" / "acceptance-evidence" / CORRELATION
            parent.mkdir(parents=True, mode=0o700)
            path = parent / "server-stop.json"
            path.write_text(json.dumps(server()))
            path.chmod(0o600)
            code = subject._GUEST_READ.replace(
                "root=pathlib.Path('/Users/admin/macos-parity'+source[:7])",
                f"root=pathlib.Path({str(root)!r})").replace("501", str(os.getuid()))
            # The host temp path has unrelated ancestors; retain the exact
            # receipt-file checks while adapting only its fixed guest root.
            code = code.replace("index>=3", "index>=999")
            args = ["python3", "-c", code, SOURCE, CORRELATION, "server-stop"]
            self.assertEqual(subprocess.run(args, capture_output=True).returncode, 0)
            link = parent / "duplicate.json"
            os.link(path, link)
            self.assertNotEqual(subprocess.run(args, capture_output=True).returncode, 0)
            link.unlink()
            tamper = code.replace("raw=os.read(fd,16385)", "raw=os.read(fd,16385);os.chmod(path,0o644)")
            self.assertNotEqual(subprocess.run(
                ["python3", "-c", tamper, SOURCE, CORRELATION, "server-stop"],
                capture_output=True).returncode, 0)

    def test_fixed_guest_collector_accepts_only_source_correlation_and_kind(self):
        calls = []
        def runner(argv, **_):
            calls.append(argv)
            output = [{"Name": "vpn-control-boot-control53", "Source": "local",
                       "Running": True, "State": "running"}] if argv[:2] == ["tart", "list"] else server()
            return SimpleNamespace(returncode=0, stdout=json.dumps(output))
        value = subject.read_guest_candidate(SOURCE, CORRELATION, "server-stop", runner=runner)
        self.assertEqual(value["serverInstanceId"], INSTANCE)
        self.assertEqual(calls[1][:5], ["tart", "exec", "vpn-control-boot-control53",
                                         "/usr/bin/python3", "-c"])
        self.assertEqual(calls[1][-3:], [SOURCE, CORRELATION, "server-stop"])
        self.assertIn("dir_fd=parent", calls[1][5])
        self.assertIn("O_NOFOLLOW", calls[1][5])
        self.assertIn("before.st_nlink!=1", calls[1][5])
        self.assertIn("after.st_uid,after.st_mode,after.st_nlink", calls[1][5])
        with self.assertRaises(subject.MacReceiptError):
            subject.read_guest_candidate(SOURCE, CORRELATION, "../../secret", runner=runner)
        self.assertEqual(len(calls), 2)

    def verify_server(self, value, **changes):
        args = {"expected_instance_id": INSTANCE, "expected_pid": 123,
                "expected_start": "darwin:100:200", "expected_ready_sha256": READY,
                "fresh_pid_generation_absent": True, "fresh_listener_absent": True}
        args.update(changes)
        subject.validate_server_stop(value, binding(), **args)

    def verify_trace(self, value, **changes):
        args = {"base_device": 1, "base_inode": 3, "base_jar_sha256": BASE,
                "candidate_device": 2, "candidate_inode": 11,
                "candidate_jar_sha256": "e" * 64,
                "protected_code": "PERSISTENCE_FAILED", "public_code": "PERSISTENCE_FAILED",
                "fresh_stage_absent": True, "fresh_backup_absent": True}
        args.update(changes)
        subject.validate_rollback_trace(value, binding(), **args)

    def test_server_stop_needs_exact_source_generation_and_fresh_kernel_absence(self):
        value = server()
        self.verify_server(value)
        for field, wrong in (("sourceSha", "f" * 40), ("correlationId", JOB),
                             ("jobId", CORRELATION), ("serverInstanceId", JOB),
                             ("serverPid", 456), ("readySha256", "f" * 64),
                             ("stopRequestCount", 2), ("stopRequestCount", True),
                             ("serverExitCode", 7), ("stopReceiptFinal", False),
                             ("schemaVersion", True)):
            changed = {**value, field: wrong}
            with self.subTest(field=field), self.assertRaises(subject.MacReceiptError):
                self.verify_server(changed)
        changed = {**value, "serverPid": True}
        with self.assertRaises(subject.MacReceiptError):
            self.verify_server(changed, expected_pid=1)
        for flag in ("fresh_pid_generation_absent", "fresh_listener_absent"):
            with self.subTest(flag=flag), self.assertRaisesRegex(subject.MacReceiptError, "unproven"):
                self.verify_server(value, **{flag: False})

    def test_rollback_trace_needs_ordered_move_fault_restore_and_exact_base(self):
        value = trace()
        self.verify_trace(value)
        changed = deepcopy(value); changed["events"][3]["type"] = "candidate-moved"
        with self.assertRaisesRegex(subject.MacReceiptError, "order"):
            self.verify_trace(changed)
        changed = deepcopy(value); changed["events"][4]["inode"] = 44
        with self.assertRaisesRegex(subject.MacReceiptError, "exact base and candidate"):
            self.verify_trace(changed)
        for index in (1, 3, 5):
            changed = deepcopy(value); changed["events"][index]["inode"] += 1
            with self.subTest(index=index), self.assertRaisesRegex(subject.MacReceiptError, "candidate identities"):
                self.verify_trace(changed)
        for changes in ({"protected_code": "OK"}, {"public_code": "OK"},
                        {"fresh_stage_absent": False}, {"fresh_backup_absent": False}):
            with self.assertRaisesRegex(subject.MacReceiptError, "unproven"):
                self.verify_trace(value, **changes)
        changed = {**value, "sourceSha": "f" * 40}
        with self.assertRaisesRegex(subject.MacReceiptError, "binding"):
            self.verify_trace(changed)
        for field in ("schemaVersion", "finalBaseDevice", "finalBaseInode"):
            changed = deepcopy(value)
            changed[field] = True
            if field == "finalBaseInode":
                for index in (0, 2, 4):
                    changed["events"][index]["inode"] = 1
            with self.subTest(field=field), self.assertRaises(subject.MacReceiptError):
                self.verify_trace(changed, base_inode=1 if field == "finalBaseInode" else 3)


if __name__ == "__main__":
    unittest.main()

import json
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from agent_tools import linux_rpm_protected_job_observe as observer


JOB = "12345678-1234-1234-1234-123456789abc"


class LinuxProtectedJobObserveTest(unittest.TestCase):
    def scan(self, root):
        namespace = {}
        exec(observer._COMMON, namespace)
        return namespace["scan"](str(root), os.getuid())

    def test_non_directory_entry_explains_protected_job_unsafe_without_opening_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "protected"
            root.mkdir(mode=0o700)
            (root / "stale.lock").write_text("must not read")
            value = self.scan(root)
        self.assertEqual("unknown", value["state"])
        self.assertEqual("unsafe-entry", value["rootState"])
        self.assertEqual(1, value["entryCount"])
        self.assertEqual("regular", value["entries"][0]["kind"])
        self.assertNotIn("stale.lock", json.dumps(value))
        self.assertEqual(16, len(value["entries"][0]["nameHash"]))

    def test_canonical_protected_job_reports_bounded_terminal_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "protected"
            root.mkdir(mode=0o700)
            job = root / JOB
            job.mkdir(mode=0o700)
            (job / "status.json").write_text(json.dumps({"version": 1, "jobId": JOB,
                                                            "sequence": 1, "phase": "CANCELLED", "code": "CANCELLED"}))
            value = self.scan(root)
        self.assertEqual("observed", value["state"])
        self.assertEqual("readable", value["rootState"])
        self.assertEqual(JOB, value["entries"][0]["jobId"])
        self.assertEqual("CANCELLED", value["entries"][0]["phase"])
        self.assertEqual("terminal", value["entries"][0]["receiptState"])

    def test_symlink_or_mismatched_receipt_never_becomes_terminal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "protected"
            root.mkdir(mode=0o700)
            job = root / JOB
            job.mkdir(mode=0o700)
            (job / "status.json").write_text(json.dumps({"version": 1, "jobId": "other", "phase": "SUCCEEDED"}))
            first = self.scan(root)
            (job / "status.json").unlink()
            (job / "status.json").symlink_to(root / "outside")
            second = self.scan(root)
        self.assertEqual("unknown", first["state"])
        self.assertEqual("unknown", second["state"])
        self.assertNotEqual("terminal", first["entries"][0]["receiptState"])
        self.assertNotEqual("terminal", second["entries"][0]["receiptState"])

    def test_route_requires_exact_owned_fedora_and_privileged_fixed_program(self):
        config = mock.Mock(hosts={"fedora2328": mock.Mock(user="vpnfixture")})
        driver = mock.Mock()
        driver._remote.return_value = {"state": "unknown", "rootState": "unsafe-entry",
                                       "entryCount": 1, "entries": [{"kind": "regular", "nameHash": "0" * 16}],
                                       "truncated": False, "observerUid": 0}
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(observer.ssh_transport, "load_config", return_value=config), \
             mock.patch.object(observer, "_driver", return_value=driver):
            result = observer.observe(Path(temporary), {"host": "fedora2328", "environment": "fedora2328"})
            self.assertEqual("unknown", result["state"])
            self.assertEqual("regular", result["entries"][0]["kind"])
            self.assertFalse(result["admissionReady"])
            with self.assertRaises(ValueError):
                observer.observe(Path(temporary), {"host": "fedora2328", "environment": "fedora2328", "command": "ls"})
        self.assertEqual(1, driver._remote.call_count)
        args, kwargs = driver._remote.call_args
        self.assertEqual("fedora2328", args[1])
        self.assertEqual(observer._PROGRAM, args[2])
        self.assertEqual((), args[3])
        self.assertTrue(kwargs["privileged"])

    def test_fixed_guard_files_are_identified_without_exposing_contents(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "protected"
            root.mkdir(mode=0o700)
            (root / "reservation-linux").write_bytes(b"")
            (root / "gate-linux").write_bytes(bytes(17))
            value = self.scan(root)
        self.assertEqual("observed", value["state"])
        self.assertEqual("readable", value["rootState"])
        self.assertEqual({"gate-linux", "reservation-linux"},
                         {row["guardName"] for row in value["entries"]})
        self.assertFalse(value.get("admissionReady", False))

    def test_unsafe_guard_and_untrusted_receipt_are_unknown(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "protected"
            root.mkdir(mode=0o700)
            (root / "gate-linux").symlink_to(root / "missing")
            first = self.scan(root)
            (root / "gate-linux").unlink()
            (root / "gate-linux").write_bytes(b"bad")
            second = self.scan(root)
            job = root / JOB
            job.mkdir(mode=0o700)
            (job / "status.json").write_text(json.dumps({"version": 1, "jobId": JOB,
                                                            "phase": "SUCCEEDED", "code": "OK"}))
            third = self.scan(root)
            (job / "status.json").write_text(json.dumps({"version": 1, "jobId": JOB,
                                                            "sequence": 2, "phase": "SUCCEEDED", "code": "RUNTIME_FAILED"}))
            fourth = self.scan(root)
            (job / "status.json").write_text(json.dumps({"version": 1, "jobId": JOB,
                                                            "sequence": 2, "phase": "MADE_UP", "code": "OK"}))
            fifth = self.scan(root)
        self.assertEqual("unknown", first["state"])
        self.assertEqual("unknown", second["state"])
        for value in (third, fourth, fifth):
            self.assertEqual("unknown", value["state"])
            self.assertEqual("untrusted", next(row for row in value["entries"] if row.get("jobId") == JOB)["receiptState"])

    def test_root_fd_identity_and_child_mount_boundary_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "protected"
            root.mkdir(mode=0o700)
            alternate = Path(temporary) / "alternate"
            alternate.mkdir(mode=0o700)
            namespace = {}
            exec(observer._COMMON, namespace)
            namespace["open_root"] = lambda path: os.open(alternate, os.O_RDONLY | os.O_DIRECTORY)
            swapped = namespace["scan"](str(root), os.getuid())
            self.assertEqual("unknown", swapped["state"])
            self.assertEqual("changed", swapped["rootState"])
            job = root / JOB
            job.mkdir(mode=0o700)
            namespace = {}
            exec(observer._COMMON, namespace)
            namespace["mounted_at"] = lambda path: path == str(job)
            mounted = namespace["scan"](str(root), os.getuid())
            self.assertEqual("unknown", mounted["state"])
            self.assertEqual("unsafe-entry", mounted["rootState"])

    def test_embedded_program_compiles_and_guard_claim_is_validated(self):
        compile(observer._PROGRAM, "<protected-observer>", "exec")
        raw = {"state": "observed", "rootState": "readable", "entryCount": 1,
               "entries": [{"nameHash": "0" * 16, "kind": "symlink", "guardName": "gate-linux",
                            "guardState": "trusted"}], "truncated": False, "observerUid": 0}
        self.assertEqual("unknown", observer._validated(raw)["state"])

    def test_failed_receipt_rejects_nonfailure_or_unknown_code(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "protected"
            root.mkdir(mode=0o700)
            job = root / JOB
            job.mkdir(mode=0o700)
            for code in ("CANCELLED", "ACCEPTED", "SOMETHING_NEW"):
                (job / "status.json").write_text(json.dumps({"version": 1, "jobId": JOB,
                                                                "sequence": 2, "phase": "FAILED", "code": code}))
                value = self.scan(root)
                self.assertEqual("unknown", value["state"], code)
                self.assertEqual("untrusted", value["entries"][0]["receiptState"], code)

    def test_status_leaf_mount_is_untrusted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "protected"
            root.mkdir(mode=0o700)
            job = root / JOB
            job.mkdir(mode=0o700)
            (job / "status.json").write_text(json.dumps({"version": 1, "jobId": JOB,
                                                            "sequence": 2, "phase": "SUCCEEDED", "code": "OK"}))
            namespace = {}
            exec(observer._COMMON, namespace)
            namespace["mounted_at"] = lambda path: path == str(job / "status.json")
            value = namespace["scan"](str(root), os.getuid())
        self.assertEqual("unknown", value["state"])
        self.assertEqual("untrusted", value["entries"][0]["receiptState"])

    def test_held_reservation_lock_is_visible_when_gate_is_clear(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "protected"
            root.mkdir(mode=0o700)
            (root / "reservation-linux").write_bytes(b"")
            (root / "gate-linux").write_bytes(bytes(17))
            namespace = {}
            exec(observer._COMMON, namespace)
            namespace["lock_held"] = lambda path, info: True
            value = namespace["scan"](str(root), os.getuid())
        self.assertEqual("observed", value["state"])
        self.assertTrue(next(row for row in value["entries"] if row.get("guardName") == "reservation-linux")["reservationLocked"])

    def test_bounded_proc_locks_parser_matches_exact_device_inode(self):
        namespace = {}
        exec(observer._COMMON, namespace)
        info = mock.Mock(st_dev=os.makedev(0, 0x50), st_ino=12345)
        row = b"1: FLOCK ADVISORY WRITE 320 00:50:12345 0 EOF\n"
        with mock.patch("builtins.open", return_value=io.BytesIO(row)):
            self.assertTrue(namespace["lock_held"](namespace["ROOT"], info))
        with mock.patch("builtins.open", return_value=io.BytesIO(row.replace(b":12345 ", b":12346 "))):
            self.assertFalse(namespace["lock_held"](namespace["ROOT"], info))
        with mock.patch("builtins.open", return_value=io.BytesIO(b"malformed\n")):
            with self.assertRaises(OSError):
                namespace["lock_held"](namespace["ROOT"], info)


if __name__ == "__main__":
    unittest.main()

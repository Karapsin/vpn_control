"""Regression tests for read-only SSH job observation."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1]


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, SOURCE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


transport = load("ssh_transport")
jobs = load("ssh_jobs")


class SshJobObservationTest(unittest.TestCase):
    def write_config(self, root: Path) -> None:
        path = root / ".vm-hosts.local.json"
        path.write_text(json.dumps({"schemaVersion": 1, "hosts": {
            "vm": {"host": "127.0.0.1", "port": 22, "user": "tester",
                   "identityFile": "/tmp/key", "knownHostsFile": "/tmp/known"},
        }}), encoding="utf-8")
        path.chmod(0o600)

    def identity(self, **changes):
        value = {"jobId": "job-17", "pid": 417, "startTicks": 9981,
                 "receiptPath": "/var/lib/vpn-control/jobs/job-17.json"}
        value.update(changes)
        return value

    def response(self, process="running", ticks=9981, receipt=None):
        if receipt is not None and "valid" not in receipt:
            receipt = {"valid": True, **receipt}
        return json.dumps({"process": {"state": process, "startTicks": ticks},
                           "receipt": receipt or {"present": False, "valid": True}}).encode()

    def test_pid_reuse_is_unknown_even_when_a_different_process_is_live(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.write_config(root)
            with mock.patch.object(jobs, "_run_probe", return_value=(0, self.response(ticks=9982))):
                result = jobs.observe(root, "vm", self.identity())
        self.assertEqual("unknown", result.status.value)
        self.assertEqual("pid_reused", result.reason)
        self.assertEqual(417, result.pid)
        self.assertEqual(9981, result.start_ticks)

    def test_malformed_or_wrong_receipt_cannot_claim_a_disappeared_process(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.write_config(root)
            malformed = self.response(process="missing", receipt={"present": True, "valid": False})
            with mock.patch.object(jobs, "_run_probe", return_value=(0, malformed)):
                malformed_result = jobs.observe(root, "vm", self.identity())
            wrong = self.response(process="missing", receipt={"present": True, "jobId": "other", "exitCode": 0})
            with mock.patch.object(jobs, "_run_probe", return_value=(0, wrong)):
                wrong_result = jobs.observe(root, "vm", self.identity())
        self.assertEqual("unknown", malformed_result.status.value)
        self.assertEqual("invalid_receipt", malformed_result.reason)
        self.assertEqual("unknown", wrong_result.status.value)
        self.assertEqual("receipt_job_mismatch", wrong_result.reason)

    def test_only_a_correlated_integer_exit_code_is_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.write_config(root)
            receipt = {"present": True, "jobId": "job-17", "exitCode": 23}
            with mock.patch.object(jobs, "_run_probe", return_value=(0, self.response(process="missing", receipt=receipt))):
                terminal = jobs.observe(root, "vm", self.identity())
            bad_exit = {"present": True, "jobId": "job-17", "exitCode": "23"}
            with mock.patch.object(jobs, "_run_probe", return_value=(0, self.response(process="missing", receipt=bad_exit))):
                unknown = jobs.observe(root, "vm", self.identity())
        self.assertEqual("terminal", terminal.status.value)
        self.assertEqual(23, terminal.exit_code)
        self.assertEqual("unknown", unknown.status.value)
        self.assertEqual("invalid_receipt", unknown.reason)

    def test_timeout_and_cancellation_remain_distinct_unknown_outcomes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.write_config(root)
            with mock.patch.object(jobs, "_run_probe", side_effect=jobs.ProbeTimeout()):
                timeout = jobs.observe(root, "vm", self.identity())
            with mock.patch.object(jobs, "_run_probe", return_value=(130, b"")):
                cancelled = jobs.observe(root, "vm", self.identity())
            with mock.patch.object(jobs, "_run_probe", return_value=(0, self.response(process="missing"))):
                disappeared = jobs.observe(root, "vm", self.identity())
        self.assertEqual(("unknown", "timeout"), (timeout.status.value, timeout.reason))
        self.assertEqual(("unknown", "observer_cancelled"), (cancelled.status.value, cancelled.reason))
        self.assertEqual(("unknown", "process_missing"), (disappeared.status.value, disappeared.reason))
        self.assertEqual(timeout.identity, cancelled.identity)

    def test_zombie_is_not_running(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.write_config(root)
            with mock.patch.object(jobs, "_run_probe", return_value=(0, self.response(process="zombie"))):
                result = jobs.observe(root, "vm", self.identity())
        self.assertEqual(("unknown", "zombie"), (result.status.value, result.reason))

    def test_identity_rejects_untrusted_remote_paths_and_missing_startticks(self):
        with self.assertRaisesRegex(jobs.SshJobError, "receipt path"):
            jobs.JobIdentity.from_mapping(self.identity(receiptPath="relative.json"))
        with self.assertRaisesRegex(jobs.SshJobError, "startTicks"):
            jobs.JobIdentity.from_mapping(self.identity(startTicks=0))


if __name__ == "__main__":
    unittest.main()

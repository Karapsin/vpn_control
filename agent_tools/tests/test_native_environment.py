from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock
import subprocess
import sys

from agent_tools import native_environment


class NativeEnvironmentTest(unittest.TestCase):
    def request(self, **changes):
        value = {"hostAlias": "mac-host", "environment": "windows-vm", "operator": "agent-a",
                 "requestedMemoryBytes": 8, "headroomBytes": 4,
                 "measurement": {"physicalMemoryBytes": 24, "runningConfiguredMemoryBytes": 0,
                                 "pressure": "normal", "swapUsedBytes": 0}}
        value.update(changes)
        return value

    def test_concurrent_same_target_has_one_owner_and_idempotent_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            results, failures = [], []
            def reserve(operator):
                try: results.append(native_environment.reserve_environment(root, self.request(operator=operator)))
                except native_environment.NativeEnvironmentError as error: failures.append(str(error))
            threads = [threading.Thread(target=reserve, args=(operator,)) for operator in ("agent-a", "agent-b")]
            for thread in threads: thread.start()
            for thread in threads: thread.join()
            self.assertEqual(1, len(results)); self.assertEqual(1, len(failures))
            retry = native_environment.reserve_environment(root, self.request(operator=results[0]["identity"]["operator"]))
            self.assertTrue(retry["idempotent"])
            self.assertEqual(results[0]["identity"], retry["identity"])

    def test_wrong_identity_cannot_release_reservation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = native_environment.reserve_environment(root, self.request())["identity"]
            wrong = {**identity, "token": "wrong"}
            with self.assertRaisesRegex(native_environment.NativeEnvironmentError, "unknown"):
                native_environment.release_environment(root, wrong)
            self.assertEqual("released", native_environment.release_environment(root, identity)["state"])

    def test_stale_and_unknown_receipts_never_report_ready(self):
        now = time.time_ns() // 1_000_000
        result = native_environment.environment_status(".", {"nowUnixMs": now, "maxObservationAgeMs": 100,
            "observations": [{"kind": "vm", "source": "receipt", "observedAtUnixMs": now - 101, "outcome": "ready"},
                             {"kind": "ssh", "source": "receipt", "observedAtUnixMs": now, "outcome": "unknown"}]})
        self.assertEqual("UNKNOWN", result["state"]); self.assertFalse(result["ready"])
        self.assertTrue(result["observations"][0]["stale"]); self.assertTrue(result["observations"][1]["unknown"])

    def test_explicit_active_or_unknown_job_refuses_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); now = time.time_ns() // 1_000_000
            request = self.request(observations=[{"kind": "active-job", "source": "ssh-receipt", "observedAtUnixMs": now, "outcome": "unknown"}])
            identity = native_environment.reserve_environment(root, request)["identity"]
            with self.assertRaisesRegex(native_environment.NativeEnvironmentError, "active or unknown"):
                native_environment.release_environment(root, identity)

    def test_idempotent_retry_cannot_clear_unknown_job_without_terminal_correlated_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); now = time.time_ns() // 1_000_000
            request = self.request(observations=[{"kind": "active-job", "source": "ssh", "observedAtUnixMs": now, "outcome": "unknown"}])
            identity = native_environment.reserve_environment(root, request)["identity"]
            native_environment.reserve_environment(root, self.request())
            with self.assertRaisesRegex(native_environment.NativeEnvironmentError, "active or unknown"):
                native_environment.release_environment(root, identity)
            native_environment.reserve_environment(root, self.request(observations=[{
                "kind": "active-job", "source": "ssh", "observedAtUnixMs": now,
                "outcome": "complete", "reservationId": identity["reservationId"], "reservationToken": identity["token"],
            }]))
            self.assertEqual("released", native_environment.release_environment(root, identity)["state"])

    def test_unavailable_job_and_stale_terminal_receipt_refuse_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); now = time.time_ns() // 1_000_000
            unavailable = self.request(observations=[{
                "kind": "active-job", "source": "ssh", "observedAtUnixMs": now, "outcome": "unavailable",
            }])
            identity = native_environment.reserve_environment(root, unavailable)["identity"]
            with self.assertRaisesRegex(native_environment.NativeEnvironmentError, "active or unknown"):
                native_environment.release_environment(root, identity)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); now = 1_000_000
            identity = native_environment.reserve_environment(root, self.request(nowUnixMs=now, maxObservationAgeMs=10,
                observations=[{"kind": "active-job", "source": "ssh", "observedAtUnixMs": now, "outcome": "absent"}]))["identity"]
            with mock.patch.object(native_environment.time, "time_ns", return_value=(now + 11) * 1_000_000):
                with self.assertRaisesRegex(native_environment.NativeEnvironmentError, "active or unknown"):
                    native_environment.release_environment(root, identity)

    def test_running_reservation_with_no_job_evidence_refuses_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = native_environment.reserve_environment(root, self.request())["identity"]
            measurement = {"physicalMemoryBytes": 32, "runningConfiguredMemoryBytes": 8, "pressure": "normal", "swapUsedBytes": 0}
            native_environment.reserve_environment(root, self.request(allocationState="running", measurement=measurement,
                reservationIdentity=identity, runningAllocationMapping=[{"reservationId": identity["reservationId"], "memoryBytes": 8}]))
            with self.assertRaisesRegex(native_environment.NativeEnvironmentError, "active or unknown"):
                native_environment.release_environment(root, identity)

    def test_host_budget_counts_pending_reservations(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            native_environment.reserve_environment(root, self.request(environment="one", requestedMemoryBytes=8))
            with self.assertRaisesRegex(native_environment.NativeEnvironmentError, "needs"):
                native_environment.reserve_environment(root, self.request(environment="two", requestedMemoryBytes=16))

    def test_running_mapping_requires_exact_identity_and_allows_unrelated_configured_memory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = native_environment.reserve_environment(root, self.request())["identity"]
            measurement = {"physicalMemoryBytes": 32, "runningConfiguredMemoryBytes": 12, "pressure": "normal", "swapUsedBytes": 0}
            with self.assertRaisesRegex(native_environment.NativeEnvironmentError, "exact identity"):
                native_environment.reserve_environment(root, self.request(allocationState="running", measurement=measurement))
            native_environment.reserve_environment(root, self.request(
                allocationState="running", measurement=measurement, reservationIdentity=identity,
                runningAllocationMapping=[{"reservationId": identity["reservationId"], "memoryBytes": 8}],
            ))
            result = native_environment.reserve_environment(root, self.request(
                environment="two", measurement=measurement,
                runningAllocationMapping=[{"reservationId": identity["reservationId"], "memoryBytes": 8}],
            ))
            self.assertEqual("reserved", result["state"])

    def test_state_files_are_private(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            native_environment.reserve_environment(root, self.request())
            directory = root / ".rag_index" / "native-environments"
            self.assertEqual(0o700, directory.stat().st_mode & 0o777)
            self.assertEqual(0o600, (directory / "reservations.json").stat().st_mode & 0o777)
            self.assertEqual(0o600, (directory / "lock").stat().st_mode & 0o777)

    def test_windows_reports_unsupported_without_importing_a_posix_lock(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(native_environment.os, "name", "nt"):
            with self.assertRaisesRegex(native_environment.NativeEnvironmentError, "unsupported"):
                native_environment.reserve_environment(Path(temporary), self.request())

    def test_direct_module_import_supports_standalone_mcp_loading(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run([sys.executable, "-c", "import native_environment"],
                cwd=temporary, env={"PYTHONPATH": str(Path(native_environment.__file__).parent)},
                capture_output=True, text=True, check=False)
            self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()

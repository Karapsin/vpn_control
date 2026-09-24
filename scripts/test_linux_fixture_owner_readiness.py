"""Fast regression for a real delayed fixture owner and guarded status polling."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from linux_fixture_owner_readiness import (EndpointIdentity, OwnerReadinessError,
                                           ProcessIdentity, StatusObservation,
                                           wait_for_exact_owner_ready)


class OwnerReadinessTests(unittest.TestCase):
    def test_real_delayed_owner_unavailable_then_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory)
            code = """
from pathlib import Path
import sys
import time
p = Path(sys.argv[1])
(p / 'endpoint').write_text('ready')
limit = time.monotonic() + 4
while not (p / 'allow-status').exists() and time.monotonic() < limit:
    time.sleep(.01)
if (p / 'allow-status').exists():
    (p / 'status').write_text('ready')
time.sleep(.5)
"""
            child = subprocess.Popen([sys.executable, "-c", code, directory])
            try:
                identity = ProcessIdentity(child.pid, 123, 1000)
                calls = []

                def live():
                    return identity if child.poll() is None else None

                def endpoint():
                    return EndpointIdentity(directory, identity, "owner-one") if (marker / "endpoint").exists() else None

                def status():
                    calls.append("status")
                    if not (marker / "status").exists():
                        (marker / "allow-status").write_text("ready")
                        return StatusObservation(2, {"code": "UNAVAILABLE", "controllerId": None})
                    return StatusObservation(0, {"schemaVersion": 1, "ok": True, "code": "OK", "final": True,
                                                 "controllerId": "owner-one"})

                result = wait_for_exact_owner_ready(workspace=directory, expected=identity,
                                                    observe_live=live, observe_endpoint=endpoint,
                                                    observe_status=status, timeout_seconds=5, poll_seconds=.02)
                self.assertEqual("owner-one", result["controllerId"])
                self.assertGreaterEqual(len(calls), 2)
            finally:
                if child.poll() is None:
                    child.terminate()
                child.wait(timeout=3)

    def test_foreign_endpoint_rejected_before_status(self):
        expected = ProcessIdentity(10, 20, 1000)
        with self.assertRaisesRegex(OwnerReadinessError, "endpoint"):
            wait_for_exact_owner_ready(workspace="/owned", expected=expected,
                                       observe_live=lambda: expected,
                                       observe_endpoint=lambda: EndpointIdentity("/owned", ProcessIdentity(11, 20, 1000), "foreign"),
                                       observe_status=lambda: self.fail("status must not be sent"))

    def test_live_child_exit_stops_before_status(self):
        expected = ProcessIdentity(10, 20, 1000)
        observations = iter((expected, None))
        with self.assertRaisesRegex(OwnerReadinessError, "identity changed"):
            wait_for_exact_owner_ready(workspace="/owned", expected=expected,
                                       observe_live=lambda: next(observations),
                                       observe_endpoint=lambda: None,
                                       observe_status=lambda: self.fail("status must not be sent"),
                                       timeout_seconds=1, poll_seconds=.01,
                                       clock=lambda: 0, sleep=lambda _: None)

    def test_endpoint_replacement_after_unavailable_fails_closed(self):
        expected = ProcessIdentity(10, 20, 1000)
        endpoints = iter((EndpointIdentity("/owned", expected, "first"),
                          EndpointIdentity("/owned", expected, "replacement")))
        with self.assertRaisesRegex(OwnerReadinessError, "controller changed"):
            wait_for_exact_owner_ready(workspace="/owned", expected=expected,
                                       observe_live=lambda: expected,
                                       observe_endpoint=lambda: next(endpoints),
                                       observe_status=lambda: StatusObservation(2, {"code": "UNAVAILABLE", "controllerId": None}),
                                       timeout_seconds=1, poll_seconds=.01,
                                       clock=lambda: 0, sleep=lambda _: None)

    def test_authenticated_foreign_controller_fails_closed(self):
        expected = ProcessIdentity(10, 20, 1000)
        with self.assertRaisesRegex(OwnerReadinessError, "Authenticated"):
            wait_for_exact_owner_ready(workspace="/owned", expected=expected,
                                       observe_live=lambda: expected,
                                       observe_endpoint=lambda: EndpointIdentity("/owned", expected, "first"),
                                       observe_status=lambda: StatusObservation(0, {"schemaVersion": 1,
                                                                                    "ok": True, "code": "OK",
                                                                                    "final": True, "controllerId": "foreign"}))

    def test_absent_endpoint_has_bounded_deadline(self):
        expected = ProcessIdentity(10, 20, 1000)
        now = [0.0]

        def advance(seconds):
            now[0] += seconds

        with self.assertRaisesRegex(OwnerReadinessError, "deadline"):
            wait_for_exact_owner_ready(workspace="/owned", expected=expected,
                                       observe_live=lambda: expected,
                                       observe_endpoint=lambda: None,
                                       observe_status=lambda: self.fail("status must not be sent"),
                                       timeout_seconds=.05, poll_seconds=.01,
                                       clock=lambda: now[0], sleep=advance)


if __name__ == "__main__":
    unittest.main()

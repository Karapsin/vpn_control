"""After its admission a Windows counter start answers with the original's retained status.

Natively (2026-11-09, operation f4fdee43 on clone 9059be98, desktop alias
windows-raw9059be98-desktop-v1) the MCP start ran 467 s while three other clones built
on the same host. Its readiness, namespace and revalidation packets were slow, the local
admission (intent.json) was written at 15:01:56 and the counter was submitted, but the
follow-up status observation ran out of readiness budget. The route answered
blocked/readiness_deadline under the internal packet operation 2fa04c5b with "original
guest program admission is incomplete" (native failure 04d91d12). The original had run:
a later reconcile found it terminal with 80 values and exit 0.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import time
import types
import unittest
from unittest import mock

from agent_tools import native_next_action, readiness, readiness_windows_jobs as jobs

OPERATION = "f4fdee43-7419-4ac7-91d9-38306b30b291"
INTERNAL = "2fa04c5b-1e74-4e23-9ff3-493aad8cbd59"
IDENTITY = {"admissionNonce": "a" * 32, "programSha256": "b" * 64}
ADMITTED = {"state": "unknown", "reason": "original_owner_ack_pending", "identity": IDENTITY}
RUNNING = {"state": "running", "reason": "original_owner_running", "identity": IDENTITY}
INPUTS = {"fixtureId": "windows-raw9059be98-desktop-v1", "operationId": OPERATION, "count": 80, "intervalSeconds": .25}
LOCAL = {"fixtureId": INPUTS["fixtureId"], "operationId": OPERATION}


def deadline_spent(*args, **kwargs):
    raise readiness.ReadinessBlocked("readiness_deadline", INTERNAL)


def identity_refused(*args, **kwargs):
    raise readiness.ReadinessBlocked("machine_identity_mismatch", INTERNAL)


@unittest.skipUnless(os.name == "posix", "POSIX private-file custody")
class StartAfterAdmissionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.executor = object.__new__(jobs.WindowsJobExecutor)
        self.executor.target, self.executor.machine = "target", "machine"
        self.executor._snapshot = {"fixed": True, "provider": "raw-qemu-windows"}

    def run_flow(self, action, inputs, *, submit=None, status=None, observe=None, ensure=None):
        backend = types.SimpleNamespace(provider="raw-qemu-windows", windows_job_executor=lambda deadline=None: self.executor)
        fixture = types.SimpleNamespace(adapter=types.SimpleNamespace(backend=backend), context=lambda deadline=None: object(),
                                        target="target", machine="machine")
        with mock.patch("agent_tools.readiness_fixture_registry.registered_fixture", return_value=fixture), \
                mock.patch("agent_tools.readiness.ensure_ready", side_effect=ensure, return_value=object()), \
                mock.patch("agent_tools.readiness.revalidate"), \
                mock.patch.object(jobs, "executor_from_snapshot", return_value=self.executor), \
                mock.patch.object(jobs.WindowsJobExecutor, "snapshot", lambda executor: executor._snapshot), \
                mock.patch.object(jobs.WindowsJobExecutor, "_guard", lambda executor: None), \
                mock.patch.object(jobs.WindowsJobExecutor, "submit", side_effect=submit), \
                mock.patch.object(jobs.WindowsJobExecutor, "_dispatch", side_effect=status), \
                mock.patch.object(jobs.WindowsJobExecutor, "observe", side_effect=observe):
            return jobs.workflow(self.root, action, inputs, deadline=time.monotonic() + 300)

    def answered(self, action, inputs, **world):
        try:
            return self.run_flow(action, inputs, **world)
        except readiness.ReadinessBlocked as error:
            self.fail("after its admission the route answered blocked/%s under %s instead of the original"
                      % (error.reason, "the public operation" if error.operation_identity == OPERATION else "an internal operation"))

    def test_f4fdee43_status_after_submission_spent_RED_blocked_internal_GREEN_retained_original(self):
        result = self.answered("start", INPUTS, submit=lambda *a, **k: dict(ADMITTED), status=deadline_spent)
        self.assertEqual((OPERATION, "unknown", "original_owner_ack_pending", False),
                         (result["operationId"], result["state"], result["reason"], result["replayAllowed"]))
        self.assertEqual(IDENTITY, result["identity"])
        self.assertEqual("reconcile_original", native_next_action.next_action("vm_workflow", "guest-program-start", result)["kind"])
        self.assertEqual(result, jobs.workflow(self.root, "status", LOCAL))

    def test_submission_spent_after_the_admission_RED_blocked_internal_GREEN_unknown_original(self):
        result = self.answered("start", INPUTS, submit=deadline_spent)
        self.assertEqual((OPERATION, "unknown", "windows_job_submission_unknown"),
                         (result["operationId"], result["state"], result["reason"]))
        self.assertTrue((self.root / ".runtime/readiness-windows-guest-jobs" / INPUTS["fixtureId"] / OPERATION / "intent.json").exists())

    def test_reconcile_spent_RED_blocked_internal_GREEN_retained_original(self):
        started = self.run_flow("start", INPUTS, submit=lambda *a, **k: dict(ADMITTED), status=lambda *a, **k: dict(RUNNING))
        self.assertEqual("running", started["state"])
        result = self.answered("reconcile", LOCAL, observe=deadline_spent)
        self.assertEqual((OPERATION, "running"), (result["operationId"], result["state"]))

    def test_fixed_an_identity_refusal_after_the_admission_still_escapes_under_the_public_operation(self):
        with self.assertRaises(readiness.ReadinessBlocked) as error:
            self.run_flow("start", INPUTS, submit=lambda *a, **k: dict(ADMITTED), status=identity_refused)
        self.assertEqual(("machine_identity_mismatch", OPERATION), (error.exception.reason, error.exception.operation_identity))
        retained = jobs.workflow(self.root, "status", LOCAL)
        self.assertEqual(("unknown", "original_owner_ack_pending"), (retained["state"], retained["reason"]))

    def test_a_refusal_before_any_admission_stays_a_refusal_with_nothing_recorded(self):
        def refused(*args, **kwargs):
            raise readiness.ReadinessBlocked("readiness_deadline", OPERATION)
        with self.assertRaises(readiness.ReadinessBlocked) as error:
            self.run_flow("start", INPUTS, ensure=refused, submit=lambda *a, **k: self.fail("submitted without admission"))
        self.assertEqual(("readiness_deadline", OPERATION), (error.exception.reason, error.exception.operation_identity))
        self.assertFalse((self.root / ".runtime/readiness-windows-guest-jobs").exists())

    def test_fixed_a_transport_timeout_of_the_follow_up_keeps_the_admitted_answer(self):
        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired(["ssh"], .1)
        result = self.run_flow("start", INPUTS, submit=lambda *a, **k: dict(ADMITTED), status=timeout)
        self.assertEqual((OPERATION, "unknown", "original_owner_ack_pending"), (result["operationId"], result["state"], result["reason"]))


if __name__ == "__main__":
    unittest.main()

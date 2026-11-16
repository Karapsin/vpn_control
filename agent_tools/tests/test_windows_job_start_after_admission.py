"""After its admission a Windows counter start answers with the original's retained status.

Natively (2026-11-09, operation f4fdee43 on clone 9059be98, desktop alias
windows-raw9059be98-desktop-v1) the MCP start ran 467 s while three other clones built
on the same host. Its admission (intent.json) was written at 15:01:56. Inside
executor.submit, job-start controller 2fa04c5b (attempt fa89f9d8, 15:02:03) sent its
123,696-byte packet through the saved-program route (correlation 59d80918, whose
program.source execs exactly that packet from base64). The target ran and returned, and the transport's
revalidation after the return ran out of readiness budget (returned-readiness-changed.json,
readiness_deadline, 15:03:12). So submit raised ssh_transport.SubmittedResultReadinessChanged
and the route answered blocked/readiness_deadline under 2fa04c5b with "original guest
program admission is incomplete" (native failure 04d91d12). No follow-up status ran: the
only job-status controller (89b26ca6) belongs to the later reconcile, which found the
original terminal with 80 values and exit 0.

Once intent.json exists a start never answers a refusal. Its packet may already have run,
whatever the readiness reason, so a refusal would invite a second counter under a new
operation while the original stays unreconciled. The start answers what status answers.
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
from agent_tools import ssh_transport as transport

OPERATION = "f4fdee43-7419-4ac7-91d9-38306b30b291"
INTERNAL = "2fa04c5b-1e74-4e23-9ff3-493aad8cbd59"
IDENTITY = {"admissionNonce": "a" * 32, "programSha256": "b" * 64}
ADMITTED = {"state": "unknown", "reason": "original_owner_ack_pending", "identity": IDENTITY}
RUNNING = {"state": "running", "reason": "original_owner_running", "identity": IDENTITY}
INPUTS = {"fixtureId": "windows-raw9059be98-desktop-v1", "operationId": OPERATION, "count": 80, "intervalSeconds": .25}
LOCAL = {"fixtureId": INPUTS["fixtureId"], "operationId": OPERATION}
# Readiness reasons the transport's revalidation can raise after a target returned and
# that 3f3ebd75 still answered as refusals: adapter blockers of readiness_transport,
# _next's transport refusals, and identity refusals.
AFTER_RETURN = ("connection_outcome_unknown", "provider_unavailable", "boot_identity_unavailable",
                "guest_agent_unavailable", "transport_state_unknown", "machine_identity_mismatch", "integrity_mismatch")


def deadline_spent(*args, **kwargs):
    raise readiness.ReadinessBlocked("readiness_deadline", INTERNAL)


def refused(reason):
    def raise_it(*args, **kwargs):
        raise readiness.ReadinessBlocked(reason, INTERNAL)
    return raise_it


def returned_then_changed(reason):
    """What run_ssh raises when the target ran and returned, then the readiness changed."""
    def raise_it(*args, **kwargs):
        raise transport.SubmittedResultReadinessChanged(readiness.ReadinessBlocked(reason, INTERNAL),
                                                        subprocess.CompletedProcess(["ssh"], 0, b"{}", b""))
    return raise_it


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

    def assert_retained_original(self, result, reason):
        self.assertEqual((OPERATION, "unknown", reason, False),
                         (result["operationId"], result["state"], result["reason"], result["replayAllowed"]))
        self.assertEqual(("reconcile_original", False), (result["nextAction"]["kind"], result["nextAction"]["replayAllowed"]))
        self.assertEqual("reconcile_original", native_next_action.next_action("vm_workflow", "guest-program-start", result)["kind"])
        self.assertEqual(result, jobs.workflow(self.root, "status", LOCAL), "the start and the status of one original disagree")
        self.assertTrue((self.root / ".runtime/readiness-windows-guest-jobs" / INPUTS["fixtureId"] / OPERATION / "intent.json").exists())

    def test_f4fdee43_job_start_target_ran_then_its_budget_was_spent_RED_blocked_internal_GREEN_unknown_original(self):
        # The native trigger: the controller inside submit, not a follow-up status.
        result = self.answered("start", INPUTS, submit=returned_then_changed("readiness_deadline"),
                               status=lambda *a, **k: self.fail("no follow-up status ran natively"))
        self.assert_retained_original(result, "windows_job_submission_unknown")

    def test_a_refusal_raised_after_the_job_start_target_ran_RED_blocked_GREEN_unknown_original(self):
        for reason in AFTER_RETURN:
            with self.subTest(reason=reason):
                self.setUp()
                result = self.answered("start", INPUTS, submit=returned_then_changed(reason))
                self.assert_retained_original(result, "windows_job_submission_unknown")

    def test_a_refusal_of_the_submit_after_its_admission_RED_blocked_GREEN_unknown_original(self):
        # A plain refusal from the controller's own admission or its dispatch guards: the
        # owner already holds admission.json, dispatch.json and a controller attempt.
        for reason in ("connection_outcome_unknown", "machine_identity_mismatch", "readiness_deadline"):
            with self.subTest(reason=reason):
                self.setUp()
                result = self.answered("start", INPUTS, submit=refused(reason))
                self.assert_retained_original(result, "windows_job_submission_unknown")

    def test_a_refusal_of_the_follow_up_after_an_admitted_submit_RED_blocked_GREEN_the_admitted_answer(self):
        for reason in ("connection_outcome_unknown", "provider_unavailable", "readiness_deadline"):
            with self.subTest(reason=reason):
                self.setUp()
                result = self.answered("start", INPUTS, submit=lambda *a, **k: dict(ADMITTED), status=refused(reason))
                self.assert_retained_original(result, "original_owner_ack_pending")
                self.assertEqual(IDENTITY, result["identity"])

    def test_an_identity_refusal_after_the_admission_answers_the_admitted_original_and_reconcile_still_refuses(self):
        result = self.answered("start", INPUTS, submit=lambda *a, **k: dict(ADMITTED), status=refused("machine_identity_mismatch"))
        self.assert_retained_original(result, "original_owner_ack_pending")
        # Nothing is bypassed: the original's own reconcile still reports the refusal, under the public operation.
        with self.assertRaises(readiness.ReadinessBlocked) as error:
            self.run_flow("reconcile", LOCAL, observe=refused("machine_identity_mismatch"))
        self.assertEqual(("machine_identity_mismatch", OPERATION), (error.exception.reason, error.exception.operation_identity))
        self.assertEqual(result, jobs.workflow(self.root, "status", LOCAL))

    def test_reconcile_after_its_packet_ran_RED_blocked_GREEN_cached_original(self):
        # A reconcile's own packet (a status read, or the proven-unsubmitted start) ran and returned.
        started = self.run_flow("start", INPUTS, submit=lambda *a, **k: dict(ADMITTED), status=lambda *a, **k: dict(RUNNING))
        self.assertEqual("running", started["state"])
        result = self.answered("reconcile", LOCAL, observe=returned_then_changed("connection_outcome_unknown"))
        self.assertEqual(started, result)

    def test_a_repeated_start_after_its_packet_ran_RED_blocked_GREEN_observes_the_original_like_a_reconcile(self):
        started = self.run_flow("start", INPUTS, submit=lambda *a, **k: dict(ADMITTED), status=lambda *a, **k: dict(RUNNING))
        never = lambda *a, **k: self.fail("a repeated start submitted again")
        result = self.answered("start", INPUTS, submit=never, observe=returned_then_changed("connection_outcome_unknown"))
        self.assertEqual(started, result)
        with self.assertRaises(readiness.ReadinessBlocked) as error:
            self.run_flow("start", INPUTS, submit=never, observe=refused("machine_identity_mismatch"))
        self.assertEqual(("machine_identity_mismatch", OPERATION), (error.exception.reason, error.exception.operation_identity))

    def test_a_spent_follow_up_status_RED_blocked_internal_GREEN_the_submits_admitted_answer(self):
        # A sibling of the native case: submit returned the admitted original and the
        # follow-up status then ran out of budget.
        result = self.answered("start", INPUTS, submit=lambda *a, **k: dict(ADMITTED), status=deadline_spent)
        self.assert_retained_original(result, "original_owner_ack_pending")
        self.assertEqual(IDENTITY, result["identity"])

    def test_reconcile_spent_RED_blocked_internal_GREEN_retained_original(self):
        started = self.run_flow("start", INPUTS, submit=lambda *a, **k: dict(ADMITTED), status=lambda *a, **k: dict(RUNNING))
        self.assertEqual("running", started["state"])
        result = self.answered("reconcile", LOCAL, observe=deadline_spent)
        self.assertEqual((OPERATION, "running"), (result["operationId"], result["state"]))

    def test_a_refusal_before_any_admission_stays_a_refusal_with_nothing_recorded(self):
        def refused_before(*args, **kwargs):
            raise readiness.ReadinessBlocked("readiness_deadline", OPERATION)
        with self.assertRaises(readiness.ReadinessBlocked) as error:
            self.run_flow("start", INPUTS, ensure=refused_before, submit=lambda *a, **k: self.fail("submitted without admission"))
        self.assertEqual(("readiness_deadline", OPERATION), (error.exception.reason, error.exception.operation_identity))
        self.assertFalse((self.root / ".runtime/readiness-windows-guest-jobs").exists())

    def test_an_identity_refusal_before_any_admission_names_the_public_operation(self):
        with self.assertRaises(readiness.ReadinessBlocked) as error:
            self.run_flow("start", INPUTS, ensure=refused("machine_identity_mismatch"),
                          submit=lambda *a, **k: self.fail("submitted without admission"))
        self.assertEqual(("machine_identity_mismatch", OPERATION), (error.exception.reason, error.exception.operation_identity))
        self.assertFalse((self.root / ".runtime/readiness-windows-guest-jobs").exists())

    def test_fixed_a_transport_timeout_of_the_follow_up_keeps_the_admitted_answer(self):
        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired(["ssh"], .1)
        result = self.run_flow("start", INPUTS, submit=lambda *a, **k: dict(ADMITTED), status=timeout)
        self.assertEqual((OPERATION, "unknown", "original_owner_ack_pending"), (result["operationId"], result["state"], result["reason"]))


if __name__ == "__main__":
    unittest.main()

"""A returned target's readiness re-check is not starved by its run (transport-readiness-revalidation-under-load).

Natively (2026-11-18 to 2026-11-20, Mac 1-minute load 13-24) run_ssh discarded
returned replies at ssh_transport.py:1208: after the remote run returned, the
saved-program generator re-checked the admitted transport (check_source_lifetime
-> Admission.revalidate -> readiness.revalidate -> TransportAdapter.observe) under
the run's own remaining submission deadline. A slow run left that re-check too
little time, so it raised readiness_deadline, or readiness_observation_unavailable
when a bounded local helper inside the probe (`ps`, `ssh -O check`, clipped by
_remaining_timeout) timed out. Hits: a read-only observe that aborted the whole
enrollment of faf8696a (enroll-lease-counter.err, readiness_windows.py:247), a
closing probe frame, a lock reply and job-namespace controllers.

The fix gives the re-check its own bounded window and observes it again on a
transient outcome; declared reads (observe, lease-status, job-namespace-status,
job-status, job-inventory) may repeat the whole read; a state-changing submit
is never repeated and keeps take_submitted_result.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types
import unittest
from contextlib import contextmanager
from unittest import mock

from agent_tools import readiness
from agent_tools import ssh_transport as transport
from agent_tools.tests import red_gate
from agent_tools.tests import test_ssh_absolute_deadline as deadline_fixture

FIXTURE = Path(__file__).parent / "fixtures/ssh_returned_revalidation"
BEFORE = json.loads((FIXTURE / "provenance.json").read_bytes())["beforeSha256"]


def _before_module(name):
    """The preserved unfixed module, executed in the agent_tools package."""
    raw = (FIXTURE / (name + ".py.before.source")).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == BEFORE[name + ".py.before.source"]
    module = types.ModuleType("agent_tools._before_" + name)
    module.__file__ = str(Path(transport.__file__).with_name(name + ".py"))
    module.__package__ = "agent_tools"
    exec(compile(raw, module.__file__, "exec", dont_inherit=True), module.__dict__)
    return module


def _red_phases(test):
    red = red_gate.red_required(test, *sorted(FIXTURE.glob("*.before.source")), FIXTURE / "provenance.json")
    return ((True,) if red else ()) + (False,)


@unittest.skipUnless(os.name == "posix", "owned Unix SSH fixture")
class ReturnedRevalidationTransportTests(unittest.TestCase):
    """Actual saved-program submission through the owned Unix-socket SSH peer."""

    @contextmanager
    def caller(self, original):
        holder = deadline_fixture.AbsoluteDeadlineTests("caller")
        with mock.patch.object(deadline_fixture, "FIXTURE", FIXTURE), holder.caller(original) as values:
            yield values

    def spend_budget_then(self, t, after):
        """The run returns, then (like a loaded host) spends nearly all its own budget."""
        def runner(argv, **kwargs):
            result = subprocess.run(argv, **kwargs)
            after()
            left = t._SUBMISSION_DEADLINE.get() - time.monotonic()
            time.sleep(max(0, left - .25))
            return result
        return runner

    def test_slow_probe_after_a_spent_run_RED_discards_the_reply_GREEN_returns_it(self):
        for original in _red_phases(self):
            with self.subTest(original=original), self.caller(original) as (t, plan, admission, delay, counter, f):
                # Only the returned target's re-check meets the slow (0.6 s) probe.
                runner = self.spend_budget_then(t, delay.touch)
                if original:
                    with self.assertRaises(t.SubmittedResultReadinessChanged) as red:
                        t.run_ssh(plan, runner=runner, stdin=subprocess.DEVNULL, capture_output=True, timeout=8)
                    self.assertIn(red.exception.reason, {"readiness_deadline", "readiness_observation_unavailable"})
                else:
                    result = t.run_ssh(plan, runner=runner, stdin=subprocess.DEVNULL, capture_output=True, timeout=8)
                    self.assertEqual((0, b"returned"), (result.returncode, result.stdout))
                self.assertEqual("once\n", counter.read_text())

    def flaky_observer(self, admission, failures, reason=None):
        """The next `failures` observations fail like a starved local helper (or with `reason`)."""
        adapter = admission.context.adapter
        real = adapter.observe
        calls = []
        def observe(requirements, deadline):
            calls.append(deadline)
            if len(calls) <= failures:
                if reason is not None:
                    raise sys.modules[type(adapter).__module__].readiness.AdapterBlocked(reason)
                raise subprocess.TimeoutExpired(["/bin/ps"], .1)
            return real(requirements, deadline)
        return lambda: setattr(adapter, "observe", observe), calls

    def test_one_transient_observation_failure_RED_discards_the_reply_GREEN_observes_again(self):
        for original in _red_phases(self):
            with self.subTest(original=original), self.caller(original) as (t, plan, admission, delay, counter, f):
                arm, calls = self.flaky_observer(admission, 1)
                def runner(argv, **kwargs):
                    result = subprocess.run(argv, **kwargs)
                    arm()
                    return result
                if original:
                    with self.assertRaises(t.SubmittedResultReadinessChanged) as red:
                        t.run_ssh(plan, runner=runner, stdin=subprocess.DEVNULL, capture_output=True, timeout=8)
                    self.assertEqual("readiness_observation_unavailable", red.exception.reason)
                    self.assertEqual(1, len(calls))
                else:
                    result = t.run_ssh(plan, runner=runner, stdin=subprocess.DEVNULL, capture_output=True, timeout=8)
                    self.assertEqual((0, b"returned"), (result.returncode, result.stdout))
                    self.assertEqual(2, len(calls))
                self.assertEqual("once\n", counter.read_text())

    def test_returned_window_is_bounded_and_keeps_the_body_without_replay(self):
        with self.caller(False) as (t, plan, admission, delay, counter, f):
            arm, calls = self.flaky_observer(admission, 10 ** 6)
            def runner(argv, **kwargs):
                result = subprocess.run(argv, **kwargs)
                arm()
                return result
            started = time.monotonic()
            with mock.patch.object(t, "RETURNED_REVALIDATION_SECONDS", 1.5):
                with self.assertRaises(t.SubmittedResultReadinessChanged) as changed:
                    t.run_ssh(plan, runner=runner, stdin=subprocess.DEVNULL, capture_output=True, timeout=8)
            self.assertLess(time.monotonic() - started, 12)
            self.assertIn(changed.exception.reason, {"readiness_deadline", "readiness_observation_unavailable"})
            self.assertGreaterEqual(len(calls), 2)
            self.assertIs(False, changed.exception.replay_allowed)
            self.assertEqual(b"returned", changed.exception.take_submitted_result().stdout)
            self.assertEqual("once\n", counter.read_text())

    def test_a_non_transient_refusal_after_return_is_never_observed_again(self):
        with self.caller(False) as (t, plan, admission, delay, counter, f):
            arm, calls = self.flaky_observer(admission, 1, reason="machine_identity_mismatch")
            def runner(argv, **kwargs):
                result = subprocess.run(argv, **kwargs)
                arm()
                return result
            with self.assertRaises(t.SubmittedResultReadinessChanged) as changed:
                t.run_ssh(plan, runner=runner, stdin=subprocess.DEVNULL, capture_output=True, timeout=8)
            self.assertEqual("machine_identity_mismatch", changed.exception.reason)
            self.assertEqual(1, len(calls))
            self.assertEqual("once\n", counter.read_text())


def _changed(reason, body=b"{}"):
    return transport.SubmittedResultReadinessChanged(readiness.ReadinessBlocked(reason, "op"),
                                                     subprocess.CompletedProcess(["ssh"], 0, body, b""))


class RetryReadOnlyTests(unittest.TestCase):
    def test_requires_an_explicit_read_only_declaration(self):
        for value in (False, None, 1, "yes"):
            with self.assertRaises(ValueError):
                transport.retry_read_only(lambda: 1, deadline=time.monotonic() + 30, read_only=value)

    def test_repeats_only_transient_reasons_within_the_deadline_and_attempts(self):
        for reason in sorted(transport.READ_ONLY_RETRY_REASONS):
            calls = []
            def attempt():
                calls.append(1)
                if len(calls) == 1:
                    raise _changed(reason)
                return "read"
            self.assertEqual("read", transport.retry_read_only(attempt, deadline=time.monotonic() + 30, read_only=True))
            self.assertEqual(2, len(calls))
        for reason in ("connection_generation_changed", "prepared_context_stale", "machine_identity_mismatch"):
            calls = []
            def refused():
                calls.append(1)
                raise _changed(reason)
            with self.assertRaises(transport.SubmittedResultReadinessChanged):
                transport.retry_read_only(refused, deadline=time.monotonic() + 30, read_only=True)
            self.assertEqual(1, len(calls))
        calls = []
        def always():
            calls.append(1)
            raise _changed("readiness_deadline")
        with self.assertRaises(transport.SubmittedResultReadinessChanged):
            transport.retry_read_only(always, deadline=time.monotonic() + 30, read_only=True)
        self.assertEqual(3, len(calls))
        calls = []
        with self.assertRaises(transport.SubmittedResultReadinessChanged):
            transport.retry_read_only(always, deadline=time.monotonic() + .5, read_only=True)
        self.assertEqual(1, len(calls))


class _Held:
    def read(self, *args, **kwargs):
        return b""

    def finish(self):
        pass

    def final_identity_pass(self):
        pass

    def close(self):
        pass


@contextmanager
def _admitted(*args, **kwargs):
    yield types.SimpleNamespace(revalidate=lambda: None, ready="ready")


@unittest.skipUnless(os.name == "posix", "POSIX private-file custody")
class DeclaredReadCallerTests(unittest.TestCase):
    """Whole-read repetition at the Windows packet and job-controller owners."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)

    def ssh(self, first, body):
        calls = []
        def run_ssh(argv, **kwargs):
            calls.append(argv)
            if len(calls) == 1:
                raise first
            return subprocess.CompletedProcess(argv, 0, body, b"")
        return run_ssh, calls

    def windows_module(self, original):
        if original:
            return _before_module("readiness_windows")
        from agent_tools import readiness_windows
        return readiness_windows

    def windows_run(self, module, mode, run_ssh):
        backend = object.__new__(module.WindowsBackend)
        backend.root = self.root
        backend.binding = {"spec": {"host": "windows-host"}}
        backend._guard = lambda: None
        saved = {}
        with mock.patch.object(transport, "admitted_transport", _admitted), \
                mock.patch.object(transport, "build_ssh_argv", lambda *a, **k: ["ssh", "argv"]), \
                mock.patch.object(transport, "load_config", lambda root: None), \
                mock.patch.object(transport, "run_ssh", run_ssh), \
                mock.patch.object(module.packets, "program", lambda *a, **k: b"print(1)\n"), \
                mock.patch.object(module, "_Held", _Held), \
                mock.patch.object(module, "_save", lambda path, value: saved.__setitem__(Path(path).name, value)):
            return module.WindowsBackend._run(backend, mode, "6a1fd1a3-6c0b-4d5e-9b0e-2f3f0a6f1c11",
                                              time.monotonic() + 120, reconcile=True)

    def test_windows_observe_after_a_starved_recheck_RED_aborts_GREEN_reads_again(self):
        body = json.dumps({"state": "observed"}).encode()
        for original in _red_phases(self):
            with self.subTest(original=original):
                module = self.windows_module(original)
                for reason in sorted(transport.READ_ONLY_RETRY_REASONS):
                    run_ssh, calls = self.ssh(_changed(reason), body)
                    if original:
                        with self.assertRaises(transport.SubmittedResultReadinessChanged):
                            self.windows_run(module, "observe", run_ssh)
                        self.assertEqual(1, len(calls))
                    else:
                        self.assertEqual(({"state": "observed"}, "ready"), self.windows_run(module, "observe", run_ssh))
                        self.assertEqual(2, len(calls))

    def test_windows_state_changing_mode_is_submitted_once(self):
        from agent_tools import readiness_windows
        self.assertEqual(frozenset({"observe", "lease-status"}), readiness_windows.READ_ONLY_MODES)
        for mode in ("wake_display", "lease-acquire", "lease-cancel", "lease-enroll", "lease-enrollment-status",
                     "reboot", "resume", "sleep-capability", "update-policy"):
            run_ssh, calls = self.ssh(_changed("readiness_deadline"), b"{}")
            with self.assertRaises(transport.SubmittedResultReadinessChanged) as error:
                self.windows_run(readiness_windows, mode, run_ssh)
            self.assertEqual(1, len(calls), mode)
            self.assertIsNotNone(error.exception.take_submitted_result())

    EXPECTED = {"actor": "a", "hostBoot": "b", "controlConnection": "c"}

    def jobs_run(self, module, mode, first):
        """One controller run whose first reply is lost to `first`; later controllers answer."""
        from agent_tools import readiness_windows as windows
        from agent_tools import native_review_source_closure as closure
        backend = types.SimpleNamespace(root=self.root, binding={"spec": {"host": "windows-host"}}, machine="m",
                                        provider="raw-qemu-windows", _guard=lambda: None)
        operations, calls = [], []
        def program(binding, mode, operation, **kwargs):
            operations.append(operation)
            return b"print(1)\n"
        def run_ssh(argv, **kwargs):
            calls.append(operations[-1])
            if len(calls) == 1:
                raise first
            return subprocess.CompletedProcess(argv, 0, json.dumps({
                "state": "observed", "job": {"state": "terminal"}, "operationId": operations[-1],
                "machine": "m", "provider": "raw-qemu-windows", **self.EXPECTED}).encode(), b"")
        with mock.patch.object(transport, "admitted_transport", _admitted), \
                mock.patch.object(transport, "build_ssh_argv", lambda *a, **k: ["ssh", "argv"]), \
                mock.patch.object(transport, "load_config", lambda root: None), \
                mock.patch.object(transport, "run_ssh", run_ssh), \
                mock.patch.object(module, "remote_program", program), \
                mock.patch.object(closure, "_Held", _Held), \
                mock.patch.object(windows, "_save", lambda path, value: None):
            try:
                return module._run(backend, mode, "4a1fd1a3-6c0b-4d5e-9b0e-2f3f0a6f1c22", time.monotonic() + 120,
                                   expected=self.EXPECTED), calls
            except transport.SubmittedResultReadinessChanged as error:
                error.calls = calls
                raise

    def test_job_controller_reads_after_a_starved_recheck_RED_abort_GREEN_read_again(self):
        for original in _red_phases(self):
            module = _before_module("readiness_windows_jobs") if original else __import__(
                "agent_tools.readiness_windows_jobs", fromlist=["_run"])
            for mode in ("job-namespace-status", "job-status", "job-inventory"):
                with self.subTest(original=original, mode=mode):
                    if original:
                        with self.assertRaises(transport.SubmittedResultReadinessChanged) as red:
                            self.jobs_run(module, mode, _changed("readiness_observation_unavailable"))
                        self.assertEqual(1, len(red.exception.calls))
                    else:
                        result, calls = self.jobs_run(module, mode, _changed("readiness_observation_unavailable"))
                        self.assertEqual({"state": "terminal"}, result)
                        self.assertEqual(2, len(set(calls)), "each read is a fresh controller")

    def test_job_enroll_and_start_are_submitted_once(self):
        from agent_tools import readiness_windows_jobs as jobs
        self.assertEqual(frozenset({"job-namespace-status", "job-status", "job-inventory"}), jobs.READ_ONLY_MODES)
        for mode in ("job-enroll", "job-start"):
            with self.assertRaises(transport.SubmittedResultReadinessChanged) as error:
                self.jobs_run(jobs, mode, _changed("readiness_deadline"))
            self.assertEqual(1, len(error.exception.calls), mode)
            self.assertIsNotNone(error.exception.take_submitted_result())


if __name__ == "__main__":
    unittest.main()

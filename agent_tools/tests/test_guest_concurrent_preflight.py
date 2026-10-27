"""Causal scheduling coverage for the registered-guest admission test.

The real namespace inventory must refuse an incompletely published operation.
Run the whole old and current test with that window held open, using only their
private loopback fixture. No production protocol or response is substituted.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch

from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_guest_jobs as facade
from agent_tools import readiness_qemu_jobs as protocol
from agent_tools.tests import test_readiness_guest_jobs as current


@unittest.skipUnless(os.name == "posix" and os.geteuid() > 0, "ordinary POSIX user required")
class ConcurrentGuestPreflightTests(unittest.TestCase):
    def before(self, group="guest_concurrent_preflight_before"):
        folder = Path(__file__).parent / "fixtures" / group
        path = folder / "test_readiness_guest_jobs.py.source"
        raw = path.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         json.loads((folder / "provenance.json").read_bytes())["sha256"])
        module = types.ModuleType("agent_tools.tests.guest_concurrent_preflight_before")
        module.__file__ = str(path)
        exec(compile(raw, str(path), "exec"), module.__dict__)
        return module

    def scheduled(self, module, *, hold_host_publication=False):
        case = module.RegisteredGuestJobsTests(
            "test_concurrent_same_original_starts_have_one_remote_admission")
        result = unittest.TestResult()
        main_thread = threading.get_ident()
        boundary = threading.Event()
        late_finished = threading.Event()
        gate_lock = threading.Lock()
        counts = {"entered": 0, "lateFinished": 0}
        diagnostics = []
        monitor_errors = []
        target_operations = set()
        host_publication = {}
        host_read = threading.Event()
        host_refusals = []
        original_namespace = facade._namespace
        original_start = facade.start
        original_remote = facade._remote
        original_barrier_wait = threading.Barrier.wait
        original_teardown = case.tearDown
        original_link = os.link
        original_record = jobs._record
        raw = jobs.owner_source()
        needle = b"        job.mkdir(mode=0o700)\n"
        self.assertEqual(raw.count(needle), 1)
        with tempfile.TemporaryDirectory(prefix="vc-guest-preflight-causal-") as folder:
            directory = Path(folder).resolve()
            enabled, published, release = (directory / name for name in ("enabled", "published", "release"))
            # These files control scheduling only. The real mkdir, intent,
            # admission index, owner, inventory and transport execute unchanged.
            hold = ("        if Path(" + repr(str(enabled)) + ").exists():\n"
                    "            Path(" + repr(str(published)) + ").write_text(operation_id)\n"
                    "            publication_deadline = time.monotonic() + 6\n"
                    "            while not Path(" + repr(str(release)) + ").exists():\n"
                    "                if time.monotonic() >= publication_deadline:\n"
                    "                    raise RuntimeError('controlled_publication_deadline')\n"
                    "                time.sleep(.005)\n").encode()
            controlled_owner = raw.replace(needle, needle + hold)

            def link(source, destination, **kwargs):
                path = Path(destination)
                controlled = (hold_host_publication and enabled.exists() and path.name == "intent.json"
                              and "readiness-guest-jobs" in path.parts)
                if controlled:
                    # Register the observation before publishing; a competing
                    # reader may run immediately after the actual link syscall.
                    host_publication.update(path=path, raw=Path(source).read_bytes(), held=True)
                original_link(source, destination, **kwargs)
                if controlled:
                    host_publication["links"] = path.stat().st_nlink
                    # With the unfixed fixture a second real reader reaches the
                    # held hardlink and releases it. With serialized publication
                    # readers correctly wait until this bounded window closes.
                    host_read.wait(6)
                    host_publication["held"] = False

            def record(path):
                competing = (host_publication.get("held") is True
                             and Path(path) == host_publication.get("path"))
                try:
                    return original_record(path)
                except jobs.DurableJobError as error:
                    if competing:
                        host_refusals.append({"reason": str(error), "links": Path(path).stat().st_nlink})
                    raise
                finally:
                    if competing:
                        host_read.set()

            def namespace(*args, **kwargs):
                if threading.get_ident() == main_thread:
                    return original_namespace(*args, **kwargs)
                with gate_lock:
                    counts["entered"] += 1
                    ordinal = counts["entered"]
                self.assertLessEqual(ordinal, 3)
                enabled.touch()
                if ordinal > 1:
                    self.assertTrue(boundary.wait(6), "first contender reached no publication/preflight boundary")
                try:
                    return original_namespace(*args, **kwargs)
                finally:
                    if ordinal > 1:
                        with gate_lock:
                            counts["lateFinished"] += 1
                            if counts["lateFinished"] == 2:
                                late_finished.set()

            def barrier_wait(barrier, timeout=None):
                # A genuine completed-preflight barrier is the alternative to
                # reaching remote publication; this never changes its parties.
                if barrier.parties == 3 and threading.get_ident() != main_thread:
                    boundary.set()
                return original_barrier_wait(barrier, timeout)

            def start(*args, **kwargs):
                if threading.get_ident() != main_thread:
                    with gate_lock:
                        target_operations.add(args[2])
                return original_start(*args, **kwargs)

            def remote(executor, source):
                class RecordingExecutor:
                    def execute_source(self, source):
                        response = executor.execute_source(source)
                        if response.returncode:
                            diagnostics.append(response.stderr.decode(errors="replace"))
                        return response
                return original_remote(RecordingExecutor(), source)

            def monitor():
                try:
                    deadline = time.monotonic() + 12
                    while not published.exists() and time.monotonic() < deadline:
                        time.sleep(.005)
                    self.assertTrue(published.exists(), "original operation never reached publication")
                    boundary.set()
                    self.assertTrue(late_finished.wait(6), "late preflight observers did not finish")
                    # The same real partial namespace must remain unavailable
                    # in both runs; the fix cannot weaken the idle gate.
                    argv, payload = protocol.stdin_command(protocol.observe_program(case.namespace))
                    refused = subprocess.run([sys.executable, *argv[1:]], input=payload,
                                             capture_output=True, timeout=5)
                    self.assertNotEqual(refused.returncode, 0)
                    self.assertIn(b"record_unavailable", refused.stderr)
                    self.assertEqual(case.submissions, 2)
                except BaseException as error:
                    monitor_errors.append(error)
                finally:
                    boundary.set()
                    release.touch()

            def teardown():
                try:
                    # Even the intentionally RED old test owns a real finite
                    # sentinel. Collect it before its temporary tree is removed.
                    release.touch()
                    for operation in target_operations:
                        terminal = case.finish(operation)
                        self.assertEqual(terminal["executions"], 1)
                        self.assertEqual(terminal["counterValues"], 12)
                        self.assertEqual(original_start(case.root, "fixture", operation,
                                         count=12, interval_seconds=.02), terminal)
                    self.assertEqual(case.submissions, 2)
                    if hold_host_publication:
                        self.assertEqual(host_publication["links"], 2)
                        self.assertEqual(host_publication["path"].stat().st_nlink, 1)
                        self.assertEqual(host_publication["path"].read_bytes(), host_publication["raw"])
                finally:
                    original_teardown()

            case.tearDown = teardown
            thread = threading.Thread(target=monitor, daemon=True)
            with patch.object(jobs, "owner_source", return_value=controlled_owner), \
                    patch.object(facade, "_namespace", side_effect=namespace), \
                    patch.object(facade, "start", side_effect=start), \
                    patch.object(facade, "_remote", side_effect=remote), \
                    patch.object(os, "link", side_effect=link), \
                    patch.object(jobs, "_record", side_effect=record), \
                    patch.object(threading.Barrier, "wait", barrier_wait):
                thread.start()
                case.run(result)
                thread.join(timeout=12)
            self.assertFalse(thread.is_alive(), "publication monitor did not finish")
            self.assertEqual([], monitor_errors)
            self.assertEqual(3, counts["entered"])
        return result, diagnostics, host_refusals

    def test_whole_before_red_current_green_with_real_partial_inventory_refusal(self):
        old_result, old_diagnostics, _ = self.scheduled(self.before())
        self.assertEqual(1, old_result.testsRun)
        self.assertEqual([], old_result.failures)
        self.assertEqual(1, len(old_result.errors), old_result.errors)
        self.assertIn("guest_original_observation_unavailable", old_result.errors[0][1])
        self.assertTrue(any("record_unavailable" in row for row in old_diagnostics), old_diagnostics)
        new_result, new_diagnostics, _ = self.scheduled(current)
        self.assertEqual(1, new_result.testsRun)
        self.assertTrue(new_result.wasSuccessful(), new_result.errors + new_result.failures)
        self.assertEqual([], new_diagnostics)

    def test_whole_barrier_only_before_red_current_green_with_real_hardlink_refusal(self):
        before = self.before("guest_concurrent_host_publication_before")
        old_result, _, old_refusals = self.scheduled(before, hold_host_publication=True)
        self.assertEqual(1, old_result.testsRun)
        self.assertEqual([], old_result.failures)
        self.assertEqual(1, len(old_result.errors), old_result.errors)
        self.assertIn("DurableJobError: record_unavailable", old_result.errors[0][1])
        self.assertTrue(old_refusals)
        self.assertTrue(all(row["reason"] == "record_unavailable" for row in old_refusals))
        self.assertIn({"reason": "record_unavailable", "links": 2}, old_refusals)
        new_result, new_diagnostics, new_refusals = self.scheduled(current, hold_host_publication=True)
        self.assertEqual(1, new_result.testsRun)
        self.assertTrue(new_result.wasSuccessful(), new_result.errors + new_result.failures)
        self.assertEqual([], new_diagnostics)
        self.assertEqual([], new_refusals)


if __name__ == "__main__":
    unittest.main()

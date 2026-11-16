"""The Windows discovery queue's decision table: a reset only where one is needed, and a start drift marks the previous
row's evidence suspect instead of silently resetting and keeping its pass (review finding 10)."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
import uuid

from agent_tools import native_row_queue as queue
from agent_tools.tests import red_gate

FIXTURE = Path(__file__).parent / "fixtures" / "native_row_queue"
PASSED = {"state": "terminal", "exitCode": 0, "collectionState": "complete"}


def op(number):
    return "00000000-0000-4000-8000-%012d" % number


class RowEndTests(unittest.TestCase):
    def test_how_the_queue_reads_a_row(self):
        end = queue.row_end(op(1), "rowA", PASSED, {"result": "passed"})
        self.assertEqual((0, False, False), (end["rc"], end["drift"], end["unproven"]))
        failed = {"state": "terminal", "exitCode": 1, "collectionState": "complete"}
        for failure, drift, unproven in (("clean_start_drift:process:vpn-control.exe", True, False),
                                         ("clean_start_drift:run-entry", True, False),
                                         ("installed_tree_differs", True, False),
                                         ("installed_registration_differs:ProductCode", True, False),
                                         ("clean_start_census_unreadable", False, True),
                                         ("clean_start_unclean_job", False, True),
                                         ("task_exit_code", False, False)):
            with self.subTest(failure=failure):
                end = queue.row_end(op(1), "rowA", failed, {"result": "failed", "failure": failure})
                self.assertEqual((1, drift, unproven), (end["rc"], end["drift"], end["unproven"]))
        refused = {"state": "unknown", "reason": "terminal_collection_unverified", "executionState": "terminal",
                   "executionExitCode": 2, "executionFailure": "clean_start_unordered"}
        self.assertEqual((1, True), (queue.row_end(op(1), "rowA", refused, None)["rc"],
                                     queue.row_end(op(1), "rowA", refused, None)["unproven"]))
        unknown = {"state": "unknown", "reason": "job_exit_unknown:unverified"}
        self.assertEqual(3, queue.row_end(op(1), "rowA", unknown, None)["rc"])

    def test_decision_table(self):
        drift = {"rc": 1, "drift": True, "unproven": False, "scenario": "rowB"}
        unproven = {"rc": 1, "drift": False, "unproven": True, "scenario": "rowB"}
        known = {"rc": 1, "drift": False, "unproven": False, "scenario": "rowB"}
        cases = (
            ({"rc": 0, "scenario": "rowA"}, 1, op(9), queue.NEXT, None),
            ({"rc": 0, "scenario": "windows-public-update.public-ready"}, 1, op(9), queue.RESET_NEXT, None),
            ({"rc": 0, "scenario": "windows-reboot-pre"}, 1, op(9), queue.RESET_NEXT, None),
            (drift, 1, op(9), queue.RETRY, op(9)),
            (drift, 1, None, queue.RETRY, None),  # right after a reset: no row to blame
            (drift, 2, None, queue.RESET_NEXT, None),
            (unproven, 1, op(9), queue.RETRY, None),
            (known, 1, op(9), queue.RESET_NEXT, None),
            ({"rc": 3}, 1, op(9), queue.STOP, None),
            (None, 1, op(9), queue.STOP, None),
        )
        for end, attempts, previous, step, suspect in cases:
            with self.subTest(end=end, attempts=attempts):
                self.assertEqual({"step": step, "suspect": suspect}, queue.decide(end, attempts=attempts, previous=previous))


class QueueTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def scripted(self, script):
        """run_row and reset over scripted (rc, failure) ends; records the --prior each row named."""
        counter, priors = [0], []

        def end(scenario, rc, failure):
            counter[0] += 1
            collected = PASSED if rc == 0 else {"state": "terminal", "exitCode": 1, "collectionState": "complete"} if rc == 1 \
                else {"state": "unknown", "reason": "job_exit_unknown:x"}
            return queue.row_end(op(counter[0]), scenario, collected, {"result": "passed" if rc == 0 else "failed", "failure": failure})

        def run_row(scenario, prior):
            priors.append(prior)
            rc, failure = script.pop(0)
            return end(scenario, rc, failure)

        def reset():
            return end(queue.RESET, 0, None)
        return run_row, reset, priors

    def test_resets_only_where_needed_and_a_drift_marks_the_previous_row_RED_kept_GREEN(self):
        drift = (1, "clean_start_drift:task")
        script = [(0, None), drift, (0, None), (1, "task_exit_code"), (0, None), (0, None)]
        scenarios = ["rowA", "rowB", "rowC", "windows-public-update.public-ready", "rowD"]
        source = FIXTURE / "queue.before.source"
        self.assertEqual(json.loads((FIXTURE / "provenance.json").read_bytes())["files"]["queue.before.source"]["sha256"],
                         hashlib.sha256(source.read_bytes()).hexdigest())
        if red_gate.red_required(self, source):
            before = types.ModuleType("queue_before")
            before.__file__ = str(source)
            exec(compile(source.read_bytes(), str(source), "exec"), before.__dict__)
            before.FAMILY = self.root
            pending, ran = list(script), []

            def runner(argv, cwd=None, stdout=None, stderr=None):
                scenario = argv[4]
                ran.append(scenario)
                rc, failure = (0, None) if scenario == before.RESET else pending.pop(0)
                drifted = isinstance(failure, str) and failure.startswith("clean_start_drift:")
                stdout.write((json.dumps({"rowEnd": {"operation": op(len(ran)), "rc": rc, "drift": drifted}}) + "\n").encode())
                return subprocess.CompletedProcess(argv, rc, b"", b"")
            with contextlib.redirect_stdout(io.StringIO()):
                code = before.main(["t", "dep", "--package", "p", "--set", "s", "--source", "x", "--version", "2.2.18", *scenarios],
                                   runner=runner)
            # RED: the private helper reset and ran rowB again, ended 0, and rowA (whose leftovers the census found)
            # kept its pass: nothing marked it.
            self.assertEqual((0, ["windows-msi-base-reset", "rowA", "rowB", "windows-msi-base-reset", "rowB"]), (code, ran[:5]))
            self.assertFalse((self.root / ".rag_index").exists())
        run_row, reset, priors = self.scripted(list(script))
        result = queue.run_queue(self.root, scenarios, run_row, reset)
        reset_name = queue.RESET
        self.assertEqual([reset_name, "rowA", "rowB", reset_name, "rowB", "rowC", reset_name,
                          "windows-public-update.public-ready", reset_name, "rowD"], result["ran"])
        self.assertEqual(0, result["code"])
        # rowA (op 2) passed right after the first reset (op 1); rowB's census (op 3) found what rowA left.
        self.assertEqual([op(2)], result["suspects"])
        self.assertEqual({"schemaVersion": 1, "correlationId": op(2), "detectedBy": op(3), "failure": "clean_start_drift:task"},
                         queue.suspect(self.root, op(2)))
        self.assertIsNone(queue.suspect(self.root, op(5)), "a row after a reset is never blamed for a later drift")
        self.assertEqual([op(1), op(1), op(4), op(4), op(7), op(9)], priors)

    def test_an_unsettled_row_or_failed_reset_stops_with_no_reset_over_it(self):
        run_row, reset, _ = self.scripted([(0, None), (3, None)])
        result = queue.run_queue(self.root, ["rowA", "rowB", "rowC"], run_row, reset)
        self.assertEqual((3, [queue.RESET, "rowA", "rowB"], "rowB"), (result["code"], result["ran"], result["stop"]))
        result = queue.run_queue(self.root, ["rowA"], lambda scenario, prior: None, lambda: None)
        self.assertEqual((3, [queue.RESET], queue.RESET), (result["code"], result["ran"], result["stop"]))

    def test_a_second_drift_of_the_same_row_resets_before_the_next_and_marks_once(self):
        drift = (1, "clean_start_drift:service")
        run_row, reset, _ = self.scripted([(0, None), drift, drift, (0, None)])
        result = queue.run_queue(self.root, ["rowA", "rowB", "rowC"], run_row, reset)
        self.assertEqual([queue.RESET, "rowA", "rowB", queue.RESET, "rowB", queue.RESET, "rowC"], result["ran"])
        self.assertEqual([op(2)], result["suspects"])

    def test_marks_are_private_create_only_and_fail_closed(self):
        record = queue.mark_suspect(self.root, op(2), detected_by=op(3), failure="clean_start_drift:task")
        path = self.root.joinpath(*queue.SUSPECTS, op(2) + ".json")
        self.assertEqual((0o600, 0o700), (path.stat().st_mode & 0o777, path.parent.stat().st_mode & 0o777))
        self.assertEqual(record, queue.mark_suspect(self.root, op(2), detected_by=op(4), failure="installed_tree_differs"))
        for bad in ({"detected_by": "x", "failure": "f"}, {"detected_by": op(3), "failure": "two words"}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                queue.mark_suspect(self.root, op(5), **bad)
        path.chmod(0o644)
        self.assertEqual("suspect_mark_unreadable", queue.suspect(self.root, op(2))["failure"])
        path.chmod(0o600)
        path.write_text("not json")
        self.assertEqual("suspect_mark_unreadable", queue.suspect(self.root, op(2))["failure"])
        self.assertIsNone(queue.suspect(self.root, op(7)))
        self.assertIsNone(queue.suspect(self.root, "../" + op(2)))


if __name__ == "__main__":
    unittest.main()

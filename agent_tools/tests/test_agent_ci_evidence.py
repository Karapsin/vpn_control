"""Public CI projections and exact shard coverage, using owned local workers."""
import copy
import hashlib
import io
import json
import math
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from agent_tools import agent_ci_evidence as subject
from agent_tools import agent_test_runner as runner
from agent_tools.tests import test_agent_ci_shards as fixture


GATE = "agent_tools.tests.test_ssh_connection_session_close"
# The gate sorts last, so with the hosted count the first shard holds it after
# one ordinary module and every other shard one ordinary module.
MODULES = sorted(["agent_tools.tests.test_evidence_" + name for name in "abcdef"] + [GATE])
COUNT = subject.SHARD_COUNT
SUCCESS = ["success"] * COUNT
PRIVATE = "PRIVATE_PROJECTION_SENTINEL"
REJECTIONS = (OSError, ValueError, KeyError, TypeError)
COUNTS = ("testsRun", "failures", "errors", "skipped", "expectedFailures", "unexpectedSuccesses")


def plan(index, modules=None, **changes):
    values = {"baseline": "a" * 40, "head": "b" * 40,
              "fingerprint": "c" * 64, "modules": MODULES if modules is None else modules,
              "index": index, "run_id": "987654321", "attempt": "4"}
    values.update(changes)
    return subject.plan_value(**values)


def read(path):
    return json.loads(path.read_text())


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + "\n")


class PublicEventTests(unittest.TestCase):
    def event(self, kind="finished", **changes):
        value = {"event": kind, "publicTestId": MODULES[0] + ".C.test_one",
                 "outcome": "success", "elapsedSeconds": 0.125,
                 "testId": PRIVATE, "privateTestId": PRIVATE,
                 "skipReason": PRIVATE, "path": "/private/" + PRIVATE,
                 "exception": PRIVATE, "subtest": {"value": PRIVATE},
                 "startedMonotonic": PRIVATE, "endedMonotonic": PRIVATE}
        value.update(changes)
        return value

    def test_started_is_incomplete_and_projects_only_bound_public_identity(self):
        value = subject.public_event(self.event("started"), MODULES)
        self.assertEqual({"schemaVersion": 1, "event": "started",
                          "publicTestId": MODULES[0] + ".C.test_one",
                          "outcome": "incomplete"}, value)
        self.assertNotIn(PRIVATE, json.dumps(value))

    def test_finished_has_only_finite_public_fields_for_each_outcome(self):
        for outcome in ("incomplete", "success", "failure", "error", "skipped",
                        "expectedFailure", "unexpectedSuccess"):
            with self.subTest(outcome=outcome):
                value = subject.public_event(self.event(outcome=outcome), MODULES)
                self.assertEqual({"schemaVersion", "event", "publicTestId",
                                  "outcome", "elapsedSeconds"}, set(value))
                self.assertEqual(outcome, value["outcome"])
                self.assertEqual(0.125, value["elapsedSeconds"])
                self.assertNotIn(PRIVATE, json.dumps(value))

    def test_private_raw_or_subtest_identity_never_becomes_public_fallback(self):
        identities = [None, 9, "x" * 513, MODULES[0] + ".C.test_one (value='" + PRIVATE + "')",
                      MODULES[0] + ".C.test_one\n" + PRIVATE,
                      "agent_tools.tests.test_foreign.C.test_one",
                      "/private/" + PRIVATE, MODULES[0] + ".C.test_one.extra",
                      "setUpClass (" + MODULES[0] + "." + PRIVATE + "/private)"]
        for identity in identities:
            with self.subTest(identity_type=type(identity).__name__):
                value = subject.public_event(self.event(publicTestId=identity), MODULES)
                self.assertEqual("unclassified-test", value["publicTestId"])
                self.assertNotIn(PRIVATE, json.dumps(value))
        value = self.event()
        value.pop("publicTestId")
        self.assertEqual("unclassified-test", subject.public_event(value, MODULES)["publicTestId"])

    def test_bound_fixture_identities_remain_public_without_fixture_details(self):
        for identity in ("setUpModule (" + MODULES[0] + ")",
                         "tearDownModule (" + MODULES[0] + ")",
                         "setUpClass (" + MODULES[0] + ".C)",
                         "tearDownClass (" + MODULES[0] + ".C)"):
            with self.subTest(identity=identity):
                value = subject.public_event(self.event(publicTestId=identity,
                                                        fixture=PRIVATE), MODULES)
                self.assertEqual(identity, value["publicTestId"])
                self.assertNotIn(PRIVATE, json.dumps(value))

    def test_elapsed_is_typed_finite_nonnegative_and_bounded(self):
        for elapsed in (False, True, None, "0.1", -0.1, math.nan,
                        math.inf, -math.inf, 7 * 86400 + 1):
            with self.subTest(elapsed_type=type(elapsed).__name__):
                self.assertIsNone(subject.public_event(self.event(elapsedSeconds=elapsed), MODULES))
        for elapsed in (0, 0.125, 7 * 86400):
            with self.subTest(elapsed=elapsed):
                self.assertEqual(elapsed, subject.public_event(self.event(elapsedSeconds=elapsed), MODULES)["elapsedSeconds"])

    def test_unrecognized_or_untyped_events_and_outcomes_refuse(self):
        for value in (None, [], "finished", {}, self.event("selection"),
                      self.event(outcome=PRIVATE), self.event(outcome=None),
                      self.event(outcome=True), self.event(outcome=[])):
            with self.subTest(value_type=type(value).__name__):
                self.assertIsNone(subject.public_event(value, MODULES))


class PlanTests(unittest.TestCase):
    maxDiff = None

    def test_every_index_binds_one_exact_sorted_global_plan(self):
        values = [plan(index) for index in range(COUNT)]
        global_value = {"baseline": values[0]["baseline"], "head": values[0]["head"],
                        "sourceFingerprint": values[0]["sourceFingerprint"], "modules": MODULES,
                        "runId": "987654321", "runAttempt": "4"}
        expected = hashlib.sha256(json.dumps(global_value, sort_keys=True,
                                              separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(6, COUNT)
        for index, value in enumerate(values):
            self.assertEqual(expected, value["globalDigest"])
            self.assertEqual(COUNT, value["shardCount"])
            self.assertEqual(MODULES[index::COUNT], value["assignedModules"])
        self.assertEqual([MODULES[0], GATE], values[0]["assignedModules"])
        self.assertEqual(MODULES, sorted(name for value in values for name in value["assignedModules"]))

    def test_invalid_global_or_shard_inputs_refuse_before_receipt_creation(self):
        changes = [{"index": True}, {"index": -1}, {"index": COUNT},
                   {"modules": list(reversed(MODULES))}, {"modules": MODULES + [MODULES[-1]]},
                   {"modules": ["os"]}, {"modules": [MODULES[0] + ".C.test_one"]},
                   {"baseline": "a" * 39}, {"head": "z" * 40},
                   {"fingerprint": "c" * 63}, {"run_id": "0"},
                   {"run_id": "foreign/attempt"}, {"attempt": "0"}, {"attempt": "01"}]
        for change in changes:
            with self.subTest(fields=sorted(change)):
                values = {"baseline": "a" * 40, "head": "b" * 40,
                          "fingerprint": "c" * 64, "modules": MODULES,
                          "index": 0, "run_id": "987654321", "attempt": "4"}
                values.update(change)
                with self.assertRaises(REJECTIONS):
                    subject.plan_value(**values)

    def test_plan_schema_partition_and_digest_cannot_be_aliased_or_tampered(self):
        for changes in ({"schemaVersion": True}, {"shardCount": True}, {"shardCount": 3}, {"shardCount": 2},
                        {"assignedModules": []}, {"globalDigest": "0" * 64},
                        {"unexpected": PRIVATE}):
            with self.subTest(fields=sorted(changes)):
                value = plan(0)
                value.update(changes)
                with self.assertRaises(REJECTIONS):
                    subject.validate_plan(value)


class EvidenceJournalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="vc-public-evidence-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def evidence(self, name="public", index=0, modules=None):
        evidence = subject.Evidence(self.root / name, plan(index, modules), stream=io.StringIO())
        self.addCleanup(lambda: evidence.journal.close() if not evidence.journal.closed else None)
        return evidence

    def test_directory_is_fresh_and_previous_attempt_bytes_are_never_reused(self):
        evidence = self.evidence()
        self.assertFalse(evidence.finish(2, False))
        before = {path.name: path.read_bytes() for path in evidence.directory.iterdir()}
        with self.assertRaises(FileExistsError):
            self.evidence()
        self.assertEqual(before, {path.name: path.read_bytes() for path in evidence.directory.iterdir()})
        self.assertFalse(read(evidence.directory / "summary.json")["successful"])

    def test_physical_journal_projection_retains_only_complete_public_events(self):
        evidence = self.evidence()
        owned = self.root / "runner" / "worker-0000"
        owned.mkdir(parents=True)
        path = owned / "timings.jsonl"
        started = {"event": "started", "publicTestId": MODULES[0] + ".C.test_one",
                   "testId": PRIVATE, "skipReason": PRIVATE, "path": PRIVATE}
        finished = {**started, "event": "finished", "outcome": "success", "elapsedSeconds": 0.25}
        partial = json.dumps(finished).encode()
        path.write_bytes(json.dumps(started).encode() + b"\n" + partial)
        offsets = {}
        evidence.observe(owned.parent, MODULES, offsets)
        rows = [json.loads(line) for line in (evidence.directory / "events.jsonl").read_text().splitlines()]
        self.assertEqual(["selection", "started"], [row["event"] for row in rows])
        with path.open("ab") as stream:
            stream.write(b"\n")
        evidence.observe(owned.parent, MODULES, offsets)
        evidence.observe(owned.parent, MODULES, offsets)
        raw = (evidence.directory / "events.jsonl").read_text()
        rows = [json.loads(line) for line in raw.splitlines()]
        self.assertEqual(["selection", "started", "finished"], [row["event"] for row in rows])
        self.assertEqual(0.25, rows[-1]["elapsedSeconds"])
        self.assertNotIn(PRIVATE, raw)
        self.assertNotIn(PRIVATE, evidence.stream.getvalue())

    def test_truncated_journal_cannot_replay_already_observed_events(self):
        evidence = self.evidence()
        owned = self.root / "runner" / "worker-0000"
        owned.mkdir(parents=True)
        path = owned / "timings.jsonl"
        path.write_text(json.dumps({"event": "started", "publicTestId": MODULES[0] + ".C.test_one"}) + "\n")
        offsets = {}
        evidence.observe(owned.parent, MODULES, offsets)
        path.write_bytes(b"")
        with self.assertRaises(ValueError):
            evidence.observe(owned.parent, MODULES, offsets)

    def test_oversized_private_line_refuses_without_exposing_its_bytes(self):
        evidence = self.evidence()
        owned = self.root / "runner" / "worker-0000"
        owned.mkdir(parents=True)
        path = owned / "timings.jsonl"
        raw = PRIVATE.encode() + b"x" * 16385 + b"\n"
        path.write_bytes(raw)
        with self.assertRaises(ValueError):
            evidence.observe(owned.parent, MODULES, {})
        self.assertEqual(raw, path.read_bytes())
        self.assertNotIn(PRIVATE, (evidence.directory / "events.jsonl").read_text())

    def test_final_observation_drains_more_than_one_live_poll_batch(self):
        evidence = self.evidence()
        owned = self.root / "runner" / "worker-0000"
        owned.mkdir(parents=True)
        event = {"event": "finished", "publicTestId": MODULES[0] + ".C.test_one",
                 "outcome": "success", "elapsedSeconds": 0}
        line = json.dumps(event).encode() + b"\n"
        path = owned / "timings.jsonl"
        path.write_bytes(line * 1001)
        offsets = {}
        evidence.observe(owned.parent, MODULES, offsets, final=True)
        rows = (evidence.directory / "events.jsonl").read_text().splitlines()
        self.assertEqual(1002, len(rows))
        self.assertEqual(path.stat().st_size, offsets["worker-0000"])

    def test_terminal_partial_line_refuses_instead_of_claiming_full_observation(self):
        evidence = self.evidence()
        owned = self.root / "runner" / "worker-0000"
        owned.mkdir(parents=True)
        path = owned / "timings.jsonl"
        path.write_text(json.dumps({"event": "started", "publicTestId": MODULES[0] + ".C.test_one"}))
        with self.assertRaises(ValueError):
            evidence.observe(owned.parent, MODULES, {}, final=True)
        self.assertFalse((evidence.directory / "summary.json").exists())
        rows = [json.loads(line) for line in (evidence.directory / "events.jsonl").read_text().splitlines()]
        self.assertEqual(["selection"], [row["event"] for row in rows])
        self.assertEqual("incomplete", rows[0]["state"])

    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"),
                         "owned nonblocking FIFO fixture required")
    def test_fifo_receipt_and_journal_refuse_before_any_blocking_read(self):
        evidence = self.evidence()
        owned = self.root / "runner" / "worker-0000"
        owned.mkdir(parents=True)
        receipt = self.root / "receipt.fifo"
        journal = owned / "timings.jsonl"
        for path in (receipt, journal):
            os.mkfifo(path, 0o600)
        actual_open = os.open
        def guarded_open(path, flags, *args, **kwargs):
            if Path(path) in (receipt, journal):
                self.assertTrue(flags & os.O_NONBLOCK, "FIFO reader must refuse without a blocking open")
            return actual_open(path, flags, *args, **kwargs)
        with mock.patch.object(os, "open", side_effect=guarded_open):
            with self.assertRaises(ValueError):
                subject.read_json(receipt)
            with self.assertRaises(ValueError):
                evidence.observe(owned.parent, MODULES, {})
        self.assertEqual(["plan.json", "events.jsonl"],
                         sorted((path.name for path in evidence.directory.iterdir()), reverse=True))

    def test_finish_cannot_claim_success_for_drift_or_uncovered_commands(self):
        cases = [(0, False, []), (7, True, []), (0, True, []),
                 (0, True, [{"modules": plan(1)["assignedModules"], "returncode": 0, "state": "complete"}]),
                 (0, True, [{"modules": plan(0)["assignedModules"], "returncode": 0, "state": "failed"}])]
        for index, (code, unchanged, commands) in enumerate(cases):
            with self.subTest(index=index):
                evidence = self.evidence("finish-" + str(index))
                evidence.commands.extend(commands)
                self.assertFalse(evidence.finish(code, unchanged))
                summary = read(evidence.directory / "summary.json")
                self.assertEqual("incomplete", summary["state"])
                self.assertIs(summary["successful"], False)

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "nofollow journal reader required")
    def test_worker_or_journal_symlink_never_exposes_another_file(self):
        for linked_directory in (False, True):
            with self.subTest(linked_directory=linked_directory):
                suffix = "directory" if linked_directory else "file"
                evidence = self.evidence("public-" + suffix)
                report = self.root / ("runner-" + suffix)
                report.mkdir()
                foreign = self.root / ("independent-" + suffix)
                foreign.mkdir()
                (foreign / "timings.jsonl").write_text(PRIVATE + "\n")
                leaf = report / "worker-0000"
                if linked_directory:
                    leaf.symlink_to(foreign, target_is_directory=True)
                else:
                    leaf.mkdir()
                    (leaf / "timings.jsonl").symlink_to(foreign / "timings.jsonl")
                with self.assertRaises((OSError, ValueError)):
                    evidence.observe(report, MODULES, {})
                self.assertNotIn(PRIVATE, (evidence.directory / "events.jsonl").read_text())
                self.assertEqual(PRIVATE + "\n", (foreign / "timings.jsonl").read_text())


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
                     "actual managed runner requires private POSIX custody")
class ActualReceiptTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="vc-shard-receipts-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name).resolve()
        cls.pairs = {}
        for label, modules in (("ordinary", MODULES), ("empty-bucket", MODULES[:1]), ("empty", [])):
            base = cls.root / label
            base.mkdir(mode=0o700)
            checkout = base / "checkout"
            package = checkout / "agent_tools" / "tests"
            package.mkdir(parents=True)
            (package.parent / "__init__.py").write_text("")
            (package / "__init__.py").write_text("")
            for module in modules:
                (checkout / (module.replace(".", "/") + ".py")).write_text(
                    "import unittest\nclass C(unittest.TestCase):\n def test_owned(self): pass\n")
            directories = []
            for index in range(COUNT):
                value = plan(index, modules)
                evidence = subject.Evidence(base / ("public-" + str(index)), value, stream=io.StringIO())
                try:
                    assigned = value["assignedModules"]
                    if GATE in assigned:
                        code = evidence.run([sys.executable, "-B", "-m", "unittest", GATE],
                                            checkout, [GATE])
                        if code:
                            raise AssertionError("Owned gate command failed: " + str(code))
                    remaining = [name for name in assigned if name != GATE]
                    if remaining:
                        input_plan = base / ("input-" + str(index) + ".json")
                        write(input_plan, {"schemaVersion": 1, "sourceFingerprint": value["sourceFingerprint"],
                                           "modules": remaining, "maxWorkers": 1})
                        report = base / ("run-" + str(index))
                        code = evidence.run([sys.executable, "-B", runner.__file__, "--plan-file", str(input_plan),
                                             "--report-dir", str(report)], checkout, remaining, report)
                        if code:
                            raise AssertionError("Owned managed command failed: " + str(code))
                    if not evidence.finish(0, True):
                        raise AssertionError("Actual owned commands did not complete")
                finally:
                    if not evidence.journal.closed:
                        evidence.journal.close()
                directories.append(evidence.directory)
            cls.pairs[label] = directories

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="vc-receipt-control-")
        self.addCleanup(temporary.cleanup)
        self.case = Path(temporary.name).resolve()

    def receipts(self, label="ordinary", name="copy"):
        destination = self.case / name
        destination.mkdir()
        copies = []
        for index, source in enumerate(self.pairs[label]):
            target = destination / str(index)
            shutil.copytree(source, target)
            copies.append(target)
        return copies

    def summary_change(self, directories, change, index=0):
        path = directories[index] / "summary.json"
        value = read(path)
        change(value)
        write(path, value)

    def nongate(self, summary):
        return next(command for command in summary["commands"] if command["modules"] != [GATE])

    def rejects(self, directories, results=None):
        with self.assertRaises(REJECTIONS):
            subject.verify(directories, SUCCESS if results is None else results)

    def test_exact_actual_receipts_of_every_shard_cover_one_global_plan(self):
        directories = self.receipts()
        result = subject.verify(directories, SUCCESS)
        self.assertEqual({"schemaVersion": 1, "successful": True,
                          "globalDigest": plan(0)["globalDigest"], "coveredModules": len(MODULES)}, result)
        self.assertEqual(result, subject.verify(list(reversed(directories)), SUCCESS))
        summaries = [read(path / "summary.json") for path in directories]
        gate = next(command for summary in summaries for command in summary["commands"] if command["modules"] == [GATE])
        self.assertEqual({"modules", "returncode", "state"}, set(gate))
        for summary in summaries:
            for command in summary["commands"]:
                if command is gate:
                    continue
                self.assertIs(command["workerClosure"], True)
                self.assertEqual(set(COUNTS), set(command["observedCounts"]))
                self.assertEqual(1, command["observedCounts"]["testsRun"])

    def test_missing_duplicate_or_extra_receipts_refuse(self):
        directories = self.receipts()
        for candidate in ([], directories[:1], directories[:-1], directories[:-1] + directories[:1],
                          directories + directories[:1]):
            with self.subTest(receipt_count=len(candidate)):
                self.rejects(candidate)

    def test_actual_parent_results_must_all_be_success(self):
        directories = self.receipts()
        for results in (["failed"] + SUCCESS[1:], SUCCESS[:-1] + ["skipped"], ["cancelled"] + SUCCESS[1:],
                        SUCCESS[:-1] + ["timed_out"], SUCCESS[:-1], SUCCESS + ["success"], ["success", "success"]):
            with self.subTest(results=results):
                self.rejects(directories, results)

    def test_global_run_attempt_head_baseline_fingerprint_and_digest_must_match(self):
        for field, replacement in (("run_id", "987654322"), ("attempt", "5"),
                                   ("head", "d" * 40), ("baseline", "e" * 40),
                                   ("fingerprint", "f" * 64)):
            with self.subTest(field=field):
                directories = self.receipts(name=field)
                changed = plan(1, **{field: replacement})
                write(directories[1] / "plan.json", changed)
                self.summary_change(directories, lambda summary: summary.update(globalDigest=changed["globalDigest"]), 1)
                self.rejects(directories)
        directories = self.receipts(name="digest")
        value = read(directories[1] / "plan.json")
        value["globalDigest"] = "0" * 64
        write(directories[1] / "plan.json", value)
        self.rejects(directories)

    def test_coherent_previous_run_attempt_or_head_cannot_satisfy_current_invocation(self):
        expected = {"runId": "987654321", "runAttempt": "4", "head": "b" * 40}
        self.assertIs(subject.verify(self.receipts(name="current"), SUCCESS,
                                     expected=expected)["successful"], True)
        for field, replacement in (("run_id", "987654320"), ("attempt", "3"), ("head", "d" * 40)):
            with self.subTest(field=field):
                directories = self.receipts(name="previous-" + field)
                for index, directory in enumerate(directories):
                    changed = plan(index, **{field: replacement})
                    write(directory / "plan.json", changed)
                    self.summary_change(directories, lambda summary: summary.update(globalDigest=changed["globalDigest"]), index)
                with self.assertRaises(REJECTIONS):
                    subject.verify(directories, SUCCESS, expected=expected)

    def test_corrupt_missing_or_extra_receipt_fields_refuse(self):
        for filename in ("plan.json", "summary.json"):
            for mode in ("corrupt", "missing", "extra"):
                with self.subTest(filename=filename, mode=mode):
                    directories = self.receipts(name=filename + "-" + mode)
                    path = directories[0] / filename
                    if mode == "corrupt":
                        path.write_bytes(b"{invalid\n")
                    elif mode == "missing":
                        path.unlink()
                    else:
                        value = read(path)
                        value["unexpected"] = PRIVATE
                        write(path, value)
                    self.rejects(directories)

    def test_failed_skipped_or_incomplete_summary_never_satisfies_coverage(self):
        changes = [{"state": "incomplete"}, {"state": "failed"}, {"state": "skipped"},
                   {"successful": False}, {"sourceUnchanged": False},
                   {"successful": 1}, {"sourceUnchanged": 1}, {"schemaVersion": True}]
        for index, changes_ in enumerate(changes):
            with self.subTest(fields=changes_):
                directories = self.receipts(name="summary-" + str(index))
                self.summary_change(directories, lambda summary: summary.update(changes_))
                self.rejects(directories)
        directories = self.receipts(name="bool-index")
        self.summary_change(directories, lambda summary: summary.update(shardIndex=True), 1)
        self.rejects(directories)

    def test_command_failure_boolean_exit_or_missing_worker_closure_refuses(self):
        changes = [{"returncode": 7}, {"returncode": False}, {"state": "failed"},
                   {"state": "skipped"}, {"state": "incomplete"},
                   {"workerClosure": False}, {"workerClosure": 1}]
        for index, changes_ in enumerate(changes):
            with self.subTest(fields=changes_):
                directories = self.receipts(name="command-" + str(index))
                self.summary_change(directories, lambda summary: self.nongate(summary).update(changes_))
                self.rejects(directories)
        directories = self.receipts(name="no-closure")
        self.summary_change(directories, lambda summary: self.nongate(summary).pop("workerClosure"))
        self.rejects(directories)

    def test_malformed_commands_counts_or_empty_state_contradiction_refuse(self):
        for mode in ("none-command", "counts-list", "nonempty-empty-state"):
            with self.subTest(mode=mode):
                directories = self.receipts(name=mode)
                def mutate(summary):
                    if mode == "none-command":
                        summary["commands"] = [None]
                    elif mode == "counts-list":
                        self.nongate(summary)["observedCounts"] = list(COUNTS)
                    else:
                        summary["state"] = "empty-shard"
                self.summary_change(directories, mutate)
                self.rejects(directories)

    def test_nongate_counts_are_exact_typed_nonnegative_and_consistent_with_success(self):
        for key in COUNTS:
            for invalid in (True, -1, 0.5):
                with self.subTest(key=key, invalid_type=type(invalid).__name__):
                    directories = self.receipts(name=key + "-" + type(invalid).__name__)
                    self.summary_change(directories, lambda summary: self.nongate(summary)["observedCounts"].update({key: invalid}))
                    self.rejects(directories)
        for key in ("failures", "errors", "unexpectedSuccesses"):
            directories = self.receipts(name="unsuccessful-" + key)
            self.summary_change(directories, lambda summary: self.nongate(summary)["observedCounts"].update({key: 1}))
            self.rejects(directories)
        for mode in ("missing", "extra"):
            directories = self.receipts(name="counts-" + mode)
            def mutate(summary):
                counts = self.nongate(summary)["observedCounts"]
                counts.pop("skipped") if mode == "missing" else counts.update(unexpected=0)
            self.summary_change(directories, mutate)
            self.rejects(directories)

    def test_only_the_single_gate_command_can_omit_worker_closure(self):
        directories = self.receipts()
        def mutate(summary):
            gate = next(command for command in summary["commands"] if command["modules"] == [GATE])
            gate["workerClosure"] = True
        self.summary_change(directories, mutate)
        self.rejects(directories)

    def test_missing_duplicate_crossed_or_reordered_module_coverage_refuses(self):
        for mode in ("missing", "duplicate", "crossed", "reordered"):
            with self.subTest(mode=mode):
                directories = self.receipts(name=mode)
                def mutate(summary):
                    if mode == "missing":
                        summary["commands"].pop()
                    elif mode == "duplicate":
                        summary["commands"].append(copy.deepcopy(summary["commands"][-1]))
                    elif mode == "crossed":
                        self.nongate(summary)["modules"] = plan(1)["assignedModules"]
                    else:
                        summary["commands"].reverse()
                self.summary_change(directories, mutate)
                self.rejects(directories)

    def test_empty_bucket_is_explicit_and_bound_to_the_same_actual_global_plan(self):
        directories = self.receipts("empty-bucket")
        result = subject.verify(directories, SUCCESS)
        self.assertEqual(1, result["coveredModules"])
        empty = read(directories[1] / "summary.json")
        self.assertEqual("empty-shard", empty["state"])
        self.assertEqual([], empty["commands"])
        self.summary_change(directories, lambda summary: summary.update(successful=False), 1)
        self.rejects(directories)

    def test_all_empty_buckets_still_require_every_actual_successful_receipt(self):
        directories = self.receipts("empty")
        result = subject.verify(directories, SUCCESS)
        self.assertEqual(0, result["coveredModules"])
        for directory in directories:
            self.assertEqual("empty-shard", read(directory / "summary.json")["state"])
        self.rejects(directories, SUCCESS[:-1] + ["skipped"])
        self.rejects(directories[:1])
        self.rejects(directories[:-1])

    def test_whole_two_shard_verifier_cannot_prove_the_hosted_receipts(self):
        # RED on the whole cc2873b5 verifier: it accepts only two receipts of a
        # two-way plan, so it refuses the complete hosted coverage; GREEN now.
        path = fixture.FIXTURE / "hosted-capacity.evidence.before.source"
        before = {"__name__": "preserved_agent_ci_evidence", "__file__": str(path)}
        exec(compile(fixture.preserved("evidence.before.source"), str(path), "exec"), before)
        directories = self.receipts()
        expected = {"runId": "987654321", "runAttempt": "4", "head": "b" * 40}
        outcomes = {}
        for label, verify in (("before", before["verify"]), ("current", subject.verify)):
            try:
                outcomes[label] = verify(directories, SUCCESS, expected=expected)
            except REJECTIONS as error:
                outcomes[label] = type(error).__name__ + ": " + str(error)
        try:
            before["validate_plan"](plan(0))
        except REJECTIONS as error:
            outcomes["beforePlan"] = type(error).__name__ + ": " + str(error)
        print(json.dumps({"event": "hosted-coverage-causal", "outcomes": outcomes}, sort_keys=True))
        self.assertEqual("ValueError: Both actual shard jobs must succeed", outcomes["before"], outcomes)
        self.assertEqual("ValueError: Invalid public shard schema", outcomes.get("beforePlan"), outcomes)
        self.assertEqual({"schemaVersion": 1, "successful": True, "globalDigest": plan(0)["globalDigest"],
                          "coveredModules": len(MODULES)}, outcomes["current"], outcomes)

    def test_owned_controller_cancellation_retains_started_and_closes_same_runner(self):
        checkout = self.case / "checkout"
        package = checkout / "agent_tools" / "tests"
        package.mkdir(parents=True)
        (package.parent / "__init__.py").write_text("")
        (package / "__init__.py").write_text("")
        module = "agent_tools.tests.test_evidence_cancel"
        ready = self.case / "ready"
        (package / "test_evidence_cancel.py").write_text(
            "import time,unittest\nfrom pathlib import Path\nclass C(unittest.TestCase):\n"
            " def test_wait(self):\n  Path(" + repr(str(ready)) + ").write_bytes(b'READY')\n"
            "  time.sleep(10)\n")
        public_plan = self.case / "public-plan.json"
        value = plan(0, [module])
        write(public_plan, value)
        runner_plan = self.case / "runner-plan.json"
        write(runner_plan, {"schemaVersion": 1, "sourceFingerprint": value["sourceFingerprint"],
                            "modules": [module], "maxWorkers": 1})
        public = self.case / "public"
        report = self.case / "run"
        controller = self.case / "controller.py"
        controller.write_text(
            "import json,sys\nfrom pathlib import Path\nsys.path.insert(0,sys.argv[1])\n"
            "from agent_tools import agent_ci_evidence as evidence\n"
            "root,public_plan,runner_plan,public,report,runner=map(Path,sys.argv[2:])\n"
            "projection=evidence.Evidence(public,json.loads(public_plan.read_text()),heartbeat=0.1)\n"
            "code=2\ntry:\n"
            " code=projection.run([sys.executable,'-B',str(runner),'--plan-file',str(runner_plan),"
            "'--report-dir',str(report)],root,projection.plan['assignedModules'],report)\n"
            "finally:\n projection.finish(code,True)\n"
            "raise SystemExit(code)\n")
        repository = Path(subject.__file__).resolve().parents[1]
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        env.pop("DYLD_INSERT_LIBRARIES", None)
        with (self.case / "controller.stdout").open("xb") as stdout, \
             (self.case / "controller.stderr").open("xb") as stderr:
            process = subprocess.Popen([sys.executable, "-B", str(controller), str(repository),
                                        str(checkout), str(public_plan), str(runner_plan), str(public),
                                        str(report), str(Path(runner.__file__).resolve())],
                                       cwd=self.case, env=env, stdout=stdout, stderr=stderr)
            try:
                deadline = time.monotonic() + 6
                def admitted():
                    if not ready.exists():
                        return False
                    try:
                        rows = (public / 'events.jsonl').read_bytes().split(b'\n')[:-1]
                    except FileNotFoundError:
                        return False
                    return any(json.loads(row).get('event') == 'started' for row in rows)
                while not admitted() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(admitted(), "Owned controller and wait test never reached READY")
                self.assertEqual(b"READY", ready.read_bytes())
                process.send_signal(signal.SIGTERM)
                self.assertNotEqual(0, process.wait(timeout=20))
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
        summary = read(public / "summary.json")
        self.assertIs(summary["successful"], False)
        self.assertEqual("incomplete", summary["state"])
        events = (public / "events.jsonl").read_text()
        self.assertNotIn(PRIVATE, events)
        self.assertIn("started", [json.loads(line)["event"] for line in events.splitlines()])
        terminal = read(report / "report.json")
        self.assertEqual("cancelled", terminal["state"])
        self.assertIs(terminal["successful"], False)
        self.assertIs(terminal["replayAllowed"], False)
        self.assertEqual(1, len(terminal["workers"]))
        worker = terminal["workers"][0]
        for key in ("reaped", "sessionAbsent", "fixtureRootRemoved"):
            self.assertIs(worker[key], True)
        self.assertIs(worker["descendantLeak"], False)
        self.assertFalse((report / "worker-0000" / "result.json").exists())


if __name__ == "__main__":
    unittest.main()

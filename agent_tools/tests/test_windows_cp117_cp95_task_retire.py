"""Deterministic no-replay, archive and lease regressions; PS5 causal case on Windows."""
from __future__ import annotations

import base64
import contextlib
import copy
import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest import mock

from agent_tools import windows_cp117_cp95_task_retire as retire

DESC = ("windows-cp117", "/qga", 123, 456, "S-1-5-21-1-2-3-1002")
SPECS = [{"profile": p, "task": "VpnControlMcpCp95-" + p, "actionSha256": "a" * 64,
          "sid": DESC[4], "correlationId": "11111111-1111-4111-8111-111111111111"}
         for p in retire.retained._PROFILE_NAMES]


def archives():
    raw = b'<Task><Actions><Exec>fixed historical XML</Exec></Actions></Task>'
    return [{"profile": s["profile"], "task": s["task"], "actionSha256": s["actionSha256"],
             "result": r, "taskResult": 0 if r == "succeeded" else 1, "lastRunTicks": 123456,
             "xmlSha256": hashlib.sha256(raw).hexdigest(), "xmlLength": len(raw),
             "xmlGzip": base64.b64encode(gzip.compress(raw, mtime=0)).decode()}
            for s, r in zip(SPECS, retire._RESULTS)]


class Cp95TaskRetireTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.patches = contextlib.ExitStack()
        self.addCleanup(self.patches.close)
        self.patches.enter_context(mock.patch.object(retire.retained, "_lease_read_lock", return_value=contextlib.nullcontext(self.root)))
        self.active = self.patches.enter_context(mock.patch.object(retire.lease, "_active", return_value=None))
        self.descriptor = self.patches.enter_context(mock.patch.object(retire.base, "_descriptor", return_value=(object(), object(), DESC)))
        self.specs = self.patches.enter_context(mock.patch.object(retire.retained, "_configured_specs", return_value=SPECS))
        self.observer = self.patches.enter_context(mock.patch.object(retire.retained, "status", return_value={"state": "ready"}))
        self.rows = archives()
        self.snapshots = [retire._validate_archive(a, s) for a, s in zip(self.rows, SPECS)]
        self.script, self.intent = retire._plan(retire._binding(DESC, self.snapshots), SPECS)

    def terminal(self):
        return {"binding": self.intent, "archives": [{**a, "bindingSha256": self.intent["bindingSha256"]} for a in self.rows],
                "terminal": {"retirementCorrelationId": retire._RETIREMENT, "state": "retired",
                             "bindingSha256": self.intent["bindingSha256"], "actionSha256": self.intent["actionSha256"]},
                "absent": True}

    def run_value(self, _root, _descriptor, source):
        if source == self.script:
            self.assertEqual(self.intent, retire.guards.secure_read(self.root / retire._DIR / "intent.json"))
            return {"submitted": True}
        if source == retire._reader(SPECS):
            return self.terminal()
        if "Parser]::ParseInput" in source:
            return {"valid": True}
        return {"archives": self.rows}

    def reserve(self):
        retire.guards.secure_write_create(self.root / retire._DIR / "intent.json", self.intent)

    def test_archive_hash_binding_and_gzip_bomb(self):
        self.assertEqual(self.snapshots[0], retire._validate_archive(self.rows[0], SPECS[0]))
        for update in ({"xmlSha256": "0" * 64}, {"xmlLength": 131073}, {"xmlGzip": "invalid!"},
                       {"task": "foreign"}, {"actionSha256": "b" * 64}, {"taskResult": 267009},
                       {"lastRunTicks": 0}, {"result": "failed"},
                       {"xmlGzip": base64.b64encode(gzip.compress(b'x' * 131073)).decode()}):
            with self.subTest(update=update), self.assertRaises(retire.WindowsCp117Cp95TaskRetireError):
                retire._validate_archive({**self.rows[0], **update}, SPECS[0])

    def test_start_durable_intent_and_repeated_start_never_redispatch(self):
        preserved = self.root / 'original-installer.exe'
        preserved.write_bytes(b'original')
        with mock.patch.object(retire, "_run", side_effect=self.run_value) as run:
            self.assertEqual("retired", retire.start(self.root, {})["state"])
            first = (self.root / retire._DIR / "intent.json").read_bytes()
            self.assertEqual("retired", retire.start(self.root, {})["state"])
        self.assertEqual(1, sum(call.args[2] == self.script for call in run.call_args_list))
        self.assertEqual(first, (self.root / retire._DIR / "intent.json").read_bytes())
        self.assertEqual(b'original', preserved.read_bytes())
        self.assertEqual(0o600, (self.root / retire._DIR / "intent.json").stat().st_mode & 0o777)

    def test_unknown_after_delete_missing_terminal_never_inferred_or_replayed(self):
        self.reserve()
        with mock.patch.object(retire, "_run", return_value=None) as run:
            for action in (retire.start, retire.status):
                result = action(self.root, {})
                self.assertEqual("unknown", result["state"])
                self.assertFalse(result["replayAllowed"])
        self.assertTrue(all(c.args[2] == retire._reader(SPECS) for c in run.call_args_list))

    def test_finish_recovery_requires_all_archives_and_absence_before_terminal_write(self):
        """The measured terminal-absent crash window never runs unregister again."""
        self.reserve()
        source = retire._finish_script(SPECS, self.intent)
        self.assertNotIn("Unregister-ScheduledTask", source)
        self.assertLess(source.index("VerifyArchive $a"), source.index("Write-SecureJsonCreate 'terminal.json'"))
        self.assertLess(source.index("Where-Object {$_.TaskName -ceq $s.task}"), source.index("Write-SecureJsonCreate 'terminal.json'"))
        self.assertLess(source.index("$children.Count -ne 6"), source.index("Write-SecureJsonCreate 'terminal.json'"))

        def run_value(_root, _descriptor, candidate):
            if "Parser]::ParseInput" in candidate:
                return {"valid": True}
            if candidate == source:
                return {"finished": True}
            if candidate == retire._reader(SPECS):
                return self.terminal()
            raise AssertionError("unexpected remote program")

        with mock.patch.object(retire, "_run", side_effect=run_value) as run:
            result = retire.workflow(self.root, "finish", {})
        self.assertEqual({"state": "retired", "phase": "complete"},
                         {k: result[k] for k in ("state", "phase")})
        self.assertEqual(1, sum(call.args[2] == source for call in run.call_args_list))

    def test_finish_without_the_consumed_original_intent_cannot_admit_or_start(self):
        with mock.patch.object(retire, "_run", side_effect=AssertionError("no remote call")):
            result = retire.workflow(self.root, "finish", {})
        self.assertEqual(("blocked", "intent"), (result["state"], result["phase"]))
        self.assertFalse((self.root / retire._DIR / "intent.json").exists())

    def test_finish_diagnostic_is_read_only_and_returns_only_a_finite_prewrite_phase(self):
        self.reserve()
        source = retire._finish_diagnostic_script(SPECS, self.intent)
        self.assertNotIn("Unregister-ScheduledTask", source)
        self.assertEqual(1, source.count("Write-SecureJsonCreate"))  # helper definition only
        for phase in retire._FINISH_DIAGNOSTIC_PHASES:
            with self.subTest(phase=phase):
                def run_value(_root, _descriptor, candidate):
                    if "Parser]::ParseInput" in candidate:
                        return {"valid": True}
                    self.assertEqual(source, candidate)
                    return {"phase": phase}
                with mock.patch.object(retire, "_run", side_effect=run_value):
                    self.assertEqual(phase, retire.finish_diagnose(self.root, {})["phase"])
        with mock.patch.object(retire, "_run", side_effect=[{"valid": True}, {"phase": ["private"]}]):
            self.assertEqual("unknown", retire.finish_diagnose(self.root, {})["phase"])

    def test_finish_diagnostic_keeps_each_fixed_task_position_distinct(self):
        """The native task blocker must not collapse five fixed task checks."""
        self.reserve()
        source = retire._finish_diagnostic_script(SPECS, self.intent)
        for phase in ("task-query",) + tuple("task-present-" + str(i) for i in range(1, 6)):
            with self.subTest(phase=phase):
                with mock.patch.object(retire, "_run", side_effect=[{"valid": True}, {"phase": phase}]):
                    self.assertEqual(phase, retire.finish_diagnose(self.root, {})["phase"])
        self.assertIn("'task-present-'+$index", source)

    def test_finish_recovery_generation_or_archive_failure_cannot_dispatch_terminal_write(self):
        self.reserve()
        source = retire._finish_script(SPECS, self.intent)
        self.descriptor.side_effect = [(object(), object(), DESC), (object(), object(), (*DESC[:2], 999, *DESC[3:]))]
        with mock.patch.object(retire, "_run", return_value={"valid": True}) as run:
            result = retire.workflow(self.root, "finish", {})
        self.assertEqual(("blocked", "generation"), (result["state"], result["phase"]))
        self.assertFalse(any(call.args[2] == source for call in run.call_args_list))

        self.descriptor.side_effect = None
        self.descriptor.return_value = (object(), object(), DESC)
        wrong = copy.deepcopy(self.intent)
        wrong["bindingSha256"] = "0" * 64
        # A substituted local intent cannot get as far as its prospective
        # terminal writer.  Preserve the original durable intent unchanged.
        (self.root / retire._DIR / "intent.json").unlink()
        retire.guards.secure_write_create(self.root / retire._DIR / "intent.json", wrong)
        with mock.patch.object(retire, "_run", side_effect=AssertionError("no guest dispatch")):
            result = retire.workflow(self.root, "finish", {})
        self.assertEqual(("blocked", "intent"), (result["state"], result["phase"]))

    def test_tail_successor_only_unregs_measured_fifth_after_prefix_proof(self):
        self.reserve()
        source, child = retire._tail_plan(SPECS, self.intent)
        self.assertEqual(1, source.count("Unregister-ScheduledTask"))
        self.assertIn("-TaskName $last.task", source)
        self.assertLess(source.index("for($index=0;$index -lt 4"), source.index("Write-SecureJsonCreate 'binding.json'"))
        self.assertLess(source.index("$parentChildren.Count -ne 6"), source.index("Write-SecureJsonCreate 'binding.json'"))
        self.assertLess(source.index("$parentTerminal"), source.index("Unregister-ScheduledTask"))
        self.assertLess(source.index("if(Test-Path -LiteralPath $JournalRoot){throw 'TAIL_EXISTS'}"), source.index("Write-SecureJsonCreate 'binding.json'"))
        self.assertLess(source.index("Write-SecureJsonCreate 'binding.json'"), source.index("Unregister-ScheduledTask"))
        self.assertLess(source.index("Unregister-ScheduledTask"), source.index("Write-SecureJsonCreate 'terminal.json'"))

        def run_value(_root, _descriptor, candidate):
            if "Parser]::ParseInput" in candidate:
                return {"valid": True}
            if candidate == source:
                self.assertEqual(child, retire.guards.secure_read(self.root / retire._TAIL_DIR / "intent.json"))
                return {"submitted": True}
            if candidate == retire._tail_reader():
                return {"binding": child["binding"], "terminal": {
                    "tailCorrelationId": retire._TAIL, "state": "completed",
                    "parentRetirementCorrelationId": retire._RETIREMENT,
                    "parentBindingSha256": self.intent["bindingSha256"],
                    "parentActionSha256": self.intent["actionSha256"],
                    "actionSha256": child["actionSha256"],
                }}
            if candidate == retire._reader(SPECS):
                return self.terminal()
            raise AssertionError("unexpected remote program")

        with mock.patch.object(retire, "_run", side_effect=run_value) as run:
            result = retire.tail_start(self.root, {})
        self.assertEqual(("retired", "complete"), (result["state"], result["phase"]))
        self.assertEqual(1, sum(call.args[2] == source for call in run.call_args_list))
        self.assertEqual(self.intent, retire.guards.secure_read(self.root / retire._DIR / "intent.json"))

    def test_tail_successor_never_replays_when_child_intent_or_race_exists(self):
        self.reserve()
        source, child = retire._tail_plan(SPECS, self.intent)
        retire.guards.secure_write_create(self.root / retire._TAIL_DIR / "intent.json", child)
        with mock.patch.object(retire, "_run", side_effect=AssertionError("no replay")):
            self.assertEqual("unknown", retire.tail_start(self.root, {})["state"])

        (self.root / retire._TAIL_DIR / "intent.json").unlink()
        original = retire.guards.secure_write_create
        def race(path, value):
            original(path, {"foreign": "preserved"})
            original(path, value)
        with mock.patch.object(retire, "_parse", return_value=True), mock.patch.object(retire, "_run", side_effect=AssertionError("no dispatch")), mock.patch.object(retire.guards, "secure_write_create", side_effect=race):
            result = retire.tail_start(self.root, {})
        self.assertEqual("unknown", result["state"])
        self.assertEqual({"foreign": "preserved"}, retire.guards.secure_read(self.root / retire._TAIL_DIR / "intent.json"))

    def test_tail_status_requires_exact_linked_child_terminal_before_parent_retired(self):
        self.reserve()
        _source, child = retire._tail_plan(SPECS, self.intent)
        retire.guards.secure_write_create(self.root / retire._TAIL_DIR / "intent.json", child)
        with mock.patch.object(retire, "_parse", return_value=True), mock.patch.object(retire, "_run", return_value={"binding": child["binding"], "terminal": {}}):
            result = retire._tail_status_locked(self.root, self.root, self.intent, DESC, SPECS)
        self.assertEqual(("unknown", "terminal", retire._TAIL),
                         (result["state"], result["phase"], result["tailCorrelationId"]))

    def test_tail_status_is_read_only_and_never_admits_a_missing_child(self):
        self.reserve()
        with mock.patch.object(retire, "_run", side_effect=AssertionError("no guest call")):
            result = retire.tail_status(self.root, {})
        self.assertEqual(("unknown", "terminal", retire._TAIL),
                         (result["state"], result["phase"], result["tailCorrelationId"]))
        self.assertFalse((self.root / retire._TAIL_DIR).exists())

    def test_tail_diagnostic_distinguishes_consumed_child_intent_and_fixed_remote_leaves(self):
        self.reserve()
        self.assertEqual("child-intent-absent", retire.tail_diagnose(self.root, {})["phase"])
        _source, child = retire._tail_plan(SPECS, self.intent)
        retire.guards.secure_write_create(self.root / retire._TAIL_DIR / "intent.json", child)
        probe = retire._journal_file_probe(retire._TAIL_ROOT, retire._TAIL_LEAVES)
        for phase in retire._JOURNAL_FILE_PHASES:
            with self.subTest(phase=phase), mock.patch.object(retire, "_run", return_value={"phase": phase}):
                self.assertEqual("remote-file-" + phase, retire.tail_diagnose(self.root, {})["phase"])
        with mock.patch.object(retire, "_run", return_value={"phase": "private"}):
            self.assertEqual("remote-file", retire.tail_diagnose(self.root, {})["phase"])
        self.assertIn(retire._TAIL_ROOT, probe)

    def test_tail_start_keeps_the_private_intent_directory_failure_finite(self):
        self.reserve()
        with mock.patch.object(retire, "_parse", return_value=True), mock.patch.object(retire.guards, "secure_write_create", side_effect=OSError("private local error")), mock.patch.object(retire, "_run", side_effect=AssertionError("no dispatch")):
            result = retire.tail_start(self.root, {})
        self.assertEqual(("unknown", "tail-local-intent"), (result["state"], result["phase"]))
        self.assertFalse((self.root / retire._TAIL_DIR / "intent.json").exists())

    def test_cold_tail_private_directory_is_created_durably_before_any_remote_dispatch(self):
        self.reserve()
        _source, child = retire._tail_plan(SPECS, self.intent)
        path = self.root / retire._TAIL_DIR / "intent.json"
        self.assertFalse(path.parent.exists())
        retire.guards.secure_write_create(path, child)
        self.assertEqual(child, retire.guards.secure_read(path))
        self.assertEqual(0o700, path.parent.stat().st_mode & 0o777)
        self.assertEqual(0o600, path.stat().st_mode & 0o777)

    def test_old_tail_pre_effect_closure_is_read_only_before_create_once_marker(self):
        self.reserve()
        source = retire._tail_closure_script(SPECS, self.intent)
        self.assertNotIn("Unregister-ScheduledTask", source)
        self.assertIn(retire._TAIL_ROOT, source)
        def run_value(_root, _descriptor, candidate):
            if "Parser]::ParseInput" in candidate:
                return {"valid": True}
            self.assertEqual(source, candidate)
            return {"verified": True}
        with mock.patch.object(retire, "_run", side_effect=run_value):
            result = retire.tail_close_pre_effect(self.root, {})
        self.assertEqual(("closed", "tail-closure-complete"), (result["state"], result["phase"]))
        marker = retire.guards.secure_read(self.root / retire._CLOSURE_DIR / "marker.json")
        self.assertEqual(retire._TAIL, marker["oldTailCorrelationId"])
        self.assertEqual(retire._SUCCESSOR, marker["successorCorrelationId"])
        with mock.patch.object(retire, "_run", side_effect=AssertionError("no repeat proof required")):
            self.assertEqual("closed", retire.tail_close_pre_effect(self.root, {})["state"])

    def test_old_tail_closure_source_remains_byte_exact_for_preserved_marker_binding(self):
        """Frozen historical recipe: its saved marker binds this source hash forever."""
        parent = {
            "binding": {"retirementCorrelationId": retire._RETIREMENT, "environment": "windows-cp117",
                        "socketPath": "/qga", "qemuPid": 123, "startTicks": 456,
                        "sid": "S-1-5-21-1-2-3-1002",
                        "snapshots": [{"profile": spec["profile"], "task": spec["task"],
                                       "actionSha256": spec["actionSha256"], "result": result,
                                       "taskResult": index + 1, "lastRunTicks": 1000 + index,
                                       "xmlSha256": str(index) * 64, "xmlLength": 42}
                                      for index, (spec, result) in enumerate(zip(SPECS, retire._RESULTS))]},
            "bindingSha256": "b" * 64, "actionSha256": "c" * 64,
        }
        # Generated from the historical old-tail source before generic 7cc
        # closure support existed.  Do not update it for a refactor.
        expected = "b4b7f905e851e64ec6307fc411acd6c37d355cc695dcdb4dafb4628da1bd062e"
        self.assertEqual(expected, hashlib.sha256(retire._tail_closure_script(SPECS, parent).encode("utf-16le")).hexdigest())
        with mock.patch.object(retire, "_pre_effect_closure_script", side_effect=AssertionError("generic changed")):
            self.assertEqual(expected, hashlib.sha256(retire._tail_closure_script(SPECS, parent).encode("utf-16le")).hexdigest())

    def test_old_tail_closure_refuses_marker_if_old_child_reservation_races_after_proof(self):
        self.reserve()
        _source, child = retire._tail_plan(SPECS, self.intent)
        def run_value(_root, _descriptor, candidate):
            if "Parser]::ParseInput" in candidate:
                return {"valid": True}
            retire.guards.secure_write_create(self.root / retire._TAIL_DIR / "intent.json", child)
            return {"verified": True}
        with mock.patch.object(retire, "_run", side_effect=run_value):
            result = retire.tail_close_pre_effect(self.root, {})
        self.assertEqual(("unknown", "generation"), (result["state"], result["phase"]))
        self.assertFalse((self.root / retire._CLOSURE_DIR / "marker.json").exists())

    def test_successor_requires_exact_closure_and_reports_new_correlation(self):
        self.reserve()
        closure_source = retire._tail_closure_script(SPECS, self.intent)
        marker = retire._closure_marker(self.intent, DESC, closure_source)
        retire.guards.secure_write_create(self.root / retire._CLOSURE_DIR / "marker.json", marker)
        source, child = retire._tail_plan(SPECS, self.intent, correlation=retire._SUCCESSOR, rootpath=retire._SUCCESSOR_ROOT)
        def run_value(_root, _descriptor, candidate):
            if "Parser]::ParseInput" in candidate: return {"valid": True}
            if candidate == source:
                self.assertEqual(child, retire.guards.secure_read(self.root / retire._SUCCESSOR_DIR / "intent.json")); return {"submitted": True}
            if candidate == retire._tail_reader(retire._SUCCESSOR_ROOT):
                return {"binding": child["binding"], "terminal": {"tailCorrelationId": retire._SUCCESSOR, "state": "completed", "parentRetirementCorrelationId": retire._RETIREMENT, "parentBindingSha256": self.intent["bindingSha256"], "parentActionSha256": self.intent["actionSha256"], "actionSha256": child["actionSha256"]}}
            if candidate == retire._reader(SPECS): return self.terminal()
            raise AssertionError("unexpected")
        with mock.patch.object(retire, "_run", side_effect=run_value): result = retire.successor_start(self.root, {})
        self.assertEqual(("retired", "complete", retire._SUCCESSOR), (result["state"], result["phase"], result["tailCorrelationId"]))

    def test_consumed_successor_closure_then_fresh_tail_uses_new_binding(self):
        """A failed pre-intent successor becomes immutable evidence before a new task-five action."""
        self.reserve()
        old_source = retire._tail_closure_script(SPECS, self.intent)
        retire.guards.secure_write_create(self.root / retire._CLOSURE_DIR / "marker.json",
                                          retire._closure_marker(self.intent, DESC, old_source))
        close_source = retire._successor_closure_script(SPECS, self.intent)
        self.assertNotIn("Unregister-ScheduledTask", close_source)
        self.assertIn(retire._SUCCESSOR_ROOT, close_source)
        def close_run(_root, _descriptor, candidate):
            if "Parser]::ParseInput" in candidate: return {"valid": True}
            self.assertEqual(close_source, candidate); return {"verified": True}
        with mock.patch.object(retire, "_run", side_effect=close_run):
            closed = retire.successor_close_pre_effect(self.root, {})
        self.assertEqual(("closed", "successor-closure-complete", retire._SUCCESSOR),
                         (closed["state"], closed["phase"], closed["tailCorrelationId"]))
        marker = retire.guards.secure_read(self.root / retire._SUCCESSOR_CLOSURE_DIR / "marker.json")
        self.assertEqual((retire._SUCCESSOR, retire._FRESH),
                         (marker["closedTailCorrelationId"], marker["freshTailCorrelationId"]))
        with mock.patch.object(retire, "_run", side_effect=AssertionError("closed successor cannot restart")):
            blocked = retire.successor_start(self.root, {})
        self.assertEqual(("blocked", "successor-closure-complete"), (blocked["state"], blocked["phase"]))

        source, child = retire._tail_plan(SPECS, self.intent, correlation=retire._FRESH,
                                          rootpath=retire._FRESH_ROOT)
        def fresh_run(_root, _descriptor, candidate):
            if "Parser]::ParseInput" in candidate: return {"valid": True}
            if candidate == source:
                self.assertEqual(child, retire.guards.secure_read(self.root / retire._FRESH_DIR / "intent.json"))
                return {"submitted": True}
            if candidate == retire._tail_reader(retire._FRESH_ROOT):
                return {"binding": child["binding"], "terminal": {
                    "tailCorrelationId": retire._FRESH, "state": "completed",
                    "parentRetirementCorrelationId": retire._RETIREMENT,
                    "parentBindingSha256": self.intent["bindingSha256"],
                    "parentActionSha256": self.intent["actionSha256"],
                    "actionSha256": child["actionSha256"],
                }}
            if candidate == retire._reader(SPECS): return self.terminal()
            raise AssertionError("unexpected")
        with mock.patch.object(retire, "_run", side_effect=fresh_run):
            result = retire.fresh_start(self.root, {})
        self.assertEqual(("retired", "complete", retire._FRESH),
                         (result["state"], result["phase"], result["tailCorrelationId"]))

    def test_successor_closure_race_never_marks_or_dispatches_fresh_tail(self):
        self.reserve()
        old_source = retire._tail_closure_script(SPECS, self.intent)
        retire.guards.secure_write_create(self.root / retire._CLOSURE_DIR / "marker.json",
                                          retire._closure_marker(self.intent, DESC, old_source))
        _source, child = retire._tail_plan(SPECS, self.intent, correlation=retire._SUCCESSOR,
                                           rootpath=retire._SUCCESSOR_ROOT)
        def race(_root, _descriptor, candidate):
            if "Parser]::ParseInput" in candidate: return {"valid": True}
            retire.guards.secure_write_create(self.root / retire._SUCCESSOR_DIR / "intent.json", child)
            return {"verified": True}
        with mock.patch.object(retire, "_run", side_effect=race):
            result = retire.successor_close_pre_effect(self.root, {})
        self.assertEqual(("unknown", "generation"), (result["state"], result["phase"]))
        self.assertFalse((self.root / retire._SUCCESSOR_CLOSURE_DIR / "marker.json").exists())

    def test_successor_closure_requires_and_rechecks_exact_old_closure_marker(self):
        self.reserve()
        with mock.patch.object(retire, "_parse", side_effect=AssertionError("old closure required")), mock.patch.object(retire, "_run", side_effect=AssertionError("no proof")):
            result = retire.successor_close_pre_effect(self.root, {})
        self.assertEqual(("blocked", "tail-closure-complete"), (result["state"], result["phase"]))
        retire.guards.secure_write_create(self.root / retire._CLOSURE_DIR / "marker.json", {"foreign": "marker"})
        with mock.patch.object(retire, "_parse", side_effect=AssertionError("exact old closure required")), mock.patch.object(retire, "_run", side_effect=AssertionError("no proof")):
            result = retire.successor_close_pre_effect(self.root, {})
        self.assertEqual(("blocked", "tail-closure-complete"), (result["state"], result["phase"]))
        (self.root / retire._CLOSURE_DIR / "marker.json").unlink()
        old_source = retire._tail_closure_script(SPECS, self.intent)
        old_marker = retire._closure_marker(self.intent, DESC, old_source)
        retire.guards.secure_write_create(self.root / retire._CLOSURE_DIR / "marker.json", old_marker)
        def race(_root, _descriptor, candidate):
            if "Parser]::ParseInput" in candidate: return {"valid": True}
            (self.root / retire._CLOSURE_DIR / "marker.json").unlink()
            return {"verified": True}
        with mock.patch.object(retire, "_run", side_effect=race):
            result = retire.successor_close_pre_effect(self.root, {})
        self.assertEqual(("unknown", "generation"), (result["state"], result["phase"]))
        self.assertFalse((self.root / retire._SUCCESSOR_CLOSURE_DIR / "marker.json").exists())

    def test_closure_excludes_old_tail_and_successor_reservation_race(self):
        self.reserve(); source = retire._tail_closure_script(SPECS, self.intent)
        retire.guards.secure_write_create(self.root / retire._CLOSURE_DIR / "marker.json", retire._closure_marker(self.intent, DESC, source))
        with mock.patch.object(retire, "_run", side_effect=AssertionError("old tail blocked")):
            self.assertEqual(("blocked", "tail-closure-complete"), (retire.tail_start(self.root, {})["state"], retire.tail_start(self.root, {})["phase"]))
        _old_source, old_child = retire._tail_plan(SPECS, self.intent)
        def race_parse(*_args):
            retire.guards.secure_write_create(self.root / retire._TAIL_DIR / "intent.json", old_child); return True
        with mock.patch.object(retire, "_parse", side_effect=race_parse), mock.patch.object(retire, "_run", side_effect=AssertionError("no successor dispatch")):
            result = retire.successor_start(self.root, {})
        self.assertEqual(("blocked", "generation"), (result["state"], result["phase"]))
        self.assertFalse((self.root / retire._SUCCESSOR_DIR / "intent.json").exists())

    def test_successor_admission_diagnostic_is_finite_and_read_only(self):
        self.reserve()
        self.assertEqual("closure", retire.successor_admission_diagnose(self.root, {})["phase"])
        with mock.patch.object(retire.base, "_descriptor", side_effect=OSError("private")):
            self.assertEqual("descriptor-oserror", retire.successor_admission_diagnose(self.root, {})["phase"])
        self.assertFalse((self.root / retire._SUCCESSOR_DIR).exists())

    def test_successor_admission_diagnostic_rejects_final_generation_drift(self):
        self.reserve(); source = retire._tail_closure_script(SPECS, self.intent)
        retire.guards.secure_write_create(self.root / retire._CLOSURE_DIR / "marker.json", retire._closure_marker(self.intent, DESC, source))
        changed = (*DESC[:2], 999, *DESC[3:])
        self.descriptor.side_effect = [(object(), object(), DESC), (object(), object(), changed)]
        with mock.patch.object(retire, "_parse", return_value=True):
            self.assertEqual("fresh", retire.successor_admission_diagnose(self.root, {})["phase"])

    def test_successor_admission_diagnostic_runs_inert_parser_and_checks_intent_parent(self):
        self.reserve(); source = retire._tail_closure_script(SPECS, self.intent)
        retire.guards.secure_write_create(self.root / retire._CLOSURE_DIR / "marker.json", retire._closure_marker(self.intent, DESC, source))
        with mock.patch.object(retire, "_parse", return_value=False):
            self.assertEqual("parser", retire.successor_admission_diagnose(self.root, {})["phase"])
        rag = self.root / ".rag_index"; rag.chmod(0o500)
        with mock.patch.object(retire, "_parse", return_value=True):
            self.assertEqual("intentfs", retire.successor_admission_diagnose(self.root, {})["phase"])

    def test_journal_diagnostic_is_finite_and_read_only(self):
        self.assertEqual("intent", retire.diagnose(self.root, {})["phase"])
        self.reserve()
        for value, phase in (({"_diagnostic": {"phase": "guest-exit"}}, "remote-file"),
                             ({"_diagnostic": {"phase": "wire-envelope"}}, "remote-encoding"),
                             ({"archives": []}, "remote-decoder"),
                             (self.terminal() | {"archives": [{}]}, "archive")):
            with self.subTest(phase=phase), mock.patch.object(retire, "_run", return_value=value):
                self.assertEqual(phase, retire.diagnose(self.root, {})["phase"])
        with mock.patch.object(retire, "_run", return_value=self.terminal()):
            self.assertEqual("complete", retire.diagnose(self.root, {})["phase"])

    def test_journal_file_probe_classifies_guest_exit_without_replay(self):
        self.reserve()
        with mock.patch.object(retire, "_run", side_effect=[{"_diagnostic": {"phase": "guest-exit"}}, {"phase": "binding-absent"}]) as run:
            result = retire.diagnose(self.root, {})
        self.assertEqual("remote-file-binding-absent", result["phase"])
        self.assertIn("ReadAllBytes", retire._journal_file_probe())
        self.assertEqual(2, run.call_count)

    def test_journal_probe_uses_exact_fixed_archive_leaf_names(self):
        source = retire._journal_file_probe()
        for profile in retire.retained._PROFILE_NAMES:
            self.assertIn("archive-" + profile + ".json", source)

    def test_status_rejects_changed_archive_binding_terminal_absence_generation(self):
        self.reserve()
        for field, value in (("binding", {}), ("terminal", {}), ("absent", False), ("archives", [])):
            changed = self.terminal(); changed[field] = value
            with self.subTest(field=field), mock.patch.object(retire, "_run", return_value=changed):
                self.assertEqual("unknown", retire.status(self.root, {})["state"])
        changed = self.terminal(); changed["archives"][0]["xmlSha256"] = "0" * 64
        with mock.patch.object(retire, "_run", return_value=changed):
            self.assertEqual("unknown", retire.status(self.root, {})["state"])
        self.descriptor.return_value = (object(), object(), (*DESC[:2], 999, *DESC[3:]))
        with mock.patch.object(retire, "_run") as run:
            self.assertEqual("generation", retire.status(self.root, {})["phase"])
            run.assert_not_called()

    def test_active_running_foreign_or_changed_generation_never_creates_intent(self):
        with mock.patch.object(retire, "_run", side_effect=self.run_value) as run:
            self.active.return_value = {"state": "active"}
            self.assertEqual("blocked", retire.start(self.root, {})["state"])
            run.assert_not_called()
            self.active.return_value = None
            for state in ("running", "unknown", "blocked"):
                self.observer.return_value = {"state": state}
                self.assertEqual("blocked", retire.start(self.root, {})["state"])
            self.observer.return_value = {"state": "ready"}
            self.rows[0]["task"] = "foreign"
            self.assertEqual("snapshot-output-archive-fields", retire.start(self.root, {})["phase"])
        self.assertFalse((self.root / retire._DIR / "intent.json").exists())

    def test_parser_failure_is_before_effects_and_preflight_is_read_only(self):
        with mock.patch.object(retire, "_run", side_effect=self.run_value):
            self.assertEqual("ready", retire.preflight(self.root, {})["state"])
        self.assertFalse((self.root / retire._DIR).exists())
        with mock.patch.object(retire, "_run", side_effect=self.run_value) as run, mock.patch.object(retire, "_parse", return_value=False):
            self.assertEqual("blocked", retire.start(self.root, {})["state"])
            run.assert_not_called()
        self.assertFalse((self.root / retire._DIR).exists())

    def test_admission_missing_fact_surfaces_exact_phase_without_effects(self):
        cases = ("descriptor", "configured-specs", "retained-proof", "snapshot-parser",
                 "snapshot-output", "mutation-parser", "reader-parser", "generation")
        for phase in cases:
            with self.subTest(phase=phase), contextlib.ExitStack() as stack:
                # Exercise admission decisions with actual malformed observations
                # or rejected parser results, without mocking its classification.
                stack.enter_context(mock.patch.object(retire, "_run", side_effect=self.run_value))
                parse_values = {"snapshot-parser": [False], "mutation-parser": [True, False],
                                "reader-parser": [True, True, False]}
                stack.enter_context(mock.patch.object(retire, "_parse", side_effect=parse_values.get(phase), return_value=True))
                if phase == "descriptor":
                    stack.enter_context(mock.patch.object(retire.base, "_descriptor", side_effect=ValueError("private text")))
                elif phase == "configured-specs":
                    stack.enter_context(mock.patch.object(retire.retained, "_configured_specs", return_value=None))
                elif phase == "retained-proof":
                    stack.enter_context(mock.patch.object(retire.retained, "status", return_value={"state": "blocked"}))
                elif phase == "snapshot-output":
                    stack.enter_context(mock.patch.object(retire, "_run", return_value={"archives": []}))
                elif phase == "generation":
                    stack.enter_context(mock.patch.object(retire.base, "_descriptor", side_effect=[(None, None, DESC), (None, None, (*DESC[:2], 999, *DESC[3:]))]))
                write = stack.enter_context(mock.patch.object(retire.guards, "secure_write_create", side_effect=AssertionError("no effects")))
                result = retire.start(self.root, {})
                self.assertEqual("blocked", result["state"])
                self.assertEqual(phase, result["phase"])
                self.assertFalse(result["nativeActionAllowed"])
                self.assertFalse(result["replayAllowed"])
                self.assertNotIn("private text", json.dumps(result))
                write.assert_not_called()
                self.assertFalse((self.root / retire._DIR).exists())

    def test_raced_intent_create_never_dispatches_or_overwrites(self):
        original_write = retire.guards.secure_write_create
        foreign = {"preserved": "foreign raced journal"}
        def race(path, value):
            original_write(path, foreign)
            original_write(path, value)
        with mock.patch.object(retire, "_run", side_effect=self.run_value) as run, mock.patch.object(retire.guards, "secure_write_create", side_effect=race):
            result = retire.start(self.root, {})
        self.assertEqual("unknown", result["state"])
        self.assertEqual(foreign, retire.guards.secure_read(self.root / retire._DIR / "intent.json"))
        self.assertFalse(any(call.args[2] == self.script for call in run.call_args_list))

    def test_generation_changes_after_preflight_do_not_create_intent(self):
        other = (*DESC[:2], 999, *DESC[3:])
        self.descriptor.side_effect = [(object(), object(), DESC), (object(), object(), DESC), (object(), object(), other)]
        with mock.patch.object(retire, "_run", side_effect=self.run_value) as run:
            result = retire.start(self.root, {})
        self.assertEqual("blocked", result["state"])
        self.assertFalse((self.root / retire._DIR / "intent.json").exists())
        self.assertFalse(any(call.args[2] == self.script for call in run.call_args_list))

    def test_fixed_seven_leaves_and_bounded_actual_sources(self):
        self.assertEqual(7, len(retire._LEAVES))
        for source in (self.script, retire._reader(SPECS), retire._snapshot_script(SPECS),
                       retire._finish_script(SPECS, self.intent), retire._tail_plan(SPECS, self.intent)[0],
                       retire._tail_reader()):
            self.assertLess(len(retire.transport._encode_ps(source)), 30000)
        # Preserved artifacts have no delete path. Only fixed task unregister.
        self.assertNotIn("Remove-Item", self.script)
        self.assertNotIn("Stop-Process", self.script)
        self.assertIn("[Security.Principal.SecurityIdentifier]::new($sid)", self.script)
        self.assertLess(self.script.index("Read back and decompress ALL"), self.script.index("Unregister-ScheduledTask"))

    def test_large_inert_parser_source_stays_inside_windows_transport_bound(self):
        """Measured CP95 successor admission must parse before it can reserve an intent."""
        source, _ = retire._tail_plan(SPECS, self.intent, correlation=retire._SUCCESSOR,
                                      rootpath=retire._SUCCESSOR_ROOT)
        # The real protected binding has non-repeating SHA data.  This fixed
        # comment models that bounded parser payload without making the source
        # executable or changing the action plan.
        source += "\n# " + "".join(hashlib.sha256(str(index).encode()).hexdigest() for index in range(12))
        with mock.patch.object(retire, "_run", return_value={"valid": True}) as run:
            self.assertTrue(retire._parse(self.root, DESC, source))
        self.assertEqual(1, run.call_count)
        self.assertLess(len(retire.transport._encode_ps(run.call_args.args[2])), 30000)

    def test_remote_active_and_race_fail_closed_without_second_dispatch(self):
        body = "import fcntl,json,os,stat,sys,time,base64" + retire._REMOTE.split("import fcntl,json,os,stat,sys,time,base64", 1)[1]
        group = self.root / 'windows-cp117/windows-cp117-campaign'
        self.root.chmod(0o700); group.parent.mkdir(mode=0o700); group.mkdir(mode=0o700)
        lock = group / '.environment.lock'; lock.write_bytes(b''); lock.chmod(0o600)
        active = group / 'active.json'
        def execute(race=False):
            calls = []
            def call(*args):
                calls.append(args[1])
                if args[1] == 'guest-exec':
                    if race: active.write_bytes(b'opaque')
                    return {'pid': 1}
                return {'exited': True, 'exitcode': 0, 'out-data': base64.b64encode(b'{"submitted":true}').decode()}
            output = io.StringIO()
            with mock.patch.object(sys, "argv", ["remote", str(self.root), DESC[0], DESC[1], str(DESC[2]), str(DESC[3]), "encoded"]), contextlib.redirect_stdout(output):
                try: exec(body, {"live": lambda *_: True, "call": call, "decode": lambda b: b.decode()})
                except SystemExit: pass
            return json.loads(output.getvalue()), calls
        active.write_bytes(b'opaque')
        value, calls = execute()
        self.assertEqual('blocked', value['state']); self.assertEqual([], calls)
        active.unlink()
        value, calls = execute(race=True)
        self.assertEqual({'state': 'diagnostic', 'phase': 'lease'}, value); self.assertEqual(['guest-exec', 'guest-exec-status'], calls)

    def test_large_guest_response_remains_inside_base_remote_stdout_cap(self):
        body = "import fcntl,json,os,stat,sys,time,base64" + retire._REMOTE.split("import fcntl,json,os,stat,sys,time,base64", 1)[1]
        group = self.root / 'windows-cp117/windows-cp117-campaign'
        self.root.chmod(0o700); group.parent.mkdir(mode=0o700); group.mkdir(mode=0o700)
        lock = group / '.environment.lock'; lock.write_bytes(b''); lock.chmod(0o600)
        payload = {"archives": [{"xmlGzip": "preserved-gzip-base64" * 1500}]}
        guest = json.dumps(payload).encode()
        self.assertGreater(len(guest), 16384)
        def run(raw, **overrides):
            status = {'exited': True, 'exitcode': 0, 'out-data': base64.b64encode(raw).decode(), **overrides}
            calls = iter(({'pid': 1}, status))
            output = io.StringIO()
            with mock.patch.object(sys, "argv", ["remote", str(self.root), DESC[0], DESC[1], str(DESC[2]), str(DESC[3]), "encoded"]), contextlib.redirect_stdout(output):
                try:
                    exec(body, {"live": lambda *_: True, "call": lambda *_: next(calls), "decode": lambda b: b.decode()})
                except SystemExit:
                    pass
            self.assertLessEqual(len(output.getvalue().encode()), 16384)
            return json.loads(output.getvalue())
        self.assertEqual(payload, retire._decode_observation(run(guest)))
        for raw, overrides, phase in ((b'{}', {'exitcode': 1}, 'guest-exit'),
                                      (b'{}', {'out-truncated': True}, 'guest-truncated'),
                                      (b'{}', {'out-data': 'bad!'}, 'guest-output-encoding'),
                                      (b'not JSON', {}, 'guest-output-json'),
                                      (b'x' * 100001, {}, 'guest-output-size'),
                                      (json.dumps({'random': base64.b64encode(os.urandom(14000)).decode()}).encode(), {}, 'wire-size')):
            with self.subTest(phase=phase):
                value = run(raw, **overrides)
                self.assertEqual('diagnostic', value['state'])
                self.assertEqual(phase, value['phase'])

    def test_measured_snapshot_payload_uses_compact_wire_form_under_16k(self):
        """The native 17,701-byte snapshot formerly produced 17,259 wire bytes."""
        body = "import fcntl,json,os,stat,sys,time,base64" + retire._REMOTE.split("import fcntl,json,os,stat,sys,time,base64", 1)[1]
        group = self.root / 'windows-cp117/windows-cp117-campaign'
        self.root.chmod(0o700); group.parent.mkdir(mode=0o700); group.mkdir(mode=0o700)
        lock = group / '.environment.lock'; lock.write_bytes(b''); lock.chmod(0o600)
        # Base64 gzip XML is deliberately incompressible enough that the old
        # map-key-heavy envelope exceeds the shared 16 KiB guest stdout cap.
        rows = []
        for index, spec in enumerate(SPECS):
            packed = base64.b64encode(gzip.compress(os.urandom(2420), mtime=0)).decode()
            rows.append({"profile": spec["profile"], "task": spec["task"], "actionSha256": spec["actionSha256"],
                         "result": retire._RESULTS[index], "taskResult": 0 if retire._RESULTS[index] == "succeeded" else index + 1,
                         "lastRunTicks": 123456 + index, "xmlSha256": hashlib.sha256(packed.encode()).hexdigest(),
                         "xmlLength": 2420, "xmlGzip": packed})
        payload = {"archives": rows}
        raw = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode()
        self.assertGreater(len(raw), 17700)
        old_wire = json.dumps({"state": "observed", "encoding": "gzip-base64", "rawBytes": len(raw),
                               "rawSha256": hashlib.sha256(raw).hexdigest(),
                               "receiptGzip": base64.b64encode(gzip.compress(raw, mtime=0)).decode()},
                              separators=(',', ':')).encode()
        self.assertGreater(len(old_wire), 16384)  # native failure: 17,259 bytes
        calls = iter(({'pid': 1}, {'exited': True, 'exitcode': 0, 'out-data': base64.b64encode(raw).decode()}))
        output = io.StringIO()
        with mock.patch.object(sys, "argv", ["remote", str(self.root), DESC[0], DESC[1], str(DESC[2]), str(DESC[3]), "encoded"]), contextlib.redirect_stdout(output):
            try:
                exec(body, {"live": lambda *_: True, "call": lambda *_: next(calls), "decode": lambda b: b.decode()})
            except SystemExit:
                pass
        wire = output.getvalue().encode()
        self.assertLessEqual(len(wire), 16384)
        self.assertEqual(payload, retire._decode_observation(json.loads(wire)))

    def test_terminal_reader_with_full_archives_stays_under_16k(self):
        """A status reader must not lose a completed retirement to wire size."""
        body = "import fcntl,json,os,stat,sys,time,base64" + retire._REMOTE.split("import fcntl,json,os,stat,sys,time,base64", 1)[1]
        group = self.root / 'windows-cp117/windows-cp117-campaign'
        self.root.chmod(0o700); group.parent.mkdir(mode=0o700); group.mkdir(mode=0o700)
        lock = group / '.environment.lock'; lock.write_bytes(b''); lock.chmod(0o600)
        snapshots, archived = [], []
        for index, spec in enumerate(SPECS):
            # Actual f31 terminal proof: 20,616 canonical bytes produced a
            # 16,512-byte v1 reader envelope and was classified wire-size.
            fixture = b"".join(hashlib.sha256(f"f31-reader-{index}-{block}".encode()).digest()
                               for block in range(77))[:2440]
            packed = base64.b64encode(gzip.compress(fixture, mtime=0)).decode()
            row = {"profile": spec["profile"], "task": spec["task"], "actionSha256": spec["actionSha256"],
                   "result": retire._RESULTS[index], "taskResult": 0 if retire._RESULTS[index] == "succeeded" else index + 1,
                   "lastRunTicks": 123456 + index, "xmlSha256": hashlib.sha256(packed.encode()).hexdigest(),
                   "xmlLength": 2440}
            snapshots.append(row); archived.append({**row, "xmlGzip": packed, "bindingSha256": "b" * 64})
        binding = {"retirementCorrelationId": retire._RETIREMENT, "environment": DESC[0], "socketPath": DESC[1],
                   "qemuPid": DESC[2], "startTicks": DESC[3], "sid": DESC[4], "snapshots": snapshots}
        payload = {"binding": {"binding": binding, "bindingSha256": "b" * 64, "actionSha256": "c" * 64},
                   "archives": archived,
                   "terminal": {"retirementCorrelationId": retire._RETIREMENT, "state": "retired", "bindingSha256": "b" * 64, "actionSha256": "c" * 64},
                   "absent": True}
        raw = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode()
        self.assertEqual(20660, len(raw))
        snapshot_fields = ("profile", "task", "actionSha256", "result", "taskResult", "lastRunTicks", "xmlSha256", "xmlLength")
        archive_fields = snapshot_fields + ("xmlGzip", "bindingSha256")
        binding_fields = ("retirementCorrelationId", "environment", "socketPath", "qemuPid", "startTicks", "sid")
        terminal_fields = ("retirementCorrelationId", "state", "bindingSha256", "actionSha256")
        old_columns = {"v": 1, "b": [binding[key] for key in binding_fields],
                       "s": [[row[key] for key in snapshot_fields] for row in snapshots],
                       "a": [[row[key] for key in archive_fields] for row in archived],
                       "i": ["b" * 64, "c" * 64],
                       "t": [payload["terminal"][key] for key in terminal_fields], "z": True}
        old_packed = base64.b85encode(gzip.compress(json.dumps(old_columns, separators=(',', ':'), sort_keys=True).encode(), mtime=0)).decode()
        old_wire = json.dumps({"state": "observed", "encoding": "gzip-base85-reader-columns-v1",
                               "rawBytes": len(raw), "rawSha256": hashlib.sha256(raw).hexdigest(),
                               "receiptGzip": old_packed}, separators=(',', ':')).encode()
        self.assertEqual(16414, len(old_wire) + 1)
        self.assertGreater(len(old_wire) + 1, 16384)  # deterministic v1 overflow
        calls = iter(({'pid': 1}, {'exited': True, 'exitcode': 0, 'out-data': base64.b64encode(raw).decode()}))
        output = io.StringIO()
        with mock.patch.object(sys, "argv", ["remote", str(self.root), DESC[0], DESC[1], str(DESC[2]), str(DESC[3]), "encoded"]), contextlib.redirect_stdout(output):
            try: exec(body, {"live": lambda *_: True, "call": lambda *_: next(calls), "decode": lambda b: b.decode()})
            except SystemExit: pass
        wire = output.getvalue().encode()
        self.assertLessEqual(len(wire), 16384)
        envelope = json.loads(wire)
        self.assertEqual("z85r4", envelope["encoding"])
        self.assertEqual(payload, retire._decode_observation(envelope))

    def test_z85r4_bomb_is_bounded_before_canonical_receipt_decode(self):
        bomb = base64.b85encode(zlib.compress(b"x" * 100001, 9)).decode()
        value = {"state": "observed", "encoding": "z85r4", "rawBytes": 1,
                 "rawSha256": hashlib.sha256(b"x").hexdigest(), "receiptGzip": bomb}
        self.assertEqual({"_diagnostic": {"phase": "wire-envelope"}}, retire._decode_observation(value))
        oversized = {**value, "receiptGzip": "x" * 16385}
        with mock.patch.object(retire.json, "dumps", side_effect=AssertionError("must not serialize oversized wire")):
            self.assertEqual({"_diagnostic": {"phase": "wire-envelope"}}, retire._decode_observation(oversized))


    def test_snapshot_diagnostic_is_bounded_and_never_creates_effects(self):
        for phase in retire._DIAGNOSTIC_PHASES:
            with self.subTest(phase=phase), mock.patch.object(retire, "_parse", return_value=True), mock.patch.object(retire, "_run", return_value={"_diagnostic": {"phase": phase, "rawBytes": 20000}}):
                result = retire.start(self.root, {})
                self.assertEqual("snapshot-output-" + phase, result["phase"])
                self.assertEqual({"phase": phase, "rawBytes": 20000}, result["snapshotDiagnostic"])
                self.assertFalse((self.root / retire._DIR).exists())
        for value in ({"state": "diagnostic", "phase": "private secret"},
                      {"state": "diagnostic", "phase": "wire-size", "private": "secret"},
                      {"state": "diagnostic", "phase": "wire-size", "rawBytes": True},
                      {"state": "diagnostic", "phase": "wire-size", "rawBytes": 150001}):
            self.assertEqual({"_diagnostic": {"phase": "wire-envelope"}}, retire._decode_observation(value))

    def test_compressed_observation_hash_size_and_gzip_bomb_rejected(self):
        raw = b'{"value":"proof"}'
        value = {"state": "observed", "encoding": "gzip-base64", "rawBytes": len(raw),
                 "rawSha256": hashlib.sha256(raw).hexdigest(), "receiptGzip": base64.b64encode(gzip.compress(raw)).decode()}
        self.assertEqual({"value": "proof"}, retire._decode_observation(value))
        for update in ({"rawSha256": "0" * 64}, {"rawBytes": len(raw) + 1}, {"receiptGzip": "bad!"},
                       {"receiptGzip": base64.b64encode(gzip.compress(b'x' * 100001)).decode()}):
            self.assertEqual({"_diagnostic": {"phase": "wire-envelope"}}, retire._decode_observation({**value, **update}))

    def test_compact_envelope_untrusted_types_fail_closed(self):
        """Lists, mappings, bool and float cannot select wire formats or versions."""
        base = {"state": "observed", "encoding": "gzip-base85-archive-columns-v1", "rawBytes": 1,
                "rawSha256": "a" * 64, "receiptGzip": ""}
        for update in ({"encoding": []}, {"encoding": {}},
                       {"state": []}, {"rawBytes": True}, {"rawBytes": 1.0},
                       {"receiptGzip": []}):
            with self.subTest(update=update):
                self.assertEqual({"_diagnostic": {"phase": "wire-envelope"}}, retire._decode_observation({**base, **update}))
        for phase in ([], {}, True, 1.0):
            with self.subTest(phase=phase):
                self.assertEqual({"_diagnostic": {"phase": "wire-envelope"}},
                                 retire._decode_observation({"state": "diagnostic", "phase": phase}))
        compact = {"v": True, "a": [["p", "t", "a", "s", 0, 1, "h", 1, "x"]]}
        packed = base64.b85encode(gzip.compress(json.dumps(compact, separators=(',', ':')).encode(), mtime=0)).decode()
        expanded = {"archives": [{"profile": "p", "task": "t", "actionSha256": "a", "result": "s", "taskResult": 0,
                                  "lastRunTicks": 1, "xmlSha256": "h", "xmlLength": 1, "xmlGzip": "x"}]}
        canonical = json.dumps(expanded, separators=(',', ':'), sort_keys=True).encode()
        value = {"state": "observed", "encoding": "gzip-base85-archive-columns-v1", "rawBytes": len(canonical),
                 "rawSha256": hashlib.sha256(canonical).hexdigest(), "receiptGzip": packed}
        self.assertEqual({"_diagnostic": {"phase": "wire-envelope"}}, retire._decode_observation(value))

    def test_windows_actual_task_snapshot_rejects_running_foreign_xml_process_and_normalizes_null(self):
        powershell = shutil.which("powershell.exe")
        if powershell is None:
            self.skipTest("requires Windows PowerShell; root retains native gate")
        execute = r'C:\fixed.exe'; arguments = 'fixed'
        spec = {**SPECS[0], "actionSha256": hashlib.sha256((execute + '\0' + arguments).encode()).hexdigest()}
        source = retire._task_functions([spec]) + r'''
function Get-CimInstance {if($global:otherPs){[pscustomobject]@{Name='powershell.exe';ProcessId=999999;CommandLine=$null}}}
function Get-ScheduledTask {return $global:task}
function Get-ScheduledTaskInfo {[pscustomobject]@{LastTaskResult=0;LastRunTime=[datetime]'2026-01-01'}}
function Export-ScheduledTask {return $global:xml}
$global:xml='<Task />';$global:otherPs=$false
$global:task=[pscustomobject]@{TaskPath='\';State='Ready';Actions=@([pscustomobject]@{Execute='C:\fixed.exe';Arguments='fixed'});Principal=[pscustomobject]@{UserId='S-1-5-21-1-2-3-1002';LogonType='Interactive';RunLevel='Limited'};Settings=[pscustomobject]@{RestartCount=0};Triggers=([object[]]@($null))}
function Check {try{$a=TaskSnapshot $specs[0];'accepted'}catch{'rejected'}}
Check;$global:task.Triggers=([object[]]@());Check
$global:task.Triggers=([object[]]@($null,$null));Check
$global:task.Triggers=([object[]]@($null,[pscustomobject]@{x=1}));Check
$global:task.Triggers=([object[]]@());$global:task.State='Running';Check
$global:task.State='Ready';$global:task.Actions[0].Arguments='foreign';Check
$global:task.Actions[0].Arguments='fixed';$global:otherPs=$true;Check
$global:otherPs=$false;$global:xml='x'*131073;Check
'''
        value = subprocess.run([powershell, '-NoProfile', '-NonInteractive', '-Command', source], capture_output=True, text=True, check=True, timeout=15)
        self.assertEqual(['accepted', 'accepted'] + ['rejected'] * 6, value.stdout.splitlines())

    def test_windows_finish_script_is_parser_valid_before_any_terminal_write(self):
        """Regression for the unmatched binding guard found during review."""
        powershell = shutil.which("powershell.exe")
        if powershell is None:
            self.skipTest("requires Windows PowerShell; root retains native gate")
        for source in (retire._finish_script(SPECS, self.intent), retire._tail_plan(SPECS, self.intent)[0], retire._tail_reader()):
            encoded = base64.b64encode(gzip.compress(source.encode("utf-16le"), mtime=0)).decode()
            parser = (
                "$i=[IO.MemoryStream]::new([byte[]][Convert]::FromBase64String('" + encoded + "'));"
                "$z=[IO.Compression.GzipStream]::new($i,[IO.Compression.CompressionMode]::Decompress);"
                "$o=[IO.MemoryStream]::new();$z.CopyTo($o);$z.Dispose();$i.Dispose();"
                "$s=[Text.Encoding]::Unicode.GetString($o.ToArray());$o.Dispose();"
                "$tokens=$null;$errors=$null;"
                "[void][Management.Automation.Language.Parser]::ParseInput($s,[ref]$tokens,[ref]$errors);"
                "[Console]::Out.WriteLine($errors.Count)"
            )
            self.assertLess(len(parser), 30000)
            value = subprocess.run([powershell, '-NoProfile', '-NonInteractive', '-Command', parser],
                                   capture_output=True, text=True, check=True, timeout=15)
            self.assertEqual("0", value.stdout.strip())

    def test_windows_tail_reader_defines_its_idle_census_before_reading_journal(self):
        powershell = shutil.which("powershell.exe")
        if powershell is None:
            self.skipTest("requires Windows PowerShell; root retains native gate")
        prefix = retire._tail_reader().split("Idle;$binding=Read-SecureJson", 1)[0]
        source = prefix + "function Get-CimInstance {,@()};Idle;[Console]::Out.WriteLine('ok')"
        value = subprocess.run([powershell, '-NoProfile', '-NonInteractive', '-Command', source],
                               capture_output=True, text=True, check=True, timeout=15)
        self.assertEqual("ok", value.stdout.strip())


if __name__ == '__main__':
    unittest.main()

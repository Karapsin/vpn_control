"""Original owner finishing while the tart registry harness observes it.

durable_remote_job.observe() checks terminal.json, then reads owner.json and only
then checks the owner's process birth. The detached owner publishes terminal.json
and then exits, so a finish between those checks reports unknown/
original_owner_missing for a completed job, and OriginalOwner.observe() turns that
into MacBlocked('macos_original_owner_unknown'). The unfixed terminal() helper
called owner.observe() as soon as the owner record existed.

Only owned inputs are controlled. The original tests' owner() launches the real
detached owner through an owned launcher that is held until the helper first finds
no owner record, and its program prints the same retained line only after an
owned release marker. The second observation of the live owner record (the first
reported it running) creates that marker and returns only after the actual owner
has published its terminal receipt and exited: the original failure's order.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shlex
import sys
import tempfile
import time
import traceback
import types
import unittest
from unittest import mock
from uuid import uuid4

from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_tart_macos_registry as subject
from agent_tools.tests import test_readiness_tart_macos_registry as current


BEFORE = Path(__file__).parent / "fixtures/tart_macos_registry_terminal_race/test_readiness_tart_macos_registry.py.before.source"
PROVENANCE = Path(__file__).parent / "fixtures/tart_macos_registry_terminal_race/provenance.json"
BEFORE_SHA256 = "684982ae6c2ca217a1baa3d34c1fd0783eac3ed8a7f7e9be4056f49e8fe28aa4"
# Original failing test -> its call of terminal() in the whole beforeimage.
ORIGINALS = {"test_actual_original_owner_collects_terminal_and_never_replaces_missing_receipt": (154, "owner=self.owner();result=self.terminal(owner)"),
             "test_actual_owner_rejects_foreign_source_generation_and_incomplete_stream": (168, "owner=self.owner();self.terminal(owner)")}
RUNNING, ABSENT, MISSING, TERMINAL = (("running", "original_owner_running"), ("unknown", "record_unavailable"),
                                      ("unknown", "original_owner_missing"), ("terminal", "correlated_terminal"))


class Recorded(unittest.TestResult):
    """Keeps the raised exception and its frames: the original failure's shape."""
    def addError(self, test, err):
        self.raised = (err[1], traceback.extract_tb(err[2])); super().addError(test, err)


class Control:
    """One original test's owned gates, its forced interleaving and what its helper observed."""
    def __init__(self, case):
        self.case, self.phase, self.inside, self.armed, self.live, self.returned = case, "test", False, False, 0, None
        self.forced, self.observed, self.calls, self.job = [], [], [], None
        self.real_record, self.real_observe, self.real_owner_observe = jobs._record, jobs.observe, subject.OriginalOwner.observe

    def launcher(self, real):
        """Owned /bin/sh launcher: its interpreter holds until the start marker, then becomes the real one with the same arguments."""
        code = ("import os,pathlib,sys,time\nstart=pathlib.Path(sys.argv[1]);deadline=time.monotonic()+60\n"
                "while not start.exists():\n if time.monotonic()>deadline:sys.exit(3)\n time.sleep(.005)\n"
                "os.execv(sys.argv[2],sys.argv[2:])\n")
        path = self.case.root / "launcher"
        path.write_text("#!/bin/sh\nexec " + " ".join(map(shlex.quote, (real, "-I", "-c", code, str(self.start), real))) + ' "$@"\n')
        path.chmod(0o700); return path

    def owner(self):
        """The original owner() with owned gates only: same root, binding, purpose and retained line."""
        root = self.case.root / "jobs"; root.mkdir(mode=0o700)
        # Beside jobs/, whose single entry the original asserts.
        self.start, self.release = self.case.root / "start", self.case.root / "release"
        binding = jobs.current_binding("controlled-mac-owner", "actual-local-host")
        program = jobs.Program("controlled-mac-custody", ("import pathlib,sys,time\nrelease=pathlib.Path(%r);deadline=time.monotonic()+60\n"
                               "while not release.exists():\n if time.monotonic()>deadline:sys.exit(3)\n time.sleep(.005)\n"
                               "print('retained',flush=True)\n" % str(self.release)).encode())
        operation = str(uuid4()); generation = jobs.root_generation(root)
        self.case.addCleanup(self.finish)  # LIFO: before the case's temporary root is removed.
        with mock.patch.object(sys, "executable", str(self.launcher(sys.executable))):
            jobs.submit(root, operation, binding, program, generation=generation)
        self.job, self.armed = (root, operation, binding, generation), True
        return subject.OriginalOwner(root, generation, operation, binding, program)

    def record(self, path):
        mine = self.armed and Path(path) == self.job[0] / self.job[1] / "owner.json"
        try:
            value = self.real_record(path)
        except jobs.DurableJobError:
            if mine: self.start.touch(exist_ok=True)  # The helper found no owner record: only now may the owner start.
            raise
        if mine and not self.release.exists() and not (Path(path).parent / "terminal.json").exists():
            self.live += 1
            if self.live == 2:
                # The owner publishes its terminal receipt and exits before this read of its live record returns.
                identity = value["owner"]; self.release.touch(); deadline = time.monotonic() + 60
                while jobs._birth(identity["pid"]) == identity["birth"] and time.monotonic() < deadline: time.sleep(.005)
                self.forced.append((self.inside, (Path(path).parent / "terminal.json").exists(), jobs._birth(identity["pid"]) != identity["birth"]))
        return value

    def observe(self, *args, **kwargs):
        status = self.real_observe(*args, **kwargs)
        if self.phase == "terminal" and not self.inside: self.observed.append((status["state"], status["reason"]))
        return status

    def owner_observe(self, owner):
        entry = (owner.root / owner.operation_id / "terminal.json").exists(); self.inside = True
        try:
            result = self.real_owner_observe(owner)
        except BaseException as error:
            self.calls.append((self.phase, entry, error)); raise
        finally:
            self.inside = False
        self.calls.append((self.phase, entry, result)); return result

    def terminal(self, owner):
        self.phase = "terminal"
        try:
            self.returned = type(self.case).terminal(self.case, owner); return self.returned
        finally:
            self.phase = "test"

    def finish(self):
        # Failure paths only: never leave the owned launcher or program holding past the case.
        for marker in (self.start, self.release): marker.touch(exist_ok=True)
        deadline = time.monotonic() + 30
        while self.job and time.monotonic() < deadline and self.real_observe(self.job[0], self.job[1], self.job[2], generation=self.job[3])["reason"] in {RUNNING[1], ABSENT[1]}:
            time.sleep(.01)


@unittest.skipUnless(os.name == "posix", "real detached durable owner and owned /bin/sh launcher")
class OwnerFinishDuringObservationTests(unittest.TestCase):
    def before(self):
        provenance = json.loads(PROVENANCE.read_bytes()); raw = BEFORE.read_bytes()
        self.assertEqual((BEFORE_SHA256, len(raw), False), (provenance["sourceSha256"], provenance["sourceBytes"], provenance["nativeFailureClaimed"]))
        self.assertEqual(BEFORE_SHA256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(sorted(current.__name__ + ".MacCustodyPrimitivesTests." + name for name in ORIGINALS), sorted(provenance["originalFailureTestIds"]))
        module = types.ModuleType("_tart_registry_terminal_race_before_" + uuid4().hex); module.__file__ = current.__file__
        exec(compile(raw, str(BEFORE), "exec", dont_inherit=True), module.__dict__)
        return module

    def original(self, module, name):
        """The unchanged original test; only its owner() inputs are owned and its observations recorded."""
        case = module.MacCustodyPrimitivesTests(name); control = Control(case); result = Recorded()
        case.owner, case.terminal = control.owner, control.terminal
        with mock.patch.object(jobs, "_record", control.record), mock.patch.object(jobs, "observe", control.observe), \
                mock.patch.object(subject.OriginalOwner, "observe", lambda owner: control.owner_observe(owner)):
            case.run(result)
        return result, control

    def test_whole_unfixed_helper_red_and_fixed_helper_green_when_owner_finishes_during_observation(self):
        before = self.before()
        for name, (line, call) in ORIGINALS.items():
            with self.subTest(name=name, fixed=False):
                result, control = self.original(before, name)
                self.assertEqual((1, [], 1), (result.testsRun, result.failures, len(result.errors)), "".join(text for _, text in result.failures + result.errors))
                error, frames = result.raised
                self.assertEqual((subject.MacBlocked, "macos_original_owner_unknown"), (type(error), str(error)))
                # The original trace: the test, terminal() at its owner.observe(), then OriginalOwner.observe's state check.
                self.assertEqual([(str(BEFORE), line, name, call), (str(BEFORE), 148, "terminal", "result=owner.observe()"),
                                  (subject.__file__, "observe", '_need(result["state"] in {"running", "terminal"}, "macos_original_owner_unknown")'),
                                  (subject.__file__, "_need", "raise MacBlocked(reason)")],
                                 [(f.filename, f.lineno, f.name, f.line) if f.filename == str(BEFORE) else (f.filename, f.name, f.line)
                                  for f in frames if f.filename in (str(BEFORE), subject.__file__)])
                # Inside OriginalOwner.observe, after its receipt check: the owner had published and exited.
                self.assertEqual([(True, True, True)], control.forced)
                self.assertEqual([("terminal", False, error)], control.calls)
                self.assertEqual({ABSENT}, set(control.observed[:-1])); self.assertEqual(RUNNING, control.observed[-1])
            with self.subTest(name=name, fixed=True):
                result, control = self.original(current, name)
                self.assertEqual((1, [], []), (result.testsRun, result.failures, result.errors), "".join(text for _, text in result.failures + result.errors))
                # The same forced finish, met by the helper's own observation-only wait.
                self.assertEqual([(False, True, True)], control.forced)
                self.assertEqual({ABSENT}, set(control.observed[:-3])); self.assertEqual([RUNNING, MISSING, TERMINAL], control.observed[-3:])
                # One read through the original owner, after the receipt exists, and its result is returned.
                helper = [call for call in control.calls if call[0] == "terminal"]
                self.assertEqual([("terminal", True)], [(phase, entry) for phase, entry, _ in helper])
                self.assertIs(helper[0][2], control.returned); self.assertEqual("terminal", control.returned["state"])

    def test_fixed_helper_still_fails_at_once_on_a_non_transient_durable_state(self):
        # A completed original whose retained stream overflowed stays UNKNOWN: reported, never waited out or read through the owner.
        temporary = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()); self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "jobs"; root.mkdir(mode=0o700)
        binding = jobs.current_binding("controlled-mac-owner", "actual-local-host")
        program = jobs.Program("controlled-mac-custody", b'print("retained",flush=True)\n', stream_limit=1)
        operation = str(uuid4()); generation = jobs.root_generation(root)
        jobs.submit(root, operation, binding, program, generation=generation)
        owner = subject.OriginalOwner(root, generation, operation, binding, program)
        with mock.patch.object(subject.OriginalOwner, "observe", side_effect=AssertionError("read through the original owner")) as read:
            with self.assertRaisesRegex(AssertionError, r"^\('unknown', 'output_overflow'\) not found in "):
                current.MacCustodyPrimitivesTests(next(iter(ORIGINALS))).terminal(owner)
        self.assertEqual(0, read.call_count)
        identity = jobs._record(root / operation / "owner.json")["owner"]; deadline = time.monotonic() + 30
        while jobs._birth(identity["pid"]) == identity["birth"] and time.monotonic() < deadline: time.sleep(.01)


if __name__ == "__main__":
    unittest.main()

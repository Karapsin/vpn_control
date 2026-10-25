"""TEST-006: complete failure discovery, failed-first reruns, then the complete tier.

The actual managed planner and runner functions run with inert command
execution. The whole retained beforeimage had no recorded failure set: a later
pre-push repeated every check without first proving the recorded failures. The
whole recovery-tree beforeimage ran the agent selection as one command, which
outgrew its 50-minute bound, reran an unparsed command unchanged with its
removed modules, and SIGKILLed a timed-out child at once, orphaning the worker
sessions that a runner stops on SIGTERM.
"""
import ast
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from agent_tools import mcp_server as server

selector = server.affected_agent_tests  # The planner's own loaded selector module.
CURRENT = Path(server.__file__)
BEFORE = Path(__file__).parent / "fixtures/readiness_identity_refusal/mcp_server.before.source"
# Whole recovery-tree beforeimage with failed-first reruns but one unbounded agent command.
UNSPLIT = Path(__file__).parent / "fixtures/runner_stdin_isolation/mcp_server.before.source"
UNIT = [sys.executable, "-m", "unittest"]
CLOSE = "agent_tools.tests.test_ssh_connection_session_close"
GATE = UNIT + [CLOSE]
# Five bulk modules sort before and after the gate. The hosted CI shards alternate
# over the whole sorted selection, so the gate's slot shifts every later module.
MODULES = ("agent_tools.tests.test_agent_test_runner", "agent_tools.tests.test_mcp_server", "agent_tools.tests.test_readiness",
           CLOSE, "agent_tools.tests.test_ssh_transport", "agent_tools.tests.test_windows_ordinary_task")
HALVES = [UNIT + ["agent_tools.tests.test_agent_test_runner", "agent_tools.tests.test_readiness", "agent_tools.tests.test_ssh_transport"],
          UNIT + ["agent_tools.tests.test_mcp_server", "agent_tools.tests.test_windows_ordinary_task"]]
SELECTED = UNIT + [name for name in MODULES if name != CLOSE]  # The beforeimage's one bulk command.
READINESS = UNIT + ["agent_tools.tests.test_readiness"]
TRANSPORT = UNIT + ["agent_tools.tests.test_ssh_transport"]
HYGIENE = ["./scripts/check_release_hygiene.sh"]
NAMES = {"run_checks", "_run_check_commands", "_commands_for", "_record_check_outcome", "_failed_modules", "_failed_commands",
         "_failure_set_path"}
# A runner-style child: on SIGTERM it records the signal, writes more than a pipe
# holds, and stops its worker session as agent_test_runner._stop_workers does;
# then it exits, or with a linger marker keeps running until only SIGKILL ends it.
CHILD = r'''import os,signal,subprocess,sys,time
from pathlib import Path
root=Path.cwd();worker=None
def stop(signum,frame):
    (root/"term").write_text(str(os.getpid()));sys.stdout.write("x"*262144);sys.stdout.flush()
    if worker is not None and worker.poll() is None:os.killpg(worker.pid,signal.SIGTERM);worker.wait()
    if not (root/"linger").exists():raise SystemExit(143)
signal.signal(signal.SIGTERM,stop)
worker=subprocess.Popen([sys.executable,"-I","-B","-c","import time;time.sleep(60)"],start_new_session=True,
                        stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
(root/"pids").write_text("%d %d"%(os.getpid(),worker.pid))
deadline=time.monotonic()+20
while time.monotonic()<deadline:time.sleep(0.01)
'''


def actual(source, names):
    """The named actual functions; a retained beforeimage must match its provenance."""
    raw = source.read_bytes()
    if source in (BEFORE, UNSPLIT):
        provenance = json.loads((source.parent / "provenance.json").read_bytes())
        if provenance["files"]["mcp_server.before.source"]["sha256"] != hashlib.sha256(raw).hexdigest():
            raise AssertionError("Retained beforeimage changed: " + source.name)
    nodes = [node for node in ast.parse(raw).body if isinstance(node, ast.FunctionDef) and node.name in names]
    for node in nodes:
        node.decorator_list = []
    return compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec")


def selection(modules):
    return selector.Selection("0" * 40, ("agent_tools/leaf.py",), tuple(modules), 900)


def tests_output(identities, truncated=False):
    return {"completionOutput": {"tests": {"identities": identities, "count": len(identities), "total": len(identities),
                                           "truncated": truncated, "unparsedHeaders": 0}}}


class FailedFirstTests(unittest.TestCase):
    def runner(self, source, failing, outputs=None):
        ns = {**vars(server)}
        exec(actual(source, NAMES), ns)
        calls = []
        def inert_run(command, **kwargs):
            calls.append(list(command))
            # As the real runner reports it, a removed or import-failing module
            # fails as unittest.loader._FailedTest.<name>, which names no module.
            broken = [name for name in command[3:] if not self.exists(name) or name in self.broken] if command[1:3] == ["-m", "unittest"] else []
            failed = list(command) in failing or bool(broken)
            output = (outputs or {}).get(tuple(command)) or (tests_output(["unittest.loader._FailedTest." + name.rsplit(".", 1)[1]
                                                                            for name in broken]) if broken else {})
            return {"ok": not failed, "command": " ".join(command), "returncode": int(failed), **(output if failed else {})}
        ns.update(_run=inert_run, _agent_test_runtime_command=lambda command, fingerprint: command,
                  _snapshot_fingerprint=lambda: "a" * 64, _check_runner_source_error=lambda **kwargs: None,
                  _changed_paths=lambda: [], _infer_area=lambda task, area, paths: area or "agent_tools",
                  _git_stdout=lambda argv: "b" * 40, _agent_test_selection=lambda: self.selection, AGENT_TEST_PYTHON=sys.executable,
                  managed_check_lease=SimpleNamespace(acquire=lambda root: nullcontext(), ManagedCheckLeaseError=RuntimeError),
                  check_output_retention=SimpleNamespace(retain_completed_output=lambda *a, **k: None),
                  RECEIPT_PATH=self.directory / "prepush_receipt.json",
                  REPO_ROOT=self.directory)
        return ns, calls

    def setUp(self):
        temporary = tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);self.directory = Path(temporary.name)
        # An inert owned root holds only the selected test module names.
        (self.directory / "agent_tools/tests").mkdir(parents=True)
        self.selection, self.broken = selection(MODULES), set()
        for module in MODULES:self.write(module)

    def path(self, module):
        return self.directory / (module.replace(".", "/") + ".py")

    def exists(self, module):
        return self.path(module).is_file()

    def write(self, module):
        self.path(module).write_text("")

    def remove(self, module):
        # A removed module also leaves the current selection.
        self.path(module).unlink();self.selection = selection(name for name in self.selection.modules if name != module)

    def state(self):
        path = self.directory / "managed_check_failures.json"
        return json.loads(path.read_text()) if path.exists() else None

    def test_complete_failure_set_failed_first_rerun_then_complete_tier(self):
        outputs = {tuple(HALVES[0]): tests_output(["agent_tools.tests.test_readiness.Cases.test_one",
                                                    "agent_tools.tests.test_readiness.Cases.test_two"])}
        ns, calls = self.runner(CURRENT, [HYGIENE, HALVES[0]], outputs)
        result = ns["run_checks"]("agent_tools", "prepush")
        plan = ns["_commands_for"]("agent_tools", "prepush")
        self.assertFalse(result["ok"]);self.assertEqual(plan, calls)
        self.assertEqual(("failed", [HYGIENE, HALVES[0]], [None, ["agent_tools.tests.test_readiness"]]),
                         (self.state()["state"], [row["command"] for row in self.state()["failed"]],
                          [row["modules"] for row in self.state()["failed"]]))
        self.assertFalse((self.directory / "prepush_receipt.json").exists())
        # The complete tier is refused until the recorded failures pass alone.
        ns, calls = self.runner(CURRENT, [])
        refused = ns["run_checks"]("agent_tools", "prepush")
        self.assertEqual("failed-first", refused["blockers"][0]["phase"]);self.assertEqual([], calls)
        ns, calls = self.runner(CURRENT, [])
        rerun = ns["run_checks"]("agent_tools", "failed")
        self.assertTrue(rerun["ok"])
        self.assertEqual([HYGIENE, READINESS], calls)
        self.assertEqual("resolved", self.state()["state"]);self.assertFalse((self.directory / "prepush_receipt.json").exists())
        ns, calls = self.runner(CURRENT, [])
        complete = ns["run_checks"]("agent_tools", "prepush")
        self.assertTrue(complete["ok"]);self.assertEqual(ns["_commands_for"]("agent_tools", "prepush"), calls)
        self.assertEqual("clear", self.state()["state"]);self.assertTrue((self.directory / "prepush_receipt.json").exists())

    def test_persisting_failure_keeps_only_the_remaining_set_and_refuses_the_complete_tier(self):
        outputs = {tuple(HALVES[0]): tests_output(["agent_tools.tests.test_ssh_transport.Cases.test_one"])}
        ns, _ = self.runner(CURRENT, [HYGIENE, HALVES[0]], outputs)
        ns["run_checks"]("agent_tools", "prepush")
        narrowed = TRANSPORT
        ns, calls = self.runner(CURRENT, [narrowed], {tuple(narrowed): tests_output(["agent_tools.tests.test_ssh_transport.Cases.test_one"])})
        rerun = ns["run_checks"]("agent_tools", "failed")
        self.assertFalse(rerun["ok"]);self.assertEqual([HYGIENE, narrowed], calls)
        self.assertEqual([narrowed], [row["command"] for row in self.state()["failed"]])
        ns, calls = self.runner(CURRENT, [])
        self.assertEqual("failed-first", ns["run_checks"]("agent_tools", "prepush")["blockers"][0]["phase"]);self.assertEqual([], calls)

    def test_unparsed_or_timed_out_half_reruns_as_the_same_command_the_complete_tier_plans(self):
        # Neither truncated identities nor a timeout name failed modules; the
        # half reruns whole, so 'resolved' predicts that the planned half fits.
        for half, outputs in ((HALVES[0], {tuple(HALVES[0]): tests_output(["agent_tools.tests.test_readiness.Cases.test_one"], truncated=True)}),
                              (HALVES[1], None)):
            with self.subTest(half=half[3:]):
                ns, _ = self.runner(CURRENT, [half], outputs)
                ns["run_checks"]("agent_tools", "prepush")
                self.assertEqual([{"command": half, "modules": None}], self.state()["failed"])
                ns, calls = self.runner(CURRENT, [])
                self.assertTrue(ns["run_checks"]("agent_tools", "failed")["ok"]);self.assertEqual([half], calls)
                ns, calls = self.runner(CURRENT, [])
                self.assertTrue(ns["run_checks"]("agent_tools", "prepush")["ok"]);self.assertIn(half, calls)

    def test_unparsed_agent_commands_rerun_once_in_the_planned_ci_groups(self):
        # The whole retained beforeimage reran an agent command without failed
        # modules unchanged, removed modules included; it now reruns once in the
        # planner's groups.
        failed = lambda *commands: {"failed": [{"command": command, "modules": None} for command in commands]}
        before, _ = self.runner(UNSPLIT, [])
        ns, _ = self.runner(CURRENT, [])
        rerun, readiness = ns["_failed_commands"], "agent_tools.tests.test_readiness"
        # A legacy bulk command reruns as the CI halves, a whole selection gate first.
        self.assertEqual([SELECTED], before["_failed_commands"](failed(SELECTED)));self.assertEqual(HALVES, rerun(failed(SELECTED)))
        self.assertEqual([GATE, *HALVES], rerun(failed(UNIT + list(MODULES))))
        # For an unchanged selection a recorded half reruns as itself, never split
        # further; one fetch of the selection serves every regrouped row.
        fetched = []
        ns["_agent_test_selection"] = lambda: fetched.append(1) or self.selection
        self.assertEqual(HALVES, rerun(failed(*HALVES)));self.assertEqual(1, len(fetched))
        for half in HALVES:
            self.assertEqual([half], rerun(failed(half)))
        # Parity is over the union of the current selection and the remaining
        # recorded modules: one that left the selection but still exists is still
        # rerun and keeps its half whole, while a newly selected module between
        # recorded ones regroups them as the new CI shards do.
        self.selection = selection(name for name in MODULES if name != readiness)
        self.assertEqual([HALVES[0]], rerun(failed(HALVES[0])))
        self.selection = selection(MODULES + ("agent_tools.tests.test_docs_assistant",))
        self.assertEqual([UNIT + ["agent_tools.tests.test_agent_test_runner"], UNIT + [readiness, "agent_tools.tests.test_ssh_transport"]],
                         rerun(failed(HALVES[0])))
        # Rows with at most one non-gate module (the gate still runs alone) and rows
        # with recorded modules never consult the selection, so a stale selector
        # refuses only regrouping.
        self.selection = selection(MODULES)
        def refused():
            raise selector.SelectionError("stale reviewed pin")
        ns["_agent_test_selection"] = refused
        self.assertEqual([GATE, READINESS, HYGIENE], rerun(failed(GATE, READINESS, HYGIENE)))
        self.assertEqual([GATE, TRANSPORT], rerun(failed(UNIT + [CLOSE, "agent_tools.tests.test_ssh_transport"])))
        self.assertEqual([TRANSPORT], rerun({"failed": [{"command": HALVES[0], "modules": ["agent_tools.tests.test_ssh_transport"]}]}))
        with self.assertRaisesRegex(selector.SelectionError, "stale"):
            rerun(failed(HALVES[1]))
        ns["_agent_test_selection"] = lambda: self.selection
        # A removed module is dropped and the rest regroup by the current
        # selection; a row whose modules were all removed is skipped, including a
        # single-module row, which the beforeimage replayed unchanged.
        self.remove(readiness)
        self.assertEqual([UNIT + ["agent_tools.tests.test_agent_test_runner"], TRANSPORT], rerun(failed(HALVES[0])))
        self.assertEqual([READINESS], before["_failed_commands"](failed(READINESS)));self.assertEqual([], rerun(failed(READINESS)))
        for name in HALVES[1][3:]:
            self.remove(name)
        self.assertEqual([], rerun(failed(HALVES[1])))

    def test_removed_module_of_an_unparsed_command_resolves_instead_of_wedging(self):
        # A module of a timed-out command is removed before its rerun: of a whole
        # half, or of a narrowed one-module rerun that timed out in turn. The real
        # runner reports the removed module as unittest.loader._FailedTest, so the
        # whole retained beforeimage reran the row forever; it is dropped once.
        removed = "agent_tools.tests.test_readiness"
        for source, narrowed, expected in ((UNSPLIT, False, ["failed"] * 3), (UNSPLIT, True, ["failed"] * 3),
                                           (CURRENT, False, ["resolved"]), (CURRENT, True, ["resolved"])):
            with self.subTest(source=source.name, narrowed=narrowed):
                self.write(removed);self.selection = selection(MODULES)
                (self.directory / "managed_check_failures.json").unlink(missing_ok=True)
                bulk = SELECTED if source == UNSPLIT else HALVES[0]
                ns, _ = self.runner(source, [bulk], {tuple(bulk): tests_output([removed + ".Cases.test_one"])} if narrowed else None)
                ns["run_checks"]("agent_tools", "prepush")
                if narrowed:
                    ns, _ = self.runner(source, [READINESS])
                    ns["run_checks"]("agent_tools", "failed")
                self.assertEqual([{"command": READINESS if narrowed else bulk, "modules": None}], self.state()["failed"])
                self.remove(removed)
                states = []
                while len(states) < 3 and states[-1:] in ([], ["failed"]):
                    ns, _ = self.runner(source, [])
                    ns["run_checks"]("agent_tools", "failed");states.append(self.state()["state"])
                self.assertEqual(expected, states)

    def test_import_failure_reruns_its_half_instead_of_resolving_without_commands(self):
        # The real runner reports a module failing at import as
        # unittest.loader._FailedTest.<name>, which is no planned module: the half
        # records no failed modules and reruns whole until the import is fixed.
        self.broken = {"agent_tools.tests.test_readiness"}
        ns, _ = self.runner(CURRENT, [])
        ns["run_checks"]("agent_tools", "prepush")
        self.assertEqual([{"command": HALVES[0], "modules": None}], self.state()["failed"])
        for fixed, state in ((False, "failed"), (True, "resolved")):
            self.broken = set() if fixed else self.broken
            ns, calls = self.runner(CURRENT, [])
            self.assertEqual(fixed, ns["run_checks"]("agent_tools", "failed")["ok"])
            self.assertEqual(([HALVES[0]], state), (calls, self.state()["state"]))

    def test_failed_gate_stops_its_consumers_at_every_level(self):
        # The gate runs alone first in the prepush, focused and failed plans (a
        # legacy whole-selection row reruns as the gate and the CI halves); once
        # it fails, nothing planned after it is dispatched.
        outputs = {tuple(GATE): tests_output([CLOSE + ".Cases.test_one"])}
        path = self.directory / "managed_check_failures.json"
        for level in ("prepush", "focused", "failed"):
            with self.subTest(level=level):
                path.unlink(missing_ok=True)
                if level == "failed":
                    path.write_text(json.dumps({"version": 1, "state": "failed", "area": "agent_tools",
                                                "failed": [{"command": UNIT + list(MODULES), "modules": None}]}))
                ns, calls = self.runner(CURRENT, [GATE], outputs)
                plan = ns["_commands_for"]("agent_tools", level)
                self.assertEqual([GATE, *HALVES], [command for command in plan if command[1:3] == ["-m", "unittest"]])
                self.assertFalse(ns["run_checks"]("agent_tools", level)["ok"])
                self.assertEqual(plan[:plan.index(GATE) + 1], calls)

    def test_planner_and_unparsed_reruns_use_the_gate_then_exactly_the_hosted_ci_shards(self):
        # 0-7, 11 and 809 bulk modules sorting before and after the gate, with
        # and without it; 809 puts more than 200 modules in each shard. Neither
        # the plan nor a rerun depends on the selection's or the row's order.
        pool = (["agent_tools.tests.test_a%04d" % index for index in range(405)] +
                ["agent_tools.tests.test_z%04d" % index for index in range(404)])
        for module in pool:self.write(module)
        for size in (0, 1, 2, 3, 4, 5, 6, 7, 11, 809):
            for gated in (False, True):
                modules = sorted(pool[:(size + 1) // 2] + pool[405:405 + size // 2] + [CLOSE] * gated)
                self.selection = selection(modules[::-1])
                shards = [[name for name in selector.shard_selection(self.selection, index, 2).modules if name != CLOSE]
                          for index in (0, 1)]
                expected = [GATE] * gated + [UNIT + shard for shard in shards if shard]
                ns, _ = self.runner(CURRENT, [])
                plans = {level: ns["_commands_for"]("agent_tools", level) for level in ("prepush", "focused")}
                plans["failed"] = ns["_failed_commands"]({"failed": [{"command": UNIT + modules[::-1], "modules": None}] if modules else []})
                self.assertEqual(ns["PREPUSH_COMMANDS"][:3] + expected + ns["PREPUSH_COMMANDS"][3:], plans["prepush"])
                self.assertEqual(expected + ns["FOCUSED_COMMANDS"]["agent_tools"], plans["focused"])
                for level, plan in plans.items():
                    with self.subTest(size=size, gated=gated, level=level):
                        agent = [command for command in plan if command[1:3] == ["-m", "unittest"]]
                        self.assertEqual(expected, agent)
                        self.assertEqual(Counter(modules), Counter(name for command in agent for name in command[3:]))
                        self.assertTrue(all(len(command) > 3 for command in agent))
                        self.assertEqual([GATE] * gated, [command for command in agent if CLOSE in command])
                        if gated:
                            self.assertEqual(GATE, agent[0])
                        if size >= 3:
                            self.assertEqual(int(gated) + 2, len(agent))

    def test_duplicate_modules_are_refused_like_the_ci_shards(self):
        self.selection = selection(MODULES + ("agent_tools.tests.test_readiness",))
        ns, calls = self.runner(CURRENT, [])
        for level in ("prepush", "focused"):
            with self.assertRaisesRegex(selector.SelectionError, "Duplicate"):
                ns["_commands_for"]("agent_tools", level)
        refused = ns["run_checks"]("agent_tools", "prepush")
        self.assertEqual("agent-test-selection", refused["blockers"][0]["phase"]);self.assertEqual([], calls)

    def test_whole_before_plans_one_unbounded_bulk_command_current_plans_gate_then_ci_halves(self):
        # The original managed prepush ran the whole selection as one command and
        # hit its 50-minute bound; each hosted CI half now carries its own bound.
        unit = lambda plan: [command for command in plan if command[1:3] == ["-m", "unittest"]]
        before, _ = self.runner(UNSPLIT, [])
        current, _ = self.runner(CURRENT, [])
        for level in ("prepush", "focused"):
            self.assertEqual([GATE, SELECTED], unit(before["_commands_for"]("agent_tools", level)))
            self.assertEqual([GATE, *HALVES], unit(current["_commands_for"]("agent_tools", level)))

    def test_failed_level_requires_a_recorded_unresolved_failure_set(self):
        ns, calls = self.runner(CURRENT, [])
        result = ns["run_checks"]("agent_tools", "failed")
        self.assertEqual(("failed-first", "absent"), (result["blockers"][0]["phase"], result["blockers"][0]["state"]))
        self.assertEqual([], calls)

    def test_whole_before_has_no_failed_first_tier_and_repeats_the_complete_tier(self):
        (self.directory / "managed_check_failures.json").write_text(json.dumps({"version": 1, "state": "failed", "area": "agent_tools",
                                                                  "failed": [{"command": HYGIENE, "modules": None}]}))
        ns, calls = self.runner(BEFORE, [])
        self.assertFalse(ns["run_checks"]("agent_tools", "failed")["ok"]);self.assertEqual([], calls)
        ns, calls = self.runner(BEFORE, [])
        self.assertTrue(ns["run_checks"]("agent_tools", "prepush")["ok"]);self.assertEqual(ns["_commands_for"]("agent_tools", "prepush"), calls)
        ns, calls = self.runner(CURRENT, [])
        self.assertEqual("failed-first", ns["run_checks"]("agent_tools", "prepush")["blockers"][0]["phase"]);self.assertEqual([], calls)


@unittest.skipUnless(os.name == "posix", "POSIX signals and worker sessions")
class TimedOutCheckTerminationTests(unittest.TestCase):
    def launch(self, source, linger=False):
        temporary = tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);root = Path(temporary.name).resolve()
        if linger:(root / "linger").write_text("")
        ns = {**vars(server), "REPO_ROOT": root}
        exec(actual(source, {"_run"}), ns)
        started = time.monotonic()
        result = ns["_run"]([sys.executable, "-I", "-B", "-c", CHILD], timeout=2)
        elapsed = time.monotonic() - started
        alive = []
        for kill, pid in zip((os.kill, os.killpg), map(int, (root / "pids").read_text().split())):
            try:
                kill(pid, 0)
            except ProcessLookupError:
                alive.append(False)
            else:
                alive.append(True);kill(pid, signal.SIGKILL)  # Nothing outlives this test.
        return result, elapsed, (root / "term").is_file(), alive

    def test_timed_out_check_sigterms_first_so_its_worker_session_stops_before_the_next_command(self):
        # RED: the whole retained beforeimage SIGKILLed the child at once; its
        # handler never ran and the worker session outlived the check.
        before, elapsed, term, alive = self.launch(UNSPLIT)
        self.assertEqual((False, [False, True]), (term, alive))
        # GREEN: SIGTERM first; the handler stops the worker session and exits,
        # so the check returns within its grace with nothing left running.
        current, elapsed, term, alive = self.launch(CURRENT)
        self.assertEqual((True, [False, False]), (term, alive));self.assertLess(elapsed, 2 + 2)
        # A child that survives SIGTERM is SIGKILLed only after the bounded grace.
        lingering, elapsed, term, alive = self.launch(CURRENT, linger=True)
        self.assertEqual((True, [False, False]), (term, alive))
        self.assertGreaterEqual(elapsed, 2 + 2);self.assertLess(elapsed, 2 + 2 + 10)
        # The returned result is unchanged: no return code and the original timeout.
        self.assertEqual(before, current);self.assertEqual(before, lingering)
        self.assertEqual((False, None, ""), (before["ok"], before["returncode"], before["stdout"]))
        self.assertTrue(before["stderr"].endswith("timed out after 2 seconds"), before["stderr"])

    def test_text_mode_timeout_is_reported_even_when_the_drained_output_does_not_decode(self):
        # A text-mode caller's child is cut inside a multi-byte character, or its
        # SIGTERM handler writes undecodable bytes. Decoding the output drained in
        # the grace must not replace the original timeout; the whole retained
        # beforeimage's subprocess.run never decoded it.
        cut = r"import os,time;os.write(1,b'progress \xe2\x82');time.sleep(30)"
        stopping = ("import os,signal,sys,time\ndef stop(signum,frame):os.write(1,b'\\xff\\xfe');sys.exit(143)\n"
                    "signal.signal(signal.SIGTERM,stop);os.write(1,b'ready\\n');time.sleep(30)\n")
        def run(source, child):
            with tempfile.TemporaryDirectory() as root:
                ns = {**vars(server), "REPO_ROOT": Path(root)}
                exec(actual(source, {"_run"}), ns)
                return ns["_run"]([sys.executable, "-I", "-B", "-c", child], timeout=2)
        with ThreadPoolExecutor(4) as pool:  # Four independent two-second timeouts at once.
            results = list(pool.map(run, (UNSPLIT, CURRENT) * 2, (cut, cut, stopping, stopping)))
        for before, current in (results[:2], results[2:]):
            self.assertEqual(before, current);self.assertEqual((False, None), (current["ok"], current["returncode"]))
            self.assertTrue(current["stderr"].endswith("timed out after 2 seconds"), current["stderr"])

    def test_managed_bound_gets_a_thirty_second_grace_and_reports_its_own_timeout(self):
        # An inert child outlives the 50-minute bound and the grace; the whole
        # retained beforeimage sent SIGKILL at once, with no SIGTERM or grace.
        # However the grace ends (its bound, undecodable text output, another
        # error or an interrupt), the child is SIGKILLed and reaped; only an
        # interrupt propagates, and an interrupt while waiting kills it as
        # subprocess.run did.
        events, raised = [], []
        class Child:
            returncode = None
            def __init__(self, command, **kwargs):pass
            def __enter__(self):return self
            def __exit__(self, *exc):events.append("closed")
            def communicate(self, input=None, timeout=None):
                events.append(timeout);error = raised.pop(0)
                raise subprocess.TimeoutExpired("check", timeout) if error is subprocess.TimeoutExpired else error()
            def terminate(self):events.append("SIGTERM")
            def kill(self):events.append("SIGKILL")
            def wait(self, timeout=None):events.append("reaped");return -9
        def undecodable():
            return UnicodeDecodeError("utf-8", b"\xe2\x82", 0, 2, "unexpected end of data")
        expired, graceful = subprocess.TimeoutExpired, [50 * 60, "SIGTERM", 30, "SIGKILL", "reaped", "closed"]
        for source, errors, expected in ((UNSPLIT, [expired], [50 * 60, "SIGKILL", "reaped", "closed"]),
                                         (CURRENT, [expired, expired], graceful), (CURRENT, [expired, undecodable], graceful),
                                         (CURRENT, [expired, OSError], graceful),
                                         (UNSPLIT, [KeyboardInterrupt], [50 * 60, "SIGKILL", "closed"]),
                                         (CURRENT, [KeyboardInterrupt], [50 * 60, "SIGKILL", "closed"]),
                                         (CURRENT, [expired, KeyboardInterrupt], graceful)):
            interrupted = errors[-1] is KeyboardInterrupt
            with self.subTest(source=source.name, errors=[error.__name__ for error in errors]), tempfile.TemporaryDirectory() as root:
                events.clear();raised[:] = errors;ns = {**vars(server), "REPO_ROOT": Path(root)}
                exec(actual(source, {"_run"}), ns)
                with mock.patch.object(subprocess, "Popen", Child), self.assertRaises(KeyboardInterrupt) if interrupted else nullcontext():
                    result = ns["_run"](["check"], timeout=50 * 60, output_capture=lambda *a: None)
                self.assertEqual(expected, events)
                if not interrupted:
                    self.assertEqual((False, None, "Command 'check' timed out after 3000 seconds"),
                                     (result["ok"], result["returncode"], result["stderr"]))


if __name__ == "__main__":
    unittest.main()

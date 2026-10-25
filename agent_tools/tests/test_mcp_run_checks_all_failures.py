"""Actual planner and runner: one managed pass reports every independent failure.

The whole retained beforeimage stopped at its first failed command, hiding later
failures until another pass. Only command execution, output and receipt
boundaries are modeled; no subprocess, network or native action is invoked.
"""
import ast
import hashlib
import json
from pathlib import Path
import sys
import time
from types import SimpleNamespace
import unittest

from agent_tools import affected_agent_tests

CURRENT = Path(__file__).resolve().parents[1] / "mcp_server.py"
BEFORE = Path(__file__).parent / "fixtures/readiness_identity_refusal/mcp_server.before.source"
GATE = [sys.executable, "-m", "unittest", "agent_tools.tests.test_ssh_connection_session_close"]
SELECTED = [sys.executable, "-m", "unittest", "agent_tools.tests.test_ssh_transport"]
SELECTION = affected_agent_tests.Selection("0" * 40, ("agent_tools/ssh_transport.py",), (GATE[3], SELECTED[3]), 2)


def planner_runner(source):
    raw = source.read_bytes()
    if source == BEFORE:
        provenance = json.loads((BEFORE.parent / "provenance.json").read_bytes())
        assert hashlib.sha256(raw).hexdigest() == provenance["files"]["mcp_server.before.source"]["sha256"]
    names, functions = {"FOCUSED_COMMANDS", "PREPUSH_COMMANDS"}, {"_commands_for", "_run_check_commands"}
    chosen = [node for node in ast.parse(raw).body
              if isinstance(node, ast.FunctionDef) and node.name in functions
              or isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in node.targets)
              or isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id in names]
    ns = {"sys": sys, "AGENT_TEST_PYTHON": sys.executable, "Path": Path, "hashlib": hashlib, "time": time,
          "__file__": str(CURRENT), "Any": object, "REPO_ROOT": Path("/inert-unused-root"),
          "RECEIPT_PATH": Path("/inert-unused-root/receipt.json"), "affected_agent_tests": affected_agent_tests,
          "_agent_test_selection": lambda: SELECTION}
    exec(compile(ast.Module(body=chosen, type_ignores=[]), str(source), "exec"), ns)
    return ns


class RunChecksAllFailuresTests(unittest.TestCase):
    def run_plan(self, source, failing):
        ns = planner_runner(source)
        calls, writes = [], []
        def inert_run(command, **kwargs):
            calls.append(list(command))
            failed = list(command) in failing
            return {"ok": not failed, "command": list(command), "returncode": int(failed)}
        ns.update(_run=inert_run, _agent_test_runtime_command=lambda command, fingerprint: command,
                  _snapshot_fingerprint=lambda: "a" * 64, _check_runner_source_error=lambda **kwargs: None,
                  _display=lambda command: " ".join(command),
                  _command_blocker=lambda phase, result: {"phase": phase, "command": result["command"]},
                  _error=lambda tool, summary, **kwargs: {"ok": False, "tool": tool, "summary": summary, **kwargs},
                  _git_stdout=lambda argv: "b" * 40, _write_json=lambda path, value: writes.append(value),
                  check_output_retention=SimpleNamespace(retain_completed_output=lambda *a, **k: None))
        plan = ns["_commands_for"]("agent_tools", "prepush")
        return plan, ns["_run_check_commands"]("agent_tools", "prepush", plan), calls, writes

    def test_whole_before_stops_at_first_failure_current_reports_every_independent_failure(self):
        plan = planner_runner(CURRENT)["_commands_for"]("agent_tools", "prepush")
        first, last = plan[1], plan[-1]
        self.assertNotIn(GATE, (first, last))
        _, old, calls, writes = self.run_plan(BEFORE, [first, last])
        self.assertFalse(old["ok"]);self.assertEqual(first, calls[-1]);self.assertNotIn(last, calls)
        plan, new, calls, writes = self.run_plan(CURRENT, [first, last])
        self.assertFalse(new["ok"]);self.assertEqual(plan, calls);self.assertEqual([], writes)
        self.assertEqual([first, last], [blocker["command"] for blocker in new["blockers"]])
        self.assertEqual(len(plan), len(new["command_results"]))
        self.assertIn(" ".join(first), new["summary"]);self.assertIn(" ".join(last), new["summary"])

    def test_failed_safety_gate_still_never_dispatches_its_consumers(self):
        for source in (BEFORE, CURRENT):
            with self.subTest(before=source == BEFORE):
                plan, result, calls, writes = self.run_plan(source, [GATE])
                self.assertFalse(result["ok"]);self.assertEqual(GATE, calls[-1]);self.assertNotIn(SELECTED, calls)
                self.assertEqual([], writes);self.assertEqual(len(calls), len(result["command_results"]))

    def test_all_passing_plan_keeps_single_complete_receipt(self):
        plan, result, calls, writes = self.run_plan(CURRENT, [])
        self.assertTrue(result["ok"]);self.assertEqual(plan, calls);self.assertEqual(1, len(writes))
        self.assertEqual([" ".join(command) for command in plan], writes[0]["commands"])

    def test_prepush_gradle_continues_past_a_failed_task(self):
        old = [command for command in planner_runner(BEFORE)["PREPUSH_COMMANDS"] if command[0] == "./gradlew"]
        new = [command for command in planner_runner(CURRENT)["PREPUSH_COMMANDS"] if command[0] == "./gradlew"]
        self.assertEqual(1, len(old));self.assertNotIn("--continue", old[0])
        self.assertEqual(["./gradlew", "--continue", *old[0][1:]], new[0])


if __name__ == "__main__":
    unittest.main()

"""Actual planner and runner: applicable SSH-close refusal precedes consumers.

Only existing command execution/output/receipt boundaries are modeled. No
subprocess, MCP server import, network, inventory, or native action is invoked.
"""
import ast
import hashlib
from pathlib import Path
import sys
import time
from types import SimpleNamespace
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "mcp_server.py"
GATE = [sys.executable, "-m", "unittest", "agent_tools.tests.test_ssh_connection_session_close"]
SELECTED = [sys.executable, "-m", "unittest", "agent_tools.tests.test_ssh_transport"]


def actual_planner_runner():
    tree = ast.parse(SOURCE.read_bytes(), filename=str(SOURCE))
    names = {"FOCUSED_COMMANDS", "PREPUSH_COMMANDS"}
    functions = {"_commands_for", "_run_check_commands"}
    chosen = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in node.targets):
            chosen.append(node)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id in names:
            chosen.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name in functions:
            chosen.append(node)
    observed = {n.name for n in chosen if isinstance(n, ast.FunctionDef)}
    assert observed == functions and len(chosen) == 4
    ns = {"sys": sys, "AGENT_TEST_PYTHON": sys.executable, "Path": Path,
          "hashlib": hashlib, "time": time, "__file__": str(SOURCE),
          "Any": object, "REPO_ROOT": Path("/inert-unused-root"),
          "RECEIPT_PATH": Path("/inert-unused-root/receipt.json"),
          "_agent_test_selection": lambda: SimpleNamespace(commands=lambda python: [GATE, SELECTED])}
    exec(compile(ast.Module(body=chosen, type_ignores=[]), str(SOURCE), "exec"), ns)
    return ns


class PrepushSshCloseGateTests(unittest.TestCase):
    def runner(self, fail_gate=False):
        ns = actual_planner_runner()
        calls, writes = [], []
        def inert_run(command, **kwargs):
            calls.append(list(command))
            return {"ok": not (fail_gate and command == GATE),
                    "command": list(command), "returncode": int(fail_gate and command == GATE)}
        ns.update(_run=inert_run, _agent_test_runtime_command=lambda command, fingerprint: command, _snapshot_fingerprint=lambda: "a" * 64,
                  _check_runner_source_error=lambda **kwargs: None,
                  _display=lambda command: " ".join(command),
                  _command_blocker=lambda phase, result: {"phase": phase, "state": "failed"},
                  _error=lambda tool, summary, **kwargs: {"ok": False, "tool": tool, **kwargs},
                  _git_stdout=lambda argv: "b" * 40,
                  _write_json=lambda path, value: writes.append(value),
                  check_output_retention=SimpleNamespace(retain_completed_output=lambda *a, **k: None))
        return ns, calls, writes

    def test_applicable_gate_precedes_selected_consumers(self):
        ns = actual_planner_runner()
        plan = ns["_commands_for"]("agent_tools", "prepush")
        self.assertEqual(1, plan.count(GATE))
        self.assertLess(plan.index(GATE), plan.index(SELECTED))
        self.assertEqual([["git", "diff", "--check"], ["./scripts/check_release_hygiene.sh"],
                          ["./scripts/check_docs_hygiene.sh"], GATE], plan[:4])

    def test_failed_close_gate_never_dispatches_consumers_or_receipt(self):
        ns, calls, writes = self.runner(fail_gate=True)
        plan = ns["_commands_for"]("agent_tools", "prepush")
        result = ns["_run_check_commands"]("agent_tools", "prepush", plan)
        self.assertFalse(result["ok"])
        self.assertEqual(GATE, calls[-1])
        self.assertNotIn(SELECTED, calls)
        self.assertEqual([], writes)
        self.assertEqual(len(calls), len(result["command_results"]))

    def test_passed_gate_keeps_product_checks_and_complete_receipt(self):
        ns, calls, writes = self.runner()
        plan = ns["_commands_for"]("docs", "prepush")
        result = ns["_run_check_commands"]("docs", "prepush", plan)
        self.assertTrue(result["ok"])
        self.assertEqual(plan, calls)
        self.assertEqual(1, calls.count(SELECTED))
        self.assertEqual(17, len(calls))
        self.assertEqual(1, len(writes))
        self.assertEqual([" ".join(command) for command in plan], writes[0]["commands"])
        self.assertTrue(any(command[0] == "./gradlew" for command in calls))

    def test_product_only_omits_agent_checks_and_plans_are_independent(self):
        ns = actual_planner_runner()
        ns["_agent_test_selection"] = lambda: SimpleNamespace(commands=lambda python: [])
        for area, commands in ns["FOCUSED_COMMANDS"].items():
            self.assertEqual(commands, ns["_commands_for"](area, "focused"))
        self.assertFalse(any("unittest" in c for c in ns["_commands_for"]("desktop", "prepush")))
        plan = ns["_commands_for"]("docs", "prepush")
        plan[0].append("caller-change")
        self.assertEqual(["git", "diff", "--check"], ns["_commands_for"]("docs", "prepush")[0])

    def test_changed_after_selection_never_runs_checks_or_publishes_receipt(self):
        ns, calls, writes = self.runner()
        result = ns["_run_check_commands"]("agent_tools", "prepush", [GATE], "c" * 64)
        self.assertFalse(result["ok"])
        self.assertEqual([], calls)
        self.assertEqual([], writes)


if __name__ == "__main__":
    unittest.main()

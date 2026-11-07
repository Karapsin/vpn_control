"""Real owned children, original timeout source, and existing runner cancellation."""
from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import select
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import types
from types import SimpleNamespace
import unittest
from unittest import mock

from agent_tools import check_output_retention, managed_agent_check as owned, managed_check_lease

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).with_name("fixtures") / "managed_agent_timeout"
REAL_POPEN = subprocess.Popen


def source(path, original_name):
    path = Path(path)
    current = ROOT / "agent_tools" / original_name
    before = FIXTURE / (original_name + ".before.source")
    if path not in (current, before):
        raise ValueError("Unknown causal source")
    raw = path.read_bytes()
    if path == before:
        row = json.loads((FIXTURE / "provenance.json").read_bytes())[original_name]
        if len(raw) != row["bytes"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
            raise ValueError("Original causal source changed")
    return raw


def original_run(root):
    path = Path(os.environ.get("MANAGED_AGENT_MCP_SOURCE", ROOT / "agent_tools/mcp_server.py"))
    tree = ast.parse(source(path, "mcp_server.py"), filename=str(path))
    names = {"_run", "_display", "_bounded", "_failure_log_excerpt"}
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    if {node.name for node in functions} != names:
        raise ValueError("Complete original command boundary required")
    # Declare the complete execution closure before compiling either source.
    namespace = {"Any": object, "subprocess": subprocess, "Path": Path,
                 "os": os, "re": re, "shlex": shlex, "REPO_ROOT": root,
                 "MAX_OUTPUT_CHARS": 12000, "check_output_retention": check_output_retention,
                 "managed_agent_check": owned,
                 "local_build_environment": SimpleNamespace(
                     apply=lambda root, environment: environment,
                     LocalBuildEnvironmentError=RuntimeError)}
    exec(compile(ast.Module(functions, []), str(path), "exec"), namespace)
    return namespace["_run"]


@unittest.skipUnless(os.name == "posix", "POSIX runner cancellation and owned pipes")
class ManagedAgentCheckTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="managed-agent-check-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.environment = dict(os.environ)
        self.environment.pop("DYLD_INSERT_LIBRARIES", None)
        self.processes = []

    def close_owned(self, process):
        if process.poll() is None:
            try:
                process.terminate()
            except ProcessLookupError:
                pass
        # Preserve the same child and streams after any readiness assertion.
        # Do not orphan an actual runner by killing its coordinator.
        while True:
            try:
                process.communicate(timeout=1)
                break
            except subprocess.TimeoutExpired:
                continue
        self.assertIsNotNone(process.returncode)

    def ready_factory(self, program):
        """Qualify Python readiness on a separate pipe before measuring timeout."""
        def start(*args, **kwargs):
            read, write = os.pipe()
            environment = dict(kwargs.get("env", self.environment))
            environment["OWNED_READY_FD"] = str(write)
            kwargs.update(env=environment, pass_fds=(*kwargs.get("pass_fds", ()), write))
            try:
                process = REAL_POPEN(*args, **kwargs)
                self.processes.append(process)
                self.addCleanup(self.close_owned, process)
            finally:
                os.close(write)
            try:
                self.assertTrue(select.select([read], [], [], 10)[0], "owned child readiness")
                self.assertEqual(b"R", os.read(read, 1))
            finally:
                os.close(read)
            return process
        return mock.patch.object(subprocess, "Popen", side_effect=start)

    def script(self, body):
        path = self.root / "child.py"
        path.write_text(body)
        return [sys.executable, "-I", "-B", str(path)]

    def test_timeout_keeps_original_handler_exit_and_binary_streams(self):
        command = self.script("""import os,signal,sys,time
def close(signum,frame):
 sys.stdout.buffer.write(b'closed\\xff\\n');sys.stdout.buffer.flush()
 sys.stderr.buffer.write(b'ended\\xfe\\n');sys.stderr.buffer.flush()
 raise SystemExit(17)
signal.signal(signal.SIGTERM,close)
os.write(int(os.environ['OWNED_READY_FD']),b'R')
while True:time.sleep(1)
""")
        run = original_run(self.root)
        arguments = {"timeout": 0.05, "output_capture": lambda rc, out, err:
                     check_output_retention.retain_completed_output(
                         self.root, label="causal-timeout", returncode=rc,
                         stdout=out, stderr=err, source_fingerprint="a" * 64)}
        if "managed_agent" in inspect.signature(run).parameters:
            arguments["managed_agent"] = True
        with self.ready_factory(command):
            result = run(command, **arguments)
        self.assertFalse(result["ok"])
        self.assertEqual(17, result["returncode"], result)
        metadata = result["completionOutput"]
        capsule = self.root / ".rag_index/check-runs" / metadata["runId"]
        self.assertEqual(b"closed\xff\n", (capsule / "stdout.private").read_bytes())
        self.assertEqual(b"ended\xfe\n", (capsule / "stderr.private").read_bytes())
        self.assertTrue(result["managedAgent"]["timedOut"])
        self.assertEqual({"stdout": True, "stderr": True}, result["managedAgent"]["streamEof"])
        self.assertTrue(all(process.poll() is not None for process in self.processes))

    def test_actual_runner_cancels_reaps_workers_and_preserves_journal(self):
        package = self.root / "agent_tools/tests"
        package.mkdir(parents=True)
        (package.parent / "__init__.py").write_bytes(b"")
        (package / "__init__.py").write_bytes(b"")
        (package / "test_owned.py").write_text("""import os,sys,time,unittest
from pathlib import Path
class Owned(unittest.TestCase):
 def test_wait(self):
  sys.stdout.buffer.write('worker λ\\n'.encode('utf-8'));sys.stdout.buffer.flush()
  Path('worker-ready').write_text('ready')
  while not Path('worker-release').exists():time.sleep(.005)
""")
        runner = self.root / "agent_tools/agent_test_runner.py"
        shutil.copyfile(ROOT / "agent_tools/agent_test_runner.py", runner)
        state = self.root / ".rag_index"
        state.mkdir(mode=0o700)
        plan = state / "plan.json"
        plan.write_text(json.dumps({"schemaVersion": 1, "sourceFingerprint": "a" * 64,
                                    "modules": ["agent_tools.tests.test_owned"], "maxWorkers": 1}))
        report = state / "run"
        command = [sys.executable, "-B", str(runner), "--plan-file", str(plan), "--report-dir", str(report)]
        def ready(*args, **kwargs):
            process = REAL_POPEN(*args, **kwargs)
            self.processes.append(process)
            self.addCleanup(self.close_owned, process)
            deadline = time.monotonic() + 10
            while not (self.root / "worker-ready").exists():
                self.assertIsNone(process.poll(), "runner exited before owned test readiness")
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.005)
            return process
        run = original_run(self.root)
        arguments = {"timeout": 0.05}
        if "managed_agent" in inspect.signature(run).parameters:
            arguments["managed_agent"] = True
        with mock.patch.object(subprocess, "Popen", side_effect=ready):
            result = run(command, **arguments)
        started = json.loads((report / "worker-0000/started.json").read_bytes())
        try:
            self.assertEqual(130, result["returncode"], result)
            self.assertTrue(result["managedAgent"]["timedOut"])
            body = json.loads((report / "report.json").read_bytes())
            self.assertEqual("cancelled", body["state"])
            self.assertFalse(body["successful"])
            self.assertEqual(1, len(body["workers"]))
            worker = body["workers"][0]
            for name in ("reaped", "sessionAbsent", "fixtureRootRemoved"):
                self.assertTrue(worker[name], worker)
            self.assertFalse(worker["descendantLeak"])
            with self.assertRaises(ProcessLookupError):
                os.killpg(worker["pid"], 0)
            self.assertIn("worker λ\n".encode("utf-8"), (report / "worker-0000/stdout.txt").read_bytes())
            journal = [json.loads(line) for line in (report / "worker-0000/timings.jsonl").read_bytes().splitlines()]
            self.assertEqual("started", journal[0]["event"])
            self.assertEqual({"stdout": True, "stderr": True}, result["managedAgent"]["streamEof"])
        finally:
            # The old boundary kills the coordinator. Its one known worker has
            # a passive exit gate: never signal a rediscovered process identity.
            (self.root / "worker-release").write_text("release original")
            deadline = time.monotonic() + 10
            while True:
                try:
                    os.killpg(started["pid"], 0)
                except ProcessLookupError:
                    break
                self.assertLess(time.monotonic(), deadline, "original worker closure unproved")
                time.sleep(0.005)
            fixture = Path(started["fixtureRoot"])
            if fixture.exists():
                from agent_tools import agent_test_runner
                self.assertTrue(agent_test_runner.cleanup_fixture_root(fixture, started["fixtureRootGeneration"]))

    def test_cleanup_pending_keeps_original_call_and_lease_until_eof(self):
        gate = self.root / "release"
        command = self.script("""import os,signal,sys,time
from pathlib import Path
def close(signum,frame):
 Path('cleanup-started').write_text('started')
 while not Path('release').exists():time.sleep(.005)
 sys.stderr.buffer.write(b'final\\xff');sys.stderr.buffer.flush()
 raise SystemExit(0)
signal.signal(signal.SIGTERM,close)
os.write(int(os.environ['OWNED_READY_FD']),b'R')
while True:time.sleep(1)
""")
        results, failures = [], []
        def execute():
            try:
                with managed_check_lease.acquire(self.root):
                    results.append(owned.run(command, cwd=self.root, env=self.environment,
                                             timeout=0.05, cleanup_seconds=0.05))
            except BaseException as error:
                failures.append(error)
        with self.ready_factory(command):
            thread = threading.Thread(target=execute)
            thread.start()
            try:
                deadline = time.monotonic() + 10
                while not (self.root / "cleanup-started").exists():
                    self.assertLess(time.monotonic(), deadline)
                    self.assertTrue(thread.is_alive(), failures)
                    time.sleep(0.005)
                # The work and separate cleanup windows have both expired.
                thread.join(0.15)
                self.assertTrue(thread.is_alive())
                with self.assertRaises(managed_check_lease.ManagedCheckLeaseError) as caught:
                    with managed_check_lease.acquire(self.root):
                        self.fail("pending owner released its lease")
                self.assertEqual("busy", caught.exception.state)
                self.assertEqual([], results)
            finally:
                gate.write_text("release original")
                thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertEqual([], failures)
        self.assertEqual(1, len(results))
        outcome = results[0]
        self.assertTrue(outcome.timed_out and outcome.cleanup_budget_exceeded)
        self.assertEqual(0, outcome.completed.returncode)
        self.assertEqual(b"final\xff", outcome.completed.stderr)
        with managed_check_lease.acquire(self.root):
            pass

    def test_zero_exit_after_timeout_remains_failed_validation(self):
        command = self.script("""import os,signal,time
def close(signum,frame):raise SystemExit(0)
signal.signal(signal.SIGTERM,close)
os.write(int(os.environ['OWNED_READY_FD']),b'R')
while True:time.sleep(1)
""")
        run = original_run(self.root)
        arguments = {"timeout": 0.05}
        if "managed_agent" in inspect.signature(run).parameters:
            arguments["managed_agent"] = True
        with self.ready_factory(command):
            result = run(command, **arguments)
        self.assertEqual(0, result["returncode"])
        self.assertFalse(result["ok"])
        self.assertTrue(result["managedAgent"]["timedOut"])

    def test_keyboard_interrupt_keeps_original_child_lease_and_streams(self):
        implementation = owned
        selected = os.environ.get("MANAGED_AGENT_OWNER_SOURCE")
        if selected:
            implementation = types.ModuleType("_owned_interrupt_before")
            sys.modules[implementation.__name__] = implementation
            self.addCleanup(sys.modules.pop, implementation.__name__, None)
            exec(compile(source(Path(selected), "managed_agent_check.py"), selected, "exec"), implementation.__dict__)
        command = self.script("""import os,signal,sys,time
from pathlib import Path
def close(signum,frame):
 while not Path('release').exists():time.sleep(.005)
 sys.stdout.buffer.write(b'closed\\xff');sys.stdout.buffer.flush()
 sys.stderr.buffer.write(b'ended\\xfe');sys.stderr.buffer.flush()
 raise SystemExit(0)
signal.signal(signal.SIGTERM,close)
os.write(int(os.environ['OWNED_READY_FD']),b'R')
while True:time.sleep(1)
""")
        original_popen = REAL_POPEN
        interrupted = threading.Event()
        errors, terminations = [], []
        def create(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            communicate, terminate = process.communicate, process.terminate
            def once(*args, **kwargs):
                if not interrupted.is_set():
                    interrupted.set()
                    raise KeyboardInterrupt("owned observation interruption")
                return communicate(*args, **kwargs)
            def termination():
                terminations.append(True)
                return terminate()
            process.communicate, process.terminate = once, termination
            return process
        def execute():
            try:
                with managed_check_lease.acquire(self.root):
                    implementation.run(command, cwd=self.root, env=self.environment,
                                       timeout=0.05, cleanup_seconds=0.05)
            except BaseException as error:
                errors.append(error)
        with mock.patch(__name__ + ".REAL_POPEN", side_effect=create), self.ready_factory(command):
            thread = threading.Thread(target=execute)
            thread.start()
            try:
                self.assertTrue(interrupted.wait(10))
                thread.join(0.4)
                self.assertTrue(thread.is_alive(), "interruption detached original custody")
                with self.assertRaises(managed_check_lease.ManagedCheckLeaseError):
                    with managed_check_lease.acquire(self.root):
                        self.fail("interrupted owner released its lease")
            finally:
                (self.root / "release").write_text("release original")
                thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(1, len(errors))
        self.assertIsInstance(errors[0], KeyboardInterrupt)
        outcome = errors[0].managed_agent_outcome
        self.assertEqual(b"closed\xff", outcome.completed.stdout)
        self.assertEqual(b"ended\xfe", outcome.completed.stderr)
        self.assertEqual(0, outcome.completed.returncode)
        self.assertTrue(outcome.timed_out)
        self.assertEqual(1, len(terminations))

    def test_private_scope_rejects_serial_foreign_and_non_posix_commands(self):
        root = self.root
        token = "12345678-1234-1234-1234-123456789abc"
        base = root / ".rag_index/agent-test-runs"
        command = [sys.executable, str(root / "agent_tools/agent_test_runner.py"),
                   "--plan-file", str(base / (token + ".plan.json")), "--report-dir", str(base / token)]
        self.assertTrue(owned.is_private_command(root, command))
        for index, value in ((1, "/foreign/agent_test_runner.py"), (2, "--serial-stdout"),
                             (3, str(base / "other.plan.json")), (5, str(root / token))):
            altered = list(command)
            altered[index] = value
            self.assertFalse(owned.is_private_command(root, altered))
        with mock.patch.object(owned.os, "name", "nt"):
            self.assertFalse(owned.is_private_command(root, command))


class ManagedBatchTests(unittest.TestCase):
    def selection(self, modules):
        path = Path(os.environ.get("MANAGED_AGENT_SELECTOR_SOURCE", ROOT / "agent_tools/affected_agent_tests.py"))
        tree = ast.parse(source(path, "affected_agent_tests.py"), filename=str(path))
        chosen = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name in {"Selection", "SelectionError"}]
        namespace = {"dataclass": dataclass}
        exec(compile(ast.Module(chosen, []), str(path), "exec"), namespace)
        selection = namespace["Selection"]("a" * 40, (), tuple(modules), len(modules))
        if "max_modules_per_command" in inspect.signature(selection.commands).parameters:
            return selection.commands(sys.executable, max_modules_per_command=16)
        return selection.commands(sys.executable)

    def test_consecutive_bound_keeps_every_module_once_in_original_order(self):
        gate = "agent_tools.tests.test_ssh_connection_session_close"
        modules = ["agent_tools.tests.test_case_%04d" % i for i in range(513)]
        modules.insert(201, gate)
        commands = self.selection(modules)
        self.assertEqual([gate], commands[0][3:])
        expected = [gate] + [name for name in modules if name != gate]
        actual = [name for command in commands for name in command[3:]]
        self.assertEqual(expected, actual)
        self.assertEqual(len(actual), len(set(actual)))
        self.assertLessEqual(max(len(command[3:]) for command in commands), 16)
        self.assertEqual(34, len(commands))
        self.assertEqual(hashlib.sha256("\n".join(expected).encode()).hexdigest(),
                         hashlib.sha256("\n".join(actual).encode()).hexdigest())

    def test_complete_saved_batches_fit_the_same_scaled_work_deadline(self):
        # This is an owned schedule witness, not a performance prediction about
        # native tests. READY/GO excludes Python startup from the 1.2 s budget.
        modules = ["agent_tools.tests.test_case_%04d" % i for i in range(48)]
        commands = self.selection(modules)
        observed, timed_out = [], False
        with tempfile.TemporaryDirectory(prefix="managed-batch-deadline-") as temporary:
            root = Path(temporary)
            program = root / "producer.py"
            program.write_text("""import json,sys,time
print('READY',flush=True)
if sys.stdin.readline()!='GO\\n':raise SystemExit(11)
for name in sys.argv[1:]:time.sleep(.035)
print(json.dumps(sys.argv[1:]),flush=True)
""")
            environment = dict(os.environ)
            environment.pop("DYLD_INSERT_LIBRARIES", None)
            for command in commands:
                argv = [sys.executable, "-I", "-B", str(program), *command[3:]]
                self.assertLessEqual(sum(len(word.encode()) + 1 for word in argv), 60000)
                with subprocess.Popen(argv, cwd=root, env=environment, stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
                    self.assertEqual(b"READY\n", process.stdout.readline())
                    try:
                        stdout, stderr = process.communicate(b"GO\n", timeout=1.2)
                    except subprocess.TimeoutExpired:
                        timed_out = True
                        process.kill()  # Exact owned producer has no descendants.
                        process.communicate()
                        break
                    self.assertEqual(0, process.returncode, stderr)
                    self.assertEqual(b"", stderr)
                    observed.extend(json.loads(stdout))
        self.assertFalse(timed_out, "aggregate command exhausted the unchanged scaled budget")
        self.assertEqual(modules, observed)


if __name__ == "__main__":
    unittest.main(verbosity=2)

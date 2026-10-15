#!/usr/bin/env python3
"""Portable causal checks for macos_vm_resource_monitor.py."""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import os
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent
MONITOR = ROOT / "macos_vm_resource_monitor.py"
SPEC = importlib.util.spec_from_file_location("macos_vm_resource_monitor", MONITOR)
assert SPEC is not None and SPEC.loader is not None
MONITOR_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MONITOR_MODULE)


FAKE_TART = """#!/usr/bin/env python3
import json, os, signal, sys, time
root = os.environ['FAKE_ROOT']
args = sys.argv[1:]
if args[:1] == ['stop'] and os.environ.get('STOP_JOURNAL_GATE'):
    # Model a dispatched helper whose child-side receipt has not started yet.
    while not os.path.exists(os.environ['STOP_JOURNAL_GATE']):
        time.sleep(.01)
with open(os.path.join(root, 'calls.jsonl'), 'a') as output:
    output.write(json.dumps(args) + '\\n')
if args[:1] == ['get']:
    print(json.dumps({'State': 'stopped', 'Running': False}))
elif args[:1] == ['run']:
    open(os.path.join(root, 'child.pid'), 'w').write(str(os.getpid()))
    def exited(_signum, _frame):
        open(os.path.join(root, 'child.exited'), 'w').close()
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, exited)
    heartbeat = 0
    while not os.path.exists(os.path.join(root, 'stop')):
        temporary = os.path.join(root, 'child.heartbeat.tmp')
        open(temporary, 'w').write(str(heartbeat))
        os.replace(temporary, os.path.join(root, 'child.heartbeat'))
        heartbeat += 1
        time.sleep(.01)
    exit_delay = float(os.environ.get('CHILD_EXIT_DELAY', '0'))
    if exit_delay:
        time.sleep(exit_delay)
elif args[:1] == ['stop']:
    stop_delay = float(os.environ.get('STOP_DELAY', '0'))
    if stop_delay:
        time.sleep(stop_delay)
    if os.environ.get('STOP_BLOCK'):
        while True:
            time.sleep(1)
    open(os.path.join(root, 'stop'), 'w').close()
else:
    raise SystemExit(64)
"""

FAKE_SYSCTL = """#!/usr/bin/env python3
import os, sys
root = os.environ['FAKE_ROOT']
if sys.argv[1:] == ['-n', 'kern.memorystatus_vm_pressure_level']:
    print(open(os.path.join(root, 'pressure')).read().strip())
elif sys.argv[1:] == ['vm.swapusage']:
    print('vm.swapusage: synthetic')
else:
    raise SystemExit(64)
"""

DISPATCH_PROBE = """#!/usr/bin/env python3
import importlib.util, json, os, pathlib, subprocess, sys
monitor_path, root, tart = sys.argv[1:4]
del sys.argv[1:4]
spec = importlib.util.spec_from_file_location('owned_monitor', monitor_path)
monitor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(monitor)
expected = [tart, 'stop', 'owned-vm', '--timeout', '60']
trace = pathlib.Path(root) / 'stop-dispatch.jsonl'
original_popen = subprocess.Popen
def dispatched(args, *positional, **keywords):
    recording = isinstance(args, (list, tuple)) and list(args) == expected
    if recording and trace.exists() and trace.stat().st_size > 8192:
        raise RuntimeError('Owned stop-dispatch trace exceeded its finite bound')
    child = original_popen(args, *positional, **keywords)
    if recording:
        # The real constructor returned. Preserve run/communicate and its timeout.
        try:
            row = json.dumps({'argv': list(args), 'pid': child.pid, 'phase': 'spawned'}) + '\\n'
            if len(row.encode('utf-8')) + (trace.stat().st_size if trace.exists() else 0) > 8192:
                raise RuntimeError('Owned stop-dispatch trace exceeded its finite bound')
            descriptor = os.open(trace, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(descriptor, 'a', encoding='utf-8') as output:
                output.write(row)
                output.flush()
                os.fsync(output.fileno())
        except BaseException:
            # Only this exact newly created test stop helper belongs to the probe.
            child.kill()
            child.wait()
            raise
    return child
subprocess.Popen = dispatched
try:
    raise SystemExit(monitor.main())
finally:
    subprocess.Popen = original_popen
"""


class MonitorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.tart = self.write_executable("fake-tart", FAKE_TART)
        self.sysctl = self.write_executable("fake-sysctl", FAKE_SYSCTL)
        self.vm_stat = self.write_executable("fake-vm-stat", "#!/usr/bin/env python3\nprint(\"Mach Virtual Memory Statistics: (page size of 16384 bytes)\\nPages free: 100.\\nPages inactive: 200.\\nPages speculative: 300.\")\n")
        (self.root / "pressure").write_text("1\n", encoding="utf-8")
        self.environment = dict(os.environ, FAKE_ROOT=str(self.root))

    def tearDown(self) -> None:
        pid_file = self.root / "child.pid"
        if pid_file.exists() and not (self.root / "stop").exists():
            try:
                os.kill(int(pid_file.read_text(encoding="utf-8")), signal.SIGTERM)
            except ProcessLookupError:
                pass
            else:
                self.wait_for(self.root / "child.exited")
        self.temporary.cleanup()

    def write_executable(self, name: str, content: str) -> Path:
        path = self.root / name
        path.write_text(textwrap.dedent(content), encoding="utf-8")
        path.chmod(0o700)
        return path

    def start_monitor(self, evidence: Path, stop_timeout_seconds: str = "1", graphical: bool = False,
                      record_stop_dispatch: bool = False) -> subprocess.Popen[str]:
        entry = [sys.executable, str(MONITOR)]
        if record_stop_dispatch:
            probe = self.write_executable("monitor-dispatch-probe.py", DISPATCH_PROBE)
            entry = [sys.executable, str(probe), str(MONITOR), str(self.root), str(self.tart)]
        return subprocess.Popen(
            entry + ["--vm-name", "owned-vm", "--evidence-dir", str(evidence),
             "--tart", str(self.tart), "--sysctl", str(self.sysctl), "--vm-stat", str(self.vm_stat), "--interval-seconds", "0.02",
             "--stop-timeout-seconds", stop_timeout_seconds] + (["--graphics"] if graphical else []),
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=self.environment,
        )

    def wait_for(self, path: Path) -> None:
        deadline = time.monotonic() + 3
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertTrue(path.exists(), path)

    def assert_monitor_exit(self, monitor: subprocess.Popen[str], expected: int, evidence: Path) -> None:
        actual = monitor.wait(timeout=3)
        receipts: dict[str, object] = {}
        for name in ("stop.json", "stop-uncertain.json", "observation-failure.json", "terminal.json"):
            path = evidence / name
            if path.exists():
                receipts[name] = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(expected, actual, receipts)

    def wait_for_heartbeat_after(self, value: int) -> None:
        heartbeat = self.root / "child.heartbeat"
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            observed = self.heartbeat_value(heartbeat)
            if observed is not None and observed > value:
                return
            time.sleep(.01)
        self.fail("synthetic child heartbeat did not advance")

    def wait_for_heartbeat(self) -> int:
        heartbeat = self.root / "child.heartbeat"
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            observed = self.heartbeat_value(heartbeat)
            if observed is not None:
                return observed
            time.sleep(.01)
        self.fail("synthetic child did not publish a complete heartbeat")

    @staticmethod
    def heartbeat_value(path: Path) -> int | None:
        try:
            value = path.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            return None
        return int(value) if value.isdecimal() else None

    @unittest.skipIf(os.name == "nt", "requires POSIX sessions and executable shebang fixture")
    def test_child_runs_in_a_new_session_and_records_terminal_receipt(self) -> None:
        evidence = self.root / "evidence"
        monitor = self.start_monitor(evidence)
        self.wait_for(evidence / "process.json")
        process = json.loads((evidence / "process.json").read_text(encoding="utf-8"))
        self.assertNotEqual(process["childSessionId"], process["monitorSessionId"])
        (self.root / "stop").touch()
        self.assert_monitor_exit(monitor, 0, evidence)
        terminal = json.loads((evidence / "terminal.json").read_text(encoding="utf-8"))
        self.assertEqual(0, terminal["childExit"])
        self.assertTrue((evidence / "samples.jsonl").exists())

    @unittest.skipIf(os.name == "nt", "requires POSIX sessions and executable shebang fixture")
    def test_graphical_owned_vm_keeps_monitor_and_isolating_tart_flags(self) -> None:
        evidence = self.root / "graphical-evidence"
        monitor = self.start_monitor(evidence, graphical=True)
        self.wait_for(self.root / "calls.jsonl")
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            calls = [json.loads(line) for line in (self.root / "calls.jsonl").read_text().splitlines()]
            launched = [call for call in calls if call[:1] == ["run"]]
            if launched:
                break
            time.sleep(.01)
        self.assertEqual(1, len(launched), calls)
        self.assertEqual(["run", "--no-audio", "--no-clipboard", "owned-vm"], launched[0])
        self.wait_for(evidence / "process.json")
        (self.root / "stop").touch()
        self.assert_monitor_exit(monitor, 0, evidence)
        self.assertTrue((evidence / "samples.jsonl").exists())

    @unittest.skipIf(os.name == "nt", "requires POSIX executable shebang fixture")
    def test_pressure_stop_records_its_exact_result(self) -> None:
        evidence = self.root / "pressure-evidence"
        monitor = self.start_monitor(evidence)
        self.wait_for(evidence / "process.json")
        (self.root / "pressure").write_text("4\n", encoding="utf-8")
        self.assert_monitor_exit(monitor, 0, evidence)
        stopped = json.loads((evidence / "stop.json").read_text(encoding="utf-8"))
        self.assertEqual(0, stopped["code"])
        self.assertTrue((evidence / "terminal.json").exists())

    @unittest.skipIf(os.name == "nt", "requires POSIX executable shebang fixture")
    def test_pressure_stop_is_not_reissued_while_child_exits(self) -> None:
        """A completed Tart stop may precede its child's observable exit."""
        evidence = self.root / "single-pressure-stop-evidence"
        self.environment["CHILD_EXIT_DELAY"] = "0.15"
        monitor = self.start_monitor(evidence)
        self.wait_for(evidence / "process.json")
        (self.root / "pressure").write_text("4\n", encoding="utf-8")
        self.assert_monitor_exit(monitor, 0, evidence)
        calls = (self.root / "calls.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual(1, sum(json.loads(call)[0] == "stop" for call in calls))
        self.assertTrue((evidence / "terminal.json").exists())

    @unittest.skipIf(os.name == "nt", "requires POSIX executable shebang fixture")
    def test_pressure_stop_accepts_a_delayed_successful_invocation(self) -> None:
        evidence = self.root / "delayed-pressure-stop-evidence"
        self.environment["STOP_DELAY"] = "0.1"
        monitor = self.start_monitor(evidence, stop_timeout_seconds="0.5")
        self.wait_for(evidence / "process.json")
        (self.root / "pressure").write_text("4\n", encoding="utf-8")
        self.assert_monitor_exit(monitor, 0, evidence)
        stopped = json.loads((evidence / "stop.json").read_text(encoding="utf-8"))
        self.assertEqual(0, stopped["code"])
        self.assertTrue((evidence / "terminal.json").exists())

    @unittest.skipIf(os.name == "nt", "requires POSIX executable shebang fixture")
    def test_observation_failure_leaves_unknown_child_running(self) -> None:
        evidence = self.root / "failure-evidence"
        monitor = self.start_monitor(evidence)
        self.wait_for(evidence / "process.json")
        self.sysctl.unlink()
        self.assert_monitor_exit(monitor, 2, evidence)
        self.wait_for(self.root / "child.pid")
        pid = int((self.root / "child.pid").read_text(encoding="utf-8"))
        os.kill(pid, 0)
        self.assertTrue((evidence / "observation-failure.json").exists())
        self.assertFalse((evidence / "stop.json").exists())

    @unittest.skipIf(os.name == "nt", "requires POSIX process-group signalling")
    def test_terminating_monitor_group_preserves_exact_child(self) -> None:
        evidence = self.root / "group-evidence"
        monitor = subprocess.Popen(
            [sys.executable, str(MONITOR), "--vm-name", "owned-vm", "--evidence-dir", str(evidence),
             "--tart", str(self.tart), "--sysctl", str(self.sysctl), "--vm-stat", str(self.vm_stat), "--interval-seconds", "0.02"],
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=self.environment,
            start_new_session=True,
        )
        self.wait_for(evidence / "process.json")
        child_pid = json.loads((evidence / "process.json").read_text(encoding="utf-8"))["childPid"]
        before = self.wait_for_heartbeat()
        os.killpg(monitor.pid, signal.SIGTERM)
        monitor.wait(timeout=3)
        os.kill(child_pid, 0)
        self.wait_for_heartbeat_after(before)

    @unittest.skipIf(os.name == "nt", "requires POSIX executable shebang fixture")
    def test_stop_timeout_is_uncertain_and_does_not_retry_or_kill_child(self) -> None:
        evidence = self.root / "timeout-evidence"
        self.environment["STOP_BLOCK"] = "1"
        self.environment["STOP_JOURNAL_GATE"] = str(self.root / "unreleased-stop-journal")
        monitor = self.start_monitor(evidence, stop_timeout_seconds="0.05", record_stop_dispatch=True)
        self.wait_for(evidence / "process.json")
        before = self.wait_for_heartbeat()
        (self.root / "pressure").write_text("4\n", encoding="utf-8")
        self.assert_monitor_exit(monitor, 2, evidence)
        self.assert_timeout_dispatch_proof(evidence)
        self.wait_for_heartbeat_after(before)

    def assert_timeout_dispatch_proof(self, evidence: Path) -> None:
        child_pid = json.loads((evidence / "process.json").read_text(encoding="utf-8"))["childPid"]
        os.kill(child_pid, 0)
        before = self.wait_for_heartbeat()
        self.wait_for_heartbeat_after(before)
        uncertain = json.loads((evidence / "stop-uncertain.json").read_text(encoding="utf-8"))
        self.assertEqual(child_pid, uncertain["childPid"])
        self.assertIn("timed out after", uncertain["error"])
        self.assertFalse((evidence / "stop.json").exists())
        self.assertFalse((evidence / "terminal.json").exists())
        self.assertFalse((self.root / "child.exited").exists())
        trace = self.root / "stop-dispatch.jsonl"
        self.assertLessEqual(trace.stat().st_size, 8192)
        dispatches = [json.loads(row) for row in trace.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(1, len(dispatches))
        dispatch = dispatches[0]
        self.assertEqual({"argv", "pid", "phase"}, set(dispatch))
        self.assertEqual([str(self.tart), "stop", "owned-vm", "--timeout", "60"], dispatch["argv"])
        self.assertEqual("spawned", dispatch["phase"])
        self.assertIs(type(dispatch["pid"]), int)
        self.assertGreater(dispatch["pid"], 0)
        self.assertNotEqual(child_pid, dispatch["pid"])
        calls = (self.root / "calls.jsonl").read_text(encoding="utf-8").splitlines()
        # No child receipt is expected behind the gate; this says nothing about
        # whether a real request was dispatched. The parent trace proves that.
        self.assertEqual(0, sum(json.loads(call)[0] == "stop" for call in calls))

    @unittest.skipIf(os.name == "nt", "requires POSIX executable shebang fixture")
    def test_preserved_child_journal_assertion_fails_after_one_real_dispatch(self) -> None:
        result = unittest.TestResult()
        preserved_timeout_case().run(result)
        self.assertEqual(1, result.testsRun)
        self.assertEqual([], result.errors)
        self.assertEqual([], result.skipped)
        self.assertEqual(1, len(result.failures))
        self.assertIn("AssertionError: 1 != 0", result.failures[0][1])

    def test_transient_warning_does_not_stop_owned_vm(self) -> None:
        # Model Windows' missing getsid even on POSIX hosts; the mock supplies it.
        evidence = self.root / "warning-evidence"
        child = mock.Mock(pid=123, poll=mock.Mock(side_effect=[None, None, None, None, 0]), wait=mock.Mock(return_value=0))
        args = argparse.Namespace(evidence_dir=str(evidence), tart="tart", sysctl="sysctl", vm_stat="vm_stat", vm_name="owned-vm", interval_seconds=5, stop_timeout_seconds=75)
        with mock.patch.object(MONITOR_MODULE, "os", SimpleNamespace(fsync=os.fsync, getpid=os.getpid)), \
                mock.patch.object(MONITOR_MODULE, "validate_admission"), \
                mock.patch.object(MONITOR_MODULE.subprocess, "Popen", return_value=child), \
                mock.patch.object(MONITOR_MODULE.os, "getsid", return_value=123, create=True), \
                mock.patch.object(MONITOR_MODULE, "pressure", side_effect=["2", "1"]), \
                mock.patch.object(MONITOR_MODULE, "memory_headroom", return_value=4 * 2**30), \
                mock.patch.object(MONITOR_MODULE, "swap", return_value="synthetic"), \
                mock.patch.object(MONITOR_MODULE, "command", return_value=subprocess.CompletedProcess([], 0, "", "")) as command, \
                mock.patch.object(MONITOR_MODULE, "tart_state", return_value={"State": "stopped"}), \
                mock.patch.object(MONITOR_MODULE.time, "sleep"):
            self.assertEqual(0, MONITOR_MODULE.monitor(args))
        command.assert_not_called()
        self.assertFalse((evidence / "stop.json").exists())

    def test_sustained_warning_with_headroom_does_not_stop(self) -> None:
        evidence = self.root / "headroom-evidence"
        child = mock.Mock(pid=123, poll=mock.Mock(side_effect=[None, None, None, None, 0]), wait=mock.Mock(return_value=0))
        args = argparse.Namespace(evidence_dir=str(evidence), tart="tart", sysctl="sysctl", vm_stat="vm_stat", vm_name="owned-vm", interval_seconds=5, stop_timeout_seconds=75)
        with mock.patch.object(MONITOR_MODULE, "os", SimpleNamespace(fsync=os.fsync, getpid=os.getpid)), \
                mock.patch.object(MONITOR_MODULE, "validate_admission"), \
                mock.patch.object(MONITOR_MODULE.subprocess, "Popen", return_value=child), \
                mock.patch.object(MONITOR_MODULE.os, "getsid", return_value=123, create=True), \
                mock.patch.object(MONITOR_MODULE, "pressure", side_effect=["2", "2"]), \
                mock.patch.object(MONITOR_MODULE, "memory_headroom", return_value=4 * 2**30, create=True), \
                mock.patch.object(MONITOR_MODULE, "swap", return_value="synthetic"), \
                mock.patch.object(MONITOR_MODULE, "command", return_value=subprocess.CompletedProcess([], 0, "", "")) as command, \
                mock.patch.object(MONITOR_MODULE, "tart_state", return_value={"State": "stopped"}), \
                mock.patch.object(MONITOR_MODULE.time, "monotonic", side_effect=[0, 31]), \
                mock.patch.object(MONITOR_MODULE.time, "sleep"):
            self.assertEqual(0, MONITOR_MODULE.monitor(args))
        command.assert_not_called()

    def test_sustained_warning_and_critical_pressure_still_stop(self) -> None:
        stop, since = MONITOR_MODULE.pressure_stop("2", 10.0, None)
        self.assertFalse(stop)
        self.assertEqual((False, since), MONITOR_MODULE.pressure_stop("2", 39.9, since))
        self.assertEqual((True, since), MONITOR_MODULE.pressure_stop("2", 40.0, since))
        self.assertEqual((False, None), MONITOR_MODULE.pressure_stop("1", 41.0, since))
        self.assertEqual((False, 42.0), MONITOR_MODULE.pressure_stop("2", 42.0, None))
        self.assertTrue(MONITOR_MODULE.pressure_stop("4", 42.1, 42.0)[0])

    def test_headroom_parser_counts_only_explicit_page_categories(self) -> None:
        text = "Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free: 100.\nPages inactive: 200.\nPages speculative: 300.\nPages purgeable: 999999.\n"
        with mock.patch.object(MONITOR_MODULE, "command", return_value=subprocess.CompletedProcess([], 0, text, "")):
            self.assertEqual(600 * 16384, MONITOR_MODULE.memory_headroom("vm_stat"))
        for invalid in ("", text.replace("Pages inactive:", "Missing:"), text.replace("16384", "0")):
            with mock.patch.object(MONITOR_MODULE, "command", return_value=subprocess.CompletedProcess([], 0, invalid, "")):
                with self.assertRaises(MONITOR_MODULE.ObservationError):
                    MONITOR_MODULE.memory_headroom("vm_stat")
        self.assertFalse(MONITOR_MODULE.pressure_stop("2", 40, 0, 2 * 2**30)[0])
        self.assertTrue(MONITOR_MODULE.pressure_stop("2", 40, 0, 2 * 2**30 - 1)[0])
        self.assertTrue(MONITOR_MODULE.pressure_stop("4", 0, None, 8 * 2**30)[0])

    def test_partial_heartbeat_is_not_evidence_of_survival(self) -> None:
        heartbeat = self.root / "child.heartbeat"
        self.assertIsNone(self.heartbeat_value(heartbeat))
        for incomplete in ("", " ", "partial"):
            heartbeat.write_text(incomplete, encoding="utf-8")
            self.assertIsNone(self.heartbeat_value(heartbeat))
        heartbeat.write_text("42", encoding="utf-8")
        self.assertEqual(42, self.heartbeat_value(heartbeat))

    def test_admission_rejects_unsafe_name_and_nonstopped_state_portably(self) -> None:
        original_state = MONITOR_MODULE.tart_state
        original_pressure = MONITOR_MODULE.pressure
        try:
            MONITOR_MODULE.pressure = lambda _sysctl: "1"
            MONITOR_MODULE.tart_state = lambda _tart, _vm: {"State": "stopped", "Running": False}
            MONITOR_MODULE.validate_admission("tart", "sysctl", "owned-vm")
            with self.assertRaises(MONITOR_MODULE.ObservationError):
                MONITOR_MODULE.validate_admission("tart", "sysctl", "owned-vm;other")
            MONITOR_MODULE.tart_state = lambda _tart, _vm: {"State": "running", "Running": True}
            with self.assertRaises(MONITOR_MODULE.ObservationError):
                MONITOR_MODULE.validate_admission("tart", "sysctl", "owned-vm")
        finally:
            MONITOR_MODULE.tart_state = original_state
            MONITOR_MODULE.pressure = original_pressure


def legacy_red() -> int:
    """Reproduce monitor-group termination killing an inherited child."""
    if os.name == "nt":
        return 0
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        child = root / "child.py"
        child.write_text(
            """import pathlib
import sys
import time

root = pathlib.Path(sys.argv[1])
heartbeat = 0
while True:
    (root / "heartbeat").write_text(str(heartbeat))
    heartbeat += 1
    time.sleep(.01)
""",
            encoding="utf-8",
        )
        monitor = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import pathlib,subprocess,sys,time; root=pathlib.Path(sys.argv[1]); "
                "child=subprocess.Popen([sys.executable, str(root/'child.py'), str(root)]); "
                "(root/'pid').write_text(str(child.pid)); time.sleep(30)",
                str(root),
            ],
            start_new_session=True,
        )
        deadline = time.monotonic() + 3
        while not (root / "heartbeat").exists() and time.monotonic() < deadline:
            time.sleep(.01)
        assert (root / "heartbeat").exists(), "legacy child did not start"
        before = int((root / "heartbeat").read_text(encoding="utf-8"))
        os.killpg(monitor.pid, signal.SIGTERM)
        monitor.wait(timeout=3)
        time.sleep(.1)
        after = int((root / "heartbeat").read_text(encoding="utf-8"))
        assert after > before, "legacy inherited child stopped with monitor group"
    return 0


def preserved_timeout_case() -> unittest.TestCase:
    """Keep the original receipt assertion in an explicit owned startup context."""
    fixtures = ROOT / "testdata/macos-vm-resource-monitor-dispatch"
    fragment = fixtures / "stop-timeout.before.fragment"
    raw = fragment.read_bytes()
    expected = "995464bf10a441029a7e8124eaeb4832bbd8d92d875fc2f022adab8063c639b5"
    if hashlib.sha256(raw).hexdigest() != expected:
        raise AssertionError("Preserved timeout assertion bytes changed")
    provenance = json.loads((fixtures / "provenance.json").read_bytes())
    if (provenance["sourceCommit"] != "c68058eb64f8452207bf2091bd2950e5a06231da"
            or provenance["fragmentSha256"] != expected):
        raise AssertionError("Preserved timeout assertion provenance changed")
    source = ast.parse(b"class PreservedTimeoutAssertion:\n" + raw, filename=str(fragment))
    namespace = {"unittest": unittest, "os": os, "json": json}
    exec(compile(source, str(fragment), "exec"), namespace)
    original = namespace["PreservedTimeoutAssertion"].test_stop_timeout_is_uncertain_and_does_not_retry_or_kill_child

    class PreservedTimeoutCase(MonitorTest):
        runTest = original

        def setUp(self) -> None:
            super().setUp()
            self.environment["STOP_JOURNAL_GATE"] = str(self.root / "unreleased-stop-journal")

        def start_monitor(self, evidence: Path, *args, **kwargs) -> subprocess.Popen[str]:
            self.timeout_evidence = evidence
            kwargs["record_stop_dispatch"] = True
            return super().start_monitor(evidence, *args, **kwargs)

        def tearDown(self) -> None:
            try:
                # Even the old assertion's RED must retain the actual one-dispatch,
                # uncertainty, no-retry and advancing-child proof before cleanup.
                self.assert_timeout_dispatch_proof(self.timeout_evidence)
            finally:
                super().tearDown()

    return PreservedTimeoutCase()


def dispatch_red() -> int:
    """Run the original assertion against a real timed-out owned subprocess."""
    if os.name == "nt":
        raise RuntimeError("Dispatch RED requires the POSIX owned executable fixture")
    result = unittest.TextTestRunner(verbosity=2).run(preserved_timeout_case())
    return 0 if result.wasSuccessful() else 1


def heartbeat_red() -> int:
    """Reproduce a reader observing the old truncate-before-write heartbeat."""
    with tempfile.TemporaryDirectory() as temporary:
        heartbeat = Path(temporary) / "heartbeat"
        heartbeat.write_text("", encoding="utf-8")
        int(heartbeat.read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--legacy-red", action="store_true")
    parser.add_argument("--heartbeat-red", action="store_true")
    parser.add_argument("--dispatch-red", action="store_true")
    arguments, remaining = parser.parse_known_args()
    if arguments.legacy_red:
        raise SystemExit(legacy_red())
    if arguments.heartbeat_red:
        raise SystemExit(heartbeat_red())
    if arguments.dispatch_red:
        raise SystemExit(dispatch_red())
    unittest.main(argv=[sys.argv[0], *remaining])

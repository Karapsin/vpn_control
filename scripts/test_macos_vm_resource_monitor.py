#!/usr/bin/env python3
"""Portable causal checks for macos_vm_resource_monitor.py."""

from __future__ import annotations

import argparse
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
import unittest


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


class MonitorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.tart = self.write_executable("fake-tart", FAKE_TART)
        self.sysctl = self.write_executable("fake-sysctl", FAKE_SYSCTL)
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

    def start_monitor(self, evidence: Path, stop_timeout_seconds: str = "1") -> subprocess.Popen[str]:
        return subprocess.Popen(
            [sys.executable, str(MONITOR), "--vm-name", "owned-vm", "--evidence-dir", str(evidence),
             "--tart", str(self.tart), "--sysctl", str(self.sysctl), "--interval-seconds", "0.02",
             "--stop-timeout-seconds", stop_timeout_seconds],
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

    @unittest.skipIf(os.name == "nt", "requires POSIX executable shebang fixture")
    def test_pressure_stop_records_its_exact_result(self) -> None:
        evidence = self.root / "pressure-evidence"
        monitor = self.start_monitor(evidence)
        self.wait_for(evidence / "process.json")
        (self.root / "pressure").write_text("2\n", encoding="utf-8")
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
        (self.root / "pressure").write_text("2\n", encoding="utf-8")
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
        (self.root / "pressure").write_text("2\n", encoding="utf-8")
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
             "--tart", str(self.tart), "--sysctl", str(self.sysctl), "--interval-seconds", "0.02"],
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
        monitor = self.start_monitor(evidence, stop_timeout_seconds="0.05")
        self.wait_for(evidence / "process.json")
        (self.root / "pressure").write_text("2\n", encoding="utf-8")
        self.assert_monitor_exit(monitor, 2, evidence)
        child_pid = json.loads((evidence / "process.json").read_text(encoding="utf-8"))["childPid"]
        os.kill(child_pid, 0)
        self.assertTrue((evidence / "stop-uncertain.json").exists())
        calls = (self.root / "calls.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual(1, sum(json.loads(call)[0] == "stop" for call in calls))

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
    arguments, remaining = parser.parse_known_args()
    if arguments.legacy_red:
        raise SystemExit(legacy_red())
    if arguments.heartbeat_red:
        raise SystemExit(heartbeat_red())
    unittest.main(argv=[sys.argv[0], *remaining])

import json
from pathlib import Path
import tempfile
import unittest
import subprocess

from linux_gui_fixture_guard import (collect_window_pids, main, observe, proc_starttime,
                                    require_fresh_gui_frontend, write_failure_receipt)


class Completed:
    def __init__(self, code, output):
        self.returncode = code
        self.stdout = output


class LinuxGuiFixtureGuardTest(unittest.TestCase):
    def test_stale_foreign_window_is_rejected(self):
        # A title-only search finds this window, but it belongs to an earlier process.
        with self.assertRaisesRegex(RuntimeError, "fresh frontend"):
            require_fresh_gui_frontend(frontend_pid=42, frontend_alive=True,
                                       window_pids=[17], crash_reports=[])

    def test_green_accepts_only_live_fresh_pid_without_crash(self):
        self.assertEqual(42, require_fresh_gui_frontend(frontend_pid=42, frontend_alive=True,
                                                         window_pids=[17, 42], crash_reports=[]))

    def test_dead_or_crashed_frontend_fails_before_lifecycle_probe(self):
        with self.assertRaisesRegex(RuntimeError, "exited"):
            require_fresh_gui_frontend(frontend_pid=42, frontend_alive=False,
                                       window_pids=[42], crash_reports=[])
        with self.assertRaisesRegex(RuntimeError, "crash report"):
            require_fresh_gui_frontend(frontend_pid=42, frontend_alive=True,
                                       window_pids=[42], crash_reports=["hs_err_pid42.log"])

    def test_observer_rejects_pid_reuse_and_accepts_only_new_owned_window(self):
        alive = lambda pid: True
        with self.assertRaisesRegex(RuntimeError, "reused"):
            observe(expected_pid=42, expected_starttime="expected", baseline_windows=[], proc_starttime=lambda pid: "old",
                    proc_alive=alive, window_pid={9: 42}, crash_reports=[])
        receipt = observe(expected_pid=42, expected_starttime="expected", baseline_windows=[9],
                          proc_starttime=lambda pid: "expected", proc_alive=alive,
                          window_pid={9: 42, 10: 42}, crash_reports=[])
        self.assertEqual([10], receipt["freshWindows"])

    def test_proc_stat_parser_handles_parentheses_and_rejects_zombie(self):
        live = "42 (frontend (render)) S " + " ".join(str(value) for value in range(4, 23))
        self.assertEqual("22", proc_starttime(42, lambda path: live))
        zombie = "42 (frontend) Z " + " ".join(str(value) for value in range(4, 23))
        with self.assertRaisesRegex(RuntimeError, "zombie"):
            proc_starttime(42, lambda path: zombie)

    def test_x11_adapter_uses_client_list_and_no_windows_is_a_receiptable_failure(self):
        calls = []
        def run(command, **kwargs):
            calls.append(command)
            if command[1:3] == ["-root", "_NET_CLIENT_LIST"]:
                return Completed(0, "_NET_CLIENT_LIST(WINDOW): window id # 0x10, 0x11")
            if command[2] == "0x10":
                return Completed(0, "_NET_WM_PID(CARDINAL) = 42")
            return Completed(0, "_NET_WM_PID:  not found.")
        self.assertEqual({16: 42}, collect_window_pids(run))
        self.assertEqual(["xprop", "-root", "_NET_CLIENT_LIST"], calls[0])
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "failure.json"
            write_failure_receipt(receipt, RuntimeError("no fresh window"), {}, [])
            self.assertEqual(False, json.loads(receipt.read_text())["ok"])

    def test_x11_adapter_missing_observer_is_a_bounded_failure(self):
        def missing(command, **kwargs):
            raise FileNotFoundError(command[0])
        with self.assertRaisesRegex(RuntimeError, "cannot execute xprop"):
            collect_window_pids(missing)

    def test_x11_adapter_timeout_is_a_bounded_failure(self):
        def timeout(command, **kwargs):
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        with self.assertRaisesRegex(RuntimeError, "cannot execute xprop"):
            collect_window_pids(timeout)

    def test_main_writes_failure_receipt_for_proc_race_or_x11_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "failure.json"
            def proc_race():
                raise OSError("process disappeared")
            code = main(["--expected-pid", "42", "--expected-proc-starttime", "expected",
                         "--receipt", str(receipt)], collect=proc_race)
            failure = json.loads(receipt.read_text())
            self.assertEqual(1, code)
            self.assertFalse(failure["ok"])
            self.assertIn("disappeared", failure["error"])


if __name__ == "__main__":
    unittest.main()

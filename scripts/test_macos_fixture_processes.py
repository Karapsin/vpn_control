#!/usr/bin/env python3
import subprocess
import unittest
from types import SimpleNamespace

from macos_fixture_processes import (
    FixtureProcessError,
    FixtureReadinessTimeout,
    FRONTEND_OWNER,
    INITIAL_SERVE_OWNER,
    INTERNAL_HEADLESS_OWNER,
    PLAIN_RETURN_GUI,
    FixtureProcessObserver,
    process_rows,
    wait_for_public_status_readiness,
)


APP = "/Users/admin/macos-gui-return108/app/vpn-control.app/Contents/MacOS/vpn-control"
STATE = "/Users/admin/macos-gui-return108/state"
OWNER = "b037f6c3-b5e8-4d53-b4e1-88449f38d2bd"
START = "Sun Sep 21 04:35:10 2026"


def row(pid: int, argv: list[str], started: str = START) -> str:
    return f"{pid:5d} {started} {' '.join(argv)}"


class MacosFixtureProcessesTest(unittest.TestCase):
    def setUp(self):
        self.observer = FixtureProcessObserver(APP, STATE)

    def test_actual_desktop_controller_and_macos_frontend_roles_are_exact(self):
        # DesktopHeadlessController relaunches the bundled launcher with this
        # headless argument, while macOS Launch Services starts this frontend
        # child after ``open ... --args``.
        rows = process_rows("\n".join((
            row(10, [APP, "--state-dir", STATE, "serve"]),
            row(11, [APP, "--headless-controller", "--state-dir", STATE]),
            row(12, [APP, "--frontend-owner", OWNER, "--state-dir", STATE]),
            row(13, [APP, "--state-dir", STATE], "Sun Sep 21 04:36:10 2026"),
        )))
        self.assertEqual(10, self.observer.identify(rows, INITIAL_SERVE_OWNER).pid)
        self.assertEqual(11, self.observer.identify(rows, INTERNAL_HEADLESS_OWNER).pid)
        self.assertEqual(12, self.observer.identify(rows, FRONTEND_OWNER, OWNER).pid)
        self.assertEqual(13, self.observer.identify(rows, PLAIN_RETURN_GUI).pid)

    def test_substring_or_extra_arguments_do_not_admit_a_role(self):
        rows = process_rows("\n".join((
            row(20, ["/tmp/foreign", APP, "--state-dir", STATE, "serve"]),
            row(21, [APP, "--state-dir", STATE, "serve", "extra"]),
            row(22, [APP, "--headless-controller", "--state-dir", STATE, "extra"]),
        )))
        self.assertIsNone(self.observer.identify(rows, INITIAL_SERVE_OWNER))
        self.assertIsNone(self.observer.identify(rows, INTERNAL_HEADLESS_OWNER))

    def test_duplicate_exact_matches_are_ambiguous(self):
        rows = process_rows("\n".join((
            row(30, [APP, "--state-dir", STATE, "serve"]),
            row(31, [APP, "--state-dir", STATE, "serve"], "Sun Sep 21 04:36:10 2026"),
        )))
        self.assertIsNone(self.observer.identify(rows, INITIAL_SERVE_OWNER))

    def test_returned_gui_rejects_pid_reuse_and_same_start_generation(self):
        prior = process_rows(row(40, [APP, "--state-dir", STATE]))[0]
        reused_pid = process_rows(row(40, [APP, "--state-dir", STATE], "Sun Sep 21 04:36:10 2026"))
        same_start = process_rows(row(41, [APP, "--state-dir", STATE]))
        fresh = process_rows(row(42, [APP, "--state-dir", STATE], "Sun Sep 21 04:36:10 2026"))
        self.assertIsNone(self.observer.returned_gui_after(reused_pid, prior))
        self.assertIsNone(self.observer.returned_gui_after(same_start, prior))
        self.assertEqual(42, self.observer.returned_gui_after(fresh, prior).pid)

    def test_rejects_paths_or_frontend_ids_that_ps_cannot_unambiguously_recover(self):
        with self.assertRaises(FixtureProcessError):
            FixtureProcessObserver("/Applications/VPN Control.app/vpn-control", STATE)
        with self.assertRaises(FixtureProcessError):
            FixtureProcessObserver(APP, "/tmp/state with spaces")
        with self.assertRaises(FixtureProcessError):
            self.observer.identify([], FRONTEND_OWNER, "not-a-uuid")

    def test_pid_visible_status_unavailable_then_success_retains_every_command_result(self):
        returned_owner = process_rows(row(50, [APP, "--headless-controller", "--state-dir", STATE]))
        samples = iter((returned_owner, returned_owner))
        responses = iter((
            SimpleNamespace(returncode=2, stdout="", stderr="connection endpoint not ready"),
            SimpleNamespace(returncode=0, stdout='{"ok":true,"data":{"runtimeRunning":false}}', stderr=""),
        ))
        commands, evidence = [], []

        readiness = wait_for_public_status_readiness(
            self.observer, lambda: next(samples), INTERNAL_HEADLESS_OWNER,
            lambda argv, _: (commands.append(tuple(argv)) or next(responses)), evidence.append,
            now=StepClock(), sleep=lambda _: None,
        )

        self.assertEqual(50, readiness.process.pid)
        self.assertFalse(evidence[0]["statusOk"])
        self.assertEqual(2, evidence[0]["exit"])
        self.assertEqual("", evidence[0]["stdout"])
        self.assertEqual("connection endpoint not ready", evidence[0]["stderr"])
        self.assertTrue(evidence[1]["statusOk"])
        self.assertEqual((APP, "--state-dir", STATE, "--json", "status"), commands[0])
        self.assertEqual(2, len(commands))

    def test_deadline_keeps_last_observation_without_declaring_the_owner_dead(self):
        returned_owner = process_rows(row(60, [APP, "--headless-controller", "--state-dir", STATE]))
        evidence = []
        clock = StepClock((0, 0, 1))

        with self.assertRaises(FixtureReadinessTimeout) as raised:
            wait_for_public_status_readiness(
                self.observer, lambda: returned_owner, INTERNAL_HEADLESS_OWNER,
                lambda _, __: SimpleNamespace(returncode=2, stdout="", stderr="endpoint unavailable"), evidence.append,
                timeout_seconds=1, now=clock, sleep=lambda _: None,
            )

        self.assertEqual(INTERNAL_HEADLESS_OWNER, raised.exception.last_observation["role"])
        self.assertEqual(2, raised.exception.last_observation["exit"])
        self.assertEqual(2, evidence[0]["exit"])
        self.assertNotIn("dead", str(raised.exception).lower())

    def test_status_runner_receives_the_remaining_deadline(self):
        returned_owner = process_rows(row(70, [APP, "--headless-controller", "--state-dir", STATE]))
        received_timeouts = []

        readiness = wait_for_public_status_readiness(
            self.observer, lambda: returned_owner, INTERNAL_HEADLESS_OWNER,
            lambda argv, timeout: (
                received_timeouts.append((tuple(argv), timeout)) or
                SimpleNamespace(returncode=0, stdout='{"ok":true}', stderr="")
            ), lambda _: None,
            timeout_seconds=2, now=StepClock((0, 0)), sleep=lambda _: None,
        )

        self.assertEqual(70, readiness.process.pid)
        self.assertEqual([(APP, "--state-dir", STATE, "--json", "status")],
                         [command for command, _ in received_timeouts])
        self.assertEqual([2], [timeout for _, timeout in received_timeouts])

    def test_subprocess_status_timeout_retains_output_without_declaring_owner_dead(self):
        returned_owner = process_rows(row(80, [APP, "--headless-controller", "--state-dir", STATE]))
        evidence = []

        def timed_out(argv, timeout):
            raise subprocess.TimeoutExpired(argv, timeout, output=b"partial stdout", stderr=b"partial stderr")

        with self.assertRaises(FixtureReadinessTimeout) as raised:
            wait_for_public_status_readiness(
                self.observer, lambda: returned_owner, INTERNAL_HEADLESS_OWNER,
                timed_out, evidence.append,
                timeout_seconds=1, now=StepClock((0, 0, 1)), sleep=lambda _: None,
            )

        self.assertTrue(evidence[0]["timedOut"])
        self.assertIsNone(evidence[0]["exit"])
        self.assertEqual("partial stdout", evidence[0]["stdout"])
        self.assertEqual("partial stderr", evidence[0]["stderr"])
        self.assertTrue(raised.exception.last_observation["rolePresent"])
        self.assertNotIn("dead", str(raised.exception).lower())

    def test_readiness_timing_must_be_finite_and_positive(self):
        invalid_timings = ((0, 0.2), (1, 0), (-1, 0.2), (1, -0.2),
                           (float("nan"), 0.2), (float("inf"), 0.2),
                           (1, float("nan")), (1, float("-inf")))
        for timeout_seconds, poll_seconds in invalid_timings:
            with self.subTest(timeout_seconds=timeout_seconds, poll_seconds=poll_seconds):
                with self.assertRaises(FixtureProcessError):
                    wait_for_public_status_readiness(
                        self.observer, lambda: (), INTERNAL_HEADLESS_OWNER,
                        lambda *_: self.fail("runner must not be called"), lambda _: None,
                        timeout_seconds=timeout_seconds, poll_seconds=poll_seconds,
                        now=StepClock((0, 1)), sleep=lambda _: None,
                    )


class StepClock:
    def __init__(self, values=(0, 0, 0, 1)):
        self.values = iter(values)

    def __call__(self):
        return next(self.values)


if __name__ == "__main__":
    unittest.main()

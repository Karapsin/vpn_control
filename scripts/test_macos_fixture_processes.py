#!/usr/bin/env python3
import unittest

from macos_fixture_processes import (
    FixtureProcessError,
    FRONTEND_OWNER,
    INITIAL_SERVE_OWNER,
    INTERNAL_HEADLESS_OWNER,
    PLAIN_RETURN_GUI,
    FixtureProcessObserver,
    process_rows,
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


if __name__ == "__main__":
    unittest.main()

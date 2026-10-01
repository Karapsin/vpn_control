"""Causal regressions for the read-only failed-v3 owner-quit diagnosis."""
from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_tools import windows_msi_owner_quit_phase_diagnostic as diagnostic


class OwnerQuitPhaseDiagnosticTests(unittest.TestCase):
    def _admitted(self):
        descriptor = ("windows-cp117", "/qga.sock", 589342, 520739,
                      "S-1-5-21-2404255130-2183793310-3766671872-1002")
        generation = {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]}
        return object(), descriptor, "b" * 64, generation, "c" * 64

    def _record(self, generation, evidence):
        return {"version": 1, "correlationId": diagnostic._CORRELATION,
                "idempotencyKey": diagnostic._CORRELATION,
                "requestSha256": diagnostic._REQUEST_SHA256,
                "sourceSha": diagnostic.relaunch._SOURCE,
                "guestGeneration": generation, "evidenceSha256": evidence, "state": "intent"}

    def test_task_program_is_read_only_and_has_one_finite_exit_per_gate(self):
        script = diagnostic._TASK_PS
        for forbidden in (" quit", "Stop-Process", "Register-ScheduledTask",
                          "Start-ScheduledTask", "Remove-Item"):
            self.assertNotIn(forbidden, script)
        self.assertIn(" status 2>$null", script)
        self.assertIn("$reply.controllerId -cne $controller", script)
        self.assertIn("$reply.data.runtimeRunning -ne $false", script)
        self.assertIn("$phase=18;Owners", script)
        for code, phase in diagnostic._EXIT_PHASES.items():
            self.assertIsInstance(code, int)
            self.assertTrue(phase)

    def test_generated_program_compiles_and_uses_compact_outer_bootstrap(self):
        compile(diagnostic._REMOTE, "owner-quit-phase-diagnostic", "exec")
        self.assertIn("compact_ps_bootstrap(script)", diagnostic._REMOTE)
        self.assertIn("VpnControlCp117OwnerQuitPhaseDiagnosticC32", diagnostic._REMOTE)

    def test_outer_command_stays_under_admission_limit(self):
        captured = []
        def fake_call(_sock, command, arguments):
            if command == "guest-exec":
                captured.append(arguments); return {"pid": 7}
            return {"exited": True, "exitcode": 0, "out-truncated": False,
                    "err-truncated": False,
                    "out-data": base64.b64encode(b'{"version":1,"state":"submitted"}\n').decode()}
        source = diagnostic._REMOTE.replace(
            "if mode not in ('start','status') or not live(sock,pid,ticks):raise ValueError()",
            "call=FAKE_CALL\n if mode not in ('start','status'):raise ValueError()")
        with mock.patch("sys.argv", ["generated", "/qga.sock", "589342", "520739",
                                      self._admitted()[1][4], "b" * 64, "start"]), contextlib.redirect_stdout(io.StringIO()):
            exec(compile(source, "owner-quit-phase-diagnostic", "exec"), {"FAKE_CALL": fake_call})
        self.assertEqual(len(captured), 1)
        self.assertLess(sum(len(x) + 1 for x in ["powershell.exe", *captured[0]["arg"]]), 30_000)
        self.assertEqual(captured[0]["arg"][-2], "-EncodedCommand")

    def test_start_requires_current_owner_admission_and_verified_v3_failure(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(diagnostic, "_admit", return_value=None), \
                mock.patch.object(diagnostic, "_run") as run:
            self.assertEqual(diagnostic.start(directory, {"host": "archlinux"}), diagnostic._UNKNOWN)
        run.assert_not_called()

    def test_admission_rejects_any_nonfailed_v3_result(self):
        config, descriptor, cli_hash, generation, evidence = self._admitted()
        prior = (config, descriptor, cli_hash, {"sourceSha": diagnostic.relaunch._SOURCE,
                                                "guestGeneration": generation, "evidenceSha256": evidence})
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(diagnostic.v3, "_observer", return_value=prior), \
                mock.patch.object(diagnostic.v1, "_admit", return_value=(config, descriptor, cli_hash, generation, evidence)), \
                mock.patch.object(diagnostic.v3, "_run", return_value={"version": 1, "state": "pending"}):
            self.assertIsNone(diagnostic._admit(Path(directory)))

    def test_durable_intent_prevents_replaying_unknown_diagnostic_start(self):
        config, descriptor, cli_hash, generation, evidence = self._admitted()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); diagnostic._write(root, self._record(generation, evidence))
            with mock.patch.object(diagnostic, "status", return_value={"state": "pending"}), \
                    mock.patch.object(diagnostic, "_run") as run:
                self.assertEqual(diagnostic.start(root, {"host": "archlinux"}), {"state": "pending"})
            run.assert_not_called()

    def test_status_projects_only_verified_task_exit_codes_and_never_starts(self):
        config, descriptor, cli_hash, generation, evidence = self._admitted()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); diagnostic._write(root, self._record(generation, evidence))
            with mock.patch.object(diagnostic, "_observer", return_value=(config, descriptor, cli_hash)), \
                    mock.patch.object(diagnostic, "_run", return_value={"version": 1, "state": "finished", "exitCode": 15}) as run, \
                    mock.patch.object(diagnostic, "start") as start:
                result = diagnostic.status(root, {"host": "archlinux"})
        self.assertEqual(result, {"state": "diagnosed", "phase": "endpoint", "replayAllowed": False, "nativeActionAllowed": False})
        self.assertEqual(run.call_args.args[-1], "status")
        start.assert_not_called()

    def test_poisoned_or_unbounded_task_exit_is_unknown(self):
        for value in ({"version": 1, "state": "finished", "exitCode": 99},
                      {"version": 1, "state": "finished", "exitCode": "15"},
                      {"version": 1, "state": "pending", "exitCode": 15}):
            with self.subTest(value=value): self.assertEqual(diagnostic._project(value), diagnostic._UNKNOWN)


if __name__ == "__main__":
    unittest.main()

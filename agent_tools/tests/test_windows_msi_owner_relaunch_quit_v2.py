"""Causal regressions for the second fixed CP117 owner quit."""
from __future__ import annotations

import ast
import hashlib
import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_tools import windows_msi_owner_relaunch_quit_v2 as quit_v2


class RelaunchQuitV2Test(unittest.TestCase):
    def _admitted(self):
        descriptor = ("windows-cp117", "/qga.sock", 589342, 520739,
                      "S-1-5-21-2404255130-2183793310-3766671872-1002")
        generation = {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]}
        return object(), descriptor, "b" * 64, generation, "c" * 64

    def _record(self, generation, evidence):
        return {"version": 1, "correlationId": quit_v2._CORRELATION,
                "idempotencyKey": quit_v2._CORRELATION,
                "requestSha256": quit_v2._REQUEST_SHA256,
                "sourceSha": quit_v2.relaunch._SOURCE,
                "guestGeneration": generation, "evidenceSha256": evidence,
                "state": "intent"}

    def test_generated_guest_program_compiles_before_any_qga_dispatch(self):
        compile(quit_v2._REMOTE, "generated-v2-relaunch-quit", "exec")
        self.assertIn("VpnControlCp117OwnerRelaunchQuitC32", quit_v2._REMOTE)
        self.assertIn("VpnControlCp117OwnerRelaunchC32", quit_v2._REMOTE)
        self.assertNotIn("\x0b", quit_v2._REMOTE)

    def test_preflight_requires_expected_running_relaunch_and_absent_v1_task(self):
        """RED→GREEN: v1 rejected while its long-lived relaunch task ran."""
        strings = [node.value for node in ast.walk(ast.parse(quit_v2._REMOTE))
                   if isinstance(node, ast.Constant) and isinstance(node.value, str)]
        # The emitted bootstrap is assembled from fixed literals and fixed task
        # constants, so inspect the generated source as one program.
        bootstrap = quit_v2._REMOTE
        self.assertIn("$r.State.ToString() -cne 'Running'", bootstrap)
        self.assertIn("$r.Principal.LogonType.ToString() -cne 'Interactive'", bootstrap)
        self.assertIn("$r.Principal.RunLevel.ToString() -cne 'Limited'", bootstrap)
        self.assertIn("$ra[0].Execute -cne", bootstrap)
        self.assertIn("$ra[0].Arguments -cne", bootstrap)
        self.assertIn("V1_TASK=" + repr(quit_v2._V1_TASK), bootstrap)
        self.assertIn("Get-ScheduledTask -TaskName '", bootstrap)
        self.assertIn("throw 'V1_TASK'", bootstrap)
        for task in quit_v2._STATUS_TASKS:
            self.assertIn(task, bootstrap)
        # The v1 task used -EncodedCommand, so its task name is absent from a
        # live process.  Match the exact generated action under the original
        # SID/session instead, and fail closed for another encoded PowerShell.
        self.assertIn("$expectedHash='\"+digest+\"'", bootstrap)
        self.assertIn("(Hash $expectedArgs) -cne $expectedHash", bootstrap)
        self.assertIn("$cmd -ceq $quoted -or $cmd -ceq $unquoted", bootstrap)
        self.assertIn("throw 'V1_PROCESS'", bootstrap)
        self.assertIn("throw 'V1_PROCESS_AMBIGUOUS'", bootstrap)
        self.assertIn("-EncodedCommand", bootstrap)
        self.assertIn("STATUS_TASKS_PS=" + repr(quit_v2._STATUS_TASKS_PS), bootstrap)
        self.assertIn('foreach($x in "+STATUS_TASKS_PS+")', bootstrap)

    def test_start_records_durable_v2_intent_before_only_submission(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(quit_v2, "_admit", return_value=self._admitted()), \
                mock.patch.object(quit_v2, "_run", return_value={"version": 1, "state": "submitted"}) as run:
            self.assertEqual(quit_v2.start(directory, {"host": "archlinux"})["state"], "submitted")
            record = quit_v2._read(Path(directory))
            self.assertEqual(record["idempotencyKey"], quit_v2._CORRELATION)
            self.assertEqual(stat.S_IMODE(quit_v2._path(Path(directory), False).stat().st_mode), 0o600)
            run.assert_called_once()

    def test_existing_v2_intent_never_replays(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); _config, _descriptor, _hash, generation, evidence = self._admitted()
            quit_v2._write(root, self._record(generation, evidence))
            with mock.patch.object(quit_v2, "status", return_value={"state": "pending"}), \
                    mock.patch.object(quit_v2, "_run") as run:
                self.assertEqual(quit_v2.start(root, {"host": "archlinux"}), {"state": "pending"})
            run.assert_not_called()

    def test_blocked_admission_neither_writes_nor_dispatches(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(quit_v2, "_admit", return_value=None), \
                mock.patch.object(quit_v2, "_run") as run:
            self.assertEqual(quit_v2.start(directory, {"host": "archlinux"}), quit_v2._UNKNOWN)
            self.assertFalse((Path(directory) / quit_v2._GROUP).exists())
            run.assert_not_called()

    def test_status_marks_exit_only_from_own_bound_task(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); _config, descriptor, cli_hash, generation, evidence = self._admitted()
            record = self._record(generation, evidence); quit_v2._write(root, record)
            with mock.patch.object(quit_v2, "_observer", return_value=(object(), descriptor, cli_hash, record)), \
                    mock.patch.object(quit_v2, "_run", return_value={"version": 1, "state": "exited"}):
                self.assertEqual(quit_v2.status(root, {"host": "archlinux"})["state"], "exited")
            self.assertEqual(quit_v2._read(root)["state"], "exited")

    def test_observer_binds_same_generation_without_live_owner_requirement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); config, descriptor, cli_hash, generation, _ignored = self._admitted()
            evidence = hashlib.sha256(json.dumps(generation, sort_keys=True).encode()).hexdigest()
            quit_v2._write(root, self._record(generation, evidence))
            launch = {"state": "intent", "guestGeneration": generation,
                      "staleRecoveryEvidenceSha256": evidence}
            with mock.patch.object(quit_v2.relaunch.liveness, "_admit",
                                   return_value=(config, descriptor, quit_v2.relaunch._SOURCE, cli_hash)), \
                    mock.patch.object(quit_v2.relaunch, "_read_intent", return_value=launch):
                self.assertIsNotNone(quit_v2._observer(root))

    def test_diagnose_has_no_start_path_and_finite_result(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(quit_v2, "_observer", return_value=(object(), self._admitted()[1], "b" * 64, {})), \
                mock.patch.object(quit_v2, "_run", return_value={"version": 1, "phase": "tasks", "task": "absent"}) as run:
            result = quit_v2.diagnose(directory, {"host": "archlinux"})
        self.assertEqual(result["state"], "diagnosed")
        self.assertEqual(run.call_args.args[-1], "diagnose")

    def test_bootstrap_diagnostic_is_read_only_and_covers_each_start_gate(self):
        """RED→GREEN: unknown submission diagnosis cannot register a retry."""
        script = quit_v2._BOOTSTRAP_DIAGNOSTIC_PS
        for forbidden in ("Register-ScheduledTask", "Start-ScheduledTask",
                          "Unregister-ScheduledTask", "Stop-Process", "Remove-Item",
                          " quit"):
            self.assertNotIn(forbidden, script)
        for gate in ("scheduler", "account-sid", "status-task-present", "v1-task-present",
                     "relaunch-task", "v1-process", "v2-task-present", "ready"):
            self.assertIn("'" + gate + "'", script)
        self.assertIn("$cmd -ceq $quoted -or $cmd -ceq $unquoted", script)
        self.assertIn("-EncodedCommand", script)

    def test_bootstrap_diagnostic_returns_only_finite_gate_without_dispatch(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(quit_v2, "_bootstrap_observer",
                                  return_value=(object(), self._admitted()[1], "b" * 64)), \
                mock.patch.object(quit_v2, "_run",
                                  return_value={"version": 1, "gate": "v1-process"}) as run:
            result = quit_v2.bootstrap_diagnostic(directory, {"host": "archlinux"})
        self.assertEqual(result, {"state": "diagnosed", "gate": "v1-process",
                                  "replayAllowed": False, "nativeActionAllowed": False})
        self.assertEqual(run.call_args.args[-1], "bootstrap-diagnostic")

    def test_bootstrap_observer_failure_cannot_impersonate_scheduler_gate(self):
        """RED→GREEN: a QGA/parser failure once looked like scheduler failure."""
        self.assertIn("$gate='observer-unknown'", quit_v2._BOOTSTRAP_DIAGNOSTIC_PS)
        self.assertIn("'gate':'observer-unknown'", quit_v2._REMOTE)
        self.assertNotIn("'gate':'scheduler'} if mode=='bootstrap-diagnostic'", quit_v2._REMOTE)
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(quit_v2, "_bootstrap_observer",
                                  return_value=(object(), self._admitted()[1], "b" * 64)), \
                mock.patch.object(quit_v2, "_run",
                                  return_value={"version": 1, "gate": "observer-unknown"}) as run:
            result = quit_v2.bootstrap_diagnostic(directory, {"host": "archlinux"})
        self.assertEqual(result, quit_v2._UNKNOWN)
        self.assertEqual(run.call_args.args[-1], "bootstrap-diagnostic")

    def test_bootstrap_diagnostic_rejects_exited_journal_without_guest_observation(self):
        """An already-proved quit cannot be re-diagnosed as a new attempt."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); _config, _descriptor, _hash, generation, evidence = self._admitted()
            record = self._record(generation, evidence); record["state"] = "exited"; quit_v2._write(root, record)
            with mock.patch.object(quit_v2, "_admit") as admit, \
                    mock.patch.object(quit_v2, "_run") as run:
                result = quit_v2.bootstrap_diagnostic(root, {"host": "archlinux"})
        self.assertEqual(result, quit_v2._UNKNOWN)
        admit.assert_not_called()
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()

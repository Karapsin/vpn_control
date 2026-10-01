from __future__ import annotations

import json
import os
import stat
import ast
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_tools import windows_msi_owner_relaunch_quit as quit_owner


class RelaunchQuitTests(unittest.TestCase):
    def _admitted(self):
        descriptor = ("windows-cp117", "/qga.sock", 589342, 520739,
                      "S-1-5-21-2404255130-2183793310-3766671872-1002")
        generation = {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]}
        return object(), descriptor, "b" * 64, generation, "c" * 64

    def test_generated_guest_programs_compile_and_keep_quit_public(self):
        """A Python quoting regression must fail before a QGA submission."""
        compile(quit_owner._REMOTE, "generated-relaunch-quit", "exec")
        self.assertIn("& $cli --state-dir $state --json --controller-id $controller --timeout-seconds 15 quit", quit_owner._TASK_PS)
        self.assertIn("VpnControlCp117OwnerPublicStatusThirdC32", quit_owner._REMOTE)
        self.assertIn("VpnControlCp117OwnerRelaunchC32", quit_owner._REMOTE)
        self.assertIn("RunLevel Limited", quit_owner._REMOTE)
        self.assertNotIn("Stop-Process", quit_owner._TASK_PS)
        self.assertNotIn("sing-box stop", quit_owner._TASK_PS)

    def test_limited_task_binds_quit_to_valid_endpoint_controller(self):
        """RED→GREEN: a bare public quit could target a replacement owner."""
        script = quit_owner._TASK_PS
        self.assertIn("$leaf=Get-Item -LiteralPath $endpoint", script)
        self.assertIn("[IO.FileAttributes]::ReparsePoint", script)
        self.assertIn("$leaf.Length -lt 2 -or $leaf.Length -gt 4096", script)
        self.assertIn("$value.schemaVersion -ne 1", script)
        self.assertIn("$value.schemaVersion -isnot [int] -and $value.schemaVersion -isnot [long]", script)
        self.assertIn("$value.port -isnot [int] -and $value.port -isnot [long]", script)
        self.assertIn("$value.controllerId -isnot [string]", script)
        self.assertIn("$value.token -isnot [string]", script)
        self.assertLess(script.index("$value.controllerId -isnot [string]"),
                        script.index("$controller=$value.controllerId"))
        self.assertLess(script.index("$value.token -isnot [string]"),
                        script.index("$token=$value.token"))
        self.assertIn("[guid]::Parse($controller).ToString() -cne $controller", script)
        self.assertIn("$value.port -lt 1 -or $value.port -gt 65535", script)
        self.assertIn("[A-Za-z0-9_-]{43}", script)
        self.assertIn("--controller-id $controller --timeout-seconds 15 quit", script)
        self.assertIn("$reply.controllerId -cne $controller", script)
        self.assertNotIn("--json --timeout-seconds 15 quit", script)

    def test_generated_bootstrap_keeps_windows_account_backslash_literal(self):
        """Regression for Python interpreting ``\\v`` as a vertical tab."""
        strings = [node.value for node in ast.walk(ast.parse(quit_owner._REMOTE))
                   if isinstance(node, ast.Constant) and isinstance(node.value, str)]
        bootstrap = next(value for value in strings if "VPNMSIX64" in value)
        self.assertIn("VPNMSIX64\\vpncp117", bootstrap)
        self.assertNotIn("\x0b", bootstrap)

    def test_inputs_are_host_only_without_caller_identity_or_hash(self):
        self.assertEqual(quit_owner._REQUEST["host"], "archlinux")
        self.assertNotIn("cliSha256", quit_owner._REQUEST)
        self.assertNotIn("pid", quit_owner._REQUEST)
        with self.assertRaises(quit_owner.WindowsMsiOwnerRelaunchQuitError):
            quit_owner.start(".", {"host": "archlinux", "parentPid": 1})

    def test_start_durably_records_before_its_single_native_submission(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(quit_owner, "_admit", return_value=self._admitted()), \
                mock.patch.object(quit_owner, "_run", return_value={"version": 1, "state": "submitted"}) as run:
            result = quit_owner.start(directory, {"host": "archlinux"})
            self.assertEqual(result["state"], "submitted")
            self.assertEqual(run.call_count, 1)
            record = quit_owner._read(Path(directory))
            self.assertEqual(record["state"], "intent")
            self.assertEqual(record["idempotencyKey"], quit_owner._CORRELATION)
            self.assertEqual(record["requestSha256"], quit_owner._REQUEST_SHA256)
            path = quit_owner._path(Path(directory), False)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_existing_intent_never_replays_the_public_quit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _config, _descriptor, _hash, generation, evidence = self._admitted()
            quit_owner._write(root, {"version": 1, "correlationId": quit_owner._CORRELATION,
                                     "idempotencyKey": quit_owner._CORRELATION,
                                     "requestSha256": quit_owner._REQUEST_SHA256,
                                     "sourceSha": quit_owner.relaunch._SOURCE,
                                     "guestGeneration": generation, "evidenceSha256": evidence,
                                     "state": "intent"})
            with mock.patch.object(quit_owner, "status", return_value={"state": "pending"}), \
                    mock.patch.object(quit_owner, "_run") as run:
                self.assertEqual(quit_owner.start(root, {"host": "archlinux"}), {"state": "pending"})
                run.assert_not_called()

    def test_blocked_admission_creates_no_journal_or_guest_dispatch(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(quit_owner, "_admit", return_value=None), \
                mock.patch.object(quit_owner, "_run") as run:
            self.assertEqual(quit_owner.start(directory, {"host": "archlinux"}), quit_owner._UNKNOWN)
            self.assertFalse((Path(directory) / quit_owner._GROUP).exists())
            run.assert_not_called()

    def test_status_is_read_only_and_marks_only_verified_post_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _config, _descriptor, _hash, generation, evidence = self._admitted()
            record = {"version": 1, "correlationId": quit_owner._CORRELATION,
                      "idempotencyKey": quit_owner._CORRELATION,
                      "requestSha256": quit_owner._REQUEST_SHA256,
                      "sourceSha": quit_owner.relaunch._SOURCE,
                      "guestGeneration": generation, "evidenceSha256": evidence, "state": "intent"}
            quit_owner._write(root, record)
            with mock.patch.object(quit_owner, "_observer_bound", return_value=(object(), self._admitted()[1], "b" * 64, record)), \
                    mock.patch.object(quit_owner, "_run", return_value={"version": 1, "state": "exited"}) as run:
                result = quit_owner.status(root, {"host": "archlinux"})
            self.assertEqual(result, {"state": "exited", "runtimeRunning": False, "ownerExited": True,
                                      "replayAllowed": False, "nativeActionAllowed": False})
            self.assertEqual(run.call_args.args[-1], "status")
            self.assertEqual(quit_owner._read(root)["state"], "exited")

    def test_post_exit_observer_does_not_require_the_two_owners_to_remain(self):
        """The successful effect removes the very owner shape used by start."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _config, descriptor, cli_hash, generation, _evidence = self._admitted()
            evidence = __import__("hashlib").sha256(json.dumps(generation, sort_keys=True).encode()).hexdigest()
            record = {"version": 1, "correlationId": quit_owner._CORRELATION,
                      "idempotencyKey": quit_owner._CORRELATION,
                      "requestSha256": quit_owner._REQUEST_SHA256,
                      "sourceSha": quit_owner.relaunch._SOURCE,
                      "guestGeneration": generation, "evidenceSha256": evidence, "state": "intent"}
            quit_owner._write(root, record)
            launch = {"state": "intent", "sourceSha": quit_owner.relaunch._SOURCE,
                      "guestGeneration": generation, "staleRecoveryEvidenceSha256": evidence}
            with mock.patch.object(quit_owner.relaunch.liveness, "_admit",
                                   return_value=(object(), descriptor, quit_owner.relaunch._SOURCE, cli_hash)), \
                    mock.patch.object(quit_owner.relaunch, "_read_intent", return_value=launch), \
                    mock.patch.object(quit_owner, "_admit", return_value=None):
                bound = quit_owner._observer_bound(root)
            self.assertEqual(bound[1:], (descriptor, cli_hash, record))

    def test_pre_effect_admission_accepts_actual_intent_redaction_and_runtime_off_liveness(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _config, descriptor, cli_hash, generation, evidence = self._admitted()
            relaunch_admitted = (object(), descriptor, cli_hash, evidence)
            launch = {"state": "intent", "guestGeneration": generation,
                      "staleRecoveryEvidenceSha256": evidence}
            exact = {"state": "detailed", "baseOwners": "none", "quotedStateServe": "one",
                     "unquotedStateServe": "one", "otherSubcommand": "none", "unrelated": "none",
                     "ownerIdentity": "exact", "endpoint": "invalid", "schemaVersion": "ambiguous",
                     "controllerId": "ambiguous", "port": "ambiguous", "token": "ambiguous",
                     "replayAllowed": False, "nativeActionAllowed": False}
            live = {"state": "blocked", "sourceSha": quit_owner.relaunch._SOURCE,
                    "correlationId": quit_owner.relaunch.stale_lock._CORRELATION,
                    "ownerProcesses": "many", "installerProcesses": "none", "consentProcesses": "none",
                    "runtimeProcesses": "none", "stateLeaves": "both", "runtimeOff": True,
                    "replayAllowed": False, "nativeActionAllowed": False}
            with mock.patch.object(quit_owner.relaunch, "_admit", return_value=relaunch_admitted), \
                    mock.patch.object(quit_owner.relaunch, "_read_intent", return_value=launch), \
                    mock.patch.object(quit_owner.relaunch, "detail", return_value=exact), \
                    mock.patch.object(quit_owner.relaunch.liveness, "observe", return_value=live):
                observed = quit_owner._admit(root)
                self.assertEqual(observed[1:], self._admitted()[1:])
                live["runtimeOff"] = False
                self.assertIsNone(quit_owner._admit(root))

    def test_admission_accepts_only_private_endpoint_redaction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _config, descriptor, cli_hash, generation, evidence = self._admitted()
            relaunch_admitted = (object(), descriptor, cli_hash, evidence)
            launch = {"state": "launched", "guestGeneration": generation,
                      "staleRecoveryEvidenceSha256": evidence}
            exact = {"state": "detailed", "baseOwners": "none", "quotedStateServe": "one",
                     "unquotedStateServe": "one", "otherSubcommand": "none", "unrelated": "none",
                     "ownerIdentity": "exact", "endpoint": "invalid", "schemaVersion": "ambiguous",
                     "controllerId": "ambiguous", "port": "ambiguous", "token": "ambiguous",
                     "replayAllowed": False, "nativeActionAllowed": False}
            live = {"state": "blocked", "sourceSha": quit_owner.relaunch._SOURCE,
                    "correlationId": quit_owner.relaunch.stale_lock._CORRELATION,
                    "ownerProcesses": "many", "installerProcesses": "none", "consentProcesses": "none",
                    "runtimeProcesses": "none", "stateLeaves": "both", "runtimeOff": True,
                    "replayAllowed": False, "nativeActionAllowed": False}
            with mock.patch.object(quit_owner.relaunch, "_admit", return_value=relaunch_admitted), \
                    mock.patch.object(quit_owner.relaunch, "_read_intent", return_value=launch), \
                    mock.patch.object(quit_owner.relaunch, "detail", return_value=exact), \
                    mock.patch.object(quit_owner.relaunch.liveness, "observe", return_value=live):
                self.assertIsNotNone(quit_owner._admit(root))
                for key, rejected in (("endpoint", "valid"), ("schemaVersion", "valid"),
                                      ("controllerId", "valid"), ("port", "valid"), ("token", "valid")):
                    with self.subTest(key=key):
                        exact[key] = rejected
                        self.assertIsNone(quit_owner._admit(root))
                        exact[key] = "invalid" if key == "endpoint" else "ambiguous"

    def test_diagnostic_projects_task_absence_without_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = {"state": "intent"}
            with mock.patch.object(quit_owner, "_observer_bound", return_value=(object(), self._admitted()[1], "b" * 64, record)), \
                    mock.patch.object(quit_owner, "_run", return_value={"version": 1, "phase": "tasks", "task": "absent"}) as run:
                result = quit_owner.diagnose(root, {"host": "archlinux"})
            self.assertEqual(result["task"], "absent")
            self.assertEqual(run.call_args.args[-1], "diagnose")


if __name__ == "__main__":
    unittest.main()

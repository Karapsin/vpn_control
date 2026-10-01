"""Causal regressions for the one-shot CP117 original-user owner relaunch."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
from unittest import TestCase, mock

from agent_tools import windows_msi_owner_relaunch as relaunch


DESCRIPTOR = ("windows-cp117", "/private/qga.sock", 589342, 520739, "S-1-5-21-1-2-3-1002")
LAUNCHED = {"version": 1, "state": "launched", "cliSha256": "a" * 64,
            "ownerPid": 778, "sessionId": 1, "runtimeRunning": False}


class OwnerRelaunchTests(TestCase):
    def _admitted(self):
        evidence = relaunch.hashlib.sha256(json.dumps({"socketPath": DESCRIPTOR[1], "qemuPid": DESCRIPTOR[2],
                                                        "startTicks": DESCRIPTOR[3]}, sort_keys=True).encode()).hexdigest()
        return object(), DESCRIPTOR, "a" * 64, evidence

    def test_intent_precedes_launch_and_unknown_response_is_never_replayed(self):
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(relaunch, "_admit", return_value=self._admitted()), \
             mock.patch.object(relaunch.stale_reconcile, "status", return_value={"state": "terminal-proven", "replayAllowed": False, "nativeActionAllowed": False}), \
             mock.patch.object(relaunch.liveness, "observe", return_value={"state": "absent"}), \
             mock.patch.object(relaunch, "_run", return_value={"state": "unknown"}) as run:
            value = relaunch.launch(temporary, {"host": "archlinux"})
            self.assertEqual(value, relaunch._UNKNOWN)
            self.assertEqual(run.call_args.args[-1], "launch")
            self.assertEqual(relaunch._read_intent(Path(temporary))["state"], "intent")
            self.assertEqual(relaunch.launch(temporary, {"host": "archlinux"}), relaunch._UNKNOWN)
            self.assertEqual(run.call_count, 1)

    def test_relaunch_requires_fresh_global_absence_before_mutation(self):
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(relaunch, "_admit", return_value=self._admitted()), \
             mock.patch.object(relaunch.stale_reconcile, "status", return_value={"state": "terminal-proven", "replayAllowed": False, "nativeActionAllowed": False}), \
             mock.patch.object(relaunch.liveness, "observe", return_value={"state": "blocked"}), \
             mock.patch.object(relaunch, "_run") as run:
            self.assertEqual(relaunch.launch(temporary, {"host": "archlinux"}), relaunch._UNKNOWN)
            run.assert_not_called()
            self.assertIsNone(relaunch._read_intent(Path(temporary)))

    def test_relaunch_requires_armed_c32_history_and_recovered_separate_reconcile_receipt(self):
        root = Path.cwd()
        evidence = relaunch.hashlib.sha256(json.dumps({"socketPath": DESCRIPTOR[1], "qemuPid": DESCRIPTOR[2],
                                                        "startTicks": DESCRIPTOR[3]}, sort_keys=True).encode()).hexdigest()
        old = {"state": "intent", "sourceSha": relaunch._SOURCE,
               "guestGeneration": {"socketPath": DESCRIPTOR[1], "qemuPid": DESCRIPTOR[2], "startTicks": DESCRIPTOR[3]},
               "evidenceSha256": evidence}
        recovery = {"state": "recovered", "sourceSha": relaunch._SOURCE,
                    "guestGeneration": {"socketPath": DESCRIPTOR[1], "qemuPid": DESCRIPTOR[2], "startTicks": DESCRIPTOR[3]},
                    "evidenceSha256": evidence}
        with mock.patch.object(relaunch.liveness, "_admit", return_value=(object(), DESCRIPTOR, relaunch._SOURCE, "a" * 64)), \
             mock.patch.object(relaunch.stale_lock, "_read_intent", return_value=old), \
             mock.patch.object(relaunch.stale_lock, "_matches_current", return_value=True), \
             mock.patch.object(relaunch.stale_reconcile, "_read", return_value=recovery), \
             mock.patch.object(relaunch.stale_reconcile, "_matches", return_value=True):
            self.assertIsNotNone(relaunch._admit(root))
            recovery["guestGeneration"]["startTicks"] += 1
            self.assertIsNone(relaunch._admit(root))

    def test_unknown_or_tampered_reconcile_receipt_cannot_admit_owner_launch(self):
        root = Path.cwd()
        old = {"state": "intent", "sourceSha": relaunch._SOURCE}
        recovered = {"state": "recovered", "sourceSha": relaunch._SOURCE}
        with mock.patch.object(relaunch.liveness, "_admit", return_value=(object(), DESCRIPTOR, relaunch._SOURCE, "a" * 64)), \
             mock.patch.object(relaunch.stale_lock, "_read_intent", return_value=old), \
             mock.patch.object(relaunch.stale_lock, "_matches_current", return_value=True), \
             mock.patch.object(relaunch.stale_reconcile, "_read", return_value=recovered), \
             mock.patch.object(relaunch.stale_reconcile, "_matches", return_value=True):
            self.assertIsNone(relaunch._admit(root))
        with mock.patch.object(relaunch, "_admit", return_value=self._admitted()), \
             mock.patch.object(relaunch.stale_reconcile, "status", return_value=relaunch._UNKNOWN), \
             mock.patch.object(relaunch.liveness, "observe", return_value={"state": "absent"}), \
             mock.patch.object(relaunch, "_run") as run:
            self.assertEqual(relaunch.launch(root, {"host": "archlinux"}), relaunch._UNKNOWN)
            run.assert_not_called()

    def test_mismatched_owner_or_noninteractive_task_is_denied_in_guest_program(self):
        for required in ("-UserId $sid", "-LogonType Interactive", "-RunLevel Limited", "SessionId -eq 1",
                         "GetOwnerSid", "Get-ScheduledTask -TaskName $taskName", "Missing $lock", "Missing $endpoint",
                         "Get-FileHash", "'2.1.19'"):
            self.assertIn(required, relaunch._LAUNCH_PS)
        self.assertIn("$process.CommandLine -in $expectedCommandLines", relaunch._LAUNCH_PS)
        self.assertIn("Get-Item -LiteralPath $path -Force -ErrorAction Stop", relaunch._LAUNCH_PS)
        self.assertIn("ObjectNotFound", relaunch._LAUNCH_PS)
        self.assertNotIn("if(Test-Path -LiteralPath $path)", relaunch._LAUNCH_PS)
        self.assertIn("$actions[0].Execute -cne $cli", relaunch._STATUS_PS)
        self.assertIn("$actions[0].Arguments -cne $argument", relaunch._STATUS_PS)
        self.assertIn("$app.CommandLine -ceq $expectedCommandLines[0]", relaunch._STATUS_PS)
        self.assertIn("function SafeAncestors", relaunch._LAUNCH_PS)
        self.assertIn("C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\cp166", relaunch._LAUNCH_PS)
        self.assertIn("function SafeAncestors", relaunch._STATUS_PS)
        self.assertIn("C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\cp166", relaunch._STATUS_PS)
        for forbidden in ("Stop-Process", "sing-box.exe --", "vpn-control.exe --"):
            self.assertNotIn(forbidden, relaunch._LAUNCH_PS)
        compile(relaunch._REMOTE, "owner-relaunch-remote", "exec")

    def test_launch_leaf_absence_accepts_only_object_not_found(self):
        # `Test-Path` maps access failures to false.  The launch program must
        # instead obtain the leaf and accept only the provider's exact absent
        # category; a present leaf reaches Fail and access/other errors reach
        # Fail from the catch branch.
        body = relaunch._LAUNCH_PS.split("function Missing", 1)[1].split("function SafeDirectory", 1)[0]
        self.assertIn("Get-Item -LiteralPath $path -Force -ErrorAction Stop", body)
        self.assertIn("Fail", body)  # present lock/endpoint
        self.assertIn("ObjectNotFound", body)  # the sole allowed exception
        self.assertNotIn("Test-Path", body)  # inaccessible must not look absent

    def test_armed_intent_diagnosis_projects_multi_owner_without_raw_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _config, descriptor, _hash, evidence = self._admitted()
            relaunch._write_intent(root, {"version": 1, "correlationId": relaunch._CORRELATION,
                                          "sourceSha": relaunch._SOURCE,
                                          "guestGeneration": {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]},
                                          "staleRecoveryEvidenceSha256": evidence, "state": "intent"})
            observed = {"phase": "owner-process-count-many", "task": "exact", "owners": "many", "endpoint": "valid"}
            with mock.patch.object(relaunch, "_admit", return_value=self._admitted()), \
                 mock.patch.object(relaunch, "_diagnostic", return_value=observed):
                result = relaunch.diagnose(root, {"host": "archlinux"})
            self.assertEqual(result, {"state": "diagnosed", **observed, "replayAllowed": False, "nativeActionAllowed": False})
            self.assertNotIn("pid", json.dumps(result).lower())
            self.assertNotIn("path", json.dumps(result).lower())

    def test_diagnosis_is_read_only_and_uses_only_bounded_task_owner_endpoint_states(self):
        for forbidden in ("Start-ScheduledTask", "Register-ScheduledTask", "Stop-Process", "Remove-Item", "Set-Content"):
            self.assertNotIn(forbidden, relaunch._DIAGNOSE_PS)
        for required in ("$taskState", "$owners", "$endpointState", "Get-ScheduledTask", "Get-CimInstance Win32_Process",
                         "PrincipalSid", "ConvertFrom-Json"):
            self.assertIn(required, relaunch._DIAGNOSE_PS)
        self.assertIn("owner-process-count-many", relaunch._DIAGNOSTIC_PHASES)

    def test_diagnosis_outer_failure_has_a_bounded_stage_and_no_raw_exception(self):
        for stage in ("ancestors", "cli", "task-query", "process-query", "endpoint", "phase-eval"):
            self.assertIn("$stage='" + stage + "'", relaunch._DIAGNOSE_PS)
            self.assertIn("diagnostic-" + stage, relaunch._DIAGNOSTIC_PHASES)
        self.assertIn("('diagnostic-'+$stage)", relaunch._DIAGNOSE_PS)
        self.assertNotIn("$_.Exception.Message", relaunch._DIAGNOSE_PS)
        # The old nested `if` expression was hard to inspect after an outer
        # fallback.  The fixed script uses ordinary branches for phase output.
        self.assertIn("if($taskState -ne 'exact')", relaunch._DIAGNOSE_PS)
        self.assertNotIn("$phase=if(", relaunch._DIAGNOSE_PS)

    def test_armed_intent_detail_projects_command_shapes_and_endpoint_schema_without_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _config, descriptor, _hash, evidence = self._admitted()
            relaunch._write_intent(root, {"version": 1, "correlationId": relaunch._CORRELATION,
                                          "sourceSha": relaunch._SOURCE,
                                          "guestGeneration": {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]},
                                          "staleRecoveryEvidenceSha256": evidence, "state": "intent"})
            observed = {"baseOwners": "one", "quotedStateServe": "one", "unquotedStateServe": "none",
                        "otherSubcommand": "none", "unrelated": "none", "ownerIdentity": "exact",
                        "endpoint": "valid", "schemaVersion": "valid", "controllerId": "valid",
                        "port": "valid", "token": "valid"}
            with mock.patch.object(relaunch, "_admit", return_value=self._admitted()), \
                 mock.patch.object(relaunch, "_detail", return_value=observed):
                result = relaunch.detail(root, {"host": "archlinux"})
            self.assertEqual(result, {"state": "detailed", **observed, "replayAllowed": False, "nativeActionAllowed": False})
            rendered = json.dumps(result).lower()
            for secret in ("pid", "path", "tokenvalue", "controller-value", "commandline"):
                self.assertNotIn(secret, rendered)

    def test_detail_program_only_classifies_fixed_command_and_endpoint_field_shapes(self):
        for required in ("$baseCommands", "$quotedCommand", "$unquotedCommand", "$subcommand", "Field $value 'token'",
                         "Field $value 'controllerId'", "Get-FileHash", "GetOwnerSid"):
            self.assertIn(required, relaunch._DETAIL_PS)
        for forbidden in ("Start-ScheduledTask", "Stop-Process", "Remove-Item", "Set-Content", "Out-File"):
            self.assertNotIn(forbidden, relaunch._DETAIL_PS)

    def test_endpoint_access_projects_acl_denial_without_endpoint_contents(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _config, descriptor, _hash, evidence = self._admitted()
            relaunch._write_intent(root, {"version": 1, "correlationId": relaunch._CORRELATION,
                                          "sourceSha": relaunch._SOURCE,
                                          "guestGeneration": {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]},
                                          "staleRecoveryEvidenceSha256": evidence, "state": "intent"})
            with mock.patch.object(relaunch, "_admit", return_value=self._admitted()), \
                 mock.patch.object(relaunch, "_endpoint_access", return_value="access-denied"):
                self.assertEqual(relaunch.endpoint_access(root, {"host": "archlinux"}),
                                 {"state": "endpoint-access", "endpoint": "access-denied", "replayAllowed": False, "nativeActionAllowed": False})
        self.assertIn("PermissionDenied", relaunch._ENDPOINT_ACCESS_PS)
        self.assertIn("ObjectNotFound", relaunch._ENDPOINT_ACCESS_PS)
        for forbidden in ("Start-ScheduledTask", "Stop-Process", "Set-Content", "Out-File"):
            self.assertNotIn(forbidden, relaunch._ENDPOINT_ACCESS_PS)

    def test_status_principal_readback_accepts_only_resolved_sid_and_actual_scheduledtask_enums(self):
        # ScheduledTasks returns `Interactive` and `Limited` for a principal
        # created with the corresponding New-ScheduledTaskPrincipal values.
        # PrincipalSid intentionally covers both a SID string and its account
        # name form before applying the exact fixed-SID comparison.
        self.assertIn("function PrincipalSid", relaunch._STATUS_PS)
        self.assertIn("[Security.Principal.NTAccount]::new($userId)", relaunch._STATUS_PS)
        self.assertIn("$principalSid -cne $sid", relaunch._STATUS_PS)
        self.assertIn("LogonType.ToString() -cne 'Interactive'", relaunch._STATUS_PS)
        self.assertIn("RunLevel.ToString() -cne 'Limited'", relaunch._STATUS_PS)
        self.assertNotIn("InteractiveToken", relaunch._STATUS_PS)
        self.assertNotIn("LeastPrivilege", relaunch._STATUS_PS)

    def test_status_requires_exact_quoted_and_unquoted_original_user_owner_pair(self):
        self.assertIn("if($apps.Count -ne 2)", relaunch._STATUS_PS)
        self.assertIn("$quoted=0;$unquoted=0", relaunch._STATUS_PS)
        self.assertIn("$quoted -ne 1 -or $unquoted -ne 1", relaunch._STATUS_PS)
        self.assertIn("$app.CommandLine -ceq $expectedCommandLines[0]", relaunch._STATUS_PS)
        self.assertIn("$app.CommandLine -ceq $expectedCommandLines[1]", relaunch._STATUS_PS)

    def test_status_and_collect_are_read_only_lost_response_proofs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _config, descriptor, _hash, evidence = self._admitted()
            relaunch._write_intent(root, {"version": 1, "correlationId": relaunch._CORRELATION,
                                          "sourceSha": relaunch._SOURCE,
                                          "guestGeneration": {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]},
                                          "staleRecoveryEvidenceSha256": evidence, "state": "intent"})
            with mock.patch.object(relaunch, "_admit", return_value=self._admitted()), \
                 mock.patch.object(relaunch, "_run", return_value=LAUNCHED) as run:
                self.assertEqual(relaunch.status(root, {"host": "archlinux"})["state"], "launched")
                self.assertEqual(relaunch.collect(root, {"host": "archlinux"})["state"], "launched")
                self.assertEqual([item.args[-1] for item in run.call_args_list], ["status", "status"])
                self.assertEqual(relaunch._read_intent(root)["state"], "intent")
        self.assertNotIn("Start-ScheduledTask", relaunch._STATUS_PS)
        self.assertNotIn("Register-ScheduledTask", relaunch._STATUS_PS)

    def test_status_without_journal_does_not_create_a_directory_or_dispatch_guest_work(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(relaunch, "_admit", return_value=self._admitted()), \
                 mock.patch.object(relaunch, "_run") as run:
                self.assertEqual(relaunch.status(root, {"host": "archlinux"}), relaunch._UNKNOWN)
                self.assertFalse((root / relaunch._GROUP).exists())
                run.assert_not_called()

    def test_status_rejects_a_journal_from_another_qemu_generation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _config, descriptor, _hash, evidence = self._admitted()
            relaunch._write_intent(root, {"version": 1, "correlationId": relaunch._CORRELATION,
                                          "sourceSha": relaunch._SOURCE,
                                          "guestGeneration": {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3] + 1},
                                          "staleRecoveryEvidenceSha256": evidence, "state": "intent"})
            with mock.patch.object(relaunch, "_admit", return_value=self._admitted()), \
                 mock.patch.object(relaunch, "_run") as run:
                self.assertEqual(relaunch.status(root, {"host": "archlinux"}), relaunch._UNKNOWN)
                run.assert_not_called()

    def test_launch_success_records_terminal_receipt_and_refuses_bad_input(self):
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(relaunch, "_admit", return_value=self._admitted()), \
             mock.patch.object(relaunch.stale_reconcile, "status", return_value={"state": "terminal-proven", "replayAllowed": False, "nativeActionAllowed": False}), \
             mock.patch.object(relaunch.liveness, "observe", return_value={"state": "absent"}), \
             mock.patch.object(relaunch, "_run", return_value=LAUNCHED):
            result = relaunch.launch(temporary, {"host": "archlinux"})
            self.assertEqual(result["state"], "launched")
            self.assertEqual(relaunch._read_intent(Path(temporary))["state"], "launched")
        with self.assertRaises(relaunch.WindowsMsiOwnerRelaunchError):
            relaunch.launch(Path.cwd(), {"host": "other"})

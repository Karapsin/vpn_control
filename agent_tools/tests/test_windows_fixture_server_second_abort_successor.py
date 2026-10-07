"""Causal regressions for the CP117 second abort proof successor."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest import mock

from agent_tools import windows_fixture_server_second_abort_successor as successor
from agent_tools import mcp_server

NEXT = "a1a2a3a4-1111-4222-8333-123456789abc"
REQUEST = {"successorCorrelationId": NEXT}
RECOVERY_REQUEST = {"recoveryCorrelationId": successor._RECOVERY}
GEN = ("windows-cp117", "/qga", 17, 29, "S-1-5-21-1-2-3-1002")
SERVER_REQUEST = {"host": "archlinux", "leaseId": "11111111-1111-4111-8111-111111111111", "stageCorrelationId": "22222222-2222-4222-8222-222222222222", "serverCorrelationId": successor._SERVER, "sourceSha": "a" * 40, "fixtureReceiptArtifactId": "sha256-" + "b" * 64, "baseMsiArtifactId": "sha256-" + "c" * 64, "targetMsiArtifactId": "sha256-" + "d" * 64}
ABORT = {"schemaVersion": 1, "mode": "abort", "request": {"leaseId": SERVER_REQUEST["leaseId"], "serverCorrelationId": successor._SERVER, "cleanupCorrelationId": successor._ABORT}, "serverRequest": SERVER_REQUEST, "environment": "windows-cp117", "socketPath": GEN[1], "qemuPid": GEN[2], "startTicks": GEN[3], "originalSid": GEN[4]}

class SecondAbortSuccessorTests(unittest.TestCase):
    def _admitted(self):
        return object(), type("Target", (), {"fixture_transfer_root": "/fixture"})(), GEN, SERVER_REQUEST, ABORT

    def _recovery_admitted(self):
        consumed = {"version": 1, "request": {"successorCorrelationId": successor._CONSUMED},
                    "serverCorrelationId": successor._SERVER, "abortCleanupCorrelationId": successor._ABORT,
                    "serverRequest": SERVER_REQUEST,
                    "guestGeneration": {"socketPath": GEN[1], "qemuPid": GEN[2], "startTicks": GEN[3]}}
        return object(), type("Target", (), {"fixture_transfer_root": "/fixture"})(), GEN, SERVER_REQUEST, consumed

    def test_red_unknown_abort_blocks_then_green_exact_absence_finishes(self):
        proof = {"state": "observed", "abortChild": "terminal-nonzero", "taskState": "absent", "process": "absent", "listener": "absent", "runtime": "off"}
        ready = {**proof, "taskState": "ready"}
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(successor, "_admission", return_value=self._admitted()), mock.patch.object(successor, "_observe", return_value=ready), mock.patch.object(successor, "_unregister", return_value={"state": "cleaned"}), mock.patch.object(successor.lease, "finish_role") as finish:
            self.assertEqual("submitted", successor.start(temp, REQUEST)["state"])
            self.assertEqual("unknown", successor.status(temp, REQUEST)["state"])
            finish.assert_not_called()
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(successor, "_admission", return_value=self._admitted()), mock.patch.object(successor, "_observe", side_effect=[ready, proof]), mock.patch.object(successor, "_unregister", return_value={"state": "cleaned"}), mock.patch.object(successor.lease, "finish_role", return_value={"state": "active"}) as finish:
            self.assertEqual("submitted", successor.start(temp, REQUEST)["state"])
            self.assertEqual("cleaned", successor.status(temp, REQUEST)["state"])
            finish.assert_called_once()

    def test_duplicate_start_never_redispatches_guest_unregister(self):
        ready = {"state": "observed", "abortChild": "expired", "taskState": "ready", "process": "absent", "listener": "absent", "runtime": "off"}
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(successor, "_admission", return_value=self._admitted()), mock.patch.object(successor, "_observe", return_value=ready), mock.patch.object(successor, "_unregister", return_value={"state": "cleaned"}) as unregister:
            self.assertEqual("submitted", successor.start(temp, REQUEST)["state"])
            self.assertEqual("unknown", successor.start(temp, REQUEST)["state"])
            self.assertIsNotNone(successor._read(Path(temp), NEXT))
            self.assertEqual(1, unregister.call_count)

    def test_recovery_red_prior_unknown_pre_effect_blocks_replay_then_green_finishes(self):
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(successor, "_recovery_admission", return_value=self._recovery_admitted()), \
             mock.patch.object(successor, "_recovery_remote", return_value={"state": "cleaned"}) as remote:
            self.assertEqual("submitted", successor.resume_start(temp, RECOVERY_REQUEST)["state"])
            self.assertEqual("unknown", successor.resume_start(temp, RECOVERY_REQUEST)["state"])
            self.assertEqual(1, remote.call_count)
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(successor, "_recovery_admission", return_value=self._recovery_admitted()), \
             mock.patch.object(successor, "_recovery_remote", side_effect=[{"state": "cleaned"}, {"state": "cleaned"}]), \
             mock.patch.object(successor.lease, "finish_role", return_value={"state": "active"}) as finish:
            self.assertEqual("submitted", successor.resume_start(temp, RECOVERY_REQUEST)["state"])
            self.assertEqual("cleaned", successor.resume_status(temp, RECOVERY_REQUEST)["state"])
            finish.assert_called_once()

    def test_recovery_terminal_without_fresh_absence_never_finishes_role(self):
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(successor, "_recovery_admission", return_value=self._recovery_admitted()), \
             mock.patch.object(successor, "_recovery_remote", side_effect=[{"state": "cleaned"}, {"state": "unknown"}]), \
             mock.patch.object(successor.lease, "finish_role") as finish:
            self.assertEqual("submitted", successor.resume_start(temp, RECOVERY_REQUEST)["state"])
            self.assertEqual("unknown", successor.resume_status(temp, RECOVERY_REQUEST)["state"])
            finish.assert_not_called()

    def test_recovery_completed_status_is_idempotent_without_guest_replay(self):
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(successor, "_recovery_completed", return_value="e" * 64), \
             mock.patch.object(successor, "_recovery_admission", side_effect=AssertionError("must not re-admit")), \
             mock.patch.object(successor, "_recovery_remote", side_effect=AssertionError("must not re-observe")):
            result = successor.resume_status(temp, RECOVERY_REQUEST)
        self.assertEqual("cleaned", result["state"])
        self.assertEqual("e" * 64, result["cleanupReceiptSha256"])

    def test_recovery_uses_resolved_sid_for_alternate_principal_spelling(self):
        self.assertIn(".Translate([Security.Principal.SecurityIdentifier]).Value", successor._REMOTE_RECOVERY)
        self.assertIn("$actual -cne $sid", successor._REMOTE_RECOVERY)
        self.assertNotIn("VPNMSIX64", successor._REMOTE_RECOVERY)
        compile(successor._REMOTE_RECOVERY, "second-abort-recovery-qga", "exec")
        compile(successor._REMOTE_RECOVERY_STATUS, "second-abort-recovery-status-qga", "exec")

    def test_completed_role_is_reconciled_without_a_second_observation(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(successor, "_admission", return_value=self._admitted()):
            successor.start(temp, REQUEST)
            with mock.patch.object(successor, "_completed", return_value="d" * 64), \
                 mock.patch.object(successor, "_observe", side_effect=AssertionError("must not replay observation")):
                result = successor.status(temp, REQUEST)
        self.assertEqual("cleaned", result["state"])

    def test_wrong_binding_blocks_before_journal(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(successor, "_admission", side_effect=successor.WindowsFixtureServerSecondAbortSuccessorError("binding")):
            self.assertEqual("unknown", successor.start(temp, REQUEST)["state"])
            self.assertIsNone(successor._read(Path(temp), NEXT))

    def test_remote_program_is_read_only(self):
        self.assertNotIn("Unregister-ScheduledTask", successor._REMOTE)
        self.assertNotIn("Stop-Process", successor._REMOTE)
        self.assertIn("Get-ScheduledTask", successor._REMOTE)
        self.assertIn("Get-NetTCPConnection", successor._REMOTE)
        self.assertIn("powershell-launch", successor._REMOTE)
        self.assertIn("powershell-status", successor._REMOTE)
        self.assertIn("census-result", successor._REMOTE)
        compile(successor._REMOTE, "second-abort-proof-qga", "exec")

    def test_unregister_remote_rechecks_exact_old_cleanup_binding_before_mutation(self):
        self.assertIn("old_binding=regular", successor._REMOTE_UNREGISTER)
        self.assertIn("old_dispatch=regular", successor._REMOTE_UNREGISTER)
        self.assertIn("old_binding.get('cleanupCorrelationId')", successor._REMOTE_UNREGISTER)
        self.assertIn("set(old_dispatch)!={'pid'}", successor._REMOTE_UNREGISTER)
        compile(successor._REMOTE_UNREGISTER, "second-abort-unregister-qga", "exec")

    def test_post_start_diagnostic_classifies_registered_username_and_two_action_fingerprints(self):
        detail = {"state": "observed", "journalBinding": "present", "journalTerminal": "absent",
                  "taskState": "ready", "principal": "expected-username", "principalSid": "resolved-sid-match", "actionCount": "two",
                  "action0Fingerprint": "expected", "action1Fingerprint": "other",
                  "additionalActions": "none", "logonType": "expected", "runLevel": "expected",
                  "process": "absent", "listener": "absent", "runtime": "off"}
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(successor, "_admission", return_value=self._admitted()), mock.patch.object(successor, "_unregister_diagnose", return_value=detail), mock.patch.object(successor, "_observe", side_effect=AssertionError("must use successor diagnostic")):
            result = successor.diagnose(temp, REQUEST)
        self.assertEqual({**detail, "successorCorrelationId": NEXT, "replayAllowed": False,
                          "nativeActionAllowed": False, "productAction": False}, result)
        self.assertNotIn("principalMatch", result)
        self.assertNotIn("executeMatch", result)
        self.assertNotIn("argumentsMatch", result)
        self.assertIn("$sv=[int]$t[0].State", successor._REMOTE_UNREGISTER_DIAGNOSTIC)
        self.assertIn("$account='VPNMSIX64\\vpncp117'", successor._REMOTE_UNREGISTER_DIAGNOSTIC)
        self.assertIn("$a0=@();if($t.Count -eq 1){$a0=@($t[0].Actions)}", successor._REMOTE_UNREGISTER_DIAGNOSTIC)
        compile(successor._REMOTE_UNREGISTER_DIAGNOSTIC, "second-abort-unregister-diagnostic-qga", "exec")

    def test_post_start_diagnostic_rejects_predecessor_aggregate_shape(self):
        old_shape = {"state": "observed", "journalBinding": "present", "journalTerminal": "absent",
                     "taskState": "ready", "principalMatch": "mismatch", "actionCount": "multiple",
                     "executeMatch": "not-applicable", "argumentsMatch": "not-applicable", "process": "absent",
                     "listener": "absent", "runtime": "off"}
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(successor, "_admission", return_value=self._admitted()), \
             mock.patch.object(successor, "_unregister_diagnose", return_value=old_shape), \
             mock.patch.object(successor, "_observe", return_value={"state": "diagnosed", "phase": "powershell-status"}):
            result = successor.diagnose(temp, REQUEST)
        self.assertEqual("diagnosed", result["state"])
        self.assertEqual("powershell-status", result["phase"])
        self.assertNotIn("principalMatch", result)

    def test_post_start_diagnostic_accepts_sid_and_three_or_more_action_classes(self):
        detail = {"state": "observed", "journalBinding": "present", "journalTerminal": "absent",
                  "taskState": "ready", "principal": "expected-sid", "principalSid": "resolved-sid-match", "actionCount": "three-or-more",
                  "action0Fingerprint": "expected", "action1Fingerprint": "other",
                  "additionalActions": "contains-other", "logonType": "expected", "runLevel": "expected",
                  "process": "absent", "listener": "absent", "runtime": "off"}
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(successor, "_admission", return_value=self._admitted()), \
             mock.patch.object(successor, "_unregister_diagnose", return_value=detail), \
             mock.patch.object(successor, "_observe", side_effect=AssertionError("must use successor diagnostic")):
            result = successor.diagnose(temp, REQUEST)
        self.assertEqual("expected-sid", result["principal"])
        self.assertEqual("three-or-more", result["actionCount"])
        self.assertEqual("contains-other", result["additionalActions"])

    def test_post_start_diagnostic_rejects_scalar_action_count_contradiction(self):
        scalar_bug = {"state": "observed", "journalBinding": "present", "journalTerminal": "absent",
                      "taskState": "ready", "principal": "expected-username", "principalSid": "resolved-sid-match",
                      "actionCount": "three-or-more", "action0Fingerprint": "not-applicable",
                      "action1Fingerprint": "not-applicable", "additionalActions": "none",
                      "logonType": "expected", "runLevel": "expected", "process": "absent",
                      "listener": "absent", "runtime": "off"}
        one_action = {**scalar_bug, "actionCount": "one", "action0Fingerprint": "expected"}
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(successor, "_admission", return_value=self._admitted()), \
             mock.patch.object(successor, "_unregister_diagnose", return_value=scalar_bug), \
             mock.patch.object(successor, "_observe", return_value={"state": "diagnosed", "phase": "powershell-status"}):
            self.assertEqual("powershell-status", successor.diagnose(temp, REQUEST)["phase"])
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(successor, "_admission", return_value=self._admitted()), \
             mock.patch.object(successor, "_unregister_diagnose", return_value=one_action), \
             mock.patch.object(successor, "_observe", side_effect=AssertionError("must use valid diagnostic")):
            self.assertEqual("one", successor.diagnose(temp, REQUEST)["actionCount"])

    def test_diagnostic_preserves_remote_phase_and_separates_admission(self):
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(successor, "_admission", return_value=self._admitted()), \
             mock.patch.object(successor, "_observe", return_value={"state": "diagnosed", "phase": "powershell-status"}):
            self.assertEqual("powershell-status", successor.diagnose(temp, REQUEST)["phase"])
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(successor, "_admission", side_effect=successor.WindowsFixtureServerSecondAbortSuccessorError("role")):
            self.assertEqual("admission", successor.diagnose(temp, REQUEST)["phase"])

    def test_expired_abort_child_red_task_present_then_green_exact_absence(self):
        """An expired QGA status is evidence only when the fresh census is exact."""
        expired = {"state": "observed", "abortChild": "expired", "taskState": "absent",
                   "process": "absent", "listener": "absent", "runtime": "off"}
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(successor, "_admission", return_value=self._admitted()), \
             mock.patch.object(successor, "_observe", return_value={**expired, "taskState": "ready"}), \
             mock.patch.object(successor.lease, "finish_role") as finish:
            successor.start(temp, REQUEST)
            self.assertEqual("unknown", successor.status(temp, REQUEST)["state"])
            finish.assert_not_called()
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(successor, "_admission", return_value=self._admitted()), \
             mock.patch.object(successor, "_observe", return_value=expired), \
             mock.patch.object(successor.lease, "finish_role", return_value={"state": "active"}):
            successor.start(temp, REQUEST)
            self.assertEqual("cleaned", successor.status(temp, REQUEST)["state"])

    def test_unregister_dispatch_red_task_running_green_ready(self):
        ready = {"state": "observed", "abortChild": "expired", "taskState": "ready", "process": "absent", "listener": "absent", "runtime": "off"}
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(successor, "_admission", return_value=self._admitted()), mock.patch.object(successor, "_observe", return_value={**ready, "taskState": "running"}), mock.patch.object(successor, "_unregister") as action:
            self.assertEqual("unknown", successor.start(temp, REQUEST)["state"])
            action.assert_not_called()
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(successor, "_admission", return_value=self._admitted()), mock.patch.object(successor, "_observe", return_value=ready), mock.patch.object(successor, "_unregister", return_value={"state": "cleaned"}) as action:
            self.assertEqual("submitted", successor.start(temp, REQUEST)["state"])
            action.assert_called_once()

    def test_mcp_route_forwards_only_the_exact_successor_identity(self):
        adapter = mock.Mock()
        adapter.diagnose.return_value = {"state": "observed", "successorCorrelationId": NEXT,
                                         "replayAllowed": False, "nativeActionAllowed": False,
                                         "productAction": False, "journalBinding": "present",
                                         "journalTerminal": "absent", "taskState": "ready",
                                         "principal": "expected-username", "principalSid": "resolved-sid-match", "actionCount": "two",
                                         "action0Fingerprint": "expected", "action1Fingerprint": "other",
                                         "additionalActions": "none", "logonType": "expected",
                                         "runLevel": "expected",
                                         "process": "absent", "listener": "absent", "runtime": "off"}
        with mock.patch.object(mcp_server, "_agent_module", return_value=adapter):
            result = mcp_server._vm_workflow_impl(
                "windows-fixture-server-second-abort-successor-diagnostic", REQUEST)
        self.assertTrue(result["ok"])
        self.assertEqual("ready", result["taskState"])
        self.assertEqual("other", result["action1Fingerprint"])
        adapter.diagnose.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)

    def test_mcp_recovery_routes_use_exact_identity_and_reject_invalid_input_before_dispatch(self):
        adapter = mock.Mock()
        adapter.resume_start.return_value = {"state": "submitted", "recoveryCorrelationId": successor._RECOVERY,
                                             "replayAllowed": False, "nativeActionAllowed": False,
                                             "productAction": False}
        adapter.resume_status.return_value = {"state": "cleaned", "recoveryCorrelationId": successor._RECOVERY,
                                              "cleanupReceiptSha256": "d" * 64, "replayAllowed": False,
                                              "nativeActionAllowed": False, "productAction": False}
        adapter.resume_diagnose.return_value = {"state": "diagnosed", "phase": "journal",
                                                "recoveryCorrelationId": successor._RECOVERY,
                                                "replayAllowed": False, "nativeActionAllowed": False,
                                                "productAction": False}
        with mock.patch.object(mcp_server, "_agent_module", return_value=adapter):
            for action, method in (("windows-fixture-server-second-abort-recovery-start", "resume_start"),
                                   ("windows-fixture-server-second-abort-recovery-status", "resume_status"),
                                   ("windows-fixture-server-second-abort-recovery-diagnose", "resume_diagnose")):
                result = mcp_server._vm_workflow_impl(action, RECOVERY_REQUEST)
                self.assertTrue(result["ok"])
                getattr(adapter, method).assert_called_once_with(mcp_server.REPO_ROOT, RECOVERY_REQUEST)
            adapter.reset_mock()
            bad = mcp_server._vm_workflow_impl("windows-fixture-server-second-abort-recovery-start", {"recoveryCorrelationId": "not-a-uuid"})
        self.assertFalse(bad["ok"])
        adapter.resume_start.assert_not_called()
        with mock.patch.object(successor, "_recovery_admission", side_effect=AssertionError("must not dispatch")):
            with self.assertRaises(successor.WindowsFixtureServerSecondAbortSuccessorError):
                successor.resume_start(".", {"recoveryCorrelationId": NEXT})

if __name__ == "__main__":
    unittest.main()

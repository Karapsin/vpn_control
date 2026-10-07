from __future__ import annotations

import unittest

from agent_tools import native_response_diagnostics as diagnostics


class NativeResponseDiagnosticsTests(unittest.TestCase):
    def test_unlisted_reason_and_phase_tokens_never_enter_public_basis(self):
        for action in ("fixture-read", "android-endpoint-admission-status",
                       "connection-channel-status", "linux-rpm-workspace-cleanup-status"):
            with self.subTest(action=action):
                clean = diagnostics.describe("vm_workflow", action, {"state": "unknown"})
                hostile = diagnostics.describe("vm_workflow", action, {
                    "state": "unknown", "reason": "private-marker", "failurePhase": "private-phase"})
                self.assertNotIn("private-marker", str(hostile))
                self.assertNotIn("private-phase", str(hostile))
                self.assertEqual(clean["failureSignature"], hostile["failureSignature"])
                self.assertFalse(hostile["admissionGap"]["nativeActionAllowed"])

    def test_known_reason_is_not_reused_for_an_unrelated_action(self):
        result = diagnostics.describe("vm_workflow", "fixture-read", {
            "state": "unknown", "reason": "permission_granted", "failurePhase": "master_snapshot"})
        self.assertEqual("unclassified", result["failureSignature"]["basis"]["reason"])
        self.assertEqual("unspecified", result["failureSignature"]["basis"]["phase"])
        self.assertIsNone(result["failureSignature"]["causalRegression"])

    def test_snapshot_causes_are_grouped_separately_without_auth_or_replay_claims(self):
        common = {"state": "unknown", "failurePhase": "master_snapshot",
                  "reason": "channel_admission_unknown", "exceptionClass": "ValueError",
                  "errno": None, "nativeActionAllowed": False, "replayAllowed": False}
        signatures = []
        for cause in ("fd_changed", "master_check", "listener_owner"):
            described = diagnostics.describe("ssh_workflow", "connection-channel-status",
                                             {**common, "failureReason": cause})
            signatures.append(described["failureSignature"]["fingerprint"])
            self.assertEqual(cause, described["failureSignature"]["basis"]["reason"])
            self.assertIn("test_snapshot_refusal_retains_only_complete_finite_diagnostics",
                          described["failureSignature"]["causalRegression"])
            self.assertIs(described["admissionGap"]["nativeActionAllowed"], False)
        self.assertEqual(len(set(signatures)), 3)
        clean = diagnostics.describe("ssh_workflow", "connection-channel-status", common)
        for change in ({"failureReason": "private-marker"}, {"failureReason": "fd_changed", "errno": True},
                       {"failureReason": "fd_changed", "nativeActionAllowed": True}):
            other = diagnostics.describe("ssh_workflow", "connection-channel-status", {**common, **change})
            self.assertEqual(clean["failureSignature"]["fingerprint"], other["failureSignature"]["fingerprint"])
            self.assertNotIn("private-marker", str(other))

    def test_rejected_channel_input_points_to_actual_route_regression(self):
        from agent_tools import mcp_server
        for action in ("connection-channel-prepare", "connection-channel-status", "connection-channel-ensure"):
            result = mcp_server._ssh_workflow_impl(action, host="archlinux", identity={})
            described = diagnostics.describe("ssh_workflow", action, result)
            self.assertIn("test_invalid_inputs_do_not_reach_provider",
                          described["failureSignature"]["causalRegression"])
            self.assertEqual("valid typed connection identity; no remote action was dispatched",
                             described["admissionGap"]["missingFact"])

    def test_exact_socket_refusal_points_to_existing_regression_without_auth_claim(self):
        result = {"state": "unknown", "socketState": "refused", "nestedState": "unknown",
                  "failurePhase": "socket_parser", "replayAllowed": False,
                  "launchAllowed": False, "nativeActionAllowed": False}
        described = diagnostics.describe("ssh_workflow", "connection-master-status", result)
        self.assertEqual("cached_socket_refused", described["failureSignature"]["basis"]["reason"])
        self.assertIn("test_exact_refusal_is_finite_cause_without_absence_authority",
                      described["failureSignature"]["causalRegression"])
        self.assertIn("fresh transport channel", described["admissionGap"]["missingFact"])
        self.assertIs(described["admissionGap"]["nativeActionAllowed"], False)
        for change in ({"socketState": "private-marker"}, {"nestedState": "ready"},
                       {"nativeActionAllowed": True}, {"failurePhase": "private-marker"}):
            other = diagnostics.describe("ssh_workflow", "connection-master-status", {**result, **change})
            self.assertEqual("unclassified", other["failureSignature"]["basis"]["reason"])
            self.assertIsNone(other["failureSignature"]["causalRegression"])

    def test_red_retained_task_and_encoding_failures_were_collapsed(self):
        common = {"state": "blocked", "phase": "absence"}
        trigger = diagnostics.describe("vm_workflow", "windows-cp117-c32-archive-preflight", {
            **common, "retainedGuard": "TASK_TRIGGER_NULL", "retainedPhase": "task",
            "receipt": "private-receipt-ignored",
        })
        encoding = diagnostics.describe("vm_workflow", "windows-cp117-c32-archive-preflight", {
            **common, "retainedGuard": "RESULT_UTF8_BOM", "retainedPhase": "result",
            "receipt": "other-private-receipt-ignored",
        })
        self.assertNotEqual(trigger["failureSignature"]["fingerprint"],
                            encoding["failureSignature"]["fingerprint"])
        self.assertEqual("TASK_TRIGGER_NULL", trigger["failureSignature"]["basis"]["retainedGuard"])
        self.assertEqual("RESULT_UTF8_BOM", encoding["failureSignature"]["basis"]["retainedGuard"])
        self.assertNotIn("receipt", trigger["failureSignature"]["basis"])
        self.assertIn("test_windows_trigger_guard", trigger["failureSignature"]["causalRegression"])
        self.assertIn("test_windows_result_decoder", encoding["failureSignature"]["causalRegression"])
        self.assertEqual({"tool": "vm_workflow", "action": "windows-cp117-c32-retained-parser", "inputs": {}},
                         trigger["admissionGap"]["readOnlyAction"])
        self.assertFalse(trigger["admissionGap"]["nativeActionAllowed"])

    def test_invalid_archive_diagnostics_are_ignored_and_do_not_change_fingerprint(self):
        common = {"state": "blocked", "phase": "absence"}
        clean = diagnostics.describe("vm_workflow", "windows-cp117-c32-archive-diagnose", common)
        hostile = diagnostics.describe("vm_workflow", "windows-cp117-c32-archive-diagnose", {
            **common, "retainedGuard": "private-path-secret", "retainedPhase": {"raw": "guest"},
            "hostFailure": "private-host", "rawLog": "do-not-classify",
        })
        self.assertEqual(clean["failureSignature"]["fingerprint"], hostile["failureSignature"]["fingerprint"])
        self.assertEqual({"retainedGuard": "unspecified", "retainedPhase": "unspecified", "hostFailure": "unspecified"},
                         {key: hostile["failureSignature"]["basis"][key]
                          for key in ("retainedGuard", "retainedPhase", "hostFailure")})
        self.assertIsNone(hostile["admissionGap"]["readOnlyAction"])

    def test_source_reservation_blockers_have_a_finite_fingerprint_basis(self):
        value = {"state": "observed", "blockers": [{"record": "c32", "phase": "absence"}]}
        described = diagnostics.describe("vm_workflow", "windows-cp117-source-campaign-reservation-diagnose", value)
        self.assertEqual([["c32", "absence"]], described["failureSignature"]["basis"]["sourceReservationBlockers"])
        self.assertIn("test_reservation_blockers", described["failureSignature"]["causalRegression"])
        self.assertIsNone(described["admissionGap"]["readOnlyAction"])

    def test_invalid_source_blocker_is_fail_closed_and_unclassified(self):
        common = {"state": "observed"}
        clean = diagnostics.describe("vm_workflow", "windows-cp117-source-campaign-reservation-diagnose", common)
        hostile = diagnostics.describe("vm_workflow", "windows-cp117-source-campaign-reservation-diagnose", {
            **common, "blockers": [{"record": "c32", "phase": "private-path"}], "guestOutput": "private",
        })
        self.assertEqual(clean["failureSignature"]["fingerprint"], hostile["failureSignature"]["fingerprint"])
        self.assertEqual([], hostile["failureSignature"]["basis"]["sourceReservationBlockers"])
        self.assertIsNone(hostile["failureSignature"]["causalRegression"])

    def test_android_endpoint_admission_reasons_map_to_their_exact_causal_regressions(self):
        cases = {
            "missing_local_intent": (
                "test_status_missing_local_intent_is_bounded_unknown_without_remote_observation",
                "durable Android endpoint admission intent for this correlation",
            ),
            "reverse_inventory_invalid": (
                "test_remote_reverse_inventory_rejects_duplicate_or_malformed_routes",
                "fresh bounded Android reverse-inventory observation",
            ),
        }
        for reason, (test_name, missing_fact) in cases.items():
            with self.subTest(reason=reason):
                described = diagnostics.describe("vm_workflow", "android-endpoint-admission-status", {
                    "state": "unknown", "reason": reason,
                    "correlationId": "private-correlation-must-not-affect-signature",
                    "receipt": "private-receipt-must-not-affect-signature",
                })
                self.assertIn(test_name, described["failureSignature"]["causalRegression"])
                self.assertEqual(missing_fact, described["admissionGap"]["missingFact"])
                self.assertNotIn("correlationId", described["failureSignature"]["basis"])
                self.assertNotIn("receipt", described["failureSignature"]["basis"])


if __name__ == "__main__":
    unittest.main()

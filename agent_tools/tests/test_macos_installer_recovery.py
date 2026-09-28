from __future__ import annotations

import unittest

from agent_tools import macos_installer_recovery as recovery


JOB = "d98286a2-1094-4459-8e8d-bc6a2d91a851"
CURRENT = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
LAUNCH = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def evidence(*, token=True, receipt="absent"):
    return {
        "jobId": JOB,
        "publicStatus": {"receiptId": JOB, "phase": "installing", "code": "OUTCOME_UNKNOWN",
                         "final": False, "installed": None},
        "protectedReceiptObservation": receipt,
        "bootSessionToken": ({"jobId": JOB, "launchBootSessionUuid": LAUNCH} if token else None),
        "currentBootSessionUuid": CURRENT,
    }


class MacInstallerRecoveryTest(unittest.TestCase):
    def test_legacy_unknown_is_preserved_without_replay_or_cancellation(self):
        result = recovery.diagnose(evidence(token=False))
        self.assertEqual(("unknown", "launch_boot_session_token_missing"),
                         (result["state"], result["reason"]))
        self.assertEqual("preserve-and-observe", result["productNextAction"])
        self.assertFalse(result["productReconciliationEligible"])
        self.assertFalse(result["nativeActionAllowed"])
        self.assertFalse(result["replayAllowed"])
        self.assertFalse(result["cancellationAllowed"])

    def test_prior_boot_is_only_a_product_revalidation_candidate(self):
        result = recovery.diagnose(evidence())
        self.assertEqual("unknown", result["state"])
        self.assertTrue(result["productReconciliationEligible"])
        self.assertEqual("caller-supplied-diagnostic-only", result["evidenceScope"])
        self.assertFalse(result["cancellationAllowed"])

    def test_same_boot_or_nonabsent_receipt_stays_unknown(self):
        same = evidence()
        same["bootSessionToken"]["launchBootSessionUuid"] = CURRENT
        self.assertEqual("same_boot_process_outcome_unknown", recovery.diagnose(same)["reason"])
        for observation in ("present", "unknown"):
            with self.subTest(observation=observation):
                result = recovery.diagnose(evidence(receipt=observation))
                self.assertFalse(result["productReconciliationEligible"])
                self.assertEqual("protected_receipt_not_authoritatively_absent", result["reason"])

    def test_malformed_receipt_observations_have_a_bounded_diagnostic_error(self):
        for observation in ([], {}, None, True, 123):
            with self.subTest(observation=observation), self.assertRaises(recovery.MacInstallerRecoveryError):
                recovery.diagnose(evidence(receipt=observation))

    def test_overbroad_mismatched_and_credential_bearing_inputs_are_rejected(self):
        invalid = []
        extra = evidence(); extra["password"] = "must-not-be-accepted"; invalid.append(extra)
        nested = evidence(); nested["bootSessionToken"]["credential"] = "secret"; invalid.append(nested)
        mismatch = evidence(); mismatch["bootSessionToken"]["jobId"] = "00000000-0000-4000-8000-000000000052"; invalid.append(mismatch)
        terminal = evidence(); terminal["publicStatus"]["final"] = True; invalid.append(terminal)
        for item in invalid:
            with self.subTest(item=item), self.assertRaises(recovery.MacInstallerRecoveryError):
                recovery.diagnose(item)


if __name__ == "__main__":
    unittest.main()

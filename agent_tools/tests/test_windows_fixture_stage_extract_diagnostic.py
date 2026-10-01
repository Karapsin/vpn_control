"""Causal regression for a lost CP117 extraction response.

The production extraction returned ``unknown`` after the durable dispatch
record was made.  Observing that record must never reserve or submit another
extraction.
"""
from __future__ import annotations

from pathlib import Path
import unittest
from unittest import mock

from agent_tools import windows_update_fixture_http_stage as http


CORR = "e848bed2-5bea-47bc-a85a-6cf17b1fcc6a"
RECORD = {"request": {"correlationId": CORR}}


class StageExtractDiagnosticTests(unittest.TestCase):
    def _observe(self, *, phase="receipt-present-unverified", binding="exact",
                 large_phase="placed"):
        root = Path.cwd()
        observed = {"state": "unknown", "correlationId": CORR, "binding": binding,
                    "phase": phase, "replayAllowed": False, "nativeActionAllowed": False}
        with (mock.patch.object(http, "_record", return_value=(root, RECORD, object(), object())),
              mock.patch.object(http.large_transfer, "read", return_value={"phase": large_phase}),
              mock.patch.object(http.stage, "diagnose", return_value=observed) as diagnose,
              mock.patch.object(http, "stage_extract", side_effect=AssertionError("must not extract")),
              mock.patch.object(http, "_large_advance", side_effect=AssertionError("must not reserve"))):
            result = http.workflow(root, "stage-extract-diagnostic", {"correlationId": CORR})
        return result, diagnose

    def test_observes_exact_durable_dispatch_without_replaying_extraction(self):
        result, diagnose = self._observe()
        self.assertEqual({"state": "diagnosed", "correlationId": CORR, "binding": "exact",
                          "phase": "receipt-present-unverified", "replayAllowed": False,
                          "nativeActionAllowed": False, "productAction": False}, result)
        diagnose.assert_called_once_with(Path.cwd(), {"correlationId": CORR})

    def test_requires_placed_transfer_before_reading_guest_dispatch(self):
        result, diagnose = self._observe(large_phase="downloaded")
        self.assertEqual("not-placed", result["phase"])
        self.assertEqual("exact", result["binding"])
        diagnose.assert_not_called()

    def test_poisoned_stage_observer_is_reduced_to_unverified_local_result(self):
        result, _ = self._observe(phase="secret-output")
        self.assertEqual({"binding": "unverified", "phase": "local-binding-invalid"},
                         {key: result[key] for key in ("binding", "phase")})

    def test_preserves_each_bounded_stage_observer_failure_phase(self):
        for phase in ("remote-layout-invalid", "guest-stage-probe-failed",
                      "dispatch-status-unknown", "result-read-failed", "receipt-invalid"):
            with self.subTest(phase=phase):
                result, _ = self._observe(phase=phase)
                self.assertEqual({"state": "diagnosed", "correlationId": CORR,
                                  "binding": "exact", "phase": phase,
                                  "replayAllowed": False, "nativeActionAllowed": False,
                                  "productAction": False}, result)

    def test_existing_observer_is_the_bounded_qga_status_and_receipt_reader(self):
        program = http.stage._REMOTE_DIAGNOSTIC
        self.assertIn("guest-exec-status", program)
        self.assertIn("out-truncated", program)
        self.assertIn("err-truncated", program)
        self.assertIn("result.json", program)
        self.assertIn("receipt-present-unverified", program)
        self.assertNotIn("Start-ScheduledTask", program)


if __name__ == "__main__":
    unittest.main()

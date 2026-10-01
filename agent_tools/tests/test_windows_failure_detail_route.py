"""Native response preserves bounded CP117 causes and causal regression links."""

import unittest
from unittest.mock import patch

from agent_tools import mcp_server, native_failure_evidence


class WindowsFailureDetailRouteTest(unittest.TestCase):
    def test_bounded_stage_cause_reaches_signature_and_receipt(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start(); self.addCleanup(guard.stop)
        result = {"tool": "vm_workflow", "state": "unknown", "phase": "guest-stage-absent",
                  "correlationId": "11111111-1111-4111-8111-111111111111", "ok": False,
                  "replayAllowed": False, "nativeActionAllowed": False}
        with patch.object(native_failure_evidence, "record_failure",
                          return_value={"evidenceId": "native-failure-test"}) as record:
            enriched = mcp_server._native_response("vm_workflow", "windows-fixture-stage-diagnostic",
                                                   result, {"correlationId": result["correlationId"]})
        self.assertEqual(enriched["failurePhase"], "fixture_stage_diagnostic")
        self.assertEqual(enriched["failureType"], "guest_stage_absent")
        self.assertFalse(enriched["failureSignature"]["regressionRequired"])
        self.assertEqual(enriched["failureSignature"]["causalRegression"],
                         enriched["regressionReference"])
        self.assertEqual(record.call_args.args[2]["failureType"], "guest_stage_absent")


if __name__ == "__main__":
    unittest.main()

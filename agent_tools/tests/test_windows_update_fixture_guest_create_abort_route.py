"""MCP boundary tests for the one-use CP117 guest-create abort action."""
import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_update_fixture_guest_create_abort as guest_create_abort


CORR = guest_create_abort._CORRELATION
REQUEST = {"correlationId": CORR}
FLAGS = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}


class GuestCreateAbortRouteTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start()
        self.addCleanup(guard.stop)

    def test_status_is_exact_read_only_and_has_a_bounded_phase(self):
        observed = {"state": "diagnosed", "correlationId": CORR, "phase": "ready",
                    "abortAllowed": True, **FLAGS}
        with patch.object(guest_create_abort, "status", return_value=observed) as status:
            result = mcp_server._vm_workflow_impl(
                "windows-update-fixture-guest-create-abort-status", REQUEST)
        status.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
        self.assertTrue(result["ok"])
        self.assertFalse(result["nativeActionAllowed"])
        self.assertEqual("causal-diagnostic", result["evidenceClass"])

        for poisoned in ({**observed, "phase": "private-path"},
                         {**observed, "abortAllowed": False},
                         {**observed, "secret": "private"}):
            with self.subTest(poisoned=poisoned), patch.object(
                    guest_create_abort, "status", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl(
                    "windows-update-fixture-guest-create-abort-status", REQUEST)
            self.assertFalse(rejected["ok"])
            self.assertNotIn("private", str(rejected))

    def test_status_projects_each_retired_evidence_failure_without_enabling_abort(self):
        retired_failures = (
            "retired-binding-invalid", "retired-shared-core-invalid", "retired-receipt-invalid",
            "retired-campaign-invalid", "retired-marker-invalid", "retired-guest-invalid",
            "retired-guest-leaf-present", "retired-guest-interpreter-present",
            "retired-guest-wrapper-unknown", "retired-guest-script-invalid",
        )
        for phase in retired_failures:
            observed = {"state": "diagnosed", "correlationId": CORR, "phase": phase,
                        "abortAllowed": False, **FLAGS}
            with self.subTest(phase=phase), patch.object(guest_create_abort, "status", return_value=observed):
                result = mcp_server._vm_workflow_impl(
                    "windows-update-fixture-guest-create-abort-status", REQUEST)
            self.assertTrue(result["ok"])
            self.assertFalse(result["abortAllowed"])

    def test_abort_accepts_only_terminal_receipt_and_exact_input(self):
        retired = {"state": "retired", "correlationId": CORR,
                   "cleanupReceiptSha256": "a" * 64, **FLAGS}
        with patch.object(guest_create_abort, "abort", return_value=retired) as abort:
            result = mcp_server._vm_workflow_impl("windows-update-fixture-guest-create-abort", REQUEST)
        abort.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
        self.assertTrue(result["ok"])
        self.assertEqual("native-campaign", result["evidenceClass"])

        for poisoned in ({**retired, "cleanupReceiptSha256": "private"},
                         {**retired, "nativeActionAllowed": True},
                         {**retired, "private": "secret"}):
            with self.subTest(poisoned=poisoned), patch.object(
                    guest_create_abort, "abort", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl("windows-update-fixture-guest-create-abort", REQUEST)
            self.assertFalse(rejected["ok"])
            self.assertNotIn("private", str(rejected))

        unknown = {"state": "unknown", "correlationId": CORR, **FLAGS}
        with patch.object(guest_create_abort, "abort", return_value=unknown):
            result = mcp_server._vm_workflow_impl("windows-update-fixture-guest-create-abort", REQUEST)
        self.assertFalse(result["ok"])
        self.assertEqual("unknown", result["state"])

        with patch.object(guest_create_abort, "abort", side_effect=AssertionError("unsafe dispatch")):
            for bad_request in ({}, {"correlationId": "00000000-0000-4000-8000-000000000000"},
                                {**REQUEST, "retry": False}, {"correlationId": 4}):
                with self.subTest(bad_request=bad_request):
                    rejected = mcp_server._vm_workflow_impl(
                        "windows-update-fixture-guest-create-abort", bad_request)
                    self.assertFalse(rejected["ok"])


if __name__ == "__main__":
    unittest.main()

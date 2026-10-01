"""Bounded MCP projection for the fixed guest-create-abort campaign successor."""
import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_cp117_guest_abort_successor as successor


NEW = "3b9cbad1-a536-4a53-bddf-d71f7dbd6694"
REQUEST = {"host": "archlinux", "oldLeaseId": successor._OLD,
           "newLeaseId": NEW, "sourceSha": successor._SOURCE,
           "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
           "baseMsiArtifactId": "sha256-" + "c" * 64,
           "targetMsiArtifactId": "sha256-" + "d" * 64}
FLAGS = {"replayAllowed": False, "nativeActionAllowed": False}


class GuestAbortSuccessorRouteTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start()
        self.addCleanup(guard.stop)

    def test_start_accepts_one_exact_request_and_finite_active_result(self):
        active = {"state": "active", "leaseId": NEW, **FLAGS}
        with patch.object(successor, "start", return_value=active) as start:
            result = mcp_server._vm_workflow_impl("windows-cp117-guest-abort-successor-start", REQUEST)
        start.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
        self.assertTrue(result["ok"])
        self.assertFalse(result["productAction"])
        for poisoned in ({**active, "replayAllowed": True},
                         {**active, "leaseId": successor._OLD},
                         {**active, "private": "secret"}):
            with self.subTest(poisoned=poisoned), patch.object(successor, "start", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl("windows-cp117-guest-abort-successor-start", REQUEST)
            self.assertFalse(rejected["ok"])
            self.assertNotIn("secret", str(rejected))
        with patch.object(successor, "start", side_effect=AssertionError("unsafe dispatch")):
            rejected = mcp_server._vm_workflow_impl(
                "windows-cp117-guest-abort-successor-start", {**REQUEST, "retry": False})
        self.assertFalse(rejected["ok"])

    def test_status_is_read_only_and_reconcile_and_resume_are_explicit(self):
        closing = {"state": "closing", "leaseId": NEW,
                   "nextAction": "inspect-close-progress", **FLAGS}
        with patch.object(successor, "status", return_value=closing) as status, \
             patch.object(successor, "reconcile", side_effect=AssertionError("no mutation")):
            result = mcp_server._vm_workflow_impl("windows-cp117-guest-abort-successor-status", REQUEST)
        status.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
        self.assertFalse(result["ok"])
        self.assertEqual("causal-diagnostic", result["evidenceClass"])

        active = {"state": "active", "leaseId": NEW, **FLAGS}
        with patch.object(successor, "reconcile", return_value=active) as reconcile:
            result = mcp_server._vm_workflow_impl("windows-cp117-guest-abort-successor-reconcile", REQUEST)
        reconcile.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
        self.assertTrue(result["ok"])

        with patch.object(successor, "resume_begin", return_value=active) as resume:
            result = mcp_server._vm_workflow_impl("windows-cp117-guest-abort-successor-resume-begin", REQUEST)
        resume.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
        self.assertTrue(result["ok"])

    def test_all_actions_reject_invalid_outputs_and_unapproved_inputs(self):
        active = {"state": "active", "leaseId": NEW, **FLAGS}
        actions = {
            "windows-cp117-guest-abort-successor-start": "start",
            "windows-cp117-guest-abort-successor-status": "status",
            "windows-cp117-guest-abort-successor-reconcile": "reconcile",
            "windows-cp117-guest-abort-successor-resume-begin": "resume_begin",
        }
        for action, method in actions.items():
            with self.subTest(action=action), patch.object(successor, method, return_value={**active, "secret": "private"}):
                result = mcp_server._vm_workflow_impl(action, REQUEST)
            self.assertFalse(result["ok"])
            self.assertNotIn("private", str(result))
        for bad_request in ({}, {**REQUEST, "oldLeaseId": "0" * 36},
                            {**REQUEST, "newLeaseId": successor._OLD},
                            {**REQUEST, "newLeaseId": NEW.upper()}):
            with self.subTest(bad_request=bad_request), patch.object(
                    successor, "status", side_effect=AssertionError("unsafe dispatch")):
                result = mcp_server._vm_workflow_impl(
                    "windows-cp117-guest-abort-successor-status", bad_request)
            self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()

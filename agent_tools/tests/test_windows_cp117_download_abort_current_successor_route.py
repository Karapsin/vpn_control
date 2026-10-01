"""MCP boundary for the isolated current download-abort campaign handoff."""
import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_cp117_download_abort_current_successor as successor


NEW = "3b9cbad1-a536-4a53-bddf-d71f7dbd6694"
REQUEST = {"host": "archlinux", "oldLeaseId": successor._OLD, "newLeaseId": NEW,
           "sourceSha": successor._SOURCE, "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
           "baseMsiArtifactId": "sha256-" + "c" * 64, "targetMsiArtifactId": "sha256-" + "d" * 64}
FLAGS = {"replayAllowed": False, "nativeActionAllowed": False}
PREFIX = "windows-cp117-download-abort-current-successor"


class CurrentDownloadAbortSuccessorRouteTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start()
        self.addCleanup(guard.stop)

    def test_start_requires_exact_current_handoff_and_active_result(self):
        active = {"state": "active", "leaseId": NEW, **FLAGS}
        with patch.object(successor, "start", return_value=active) as start:
            result = mcp_server._vm_workflow_impl(PREFIX + "-start", REQUEST)
        start.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
        self.assertTrue(result["ok"])
        self.assertEqual("native-campaign", result["evidenceClass"])
        for poisoned in ({**active, "replayAllowed": True}, {**active, "leaseId": successor._OLD},
                         {**active, "secret": "private"}):
            with self.subTest(poisoned=poisoned), patch.object(successor, "start", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl(PREFIX + "-start", REQUEST)
            self.assertFalse(rejected["ok"])
            self.assertNotIn("private", str(rejected))

    def test_status_is_read_only_and_recovery_operations_are_explicit(self):
        closing = {"state": "closing", "leaseId": NEW,
                   "nextAction": "inspect-close-progress", **FLAGS}
        with patch.object(successor, "status", return_value=closing) as status, \
             patch.object(successor, "reconcile", side_effect=AssertionError("no mutation")):
            result = mcp_server._vm_workflow_impl(PREFIX + "-status", REQUEST)
        status.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
        self.assertFalse(result["ok"])
        self.assertEqual("causal-diagnostic", result["evidenceClass"])
        resume_close_status = {"state": "closing", "leaseId": NEW,
                               "nextAction": "resume-close", **FLAGS}
        with patch.object(successor, "status", return_value=resume_close_status):
            result = mcp_server._vm_workflow_impl(PREFIX + "-status", REQUEST)
        self.assertFalse(result["ok"])
        self.assertEqual("resume-close", result["nextAction"])
        active = {"state": "active", "leaseId": NEW, **FLAGS}
        with patch.object(successor, "reconcile", return_value=active) as reconcile:
            result = mcp_server._vm_workflow_impl(PREFIX + "-reconcile", REQUEST)
        reconcile.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
        self.assertTrue(result["ok"])
        closed = {"state": "closed", "leaseId": NEW, **FLAGS}
        with patch.object(successor, "resume_close", return_value=closed) as resume_close:
            result = mcp_server._vm_workflow_impl(PREFIX + "-resume-close", REQUEST)
        resume_close.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
        self.assertTrue(result["ok"])
        with patch.object(successor, "resume_begin", return_value=active) as resume:
            result = mcp_server._vm_workflow_impl(PREFIX + "-resume-begin", REQUEST)
        resume.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
        self.assertTrue(result["ok"])

    def test_rejects_unapproved_inputs_and_nonfinite_results(self):
        active = {"state": "active", "leaseId": NEW, **FLAGS}
        for action, method in ((PREFIX + "-start", "start"), (PREFIX + "-status", "status"),
                               (PREFIX + "-reconcile", "reconcile"), (PREFIX + "-resume-close", "resume_close"),
                               (PREFIX + "-resume-begin", "resume_begin")):
            with self.subTest(action=action), patch.object(successor, method, return_value={**active, "private": "secret"}):
                result = mcp_server._vm_workflow_impl(action, REQUEST)
            self.assertFalse(result["ok"])
            self.assertNotIn("private", str(result))
        with patch.object(successor, "start", return_value={"state": "closed", "leaseId": NEW, **FLAGS}):
            rejected = mcp_server._vm_workflow_impl(PREFIX + "-start", REQUEST)
        self.assertFalse(rejected["ok"])
        with patch.object(successor, "status", side_effect=AssertionError("unsafe dispatch")):
            for request in ({}, {**REQUEST, "oldLeaseId": "0" * 36},
                            {**REQUEST, "sourceSha": "0" * 40}, {**REQUEST, "retry": False}):
                with self.subTest(request=request):
                    rejected = mcp_server._vm_workflow_impl(PREFIX + "-status", request)
                self.assertFalse(rejected["ok"])


if __name__ == "__main__":
    unittest.main()

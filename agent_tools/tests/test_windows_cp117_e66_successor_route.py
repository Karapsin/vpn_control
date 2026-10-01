"""Bounded MCP projection for the one retired-e66 campaign successor."""
import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_cp117_e66_successor as successor


NEW = "3b9cbad1-a536-4a53-bddf-d71f7dbd6694"
REQUEST = {"host": "archlinux", "oldLeaseId": successor._OLD,
           "newLeaseId": NEW, "sourceSha": "a" * 40,
           "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
           "baseMsiArtifactId": "sha256-" + "c" * 64,
           "targetMsiArtifactId": "sha256-" + "d" * 64}
FLAGS = {"replayAllowed": False, "nativeActionAllowed": False}


class E66SuccessorRouteTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start(); self.addCleanup(guard.stop)

    def test_start_exact_request_and_finite_projection(self):
        active = {"state": "active", "leaseId": NEW, **FLAGS}
        with patch.object(successor, "start", return_value=active) as start:
            result = mcp_server._vm_workflow_impl("windows-cp117-e66-successor-start", REQUEST)
        start.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
        self.assertTrue(result["ok"])
        self.assertEqual("active", result["state"])
        self.assertFalse(result["productAction"])
        for poisoned in ({**active, "replayAllowed": True},
                         {**active, "secret": "private"},
                         {**active, "leaseId": successor._OLD}):
            with patch.object(successor, "start", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl("windows-cp117-e66-successor-start", REQUEST)
            self.assertFalse(rejected["ok"])
            self.assertNotIn("private", str(rejected))
        with patch.object(successor, "start", side_effect=AssertionError("unsafe call")):
            self.assertFalse(mcp_server._vm_workflow_impl(
                "windows-cp117-e66-successor-start", {**REQUEST, "command": "replay"})["ok"])

    def test_status_partial_is_read_only_and_reconcile_remains_explicit(self):
        partial = {"state": "closing", "leaseId": NEW,
                   "nextAction": "inspect-close-progress", **FLAGS}
        with patch.object(successor, "status", return_value=partial) as status, \
             patch.object(successor, "reconcile", side_effect=AssertionError("no transition")):
            result = mcp_server._vm_workflow_impl("windows-cp117-e66-successor-status", REQUEST)
        status.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
        self.assertEqual("closing", result["state"])
        self.assertFalse(result["ok"])
        self.assertEqual("causal-diagnostic", result["evidenceClass"])
        with patch.object(successor, "reconcile", return_value={"state": "active", "leaseId": NEW, **FLAGS}) as reconcile:
            resumed = mcp_server._vm_workflow_impl("windows-cp117-e66-successor-reconcile", REQUEST)
        reconcile.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
        self.assertTrue(resumed["ok"])

    def test_resume_begin_is_a_separate_exact_one_shot_action(self):
        active = {"state": "active", "leaseId": NEW, **FLAGS}
        with patch.object(successor, "resume_begin", return_value=active) as resume:
            result = mcp_server._vm_workflow_impl("windows-cp117-e66-successor-resume-begin", REQUEST)
        resume.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST)
        self.assertTrue(result["ok"])
        with patch.object(successor, "resume_begin", side_effect=AssertionError("unsafe call")):
            rejected = mcp_server._vm_workflow_impl(
                "windows-cp117-e66-successor-resume-begin", {**REQUEST, "replay": True})
        self.assertFalse(rejected["ok"])


if __name__ == "__main__":
    unittest.main()

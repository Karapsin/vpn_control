"""MCP boundaries for exact CP117 campaign continuation and status."""

import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_cp117_campaign_rebase as rebase
from agent_tools import windows_cp117_campaign_status as campaign_status


LEASE = "22222222-2222-4222-8222-222222222222"
OLD = "c32cb108-4d48-407e-9153-40774559ba50"


class WindowsCampaignRoutesTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start(); self.addCleanup(guard.stop)

    def test_rebase_exact_request_and_projection(self):
        request = {"host": "archlinux", "leaseId": LEASE, "previousLeaseId": OLD,
                   "sourceSha": "a" * 40, "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
                   "baseMsiArtifactId": "sha256-" + "c" * 64,
                   "targetMsiArtifactId": "sha256-" + "d" * 64}
        active = {"state": "active", "leaseId": LEASE, "previousLeaseId": OLD,
                  "baseTerminalReceiptSha256": "e" * 64, "replayAllowed": False}
        with patch.object(rebase, "start", return_value=active) as start:
            result = mcp_server._vm_workflow_impl("windows-cp117-campaign-rebase", request)
        start.assert_called_once_with(mcp_server.REPO_ROOT, request)
        self.assertTrue(result["ok"])
        self.assertFalse(result["nativeActionAllowed"])
        for poisoned in ({**active, "replayAllowed": True}, {**active, "path": "secret"}):
            with patch.object(rebase, "start", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl("windows-cp117-campaign-rebase", request)
            self.assertFalse(rejected["ok"])
            self.assertNotIn("secret", str(rejected))
        with patch.object(rebase, "start", side_effect=AssertionError("unsafe dispatch")):
            self.assertFalse(mcp_server._vm_workflow_impl(
                "windows-cp117-campaign-rebase", {**request, "command": "replay"})["ok"])

    def test_status_exact_host_and_bounded_projection(self):
        observed = {"state": "active", "nextAction": "inspect-active-campaign",
                    "leaseId": LEASE, "sourceSha": "a" * 40,
                    "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
                    "baseMsiArtifactId": "sha256-" + "c" * 64,
                    "targetMsiArtifactId": "sha256-" + "d" * 64,
                    "guestGeneration": {"socketPath": "/private/qga.sock",
                                        "qemuPid": 12, "startTicks": 34},
                    "role": None, "replayAllowed": False,
                    "nativeActionAllowed": False}
        with patch.object(campaign_status, "status", return_value=observed) as status:
            result = mcp_server._vm_workflow_impl("windows-cp117-campaign-status",
                                                  {"host": "archlinux"})
        status.assert_called_once_with(mcp_server.REPO_ROOT, {"host": "archlinux"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["campaignNextAction"], "inspect-active-campaign")
        self.assertFalse(result["nativeActionAllowed"])
        for poisoned in ({**observed, "nativeActionAllowed": True},
                         {**observed, "secret": "private"}):
            with patch.object(campaign_status, "status", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl("windows-cp117-campaign-status",
                                                        {"host": "archlinux"})
            self.assertFalse(rejected["ok"])
            self.assertNotIn("private", str(rejected))
        for role in ("owner-network", "network-probe"):
            with self.subTest(role=role), patch.object(campaign_status, "status",
                                                       return_value={**observed, "role": role}):
                role_result = mcp_server._vm_workflow_impl("windows-cp117-campaign-status",
                                                           {"host": "archlinux"})
            self.assertTrue(role_result["ok"])
        with patch.object(campaign_status, "status", return_value={
                "state": "unknown", "nextAction": "inspect-prerequisites",
                "replayAllowed": False, "nativeActionAllowed": False}):
            unknown = mcp_server._vm_workflow_impl("windows-cp117-campaign-status",
                                                   {"host": "archlinux"})
        self.assertFalse(unknown["ok"])

    def test_campaign_diagnostic_bounded_phase(self):
        observed = {"state": "unknown", "phase": "old-history",
                    "replayAllowed": False, "nativeActionAllowed": False}
        with patch.object(campaign_status, "diagnose", return_value=observed):
            result = mcp_server._vm_workflow_impl("windows-cp117-campaign-diagnostic",
                                                  {"host": "archlinux"})
        self.assertEqual(result["phase"], "old-history")
        for poisoned in ({**observed, "phase": "private"},
                         {**observed, "nativeActionAllowed": True}):
            with patch.object(campaign_status, "diagnose", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl("windows-cp117-campaign-diagnostic",
                                                        {"host": "archlinux"})
            self.assertEqual(rejected["phase"], "projection")
            self.assertFalse(rejected["nativeActionAllowed"])


if __name__ == "__main__":
    unittest.main()

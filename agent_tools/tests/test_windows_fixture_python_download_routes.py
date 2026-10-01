"""MCP boundaries for the CP117 Python download and source observations."""
import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_fixture_python_download_preflight as download
from agent_tools import windows_fixture_python_host_source as source
from agent_tools import windows_update_fixture_server as server


REQUEST = {"host": "archlinux", "leaseId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
           "stageCorrelationId": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
           "serverCorrelationId": "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "sourceSha": "d" * 40,
           "fixtureReceiptArtifactId": "sha256-" + "e" * 64, "baseMsiArtifactId": "sha256-" + "f" * 64,
           "targetMsiArtifactId": "sha256-" + "1" * 64}
IDS = {key: REQUEST[key] for key in ("leaseId", "stageCorrelationId", "serverCorrelationId")}


class PythonDownloadRoutesTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start(); self.addCleanup(guard.stop)

    def test_download_preflight_projects_only_bounded_endpoint(self):
        observed = {"state": "observed", **IDS, "candidateCount": 0, "serverReady": False,
                    "installerSha256": download._SHA256, "classification": "reachable", "phase": "reachable", "tlsSha256": "a" * 64,
                    "statusCode": 200, "contentLength": 29_452_944}
        with patch.object(download, "preflight", return_value=observed):
            result = mcp_server._vm_workflow_impl("windows-fixture-python-download-preflight", REQUEST)
        self.assertTrue(result["ok"]); self.assertFalse(result["nativeActionAllowed"])
        for poisoned in ({**observed, "path": "secret"}, {**observed, "contentLength": -1}):
            with patch.object(download, "preflight", return_value=poisoned):
                result = mcp_server._vm_workflow_impl("windows-fixture-python-download-preflight", REQUEST)
        self.assertFalse(result["ok"]); self.assertNotIn("secret", str(result))

    def test_download_phase_survives_read_only_projection(self):
        observed = {"state": "observed", **IDS, "candidateCount": 0, "serverReady": False,
                    "installerSha256": download._SHA256, "classification": "unknown", "phase": "network-timeout",
                    "tlsSha256": "unknown", "statusCode": "unknown", "contentLength": "unknown"}
        with patch.object(download, "preflight", return_value=observed):
            result = mcp_server._vm_workflow_impl("windows-fixture-python-download-preflight", REQUEST)
        self.assertTrue(result["ok"])
        self.assertEqual(result["phase"], "network-timeout")

    def test_download_preflight_rejects_malformed_or_extra_before_dispatch(self):
        with patch.object(download, "preflight", side_effect=AssertionError("unsafe dispatch")):
            for value in ({}, {**REQUEST, "command": "id"}, {**REQUEST, "sourceSha": "bad"}):
                self.assertFalse(mcp_server._vm_workflow_impl("windows-fixture-python-download-preflight", value)["ok"])

    def test_host_source_requires_campaign_admission_and_redacts_source(self):
        with patch.object(server, "_admit_campaign") as admit, patch.object(source, "observe", return_value={
                "state": "present", "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}) as observe:
            result = mcp_server._vm_workflow_impl("windows-fixture-python-host-source-observe", REQUEST)
        self.assertTrue(result["ok"]); admit.assert_called_once_with(mcp_server.REPO_ROOT, REQUEST, require_credentials=True)
        observe.assert_called_once_with(mcp_server.REPO_ROOT, {"host": "archlinux", "timeoutSeconds": 30})
        with patch.object(server, "_admit_campaign", side_effect=ValueError), patch.object(source, "observe", side_effect=AssertionError("unsafe")):
            self.assertFalse(mcp_server._vm_workflow_impl("windows-fixture-python-host-source-observe", REQUEST)["ok"])
        with patch.object(server, "_admit_campaign") as admit, patch.object(source, "observe", return_value={"state": "present", "path": "secret"}):
            result = mcp_server._vm_workflow_impl("windows-fixture-python-host-source-observe", REQUEST)
        self.assertFalse(result["ok"]); self.assertNotIn("secret", str(result)); admit.assert_called_once()
        self.assertFalse(mcp_server._vm_workflow_impl("windows-fixture-python-host-source-observe", {**REQUEST, "x": 1})["ok"])

    def test_host_source_absence_is_successful_read_only_observation(self):
        observed = {"state": "absent-or-mismatch", "replayAllowed": False,
                    "nativeActionAllowed": False, "productAction": False}
        with patch.object(server, "_admit_campaign"), patch.object(source, "observe", return_value=observed):
            result = mcp_server._vm_workflow_impl("windows-fixture-python-host-source-observe", REQUEST)
        self.assertTrue(result["ok"])
        self.assertEqual(result["state"], "absent-or-mismatch")
        self.assertFalse(result["nativeActionAllowed"])


if __name__ == "__main__":
    unittest.main()

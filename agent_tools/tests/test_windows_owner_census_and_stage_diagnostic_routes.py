"""MCP boundaries for read-only CP117 owner and uncertain stage observations."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_tools import mcp_server, windows_msi_owner_census as census
from agent_tools import windows_msi_owner_diagnostic as owner_diagnostic
from agent_tools import windows_msi_owner_liveness as owner_liveness
from agent_tools import windows_update_fixture_stage as stage
from agent_tools import windows_update_fixture_stage_recovery as stage_recovery


CORRELATION = "11111111-1111-4111-8111-111111111111"


class WindowsObservationRoutesTest(unittest.TestCase):
    def setUp(self):
        source_guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        source_guard.start(); self.addCleanup(source_guard.stop)

    def test_owner_census_exact_host_and_bounded_identity(self):
        observed = {"state": "observed", "sourceSha": "a" * 40,
                    "controllerId": CORRELATION, "installedCliSha256": "b" * 64,
                    "parentPid": 123, "parentStartedAtUtc": "2026-09-30T03:16:29Z",
                    "childPid": 456, "childStartedAtUtc": "2026-09-30T03:16:30Z",
                    "runtimeRunning": False, "replayAllowed": False,
                    "nativeActionAllowed": False}
        with patch.object(census, "workflow", return_value=observed) as workflow:
            result = mcp_server._vm_workflow_impl("windows-msi-owner-census", {"host": "archlinux"})
        workflow.assert_called_once_with(mcp_server.REPO_ROOT, {"host": "archlinux"})
        self.assertTrue(result["ok"])
        self.assertFalse(result["nativeActionAllowed"])
        self.assertFalse(result["productAction"])
        for poisoned in ({**observed, "path": "private"},
                         {**observed, "runtimeRunning": True},
                         {**observed, "installedCliSha256": "bad"}):
            with self.subTest(poisoned=poisoned), patch.object(census, "workflow", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl("windows-msi-owner-census", {"host": "archlinux"})
            self.assertFalse(rejected["ok"])
            self.assertNotIn("private", str(rejected))
        with patch.object(census, "workflow", side_effect=AssertionError("unsafe dispatch")):
            self.assertFalse(mcp_server._vm_workflow_impl(
                "windows-msi-owner-census", {"host": "archlinux", "pid": 123})["ok"])

    def test_owner_census_preflight_is_fixed(self):
        with patch.object(census, "preflight", return_value={"state": "passed",
                                                             "checks": ["ps5-parse", "gzip"]}):
            result = mcp_server._vm_workflow_impl("windows-msi-owner-census-preflight",
                                                  {"host": "archlinux"})
        self.assertTrue(result["ok"])
        self.assertFalse(result["productAction"])

    def test_stage_diagnostic_is_unknown_and_nonreplayable(self):
        request = {"correlationId": CORRELATION}
        observed = {"state": "unknown", "correlationId": CORRELATION,
                    "binding": "exact", "phase": "remote-stage-partial",
                    "replayAllowed": False, "nativeActionAllowed": False}
        with patch.object(stage, "diagnose", return_value=observed) as diagnose:
            result = mcp_server._vm_workflow_impl("windows-fixture-stage-diagnostic", request)
        diagnose.assert_called_once_with(mcp_server.REPO_ROOT, request)
        self.assertTrue(result["ok"])
        self.assertEqual(result["state"], "unknown")
        self.assertFalse(result["nativeActionAllowed"])
        self.assertFalse(result["productAction"])
        for poisoned in ({**observed, "path": "private"},
                         {**observed, "phase": "private"},
                         {**observed, "binding": "mismatch"},
                         {**observed, "phase": "local-intent", "binding": "exact"},
                         {**observed, "replayAllowed": True}):
            with self.subTest(poisoned=poisoned), patch.object(stage, "diagnose", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl("windows-fixture-stage-diagnostic", request)
            self.assertEqual(rejected["phase"], "qga-protocol")
            self.assertNotIn("private", str(rejected))

    def test_cli_accepts_fixed_stage_diagnostic(self):
        request = {"correlationId": CORRELATION}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "request.json"
            path.write_text(json.dumps(request))
            with patch.object(mcp_server, "vm_workflow", return_value={"tool": "vm_workflow", "ok": True}) as route, \
                    contextlib.redirect_stdout(io.StringIO()):
                code = mcp_server.main(["vm-workflow", "windows-fixture-stage-diagnostic",
                                        "--inputs-file", str(path)])
        self.assertEqual(code, 0)
        route.assert_called_once_with("windows-fixture-stage-diagnostic", request)

    def test_stage_diagnostic_preserves_bounded_local_causes(self):
        request = {"correlationId": CORRELATION}
        for phase, binding in (("local-intent", "unverified"),
                               ("local-artifact", "unverified"),
                               ("descriptor", "mismatch")):
            observed = {"state": "unknown", "correlationId": CORRELATION,
                        "binding": binding, "phase": phase,
                        "replayAllowed": False, "nativeActionAllowed": False}
            with self.subTest(phase=phase), patch.object(stage, "diagnose", return_value=observed):
                result = mcp_server._vm_workflow_impl("windows-fixture-stage-diagnostic", request)
            self.assertEqual(result["phase"], phase)
            self.assertEqual(result["binding"], binding)
            self.assertFalse(result["nativeActionAllowed"])

    def test_owner_diagnostic_bounded_cause(self):
        observed = {"state": "diagnosed", "phase": "state-directory",
                    "detail": "foreign-allow-ace-other",
                    "sourceSha": "a" * 40,
                    "correlationId": owner_diagnostic._CORRELATION,
                    "replayAllowed": False, "nativeActionAllowed": False}
        with patch.object(owner_diagnostic, "diagnose", return_value=observed):
            result = mcp_server._vm_workflow_impl("windows-msi-owner-diagnostic",
                                                  {"host": "archlinux"})
        self.assertEqual(result["phase"], "state-directory")
        self.assertEqual(result["detail"], "foreign-allow-ace-other")
        self.assertFalse(result["nativeActionAllowed"])
        for poisoned in ({**observed, "phase": "private"},
                         {**observed, "detail": "private"},
                         {**observed, "raw": "secret"},
                         {**observed, "nativeActionAllowed": True}):
            with patch.object(owner_diagnostic, "diagnose", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl("windows-msi-owner-diagnostic",
                                                        {"host": "archlinux"})
            self.assertFalse(rejected["ok"])
            self.assertNotIn("secret", str(rejected))

    def test_owner_diagnostic_preserves_state_file_detail(self):
        observed = {"state": "diagnosed", "phase": "state-files",
                    "detail": "endpoint-foreign-allow-ace-other", "sourceSha": "a" * 40,
                    "correlationId": owner_diagnostic._CORRELATION,
                    "replayAllowed": False, "nativeActionAllowed": False}
        with patch.object(owner_diagnostic, "diagnose", return_value=observed):
            result = mcp_server._vm_workflow_impl("windows-msi-owner-diagnostic",
                                                  {"host": "archlinux"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["detail"], "endpoint-foreign-allow-ace-other")
        with patch.object(owner_diagnostic, "diagnose", return_value={**observed,
                                                                        "detail": "private"}):
            rejected = mcp_server._vm_workflow_impl("windows-msi-owner-diagnostic",
                                                    {"host": "archlinux"})
        self.assertFalse(rejected["ok"])

    def test_owner_diagnostic_preserves_endpoint_process_proof(self):
        observed = {"state": "diagnosed", "phase": "endpoint-unavailable",
                    "detail": "endpoint-absent-process-exact", "sourceSha": "a" * 40,
                    "correlationId": owner_diagnostic._CORRELATION,
                    "replayAllowed": False, "nativeActionAllowed": False}
        with patch.object(owner_diagnostic, "diagnose", return_value=observed):
            result = mcp_server._vm_workflow_impl("windows-msi-owner-diagnostic",
                                                  {"host": "archlinux"})
        self.assertEqual(result["detail"], "endpoint-absent-process-exact")
        with patch.object(owner_diagnostic, "diagnose", return_value={**observed,
                                                                        "detail": "secret"}):
            rejected = mcp_server._vm_workflow_impl("windows-msi-owner-diagnostic",
                                                    {"host": "archlinux"})
        self.assertFalse(rejected["ok"])

    def test_owner_liveness_requires_complete_absence(self):
        observed = {"state": "absent", "sourceSha": "a" * 40,
                    "correlationId": owner_liveness._CORRELATION,
                    "ownerProcesses": "none", "installerProcesses": "none",
                    "consentProcesses": "none", "runtimeProcesses": "none",
                    "stateLeaves": "none", "runtimeOff": True,
                    "replayAllowed": False, "nativeActionAllowed": False}
        with patch.object(owner_liveness, "observe", return_value=observed) as observe:
            result = mcp_server._vm_workflow_impl("windows-msi-owner-liveness",
                                                  {"host": "archlinux"})
        observe.assert_called_once_with(mcp_server.REPO_ROOT, {"host": "archlinux"})
        self.assertTrue(result["ok"])
        self.assertFalse(result["nativeActionAllowed"])
        for poisoned in ({**observed, "stateLeaves": "one"},
                         {**observed, "ownerProcesses": "one"},
                         {**observed, "path": "secret"}):
            with patch.object(owner_liveness, "observe", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl("windows-msi-owner-liveness",
                                                        {"host": "archlinux"})
            self.assertFalse(rejected["ok"])
            self.assertNotIn("secret", str(rejected))

    def test_exact_stage_recovery_route_is_bounded(self):
        observed = {"state": "recovered", "correlationId": stage_recovery._CORRELATION,
                    "cleanupReceiptSha256": "b" * 64, "replayAllowed": False}
        with patch.object(stage_recovery, "recover", return_value=observed) as recover:
            result = mcp_server._vm_workflow_impl("windows-fixture-stage-recover-7f27",
                                                  {"host": "archlinux"})
        recover.assert_called_once_with(mcp_server.REPO_ROOT, {"host": "archlinux"})
        self.assertTrue(result["ok"])
        self.assertFalse(result["nativeActionAllowed"])
        for poisoned in ({**observed, "path": "secret"},
                         {**observed, "replayAllowed": True},
                         {**observed, "cleanupReceiptSha256": "bad"}):
            with patch.object(stage_recovery, "recover", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl("windows-fixture-stage-recover-7f27",
                                                        {"host": "archlinux"})
            self.assertFalse(rejected["ok"])
            self.assertNotIn("secret", str(rejected))
        with patch.object(stage_recovery, "recover", side_effect=AssertionError("unsafe dispatch")):
            self.assertFalse(mcp_server._vm_workflow_impl("windows-fixture-stage-recover-7f27",
                                                         {"host": "archlinux", "correlationId": stage_recovery._CORRELATION})["ok"])

    def test_exact_stage_recovery_diagnostic_route_is_bounded(self):
        observed = {"state": "diagnosed", "correlationId": stage_recovery._CORRELATION,
                    "phase": "remote-binding-only", "recoveryAllowed": True,
                    "nativeActionAllowed": False}
        with patch.object(stage_recovery, "diagnose", return_value=observed):
            result = mcp_server._vm_workflow_impl("windows-fixture-stage-recover-7f27-diagnostic",
                                                  {"host": "archlinux"})
        self.assertEqual(result["phase"], "remote-binding-only")
        self.assertFalse(result["nativeActionAllowed"])
        for poisoned in ({**observed, "phase": "private"},
                         {**observed, "recoveryAllowed": False},
                         {**observed, "path": "secret"}):
            with patch.object(stage_recovery, "diagnose", return_value=poisoned):
                rejected = mcp_server._vm_workflow_impl("windows-fixture-stage-recover-7f27-diagnostic",
                                                        {"host": "archlinux"})
            self.assertEqual(rejected["phase"], "remote-stage")
            self.assertFalse(rejected["recoveryAllowed"])
            self.assertNotIn("secret", str(rejected))
        campaign = {"state": "diagnosed", "correlationId": stage_recovery._CORRELATION,
                    "phase": "campaign", "campaignDetail": "active-role-required",
                    "recoveryAllowed": False, "nativeActionAllowed": False}
        with patch.object(stage_recovery, "diagnose", return_value=campaign):
            result = mcp_server._vm_workflow_impl("windows-fixture-stage-recover-7f27-diagnostic",
                                                  {"host": "archlinux"})
        self.assertEqual(result["campaignDetail"], "active-role-required")
        with patch.object(stage_recovery, "diagnose", return_value={**campaign,
                                                                      "campaignDetail": "secret"}):
            rejected = mcp_server._vm_workflow_impl("windows-fixture-stage-recover-7f27-diagnostic",
                                                    {"host": "archlinux"})
        self.assertEqual(rejected["phase"], "remote-stage")
        self.assertNotIn("secret", str(rejected))


if __name__ == "__main__":
    unittest.main()

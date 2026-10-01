"""MCP projection for the source-bound CP117 fixture HTTP path."""

import unittest
from unittest.mock import patch

from agent_tools import mcp_server
from agent_tools import windows_update_fixture_http_stage as transfer


CORR = "22222222-2222-4222-8222-222222222222"
REQUEST = {"host": "archlinux", "correlationId": CORR, "sourceSha": "a" * 40,
           "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
           "baseMsiArtifactId": "sha256-" + "c" * 64,
           "targetMsiArtifactId": "sha256-" + "d" * 64}


class WindowsUpdateFixtureHttpStageRouteTest(unittest.TestCase):
    def setUp(self):
        guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        guard.start()
        self.addCleanup(guard.stop)

    def test_prepare_exact_input_and_private_projection(self):
        observed = {"state": "prepared", "correlationId": CORR,
                    "bundleSha256": "e" * 64, "bundleSize": 131072,
                    "replayAllowed": False, "nativeActionAllowed": False,
                    "productAction": False}
        with patch.object(transfer, "workflow", return_value=observed) as call:
            result = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                                                  {"phase": "prepare", **REQUEST})
        call.assert_called_once_with(mcp_server.REPO_ROOT, "prepare", REQUEST)
        self.assertTrue(result["ok"])
        self.assertFalse(result["nativeActionAllowed"])
        with patch.object(transfer, "workflow", side_effect=AssertionError("unsafe dispatch")):
            invalid = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                {"phase": "prepare", **REQUEST, "path": "/private/fixture"})
        self.assertFalse(invalid["ok"])

    def test_prepare_diagnostic_is_read_only_and_bounded(self):
        observed = {"state": "diagnosed", "correlationId": CORR,
                    "phase": "source-unadmitted", "preEffect": True,
                    "replayAllowed": False, "nativeActionAllowed": False,
                    "productAction": False}
        with patch.object(transfer, "workflow", return_value=observed) as call:
            result = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                                                  {"phase": "prepare-diagnostic", **REQUEST})
        call.assert_called_once_with(mcp_server.REPO_ROOT, "prepare-diagnostic", REQUEST)
        self.assertTrue(result["ok"])
        self.assertEqual(result["phase"], "source-unadmitted")
        for poison in ({**observed, "preEffect": False},
                       {**observed, "phase": "private-path"},
                       {**observed, "private": "secret"}):
            with patch.object(transfer, "workflow", return_value=poison):
                rejected = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                    {"phase": "prepare-diagnostic", **REQUEST})
            self.assertFalse(rejected["ok"])
            self.assertNotIn("secret", str(rejected))
        with patch.object(transfer, "workflow", return_value={
                **observed, "phase": "bundle-unbuildable"}) as call:
            bundle = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                {"phase": "bundle-diagnostic", **REQUEST})
        call.assert_called_once_with(mcp_server.REPO_ROOT, "bundle-diagnostic", REQUEST)
        self.assertTrue(bundle["ok"])
        with patch.object(transfer, "workflow", return_value={
                **observed, "phase": "ready-to-reserve"}):
            invalid_bundle = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                {"phase": "bundle-diagnostic", **REQUEST})
        self.assertFalse(invalid_bundle["ok"])
        with patch.object(transfer, "workflow", return_value={
                **observed, "phase": "prior-stage-needs-confirmation"}) as call:
            reserve = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                {"phase": "reserve-diagnostic", **REQUEST})
        call.assert_called_once_with(mcp_server.REPO_ROOT, "reserve-diagnostic", REQUEST)
        self.assertTrue(reserve["ok"])
        with patch.object(transfer, "workflow", return_value={
                **observed, "phase": "bundle-ready"}):
            invalid_reserve = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                {"phase": "reserve-diagnostic", **REQUEST})
        self.assertFalse(invalid_reserve["ok"])
        with patch.object(transfer, "workflow", return_value={
                **observed, "phase": "remote-status-mismatch"}) as call:
            prior = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                {"phase": "prior-stage-confirmation", **REQUEST})
        call.assert_called_once_with(mcp_server.REPO_ROOT, "prior-stage-confirmation", REQUEST)
        self.assertTrue(prior["ok"])
        with patch.object(transfer, "workflow", return_value={
                **observed, "phase": "bundle-ready"}):
            invalid_prior = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                {"phase": "prior-stage-confirmation", **REQUEST})
        self.assertFalse(invalid_prior["ok"])
        with patch.object(transfer, "workflow", return_value={
                **observed, "phase": "campaign-not-claimed"}) as call:
            stage_diag = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                {"phase": "stage-start-diagnostic", "correlationId": CORR})
        call.assert_called_once_with(mcp_server.REPO_ROOT, "stage-start-diagnostic",
                                     {"correlationId": CORR})
        self.assertTrue(stage_diag["ok"])
        with patch.object(transfer, "workflow", return_value={
                **observed, "phase": "bundle-ready"}):
            invalid_stage_diag = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                {"phase": "stage-start-diagnostic", "correlationId": CORR})
        self.assertFalse(invalid_stage_diag["ok"])
        with patch.object(transfer, "workflow", return_value={
                **observed, "phase": "host-stage-absent"}) as call:
            host_diag = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                {"phase": "host-staged-pre-effect-diagnostic", "correlationId": CORR})
        call.assert_called_once_with(mcp_server.REPO_ROOT, "host-staged-pre-effect-diagnostic",
                                     {"correlationId": CORR})
        self.assertTrue(host_diag["ok"])
        with patch.object(transfer, "workflow", return_value={
                "state": "aborted", "correlationId": CORR,
                "replayAllowed": False, "nativeActionAllowed": False,
                "productAction": False}) as call:
            closed = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                {"phase": "host-staged-pre-effect-close", "correlationId": CORR})
        call.assert_called_once_with(mcp_server.REPO_ROOT, "host-staged-pre-effect-close",
                                     {"correlationId": CORR})
        self.assertTrue(closed["ok"])

    def test_e66_recovery_accepts_only_bounded_abort(self):
        corr = transfer._E66_CORRELATION
        aborted = {"state": "aborted", "correlationId": corr,
                   "replayAllowed": False, "nativeActionAllowed": False,
                   "productAction": False}
        with patch.object(transfer, "workflow", return_value=aborted) as call:
            result = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                {"phase": "e66-pre-effect-recovery", "correlationId": corr})
        call.assert_called_once_with(mcp_server.REPO_ROOT, "e66-pre-effect-recovery",
                                     {"correlationId": corr})
        self.assertTrue(result["ok"])
        for poison in ({**aborted, "rawTranscript": "secret"},
                       {**aborted, "replayAllowed": True}):
            with patch.object(transfer, "workflow", return_value=poison):
                rejected = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                    {"phase": "e66-pre-effect-recovery", "correlationId": corr})
            self.assertFalse(rejected["ok"])
            self.assertNotIn("secret", str(rejected))

    def test_e66_retirement_routes_are_exact_and_non_replayable(self):
        corr = transfer._E66_CORRELATION
        flags = {"correlationId": corr, "replayAllowed": False,
                 "nativeActionAllowed": False, "productAction": False}
        for phase, states in (("e66-retire-aborted-stage", ("retired",)),
                              ("e66-retire-aborted-stage-status", ("ready", "pending-finish", "retired"))):
            for state in states:
                with self.subTest(phase=phase, state=state), patch.object(
                    transfer, "workflow", return_value={"state": state, **flags}) as call:
                    result = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                        {"phase": phase, "correlationId": corr})
                call.assert_called_once_with(mcp_server.REPO_ROOT, phase,
                                             {"correlationId": corr})
                self.assertTrue(result["ok"])
                self.assertFalse(result["replayAllowed"])
        with patch.object(transfer, "workflow", return_value={
                "state": "retired", **flags, "privateReceipt": "secret"}):
            rejected = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                {"phase": "e66-retire-aborted-stage", "correlationId": corr})
        self.assertFalse(rejected["ok"])
        self.assertNotIn("secret", str(rejected))
        with patch.object(transfer, "workflow", return_value={"state": "aborted", **flags,
                "bundleSha256": "a" * 64, "bundleSize": 131218059}):
            terminal = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                {"phase": "status", "correlationId": corr})
        self.assertTrue(terminal["ok"])
        self.assertEqual(terminal["state"], "aborted")
        with patch.object(transfer, "workflow", return_value={"state": "aborted",
                **{**flags, "correlationId": CORR},
                "bundleSha256": "a" * 64, "bundleSize": 131218059}):
            foreign = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                {"phase": "status", "correlationId": CORR})
        self.assertFalse(foreign["ok"])
        self.assertEqual(foreign["state"], "unknown")

    def test_phase_projection_rejects_private_and_replay_fields(self):
        observed = {"state": "listening", "correlationId": CORR,
                    "replayAllowed": False, "nativeActionAllowed": False,
                    "productAction": False}
        for poison in ({**observed, "port": 32123},
                       {**observed, "replayAllowed": True},
                       {**observed, "correlationId": "33333333-3333-4333-8333-333333333333"}):
            with patch.object(transfer, "workflow", return_value=poison):
                result = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                    {"phase": "listener-start", "correlationId": CORR})
            self.assertFalse(result["ok"])
            self.assertNotIn("32123", str(result))
        with patch.object(transfer, "workflow", side_effect=AssertionError("unsafe dispatch")):
            invalid = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                {"phase": "guest-download", "correlationId": CORR, "port": 32123})
        self.assertFalse(invalid["ok"])
        with patch.object(transfer, "workflow", side_effect=AttributeError("stream has no open")):
            failed = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                {"phase": "stage-start", "correlationId": CORR})
        self.assertFalse(failed["ok"])
        self.assertNotIn("stream", str(failed))

    def test_collect_can_project_bounded_authoritative_receipt(self):
        observed = {"state": "staged-not-server-ready", "correlationId": CORR,
                    "sourceSha": "a" * 40, "targetMsiSha256": "d" * 64,
                    "bundleSha256": "e" * 64, "fileHashes": {"target.msi": "f" * 64},
                    "serverReady": False, "replayAllowed": False}
        with patch.object(transfer, "workflow", return_value=observed):
            result = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                {"phase": "collect", "correlationId": CORR})
        self.assertTrue(result["ok"])
        self.assertEqual(result["fileHashes"], observed["fileHashes"])
        for name in ("/private/secret", "content//secret", "/", "./secret"):
            with self.subTest(name=name), patch.object(transfer, "workflow", return_value={
                    **observed, "fileHashes": {name: "f" * 64}}):
                rejected = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                    {"phase": "collect", "correlationId": CORR})
                self.assertFalse(rejected["ok"])
                self.assertNotIn(name, str(rejected))

    def test_each_phase_accepts_only_its_result_schema(self):
        core = {"correlationId": CORR, "replayAllowed": False}
        flags = {"nativeActionAllowed": False, "productAction": False}
        examples = {
            "status": {**core, **flags, "state": "prepared", "bundleSha256": "e" * 64,
                       "bundleSize": 131072},
            "stage-start": {**core, "state": "staged", "sha256": "e" * 64,
                            "length": 131072},
            "listener-start": {**core, **flags, "state": "listening"},
            "listener-status": {**core, **flags, "state": "served"},
            "guest-create": {**core, "state": "created"},
            "guest-download": {**core, "state": "submitted"},
            "stage-extract": {**core, "state": "staged"},
            "cleanup": {**core, **flags, "state": "cleaned"},
        }
        for phase, observed in examples.items():
            with self.subTest(phase=phase), patch.object(transfer, "workflow", return_value=observed):
                result = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                    {"phase": phase, "correlationId": CORR})
                self.assertTrue(result["ok"])
        for poison in ({**examples["stage-start"], "state": "prepared"},
                       {**examples["status"], "bundleSha256": "private"},
                       {**examples["status"], "bundleSize": -1},
                       {**examples["guest-create"], "sourceSha": "a" * 40}):
            with patch.object(transfer, "workflow", return_value=poison):
                result = mcp_server._vm_workflow_impl("windows-update-fixture-http-transfer",
                    {"phase": "stage-start" if "sha256" in poison else
                     "guest-create" if "sourceSha" in poison else "status",
                     "correlationId": CORR})
            self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()

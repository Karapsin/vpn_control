"""Public MCP/CLI routing tests; no network or VM mutations."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from agent_tools import mcp_server


class NativeRoutesTest(unittest.TestCase):
    def test_apk_publication_requires_exact_fields_before_transport(self):
        from agent_tools import ssh_transfer
        with patch.object(ssh_transfer, "publish_android_apk") as publish:
            result = mcp_server.ssh_workflow("apk-publish", host="vm", transfer={"apkPath": "/file.apk"})
        self.assertFalse(result["ok"])
        publish.assert_not_called()

    def test_apk_status_preserves_unknown_identity(self):
        from agent_tools import ssh_transfer
        identity = {"correlationId": "apk-retained"}
        with patch.object(ssh_transfer, "android_apk_stage_status", return_value={"ok": False, "state": "unknown", "identity": identity}) as observe:
            result = mcp_server.ssh_workflow("apk-status", host="vm", identity=identity)
        self.assertEqual(identity, result["identity"])
        observe.assert_called_once_with(mcp_server.REPO_ROOT, "vm", identity, timeout_seconds=15)

    def test_connection_recovery_delegates_only_configured_alias_and_deadline(self):
        from agent_tools import ssh_connection_recovery
        with patch.object(ssh_connection_recovery, "recover", return_value={"ok": False, "state": "recovery_intent_pending"}) as recover:
            result = mcp_server.ssh_workflow("connection-recover", host="vm", timeout_seconds=20)
        recover.assert_called_once_with(mcp_server.REPO_ROOT, "vm", 20)
        self.assertFalse(result["ok"])
        self.assertEqual("recovery_intent_pending", result["state"])

    def test_android_observation_uses_only_configured_device_profile(self):
        from types import SimpleNamespace
        from agent_tools import ssh_transport, android_observation
        profile = {"adb": "/approved/adb", "cli": "/approved/cli", "serial": "emulator-5684",
                   "expectedAvd": "owned-api29", "api": 29}
        config = SimpleNamespace(hosts={"vm": SimpleNamespace(android_devices={"api29": profile})})
        with patch.object(ssh_transport, "load_config", return_value=config), patch.object(
                android_observation, "observe", return_value={"available": True}) as observe:
            self.assertTrue(mcp_server.ssh_workflow("android-observe", host="vm", device="api29")["ok"])
            observe.assert_called_once_with(mcp_server.REPO_ROOT, "vm", profile, 15)
            observe.reset_mock()
            self.assertFalse(mcp_server.ssh_workflow("android-observe", host="vm", device="missing")["ok"])
            observe.assert_not_called()

    def test_fixture_publish_requires_exact_fields_before_transport(self):
        from agent_tools import ssh_transfer
        with patch.object(ssh_transfer, "publish") as publish:
            result = mcp_server.ssh_workflow("fixture-publish", host="vm", transfer={"command": "unexpected"})
        self.assertFalse(result["ok"])
        publish.assert_not_called()

    def test_fixture_status_preserves_unknown_identity(self):
        from agent_tools import ssh_transfer
        identity = {"correlationId": "retained"}
        result = {"ok": False, "state": "unknown", "identity": identity}
        with patch.object(ssh_transfer, "status", return_value=result) as observe:
            actual = mcp_server.ssh_workflow("fixture-status", host="vm", identity=identity)
        self.assertEqual(identity, actual["identity"])
        self.assertEqual("unknown", actual["state"])
        observe.assert_called_once()

    def test_command_noise_filter_preserves_real_errors_and_exit_status(self):
        from subprocess import CompletedProcess
        noise = "2026-09-24 15:24:09.612 zsh[44632:4550809] [AppleSharpener] Not in Dock process (bundle ID: (null)), skipping setup\n"
        other = "2026-09-24 15:24:09.612 zsh[44632:4550809] [AppleSharpener] unexpected failure\n"
        completed = CompletedProcess(["test"], 7, noise + "actual stdout\n", noise + other + "actual stderr\n")
        with patch.object(mcp_server.subprocess, "run", return_value=completed) as run:
            result = mcp_server._run(["test"])
        self.assertEqual(7, result["returncode"])
        self.assertFalse(result["ok"])
        self.assertEqual("actual stdout", result["stdout"])
        self.assertEqual(other + "actual stderr", result["stderr"])
        self.assertNotIn("DYLD_INSERT_LIBRARIES", run.call_args.kwargs["env"])

    def test_private_inventory_cannot_be_managed_staged(self):
        self.assertIsNotNone(mcp_server._validate_commit_paths([".vm-hosts.local.json"]))

    def test_inventory_failure_does_not_leak_private_configuration(self):
        with tempfile.TemporaryDirectory() as root, patch.object(mcp_server, "REPO_ROOT", Path(root)):
            result = mcp_server.ssh_workflow()
            self.assertFalse(result["ok"])
            evidence = result.pop("failureEvidence", {})
            self.assertNotIn(root, json.dumps(result))
            if evidence.get("evidencePath"):
                self.assertIn("/.rag_index/native-failures/", evidence["evidencePath"])
                self.assertNotIn(".vm-hosts.local.json", evidence["evidencePath"])

    def test_artifact_mismatch_is_not_successful_verification(self):
        from agent_tools import native_artifact_registry
        with patch.object(native_artifact_registry, "verify_artifact", return_value={"verification": "mismatch"}):
            result = mcp_server.vm_workflow("artifact-verify", {"artifactId": "sha256-" + "a" * 64})
        self.assertFalse(result["ok"])
        self.assertEqual("mismatch", result["verification"])

    def test_bundle_route_rejects_unknown_scenario_before_preparation(self):
        result = mcp_server.vm_workflow("bundle-prepare", {"scenarioId": "arbitrary-command"})
        self.assertFalse(result["ok"])

    def test_forward_status_is_observation_only(self):
        from agent_tools import ssh_forward
        with patch.object(ssh_forward, "status", return_value={"ok": False, "state": "not_open"}) as observe, patch.object(ssh_forward, "open_forward") as start:
            result = mcp_server.ssh_workflow("forward-status", host="archlinux")
        observe.assert_called_once_with(mcp_server.REPO_ROOT, "archlinux")
        start.assert_not_called()
        self.assertFalse(result["ok"])

    def test_environment_unknown_observation_cannot_claim_ready(self):
        result = mcp_server.vm_workflow("environment-status", {"observations": []})
        self.assertFalse(result["ready"])

    def test_scenario_submission_has_public_success_envelope(self):
        from agent_tools import native_scenario_execution
        request = {"scenarioId": "linux-public-update-preflight", "artifactIds": {"bundleManifest": "sha256-" + "a" * 64}}
        with patch.object(native_scenario_execution.ScenarioExecutor, "start", return_value={"state": "submitted", "correlationId": "retained"}):
            result = mcp_server.vm_workflow("scenario-start", request)
        self.assertTrue(result.get("ok"))
        self.assertFalse(result["productAction"])
        self.assertEqual("retained", result["correlationId"])

    def test_vm_unknown_action_is_structured_failure(self):
        self.assertFalse(mcp_server.vm_workflow("restart-unknown-installer", {})["ok"])

    def test_memory_plan_is_never_start_authorization(self):
        result = mcp_server.vm_workflow("admit-plan", {
            "measurement": {"physicalMemoryBytes": 16000, "runningConfiguredMemoryBytes": 4000,
                            "pressure": "normal", "swapUsedBytes": 0},
            "requestedMemoryBytes": 4000, "headroomBytes": 4000,
        })
        self.assertTrue(result["ok"])
        self.assertFalse(result["nativeActionAllowed"])
        self.assertEqual("caller-supplied", result["measurementSource"])

    def test_cli_requires_json_object(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "inputs.json"
            path.write_text("[]")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = mcp_server.main(["vm-workflow", "admit-plan", "--inputs-file", str(path)])
            self.assertEqual(1, code)
            self.assertFalse(json.loads(output.getvalue())["ok"])


if __name__ == "__main__":
    unittest.main()

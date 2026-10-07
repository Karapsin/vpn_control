"""Public MCP/CLI routing tests; no network or VM mutations."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from agent_tools import mcp_server


class NativeRoutesTest(unittest.TestCase):
    def test_baseline_metadata_route_rejects_overrides_before_reader(self):
        from agent_tools import native_vm_baseline_inventory as inventory
        with patch.object(inventory, "configured_source_metadata") as read, \
             patch.object(mcp_server, "_native_response") as native:
            for request in ({"root": "/private"}, {"provider": "tart"},
                            {"command": "untrusted"}, None):
                self.assertFalse(mcp_server.vm_workflow("baseline-source-inventory", request)["ok"])
            read.assert_not_called()
            native.assert_not_called()

    def test_baseline_metadata_route_suppresses_private_errors_without_evidence_write(self):
        from agent_tools import native_vm_baseline_inventory as inventory
        with patch.object(inventory, "configured_source_metadata", side_effect=ValueError("private sentinel")) as read, \
             patch.object(mcp_server, "_native_response") as native:
            result = mcp_server.vm_workflow("baseline-source-inventory", {})
            self.assertFalse(result["ok"])
            self.assertFalse(result["nativeActionAllowed"])
            self.assertFalse(result["readinessVerified"])
            self.assertNotIn("private sentinel", json.dumps(result))
            read.assert_called_once_with(mcp_server.REPO_ROOT)
            native.assert_not_called()

    def test_baseline_metadata_route_only_projects_known_finite_reason(self):
        from agent_tools import native_vm_baseline_inventory as inventory
        for reason in ("baselines_not_configured", "invalid_inventory",
                       "invalid_source_configuration", "metadata_unavailable", "private sentinel"):
            error = inventory.BaselineInventoryError(reason=reason)
            with self.subTest(reason=reason), \
                 patch.object(inventory, "configured_source_metadata", side_effect=error), \
                 patch.object(mcp_server, "_native_response") as native:
                result = mcp_server.vm_workflow("baseline-source-inventory", {})
                self.assertEqual("metadata_unavailable" if reason == "private sentinel" else reason,
                                 result["reason"])
                self.assertNotIn("private sentinel", json.dumps(result))
                native.assert_not_called()

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
                         "Configured private inventory requires POSIX nofollow")
    def test_baseline_metadata_actual_private_fixture_and_fresh_cli(self):
        import subprocess
        import sys
        from agent_tools.tests.test_native_vm_baseline_inventory import BaselineInventoryTests
        fixture = BaselineInventoryTests()
        fixture.setUp()
        try:
            with patch.object(mcp_server, "REPO_ROOT", fixture.root), \
                 patch.object(mcp_server, "_native_response") as native:
                result = mcp_server.vm_workflow("baseline-source-inventory", {})
                self.assertTrue(result["ok"])
                self.assertFalse(result["nativeActionAllowed"])
                self.assertEqual([{"sourceId": "source-one", "provider": "qemu",
                                   "generation": "generation-one"}], result["sources"])
                native.assert_not_called()
            # Use the real parser in script import mode; only the trusted checkout
            # constant points at the synthetic private inventory.
            inputs = fixture.root / "inputs.json"
            inputs.write_text("{}")
            code = "import sys;from pathlib import Path;sys.path.insert(0,'agent_tools');import mcp_server;mcp_server.REPO_ROOT=Path(sys.argv[1]);mcp_server.main(['vm-workflow','baseline-source-inventory','--inputs-file',sys.argv[2]])"
            child = subprocess.run([sys.executable, "-c", code, str(fixture.root), str(inputs)],
                                   cwd=mcp_server.REPO_ROOT, capture_output=True, text=True, timeout=30)
            self.assertEqual(0, child.returncode, child.stderr)
            self.assertEqual(result, json.loads(child.stdout))
            self.assertNotIn("credential-sentinel", child.stdout)
            self.assertNotIn("private-provider-sentinel", child.stdout)
            self.assertFalse((fixture.root / ".rag_index").exists())
        finally:
            fixture.doCleanups()

    def test_windows_probe_routes_only_configured_identity_and_deadline(self):
        from agent_tools import windows_credential_probe_ssh as probe
        request = {"host": "owned", "correlationId": "00000000-0000-0000-0000-000000000001", "timeoutSeconds": 20}
        with patch.object(probe, "start", return_value={"ok": False, "state": "unknown"}) as start:
            result = mcp_server.vm_workflow("windows-credential-probe-start", request)
            self.assertEqual("unknown", result["state"])
            start.assert_called_once_with(mcp_server.REPO_ROOT, "owned", request["correlationId"], timeout_seconds=20)
            start.reset_mock()
            self.assertFalse(mcp_server.vm_workflow("windows-credential-probe-start", {**request, "command": "untrusted"})["ok"])
            start.assert_not_called()
        with patch.object(probe, "status", side_effect=probe.WindowsCredentialProbeSshError("private sentinel")):
            result = mcp_server.vm_workflow("windows-credential-probe-status", request)
            self.assertFalse(result["ok"])
            self.assertNotIn("private sentinel", json.dumps(result))

    def test_credential_recovery_routes_exclude_secrets_and_unconfigured_commands(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        class PrivateError(ValueError):
            pass
        backend = SimpleNamespace(start=Mock(return_value={"state": "submitted"}),
                                  status=Mock(return_value={"state": "unknown"}),
                                  credential_status=Mock(return_value={"state": "ready"}),
                                  WindowsCredentialRecoveryError=PrivateError)
        request = {"host": "owned", "correlationId": "00000000-0000-0000-0000-000000000001"}
        original_import = mcp_server.importlib.import_module
        def load(name):
            return backend if name.endswith("windows_credential_recovery_ssh") else original_import(name)
        with patch.object(mcp_server.importlib, "import_module", side_effect=load):
            self.assertEqual("submitted", mcp_server.vm_workflow("windows-credential-recover-start", request)["state"])
            backend.start.assert_called_once_with(mcp_server.REPO_ROOT, "owned", request["correlationId"], timeout_seconds=15)
            for forbidden in ("password", "command", "accountName", "expectedSid", "credentialPath"):
                backend.start.reset_mock()
                self.assertFalse(mcp_server.vm_workflow("windows-credential-recover-start", {**request, forbidden: "private"})["ok"])
                backend.start.assert_not_called()
            mcp_server.vm_workflow("credential-status", {**request, "handle": "opaque"})
            backend.credential_status.assert_called_once_with(mcp_server.REPO_ROOT, "owned", "opaque", request["correlationId"])
            backend.status.side_effect = PrivateError("secret sentinel")
            result = mcp_server.vm_workflow("windows-credential-recover-status", request)
            self.assertFalse(result["ok"])
            self.assertNotIn("secret sentinel", json.dumps(result))

    def test_android_proxy_recovery_accepts_only_fixed_device_and_correlation(self):
        from agent_tools import android_proxy_recovery as recovery
        request = {"host": "owned", "device": "api29", "expectedPort": 12345,
                   "correlationId": "00000000-0000-0000-0000-000000000001"}
        with patch.object(recovery, "recover_owned_stale_proxy", return_value={"ok": False, "state": "unknown"}) as start:
            result = mcp_server.vm_workflow("android-proxy-recover", request)
            self.assertEqual("unknown", result["state"])
            start.assert_called_once_with(mcp_server.REPO_ROOT, "owned", "api29", 12345, request["correlationId"])
            for invalid in ({**request, "expectedPort": True}, {**request, "command": "settings"}):
                start.reset_mock()
                self.assertFalse(mcp_server.vm_workflow("android-proxy-recover", invalid)["ok"])
                start.assert_not_called()
        with patch.object(recovery, "observe_recovery", side_effect=recovery.AndroidProxyRecoveryError("private sentinel")):
            result = mcp_server.vm_workflow("android-proxy-recovery-status", {"host": "owned", "device": "api29", "identity": {}})
            self.assertFalse(result["ok"])
            self.assertNotIn("private sentinel", json.dumps(result))

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

    def test_macos_installer_recovery_route_preserves_legacy_unknown_without_native_action(self):
        job = "d98286a2-1094-4459-8e8d-bc6a2d91a851"
        result = mcp_server.vm_workflow("macos-installer-recovery-status", {
            "jobId": job,
            "publicStatus": {"receiptId": job, "phase": "installing", "code": "OUTCOME_UNKNOWN",
                             "final": False, "installed": None},
            "protectedReceiptObservation": "absent",
            "bootSessionToken": None,
            "currentBootSessionUuid": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        })
        self.assertTrue(result["ok"])
        self.assertEqual(("unknown", "launch_boot_session_token_missing"),
                         (result["state"], result["reason"]))
        self.assertFalse(result["nativeActionAllowed"])
        self.assertFalse(result["replayAllowed"])
        self.assertFalse(result["cancellationAllowed"])

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


class SourceReviewClosureRoutesTest(unittest.TestCase):
    def test_source_closure_forwards_explicit_authority_without_native_recording(self):
        from agent_tools import native_review_source_closure as closure
        request = {"manifestPath": "/review.json", "manifestSha256": "a" * 64,
                   "packetManifestPath": "/packet.json", "packetManifestSha256": "b" * 64}
        receipt = {"scope": "SOURCE_ONLY", "nativeActionAllowed": False,
                   "productAcceptance": False}
        with patch.object(closure, "close_review_sources", return_value=receipt) as close, \
             patch.object(mcp_server, "_native_response") as native:
            result = mcp_server.vm_workflow("source-review-close", request)
        self.assertTrue(result["ok"])
        self.assertEqual("SOURCE_ONLY", result["scope"])
        self.assertFalse(result["nativeActionAllowed"])
        self.assertFalse(result["productAcceptance"])
        close.assert_called_once_with("/review.json", "a" * 64,
            packet_manifest_path="/packet.json", packet_manifest_sha256="b" * 64,
            proof_path=None, proof_sha256=None)
        native.assert_not_called()

    def test_source_closure_refusals_do_not_write_native_failure_evidence(self):
        from agent_tools import native_review_source_closure as closure
        request = {"manifestPath": "/review.json", "manifestSha256": "a" * 64}
        for invalid in ({}, {**request, "command": "untrusted"}, None):
            with self.subTest(invalid=invalid), \
                 patch.object(closure, "close_review_sources") as close, \
                 patch.object(mcp_server, "_native_response") as native:
                self.assertFalse(mcp_server.vm_workflow("source-review-close", invalid)["ok"])
                close.assert_not_called()
                native.assert_not_called()
        for error in (ValueError("private sentinel"), OSError("private sentinel"), TypeError("private sentinel")):
            with self.subTest(error=type(error)), \
                 patch.object(closure, "close_review_sources", side_effect=error), \
                 patch.object(mcp_server, "_native_response") as native:
                result = mcp_server.vm_workflow("source-review-close", request)
                self.assertFalse(result["ok"])
                self.assertNotIn("private sentinel", json.dumps(result))
                native.assert_not_called()


    @unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
                         "Strict source closure requires POSIX nofollow support")
    def test_source_closure_real_temp_files_and_cli_remain_readonly(self):
        import hashlib
        from agent_tools import native_review_source_closure as closure
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source.py"
            source.write_bytes(b"bounded review source")
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"inputs": {str(source): {
                "generation": list(closure.generation(source.stat())),
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}}}))
            request = {"manifestPath": str(manifest), "manifestSha256":
                       hashlib.sha256(manifest.read_bytes()).hexdigest()}
            request_path = root / "request.json"
            request_path.write_text(json.dumps(request))
            before = {p.name: (p.read_bytes(), closure.generation(p.stat())) for p in root.iterdir()}
            output = io.StringIO()
            with patch.object(mcp_server, "_native_response") as native, contextlib.redirect_stdout(output):
                status = mcp_server.main(["vm-workflow", "source-review-close",
                                          "--inputs-file", str(request_path)])
            self.assertEqual(0, status)
            result = json.loads(output.getvalue())
            self.assertTrue(result["ok"])
            self.assertEqual("SOURCE_ONLY", result["scope"])
            self.assertEqual(1, result["sourceCount"])
            self.assertFalse(result["nativeActionAllowed"])
            self.assertFalse(result["productAcceptance"])
            native.assert_not_called()
            after = {p.name: (p.read_bytes(), closure.generation(p.stat())) for p in root.iterdir()}
            self.assertEqual(before, after)


class SecondAbortFailureProjectionTests(unittest.TestCase):
    correlation = "691bd32a-4ea6-42a6-a3a2-e28b8d3498ec"
    routes = (
        ("windows-fixture-server-second-abort-successor-start", "successorCorrelationId", "start"),
        ("windows-fixture-server-second-abort-successor-status", "successorCorrelationId", "status"),
        ("windows-fixture-server-second-abort-successor-diagnostic", "successorCorrelationId", "diagnose"),
        ("windows-fixture-server-second-abort-recovery-diagnose", "recoveryCorrelationId", "resume_diagnose"),
        ("windows-fixture-server-second-abort-recovery-start", "recoveryCorrelationId", "resume_start"),
        ("windows-fixture-server-second-abort-recovery-status", "recoveryCorrelationId", "resume_status"),
    )

    def test_actual_public_response_refuses_private_adapter_exception_text(self):
        from types import SimpleNamespace
        sentinel = "SYNTHETIC_CREDENTIAL_TOKEN /synthetic/private/path SYNTHETIC_RAW_BODY"
        for action, field, method in self.routes:
            for error_class in (ValueError, OSError, KeyError, TypeError):
                with self.subTest(action=action, error=error_class.__name__):
                    calls = []
                    def refuse(*args):
                        calls.append(args)
                        raise error_class(sentinel)
                    adapter = SimpleNamespace(**{method: refuse})
                    # Only the native adapter and diagnostic storage are inert.
                    # The public route and response enrichment execute unchanged.
                    modules = {
                        "windows_fixture_server_second_abort_successor": adapter,
                        "native_next_action": SimpleNamespace(next_action=lambda *args: {"kind": "inspect-evidence"}),
                        "native_failure_evidence": SimpleNamespace(bounded_failure_details=lambda *args: {},
                            record_failure=lambda *args: {"state": "synthetic-retention"}),
                        "native_response_diagnostics": SimpleNamespace(describe=lambda *args: {}),
                    }
                    with patch.object(mcp_server, "_agent_module", side_effect=modules.__getitem__):
                        result = mcp_server.vm_workflow(action, {field: self.correlation})
                    self.assertEqual(calls, [(mcp_server.REPO_ROOT, {field: self.correlation})])
                    self.assertNotIn(sentinel, json.dumps(result))
                    self.assertEqual("unknown", result["state"])
                    self.assertEqual("windows-fixture-lifecycle-unavailable", result["reason"])
                    self.assertEqual(self.correlation, result[field])
                    self.assertIs(result["ok"], False)
                    for key in ("replayAllowed", "nativeActionAllowed", "productAction"):
                        self.assertIs(result[key], False)

    def test_invalid_correlation_refuses_before_adapter(self):
        for action, field, _method in self.routes:
            for request in ({field: "../foreign"}, {field: True}, {field: self.correlation, "path": "/private"}):
                with self.subTest(action=action, request=request), patch.object(mcp_server, "_agent_module") as load:
                    result = mcp_server._vm_workflow_impl(action, request)
                    self.assertIs(result["ok"], False)
                    load.assert_not_called()

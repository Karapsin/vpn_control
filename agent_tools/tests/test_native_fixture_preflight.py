from __future__ import annotations

from pathlib import Path, PurePosixPath
from types import SimpleNamespace
import os
import json
import tempfile
import unittest
from unittest.mock import Mock, patch

from agent_tools import native_fixture_preflight as preflight
from agent_tools import ssh_transport


class Dispatch:
    def __init__(self, artifact="verified", bundle=True, host=True):
        self.calls = []
        self.artifact, self.bundle, self.host = artifact, bundle, host

    def __call__(self, surface, action, inputs):
        self.calls.append((surface, action, dict(inputs)))
        if action == "artifact-verify":
            return {"verification": self.artifact,
                    "location": {"localPath": "/private/frozen/native-scenario-manifest.json"}}
        if action == "bundle-verify":
            return {"ok": self.bundle, "scenarioId": "linux-public-update-driver"}
        if action == "environment-status":
            return {"source": "live-tool", "requestedProbesReady": self.host,
                    "components": {"ssh": {"status": "available" if self.host else "unknown", "freshness": "fresh"},
                                   "host": {"freshness": "fresh", "observation": {"vmIdentity": {"state": "matched"}}}}}
        raise AssertionError(action)


class NativeFixturePreflightTest(unittest.TestCase):
    def linux_request(self):
        return {"scenarioId": "linux-public-update-preflight", "host": "owned", "environment": "fixture",
                "bundleManifestArtifactId": "sha256-" + "a" * 64}

    def test_scheduled_static_probe_uses_local_gateway_auth_through_three_hosts(self):
        root = Path(__file__).resolve().parents[2]
        direct = ssh_transport.SshHost("gateway", "gateway.example", 2228, "owner", Path("/owned/key"),
                                       Path("/owned/known_hosts"), password="gateway-secret")
        arch = ssh_transport.SshHost("arch", "unused", 22, "unused", Path("/unused/key"),
                                     PurePosixPath("/owned/known_hosts"), transport="nested", gateway="gateway",
                                     remote_host_alias="archlinux", remote_control_path=PurePosixPath("/owned/master.sock"),
                                     password="wrong-intermediate-secret")
        guest = ssh_transport.SshHost("guest", "unused", 2328, "unused", Path("/unused/key"),
                                      PurePosixPath("/owned/guest_known_hosts"), transport="nested", gateway="arch",
                                      remote_host_alias="fedora", remote_config_file=PurePosixPath("/owned/scp-config"))
        config = ssh_transport.SshConfig(root, {"gateway": direct, "arch": arch, "guest": guest})
        result = Mock(returncode=0, stdout=json.dumps({"profile": "linux-scheduled-refresh-static",
                                                        "checks": {"package": True, "desktopJar": True,
                                                                   "protectedOwner": True}}).encode())
        with patch.object(ssh_transport, "load_config", return_value=config), \
             patch.object(ssh_transport, "_askpass_environment", return_value=(Path("/unused/askpass"), {})) as askpass, \
             patch.object(preflight.subprocess, "run", return_value=result) as run:
            self.assertIsNotNone(preflight._remote_linux_static(root, "guest", b"{}", 5))
        self.assertEqual("gateway-secret", askpass.call_args.args[0])
        self.assertIn("archlinux", run.call_args.args[0][-1])
        self.assertIn("scp-config", run.call_args.args[0][-1])
        self.assertNotIn("gateway-secret", " ".join(run.call_args.args[0]))

    def test_invalid_timeout_fails_before_any_probe_or_intent(self):
        dispatch = Dispatch()
        request = self.linux_request() | {"timeoutSeconds": 0}
        with self.assertRaisesRegex(preflight.NativeFixturePreflightError, "timeout"):
            preflight.check("/unused", request, dispatch)
        self.assertEqual([], dispatch.calls)

    def test_import_profile_verifies_bytes_bundle_and_live_host(self):
        host = SimpleNamespace(fixture_transfer_root=PurePosixPath("/owned"))
        with patch.object(preflight, "_configured", return_value=host), patch.object(preflight, "_remote_root_status", return_value=True):
            result = preflight.check("/unused", self.linux_request(), Dispatch())
        self.assertTrue(result["ready"])
        self.assertEqual("not-applicable", result["requirements"]["certificate"]["state"])
        self.assertEqual("ready", result["requirements"]["bundle"]["state"])

    def test_changed_bundle_and_unknown_host_never_admit(self):
        host = SimpleNamespace(fixture_transfer_root=PurePosixPath("/owned"))
        with patch.object(preflight, "_configured", return_value=host), patch.object(preflight, "_remote_root_status", return_value=True):
            result = preflight.check("/unused", self.linux_request(), Dispatch(bundle=False, host=False))
        self.assertFalse(result["ready"])
        self.assertEqual("failed", result["requirements"]["bundle"]["state"])
        self.assertEqual("unknown", result["requirements"]["host"]["state"])

    def test_prepared_scheduled_fixture_checks_real_guest_result_and_rejects_wrong_endpoint(self):
        host = SimpleNamespace(fixture_transfer_root=PurePosixPath("/owned"))
        request = {"scenarioId": "linux-scheduled-refresh-fixture-ready", "host": "owned", "environment": "fixture",
                   "expectedTestUrl": "https://fixture.example/test", "certificateRelativePath": "certs/root.pem"}
        checks = {key: True for key in ("workspace", "settings", "benchmarkSettings", "protocol", "certificate", "endpoint")}
        with patch.object(preflight, "_configured", return_value=host), \
             patch.object(preflight, "_remote_root_status", return_value=True), \
             patch.object(preflight, "_remote_linux_refresh", return_value={"checks": checks}) as probe:
            self.assertTrue(preflight.check("/unused", request, Dispatch())["ready"])
            self.assertEqual(PurePosixPath("/owned/certs/root.pem"), probe.call_args.args[-1])
            checks["endpoint"] = False
            failed = preflight.check("/unused", request, Dispatch())
        self.assertFalse(failed["ready"])
        self.assertEqual("failed", failed["requirements"]["endpoint"]["state"])

    def test_scheduled_static_admission_defers_dynamic_fixture_until_runner_prepares_it(self):
        import json
        with tempfile.TemporaryDirectory() as raw:
            input_path = Path(raw) / "input.json"
            input_path.write_text(json.dumps({"schema": "vpn-control.linux-scheduled-refresh.input",
                "schemaVersion": 1, "scenarioId": "linux-scheduled-refresh", "correlationId": "scenario-17"}))
            host = SimpleNamespace(fixture_transfer_root=PurePosixPath("/owned"))
            request = {"scenarioId": "linux-scheduled-refresh", "host": "owned", "environment": "fixture",
                       "bundleManifestArtifactId": "sha256-" + "a" * 64,
                       "scenarioInputArtifactId": "sha256-" + "b" * 64,
                       "scenarioCorrelationId": "scenario-17"}
            class ScheduledDispatch(Dispatch):
                def __call__(self, surface, action, inputs):
                    if action == "artifact-verify" and inputs["artifactId"] == request["scenarioInputArtifactId"]:
                        return {"verification": "verified", "location": {"localPath": str(input_path)}}
                    if action == "bundle-verify":
                        return {"ok": True, "scenarioId": "linux-scheduled-refresh-driver"}
                    return super().__call__(surface, action, inputs)
            checks = {"package": True, "desktopJar": True, "protectedOwner": True}
            with patch.object(preflight, "_configured", return_value=host), \
                 patch.object(preflight, "_remote_root_status", return_value=True), \
                 patch.object(preflight, "_remote_linux_static", return_value={"checks": checks}):
                result = preflight.check("/unused", request, ScheduledDispatch())
            self.assertTrue(result["ready"])
            self.assertEqual("deferred", result["requirements"]["certificate"]["state"])
            self.assertEqual("ready", result["requirements"]["protectedOwner"]["state"])

    @unittest.skipUnless(os.name == "posix", "Private credential mode checks require POSIX.")
    def test_private_credential_input_is_scoped_to_exact_environment_and_vm(self):
        with tempfile.TemporaryDirectory() as raw:
            secret = Path(raw) / "credential"
            secret.write_bytes(b"private\n")
            secret.chmod(0o600)
            descriptor = SimpleNamespace(environment="owned-vm", credential_path=secret,
                                         qemu_pid=123, qemu_start_ticks=456)
            host = SimpleNamespace(fixture_transfer_root=PurePosixPath("/owned"), windows_credential_probe=descriptor)
            request = {"scenarioId": "windows-credential-validity-v1", "host": "owned", "environment": "owned-vm"}
            with patch.object(preflight, "_configured", return_value=host), patch.object(preflight, "_remote_root_status", return_value=True):
                self.assertTrue(preflight.check("/unused", request, Dispatch())["ready"])
                self.assertFalse(preflight.check("/unused", request | {"environment": "other"}, Dispatch())["ready"])
            secret.chmod(0o644)
            with patch.object(preflight, "_configured", return_value=host), patch.object(preflight, "_remote_root_status", return_value=True):
                result = preflight.check("/unused", request, Dispatch())
            self.assertEqual("failed", result["requirements"]["credentialInput"]["state"])


if __name__ == "__main__":
    unittest.main()

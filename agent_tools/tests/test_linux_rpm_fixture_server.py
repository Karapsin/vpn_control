"""Admission regression for the Fedora public RPM update endpoint."""

import json
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from agent_tools import native_rpm_public_install_ssh
from agent_tools import linux_rpm_fixture_server as guard
from agent_tools import native_rpm_public_install_adapter as adapter


class LinuxRpmFixtureServerTest(unittest.TestCase):
    def test_host_endpoint_gate_uses_exact_live_protected_server_observation(self):
        intent = adapter.RpmPublicInstallIntent.from_mapping({
            "scenarioId": adapter.SCENARIO_ID, "host": "fedora2328",
            "environment": "fedora2328", "bundleHash": "a" * 64,
            "artifactIds": {"bundleManifest": "sha256-" + "a" * 64,
                            "scenarioInput": "sha256-" + "b" * 64,
                            "sourceFixture": "sha256-" + "c" * 64,
                            "targetPackage": "sha256-" + "d" * 64},
            "credentialHandle": "rpm-auth-" + "e" * 32,
            "correlationId": "12345678-1234-1234-1234-123456789abc"})
        with mock.patch("agent_tools.linux_rpm_fixture_server_lifecycle.ready_for_public",
                        return_value=True) as observed:
            self.assertTrue(guard.host_endpoint_ready(Path("/fixed/repo"), intent, "f" * 64))
        observed.assert_called_once_with(Path("/fixed/repo"), intent, "f" * 64)

    def test_missing_host_endpoint_blocks_before_public_correlation_journal(self):
        intent = adapter.RpmPublicInstallIntent.from_mapping({
            "scenarioId": adapter.SCENARIO_ID, "host": "fedora2328", "environment": "owned",
            "bundleHash": "a" * 64,
            "artifactIds": {"bundleManifest": "sha256-" + "a" * 64,
                            "scenarioInput": "sha256-" + "b" * 64,
                            "sourceFixture": "sha256-" + "c" * 64,
                            "targetPackage": "sha256-" + "d" * 64},
            "credentialHandle": "rpm-auth-" + "e" * 32,
            "correlationId": "12345678-1234-1234-1234-123456789abc"})
        with tempfile.TemporaryDirectory() as temporary:
            driver = native_rpm_public_install_ssh.RpmPublicInstallSshDriver(temporary)
            with mock.patch.object(native_rpm_public_install_ssh, "admission",
                                   return_value={"typed": {"sourceFingerprint": "f" * 64}}), \
                    mock.patch.object(driver, "_save_journal", side_effect=AssertionError("journal consumed")):
                request = {"scenarioId": adapter.SCENARIO_ID, "host": intent.host,
                    "environment": intent.environment,
                    "bundleManifestArtifactId": intent.artifact_ids["bundleManifest"],
                    "scenarioInputArtifactId": intent.artifact_ids["scenarioInput"],
                    "sourceFixtureArtifactId": intent.artifact_ids["sourceFixture"],
                    "targetPackageArtifactId": intent.artifact_ids["targetPackage"],
                    "credentialHandle": intent.credential_handle,
                    "scenarioCorrelationId": intent.correlation_id}
                preflight = native_rpm_public_install_ssh.preflight(temporary, request)
                self.assertFalse(preflight["ready"])
                self.assertEqual("governed-server-unavailable",
                                 preflight["requirements"]["fixtureEndpoint"]["reason"])
                with self.assertRaisesRegex(ValueError, "fixture endpoint"):
                    driver.submit(intent)

    def test_missing_endpoint_receipts_block_before_process_use(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, "fixture endpoint unavailable"):
                guard.admit_endpoint(root / "job", root / "stage",
                                     {"correlationId": "12345678-1234-1234-1234-123456789abc"})

    def test_public_launcher_binds_the_separate_protected_server_workspace(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            correlation = "12345678-1234-1234-1234-123456789abc"
            public_job = root / "native-scenario-jobs/fedora2328/linux-rpm-public-install-recovery" / correlation
            public_stage = public_job / "stage"
            protected = root / "linux-rpm-fixture-server-jobs" / correlation
            protected_stage = protected / "stage"
            for directory in (public_stage, protected_stage):
                directory.mkdir(parents=True)
            for directory in (root, root / "native-scenario-jobs",
                              root / "native-scenario-jobs/fedora2328", public_job.parent,
                              public_job, public_stage, protected.parent, protected, protected_stage):
                directory.chmod(0o700)
            public = {"scenarioId": "linux-rpm-public-install-recovery", "host": "fedora2328",
                      "environment": "fedora2328", "bundleHash": "a" * 64,
                      "artifactIds": {"targetPackage": "sha256-" + "b" * 64},
                      "correlationId": correlation}
            digest = hashlib.sha256((json.dumps(public, sort_keys=True,
                              separators=(",", ":")) + "\n").encode()).hexdigest()
            metadata = {**public, "publicIntentSha256": digest,
                        "authorizationHandleSha256": "c" * 64,
                        "sourceFingerprint": "d" * 64, "expectedBaseVersion": "2.1.19",
                        "expectedTargetVersion": "2.2.0",
                        "expectedBaseNevra": "vpn-control-2.1.19-1.x86_64",
                        "expectedTargetNevra": "vpn-control-2.2.0-1.x86_64",
                        "expectedDesktopJarSha256": "1" * 64}
            protected_intent = {**metadata, "sourceSha": "e" * 40}
            receipt = {"state": "ready", "correlationId": correlation,
                       "sourceSha": "e" * 40, "publicIntentSha256": digest,
                       "sourceFixtureArtifactId": "sha256-" + "f" * 64,
                       "targetPackageArtifactId": public["artifactIds"]["targetPackage"]}
            metadata["artifactIds"]["sourceFixture"] = "sha256-" + "f" * 64
            protected_intent["artifactIds"] = dict(metadata["artifactIds"])
            # Digest uses the complete public artifact map, including sourceFixture.
            digest = hashlib.sha256((json.dumps({key: metadata[key] for key in public},
                sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest()
            metadata["publicIntentSha256"] = protected_intent["publicIntentSha256"] = digest
            receipt["publicIntentSha256"] = digest
            with mock.patch.object(guard, "_private_json", side_effect=[protected_intent, receipt]), \
                 mock.patch.object(guard, "admit_endpoint", return_value={"JAVA_TOOL_OPTIONS": "verified"}) as endpoint:
                self.assertEqual({"JAVA_TOOL_OPTIONS": "verified"},
                                 guard.admit_protected_server(public_job, public_stage, metadata))
            endpoint.assert_called_once_with(protected, protected_stage, protected_intent)
            changed = {**metadata, "expectedTargetVersion": "2.1.19"}
            with mock.patch.object(guard, "_private_json", side_effect=[protected_intent, receipt]), \
                 mock.patch.object(guard, "admit_endpoint", side_effect=AssertionError("foreign endpoint used")):
                with self.assertRaisesRegex(ValueError, "protected intent differs"):
                    guard.admit_protected_server(public_job, public_stage, changed)

    def test_exact_live_server_probe_and_target_bind_proxy_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job, stage = root / "job", root / "stage"
            fixture = stage / "fixture"
            events = fixture / "probe-events"
            events.mkdir(parents=True); job.mkdir()
            trust = stage / "fixture-truststore.p12"
            trust.write_bytes(b"test fixture trust store")
            (stage / "fixture-certificate.pem").write_text("test certificate stub")
            source = "a" * 64
            target = "b" * 64
            correlation = "12345678-1234-1234-1234-123456789abc"
            instance = "87654321-4321-4321-4321-cba987654321"
            cert = "c" * 64
            manifest = {"schemaVersion": 1, "assets": [{"packageType": "rpm",
                "displayVersion": "2.2.0", "sha256": target,
                "downloadUrl": "https://github.com/example/target.rpm"}]}
            receipt = fixture / "fixture-receipt.json"
            receipt.write_text(json.dumps({"sourceFingerprint": source, "manifest": manifest}))
            receipt.chmod(0o400)
            manifest_body = json.dumps(manifest, separators=(",", ":")).encode()
            manifest_hash = hashlib.sha256(manifest_body).hexdigest()
            receipt_hash = hashlib.sha256(receipt.read_bytes()).hexdigest()
            def private(path, value):
                path.write_text(json.dumps(value)); path.chmod(0o600)
            ready = {"port": 53432, "serverInstanceId": instance, "serverPid": 1234,
                "serverProcessStartIdentity": "linux:12345678-1234-1234-1234-123456789abc:99",
                "sourceFingerprint": source, "fixtureReceiptSha256": receipt_hash,
                "manifestSha256": manifest_hash, "peerCertificateSha256": cert, "manifest": manifest}
            private(job / "fixture-server-ready.json", ready)
            private(job / "fixture-endpoint-binding.json", {"schemaVersion": 1,
                "correlationId": correlation, "serverInstanceId": instance,
                "peerCertificateSha256": cert,
                "trustStoreSha256": hashlib.sha256(trust.read_bytes()).hexdigest(),
                "fixtureReceiptSha256": receipt_hash})
            private(events / (correlation + ".json"), {"schemaVersion": 1,
                "correlationId": correlation, "serverInstanceId": instance,
                "connectAccepted": True, "tlsSucceeded": True, "exactManifestGet": True,
                "manifestSha256": manifest_hash, "peerCertificateSha256": cert,
                "servedBytes": len(manifest_body)})
            proc = root / "proc"
            (proc / "1234").mkdir(parents=True)
            (proc / "1234/fd").mkdir()
            (proc / "1234/fd/5").symlink_to("socket:[7890]")
            (proc / "net").mkdir()
            (proc / "net/tcp").write_text(
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                "   0: 0100007F:D0B8 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 7890\n")
            (proc / "sys/kernel/random").mkdir(parents=True)
            (proc / "sys/kernel/random/boot_id").write_text("12345678-1234-1234-1234-123456789abc\n")
            (proc / "1234/stat").write_text("1234 (python3) S " + " ".join(["1"] * 18 + ["99"] + ["1"] * 8))
            (proc / "1234/status").write_text(f"Uid:\t{os.getuid()}\t{os.getuid()}\t{os.getuid()}\t{os.getuid()}\n")
            intent = {"correlationId": correlation, "sourceFingerprint": source,
                      "expectedTargetVersion": "2.2.0",
                      "artifactIds": {"targetPackage": "sha256-" + target}}
            with mock.patch.dict(os.environ, {}, clear=True), \
                    mock.patch.object(guard, "_certificate", return_value=cert):
                admitted = guard.admit_endpoint(job, stage, intent, proc_root=proc)
            self.assertIn("-Dhttps.proxyPort=53432", admitted["JAVA_TOOL_OPTIONS"])
            old_inode = receipt.stat().st_ino
            original_read = os.read
            replaced = False
            def replace_after_pinned_read(fd, amount):
                nonlocal replaced
                raw = original_read(fd, amount)
                if not replaced and os.fstat(fd).st_ino == old_inode:
                    replacement = receipt.with_name("replacement.json")
                    replacement.write_text(json.dumps({"sourceFingerprint": source,
                        "manifest": manifest, "unexamined": "new bytes"}))
                    replacement.chmod(0o400)
                    os.replace(replacement, receipt)
                    replaced = True
                return raw
            with mock.patch.dict(os.environ, {}, clear=True), \
                    mock.patch.object(guard, "_certificate", return_value=cert), \
                    mock.patch.object(os, "read", side_effect=replace_after_pinned_read):
                with self.assertRaisesRegex(ValueError, "fixture endpoint unavailable"):
                    guard.admit_endpoint(job, stage, intent, proc_root=proc)
            self.assertTrue(replaced)
            receipt.chmod(0o600)
            receipt.write_text(json.dumps({"sourceFingerprint": source, "manifest": manifest}))
            receipt.chmod(0o400)
            with mock.patch.dict(os.environ, {}, clear=True), \
                    mock.patch.object(guard, "_certificate", return_value=cert):
                ready["serverProcessStartIdentity"] = ready["serverProcessStartIdentity"].replace(":99", ":100")
                private(job / "fixture-server-ready.json", ready)
                with self.assertRaisesRegex(ValueError, "fixture endpoint unavailable"):
                    guard.admit_endpoint(job, stage, intent, proc_root=proc)

    def test_public_launcher_refuses_unbound_endpoint_before_invoking_harness(self):
        class HarnessReached(Exception):
            pass

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job, stage = root / "job", root / "stage"
            job.mkdir(); stage.mkdir()
            (job / "release").touch()
            (job / "intent.json").write_text(json.dumps({"expectedTargetVersion": "2.2.0",
                "identity": {"pid": 1234, "startTicks": 99},
                "scenarioId": "linux-rpm-public-install-recovery", "host": "fedora2328",
                "environment": "fedora2328", "bundleHash": "a" * 64,
                "artifactIds": {}, "correlationId": "12345678-1234-1234-1234-123456789abc"}))
            with mock.patch.object(sys, "argv", ["launch.py", str(job), str(stage)]), \
                    mock.patch("subprocess.call", side_effect=HarnessReached):
                with self.assertRaises(SystemExit) as stopped:
                    exec(native_rpm_public_install_ssh._LAUNCHER, {"__name__": "__main__"})
            self.assertEqual(1, stopped.exception.code)
            receipt = json.loads((job / "receipt.json").read_text())
            self.assertEqual("guest-admission", receipt["failurePhase"])
            self.assertEqual(1, receipt["exitCode"])

    def test_public_launcher_passes_verified_proxy_environment_to_harness(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job, stage = root / "job", root / "stage"
            job.mkdir(); stage.mkdir()
            (job / "release").touch()
            (job / "intent.json").write_text(json.dumps({"expectedTargetVersion": "2.2.0",
                "identity": {"pid": 1234, "startTicks": 99},
                "scenarioId": "linux-rpm-public-install-recovery", "host": "fedora2328",
                "environment": "fedora2328", "bundleHash": "a" * 64,
                "artifactIds": {}, "correlationId": "12345678-1234-1234-1234-123456789abc",
                "sourceFingerprint": "f" * 64}))
            options = "-Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=53432"
            guard_source = ("def admit_protected_server(*_):\n"
                            f"    return {{'JAVA_TOOL_OPTIONS': {options!r}}}\n").encode()
            (stage / "linux-rpm-fixture-server.py").write_bytes(guard_source)
            (stage / "linux-rpm-fixture-server.py").chmod(0o600)
            data = json.loads((job / "intent.json").read_text())
            data["serverGuardSha256"] = hashlib.sha256(guard_source).hexdigest()
            (job / "intent.json").write_text(json.dumps(data))
            with mock.patch.object(sys, "argv", ["launch.py", str(job), str(stage)]), \
                    mock.patch("subprocess.call", return_value=1) as call:
                exec(native_rpm_public_install_ssh._LAUNCHER, {"__name__": "__main__"})
            self.assertEqual(options, call.call_args.kwargs["env"]["JAVA_TOOL_OPTIONS"])
            self.assertEqual(1, json.loads((job / "receipt.json").read_text())["exitCode"])

    def test_public_launcher_rejects_guard_changed_after_transfer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job, stage = root / "job", root / "stage"
            job.mkdir(); stage.mkdir(); (job / "release").touch()
            original = b"def admit_protected_server(*_): return {'JAVA_TOOL_OPTIONS': 'safe'}\n"
            tampered = b"def admit_protected_server(*_): return {'JAVA_TOOL_OPTIONS': 'tampered'}\n"
            (stage / "linux-rpm-fixture-server.py").write_bytes(tampered)
            (stage / "linux-rpm-fixture-server.py").chmod(0o600)
            (job / "intent.json").write_text(json.dumps({"expectedTargetVersion": "2.2.0",
                "identity": {"pid": 1234, "startTicks": 99},
                "scenarioId": "linux-rpm-public-install-recovery", "host": "fedora2328",
                "environment": "fedora2328", "bundleHash": "a" * 64,
                "artifactIds": {}, "correlationId": "12345678-1234-1234-1234-123456789abc",
                "serverGuardSha256": hashlib.sha256(original).hexdigest()}))
            with mock.patch.object(sys, "argv", ["launch.py", str(job), str(stage)]), \
                    mock.patch("subprocess.call", side_effect=AssertionError("harness reached")):
                with self.assertRaises(SystemExit):
                    exec(native_rpm_public_install_ssh._LAUNCHER, {"__name__": "__main__"})
            self.assertEqual("guest-admission",
                             json.loads((job / "receipt.json").read_text())["failurePhase"])


if __name__ == "__main__":
    unittest.main()

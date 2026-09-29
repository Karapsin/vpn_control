"""Causal guards for one-shot DEB/Arch native acceptance admission."""
from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
import unittest
from unittest import mock
import uuid

from agent_tools import linux_deb_arch_acceptance as acceptance


SHA = "a" * 40
FINGERPRINT = "b" * 64


class Driver:
    def __init__(self, submit=None, status=None):
        self.submissions = 0
        self.submission = submit or {"state": "submitted"}
        self.observation = status or {"state": "running"}

    def submit(self, intent, admission):
        self.submissions += 1
        return {**self.submission, "correlationId": intent.correlation_id}

    def status(self, intent):
        return {"sourceSha": intent.source_sha, "artifactIds": intent.artifact_ids,
                "guestRole": intent.guest_role, "guestPort": intent.guest_port,
                **self.observation, "correlationId": intent.correlation_id}


class DebArchAcceptanceTest(unittest.TestCase):
    def request(self, profile="package-update", distribution="ubuntu"):
        return {"profile": profile, "distribution": distribution,
                "correlationId": str(uuid.uuid4()), "sourceSha": SHA,
                "artifactIds": {key: "sha256-" + letter * 64 for key, letter in
                                {"guestManifest": "1", "preparationReceipt": "6", "fixtureReceipt": "2",
                                 "basePackage": "3", "targetPackage": "4", "bundleManifest": "5"}.items()}}

    def test_profile_is_fixed_and_distinct_guest_role_is_bound(self):
        self.assertEqual("ubuntu-update", acceptance.Intent.parse(self.request()).guest_role)
        self.assertEqual("ubuntu-fresh", acceptance.Intent.parse(self.request("fresh-deb-dependencies")).guest_role)
        self.assertEqual("arch-rollback", acceptance.Intent.parse(self.request("arch-rollback", "arch")).guest_role)
        for profile, distro in (("arch-rollback", "ubuntu"), ("fresh-deb-dependencies", "arch")):
            with self.subTest(profile=profile, distro=distro), self.assertRaises(ValueError):
                acceptance.Intent.parse(self.request(profile, distro))

    def test_unknown_submission_is_durable_and_cannot_replay(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            driver = Driver(submit={"state": "unknown"})
            adapter = acceptance.Adapter(root, driver=driver, admit=lambda _: {"ready": True})
            request = self.request()
            first = adapter.start(request)
            self.assertEqual("unknown", first["state"])
            self.assertEqual(1, driver.submissions)
            again = adapter.start(request)
            self.assertEqual("running", again["state"])
            self.assertEqual(1, driver.submissions)
            distinct = self.request()
            self.assertEqual("blocked", adapter.start(distinct)["state"])
            self.assertEqual(1, driver.submissions)

    def test_reused_correlation_with_different_artifacts_cannot_observe_or_submit(self):
        with tempfile.TemporaryDirectory() as temp:
            driver = Driver()
            adapter = acceptance.Adapter(temp, driver=driver, admit=lambda _: {"ready": True})
            original = self.request()
            self.assertEqual("submitted", adapter.start(original)["state"])
            altered = {**original, "artifactIds": {**original["artifactIds"],
                                                   "targetPackage": "sha256-" + "6" * 64}}
            observed = adapter.start(altered)
            self.assertEqual("unknown", observed["state"])
            self.assertEqual("correlation-intent-mismatch", observed["reason"])
            self.assertEqual(1, driver.submissions)

    def test_incomplete_claim_or_journal_fails_closed_without_replay(self):
        with tempfile.TemporaryDirectory() as temp:
            driver = Driver()
            adapter = acceptance.Adapter(temp, driver=driver, admit=lambda _: {"ready": True})
            request = self.request()
            intent = acceptance.Intent.parse(request)
            acceptance._private_dir(adapter.directory)
            acceptance._exclusive(adapter.directory / (intent.guest_role + ".claim"),
                                  {"guestRole": intent.guest_role, "correlationId": intent.correlation_id})
            self.assertEqual("blocked", adapter.start(request)["state"])
            self.assertEqual(0, driver.submissions)
            other = self.request("arch-rollback", "arch")
            other_intent = acceptance.Intent.parse(other)
            acceptance._exclusive(adapter.directory / (other_intent.correlation_id + ".json"),
                                  other_intent.public_mapping())
            self.assertEqual("unknown", adapter.start(other)["state"])
            self.assertEqual(0, driver.submissions)

    def test_failed_admission_never_claims_or_dispatches(self):
        with tempfile.TemporaryDirectory() as temp:
            driver = Driver()
            adapter = acceptance.Adapter(temp, driver=driver, admit=lambda _: {"ready": False, "reason": "guest-unknown"})
            request = self.request()
            self.assertEqual("blocked", adapter.start(request)["state"])
            self.assertEqual(0, driver.submissions)
            self.assertFalse((Path(temp) / ".rag_index/native-linux-deb-arch").exists())

    def test_terminal_receipt_requires_exact_correlation_and_protected_result(self):
        with tempfile.TemporaryDirectory() as temp:
            driver = Driver(status={"state": "terminal", "exitCode": 0,
                                    "protectedReceipt": {"version": 1, "sequence": 4, "jobId": "job", "phase": "SUCCEEDED", "code": "OK"},
                                    "accepted": {"schemaVersion": 1, "code": "ACCEPTED", "ok": True, "final": False,
                                                 "controllerId": "original", "requestId": "request", "operationId": "operation",
                                                 "data": {"jobId": "job", "handoffReady": True}},
                                    "replacementRecoveryObservation": {"schemaVersion": 1, "ok": True, "code": "OK",
                                                                       "final": True, "controllerId": "replacement",
                                                                       "operationId": "operation",
                                                                       "data": {"jobId": "job", "originControllerId": "original",
                                                                                "originRequestId": "request"}},
                                    "sameSourceRecoveryProven": True, "productionTrustedInstallSucceeded": True,
                                    "sourceFingerprint": FINGERPRINT, "targetVersion": "2.2.0",
                                    "guestGeneration": {"pid": 123, "startTicks": 456,
                                                        "diskDevice": 7, "diskInode": 8}})
            adapter = acceptance.Adapter(temp, driver=driver, admit=lambda _: {"ready": True})
            request = self.request()
            adapter.start(request)
            guest = {"qemuPid": 123, "qemuStartTicks": 456, "diskDevice": 7, "diskInode": 8}
            with mock.patch.object(acceptance, "_verified_artifact", return_value={"record": {}}), \
                 mock.patch.object(acceptance, "_fixture", return_value={"sourceFingerprint": FINGERPRINT,
                                                                         "targetVersion": "2.2.0"}), \
                 mock.patch.object(acceptance, "_bundle"), \
                 mock.patch.object(acceptance, "_guest_manifest", return_value=guest), \
                 mock.patch.object(acceptance, "_preparation", return_value={}):
                self.assertEqual("terminal", adapter.collect(request["correlationId"])["state"])
                driver.observation["replacementRecoveryObservation"]["data"]["jobId"] = "other"
                self.assertEqual("unknown", adapter.collect(request["correlationId"])["state"])

    def test_invalid_artifact_or_guest_manifest_fails_before_dispatch(self):
        with tempfile.TemporaryDirectory() as temp:
            request = self.request()
            with mock.patch.object(acceptance, "_verified_artifact", side_effect=ValueError("missing")):
                result = acceptance.preflight(Path(temp), acceptance.Intent.parse(request), live_observer=lambda *_: {"ready": True})
            self.assertFalse(result["ready"])

    def test_dirty_head_blocks_before_artifact_or_guest_admission(self):
        with tempfile.TemporaryDirectory() as temp:
            intent = acceptance.Intent.parse(self.request())
            with mock.patch.object(acceptance.subprocess, "check_output", side_effect=[SHA + "\n", " M desktopApp/file.kt\n"]), \
                 mock.patch.object(acceptance, "_verified_artifact") as artifact:
                result = acceptance.preflight(temp, intent, live_observer=lambda *_: {"ready": True})
            self.assertFalse(result["ready"])
            self.assertIn("not frozen clean", result["reason"])
            artifact.assert_not_called()

    def test_bundle_rejects_missing_or_changed_native_harness(self):
        import hashlib
        with tempfile.TemporaryDirectory() as temp:
            stage = Path(temp)
            entries = []
            for relative in sorted(acceptance._BUNDLE_FILES):
                path = stage / relative
                path.parent.mkdir(exist_ok=True)
                path.write_bytes(relative.encode())
                entries.append({"path": relative, "sha256": hashlib.sha256(relative.encode()).hexdigest(),
                                "sizeBytes": len(relative)})
            manifest = stage / "native-scenario-manifest.json"
            manifest.write_text(json.dumps({"schemaVersion": 1, "scenarioId": "linux-public-update-driver",
                                            "files": entries}))
            captured = {"bundleManifest": {"path": manifest}}
            acceptance._bundle(captured)
            (stage / "scripts/test_linux_public_install.py").write_bytes(
                b"X" * len(b"scripts/test_linux_public_install.py"))
            with self.assertRaisesRegex(ValueError, "bundle bytes differ"):
                acceptance._bundle(captured)
            (stage / "scripts/test_linux_public_install.py").write_bytes(
                b"scripts/test_linux_public_install.py")
            entries.pop()
            manifest.write_text(json.dumps({"schemaVersion": 1, "scenarioId": "linux-public-update-driver",
                                            "files": entries}))
            with self.assertRaisesRegex(ValueError, "required native harness is absent"):
                acceptance._bundle(captured)

    def test_terminal_same_job_but_wrong_source_is_unknown(self):
        with tempfile.TemporaryDirectory() as temp:
            driver = Driver(status={"state": "terminal", "exitCode": 0, "sourceSha": "b" * 40})
            adapter = acceptance.Adapter(temp, driver=driver, admit=lambda _: {"ready": True})
            request = self.request()
            adapter.start(request)
            observed = adapter.collect(request["correlationId"])
            self.assertEqual("unknown", observed["state"])
            self.assertEqual("source-or-guest-mismatch", observed["reason"])

    def test_fresh_deb_requires_pre_and_post_dependency_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            transaction = {"manager": "apt", "exitCode": 0, "beforeXdgUtilsAbsent": True,
                           "beforeDesktopDirectoryAbsent": True, "afterXdgUtilsInstalled": True,
                           "afterDesktopDirectoryPresent": True, "dpkgAuditClean": True,
                           "onlyExpectedPackagesAdded": True}
            driver = Driver(status={"state": "terminal", "exitCode": 0,
                                    "packageTransaction": transaction, "launcherVersionMatched": True,
                                    "sourceFingerprint": FINGERPRINT, "targetVersion": "2.2.0",
                                    "guestGeneration": {"pid": 123, "startTicks": 456,
                                                        "diskDevice": 7, "diskInode": 8}})
            adapter = acceptance.Adapter(temp, driver=driver, admit=lambda _: {"ready": True})
            request = self.request("fresh-deb-dependencies")
            adapter.start(request)
            guest = {"qemuPid": 123, "qemuStartTicks": 456, "diskDevice": 7, "diskInode": 8}
            with mock.patch.object(acceptance, "_verified_artifact", return_value={"record": {}}), \
                 mock.patch.object(acceptance, "_fixture", return_value={"sourceFingerprint": FINGERPRINT,
                                                                         "targetVersion": "2.2.0"}), \
                 mock.patch.object(acceptance, "_bundle"), \
                 mock.patch.object(acceptance, "_guest_manifest", return_value=guest), \
                 mock.patch.object(acceptance, "_preparation", return_value={}):
                self.assertEqual("dependencies-installed", adapter.collect(request["correlationId"])["result"])
                transaction["beforeDesktopDirectoryAbsent"] = False
                self.assertEqual("dependency-acquisition-unverified", adapter.collect(request["correlationId"])["reason"])

    def test_preparation_receipt_binds_correlation_and_base_package(self):
        with tempfile.TemporaryDirectory() as temp:
            intent = acceptance.Intent.parse(self.request())
            fixture = {"sourceFingerprint": FINGERPRINT, "baseVersion": "2.1.19", "targetVersion": "2.2.0",
                       "codeFingerprint": "c" * 64}
            guest = {"qemuPid": 123, "qemuStartTicks": 456, "diskDevice": 7, "diskInode": 8,
                     "sshPort": intent.guest_port, "tree": "/home/kardinal/vpn-control-install-vm-parity-ubuntu-update"}
            receipt = {"schemaVersion": 1, "host": "archlinux", "profile": intent.profile,
                       "distribution": intent.distribution, "guestRole": intent.guest_role,
                       "sourceSha": intent.source_sha, "sourceFingerprint": FINGERPRINT,
                       "correlationId": intent.correlation_id, "qemu": {"pid": 123, "startTicks": 456,
                           "diskDevice": 7, "diskInode": 8, "sshPort": intent.guest_port, "tree": guest["tree"]},
                       "baseline": {"installedBaseVersion": "2.1.19", "installedPackageSha256": "d" * 64,
                                    "codeFingerprint": "c" * 64, "cleanPackageDatabase": True,
                                    "xdgUtilsAbsent": None, "desktopDirectoryAbsent": None},
                       "fixture": {"serverPid": 55, "serverStartTicks": 66, "readySha256": "1" * 64,
                                   "manifestSha256": "2" * 64, "certificateSha256": "3" * 64,
                                   "trustStoreSha256": "4" * 64, "publicFixtureSha256": "5" * 64},
                       "publicCli": {"polkitReady": True, "ptyReady": True, "credentialReady": True},
                       "safety": {"ownerRuntimeOff": True, "protectedJobsTerminal": True,
                                  "rootOwnedStage": True},
                       "stage": "/var/lib/vpn-control-parity/ubuntu-update", "state": "ready"}
            for field, key in (("guestManifestArtifactId", "guestManifest"),
                               ("fixtureReceiptArtifactId", "fixtureReceipt"),
                               ("basePackageArtifactId", "basePackage"),
                               ("targetPackageArtifactId", "targetPackage"),
                               ("bundleManifestArtifactId", "bundleManifest")):
                receipt[field] = intent.artifact_ids[key]
            worker = {"profile": intent.profile, "distribution": intent.distribution,
                      "guestRole": intent.guest_role, "correlationId": intent.correlation_id,
                      "sourceSha": intent.source_sha, "sourceFingerprint": FINGERPRINT,
                      "targetVersion": "2.2.0", "targetSha256": "e" * 64,
                      "fixtureReceiptArtifactId": intent.artifact_ids["fixtureReceipt"],
                      "harnessSha256": "f" * 64,
                      "trustStoreSha256": "4" * 64}
            receipt["workerIntentSha256"] = hashlib.sha256(
                (json.dumps(worker, sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest()
            receipt["nativeWorkerSha256"] = "a" * 64
            receipt["rollbackWorkerSha256"] = "b" * 64
            path = Path(temp) / "preparation.json"
            path.write_text(json.dumps(receipt))
            captured = {"preparationReceipt": {"path": path},
                        "basePackage": {"record": {"sha256": "d" * 64}},
                        "targetPackage": {"record": {"sha256": "e" * 64}}}
            with mock.patch.object(acceptance, "_harness_sha", return_value="f" * 64), \
                 mock.patch.object(acceptance, "_frozen_source_sha", side_effect=["a" * 64, "b" * 64]):
                self.assertEqual("ready", acceptance._preparation(intent, captured, fixture, guest)["state"])
            receipt["correlationId"] = str(uuid.uuid4())
            path.write_text(json.dumps(receipt))
            with mock.patch.object(acceptance, "_harness_sha", return_value="f" * 64), \
                 mock.patch.object(acceptance, "_frozen_source_sha", side_effect=["a" * 64, "b" * 64]):
                with self.assertRaisesRegex(ValueError, "does not bind"):
                    acceptance._preparation(intent, captured, fixture, guest)


if __name__ == "__main__":
    unittest.main()

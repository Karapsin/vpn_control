"""Fixed DEB/Arch guest preparation boundaries and no-replay regressions."""

import json
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import threading
import unittest
from unittest import mock

from agent_tools import linux_deb_arch_guest_prepare as subject


SOURCE = "a" * 40
CORRELATION = "12345678-1234-1234-1234-123456789abc"


def request(profile="package-update", distribution="ubuntu"):
    return {"profile": profile, "distribution": distribution,
            "correlationId": CORRELATION, "sourceSha": SOURCE,
            "artifactIds": {"fixtureReceipt": "sha256-" + "b" * 64,
                            "basePackage": "sha256-" + "c" * 64,
                            "targetPackage": "sha256-" + "d" * 64,
                            "bundleManifest": "sha256-" + "e" * 64}}


def receipt(parsed, *, fresh=False):
    role = parsed.guest_role
    guest = {"qemuPid": 100, "qemuStartTicks": 200, "diskDevice": 300,
             "diskInode": 400, "sshPort": parsed.guest_port,
             "tree": "/home/kardinal/vpn-control-install-vm-parity-" + role}
    fixture = {"sourceFingerprint": "f" * 64, "baseVersion": "2.1.19",
               "codeFingerprint": "1" * 64}
    baseline = {"installedBaseVersion": None if fresh else "2.1.19",
                "installedPackageSha256": None if fresh else "c" * 64,
                "codeFingerprint": None if fresh else "1" * 64,
                "cleanPackageDatabase": True, "xdgUtilsAbsent": True if fresh else None,
                "desktopDirectoryAbsent": True if fresh else None}
    server = None if fresh else {"serverPid": 500, "serverStartTicks": 600,
        "readySha256": "2" * 64, "manifestSha256": "3" * 64,
        "certificateSha256": "4" * 64, "trustStoreSha256": "5" * 64,
        "publicFixtureSha256": "8" * 64}
    value = {"schemaVersion": 1, "host": "archlinux", "profile": parsed.profile,
             "distribution": parsed.distribution, "guestRole": role,
             "sourceSha": SOURCE, "sourceFingerprint": "f" * 64,
             "correlationId": CORRELATION,
             "guestManifestArtifactId": "sha256-" + "6" * 64,
             "fixtureReceiptArtifactId": parsed.artifact_ids["fixtureReceipt"],
             "basePackageArtifactId": parsed.artifact_ids["basePackage"],
             "targetPackageArtifactId": parsed.artifact_ids["targetPackage"],
             "bundleManifestArtifactId": parsed.artifact_ids["bundleManifest"],
             "qemu": {"pid": 100, "startTicks": 200, "diskDevice": 300,
                      "diskInode": 400, "sshPort": parsed.guest_port, "tree": guest["tree"]},
             "baseline": baseline, "fixture": server,
             "publicCli": None if fresh else
                 {"polkitReady": True, "ptyReady": True, "credentialReady": True},
             "safety": {"ownerRuntimeOff": True, "protectedJobsTerminal": True,
                        "rootOwnedStage": True},
             "stage": "/var/lib/vpn-control-parity/" + role,
             "workerIntentSha256": "7" * 64,
             "nativeWorkerSha256": "9" * 64,
             "rollbackWorkerSha256": "a" * 64,
             "state": "ready"}
    return value, fixture, guest


class GuestPreparationTest(unittest.TestCase):
    def test_transfer_bundle_freezes_exact_registered_bytes_before_remote_effect(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            for name in ("prepare_linux_install_vm.py", "fixture_environment.py",
                         "macos_packaging_jdk_preflight.py", "rpm_public_update.py",
                         "install_arch_desktop_update.sh"):
                (root / "scripts" / name).write_bytes(b"# frozen " + name.encode())
            (root / "agent_tools").mkdir()
            for name in ("linux_deb_arch_guest_prepare_remote.py", "linux_deb_arch_native_driver.py",
                         "linux_deb_arch_rollback.py"):
                (root / "agent_tools" / name).write_bytes(b"# frozen " + name.encode())
            base, target = root / "base.deb", root / "target.deb"
            base.write_bytes(b"base package")
            target.write_bytes(b"target package")
            asset = lambda path, name: {"packageType": "deb", "fileName": name,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "sizeBytes": path.stat().st_size}
            original = {"schemaVersion": 1, "testOnly": True, "productionTrustChanged": False,
                "sourceFingerprint": "f" * 64,
                "builds": [{"assets": [asset(base, "base.deb")]},
                           {"assets": [asset(target, "target.deb")]}],
                "manifest": {"assets": [asset(target, "target.deb")]}}
            original_path = root / "fixture.json"
            original_path.write_text(json.dumps(original))
            script = root / "scripts/harness.py"
            script.write_bytes(b"# frozen harness")
            bundle_path = root / "bundle.json"
            bundle_path.write_text(json.dumps({"files": [{"path": "scripts/harness.py",
                "sha256": hashlib.sha256(script.read_bytes()).hexdigest(),
                "sizeBytes": script.stat().st_size}]}))
            value = request()
            value["artifactIds"] = {"fixtureReceipt": "sha256-" + hashlib.sha256(original_path.read_bytes()).hexdigest(),
                "basePackage": "sha256-" + hashlib.sha256(base.read_bytes()).hexdigest(),
                "targetPackage": "sha256-" + hashlib.sha256(target.read_bytes()).hexdigest(),
                "bundleManifest": "sha256-" + hashlib.sha256(bundle_path.read_bytes()).hexdigest()}
            parsed = subject.Request.parse(value)
            paths = {"fixtureReceipt": original_path, "basePackage": base,
                     "targetPackage": target, "bundleManifest": bundle_path}
            fixture = {"sourceFingerprint": "f" * 64, "targetVersion": "2.2.0"}
            admitted = {"inputsVerified": True, "sourceSha": SOURCE, "guestRole": parsed.guest_role,
                        "artifactIds": dict(parsed.artifact_ids), "fixture": fixture}
            def captured(_, identifier, kind, source):
                key = next(key for key, item in parsed.artifact_ids.items() if item == identifier)
                return {"path": paths[key], "record": {}}
            with mock.patch.object(subject.acceptance, "_verified_artifact", side_effect=captured), \
                 mock.patch.object(subject.acceptance, "_fixture", return_value=fixture), \
                 mock.patch.object(subject.acceptance, "_bundle"), \
                 mock.patch.object(subject, "_tracked_bytes", side_effect=lambda _, __, relative: (root / relative).read_bytes()):
                raw, manifest = subject.transfer_bundle(root, parsed, admitted)
                with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
                    names = set(archive.getnames())
                    self.assertIn("guest/fixture/packages/target/target.deb", names)
                    self.assertNotIn("guest/worker-intent.json", names)
                    self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(),
                        manifest["files"]["guest/target.deb"]["sha256"])
                target.write_bytes(b"changed")
                with self.assertRaisesRegex(subject.GuestPreparationError, "bytes differ"):
                    subject.transfer_bundle(root, parsed, admitted)

    def test_worker_intent_requires_guest_trust_for_update(self):
        parsed = subject.Request.parse(request())
        fixture = {"sourceFingerprint": "f" * 64, "targetVersion": "2.2.0"}
        with self.assertRaisesRegex(subject.GuestPreparationError, "trust binding"):
            subject.worker_intent_bytes(parsed, fixture, None, "2" * 64)
        raw = subject.worker_intent_bytes(parsed, fixture, "1" * 64, "2" * 64)
        self.assertEqual("1" * 64, json.loads(raw)["trustStoreSha256"])
        self.assertEqual("2" * 64, json.loads(raw)["harnessSha256"])
        self.assertTrue(raw.endswith(b"\n"))

    def test_only_fixed_roles_and_artifact_keys_are_accepted(self):
        self.assertEqual("ubuntu-update", subject.Request.parse(request()).guest_role)
        self.assertEqual("arch-rollback", subject.Request.parse(
            request("arch-rollback", "arch")).guest_role)
        for bad in (request("arch-rollback", "ubuntu"),
                    {**request(), "profile": ["package-update"]},
                    {**request(), "command": "true"},
                    {**request(), "artifactIds": {"targetPackage": "sha256-" + "d" * 64}}):
            with self.subTest(bad=bad), self.assertRaises(subject.GuestPreparationError):
                subject.Request.parse(bad)

    def test_dirty_source_freeze_blocks_before_guest_preflight_claim(self):
        parsed = subject.Request.parse(request())
        with tempfile.TemporaryDirectory() as temporary:
            first = mock.Mock(returncode=0, stdout=SOURCE + "\n")
            second = mock.Mock(returncode=0, stdout=" M scripts/test_linux_public_install.py\n")
            with mock.patch.object(subject.subprocess, "run", side_effect=[first, second]), \
                 mock.patch.object(subject.acceptance, "_verified_artifact", return_value={"record": {}, "path": Path(temporary)}), \
                 mock.patch.object(subject.acceptance, "_fixture", return_value={"sourceFingerprint": "f" * 64}), \
                 mock.patch.object(subject.acceptance, "_bundle"):
                with self.assertRaisesRegex(subject.GuestPreparationError, "dirty"):
                    subject.preflight(temporary, parsed)
                command = subject.subprocess.run.call_args.args[0]
                self.assertIn("--no-optional-locks", command)
                self.assertIn("core.fsmonitor=false", command)
                self.assertIn("core.untrackedCache=false", command)

    def test_update_receipt_binds_exact_qemu_source_base_and_server(self):
        parsed = subject.Request.parse(request())
        value, fixture, guest = receipt(parsed)
        self.assertEqual(value, subject.validate_receipt(parsed, value, fixture, guest,
            guest_manifest_artifact_id="sha256-" + "6" * 64,
            worker_intent_sha256="7" * 64, native_worker_sha256="9" * 64,
            rollback_worker_sha256="a" * 64))
        for changed in ({**value, "qemu": {**value["qemu"], "startTicks": 201}},
                        {**value, "baseline": {**value["baseline"],
                                                "installedPackageSha256": "0" * 64}},
                        {**value, "fixture": {**value["fixture"], "serverPid": None}},
                        {**value, "stage": "/home/vpnfixture/.parity-ubuntu-update"}):
            with self.subTest(changed=changed), self.assertRaises(subject.GuestPreparationError):
                subject.validate_receipt(parsed, changed, fixture, guest,
                    guest_manifest_artifact_id="sha256-" + "6" * 64,
                    worker_intent_sha256="7" * 64, native_worker_sha256="9" * 64,
                    rollback_worker_sha256="a" * 64)

    def test_fresh_deb_requires_clean_absent_baseline_without_server(self):
        parsed = subject.Request.parse(request("fresh-deb-dependencies", "ubuntu"))
        value, fixture, guest = receipt(parsed, fresh=True)
        self.assertEqual(value, subject.validate_receipt(parsed, value, fixture, guest,
            guest_manifest_artifact_id="sha256-" + "6" * 64,
            worker_intent_sha256="7" * 64, native_worker_sha256="9" * 64,
            rollback_worker_sha256="a" * 64))
        with self.assertRaisesRegex(subject.GuestPreparationError, "not clean"):
            subject.validate_receipt(parsed, {**value, "fixture": {}}, fixture, guest,
                guest_manifest_artifact_id="sha256-" + "6" * 64,
                worker_intent_sha256="7" * 64, native_worker_sha256="9" * 64,
                rollback_worker_sha256="a" * 64)

    def test_start_journals_before_driver_effect_and_never_replays_unknown(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            driver = mock.Mock()
            def interrupted(parsed, admitted):
                record = subject._read(root, parsed.correlation_id)
                self.assertEqual(parsed.public_mapping(), record)
                self.assertEqual(True, admitted["inputsVerified"])
                raise TimeoutError("response lost")
            driver.submit.side_effect = interrupted
            adapter = subject.Adapter(root, driver=driver)
            with mock.patch.object(subject, "preflight", return_value={"inputsVerified": True}):
                self.assertEqual("unknown", adapter.start(request())["state"])
                self.assertEqual("unknown", adapter.start(request())["state"])
            self.assertEqual(1, driver.submit.call_count)

    def test_unimplemented_executor_and_unverified_ready_never_claim_guest_ready(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(subject, "preflight", return_value={"inputsVerified": True}):
                blocked = subject.Adapter(root).start(request())
            self.assertEqual("blocked", blocked["state"])
            self.assertIsNone(subject._read(root, CORRELATION))
            subject._save(root, subject.Request.parse(request()).public_mapping())
            driver = mock.Mock()
            driver.status.return_value = {"state": "ready", "correlationId": CORRELATION,
                "sourceSha": SOURCE, "guestRole": "ubuntu-update",
                "artifactIds": request()["artifactIds"]}
            self.assertEqual("unknown", subject.Adapter(root, driver=driver).status(CORRELATION)["state"])

    def test_only_live_verified_registered_ids_promote_ready(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parsed = subject.Request.parse(request())
            self.assertTrue(subject._claim_role(root, parsed))
            subject._save(root, parsed.public_mapping())
            driver = mock.Mock()
            basic = {"state": "ready", "correlationId": CORRELATION,
                     "sourceSha": SOURCE, "guestRole": parsed.guest_role,
                     "artifactIds": dict(parsed.artifact_ids),
                     "guestManifestArtifactId": "sha256-" + "1" * 64,
                     "preparationReceiptArtifactId": "sha256-" + "2" * 64}
            driver.status.return_value = basic
            self.assertEqual("unknown", subject.Adapter(root, driver=driver).status(CORRELATION)["state"])
            driver.status.return_value = {**basic, "liveReady": True}
            self.assertEqual({"state": "ready", "correlationId": CORRELATION,
                              "guestManifestArtifactId": "sha256-" + "1" * 64,
                              "preparationReceiptArtifactId": "sha256-" + "2" * 64,
                              "replayAllowed": False},
                             subject.Adapter(root, driver=driver).status(CORRELATION))
            driver.status.return_value = {**basic, "state": "unknown",
                "phase": "staging-guest", "reason": "worker-exited-or-unreadable"}
            observed = subject.Adapter(root, driver=driver).status(CORRELATION)
            self.assertEqual("unknown", observed["state"])
            self.assertEqual("staging-guest", observed["phase"])
            self.assertFalse(observed["replayAllowed"])

    def test_journal_rejects_symlinked_private_ancestor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            foreign = Path(temporary) / "foreign"
            foreign.mkdir(mode=0o700)
            (root / ".rag_index").symlink_to(foreign, target_is_directory=True)
            with self.assertRaisesRegex(subject.GuestPreparationError, "unsafe"):
                subject._save(root, subject.Request.parse(request()).public_mapping())
            self.assertEqual([], list(foreign.iterdir()))

    def test_distinct_correlations_cannot_start_one_fixed_guest_role_concurrently(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            driver = mock.Mock()
            driver.submit.side_effect = lambda parsed, _: {"state": "submitted",
                "correlationId": parsed.correlation_id}
            adapter = subject.Adapter(root, driver=driver)
            gate = threading.Barrier(2)
            values = [request(), {**request(),
                "correlationId": "87654321-4321-4321-4321-cba987654321"}]
            results = []
            def run(value):
                gate.wait(timeout=3)
                results.append(adapter.start(value))
            with mock.patch.object(subject, "preflight", return_value={"inputsVerified": True}):
                workers = [threading.Thread(target=run, args=(value,)) for value in values]
                for worker in workers: worker.start()
                for worker in workers: worker.join(timeout=3)
            self.assertTrue(all(not worker.is_alive() for worker in workers))
            self.assertEqual(1, driver.submit.call_count)
            self.assertEqual(["blocked", "submitted"], sorted(item["state"] for item in results))

    def test_scoped_receipt_filters_other_families_and_binds_raw_original(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base, target = root / "base.deb", root / "target.deb"
            base.write_bytes(b"base package")
            target.write_bytes(b"target package")
            def asset(path, kind):
                return {"packageType": kind, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                        "sizeBytes": path.stat().st_size}
            original = {"schemaVersion": 1, "sourceFingerprint": "f" * 64,
                "builds": [{"label": "base", "assets": [asset(base, "deb"), {"packageType": "rpm"}]},
                           {"label": "target", "assets": [asset(target, "deb"), {"packageType": "rpm"}]}],
                "manifest": {"assets": [asset(target, "deb"), {"packageType": "rpm"}]}}
            raw = json.dumps(original, indent=2).encode()
            parsed = subject.Request.parse(request())
            parsed = subject.Request.parse({**request(), "artifactIds": {
                **request()["artifactIds"],
                "fixtureReceipt": "sha256-" + hashlib.sha256(raw).hexdigest(),
                "basePackage": "sha256-" + asset(base, "deb")["sha256"],
                "targetPackage": "sha256-" + asset(target, "deb")["sha256"]}})
            scoped = subject.scoped_fixture_receipt(parsed, raw,
                {"basePackage": base, "targetPackage": target})
            self.assertEqual(["deb"], [item["packageType"] for item in scoped["manifest"]["assets"]])
            self.assertEqual(parsed.artifact_ids["fixtureReceipt"],
                             scoped["derivedFrom"]["derivedFromArtifactId"])
            with self.assertRaisesRegex(subject.GuestPreparationError, "original receipt bytes differ"):
                subject.scoped_fixture_receipt(parsed, raw + b" ",
                    {"basePackage": base, "targetPackage": target})

    def test_arch_bundle_rejects_traversal_before_root_extraction(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "base.tar.gz"
            installer = b"#!/bin/sh\nexit 0\n"
            with tarfile.open(path, "w:gz") as archive:
                for name, data in (("vpn-control-arch-update/install.sh", installer),
                                   ("vpn-control-arch-update/app/bin/vpn-control", b"launcher"),
                                   ("vpn-control-arch-update/sing-box", b"runtime"),
                                   ("vpn-control-arch-update/../../etc/shadow", b"unsafe")):
                    entry = tarfile.TarInfo(name)
                    entry.size = len(data)
                    archive.addfile(entry, io.BytesIO(data))
            with self.assertRaisesRegex(subject.GuestPreparationError, "member is unsafe"):
                subject.inspect_arch_base_bundle(path, hashlib.sha256(path.read_bytes()).hexdigest(),
                    hashlib.sha256(installer).hexdigest())
            with tarfile.open(path, "w:gz") as archive:
                for name, data in (("vpn-control-arch-update/install.sh", installer),
                                   ("vpn-control-arch-update/app/bin/vpn-control", b"launcher"),
                                   ("vpn-control-arch-update/sing-box", b"runtime")):
                    entry = tarfile.TarInfo(name)
                    entry.size = len(data)
                    archive.addfile(entry, io.BytesIO(data))
            admitted = subject.inspect_arch_base_bundle(path,
                hashlib.sha256(path.read_bytes()).hexdigest(), hashlib.sha256(installer).hexdigest())
            self.assertEqual(3, admitted["memberCount"])


if __name__ == "__main__":
    unittest.main()

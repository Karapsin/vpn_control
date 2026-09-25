import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from agent_tools import native_vm_baseline as baseline
from agent_tools import native_vm_baseline_config as config


@unittest.skipIf(os.name != "posix", "private VM proof files require POSIX")
class ConfiguredBaselineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source_root = self.root / "vms"
        self.source_root.mkdir(mode=0o700)
        self.source = self.source_root / "fixture.qcow2"
        self.source.write_bytes(b"qcow fixture")
        self.proof_root = self.root / "proofs"
        self.proof_root.mkdir(mode=0o700)
        self.source_sha = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.identity = {"schemaVersion": 1, "sourceId": "linux-one",
                         "generation": "generation-one", "sourceSha256": self.source_sha}
        self.access_evidence = self.proof_root / "access-evidence.json"
        self.dependency_evidence = self.proof_root / "dependency-evidence.json"
        self.access_evidence.write_bytes(b'{"verified":"access"}')
        self.dependency_evidence.write_bytes(b'{"verified":"dependency"}')
        self.fingerprint = {"runtime": "a" * 64}
        access = {**self.identity, "state": "ready", "evidencePath": str(self.access_evidence),
                  "evidenceSha256": hashlib.sha256(self.access_evidence.read_bytes()).hexdigest()}
        dependency = {**self.identity, "state": "ready", "evidencePath": str(self.dependency_evidence),
                      "evidenceSha256": hashlib.sha256(self.dependency_evidence.read_bytes()).hexdigest(),
                      "fingerprint": self.fingerprint}
        job = {**self.identity, "state": "none"}
        self.access_path = self.proof_root / "access.json"
        self.dependency_path = self.proof_root / "dependency.json"
        self.job_path = self.proof_root / "job.json"
        self.prep_path = self.proof_root / "preparation.json"
        self.write(self.access_path, access)
        self.write(self.dependency_path, dependency)
        self.write(self.job_path, job)
        self.write_prep()
        self.entry = {"provider": "qemu", "sourceRoot": str(self.source_root),
                      "sourcePath": str(self.source), "generation": "generation-one",
                      "providerName": "linux-one", "preparationReceiptPath": str(self.prep_path),
                      "accessReceiptPath": str(self.access_path),
                      "dependencyReceiptPath": str(self.dependency_path),
                      "installerJobReceiptPath": str(self.job_path)}
        self.inventory = {"schemaVersion": 1, "hosts": {}, "nativeBaselines":
                          {"schemaVersion": 1, "sources": {"linux-one": self.entry}}}
        self.inventory_path = self.root / ".vm-hosts.local.json"
        self.write(self.inventory_path, self.inventory)
        self.stopped = mock.patch.object(config, "_fixed_qemu_stopped", return_value=True)
        self.flat = mock.patch.object(baseline.QemuProvider, "inspect_flat_qcow2", return_value=None)
        self.stopped.start(); self.flat.start()
        self.addCleanup(self.stopped.stop); self.addCleanup(self.flat.stop)

    def write(self, path, value):
        path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
        os.chmod(path, 0o600)

    def write_prep(self):
        self.write(self.prep_path, {**self.identity, "provider": "qemu", "sourcePath": str(self.source),
                                    "accessReceiptSha256": hashlib.sha256(self.access_path.read_bytes()).hexdigest(),
                                    "dependencyReceiptSha256": hashlib.sha256(self.dependency_path.read_bytes()).hexdigest(),
                                    "installerJobReceiptSha256": hashlib.sha256(self.job_path.read_bytes()).hexdigest()})

    def preflight(self):
        return config.handle(self.root, "baseline-preflight", {"provider": "qemu", "sourceId": "linux-one"})

    def test_preflight_and_missing_verify_do_not_create_baseline_store(self):
        store = self.root / ".rag_index" / "native-vm-baselines"
        self.assertFalse(store.exists())
        self.assertTrue(self.preflight()["ready"])
        self.assertFalse(store.exists())
        with self.assertRaises(baseline.VmBaselineError):
            config.handle(self.root, "baseline-verify", {"manifest": {"version": 1}})
        self.assertFalse(store.exists())

    def test_configured_preflight_capture_verify_and_restore(self):
        self.assertTrue(self.preflight()["ready"])
        manifest = config.handle(self.root, "baseline-capture", {"provider": "qemu", "sourceId": "linux-one",
                                                                 "baseline": "base-one", "generation": "generation-one"})
        self.assertEqual(self.source.read_bytes(), Path(manifest["baselinePath"]).read_bytes())
        self.assertEqual(manifest, config.handle(self.root, "baseline-verify", {"manifest": manifest}))
        def overlay(provider, backing, dest):
            self.assertEqual(str(backing), manifest["baselinePath"])
            dest.write_bytes(b"overlay")
        with mock.patch.object(baseline.QemuProvider, "overlay", overlay):
            restored = config.handle(self.root, "baseline-restore",
                                     {"manifest": manifest, "destination": "run-one"})
        self.assertEqual(b"overlay", Path(restored["path"]).read_bytes())

    def test_missing_or_changed_proofs_fail_closed(self):
        self.access_evidence.write_bytes(b"changed")
        with self.assertRaises(config.BaselineConfigError):
            self.preflight()
        self.access_evidence.write_bytes(b'{"verified":"access"}')
        self.dependency_path.write_bytes(b"{}")
        with self.assertRaises(config.BaselineConfigError):
            self.preflight()

    def test_unknown_job_and_live_pid_block(self):
        job = {**self.identity, "state": "unknown"}
        self.write(self.job_path, job)
        self.write_prep()
        with self.assertRaises(config.BaselineConfigError):
            self.preflight()
        job = {**self.identity, "state": "terminal", "pid": os.getpid(), "exitCode": 0}
        self.write(self.job_path, job)
        self.write_prep()
        with self.assertRaises(config.BaselineConfigError):
            self.preflight()

    def test_running_or_unobservable_provider_blocks(self):
        with mock.patch.object(config, "_fixed_qemu_stopped", return_value=False):
            with self.assertRaises(config.BaselineConfigError):
                self.preflight()
        with mock.patch.object(config, "_fixed_qemu_stopped", side_effect=config.BaselineConfigError("unknown")):
            with self.assertRaises(config.BaselineConfigError):
                self.preflight()

    def test_source_generation_and_bytes_are_bound(self):
        self.source.write_bytes(b"changed")
        with self.assertRaises(config.BaselineConfigError):
            self.preflight()
        self.source.write_bytes(b"qcow fixture")
        self.entry["generation"] = "generation-two"
        self.write(self.inventory_path, self.inventory)
        with self.assertRaises(config.BaselineConfigError):
            self.preflight()

    def test_inventory_is_private_and_rejects_arbitrary_inputs(self):
        os.chmod(self.inventory_path, 0o644)
        with self.assertRaises(config.BaselineConfigError):
            self.preflight()
        os.chmod(self.inventory_path, 0o600)
        with self.assertRaises(config.BaselineConfigError):
            config.handle(self.root, "baseline-capture", {"provider": "qemu", "sourceId": "linux-one",
                                                          "baseline": "base-one", "generation": "generation-one",
                                                          "stopped": True})
        with self.assertRaises(baseline.VmBaselineError):
            config.handle(self.root, "baseline-capture", {"provider": "qemu", "sourceId": "unknown-one",
                                                          "baseline": "base-one", "generation": "generation-one"})

    def test_symlinked_receipt_is_rejected(self):
        original = self.access_path
        link = self.proof_root / "access-link.json"
        link.symlink_to(original)
        self.entry["accessReceiptPath"] = str(link)
        self.write(self.inventory_path, self.inventory)
        with self.assertRaises(config.BaselineConfigError):
            self.preflight()

    def test_qemu_observation_allows_unrelated_open_disk_and_blocks_exact_inode(self):
        self.stopped.stop()
        other = self.source_root / "other.qcow2"
        other.write_bytes(b"other")
        def process(command, **kwargs):
            response = mock.Mock(returncode=0, stderr=b"")
            if command == ("ps", "-axo", "pid=,comm="):
                response.stdout = b"123 /usr/bin/qemu-system-x86_64\n"
            elif command == ("ps", "-p", "123", "-o", "lstart="):
                response.stdout = b"Fri Sep 25 11:00:00 2026\n"
            elif command == ("lsof", "-Fpn", "-p", "123"):
                response.stdout = ("p123\nn" + str(other) + "\n").encode()
            else:
                raise AssertionError(command)
            return response
        with mock.patch.object(config.sys, "platform", "darwin"), mock.patch.object(config.subprocess, "run", side_effect=process):
            self.assertTrue(config._fixed_qemu_stopped(self.source))
        def attached(command, **kwargs):
            response = process(command, **kwargs)
            if command == ("lsof", "-Fpn", "-p", "123"):
                response.stdout = ("p123\nn" + str(self.source) + "\n").encode()
            return response
        with mock.patch.object(config.sys, "platform", "darwin"), mock.patch.object(config.subprocess, "run", side_effect=attached):
            self.assertFalse(config._fixed_qemu_stopped(self.source))

    def test_configured_tart_preflight_uses_stopped_listing_and_tree_hash(self):
        tart_source = self.source_root / "mac-fixture"
        tart_source.mkdir()
        (tart_source / "disk.img").write_bytes(b"tart disk")
        self.source = tart_source
        self.source_sha = baseline._tree_hash(tart_source)
        self.identity["sourceSha256"] = self.source_sha
        for path in (self.access_path, self.dependency_path, self.job_path):
            record = json.loads(path.read_text(encoding="utf-8"))
            record["sourceSha256"] = self.source_sha
            self.write(path, record)
        self.write_prep()
        prep = json.loads(self.prep_path.read_text(encoding="utf-8"))
        prep["provider"] = "tart"
        prep["sourcePath"] = str(tart_source)
        self.write(self.prep_path, prep)
        self.entry.update(provider="tart", sourcePath=str(tart_source), providerName="mac-fixture")
        self.write(self.inventory_path, self.inventory)
        with mock.patch.object(config, "_fixed_tart_stopped", return_value=True) as stopped:
            result = config.handle(self.root, "baseline-preflight", {"provider": "tart", "sourceId": "linux-one"})
        self.assertTrue(result["ready"])
        self.assertEqual(self.source_sha, result["sourceSha256"])
        stopped.assert_called_once_with("mac-fixture")

    def test_tart_listing_exact_stopped_name(self):
        with mock.patch.object(config.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = b'[{"Name":"fixture","State":"stopped"}]'
            self.assertTrue(config._fixed_tart_stopped("fixture"))
            run.return_value.stdout = b'[{"Name":"fixture","State":"running"}]'
            self.assertFalse(config._fixed_tart_stopped("fixture"))
            run.return_value.stdout = b'[{"Name":"other","State":"stopped"}]'
            with self.assertRaises(config.BaselineConfigError):
                config._fixed_tart_stopped("fixture")


if __name__ == "__main__":
    unittest.main()


class PortableConfigValidationTests(unittest.TestCase):
    def test_digest_parser(self):
        self.assertEqual("a" * 64, config._sha("a" * 64, "test"))
        with self.assertRaises(config.BaselineConfigError):
            config._sha("", "test")

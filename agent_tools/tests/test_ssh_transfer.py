"""Causal regressions for fixed desktop fixture SSH publication."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest import mock

from agent_tools import ssh_transfer


@unittest.skipIf(os.name == "nt", "local OpenSSH receiver simulation needs POSIX shell")
class SshTransferTest(unittest.TestCase):
    def make_stage(self, root: Path) -> Path:
        stage = root / "stage"; stage.mkdir()
        hashes = {}
        for name in ssh_transfer.CANONICAL_HELPERS:
            contents = (ssh_transfer.SCRIPTS_ROOT / name).read_bytes()
            (stage / name).write_bytes(contents); hashes[name] = hashlib.sha256(contents).hexdigest()
        (stage / ssh_transfer.MANIFEST_NAME).write_bytes(
            "".join(f"{hashes[name]}  {name}\n" for name in sorted(hashes)).encode())
        return stage

    def make_config(self, root: Path, destination: Path, *, resolve_path: bool = True) -> None:
        path = root / ".vm-hosts.local.json"
        path.write_text(json.dumps({"schemaVersion": 1, "hosts": {"fixture": {
            "host": "local.test", "port": 22, "user": "tester", "identityFile": "/tmp/key",
            "knownHostsFile": "/tmp/known", "fixtureTransferRoot": str(destination.resolve() if resolve_path else destination),
        }}}), encoding="utf-8")
        path.chmod(0o600)

    def fake_ssh(self, root: Path, body: str = 'exec /bin/sh -c "$last"\n') -> Path:
        command = root / "fake-ssh"
        command.write_text("#!/bin/sh\nlast=\nfor value in \"$@\"; do last=$value; done\n" + body, encoding="utf-8")
        command.chmod(0o700)
        return command

    def publish(self, root: Path, stage: Path, destination: Path, correlation: str = "transfer-1", *, ssh: Path | None = None):
        return ssh_transfer.publish(root, "fixture", stage, "owner-1", "arch-ci", correlation,
                                    timeout_seconds=3, ssh_binary=str(ssh or self.fake_ssh(root)))

    def identity(self, stage: Path, correlation: str = "transfer-1") -> dict[str, str]:
        return ssh_transfer._capture_source(stage, "owner-1", "arch-ci", correlation).identity.as_dict()

    def test_tampered_source_rejects_before_ssh_or_intent_reservation(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); destination = root / "remote"; destination.mkdir(mode=0o700)
            stage = self.make_stage(root); self.make_config(root, destination)
            (stage / "fixture_environment.py").write_text("tampered\n", encoding="utf-8")
            with mock.patch.object(ssh_transfer.subprocess, "run") as run:
                with self.assertRaisesRegex(ssh_transfer.SshTransferError, "differs from checked-in"):
                    self.publish(root, stage, destination)
            run.assert_not_called()
            self.assertFalse((root / ".rag_index" / "ssh-transfer-receipts").exists())

    def test_payload_uses_the_verified_captured_bytes_not_a_second_source_read(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); stage = self.make_stage(root)
            captured = ssh_transfer._capture_source(stage, "owner-1", "arch-ci", "transfer-1")
            original = captured.contents["fixture_environment.py"]
            (stage / "fixture_environment.py").write_bytes(b"changed after capture\n")
            header, body = ssh_transfer._payload(captured).split(b"\n", 1)
            self.assertEqual(1, json.loads(header)["schema"])
            offset = 0
            for item in json.loads(header)["files"]:
                data = body[offset:offset + item["size"]]; offset += item["size"]
                if item["name"] == "fixture_environment.py":
                    self.assertEqual(original, data)
            self.assertEqual(len(body), offset)

    def test_remote_pipe_error_is_structured_as_unknown(self):
        with mock.patch.object(ssh_transfer.select, "select", side_effect=OSError("pipe failed")):
            with self.assertRaisesRegex(ssh_transfer.SshTransferError, "ssh_io_error"):
                ssh_transfer._bounded_run(["/bin/sh", "-c", "sleep 1"], None, 1)

    def test_existing_remote_correlation_refuses_without_overwrite(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); destination = root / "remote"; destination.mkdir(mode=0o700)
            stage = self.make_stage(root); self.make_config(root, destination)
            existing = destination / "arch-ci" / "owner-1" / "transfer-1"
            existing.mkdir(parents=True, mode=0o700)
            for directory in (existing.parent.parent, existing.parent, existing): directory.chmod(0o700)
            sentinel = existing / "keep"; sentinel.write_text("existing fixture", encoding="utf-8")
            result = self.publish(root, stage, destination)
            self.assertEqual((False, "unknown", "interrupted_or_unverified"),
                             (result["ok"], result["state"], result["reason"]))
            self.assertEqual("existing fixture", sentinel.read_text(encoding="utf-8"))

    def test_interrupted_stream_keeps_durable_identity_and_status_never_replays(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); destination = root / "remote"; destination.mkdir(mode=0o700)
            stage = self.make_stage(root); self.make_config(root, destination)
            interrupted = self.fake_ssh(root, 'head -c 1 >/dev/null\nexit 255\n')
            result = self.publish(root, stage, destination, ssh=interrupted)
            self.assertEqual((False, "unknown"), (result["ok"], result["state"]))
            self.assertEqual("ssh_transport_unavailable", result["reason"])
            disconnected = ssh_transfer.status(root, "fixture", result["identity"], timeout_seconds=3,
                                                ssh_binary=str(interrupted))
            self.assertEqual("ssh_transport_unavailable", disconnected["reason"])
            self.assertEqual(result["identity"], disconnected["identity"])
            intent = Path(result["intentPath"])
            self.assertEqual(0o600, stat.S_IMODE(intent.stat().st_mode))
            self.assertEqual(result["identity"], json.loads(intent.read_text(encoding="utf-8"))["identity"])
            observed = ssh_transfer.status(root, "fixture", result["identity"], timeout_seconds=3,
                                           ssh_binary=str(self.fake_ssh(root)))
            self.assertEqual((False, "unknown", "not_published"),
                             (observed["ok"], observed["state"], observed["reason"]))
            duplicate = self.publish(root, stage, destination, ssh=self.fake_ssh(root))
            self.assertEqual((False, "unknown"), (duplicate["ok"], duplicate["state"]))
            self.assertIn("durable local receipt", duplicate["reason"])

    def test_forged_receipt_with_matching_identity_but_no_verified_hashes_stays_unknown(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); destination = root / "remote"; destination.mkdir(mode=0o700)
            stage = self.make_stage(root); self.make_config(root, destination)
            identity = self.identity(stage)
            ssh_transfer._private_intent(root, "fixture", destination.resolve(), ssh_transfer.TransferIdentity.from_mapping(identity),
                                         ssh_transfer._capture_source(stage, "owner-1", "arch-ci", "transfer-1").hashes)
            final = destination / "arch-ci" / "owner-1" / "transfer-1"
            final.mkdir(parents=True, mode=0o700)
            for directory in (final.parent.parent, final.parent, final): directory.chmod(0o700)
            forged = {"state": "published", "identity": identity, "hashes": {}}
            (final / "receipt.json").write_text(json.dumps(forged), encoding="utf-8")
            result = ssh_transfer.status(root, "fixture", identity, timeout_seconds=3, ssh_binary=str(self.fake_ssh(root)))
            self.assertEqual((False, "unknown", "invalid_receipt"), (result["ok"], result["state"], result["reason"]))

    def test_symlinked_remote_environment_parent_is_rejected_without_touching_target(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); destination = root / "remote"; destination.mkdir(mode=0o700)
            stage = self.make_stage(root); self.make_config(root, destination)
            protected = root / "protected"; protected.mkdir(mode=0o700)
            sentinel = protected / "keep"; sentinel.write_text("do not stage here", encoding="utf-8")
            (destination / "arch-ci").symlink_to(protected, target_is_directory=True)
            result = self.publish(root, stage, destination)
            self.assertEqual((False, "unknown"), (result["ok"], result["state"]))
            self.assertEqual("do not stage here", sentinel.read_text(encoding="utf-8"))

    def test_symlinked_ancestor_of_configured_root_is_rejected_without_touching_target(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); stage = self.make_stage(root)
            protected = root / "protected"; protected.mkdir(mode=0o700)
            sentinel = protected / "keep"; sentinel.write_text("do not stage here", encoding="utf-8")
            (root / "redirect").symlink_to(protected, target_is_directory=True)
            destination = root / "redirect" / "remote"
            self.make_config(root, destination, resolve_path=False)
            result = self.publish(root, stage, destination)
            self.assertEqual((False, "unknown"), (result["ok"], result["state"]))
            self.assertEqual("do not stage here", sentinel.read_text(encoding="utf-8"))
            self.assertFalse((protected / "remote").exists())

    def test_oversized_fake_ssh_output_is_bounded_and_never_claims_publish(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); destination = root / "remote"; destination.mkdir(mode=0o700)
            stage = self.make_stage(root); self.make_config(root, destination)
            noisy = self.fake_ssh(root, 'head -c 5000 /dev/zero\n')
            result = self.publish(root, stage, destination, ssh=noisy)
            self.assertEqual((False, "unknown", "oversized_remote_output"), (result["ok"], result["state"], result["reason"]))

    def test_fixed_receiver_publishes_only_verified_source_bytes_and_receipt(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); destination = root / "remote"; destination.mkdir(mode=0o700)
            stage = self.make_stage(root); self.make_config(root, destination)
            result = self.publish(root, stage, destination)
            self.assertTrue(result["ok"], result)
            final = destination / "arch-ci" / "owner-1" / "transfer-1"
            self.assertTrue((final / "receipt.json").is_file())
            self.assertEqual(result["sourceHashes"], result["destinationHashes"])
            for name in (*ssh_transfer.CANONICAL_HELPERS, ssh_transfer.MANIFEST_NAME):
                self.assertEqual((stage / name).read_bytes(), (final / name).read_bytes())
            observed = ssh_transfer.status(root, "fixture", result["identity"], timeout_seconds=3,
                                           ssh_binary=str(self.fake_ssh(root)))
            self.assertEqual((True, "published"), (observed["ok"], observed["state"]))

    def test_status_rejects_fifo_without_blocking(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); destination = root / "remote"; destination.mkdir(mode=0o700)
            stage = self.make_stage(root); self.make_config(root, destination)
            result = self.publish(root, stage, destination)
            self.assertTrue(result["ok"], result)
            helper = destination / "arch-ci" / "owner-1" / "transfer-1" / "fixture_environment.py"
            helper.unlink(); os.mkfifo(helper, 0o600)
            observed = ssh_transfer.status(root, "fixture", result["identity"], timeout_seconds=3,
                                           ssh_binary=str(self.fake_ssh(root)))
            self.assertEqual((False, "unknown", "invalid_receipt"),
                             (observed["ok"], observed["state"], observed["reason"]))


if __name__ == "__main__":
    unittest.main()

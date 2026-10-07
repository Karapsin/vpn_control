"""Durable no-replay boundaries for the host-only Android endpoint campaign."""

from __future__ import annotations

import json
import base64
import contextlib
import fcntl
import io
import hashlib
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from agent_tools import android_native_fixture as fixture
from agent_tools import android_native_fixture_lifecycle as lifecycle


CAMPAIGN = "704f816c-d672-4cbf-a73e-e31ca4bc303b"
OTHER = "fa04c82d-f86e-4c9d-ac7a-68c16c58bde2"
SOURCE = "a" * 40


class AndroidNativeFixtureLifecycleTest(unittest.TestCase):
    def _remote_namespace(self, root: Path) -> dict:
        namespace = {"__name__": "remote_test"}
        argv = ["remote", "invalid", str(root), "api35", CAMPAIGN, "a" * 64, "b" * 64, "c" * 64]
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                exec(lifecycle._REMOTE, namespace)
        return namespace

    def test_remote_process_identity_errors_are_unknown_not_absence(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            remote = self._remote_namespace(root)
            with mock.patch.object(Path, "read_text", side_effect=PermissionError("proc denied")), \
                 contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    remote["ticks"](123)
            with mock.patch.object(Path, "read_text", return_value="malformed"), \
                 contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    remote["ticks"](123)
            with mock.patch.object(Path, "read_text", side_effect=FileNotFoundError()), \
                 mock.patch.object(Path, "is_dir", return_value=True), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertIsNone(remote["ticks"](123))

    def test_remote_wrong_https_status_never_counts_as_traffic(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            remote = self._remote_namespace(root)
            job = root / ("android-native-fixture-" + CAMPAIGN); job.mkdir(mode=0o700)
            events = job / "events.jsonl"
            events.write_text(json.dumps({"campaignId": CAMPAIGN, "event": "epoch-start"}) + "\n" +
                              json.dumps({"campaignId": CAMPAIGN, "transport": "https", "path": "/traffic", "status": 404}) + "\n")
            events.chmod(0o600)
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    remote["counts"]()

    def test_remote_job_symlink_rejected_before_any_file_read(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            remote = self._remote_namespace(root)
            target = root / "target"; target.mkdir(mode=0o700)
            (root / ("android-native-fixture-" + CAMPAIGN)).symlink_to(target, target_is_directory=True)
            remote["read"] = mock.Mock(side_effect=AssertionError("followed job before validation"))
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    remote["observe"]()
            remote["read"].assert_not_called()

    def test_remote_private_read_rejects_same_length_replacement_between_lstat_and_open(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            remote = self._remote_namespace(root)
            victim = root / "ready.json"; victim.write_bytes(b"old!"); victim.chmod(0o600)
            original_open = os.open
            replaced = False
            def swap(path, flags, *args, **kwargs):
                nonlocal replaced
                if Path(path) == victim and not replaced:
                    replaced = True
                    victim.unlink()
                    victim.write_bytes(b"new!")
                    victim.chmod(0o600)
                return original_open(path, flags, *args, **kwargs)
            with mock.patch.object(os, "open", side_effect=swap), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    remote["read"](victim, 0o600)
            self.assertTrue(replaced)

    def test_remote_terminal_receipt_uses_pinned_job_directory(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            remote = self._remote_namespace(root)
            job = root / ("android-native-fixture-" + CAMPAIGN); job.mkdir(mode=0o700)
            content = {"fixture.py": b"fixture", "certificate.pem": b"certificate", "private-key.pem": b"key"}
            hashes = {name: hashlib.sha256(data).hexdigest() for name, data in content.items()}
            remote["source_hash"] = hashes["fixture.py"]
            remote["cert_hash"] = hashes["certificate.pem"]
            remote["key_hash"] = hashes["private-key.pem"]
            for name, data in content.items():
                path = job / name; path.write_bytes(data); path.chmod(0o600)
            intent = {"campaignId": CAMPAIGN, "device": "api35", "sourceSha256": remote["source_hash"],
                      "certificateSha256": remote["cert_hash"], "privateKeySha256": remote["key_hash"]}
            ready = {"campaignId": CAMPAIGN, "state": "running", "certificateSha256": remote["cert_hash"],
                     "endpoint": {"hostHttpsPort": 30001, "hostSocksPort": 30002}, "pid": 123, "startTicks": 1}
            counts = {"campaignId": CAMPAIGN, "socksConnected": 0, "socksRejected": 0,
                      "health": 0, "traffic": 0, "subscription": 0}
            for name, value in (("intent.json", intent), ("ready.json", ready),
                                ("stopped.json", {"campaignId": CAMPAIGN, "state": "stopped", "eventCounts": counts})):
                path = job / name; path.write_text(json.dumps(value)); path.chmod(0o600)
            events = job / "events.jsonl"
            events.write_text(json.dumps({"campaignId": CAMPAIGN, "event": "epoch-start"}) + "\n")
            events.chmod(0o600)
            remote["ticks"] = lambda _pid: None
            remote["read"] = mock.Mock(side_effect=AssertionError("terminal followed mutable parent"))
            observed = remote["observe"]()
            self.assertEqual("stopped", observed["state"])
            remote["read"].assert_not_called()

    def test_remote_failed_job_creation_does_not_strand_device_lease(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            (root / ("android-native-fixture-" + CAMPAIGN)).write_text("occupied")
            source, cert, key = b"fixture", b"certificate", b"key"
            hashes = [hashlib.sha256(value).hexdigest() for value in (source, cert, key)]
            payload = json.dumps({"source": base64.b64encode(source).decode(),
                                  "certificate": base64.b64encode(cert).decode(),
                                  "privateKey": base64.b64encode(key).decode()}).encode()
            command = [sys.executable, "-c", "exec(" + repr(lifecycle._REMOTE) + ")", "start", str(root),
                       "api35", CAMPAIGN, *hashes]
            result = subprocess.run(command, input=payload, capture_output=True, timeout=5)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("submission_uncertain", json.loads(result.stdout)["reason"])
            self.assertFalse((root / "android-native-fixture-api35.lease").exists())

    def test_remote_stop_rechecks_generation_after_pidfd_before_signal(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            remote = self._remote_namespace(root)
            remote["ticks"] = lambda _pid: 99
            with mock.patch.object(os, "pidfd_open", return_value=17, create=True), \
                 mock.patch.object(signal, "pidfd_send_signal", create=True) as send, \
                 mock.patch.object(os, "close"), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    remote["signal_exact"](123, 42)
            send.assert_not_called()

    def test_start_journals_before_one_remote_submission_and_second_campaign_is_blocked(self):
        configured = SimpleNamespace(android_devices={"api35": {}}, fixture_transfer_root=Path("/private/fixtures"))
        config = SimpleNamespace(hosts={"archlinux": configured})
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as raw:
            root = Path(raw); root.chmod(0o700)
            plan = {"sourceSha": SOURCE, "baseArtifactId": fixture.BASE_ARTIFACT_ID,
                    "deviceMutationAllowed": False}
            plan_path = root / "plan.json"
            fixture.write_private_plan(plan_path, plan)
            seen = []
            publication_order = []
            original_write = fixture.write_private_plan
            def ordered_write(path, value):
                publication_order.append(Path(path).name)
                return original_write(path, value)
            def submit(_root, host, action, device, campaign, source_hash, cert_hash, key_hash, payload):
                self.assertEqual("start", action)
                self.assertEqual(("archlinux", "api35", CAMPAIGN), (host, device, campaign))
                intent = lifecycle._read_plan(lifecycle._directory(root) / (campaign + ".json"))
                self.assertEqual(campaign, intent["campaignId"])
                self.assertEqual(campaign, lifecycle._read_plan(
                    lifecycle._directory(root) / "device-archlinux-api35.lease")["campaignId"])
                self.assertIn(b'"privateKey"', payload)
                seen.append(campaign)
                return {"state": "running", "campaignId": campaign,
                        "endpoint": {"hostHttpsPort": 30001, "hostSocksPort": 30002}}
            with mock.patch.object(lifecycle.ssh_transport, "load_config", return_value=config), \
                 mock.patch.object(lifecycle.ssh_transport, "connection_host", return_value=SimpleNamespace(password=None)), \
                 mock.patch.object(fixture, "prepare_requirements", return_value=plan), \
                 mock.patch.object(fixture, "_head", return_value=SOURCE), \
                 mock.patch.object(fixture, "_clean", return_value=True), \
                 mock.patch.object(fixture, "_stable_tls_bytes", side_effect=[(b"cert", (1,2,3,4)), (b"key", (1,3,3,4)),
                                                                            (b"cert", (1,2,3,4)), (b"key", (1,3,3,4))]), \
                 mock.patch.object(fixture, "write_private_plan", side_effect=ordered_write), \
                 mock.patch.object(lifecycle, "_remote", side_effect=submit):
                first = lifecycle.start(root, "archlinux", "api35", CAMPAIGN, plan_path, root / "cert", root / "key")
                self.assertTrue(first["ok"])
                self.assertFalse(first["installerTargetAdmitted"])
                self.assertFalse(first["deviceMutationAllowed"])
                with self.assertRaises(FileExistsError):
                    lifecycle.start(root, "archlinux", "api35", OTHER, plan_path, root / "cert", root / "key")
            self.assertEqual([CAMPAIGN], seen)
            self.assertLess(publication_order.index(CAMPAIGN + ".json"),
                            publication_order.index("device-archlinux-api35.lease"))

    def test_clean_linked_source_admits_dirty_coordinator_without_source_path_in_intent(self):
        configured = SimpleNamespace(android_devices={"api35": {}}, fixture_transfer_root=Path("/private/fixtures"))
        config = SimpleNamespace(hosts={"archlinux": configured})
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as raw:
            root = Path(raw); root.chmod(0o700)
            clean_source = root / "clean-source"; clean_source.mkdir()
            plan = {"sourceSha": SOURCE, "baseArtifactId": fixture.BASE_ARTIFACT_ID,
                    "deviceMutationAllowed": False}
            plan_path = root / "plan.json"
            fixture.write_private_plan(plan_path, plan)
            seen = []

            def submit(_root, _host, _action, _device, campaign, *_args):
                intent = lifecycle._read_plan(lifecycle._directory(root) / (campaign + ".json"))
                self.assertNotIn("sourceRoot", intent)
                self.assertNotIn(str(clean_source), json.dumps(intent, sort_keys=True))
                seen.append(campaign)
                return {"state": "running", "campaignId": campaign,
                        "endpoint": {"hostHttpsPort": 30001, "hostSocksPort": 30002}}

            with mock.patch.object(lifecycle.ssh_transport, "load_config", return_value=config), \
                    mock.patch.object(lifecycle.ssh_transport, "connection_host", return_value=SimpleNamespace(password=None)), \
                    mock.patch.object(fixture, "_source_root", return_value=clean_source) as bind, \
                    mock.patch.object(fixture, "prepare_requirements", return_value=plan) as prepare, \
                    mock.patch.object(fixture, "_head", side_effect=lambda path: SOURCE if path == clean_source else "dirty"), \
                    mock.patch.object(fixture, "_clean", side_effect=lambda path: path == clean_source), \
                    mock.patch.object(fixture, "_stable_tls_bytes", side_effect=[(b"cert", (1,2,3,4)), (b"key", (1,3,3,4))]), \
                    mock.patch.object(lifecycle, "_remote", side_effect=submit):
                observed = lifecycle.start(root, "archlinux", "api35", CAMPAIGN, plan_path,
                                           root / "cert", root / "key", source_root=clean_source)
            self.assertTrue(observed["ok"])
            self.assertEqual([CAMPAIGN], seen)
            bind.assert_called_once_with(root.resolve(), clean_source)
            prepare.assert_called_once_with(root.resolve(), SOURCE, fixture.BASE_ARTIFACT_ID,
                                            source_root=clean_source)

    def test_invalid_source_root_rejects_before_fixture_lease_or_remote_dispatch(self):
        configured = SimpleNamespace(android_devices={"api35": {}}, fixture_transfer_root=Path("/private/fixtures"))
        config = SimpleNamespace(hosts={"archlinux": configured})
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as raw:
            root = Path(raw); root.chmod(0o700)
            plan = {"sourceSha": SOURCE, "baseArtifactId": fixture.BASE_ARTIFACT_ID,
                    "deviceMutationAllowed": False}
            plan_path = root / "plan.json"
            fixture.write_private_plan(plan_path, plan)
            for source_error in (ValueError("foreign"), ValueError("dirty"), ValueError("symlink")):
                with self.subTest(source_error=str(source_error)), \
                        mock.patch.object(lifecycle.ssh_transport, "load_config", return_value=config), \
                        mock.patch.object(lifecycle.ssh_transport, "connection_host", return_value=SimpleNamespace(password=None)), \
                        mock.patch.object(fixture, "_source_root", side_effect=source_error), \
                        mock.patch.object(lifecycle, "_remote") as remote:
                    with self.assertRaises(ValueError):
                        lifecycle.start(root, "archlinux", "api35", CAMPAIGN, plan_path,
                                        root / "cert", root / "key", source_root=root / "source")
                    remote.assert_not_called()
                    self.assertFalse((root / ".rag_index" / "android-native-fixture-campaigns" /
                                      (CAMPAIGN + ".json")).exists())

    def test_changed_clean_source_sha_or_status_rejects_before_lease_write_or_dispatch(self):
        configured = SimpleNamespace(android_devices={"api35": {}}, fixture_transfer_root=Path("/private/fixtures"))
        config = SimpleNamespace(hosts={"archlinux": configured})
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as raw:
            root = Path(raw); root.chmod(0o700)
            clean_source = root / "clean-source"; clean_source.mkdir()
            plan = {"sourceSha": SOURCE, "baseArtifactId": fixture.BASE_ARTIFACT_ID,
                    "deviceMutationAllowed": False}
            plan_path = root / "plan.json"
            fixture.write_private_plan(plan_path, plan)
            for head, clean in (("b" * 40, True), (SOURCE, False)):
                with self.subTest(head=head, clean=clean), \
                        mock.patch.object(lifecycle.ssh_transport, "load_config", return_value=config), \
                        mock.patch.object(lifecycle.ssh_transport, "connection_host", return_value=SimpleNamespace(password=None)), \
                        mock.patch.object(fixture, "_source_root", return_value=clean_source), \
                        mock.patch.object(fixture, "prepare_requirements", return_value=plan), \
                        mock.patch.object(fixture, "_head", return_value=head), \
                        mock.patch.object(fixture, "_clean", return_value=clean), \
                        mock.patch.object(fixture, "_stable_tls_bytes", side_effect=[(b"cert", (1,2,3,4)), (b"key", (1,3,3,4))]), \
                        mock.patch.object(lifecycle, "_remote") as remote:
                    with self.assertRaisesRegex(ValueError, "source changed"):
                        lifecycle.start(root, "archlinux", "api35", CAMPAIGN, plan_path,
                                        root / "cert", root / "key", source_root=clean_source)
                    remote.assert_not_called()
                    self.assertFalse((root / ".rag_index" / "android-native-fixture-campaigns" /
                                      (CAMPAIGN + ".json")).exists())

    def test_unknown_status_preserves_correlation_and_lease(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as raw:
            root = Path(raw); root.chmod(0o700)
            directory = lifecycle._directory(root)
            fixture.write_private_plan(directory / (CAMPAIGN + ".json"), {
                "host": "archlinux", "device": "api35", "campaignId": CAMPAIGN,
                "sourceSha256": "a" * 64, "certificateSha256": "b" * 64, "privateKeySha256": "c" * 64})
            fixture.write_private_plan(directory / "device-archlinux-api35.lease", {"campaignId": CAMPAIGN})
            with mock.patch.object(lifecycle, "_remote", return_value={"state": "unknown", "campaignId": CAMPAIGN,
                                                                       "reason": "transport_uncertain"}):
                result = lifecycle.status(root, CAMPAIGN)
            self.assertFalse(result["ok"])
            self.assertFalse(result["replayAllowed"])
            self.assertTrue((directory / "device-archlinux-api35.lease").exists())

    def test_collect_requires_terminal_remote_receipt_then_releases_exact_lease(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as raw:
            root = Path(raw); root.chmod(0o700)
            directory = lifecycle._directory(root)
            fixture.write_private_plan(directory / (CAMPAIGN + ".json"), {
                "host": "archlinux", "device": "api35", "campaignId": CAMPAIGN,
                "sourceSha256": "a" * 64, "certificateSha256": "b" * 64, "privateKeySha256": "c" * 64})
            lease = directory / "device-archlinux-api35.lease"
            fixture.write_private_plan(lease, {"campaignId": CAMPAIGN})
            terminal = {"state": "stopped", "campaignId": CAMPAIGN, "collected": True,
                        "endpoint": {"hostHttpsPort": 30001, "hostSocksPort": 30002},
                        "eventCounts": {"socksConnected": 1}}
            with mock.patch.object(lifecycle, "status", return_value={"state": "stopped", "campaignId": CAMPAIGN}), \
                 mock.patch.object(lifecycle, "_remote", return_value=terminal), \
                 mock.patch.object(fcntl, "flock", wraps=fcntl.flock) as lock:
                self.assertTrue(lifecycle.collect(root, CAMPAIGN)["ok"])
                self.assertFalse(lease.exists())
                self.assertEqual(terminal["eventCounts"],
                                 lifecycle._read_plan(directory / (CAMPAIGN + "-collected.json"))["eventCounts"])
                self.assertTrue(lifecycle.collect(root, CAMPAIGN)["ok"])
            self.assertGreaterEqual(sum(call.args[1] == fcntl.LOCK_EX for call in lock.call_args_list), 2)

    def test_remote_payload_mismatch_cannot_claim_device(self):
        compile(lifecycle._REMOTE, "remote-fixture.py", "exec")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            command = [sys.executable, "-c", "exec(" + repr(lifecycle._REMOTE) + ")",
                       "start", str(root), "api35", CAMPAIGN, "a" * 64, "b" * 64, "c" * 64]
            completed = subprocess.run(command, input=b'{"source":"Zg==","certificate":"Yw==","privateKey":"aw=="}',
                                       capture_output=True, timeout=5)
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertEqual("payload_hash_mismatch", json.loads(completed.stdout)["reason"])
            self.assertFalse((root / "android-native-fixture-api35.lease").exists())


if __name__ == "__main__":
    unittest.main()

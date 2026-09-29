"""Causal guards for recovery of one uncertain API29 document job.

All tests use private temporary state and mocked host boundaries.  They never
connect to an emulator or submit a product action.
"""
from __future__ import annotations

import tempfile
import unittest
import json
import hashlib
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from agent_tools import android_document_recovery as subject


RECOVERY = "3d0a8494-d1c6-4d49-b8fd-e5f420966a28"
UNKNOWN = "a2879d55-ceaf-425a-ac66-96c59483d35e"
OPENING = "1188aa04-b019-46f6-acdd-dda493cbba6c"
CURRENT = "ef630f0b-b27d-440f-b5f9-a370ccf00e5f"
CLOSING = "f0dc5966-be10-4272-865e-4242fa06d3c4"
CLI_STAGE = "7af828db-f5e9-4fa7-bcbd-52b9c0f9a4d6"
OWNER = "9a0e0fc1-32c8-423c-8ea7-f99735ca907f"
SHA = "a" * 64
ARTIFACT = "sha256-" + SHA
OPENING_SHA = "4314a4e301d744b41f2a127dff92e8844713dc6eb8131627bb9c33f446289e95"
CURRENT_SHA = "2d2fa7e05e5ae32af77ef555ece33970876359845f4cca6b869ceb580c22b478"


def intent() -> dict:
    return {"host": "archlinux", "device": "api29", "correlationId": RECOVERY,
            "unknownDocumentCorrelationId": UNKNOWN,
            "openingReadbackCorrelationId": OPENING,
            "currentReadbackCorrelationId": CURRENT,
            "packageSha256": SHA, "expectedOwner": OWNER, "expectedRevision": 1,
            "openingRevision": 0, "openingBackupSha256": OPENING_SHA,
            "openingBackupSize": 239, "openingExportSha256": OPENING_SHA,
            "openingExportSize": 239, "currentBackupSha256": CURRENT_SHA,
            "currentBackupSize": 11_872_243,
            "fixtureRoot": "/fixture"}


def terminal_result() -> dict:
    return {"state": "complete", "sourcePackageSha256": SHA,
            "opening": {"sha256": OPENING_SHA, "size": 239},
            "current": {"sha256": CURRENT_SHA, "size": 11_872_243, "revision": 1},
            "restore": {"controllerId": OWNER, "revision": 2,
                        "rulesRestored": True, "runtimeOff": True,
                        "exportSha256": hashlib.sha256(b"restored").hexdigest(), "exportSize": 8},
            "replayAllowed": False}


def start(root: Path | str, *, owner: str = OWNER, revision: int = 0,
          unknown: str = UNKNOWN, opening: str = OPENING, current: str = CURRENT,
          recovery: str = RECOVERY) -> dict:
    return subject.start(root, "archlinux", "api29", recovery, unknown,
                         opening, current, ARTIFACT, CLI_STAGE, owner, revision)


def preserved_metadata_fixture(root: Path) -> tuple[str, str]:
    root.chmod(0o700)
    document = {"type": "vpn_control_routing_rules", "version": 7,
                "exported_at": "2026-09-29T00:00:00Z",
                "rules": {"ignore_rules": False, "block_quic_udp_443": False,
                          "proxy_packages": [], "direct_domain_suffixes": []}}
    first = json.dumps(document, separators=(",", ":")).encode()
    opening_bytes = first + b" " * (239 - len(first))
    document["exported_at"] = "2026-09-29T00:00:01Z"
    second = json.dumps(document, separators=(",", ":")).encode()
    readback_bytes = second + b" " * (239 - len(second))
    assert len(opening_bytes) == len(readback_bytes) == 239
    assert json.loads(opening_bytes)["rules"] == json.loads(readback_bytes)["rules"]
    opening_sha = hashlib.sha256(opening_bytes).hexdigest()
    readback_sha = hashlib.sha256(readback_bytes).hexdigest()
    assert opening_sha != readback_sha
    for folder, filename, payload in (("android-document-job-" + UNKNOWN,
                                       "opening-routing.json", opening_bytes),
                                      ("android-readback-" + OPENING,
                                       "routing.json", readback_bytes),
                                      ("android-readback-" + CURRENT,
                                       "routing.json", readback_bytes)):
        directory = root / folder
        directory.mkdir(mode=0o700)
        path = directory / filename
        path.write_bytes(payload); path.chmod(0o600)
    return opening_sha, readback_sha


def preserved_preflight(root: Path, expected_opening_sha: str, expected_current_sha: str) -> dict:
    command = [sys.executable, "-I", "-B", "-c",
               "exec(" + repr(subject._PRESERVED_PREFLIGHT) + ")",
               str(root), UNKNOWN, OPENING, CURRENT,
               expected_opening_sha, "239", expected_current_sha, "239"]
    done = subprocess.run(command, capture_output=True, check=True, timeout=10)
    observed = json.loads(done.stdout)
    assert "rules" not in done.stdout.decode()
    return observed


class AndroidDocumentRecoveryTest(unittest.TestCase):
    def test_preserved_preflight_reports_only_bounded_hashes_for_metadata_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            opening_sha, readback_sha = preserved_metadata_fixture(root)
            observed = preserved_preflight(root, opening_sha, opening_sha)
            self.assertFalse(observed["ready"])
            self.assertTrue(observed["semanticMatch"])
            self.assertEqual(observed["openingExport"], {"state": "verified_file",
                             "sha256": opening_sha, "size": 239, "validDocument": True})
            self.assertEqual(observed["openingReadback"], {"state": "verified_file",
                             "sha256": readback_sha, "size": 239,
                             "matchesExpected": False, "validDocument": True})
            self.assertEqual(observed["current"], {"state": "verified_file",
                             "sha256": readback_sha, "size": 239,
                             "matchesExpected": False, "validDocument": True})
            self.assertFalse(subject._journal(root, RECOVERY).exists())
            self.assertFalse(subject._reservation(root, UNKNOWN).exists())

    def test_preserved_preflight_accepts_semantically_equal_metadata_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            opening_sha, readback_sha = preserved_metadata_fixture(root)
            observed = preserved_preflight(root, readback_sha, readback_sha)
            self.assertTrue(observed["ready"])
            self.assertTrue(observed["semanticMatch"])
            self.assertNotEqual(observed["openingExport"]["sha256"],
                                observed["openingReadback"]["sha256"])
            self.assertEqual(observed["openingReadback"]["sha256"], readback_sha)
            self.assertEqual(observed["openingExport"]["sha256"], opening_sha)
            self.assertFalse(subject._journal(root, RECOVERY).exists())
            self.assertFalse(subject._reservation(root, UNKNOWN).exists())

    def test_preserved_preflight_rejects_persistent_rule_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, current_sha = preserved_metadata_fixture(root)
            opening_readback = root / ("android-readback-" + OPENING) / "routing.json"
            payload = opening_readback.read_bytes()
            self.assertIn(b'"block_quic_udp_443":false', payload)
            changed = payload.replace(b'"block_quic_udp_443":false',
                                      b'"block_quic_udp_443":true') + b" "
            self.assertEqual(len(changed), 239)
            opening_readback.write_bytes(changed)
            changed_sha = hashlib.sha256(changed).hexdigest()
            observed = preserved_preflight(root, changed_sha, current_sha)
            self.assertFalse(observed["ready"])
            self.assertFalse(observed["semanticMatch"])
            self.assertTrue(observed["openingReadback"]["matchesExpected"])
            self.assertTrue(observed["current"]["matchesExpected"])
            self.assertFalse(subject._journal(root, RECOVERY).exists())
            self.assertFalse(subject._reservation(root, UNKNOWN).exists())

    def test_start_rejects_non_239_byte_opening_backup_before_submission(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            subject.android_document_acceptance._claim_device(tmp, "archlinux", "api29", UNKNOWN)
            old = {"host": "archlinux", "device": "api29", "expectedOwner": OWNER,
                   "expectedRevision": 0, "packageSha256": SHA,
                   "cliStageCorrelationId": CLI_STAGE,
                   "cliPath": "/fixture/android-cli-stage-" + CLI_STAGE + "/tree/bin/vpn-control"}
            config = SimpleNamespace(hosts={"archlinux": SimpleNamespace(
                android_devices={"api29": {}}, fixture_transfer_root=Path("/fixture"))})
            stage = {"ok": True, "state": "published", "sourceSha": "f" * 40,
                     "receipt": {"cliPath": old["cliPath"], "manifestSha256": "e" * 64}}
            artifact = {"verification": "verified", "artifact": {"platform": "android",
                        "artifactKind": "apk", "sourceSha": "f" * 40, "sha256": SHA},
                        "location": {"localPath": "/verified.apk"}}
            opening = {"backup": {"sha256": OPENING_SHA, "size": 240}}
            current = {"backup": {"sha256": CURRENT_SHA, "size": 11_872_243}}
            with mock.patch.object(subject.android_document_acceptance, "_load", return_value=old), \
                    mock.patch.object(subject.android_document_acceptance, "status", return_value={
                        "state": "unknown", "reason": "command_failed",
                        "identity": {"pid": 123, "startTicks": 456}}), \
                    mock.patch.object(subject.ssh_transport, "load_config", return_value=config), \
                    mock.patch.object(subject.ssh_transport, "connection_host", return_value=SimpleNamespace(password=None)), \
                    mock.patch.object(subject.android_observation, "_profile", return_value={"api": 29,
                        "adb": "/adb", "serial": "emulator-1", "expectedAvd": "owned-api29"}), \
                    mock.patch.object(subject.native_artifact_registry, "verify_artifact", return_value=artifact), \
                    mock.patch.object(subject.subprocess, "run", return_value=SimpleNamespace(stdout="f" * 40 + "\n")), \
                    mock.patch.object(subject.android_package_install, "_inspect_apk"), \
                    mock.patch.object(subject.android_cli_stage, "status", return_value=stage), \
                    mock.patch.object(subject, "_readback", side_effect=[opening, current]), \
                    mock.patch.object(subject.ssh_transport, "build_ssh_argv", return_value=["mock-ssh"]) as remote, \
                    mock.patch.object(subject.android_observation, "_run_probe",
                                      return_value=(0, b'{"ready":true}')) as probe, \
                    mock.patch.object(subject, "_reserve") as reserve:
                with self.assertRaisesRegex(ValueError, "large import"):
                    start(tmp, revision=1)
                remote.assert_called_once()
                probe.assert_called_once()
                reserve.assert_not_called()

    def test_transport_unknown_original_is_not_recovery_permission(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            old = {"host": "archlinux", "device": "api29", "expectedOwner": OWNER,
                   "expectedRevision": 0}
            with mock.patch.object(subject.android_document_acceptance, "_load", return_value=old), \
                    mock.patch.object(subject.android_document_acceptance, "status", return_value={
                        "state": "unknown", "reason": "transport_or_receipt_unknown",
                        "identity": {"pid": 123, "startTicks": 456}}), \
                    mock.patch.object(subject.ssh_transport, "load_config") as remote:
                with self.assertRaisesRegex(ValueError, "exact unknown document job"):
                    start(tmp, revision=1)
                remote.assert_not_called()

    def test_original_terminal_proof_rejects_live_worker_and_missing_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); root.chmod(0o700)
            old = {"host": "archlinux", "device": "api29", "correlationId": UNKNOWN}
            job = root / ("android-document-job-" + UNKNOWN)
            job.mkdir(mode=0o700)
            for name, value in (("intent.json", old),
                                ("identity.json", {"pid": 123, "startTicks": 456}),
                                ("result.json", {"state": "unknown", "reason": "command_failed"})):
                path = job / name
                path.write_text(json.dumps(value)); path.chmod(0o600)
            proc = root / "proc" / "123"
            proc.mkdir(parents=True)
            stat_file = proc / "stat"
            stat_file.write_text("123 (worker) R " + "0 " * 18 + "456\n")
            source = subject._ORIGINAL_TERMINAL.replace('f"/proc/{pid}/stat"', 'f"{root}/proc/{pid}/stat"')
            self.assertNotEqual(source, subject._ORIGINAL_TERMINAL)

            def probe(*, permission_denied: bool = False) -> dict:
                code = "exec(" + repr(source) + ")"
                if permission_denied:
                    code = ("import pathlib\n"
                            "_original_read_text = pathlib.Path.read_text\n"
                            "def _deny_stat(self, *args, **kwargs):\n"
                            " if self.name == 'stat': raise PermissionError(13, 'denied')\n"
                            " return _original_read_text(self, *args, **kwargs)\n"
                            "pathlib.Path.read_text = _deny_stat\n" + code)
                command = [sys.executable, "-I", "-B", "-c", code,
                           str(root), UNKNOWN, json.dumps(old, sort_keys=True, separators=(",", ":")),
                           "123", "456"]
                done = subprocess.run(command, capture_output=True, check=True, timeout=10)
                return json.loads(done.stdout)

            self.assertEqual(probe(), {"ready": False})
            self.assertEqual(probe(permission_denied=True), {"ready": False})
            stat_file.write_text("malformed process stat\n")
            self.assertEqual(probe(), {"ready": False})
            stat_file.unlink()
            self.assertEqual(probe(), {"ready": True})
            (job / "result.json").unlink()
            self.assertEqual(probe(), {"ready": False})

    def test_reservation_prevents_second_recovery_for_same_unknown_job(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            first = intent()
            subject._reserve(tmp, first)
            self.assertEqual(subject._load(tmp, RECOVERY), first)
            self.assertEqual(subject._private_read(subject._reservation(tmp, UNKNOWN),
                                                   "unknownDocumentCorrelationId", UNKNOWN),
                             {"unknownDocumentCorrelationId": UNKNOWN,
                              "recoveryCorrelationId": RECOVERY})
            second = {**first, "correlationId": "6cfc4136-887c-43d1-90a2-cac3e00eeb52"}
            with self.assertRaises(FileExistsError):
                subject._reserve(tmp, second)
            self.assertIsNone(subject._load(tmp, second["correlationId"]))
            self.assertEqual(subject._load(tmp, RECOVERY), first)

    def test_recovery_status_reader_accepts_its_terminal_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); root.chmod(0o700)
            expected = intent(); expected["fixtureRoot"] = str(root)
            job = root / ("android-document-recovery-job-" + RECOVERY)
            job.mkdir(mode=0o700)
            for name, value in (("intent.json", expected),
                                ("identity.json", {"pid": 1, "startTicks": 1}),
                                ("result.json", {"state": "complete", "result": terminal_result()})):
                path = job / name
                path.write_text(json.dumps(value)); path.chmod(0o600)
            export = job / "restored-routing.json"
            export.write_bytes(b"restored"); export.chmod(0o600)
            command = [sys.executable, "-I", "-B", "-c", "exec(" + repr(subject._STATUS) + ")",
                       str(root), RECOVERY, json.dumps(expected, sort_keys=True, separators=(",", ":"))]
            done = subprocess.run(command, capture_output=True, check=True, timeout=10)
            observed = json.loads(done.stdout)
            self.assertEqual(observed["state"], "complete", observed)
            self.assertEqual(observed["receipt"]["result"], terminal_result())

    def test_recovery_status_reader_rejects_changed_private_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); root.chmod(0o700)
            expected = intent(); expected["fixtureRoot"] = str(root)
            job = root / ("android-document-recovery-job-" + RECOVERY)
            job.mkdir(mode=0o700)
            for name, value in (("intent.json", expected),
                                ("identity.json", {"pid": 1, "startTicks": 1}),
                                ("result.json", {"state": "complete", "result": terminal_result()})):
                path = job / name
                path.write_text(json.dumps(value)); path.chmod(0o600)
            export = job / "restored-routing.json"
            export.write_bytes(b"tampered"); export.chmod(0o600)
            command = [sys.executable, "-I", "-B", "-c", "exec(" + repr(subject._STATUS) + ")",
                       str(root), RECOVERY, json.dumps(expected, sort_keys=True, separators=(",", ":"))]
            done = subprocess.run(command, capture_output=True, check=True, timeout=10)
            observed = json.loads(done.stdout)
            self.assertEqual(observed["state"], "unknown")
            self.assertFalse(observed.get("receipt"))

    def test_release_and_next_claim_serialize_on_same_device(self) -> None:
        """A new claim cannot slip between validation and unlink of old lease."""
        document = subject.android_document_acceptance
        next_recovery = "6cfc4136-887c-43d1-90a2-cac3e00eeb52"
        with tempfile.TemporaryDirectory() as tmp:
            document._claim_device(tmp, "archlinux", "api29", UNKNOWN)
            lease = document._lease(tmp, "archlinux", "api29", UNKNOWN)
            inside_unlink = threading.Event()
            claim_at_lock = threading.Event()
            let_unlink_finish = threading.Event()
            original_unlink = Path.unlink
            original_flock = document.fcntl.flock

            def pause_unlink(path: Path, *args, **kwargs):
                if path == lease and not inside_unlink.is_set():
                    inside_unlink.set()
                    if not let_unlink_finish.wait(3):
                        raise TimeoutError("test release gate timed out")
                return original_unlink(path, *args, **kwargs)

            def mark_flock(fd, operation):
                if threading.current_thread().name == "next_claim" and operation == document.fcntl.LOCK_EX:
                    claim_at_lock.set()
                return original_flock(fd, operation)

            def next_claim():
                threading.current_thread().name = "next_claim"
                return document._claim_device(tmp, "archlinux", "api29", next_recovery)

            with mock.patch.object(Path, "unlink", pause_unlink), \
                    mock.patch.object(document.fcntl, "flock", mark_flock), \
                    ThreadPoolExecutor(max_workers=2) as pool:
                releasing = pool.submit(document._release_device, tmp, "archlinux", "api29", UNKNOWN)
                self.assertTrue(inside_unlink.wait(3))
                claiming = pool.submit(next_claim)
                self.assertTrue(claim_at_lock.wait(3))
                with self.assertRaises(FutureTimeout):
                    claiming.result(timeout=0.05)
                let_unlink_finish.set()
                self.assertTrue(releasing.result(timeout=3))
                claiming.result(timeout=3)
            self.assertFalse(document._release_device(tmp, "archlinux", "api29", UNKNOWN))
            self.assertTrue(lease.exists())
            self.assertTrue(document._release_device(tmp, "archlinux", "api29", next_recovery))

    def test_missing_status_is_unknown_and_never_replayable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            observed = subject.status(tmp, RECOVERY)
        self.assertEqual(observed["state"], "unknown")
        self.assertFalse(observed["replayAllowed"])

    def test_invalid_or_foreign_device_cannot_reach_remote(self) -> None:
        with mock.patch.object(subject.ssh_transport, "load_config", side_effect=AssertionError("remote reached")):
            with self.assertRaises(ValueError):
                subject.start("/unused", "archlinux", "api35", RECOVERY, UNKNOWN,
                              OPENING, CURRENT, ARTIFACT, CLI_STAGE, OWNER, 0)
            with self.assertRaises(ValueError):
                start("/unused", recovery="not-a-uuid")
            with self.assertRaises(ValueError):
                start("/unused", unknown=RECOVERY)
            with self.assertRaises(ValueError):
                start("/unused", revision=-1)

    def test_unsubmitted_collect_never_recovers_by_replaying(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(subject.ssh_transport, "load_config", side_effect=AssertionError("remote reached")):
            result = subject.collect(tmp, RECOVERY)
        self.assertEqual(result["state"], "unknown")
        self.assertFalse(result["replayAllowed"])

    def test_finalize_rejects_missing_recovery_without_readback_or_release(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(subject.ssh_transport, "load_config", side_effect=AssertionError("remote reached")):
            result = subject.finalize(tmp, RECOVERY, CLOSING, OWNER, 0)
        self.assertEqual(result["state"], "unknown")
        self.assertFalse(result["replayAllowed"])

    def test_collect_rejects_mismatched_terminal_binding_and_preserves_lease(self) -> None:
        expected = intent()
        wrong = terminal_result(); wrong["current"] = {**wrong["current"], "sha256": "c" * 64}
        with mock.patch.object(subject, "status", return_value={"state": "complete", "ok": True,
                "receipt": {"result": wrong}}), \
                mock.patch.object(subject, "_load", return_value=expected), \
                mock.patch.object(subject.android_document_acceptance, "_release_device") as release:
            observed = subject.collect("/unused", RECOVERY)
            self.assertEqual(observed["state"], "unknown")
            self.assertFalse(observed["replayAllowed"])
            release.assert_not_called()

    def test_collect_terminal_still_holds_original_unknown_lease(self) -> None:
        expected = intent(); result = terminal_result()
        with mock.patch.object(subject, "status", return_value={"state": "complete", "ok": True,
                "receipt": {"result": result}}), \
                mock.patch.object(subject, "_load", return_value=expected), \
                mock.patch.object(subject.android_document_acceptance, "_release_device") as release:
            observed = subject.collect("/unused", RECOVERY)
            self.assertTrue(observed["ok"])
            self.assertEqual(observed["state"], "complete")
            self.assertFalse(observed["leaseReleased"])
            self.assertFalse(observed["replayAllowed"])
            release.assert_not_called()

    def test_finalize_rejects_old_readback_and_changed_backup_before_release(self) -> None:
        expected = intent(); result = terminal_result()
        completed = {"state": "complete", "ok": True, "result": result}
        with mock.patch.object(subject, "collect", return_value=completed), \
                mock.patch.object(subject, "_load", return_value=expected), \
                mock.patch.object(subject, "_readback", return_value={"backup": {"sha256": CURRENT_SHA,
                                                         "size": 11_872_243}}) as readback, \
                mock.patch.object(subject.android_document_acceptance, "_release_device") as release:
            old = subject.finalize("/unused", RECOVERY, CURRENT, OWNER, 2)
            self.assertEqual(old["state"], "unknown")
            readback.assert_not_called()
            changed = subject.finalize("/unused", RECOVERY, CLOSING, OWNER, 2)
            self.assertEqual(changed["state"], "unknown")
            release.assert_not_called()

    def test_finalize_rejects_missing_original_lease_before_closing_readback(self) -> None:
        expected = intent(); completed = {"state": "complete", "ok": True,
                                          "result": terminal_result()}
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(subject, "collect", return_value=completed), \
                mock.patch.object(subject, "_load", return_value=expected), \
                mock.patch.object(subject, "_readback") as readback, \
                mock.patch.object(subject.android_document_acceptance, "_release_device") as release:
            observed = subject.finalize(tmp, RECOVERY, CLOSING, OWNER, 2)
            self.assertEqual(observed["state"], "unknown")
            self.assertFalse(observed["replayAllowed"])
            readback.assert_not_called()
            release.assert_not_called()

    def test_finalize_rejects_stale_live_readback_before_release(self) -> None:
        expected = intent(); completed = {"state": "complete", "ok": True,
                                          "result": terminal_result()}
        with tempfile.TemporaryDirectory() as tmp:
            subject.android_document_acceptance._claim_device(tmp, "archlinux", "api29", UNKNOWN)
            stale = {"ok": True, "outcome": "observed", "result": {
                "deviceIdentity": True, "controllerId": OWNER,
                "configurationRevision": 2, "stage": "backup_present",
                "backup": {"sha256": CURRENT_SHA, "size": 11_872_243,
                           "formatValid": True}}}
            with mock.patch.object(subject, "collect", return_value=completed), \
                    mock.patch.object(subject, "_load", return_value=expected), \
                    mock.patch.object(subject.android_admission_readback, "readback_status", return_value=stale), \
                    mock.patch.object(subject, "_readback", return_value={"backup": {
                        "sha256": OPENING_SHA, "size": 239}}) as readback, \
                    mock.patch.object(subject.android_document_acceptance, "_release_device") as release:
                observed = subject.finalize(tmp, RECOVERY, CLOSING, OWNER, 2)
                self.assertEqual(observed["state"], "unknown")
                self.assertFalse(observed["replayAllowed"])
                readback.assert_called_once()
                release.assert_not_called()

    def test_finalize_releases_only_exact_unknown_lease_after_closing_readback(self) -> None:
        expected = intent(); result = terminal_result()
        completed = {"state": "complete", "ok": True, "result": result}
        public = {"ok": True, "outcome": "admitted", "result": {
            "runtime": {"running": False, "observation": "stopped"}}}
        fresh = {"ok": True, "outcome": "observed", "result": {
            "deviceIdentity": True, "controllerId": OWNER,
            "configurationRevision": 2, "stage": "backup_present",
            "backup": {"sha256": OPENING_SHA, "size": 239,
                       "formatValid": True}}}
        config = SimpleNamespace(hosts={"archlinux": SimpleNamespace(fixture_transfer_root=Path("/fixture"))})
        with tempfile.TemporaryDirectory() as tmp:
            subject.android_document_acceptance._claim_device(tmp, "archlinux", "api29", UNKNOWN)
            lease = subject.android_document_acceptance._lease(tmp, "archlinux", "api29", UNKNOWN)
            real_release = subject.android_document_acceptance._release_device
            with mock.patch.object(subject, "collect", return_value=completed), \
                    mock.patch.object(subject, "_load", return_value=expected), \
                    mock.patch.object(subject, "_readback", return_value={"backup": {"sha256": OPENING_SHA,
                                                             "size": 239}}) as readback, \
                    mock.patch.object(subject.android_admission_readback, "readback_status", return_value=fresh), \
                    mock.patch.object(subject.ssh_transport, "load_config", return_value=config), \
                    mock.patch.object(subject.ssh_transport, "build_ssh_argv", return_value=["mock-ssh"]), \
                    mock.patch.object(subject.android_observation, "_run_probe", return_value=(0,
                        b'{"same":true,"canonicalSha256":"' + b"d" * 64 + b'"}')), \
                    mock.patch.object(subject.android_public_inspect, "inspect", return_value=public), \
                    mock.patch.object(subject.android_document_acceptance, "_release_device", wraps=real_release) as release:
                observed = subject.finalize(tmp, RECOVERY, CLOSING, OWNER, 2)
                self.assertTrue(observed["ok"])
                self.assertEqual(observed["state"], "complete")
                self.assertTrue(observed["leaseReleased"])
                self.assertFalse(observed["replayAllowed"])
                readback.assert_called_once_with(tmp, CLOSING, "archlinux", "api29", SHA, OWNER, 2)
                release.assert_called_once_with(tmp, "archlinux", "api29", UNKNOWN)
            self.assertFalse(lease.exists())


if __name__ == "__main__":
    unittest.main()

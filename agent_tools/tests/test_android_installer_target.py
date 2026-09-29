"""Causal admission and no-replay evidence for Android product self-update."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import contextmanager
from unittest import mock

from agent_tools import android_installer_target as target
from agent_tools import android_admission_readback, android_package_install, android_public_inspect, native_artifact_registry


def fixture(path: Path, data: bytes) -> str:
    path.write_bytes(data)
    path.chmod(0o600)
    return hashlib.sha256(data).hexdigest()


@contextmanager
def admitted(pair, backup_hash, backup_path, avd, api, *, changed=False):
    size = backup_path.stat().st_size
    observed = {"ok": True, "result": {"stage": "backup_present", "deviceIdentity": True,
        "controllerId": "owner", "configurationRevision": 4,
        "backup": {"sha256": "0" * 64 if changed else backup_hash,
                   "formatValid": True, "size": size}}}
    opening = {"ok": True, "state": "complete", "result": {
        "guard": {"controllerId": "owner", "configurationRevision": 4},
        "package": {"baseSha256": pair["baseSha256"]},
        "backup": {"sha256": backup_hash, "path": str(backup_path), "size": size,
            "type": "vpn_control_routing_rules", "version": 7, "rulesValid": True},
        "device": {"uid": "2000", "avd": avd, "api": api}}}
    public = {"ok": True, "outcome": "admitted", "result": {
        "packageSha256": pair["baseSha256"], "controllerId": "owner",
        "configurationRevision": 4, "device": {"uid": "2000", "avd": avd, "api": api},
        "runtime": {"running": False, "observation": "stopped"}, "operationCount": 0}}
    with mock.patch.object(target, "admit_pair", return_value=pair), \
         mock.patch.object(android_admission_readback, "readback_status", return_value=observed), \
         mock.patch.object(android_admission_readback, "async_collect", return_value=opening), \
         mock.patch.object(android_public_inspect, "inspect", return_value=public):
        yield


class AndroidInstallerTargetTest(unittest.TestCase):
    def test_target_must_be_exact_source_higher_version_and_same_signer(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            old_path, new_path = root / "base.apk", root / "target.apk"
            old_hash = fixture(old_path, b"base")
            new_hash = fixture(new_path, b"target")
            source = "a" * 40
            def artifact(_root, artifact_id):
                digest = artifact_id[7:]
                path = old_path if digest == old_hash else new_path
                return {"verification": "verified", "artifact": {
                    "platform": "android", "artifactKind": "apk", "sha256": digest,
                    "sourceSha": "old" if path == old_path else source,
                }, "location": {"localPath": str(path)}}
            def inspect(_root, path):
                old = path == old_path
                return {"package": "com.kardinal.vpncontrol", "abi": "x86_64", "debuggable": False,
                        "version": "2.2.0" if old else "2.2.1", "code": 16800 if old else 16820,
                        "signerSha256": "b" * 64}
            with mock.patch.object(native_artifact_registry, "verify_artifact", side_effect=artifact), \
                 mock.patch.object(android_package_install, "_inspect_apk", side_effect=inspect), \
                 mock.patch.object(target.subprocess, "run", return_value=mock.Mock(stdout=source + "\n")):
                admitted = target.admit_pair(root, source, "sha256-" + old_hash,
                                             "sha256-" + new_hash, old_hash)
                self.assertEqual(new_hash, admitted["targetSha256"])
                with self.assertRaisesRegex(ValueError, "installed digest|compatible"):
                    target.admit_pair(root, source, "sha256-" + old_hash,
                                      "sha256-" + new_hash, "0" * 64)
                with mock.patch.object(android_package_install, "_inspect_apk",
                                       side_effect=lambda _root, path: {**inspect(_root, path),
                                           "signerSha256": "c" * 64 if path == new_path else "b" * 64}):
                    with self.assertRaisesRegex(ValueError, "compatible"):
                        target.admit_pair(root, source, "sha256-" + old_hash,
                                          "sha256-" + new_hash, old_hash)
                new_path.write_bytes(b"corrupt-target")
                with self.assertRaisesRegex(ValueError, "bytes changed"):
                    target.admit_pair(root, source, "sha256-" + old_hash,
                                      "sha256-" + new_hash, old_hash)

    def test_private_intent_is_once_only_and_backup_bound(self):
        correlation = "3a328d13-28a6-442b-bcc0-266ca20368f5"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            backup = root / "opening.json"
            backup_hash = fixture(backup, b'{"type":"vpn_control_routing_rules","version":7,"rules":{}}')
            pair = {"sourceSha": "a" * 40, "baseArtifactId": "sha256-" + "b" * 64,
                    "targetArtifactId": "sha256-" + "c" * 64,
                    "baseSha256": "b" * 64,
                    "targetSha256": "c" * 64, "targetVersion": "2.2.1", "targetCode": 16820}
            output = root / "job"
            with admitted(pair, backup_hash, backup, "owned-api35", 35):
                first = target.create_intent(root, output, correlation, pair, host="archlinux", device="api35",
                    backup_correlation_id="5a328d13-28a6-442b-bcc0-266ca20368f5",
                    inspect_correlation_id="6a328d13-28a6-442b-bcc0-266ca20368f5",
                    expected_avd="owned-api35", expected_api=35, expected_owner="owner", expected_revision=4,
                    backup_path=backup, backup_sha256=backup_hash, expected_terminal="cancelled")
            self.assertEqual("prepared", first["state"])
            self.assertEqual("prepared", target.status(output, correlation)["state"])
            with admitted(pair, backup_hash, backup, "owned-api35", 35), self.assertRaises(ValueError):
                target.create_intent(root, output, correlation, pair, host="archlinux", device="api35",
                    backup_correlation_id="5a328d13-28a6-442b-bcc0-266ca20368f5",
                    inspect_correlation_id="6a328d13-28a6-442b-bcc0-266ca20368f5",
                    expected_avd="owned-api35", expected_api=35, expected_owner="owner", expected_revision=4,
                    backup_path=backup, backup_sha256=backup_hash, expected_terminal="cancelled")
            backup.write_bytes(b"tampered")
            with admitted(pair, backup_hash, backup, "owned-api35", 35, changed=True), self.assertRaisesRegex(ValueError, "readback changed"):
                target.create_intent(root, root / "next", correlation, pair, host="archlinux", device="api35",
                    backup_correlation_id="5a328d13-28a6-442b-bcc0-266ca20368f5",
                    inspect_correlation_id="6a328d13-28a6-442b-bcc0-266ca20368f5",
                    expected_avd="owned-api35", expected_api=35, expected_owner="owner", expected_revision=4,
                    backup_path=backup, backup_sha256=backup_hash, expected_terminal="cancelled")

    def test_incomplete_or_forged_terminal_never_allows_replay(self):
        correlation = "3a328d13-28a6-442b-bcc0-266ca20368f5"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            backup = root / "opening.json"
            backup_hash = fixture(backup, b'{"type":"vpn_control_routing_rules","version":7,"rules":{}}')
            pair = {"sourceSha": "a" * 40, "baseArtifactId": "sha256-" + "b" * 64,
                    "targetArtifactId": "sha256-" + "c" * 64,
                    "baseSha256": "b" * 64,
                    "targetSha256": "c" * 64, "targetVersion": "2.2.1", "targetCode": 16820}
            output = root / "job"
            with admitted(pair, backup_hash, backup, "owned-api29", 29):
                target.create_intent(root, output, correlation, pair, host="archlinux", device="api29",
                    backup_correlation_id="5a328d13-28a6-442b-bcc0-266ca20368f5",
                    inspect_correlation_id="6a328d13-28a6-442b-bcc0-266ca20368f5",
                    expected_avd="owned-api29", expected_api=29, expected_owner="owner", expected_revision=4,
                    backup_path=backup, backup_sha256=backup_hash, expected_terminal="installed")
            self.assertFalse(target.collect(output, correlation)["ok"])
            checkpoint = output / "probe.json"
            fixture(output / "run-started.json", json.dumps({"correlationId": correlation,
                "state": "may_have_started"}).encode())
            self.assertEqual("unknown", target.status(output, correlation)["state"])
            fixture(checkpoint, json.dumps({"callbackReceipt": {"installerLifecycle": {
                "operationId": "operation", "interactiveAccepted": {"exit": 0,
                    "response": {"ok": True, "code": "ACCEPTED", "final": False,
                                 "operationId": "operation", "controllerId": "owner",
                                 "configurationRevision": 4}}}}}).encode())
            self.assertEqual("submitted", target.status(output, correlation)["state"])
            receipt = output / "lifecycle-receipt.json"
            terminal = {"probe": {"acceptance": "terminal-confirmed",
                "targetSha256": "c" * 64, "terminalExpectation": "installed",
                "operationId": "operation", "installedBaseSha256": "c" * 64,
                "originalOperation": {"identity": {"operationId": "operation", "receiptId": "receipt",
                    "sessionId": 17, "version": "2.2.1", "targetSha256": "c" * 64}},
                "reconciliation": {"terminal": {"response": {"controllerId": "new-owner",
                    "configurationRevision": 5, "data": {"installReceipt": {
                    "installReceiptId": "receipt", "installSessionId": 17,
                    "installPhase": "installed", "installed": True}}}}}},
                "installerIntent": {"correlationId": correlation, "sourceSha": "a" * 40,
                    "targetArtifactId": "sha256-" + "c" * 64, "backupSha256": backup_hash},
                "frozenBaseSha256": "b" * 64, "targetInstall": True,
                "baseline": {"controllerId": "owner", "installedBaseSha256": "b" * 64},
                "cleanupFailures": []}
            fixture(output / "handoff.json", json.dumps({"identity": terminal["probe"]["originalOperation"]["identity"],
                "originalOperation": json.loads(checkpoint.read_text())["callbackReceipt"]["installerLifecycle"]["interactiveAccepted"],
                "targetSha256": "c" * 64, "targetVersion": "2.2.1", "targetCode": 16820}).encode())
            fixture(receipt, json.dumps(terminal).encode())
            confirmed = target.collect(output, correlation)
            self.assertTrue(confirmed["ok"])
            self.assertEqual("new-owner", confirmed["terminalOwner"])
            self.assertEqual(5, confirmed["terminalRevision"])
            terminal["probe"]["reconciliation"]["terminal"]["response"]["data"]["installReceipt"]["installReceiptId"] = "other"
            receipt.write_bytes(json.dumps(terminal).encode())
            self.assertEqual("unknown", target.collect(output, correlation)["state"])
            self.assertFalse(target.collect(output, correlation)["replayAllowed"])

    def test_cancelled_terminal_requires_exact_retained_session(self):
        intent = {"correlationId": "3a328d13-28a6-442b-bcc0-266ca20368f5",
            "expectedTerminal": "cancelled", "expectedOwner": "owner", "expectedRevision": 4,
            "backupSha256": "d" * 64,
            "pair": {"sourceSha": "a" * 40, "baseSha256": "b" * 64,
                "targetSha256": "c" * 64, "targetVersion": "2.2.1",
                "targetArtifactId": "sha256-" + "c" * 64}}
        checkpoint = {"callbackReceipt": {"installerLifecycle": {
            "operationId": "operation", "interactiveAccepted": {"exit": 0, "response": {
                "ok": True, "code": "ACCEPTED", "final": False,
                "operationId": "operation", "controllerId": "owner",
                "configurationRevision": 4}}}}}
        receipt = {"targetInstall": True, "frozenBaseSha256": "b" * 64,
            "baseline": {"controllerId": "owner", "installedBaseSha256": "b" * 64},
            "installerIntent": {"correlationId": intent["correlationId"],
                "sourceSha": "a" * 40, "targetArtifactId": "sha256-" + "c" * 64,
                "backupSha256": "d" * 64}, "cleanupFailures": [],
            "probe": {"acceptance": "terminal-confirmed", "terminalExpectation": "cancelled",
                "targetSha256": "c" * 64, "operationId": "operation",
                "originalOperation": {"identity": {"operationId": "operation",
                    "receiptId": "receipt", "sessionId": 17, "version": "2.2.1",
                    "targetSha256": "c" * 64}, "status": {"response": {"controllerId": "owner",
                    "configurationRevision": 4, "data": {
                    "installReceiptId": "receipt", "installSessionId": 17,
                    "installPhase": "cancelled", "installed": False}}}}}}
        self.assertEqual("cancelled", target._terminal(intent, checkpoint, receipt)["terminal"])
        receipt["probe"]["originalOperation"]["status"]["response"]["controllerId"] = "foreign-owner"
        with self.assertRaisesRegex(ValueError, "cancelled_owner_changed"):
            target._terminal(intent, checkpoint, receipt)
        receipt["probe"]["originalOperation"]["status"]["response"]["controllerId"] = "owner"
        receipt["probe"]["originalOperation"]["status"]["response"]["data"]["installed"] = True
        with self.assertRaisesRegex(ValueError, "session_receipt"):
            target._terminal(intent, checkpoint, receipt)
        receipt["probe"]["originalOperation"]["status"]["response"]["data"]["installed"] = False
        checkpoint["callbackReceipt"]["installerLifecycle"]["interactiveAccepted"]["response"]["controllerId"] = "foreign-owner"
        with self.assertRaisesRegex(ValueError, "original_submission_not_bound"):
            target._terminal(intent, checkpoint, receipt)
        checkpoint["callbackReceipt"]["installerLifecycle"]["interactiveAccepted"]["response"]["controllerId"] = "owner"
        checkpoint["callbackReceipt"]["installerLifecycle"]["interactiveAccepted"]["response"]["configurationRevision"] = 5
        with self.assertRaisesRegex(ValueError, "original_submission_not_bound"):
            target._terminal(intent, checkpoint, receipt)


if __name__ == "__main__":
    unittest.main()

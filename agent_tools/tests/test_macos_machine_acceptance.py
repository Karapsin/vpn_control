"""Causal one-shot and exact-evidence tests for disposable Tart acceptance."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from agent_tools import macos_machine_acceptance as subject


CORRELATION = "11111111-1111-4111-8111-111111111111"
OPERATION = "22222222-2222-4222-8222-222222222222"
JOB = "33333333-3333-4333-8333-333333333333"
SOURCE = "a" * 40


def request(scenario="install"):
    return {"correlationId": CORRELATION, "scenario": scenario, "sourceSha": SOURCE,
            "sourceFingerprint": "b" * 64, "fixtureReceiptArtifactId": "sha256-" + "c" * 64,
            "baseDmgArtifactId": "sha256-" + "d" * 64,
            "targetDmgArtifactId": "sha256-" + "e" * 64,
            "baseJarSha256": "f" * 64, "targetJarSha256": "0" * 64}


class FakeBoundary:
    def __init__(self, wanted):
        self.wanted = wanted
        self.submit_count = 0
        self.grant_count = 0
        self.source = SOURCE
        self.clean = True
        self.prompt_count = 0
        self.changed = {}
        self.terminal_changed = {}

    def current_source_sha(self):
        return self.source

    def source_tree_clean(self):
        return self.clean

    def admission(self, requested):
        return {"sourceSha": SOURCE, "sourceFingerprint": requested["sourceFingerprint"],
                "fixtureReceiptArtifactId": requested["fixtureReceiptArtifactId"],
                "baseDmgArtifactId": requested["baseDmgArtifactId"],
                "targetDmgArtifactId": requested["targetDmgArtifactId"],
                **subject._fixed_paths(requested), "vmRunning": True, "resourceAdmitted": True,
                "ownerReady": True, "runtimeRunning": False, "existingPromptCount": self.prompt_count,
                "conflictingJobCount": 0, "legacyUnknownPreserved": True,
                "reservationId": "owned-reservation", "bootSessionUuid": "boot-1",
                "controllerId": "controller-1", "ownerPid": 123, "ownerStartTicks": 456,
                "baseDevice": 12, "baseInode": 34,
                "baseJarSha256": requested["baseJarSha256"], "baseSignatureValid": True,
                "baseRootOwned": True, "targetDmgSha256": requested["targetDmgArtifactId"][7:],
                "baseDmgSha256": requested["baseDmgArtifactId"][7:], **self.changed}

    def submit(self, requested, admitted):
        self.submit_count += 1
        return {"accepted": True, "controllerId": admitted["controllerId"],
                "operationId": OPERATION, "jobId": JOB}

    def prompt(self, requested, operation):
        return {**operation, "visible": True, "count": 1}

    def secure_authorize(self, requested, operation):
        self.grant_count += 1

    def terminal(self, requested, operation):
        proof = {"sourceSha": SOURCE, **operation, "bootSessionUuid": "boot-1",
                 "app": subject._fixed_paths(requested)["app"], "runtimeRunning": False,
                 "cleanupCode": "OK", "signatureValid": True, "oldOwnerExited": True,
                 "guiReturned": True, "guiBundlePath": subject._fixed_paths(requested)["app"],
                 "fixtureServerStopped": True, "publicFinal": True,
                 "newOwnerPid": 999, "guiPid": 1000,
                 "protectedPhase": "SUCCEEDED", "protectedCode": "OK", "publicCode": "OK",
                 "installed": True, "installedJarSha256": requested["targetJarSha256"],
                 "backupAbsent": True, "stageAbsent": True, "secret": "never-store-this"}
        if requested["scenario"] == "rollback":
            proof.update(protectedPhase="FAILED", protectedCode="PERSISTENCE_FAILED",
                         publicCode="PERSISTENCE_FAILED", installed=None,
                         installedJarSha256=requested["baseJarSha256"],
                         baseDevice=12, baseInode=34, rollbackFaultObserved=True)
        return {**proof, **self.terminal_changed}


class MacMachineAcceptanceTest(unittest.TestCase):
    def test_source_or_installed_base_mismatch_rejects_before_submission(self):
        wanted = request()
        with tempfile.TemporaryDirectory() as directory:
            boundary = FakeBoundary(wanted)
            boundary.source = "9" * 40
            with self.assertRaisesRegex(subject.MacMachineAcceptanceError, "Source freeze"):
                subject.start(Path(directory), wanted, boundary)
            self.assertEqual(boundary.submit_count, 0)
            boundary.source = SOURCE
            boundary.clean = False
            with self.assertRaisesRegex(subject.MacMachineAcceptanceError, "Source freeze"):
                subject.start(Path(directory), wanted, boundary)
            self.assertEqual(boundary.submit_count, 0)
            boundary.clean = True
            boundary.changed["baseInode"] = 0
            with self.assertRaisesRegex(subject.MacMachineAcceptanceError, "generation"):
                subject.start(Path(directory), wanted, boundary)
            self.assertEqual(boundary.submit_count, 0)

    def test_prospective_legacy_preservation_is_separate_and_requires_postcheck(self):
        wanted = request()
        with tempfile.TemporaryDirectory() as directory:
            boundary = FakeBoundary(wanted)
            boundary.changed.update(legacyUnknownPreserved=False,
                legacyProspectivePreserved=True,
                legacyProspectiveBaselineId="sha256-" + "9" * 64)
            first = subject.start(Path(directory), wanted, boundary)
            self.assertEqual("unknown", first["state"])
            self.assertEqual(1, boundary.submit_count)
            boundary.terminal_changed["legacyProspectivePreservedAfter"] = False
            self.assertEqual("unknown", subject.status(Path(directory), CORRELATION, boundary)["state"])
            boundary.terminal_changed["legacyProspectivePreservedAfter"] = True
            boundary.terminal_changed["legacyProspectiveBaselineId"] = "sha256-" + "9" * 64
            self.assertEqual("complete", subject.status(Path(directory), CORRELATION, boundary)["state"])

    def test_durable_intent_prevents_duplicate_install_after_lost_response(self):
        wanted = request()
        with tempfile.TemporaryDirectory() as directory:
            boundary = FakeBoundary(wanted)
            def lost_response(requested, admitted):
                boundary.submit_count += 1
                raise TimeoutError("native response lost")
            boundary.submit = lost_response
            first = subject.start(Path(directory), wanted, boundary)
            self.assertEqual(first["state"], "unknown")
            self.assertIsNone(first["operationId"])
            self.assertEqual(subject.start(Path(directory), wanted, boundary), first)
            self.assertEqual(boundary.submit_count, 1)
            with self.assertRaisesRegex(subject.MacMachineAcceptanceError, "different inputs"):
                subject.start(Path(directory), {**wanted, "scenario": "rollback"}, boundary)
            with self.assertRaisesRegex(subject.MacMachineAcceptanceError, "prior Tart campaign"):
                subject.start(Path(directory), {**wanted,
                    "correlationId": "44444444-4444-4444-8444-444444444444"}, boundary)
            self.assertEqual(boundary.submit_count, 1)

    def test_secure_grant_is_exact_and_one_shot_without_secret_in_receipt(self):
        wanted = request()
        with tempfile.TemporaryDirectory() as directory:
            boundary = FakeBoundary(wanted)
            subject.start(Path(directory), wanted, boundary)
            boundary.prompt_count = 1
            boundary.changed["ownerStartTicks"] = 999
            with self.assertRaisesRegex(subject.MacMachineAcceptanceError, "changed"):
                subject.authorize(Path(directory), CORRELATION, boundary)
            self.assertEqual(boundary.grant_count, 0)
            boundary.changed.clear()
            subject.authorize(Path(directory), CORRELATION, boundary)
            self.assertEqual(boundary.grant_count, 1)
            with self.assertRaises(subject.MacMachineAcceptanceError):
                subject.authorize(Path(directory), CORRELATION, boundary)
            self.assertEqual(boundary.grant_count, 1)
            record = Path(directory) / ".rag_index/macos-machine-acceptance" / (CORRELATION + ".json")
            self.assertEqual(record.stat().st_mode & 0o777, 0o600)
            self.assertNotIn("password", record.read_text())

    def test_terminal_requires_exact_target_and_gui_return(self):
        wanted = request()
        with tempfile.TemporaryDirectory() as directory:
            boundary = FakeBoundary(wanted)
            subject.start(Path(directory), wanted, boundary)
            boundary.terminal_changed["guiReturned"] = False
            self.assertEqual(subject.status(Path(directory), CORRELATION, boundary)["state"], "unknown")
            boundary.terminal_changed = {"installedJarSha256": "9" * 64}
            self.assertEqual(subject.status(Path(directory), CORRELATION, boundary)["state"], "unknown")
            boundary.terminal_changed = {"publicFinal": False}
            self.assertEqual(subject.status(Path(directory), CORRELATION, boundary)["state"], "unknown")
            boundary.terminal_changed.clear()
            self.assertEqual(subject.status(Path(directory), CORRELATION, boundary)["state"], "complete")
            record = json.loads((Path(directory) / ".rag_index/macos-machine-acceptance" /
                                 (CORRELATION + ".json")).read_text())
            self.assertNotIn("secret", json.dumps(record))
            self.assertEqual(boundary.submit_count, 1)

    def test_rollback_requires_failed_protected_receipt_and_unchanged_inode(self):
        wanted = request("rollback")
        with tempfile.TemporaryDirectory() as directory:
            boundary = FakeBoundary(wanted)
            subject.start(Path(directory), wanted, boundary)
            boundary.terminal_changed["baseInode"] = 35
            self.assertEqual(subject.status(Path(directory), CORRELATION, boundary)["state"], "unknown")
            boundary.terminal_changed = {"publicCode": "OK"}
            self.assertEqual(subject.status(Path(directory), CORRELATION, boundary)["state"], "unknown")
            boundary.terminal_changed.clear()
            self.assertEqual(subject.status(Path(directory), CORRELATION, boundary)["state"], "complete")


if __name__ == "__main__":
    unittest.main()
